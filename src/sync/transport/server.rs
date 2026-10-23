use crate::sync::crypto::KEY_SIZE;
use crate::sync::discovery::PeerManager;
use crate::sync::file_transfer::FileTransferManager;
use crate::sync::protocol::{
    FileResponsePayload, MSG_FILE_OFFER, MSG_HEARTBEAT, MSG_PAIR_REQUEST, MSG_SESSION_INIT,
    MSG_UNPAIR_NOTICE, PAIR_BOOTSTRAP_KEY, SessionRespPayload, decode_file_offer_packet_in_place,
    decode_heartbeat_packet_in_place, decode_packet_in_place, decode_session_init_packet_in_place,
    decode_unpair_notice_packet_in_place, encode_file_response_packet, encode_heartbeat_packet,
    encode_session_resp_packet,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::pairing::handle_incoming_pair_request;
use super::{
    ClipboardCallback, LoopbackFilter, MAX_PAYLOAD_SIZE, PairAttemptCommand, PairRequestCallback,
    PairSuccessCallback, PendingPairRequest, TransportError, UnpairCallback,
    read_framed_packet_into,
};

/// 同时处理的最大连接数。
///
/// 每个连接占一个 OS 线程（默认 1 MiB 栈）。若不设上限，攻击者只需在无需任何密钥的情况下
/// 建立上万个 TCP 连接，即可把线程数与虚拟内存打满。局域网场景下 64 个并发连接绰绰有余
/// （一个用户最多几台设备，文件传输占用一条连接）。
pub const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// **完成 PFS 认证之前**允许的单帧最大载荷。
///
/// 已认证连接沿用 `MAX_PAYLOAD_SIZE`（16 MiB，剪贴板大内容所需）；未认证连接只允许
/// 握手/心跳这类小帧。否则未认证方只需发送一个 `payload_len = 16 MiB` 的帧头再做慢速发送，
/// 就能让每个连接常驻 16 MiB 堆内存（慢速攻击 + 内存放大）。
pub const UNAUTHENTICATED_MAX_PAYLOAD: usize = 64 * 1024;

/// 未认证连接的空闲读超时。认证成功后放宽到 `AUTHENTICATED_READ_TIMEOUT_SECS`。
const UNAUTHENTICATED_READ_TIMEOUT_SECS: u64 = 10;
const AUTHENTICATED_READ_TIMEOUT_SECS: u64 = 300;

/// RAII 连接槽位：无论 worker 正常返回、panic 还是 spawn 失败，都会归还计数。
struct ConnectionSlot {
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl ConnectionSlot {
    /// 以 CAS 循环尝试占位；达到 `max` 则返回 `None`。
    fn try_acquire(counter: Arc<std::sync::atomic::AtomicUsize>, max: usize) -> Option<Self> {
        loop {
            let current = counter.load(Ordering::SeqCst);
            if current >= max {
                return None;
            }
            if counter
                .compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Some(Self { counter });
            }
        }
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct SyncServer {
    local_device_id: String,
    local_device_name: String,
    local_device_type: RwLock<String>,
    long_term_key: Arc<RwLock<Option<[u8; KEY_SIZE]>>>,
    loopback_filter: Arc<LoopbackFilter>,
    peer_manager: Arc<PeerManager>,
    callback: Arc<RwLock<Option<ClipboardCallback>>>,
    pair_request_callback: Arc<RwLock<Option<PairRequestCallback>>>,
    pair_success_callback: Arc<RwLock<Option<PairSuccessCallback>>>,
    unpair_callback: Arc<RwLock<Option<UnpairCallback>>>,
    pending_pairs: Arc<Mutex<HashMap<String, PendingPairRequest>>>,
    file_transfer_mgr: Arc<FileTransferManager>,
    running: Arc<AtomicBool>,
    listen_port: Arc<Mutex<u16>>,
    active_connections: Arc<std::sync::atomic::AtomicUsize>,
    server_handle: Mutex<Option<JoinHandle<()>>>,
}

impl SyncServer {
    pub fn new(
        local_device_id: String,
        local_device_name: String,
        long_term_key: Arc<RwLock<Option<[u8; KEY_SIZE]>>>,
        loopback_filter: Arc<LoopbackFilter>,
        peer_manager: Arc<PeerManager>,
        file_transfer_mgr: Arc<FileTransferManager>,
    ) -> Self {
        Self {
            local_device_id,
            local_device_name,
            local_device_type: RwLock::new("Windows".to_string()),
            long_term_key,
            loopback_filter,
            peer_manager,
            callback: Arc::new(RwLock::new(None)),
            pair_request_callback: Arc::new(RwLock::new(None)),
            pair_success_callback: Arc::new(RwLock::new(None)),
            unpair_callback: Arc::new(RwLock::new(None)),
            pending_pairs: Arc::new(Mutex::new(HashMap::new())),
            file_transfer_mgr,
            running: Arc::new(AtomicBool::new(false)),
            listen_port: Arc::new(Mutex::new(0)),
            active_connections: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            server_handle: Mutex::new(None),
        }
    }

    pub fn set_local_device_type(&self, device_type: &str) {
        if let Ok(mut dt) = self.local_device_type.write() {
            *dt = device_type.to_string();
        }
    }

    pub fn set_callback(&self, cb: ClipboardCallback) {
        if let Ok(mut c) = self.callback.write() {
            *c = Some(cb);
        }
    }

    pub fn set_pair_request_callback(&self, cb: PairRequestCallback) {
        if let Ok(mut c) = self.pair_request_callback.write() {
            *c = Some(cb);
        }
    }

    pub fn set_pair_success_callback(&self, cb: PairSuccessCallback) {
        if let Ok(mut c) = self.pair_success_callback.write() {
            *c = Some(cb);
        }
    }

    pub fn set_unpair_callback(&self, cb: UnpairCallback) {
        if let Ok(mut c) = self.unpair_callback.write() {
            *c = Some(cb);
        }
    }

    pub fn notify_peer_unpaired(&self, device_id: &str) {
        self.peer_manager.remove_paired_device_id(device_id);
        // 先释放读锁再回调，避免用户回调内重设回调（写锁）时自死锁。
        let cb = self
            .unpair_callback
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        if let Some(cb) = cb {
            cb(device_id.to_string());
        }
    }

    pub fn file_transfer_manager(&self) -> Arc<FileTransferManager> {
        Arc::clone(&self.file_transfer_mgr)
    }

    pub fn respond_pair(&self, request_id: &str, pin: &str, accept: bool) -> i32 {
        let tx = {
            let mut map = match self.pending_pairs.lock() {
                Ok(m) => m,
                Err(_) => return -1,
            };

            let Some(p) = map.get(request_id) else {
                return 1; // Not found or timed out
            };

            // Enforce strict 60-second pairing session timeout
            if p.created_at.elapsed() > Duration::from_secs(60) {
                map.remove(request_id);
                return 1;
            }

            let tx_clone = p.tx.clone();
            if !accept {
                map.remove(request_id);
            }
            tx_clone
        };

        let (reply_tx, reply_rx) = std::sync::mpsc::channel::<i32>();
        if tx
            .send(PairAttemptCommand {
                pin: pin.trim().to_string(),
                accept,
                reply_tx,
            })
            .is_err()
        {
            if let Ok(mut map) = self.pending_pairs.lock() {
                map.remove(request_id);
            }
            return 1;
        }

        let res = reply_rx.recv_timeout(Duration::from_secs(10)).unwrap_or(1);
        if res != 2 {
            if let Ok(mut map) = self.pending_pairs.lock() {
                map.remove(request_id);
            }
        }
        res
    }

    pub fn start(&self, requested_port: u16) -> Result<u16, TransportError> {
        if self.running.swap(true, Ordering::SeqCst) {
            let port = *self.listen_port.lock().unwrap();
            return Ok(port);
        }

        let listen_addr: SocketAddr = format!("0.0.0.0:{}", requested_port)
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));

        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
        #[cfg(unix)]
        let _ = socket.set_reuse_address(true);
        // ⚠️ 禁止静态设置 SO_RCVBUF / SO_SNDBUF —— 这不是「调大缓冲更快」，是自伤。
        //
        // 病历（历史真实事故）：这里曾经设过 SO_RCVBUF = SO_SNDBUF = 4MB。跨设备真实
        // 传输只跑到 20~30 MB/s，而同一条链路上 Windows 文件共享（SMB）能跑 60 MB/s。
        // 删除静态缓冲设置（含 accept 后的重复设置）后回到链路允许的速度：千兆有线
        // 约 100~110 MiB/s，Wi-Fi 也接近跑满。
        //
        // 机制：Windows Vista+ 的 TCP Receive Window Auto-Tuning 是闭环控制（按实测
        // RTT 与丢包动态调窗口）。显式设 SO_RCVBUF 会把它关掉、窗口变成固定值；同时
        // 4MB 的 SO_SNDBUF 让 write_all 立即返回，发送端在极短时间内把数 MB 灌进内核，
        // 突发压力被整体转移到路径上（交换机/AP 队列通常只有几百 KB），造成队列溢出
        // → 丢包重传 → 拥塞窗口缩半 → 再突发，进入低吞吐稳态。
        //
        // 为什么长期没被发现：回环（127.0.0.1）RTT < 0.1ms，BDP 极小，4MB 缓冲根本
        // 用不上，本机自测数字完全正常。只有跨设备 + 大流量才暴露。
        //
        // 依据：Microsoft TechCommunity《Windows network performance suffering from
        // bad buffering》——官方明确建议不要静态分配 TCP 缓冲。若将来有人（含 AI）
        // 提议加回这两行，请先让他解释为什么微软的结论是错的。
        let _ = socket.set_nodelay(true);

        if socket.bind(&listen_addr.into()).is_err() {
            let fallback_addr: SocketAddr = SocketAddr::from(([0, 0, 0, 0], 0));
            socket.bind(&fallback_addr.into())?;
        }

        socket.listen(128)?;
        let listener: TcpListener = socket.into();

        let bound_port = listener.local_addr()?.port();
        if let Ok(mut p) = self.listen_port.lock() {
            *p = bound_port;
        }

        // PERF: 阻塞式 accept。旧实现用非阻塞 + 50ms sleep 轮询，代价是**每条连接**最多
        // 多等 50ms 才被受理 —— 剪贴板同步是「每次内容变更新建一条连接」，这 50ms 直接
        // 落在用户可感知的同步延迟上；同时空闲时也在白白唤醒 CPU。
        // 退出改由 `stop()` 向本地回环发起一次连接来唤醒 accept（见 stop 的注释）。
        listener.set_nonblocking(false)?;

        let running = Arc::clone(&self.running);
        let key_lock = Arc::clone(&self.long_term_key);
        let loopback = Arc::clone(&self.loopback_filter);
        let cb_lock = Arc::clone(&self.callback);
        let pair_req_cb_lock = Arc::clone(&self.pair_request_callback);
        let pair_success_cb_lock = Arc::clone(&self.pair_success_callback);
        let pending_pairs_ref = Arc::clone(&self.pending_pairs);
        let peer_mgr = Arc::clone(&self.peer_manager);
        let unpair_cb_lock = Arc::clone(&self.unpair_callback);
        let ft_mgr = Arc::clone(&self.file_transfer_mgr);
        let local_id = self.local_device_id.clone();
        let local_name = self.local_device_name.clone();
        let active_conns = Arc::clone(&self.active_connections);
        let local_type = self
            .local_device_type
            .read()
            .map(|s| s.clone())
            .unwrap_or_else(|_| "Windows".to_string());

        let handle = thread::Builder::new()
            .name("muclip-p2p-server".into())
            .spawn(move || {
                while running.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, addr)) => {
                            // 退出唤醒连接：stop() 会向本地回环打一次 connect 把阻塞的
                            // accept 踢醒，这里立刻丢弃，不占槽位、不起线程。
                            if !running.load(Ordering::Relaxed) {
                                drop(stream);
                                break;
                            }
                            // SECURITY: 连接槽位必须在 accept 后立刻占用。
                            // 否则每个连接都会无条件 spawn 一个 OS 线程，未认证的远程方
                            // 可以靠堆积空闲连接把线程数/内存打满（无需任何密钥）。
                            let Some(slot) = ConnectionSlot::try_acquire(
                                Arc::clone(&active_conns),
                                MAX_CONCURRENT_CONNECTIONS,
                            ) else {
                                crate::log_warn!(
                                    "并发连接已达上限 {}，拒绝 {}",
                                    MAX_CONCURRENT_CONNECTIONS,
                                    addr
                                );
                                // 直接 drop 会发送 FIN，且不消耗任何线程
                                drop(stream);
                                continue;
                            };

                            let running_worker = Arc::clone(&running);
                            let key_lock_worker = Arc::clone(&key_lock);
                            let loopback_worker = Arc::clone(&loopback);
                            let cb_lock_worker = Arc::clone(&cb_lock);
                            let pair_req_cb_lock_worker = Arc::clone(&pair_req_cb_lock);
                            let pair_success_cb_lock_worker = Arc::clone(&pair_success_cb_lock);
                            let pending_pairs_worker = Arc::clone(&pending_pairs_ref);
                            let peer_mgr_worker = Arc::clone(&peer_mgr);
                            let unpair_cb_lock_worker = Arc::clone(&unpair_cb_lock);
                            let ft_mgr_worker = Arc::clone(&ft_mgr);
                            let local_id_worker = local_id.clone();
                            let local_name_worker = local_name.clone();
                            let local_type_worker = local_type.clone();

                            let spawn_result = thread::Builder::new()
                                .name("muclip-p2p-conn".into())
                                .spawn(move || {
                                    // 槽位移入闭包：正常退出、panic、或 spawn 失败导致闭包被丢弃时，
                                    // 都会通过 Drop 归还计数。
                                    let _slot = slot;
                                    handle_client_connection(
                                        stream,
                                        addr,
                                        bound_port,
                                        &running_worker,
                                        &local_id_worker,
                                        &local_name_worker,
                                        &local_type_worker,
                                        &key_lock_worker,
                                        &loopback_worker,
                                        &peer_mgr_worker,
                                        &ft_mgr_worker,
                                        &pending_pairs_worker,
                                        &cb_lock_worker,
                                        &pair_req_cb_lock_worker,
                                        &pair_success_cb_lock_worker,
                                        &unpair_cb_lock_worker,
                                    );
                                });
                            if let Err(e) = spawn_result {
                                // 系统线程资源耗尽：不再 panic（thread::spawn 会 panic），
                                // 优雅拒绝本次连接，闭包被丢弃时槽位已自动归还。
                                crate::log_warn!("无法创建连接处理线程，拒绝 {}: {}", addr, e);
                            }
                        }
                        Err(ref e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::Interrupted
                                    | std::io::ErrorKind::ConnectionAborted
                            ) =>
                        {
                            // 瞬态错误（EINTR / 对端在完成握手前 RST）：立刻重试即可。
                        }
                        Err(e) => {
                            // 持久性错误（如本地 socket 资源耗尽 EBADF/EMFILE）：退避以免
                            // 打满 CPU，但保持服务存活，等资源恢复后继续 accept。
                            crate::log_error!("accept 失败，稍后重试: {}", e);
                            thread::sleep(Duration::from_millis(50));
                        }
                    }
                }
            })?;

        if let Ok(mut g) = self.server_handle.lock() {
            *g = Some(handle);
        }

        Ok(bound_port)
    }

    pub fn stop(&self) {
        let was_running = self.running.swap(false, Ordering::SeqCst);
        // 唤醒阻塞在 `accept()` 上的服务线程：监听器是阻塞模式（为了消除每条连接
        // 最多 50ms 的轮询延迟），所以必须由外部踢一脚才会返回。向本地回环发起一次
        // 连接即可 —— 该连接会被 accept 收到，随即因 `running == false` 被丢弃。
        // 这只是把线程从内核态唤醒，不建立任何有意义的会话。
        if was_running {
            let port = self.listen_port.lock().map(|p| *p).unwrap_or(0);
            if port != 0 {
                let addr = SocketAddr::from(([127, 0, 0, 1], port));
                let _ = TcpStream::connect_timeout(&addr, Duration::from_millis(200));
            }
        }
        if let Ok(mut g) = self.server_handle.lock() {
            if let Some(h) = g.take() {
                let _ = h.join();
            }
        }
    }
}

impl Drop for SyncServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_client_connection(
    mut stream: TcpStream,
    addr: SocketAddr,
    bound_port: u16,
    running: &Arc<AtomicBool>,
    local_id: &str,
    local_name: &str,
    local_type: &str,
    key_lock: &Arc<RwLock<Option<[u8; KEY_SIZE]>>>,
    loopback: &Arc<LoopbackFilter>,
    peer_mgr: &Arc<PeerManager>,
    ft_mgr: &Arc<FileTransferManager>,
    pending_pairs: &Arc<Mutex<HashMap<String, PendingPairRequest>>>,
    cb_lock: &Arc<RwLock<Option<ClipboardCallback>>>,
    pair_req_cb_lock: &Arc<RwLock<Option<PairRequestCallback>>>,
    pair_success_cb_lock: &Arc<RwLock<Option<PairSuccessCallback>>>,
    unpair_cb_lock: &Arc<RwLock<Option<UnpairCallback>>>,
) {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_nodelay(true);
    // 未认证阶段用短超时：认证成功后放宽到 300s（见下方 session_key 赋值处）
    let _ = stream.set_read_timeout(Some(Duration::from_secs(UNAUTHENTICATED_READ_TIMEOUT_SECS)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(15)));

    let client_ip = addr.ip().to_string();
    let mut session_key: Option<zeroize::Zeroizing<[u8; KEY_SIZE]>> = None;
    let mut authenticated_client_id: Option<String> = None;
    // 连接生命周期内复用的帧缓冲区
    let mut packet_buf: Vec<u8> = Vec::new();

    while running.load(Ordering::Relaxed) {
        // SECURITY: 未认证连接只允许小帧。否则对端只需发一个 16 MiB 的帧头再慢速发送，
        // 就能让每个连接常驻 16 MiB 堆内存（内存放大 + 慢速攻击）。
        let max_payload = if session_key.is_some() {
            MAX_PAYLOAD_SIZE
        } else {
            UNAUTHENTICATED_MAX_PAYLOAD
        };
        // 复用同一块缓冲区：长连接上避免每帧一次堆分配（大载荷时是每帧一次十几 MB）
        let Ok((header, packet_len)) =
            read_framed_packet_into(&mut stream, max_payload, &mut packet_buf)
        else {
            break;
        };
        let raw_packet: &mut [u8] = &mut packet_buf[..packet_len];

        if header.msg_type == MSG_SESSION_INIT {
            if let Ok((_h, init_payload)) = decode_session_init_packet_in_place(raw_packet) {
                // P0-3: Handshake stage MUST verify pairing status first!
                if !peer_mgr.is_paired(&init_payload.client_device_id) {
                    let resp_payload = SessionRespPayload {
                        responder_device_id: local_id.to_string(),
                        ephemeral_pk: [0u8; 32],
                        auth_tag: String::new(),
                        accepted: false,
                    };
                    if let Ok(resp_pkt) =
                        encode_session_resp_packet(header.sequence + 1, &resp_payload)
                    {
                        let _ = stream.write_all(&resp_pkt);
                        let _ = stream.flush();
                    }
                    break;
                }

                // P1-1: Verify target device ID if specified by initiator
                if let Some(ref target) = init_payload.target_device_id {
                    if !target.is_empty() && target != local_id {
                        let resp_payload = SessionRespPayload {
                            responder_device_id: local_id.to_string(),
                            ephemeral_pk: [0u8; 32],
                            auth_tag: String::new(),
                            accepted: false,
                        };
                        if let Ok(resp_pkt) =
                            encode_session_resp_packet(header.sequence + 1, &resp_payload)
                        {
                            let _ = stream.write_all(&resp_pkt);
                            let _ = stream.flush();
                        }
                        break;
                    }
                }

                // P0-2: Candidate key is ONLY the currently paired key for this specific device
                // (or local key if configured as direct pairing). NEVER use fallback keys or other peers' keys!
                let expected_key = peer_mgr
                    .get_peer_key(&init_payload.client_device_id)
                    .or_else(|| key_lock.read().ok().and_then(|k| *k));

                let Some(ltk) = expected_key else {
                    let resp_payload = SessionRespPayload {
                        responder_device_id: local_id.to_string(),
                        ephemeral_pk: [0u8; 32],
                        auth_tag: String::new(),
                        accepted: false,
                    };
                    if let Ok(resp_pkt) =
                        encode_session_resp_packet(header.sequence + 1, &resp_payload)
                    {
                        let _ = stream.write_all(&resp_pkt);
                        let _ = stream.flush();
                    }
                    break;
                };

                let target_id_str = init_payload.target_device_id.as_deref().unwrap_or("");
                let expected_tag = crate::sync::crypto::compute_session_auth_tag(
                    &ltk,
                    &init_payload.client_device_id,
                    target_id_str,
                    &init_payload.ephemeral_pk,
                    None,
                    "initiator",
                    &init_payload.challenge,
                );

                if crate::sync::crypto::constant_time_eq_str(&expected_tag, &init_payload.auth_tag)
                {
                    let server_ex = crate::sync::crypto::KeyExchangeSession::new();
                    let server_pk = server_ex.public_key;
                    let shared = server_ex.compute_shared_secret(&init_payload.ephemeral_pk);
                    let derived_session_key = crate::sync::crypto::derive_pfs_session_key(
                        &*shared,
                        &ltk,
                        &init_payload.challenge,
                    );
                    let resp_tag = crate::sync::crypto::compute_session_auth_tag(
                        &ltk,
                        &init_payload.client_device_id,
                        local_id,
                        &server_pk,
                        Some(&init_payload.ephemeral_pk),
                        "responder",
                        &init_payload.challenge,
                    );
                    let resp_payload = SessionRespPayload {
                        responder_device_id: local_id.to_string(),
                        ephemeral_pk: server_pk,
                        auth_tag: resp_tag,
                        accepted: true,
                    };
                    if let Ok(resp_pkt) =
                        encode_session_resp_packet(header.sequence + 1, &resp_payload)
                    {
                        if stream.write_all(&resp_pkt).is_ok() && stream.flush().is_ok() {
                            session_key = Some(derived_session_key);
                            authenticated_client_id = Some(init_payload.client_device_id);
                            // 已认证：放宽读超时，支持长连接上的间歇性剪贴板同步
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(
                                AUTHENTICATED_READ_TIMEOUT_SECS,
                            )));
                            // P0-2: Handshake only authenticates; DO NOT overwrite peer_mgr.set_peer_key!
                            continue;
                        }
                    }
                } else {
                    let resp_payload = SessionRespPayload {
                        responder_device_id: local_id.to_string(),
                        ephemeral_pk: [0u8; 32],
                        auth_tag: String::new(),
                        accepted: false,
                    };
                    if let Ok(resp_pkt) =
                        encode_session_resp_packet(header.sequence + 1, &resp_payload)
                    {
                        let _ = stream.write_all(&resp_pkt);
                        let _ = stream.flush();
                    }
                    break;
                }
            }
            break;
        } else if header.msg_type == MSG_HEARTBEAT {
            handle_heartbeat_msg(
                &mut stream,
                header.sequence,
                &mut *raw_packet,
                &client_ip,
                local_id,
                local_name,
                local_type,
                bound_port,
                peer_mgr,
            );
            break;
        } else if header.msg_type == MSG_PAIR_REQUEST {
            handle_incoming_pair_request(
                &mut stream,
                &mut *raw_packet,
                &client_ip,
                local_id,
                local_name,
                key_lock,
                peer_mgr,
                pending_pairs,
                pair_req_cb_lock,
                pair_success_cb_lock,
            );
            break;
        } else if header.msg_type == MSG_UNPAIR_NOTICE {
            let Some(pfs_key) = session_key.as_ref() else {
                let _ = stream.write_all(b"ERR_NO_SESSION");
                let _ = stream.flush();
                break;
            };
            let auth_id = authenticated_client_id.as_deref().unwrap_or("");
            handle_unpair_notice_msg(
                &mut stream,
                &mut *raw_packet,
                &**pfs_key,
                auth_id,
                peer_mgr,
                unpair_cb_lock,
            );
            break;
        } else if header.msg_type == MSG_FILE_OFFER {
            let Some(pfs_key) = session_key.as_ref() else {
                let resp = FileResponsePayload {
                    transfer_id: String::new(),
                    accepted: false,
                    error_code: 6,
                    error_message: Some("PFS session handshake required".to_string()),
                    offset: 0,
                };
                if let Ok(resp_pkt) = encode_file_response_packet(&PAIR_BOOTSTRAP_KEY, 1, &resp) {
                    let _ = stream.write_all(&resp_pkt);
                    let _ = stream.flush();
                }
                return;
            };
            handle_file_offer_msg(
                stream,
                &mut *raw_packet,
                &client_ip,
                &**pfs_key,
                authenticated_client_id.as_deref().unwrap_or(""),
                peer_mgr,
                ft_mgr,
            );
            return;
        } else {
            let Some(pfs_key) = session_key.as_ref() else {
                let _ = stream.write_all(b"ERR_NO_SESSION");
                let _ = stream.flush();
                break;
            };
            let keep_open = handle_clipboard_sync_msg(
                &mut stream,
                &mut *raw_packet,
                &client_ip,
                local_id,
                &**pfs_key,
                authenticated_client_id.as_deref().unwrap_or(""),
                loopback,
                peer_mgr,
                cb_lock,
            );
            if !keep_open {
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_heartbeat_msg(
    stream: &mut TcpStream,
    sequence: u64,
    raw_packet: &mut [u8],
    client_ip: &str,
    local_id: &str,
    local_name: &str,
    local_type: &str,
    bound_port: u16,
    peer_mgr: &Arc<PeerManager>,
) {
    if let Ok((_h, remote_beacon)) = decode_heartbeat_packet_in_place(raw_packet) {
        if remote_beacon.device_id != local_id {
            // SECURITY: 该帧由公开的 PAIR_BOOTSTRAP_KEY 加密，任何同网段主机都能伪造。
            // 因此只允许刷新**已存在**的 peer（探活 / DHCP 换 IP），绝不凭它创建新身份，
            // 否则攻击者可往设备列表塞任意 device_id 冒充待配对设备，或覆盖真实 peer 的端点。
            let updated = peer_mgr.update_existing_peer_only(remote_beacon, client_ip.to_string());
            if !updated {
                // 这是预期内的拒绝（陌生设备 / 设备表已清理），属正常网络噪声，
                // 定在 DEBUG 以免刷屏；排查「设备消失」类问题时再临时打开 DEBUG。
                crate::log_debug!(
                    "忽略来自 {} 的心跳：devid 未在本地设备表中（不凭未认证心跳创建身份）",
                    client_ip
                );
            }
        }
        let reply_beacon = crate::sync::discovery::DiscoveryBeacon {
            magic: crate::sync::discovery::BEACON_MAGIC.to_string(),
            device_id: local_id.to_string(),
            device_name: local_name.to_string(),
            device_type: local_type.to_string(),
            sync_port: bound_port,
            protocol_ver: 1,
            fingerprint: peer_mgr.get_local_fingerprint(),
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            is_reply: true,
            known_peers: peer_mgr.get_gossip_peers(local_id),
        };
        if let Ok(reply_pkt) = encode_heartbeat_packet(sequence, &reply_beacon) {
            let _ = stream.write_all(&reply_pkt);
            let _ = stream.flush();
        }
    }
}

fn handle_unpair_notice_msg(
    stream: &mut TcpStream,
    raw_packet: &mut [u8],
    pfs_key: &[u8; KEY_SIZE],
    authenticated_id: &str,
    peer_mgr: &Arc<PeerManager>,
    unpair_cb_lock: &Arc<RwLock<Option<UnpairCallback>>>,
) {
    if let Ok((_h, unpair_payload)) = decode_unpair_notice_packet_in_place(pfs_key, raw_packet) {
        if !authenticated_id.is_empty() && unpair_payload.from_device_id == authenticated_id {
            peer_mgr.remove_paired_device_id(&unpair_payload.from_device_id);
            // 先释放读锁再回调（同 notify_peer_unpaired）。
            let cb = unpair_cb_lock
                .read()
                .ok()
                .and_then(|guard| guard.as_ref().map(Arc::clone));
            if let Some(cb) = cb {
                cb(unpair_payload.from_device_id);
            }
            let _ = stream.write_all(b"OK");
            let _ = stream.flush();
        } else {
            let _ = stream.write_all(b"ERR_FORGERY");
            let _ = stream.flush();
        }
    } else {
        let _ = stream.write_all(b"ERR_AUTH");
        let _ = stream.flush();
    }
}

fn handle_file_offer_msg(
    mut stream: TcpStream,
    raw_packet: &mut [u8],
    client_ip: &str,
    pfs_key: &[u8; KEY_SIZE],
    authenticated_id: &str,
    peer_mgr: &Arc<PeerManager>,
    ft_mgr: &Arc<FileTransferManager>,
) {
    match decode_file_offer_packet_in_place(pfs_key, raw_packet) {
        Err(_) => {
            let resp = FileResponsePayload {
                transfer_id: String::new(),
                accepted: false,
                error_code: 5,
                error_message: Some("解密失败，会话密钥不匹配".to_string()),
                offset: 0,
            };
            if let Ok(resp_pkt) = encode_file_response_packet(&PAIR_BOOTSTRAP_KEY, 1, &resp) {
                let _ = stream.write_all(&resp_pkt);
                let _ = stream.flush();
            }
        }
        Ok((_h, offer)) => {
            // P1-A: The payload's self-declared device ID MUST match the identity that was
            // authenticated by the PFS handshake. Otherwise a legitimately paired peer could
            // push files (or clipboard content) while impersonating a different paired device.
            if authenticated_id.is_empty() || offer.from_device_id != authenticated_id {
                let resp = FileResponsePayload {
                    transfer_id: String::new(),
                    accepted: false,
                    error_code: 7,
                    error_message: Some("设备身份与已认证会话不符".to_string()),
                    offset: 0,
                };
                if let Ok(resp_pkt) = encode_file_response_packet(pfs_key, 1, &resp) {
                    let _ = stream.write_all(&resp_pkt);
                    let _ = stream.flush();
                }
                return;
            }
            peer_mgr.upsert_incoming_peer(
                &offer.from_device_id,
                &offer.from_device_name,
                client_ip,
                crate::sync::DEFAULT_SYNC_PORT,
                false,
            );
            if !peer_mgr.is_paired(&offer.from_device_id) {
                let resp = FileResponsePayload {
                    transfer_id: offer.transfer_id,
                    accepted: false,
                    error_code: 2,
                    error_message: Some("设备尚未配对，请在设置中先完成配对".to_string()),
                    offset: 0,
                };
                if let Ok(resp_pkt) = encode_file_response_packet(pfs_key, 1, &resp) {
                    let _ = stream.write_all(&resp_pkt);
                    let _ = stream.flush();
                }
            } else {
                let ft_worker = Arc::clone(ft_mgr);
                ft_worker.notify_offer(
                    &offer.transfer_id,
                    &offer.from_device_id,
                    &offer.from_device_name,
                    &offer.file_name,
                    offer.file_size,
                );
                #[cfg(unix)]
                if ft_worker.has_incoming_stream_callback() {
                    use std::os::unix::io::{FromRawFd, IntoRawFd};
                    let raw_fd = stream.into_raw_fd();
                    if ft_worker.try_delegate_incoming_stream(raw_fd, &offer, pfs_key) {
                        return;
                    }
                    let restored = unsafe { TcpStream::from_raw_fd(raw_fd) };
                    let _ = ft_worker.handle_incoming_file_stream(restored, offer, pfs_key);
                    return;
                }
                let _ = ft_worker.handle_incoming_file_stream(stream, offer, pfs_key);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_clipboard_sync_msg(
    stream: &mut TcpStream,
    raw_packet: &mut [u8],
    client_ip: &str,
    local_id: &str,
    pfs_key: &[u8; KEY_SIZE],
    authenticated_id: &str,
    loopback: &Arc<LoopbackFilter>,
    peer_mgr: &Arc<PeerManager>,
    cb_lock: &Arc<RwLock<Option<ClipboardCallback>>>,
) -> bool {
    if let Ok((_h, payload)) = decode_packet_in_place(pfs_key, raw_packet) {
        // P1-A: Bind the payload's self-declared device ID to the identity authenticated by
        // the PFS handshake. Without this, any paired peer could inject clipboard content
        // (and poison the peer endpoint table via upsert_incoming_peer) under another
        // paired peer's device ID.
        if authenticated_id.is_empty() || payload.source_device_id != authenticated_id {
            let _ = stream.write_all(b"ERR_ID_MISMATCH");
            let _ = stream.flush();
            return false;
        }

        peer_mgr.upsert_incoming_peer(
            &payload.source_device_id,
            &payload.source_device_name,
            client_ip,
            crate::sync::DEFAULT_SYNC_PORT,
            false,
        );

        let sender_paired = peer_mgr.is_paired(&payload.source_device_id);
        if payload.content_type != "system/ping" && !sender_paired {
            let _ = stream.write_all(b"ERR_NOT_PAIRED");
            let _ = stream.flush();
            return false;
        }

        // Direct P2P: update local clipboard if from another device and not duplicated.
        // No automatic relay to other peers, preventing unauthorized data leakage across hops.
        if payload.source_device_id != local_id
            && !loopback.is_duplicate_or_record(&payload.content_hash)
            && payload.content_type != "system/ping"
        {
            // 先释放读锁再回调：宿主在回调里可能重设剪贴板回调（需写锁），
            // 持锁调用会当场自死锁。
            let cb = cb_lock
                .read()
                .ok()
                .and_then(|guard| guard.as_ref().map(Arc::clone));
            if let Some(cb) = cb {
                cb(payload);
            }
        }
        let _ = stream.write_all(b"OK");
        let _ = stream.flush();
        // Keep persistent connection open for subsequent clipboard sync packets
        true
    } else {
        let _ = stream.write_all(b"ERR_KEY_MISMATCH");
        let _ = stream.flush();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::AtomicUsize;

    /// 构造一个只为验证 start/stop 生命周期的最小服务端（不涉及配对与鉴权）。
    fn bare_server() -> SyncServer {
        SyncServer::new(
            "dev-test".to_string(),
            "Test Device".to_string(),
            Arc::new(RwLock::new(Some([7u8; KEY_SIZE]))),
            Arc::new(LoopbackFilter::new(16)),
            Arc::new(PeerManager::new("fp-test".to_string())),
            Arc::new(FileTransferManager::new(
                std::env::temp_dir().join("muclip-test-downloads"),
            )),
        )
    }

    /// 并发抢占槽位时，任意时刻的持有数不得超过上限。
    /// 这是「未认证连接不能无限 spawn 线程」的核心保证：
    /// 上限失效即等于把线程数与虚拟内存交给远程随意消耗。
    #[test]
    fn connection_slots_never_exceed_limit_under_concurrency() {
        const MAX: usize = 8;
        const THREADS: usize = 48;

        let counter = Arc::new(AtomicUsize::new(0));
        let held_peak = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::new();

        for _ in 0..THREADS {
            let counter = Arc::clone(&counter);
            let held_peak = Arc::clone(&held_peak);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                if let Some(slot) = ConnectionSlot::try_acquire(Arc::clone(&counter), MAX) {
                    // try_acquire 成功后读到的值即包含自己在内的当前持有数
                    held_peak.fetch_max(counter.load(Ordering::SeqCst), Ordering::SeqCst);
                    thread::sleep(Duration::from_millis(30));
                    drop(slot);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        assert!(
            held_peak.load(Ordering::SeqCst) <= MAX,
            "并发持有数 {} 超过上限 {}，说明上限判断存在竞态",
            held_peak.load(Ordering::SeqCst),
            MAX
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            0,
            "所有槽位必须在 Drop 时归还，否则可用连接数会被永久吃掉"
        );
    }

    /// `stop()` 必须能在无连接到来时及时返回。
    ///
    /// 服务线程是阻塞在 `accept()` 上的（为了让每条连接都被立即受理，而不是靠 50ms
    /// 轮询），所以退出完全依赖 `stop()` 里那次本地回环 connect 把 `accept()` 踢醒。
    /// 一旦这个唤醒失效，`join()` 会永久挂死 —— 用户侧表现为「关掉同步不生效、
    /// 进程关不掉」。这里用带超时的 recv 把这种挂死变成可断言的失败。
    #[test]
    fn stop_wakes_blocked_accept_and_returns_promptly() {
        for _ in 0..3 {
            let server = bare_server();
            let port = server.start(0).expect("server should bind");
            assert_ne!(port, 0, "必须拿到真实监听端口，否则唤醒连接无处可发");

            let (tx, rx) = std::sync::mpsc::channel::<()>();
            let handle = thread::spawn(move || {
                server.stop();
                let _ = tx.send(());
            });

            assert!(
                rx.recv_timeout(Duration::from_secs(5)).is_ok(),
                "stop() 未能在 5s 内返回，说明阻塞的 accept() 没有被唤醒"
            );
            handle.join().unwrap();
        }
    }

    /// 同一端口上反复 start/stop，验证唤醒后服务线程确实完全退出、
    /// 没有残留线程继续持有监听 socket。
    #[test]
    fn start_stop_cycles_release_the_listen_port() {
        let server = bare_server();
        let port = server.start(0).expect("server should bind");
        server.stop();
        server.stop(); // 幂等：未运行时调用不得 panic / 死等

        // 重新在同一个端口上绑定，若上一轮线程没退出，这里会因端口占用失败。
        let again = bare_server();
        let bound = again
            .start(port)
            .expect("port should be rebindable after stop");
        assert_eq!(bound, port, "端口未按请求绑定，可能被上一轮残留线程占用");
        again.stop();
    }
}

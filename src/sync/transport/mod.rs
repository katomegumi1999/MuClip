pub mod client;
pub mod pairing;
pub mod server;

pub use client::{SyncClient, execute_pfs_client_handshake};
pub use server::SyncServer;

use crate::sync::discovery::parse_peer_endpoint;
use crate::sync::protocol::{HEADER_SIZE, SyncHeader, SyncPayload};
use std::collections::VecDeque;
use std::io::Read;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024; // 16 MB max clipboard payload
pub const MAX_PIN_ATTEMPTS: u8 = 3;

/// 帧缓冲区容量超过此值时，若本次帧很小就回缩。见 [`read_framed_packet_into`] 的内存注释。
const BUF_SHRINK_TRIGGER: usize = 1024 * 1024;
/// 收缩目标容量：足够容纳绝大多数剪贴板正文，避免立刻再次扩容。
const BUF_SHRINK_TARGET: usize = 256 * 1024;

pub(crate) fn resolve_socket_addr(peer_addr: &str) -> Result<SocketAddr, TransportError> {
    let (host, port) =
        parse_peer_endpoint(peer_addr, crate::sync::DEFAULT_SYNC_PORT).ok_or_else(|| {
            TransportError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Empty peer address",
            ))
        })?;
    let lookup = format!("{}:{}", host, port);
    let mut addrs = lookup.to_socket_addrs().map_err(TransportError::Io)?;
    addrs.next().ok_or_else(|| {
        TransportError::Io(std::io::Error::new(
            std::io::ErrorKind::AddrNotAvailable,
            format!("Could not resolve address: {}", lookup),
        ))
    })
}

/// Shared packet framing reader: reads `HEADER_SIZE` bytes, parses `SyncHeader`,
/// validates `payload_len <= max_payload_size`, and returns `(SyncHeader, raw_packet)`.
pub(crate) fn read_framed_packet(
    stream: &mut TcpStream,
    max_payload_size: usize,
) -> Result<(SyncHeader, Vec<u8>), TransportError> {
    let mut header_buf = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header_buf)?;

    let header = SyncHeader::parse(&header_buf)?;
    let payload_len = header.payload_len as usize;
    if payload_len > max_payload_size {
        return Err(TransportError::PayloadTooLarge(
            payload_len,
            max_payload_size,
        ));
    }

    let mut raw_packet = vec![0u8; HEADER_SIZE + payload_len];
    raw_packet[..HEADER_SIZE].copy_from_slice(&header_buf);
    stream.read_exact(&mut raw_packet[HEADER_SIZE..])?;

    Ok((header, raw_packet))
}

/// 与 [`read_framed_packet`] 行为一致，但把帧数据读进调用方提供的可复用缓冲区。
///
/// 长连接（剪贴板同步）上每帧都 `vec![0u8; n]` 会在每次 malloc/free 上花时间，
/// 大载荷时更是一次十几 MB 的分配。复用同一块 `Vec` 在容量足够时完全不再分配。
///
/// 返回 `(header, 帧总长)`；`buf[..len]` 即完整帧（含 44 字节头）。
pub(crate) fn read_framed_packet_into(
    stream: &mut TcpStream,
    max_payload_size: usize,
    buf: &mut Vec<u8>,
) -> Result<(SyncHeader, usize), TransportError> {
    let mut header_buf = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header_buf)?;

    let header = SyncHeader::parse(&header_buf)?;
    let payload_len = header.payload_len as usize;
    if payload_len > max_payload_size {
        return Err(TransportError::PayloadTooLarge(
            payload_len,
            max_payload_size,
        ));
    }

    let total_len = HEADER_SIZE + payload_len;

    // MEMORY: 复用缓冲区必须设上限，否则一次大载荷会让该连接永久持有峰值容量。
    //
    // `Vec::clear()` 只把 len 归零，容量原地不动；`resize()` 只在容量不足时增长、
    // 从不收缩。于是「用户复制了一张大图」这类一次性事件，会把这条连接的缓冲区
    // 撑到 MAX_PAYLOAD_SIZE(16 MiB) 并一直保持到连接断开；配合
    // MAX_CONCURRENT_CONNECTIONS(64)，理论驻留峰值 1 GiB。
    //
    // 这个坑在回环基准和开发机上永远复现不出来——只有长时间挂着、偶尔同步过大图的
    // 真实用户会慢慢吃到。收缩阈值 1 MiB 定得偏高是刻意的：剪贴板正文极少超过它，
    // 常规同步不会走进这个分支，也就不会引入 realloc 抖动。
    if total_len < BUF_SHRINK_TARGET && buf.capacity() > BUF_SHRINK_TRIGGER {
        buf.shrink_to(BUF_SHRINK_TARGET);
    }

    // 容量足够时 resize 不会重新分配；新增部分被清零，随后由 read_exact 覆盖
    buf.clear();
    buf.resize(total_len, 0);
    buf[..HEADER_SIZE].copy_from_slice(&header_buf);
    stream.read_exact(&mut buf[HEADER_SIZE..])?;

    Ok((header, total_len))
}

#[derive(Error, Debug)]
pub enum TransportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Protocol error: {0}")]
    Protocol(#[from] crate::sync::protocol::ProtocolError),
    #[error("Crypto error: {0}")]
    Crypto(#[from] crate::sync::crypto::CryptoError),
    #[error("Payload exceeded limit: {0} > {1}")]
    PayloadTooLarge(usize, usize),
    #[error("Sync key not configured")]
    KeyNotConfigured,
    #[error("Server not running")]
    ServerNotRunning,
    #[error("Target peer rejected sync: not paired")]
    NotPairedByPeer,
    #[error("Sync rejected by peer")]
    SyncRejected,
}

/// Thread-safe bounded cache to prevent loopback broadcast loops and redundant syncs.
///
/// `HashSet` + `VecDeque` 双结构：`set` 负责 O(1) 命中判断（原实现是对
/// `VecDeque` 做线性 `iter().any()`，容量 100 时每条同步要比较 100 次字符串），
/// `order` 负责按插入顺序淘汰最旧的一条。
pub struct LoopbackFilter {
    state: Mutex<LoopbackState>,
    capacity: usize,
}

struct LoopbackState {
    /// 淘汰顺序队列，与 `seen` 的内容保持严格一致
    order: VecDeque<String>,
    /// O(1) 命中判断
    seen: std::collections::HashSet<String>,
}

impl LoopbackFilter {
    pub fn new(capacity: usize) -> Self {
        Self {
            state: Mutex::new(LoopbackState {
                order: VecDeque::with_capacity(capacity),
                seen: std::collections::HashSet::with_capacity(capacity),
            }),
            capacity,
        }
    }

    /// Checks if a content hash was recently observed. If not, records it and returns `false`.
    /// Returns `true` if this hash was already processed (meaning loopback or duplicate).
    pub fn is_duplicate_or_record(&self, hash: &str) -> bool {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return false,
        };

        if state.seen.contains(hash) {
            return true;
        }
        self.record(&mut state, hash);
        false
    }

    /// Manually marks a hash as published by the local device so reflections will be dropped.
    pub fn mark_published(&self, hash: &str) {
        let mut state = match self.state.lock() {
            Ok(s) => s,
            Err(_) => return,
        };
        if !state.seen.contains(hash) {
            self.record(&mut state, hash);
        }
    }

    /// 记录一条 hash，并在超出容量时淘汰最旧的一条（同时从 `seen` 移除，保持两结构一致）。
    fn record(&self, state: &mut LoopbackState, hash: &str) {
        if self.capacity == 0 {
            return;
        }
        if state.order.len() >= self.capacity {
            if let Some(evicted) = state.order.pop_front() {
                state.seen.remove(&evicted);
            }
        }
        state.order.push_back(hash.to_string());
        state.seen.insert(hash.to_string());
    }
}

pub type ClipboardCallback = Arc<dyn Fn(SyncPayload) + Send + Sync + 'static>;
pub type PairRequestCallback = Arc<dyn Fn(String, String, String, String) + Send + Sync + 'static>;
pub type PairSuccessCallback = Arc<dyn Fn(String, String, String, String) + Send + Sync + 'static>;
pub type UnpairCallback = Arc<dyn Fn(String) + Send + Sync + 'static>;

pub struct PairAttemptCommand {
    pub pin: String,
    pub accept: bool,
    pub reply_tx: std::sync::mpsc::Sender<i32>,
}

pub struct PendingPairRequest {
    pub created_at: std::time::Instant,
    pub tx: std::sync::mpsc::Sender<PairAttemptCommand>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::derive_key;
    use crate::sync::discovery::PeerManager;
    use crate::sync::file_transfer::FileTransferManager;
    use std::sync::RwLock;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_loopback_filter() {
        let filter = LoopbackFilter::new(5);
        assert!(!filter.is_duplicate_or_record("hash1"));
        assert!(filter.is_duplicate_or_record("hash1"));
        assert!(!filter.is_duplicate_or_record("hash2"));
    }

    /// 淘汰逻辑必须让 `order` 与 `seen` 严格同步：淘汰某条时也要从 set 里移除，
    /// 否则 set 会无限增长（内存泄漏）且已淘汰的 hash 仍被判为重复（误丢同步）。
    #[test]
    fn test_loopback_filter_evicts_oldest_and_keeps_set_consistent() {
        let filter = LoopbackFilter::new(3);

        // 填满 a / b / c（此时均不重复）
        for h in ["a", "b", "c"] {
            assert!(!filter.is_duplicate_or_record(h), "{} 首次出现不应判重", h);
        }
        // 三条都应命中（查询不改变顺序）
        for h in ["a", "b", "c"] {
            assert!(filter.is_duplicate_or_record(h), "{} 应仍在集合内", h);
        }

        // 插入 d，应淘汰最旧的 a
        assert!(!filter.is_duplicate_or_record("d"), "d 是新内容");
        for h in ["b", "c", "d"] {
            assert!(filter.is_duplicate_or_record(h), "{} 应仍在集合内", h);
        }

        // 最后验证 a 确实已被淘汰：再次出现应视为新内容（同时会淘汰 b）
        assert!(
            !filter.is_duplicate_or_record("a"),
            "a 已被淘汰，再次出现必须视为新内容而不是重复"
        );
    }

    #[test]
    fn test_loopback_filter_zero_capacity_never_records() {
        let filter = LoopbackFilter::new(0);
        assert!(!filter.is_duplicate_or_record("x"));
        assert!(
            !filter.is_duplicate_or_record("x"),
            "容量为 0 时不记录任何内容，因此也永远不会判重"
        );
    }

    #[test]
    fn test_sync_server_and_client_e2e() {
        let key = derive_key("e2e-pin-1234", None).unwrap();
        let long_term_key = Arc::new(RwLock::new(Some(key)));
        let loopback = Arc::new(LoopbackFilter::new(100));
        let peer_manager = Arc::new(PeerManager::new("test-fp".into()));

        // Mark device-android-test as paired initially
        peer_manager.add_paired_device_id("device-android-test".into());

        let server = SyncServer::new(
            "device-win-test".into(),
            "Windows Test Device".into(),
            long_term_key.clone(),
            loopback,
            Arc::clone(&peer_manager),
            Arc::new(FileTransferManager::new(std::env::temp_dir())),
        );
        let received_count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&received_count);

        server.set_callback(Arc::new(move |payload| {
            assert_eq!(payload.content, "Test E2EE Sync Content");
            count_clone.fetch_add(1, Ordering::SeqCst);
        }));

        let port = server.start(0).expect("start server");
        assert!(port > 0);

        let client = SyncClient::new();
        let payload = SyncPayload::new_text(
            "device-android-test",
            "Android Phone",
            "Test E2EE Sync Content",
        );

        let res = client.send_payload(&format!("127.0.0.1:{}", port), None, &key, &payload);
        assert!(res.is_ok());

        // Wait for server processing (up to 1s)
        for _ in 0..20 {
            if received_count.load(Ordering::SeqCst) == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(received_count.load(Ordering::SeqCst), 1);

        // Sending same payload again should be blocked by loopback filter
        let _ = client.send_payload(&format!("127.0.0.1:{}", port), None, &key, &payload);
        thread::sleep(Duration::from_millis(150));
        assert_eq!(received_count.load(Ordering::SeqCst), 1); // Still 1, duplicate dropped!

        // Now simulate unpairing: remove device-android-test from server whitelist
        peer_manager.remove_paired_device_id("device-android-test");

        let new_payload = SyncPayload::new_text(
            "device-android-test",
            "Android Phone",
            "Should be rejected because unpaired",
        );
        let unpair_res =
            client.send_payload(&format!("127.0.0.1:{}", port), None, &key, &new_payload);
        assert!(
            matches!(unpair_res, Err(TransportError::NotPairedByPeer)),
            "Unpaired peer must be rejected with NotPairedByPeer"
        );
        assert_eq!(received_count.load(Ordering::SeqCst), 1); // Server dropped it!

        server.stop();
    }

    #[test]
    fn test_direct_connection_without_pfs_handshake_is_rejected() {
        use std::io::Write;
        let key = derive_key("pfs-strict-test", None).unwrap();
        let long_term_key = Arc::new(RwLock::new(Some(key)));
        let loopback = Arc::new(LoopbackFilter::new(100));
        let peer_manager = Arc::new(PeerManager::new("test-fp-strict".into()));
        peer_manager.add_paired_device_id("attacker-node".into());

        let server = SyncServer::new(
            "target-server".into(),
            "Target Server".into(),
            long_term_key,
            loopback,
            Arc::clone(&peer_manager),
            Arc::new(FileTransferManager::new(std::env::temp_dir())),
        );

        let port = server.start(0).expect("start server");
        assert!(port > 0);

        // Attacker or legacy client connects and sends CLIPBOARD_SYNC packet directly without MSG_SESSION_INIT
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        let payload =
            SyncPayload::new_text("attacker-node", "Attacker", "Legacy unauthenticated sync");
        let packet = crate::sync::protocol::encode_packet(
            &key,
            crate::sync::protocol::MSG_CLIPBOARD_SYNC,
            1,
            &payload,
        )
        .unwrap();
        stream.write_all(&packet).unwrap();
        stream.flush().unwrap();

        let mut ack = [0u8; 32];
        let n = stream.read(&mut ack).unwrap_or(0);
        assert!(n >= 14, "Expected error response from server");
        assert_eq!(
            &ack[..14],
            b"ERR_NO_SESSION",
            "Server must reject packets sent without PFS session handshake"
        );

        server.stop();
    }

    /// 载荷里自称的设备 ID 必须与 PFS 握手认证的身份一致。
    /// 否则任何已配对设备都能冒充另一台已配对设备注入剪贴板内容，并把其端点表指向自己。
    #[test]
    fn test_payload_device_id_must_match_authenticated_session() {
        use std::io::Write;

        let key = derive_key("identity-binding-test", None).unwrap();
        let long_term_key = Arc::new(RwLock::new(Some(key)));
        let loopback = Arc::new(LoopbackFilter::new(100));
        let peer_manager = Arc::new(PeerManager::new("test-fp-identity".into()));
        peer_manager.add_paired_device_id("node-a".into());
        peer_manager.add_paired_device_id("node-b".into());

        let server = SyncServer::new(
            "target-server".into(),
            "Target Server".into(),
            long_term_key,
            Arc::clone(&loopback),
            Arc::clone(&peer_manager),
            Arc::new(FileTransferManager::new(std::env::temp_dir())),
        );

        let port = server.start(0).expect("start server");
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

        // 以 node-a 的身份完成 PFS 握手
        let session_key = execute_pfs_client_handshake(&mut stream, "node-a", None, &key, 1)
            .expect("handshake as node-a");

        // 但载荷谎称来自 node-b
        let payload = SyncPayload::new_text("node-b", "B Device", "spoofed clipboard content");
        let packet = crate::sync::protocol::encode_packet(
            &session_key,
            crate::sync::protocol::MSG_CLIPBOARD_SYNC,
            2,
            &payload,
        )
        .unwrap();
        stream.write_all(&packet).unwrap();
        stream.flush().unwrap();

        let mut ack = [0u8; 32];
        let n = stream.read(&mut ack).unwrap_or(0);
        assert_eq!(
            &ack[..n],
            b"ERR_ID_MISMATCH",
            "载荷设备 ID 与已认证身份不一致时必须拒绝，否则可跨设备冒充"
        );

        server.stop();
    }

    #[test]
    fn test_single_stream_pair_handshake_e2e() {
        let server_key = Arc::new(RwLock::new(None));
        let loopback = Arc::new(LoopbackFilter::new(100));
        let peer_manager = Arc::new(PeerManager::new("test-fp-handshake".into()));

        let server = Arc::new(SyncServer::new(
            "server-dev-1".into(),
            "Server Device".into(),
            server_key.clone(),
            loopback,
            peer_manager.clone(),
            Arc::new(FileTransferManager::new(std::env::temp_dir())),
        ));

        let attempt_counter = Arc::new(AtomicUsize::new(0));
        let attempt_clone = Arc::clone(&attempt_counter);
        let server_ref = Arc::clone(&server);

        server.set_pair_request_callback(Arc::new(move |req_id, from_id, from_name, _ip| {
            assert_eq!(from_id, "client-dev-1");
            assert_eq!(from_name, "Client Device");
            let attempt = attempt_clone.fetch_add(1, Ordering::SeqCst);

            let s = Arc::clone(&server_ref);
            thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                if attempt == 0 {
                    // First request: 3 wrong PIN attempts -> 2, 2, then 3 (invalidated on 3rd strike!)
                    assert_eq!(s.respond_pair(&req_id, "999991", true), 2);
                    assert_eq!(s.respond_pair(&req_id, "999992", true), 2);
                    assert_eq!(s.respond_pair(&req_id, "999993", true), 3);
                    // Retrying on the invalidated req_id must return 1 (not found/invalidated)
                    assert_eq!(s.respond_pair(&req_id, "123456", true), 1);
                } else {
                    // Second request with fresh PIN: 1 wrong attempt (returns 2), then right PIN on 2nd try (returns 0)!
                    assert_eq!(s.respond_pair(&req_id, "000000", true), 2);
                    assert_eq!(s.respond_pair(&req_id, "654321", true), 0);
                }
            });
        }));

        let port = server.start(0).expect("start server");
        assert!(port > 0);

        let client = SyncClient::new();
        // Attempt 1: wrong PIN entered on responder -> immediately rejected with error_code = 2
        let failed_resp = client
            .request_pair(
                &format!("127.0.0.1:{}", port),
                "client-dev-1",
                "Client Device",
                "123456",
                5,
            )
            .expect("pair handshake attempt 1");
        assert!(!failed_resp.accepted);
        assert_eq!(failed_resp.error_code, 2);

        // Attempt 2: fresh PIN generated and entered -> succeeds!
        let pair_resp = client
            .request_pair(
                &format!("127.0.0.1:{}", port),
                "client-dev-1",
                "Client Device",
                "654321",
                5,
            )
            .expect("pair handshake attempt 2");

        assert!(pair_resp.accepted);
        assert_eq!(pair_resp.responder_device_id, "server-dev-1");
        assert_eq!(pair_resp.responder_device_name, "Server Device");
        assert_eq!(pair_resp.error_code, 0);

        // Verify SPAKE2 derived pairwise key matches on both initiator and responder:
        let client_ltk_hex = pair_resp
            .long_term_key_hex
            .expect("pairwise key from handshake");

        let mut server_key_bytes = None;
        for _ in 0..100 {
            if let Some(k) = peer_manager.get_peer_key("client-dev-1") {
                server_key_bytes = Some(k);
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        let server_key_bytes =
            server_key_bytes.expect("server pairwise key stored in peer_manager");
        let server_ltk_hex = crate::sync::crypto::bytes_to_hex(&server_key_bytes);
        assert_eq!(
            client_ltk_hex, server_ltk_hex,
            "SPAKE2 pairwise key must match perfectly on both sides!"
        );

        server.stop();
    }

    /// `MSG_HEARTBEAT` 用公开的 `PAIR_BOOTSTRAP_KEY` 加密，同网段任何主机都能构造出合法帧。
    /// 服务端不得凭未认证心跳在设备表中创建新身份，否则攻击者可伪装成"待配对的某台设备"。
    #[test]
    fn test_forged_heartbeat_cannot_inject_peer_identity() {
        use std::io::Write;

        let peer_manager = Arc::new(PeerManager::new("test-fp-heartbeat".into()));
        let server = SyncServer::new(
            "local-server".into(),
            "Local Server".into(),
            Arc::new(RwLock::new(None)),
            Arc::new(LoopbackFilter::new(100)),
            Arc::clone(&peer_manager),
            Arc::new(FileTransferManager::new(std::env::temp_dir())),
        );
        let port = server.start(0).expect("start server");

        // 攻击者视角：用公开的 bootstrap key 构造一个格式完全合法的心跳
        let forged = crate::sync::discovery::DiscoveryBeacon {
            magic: crate::sync::discovery::BEACON_MAGIC.to_string(),
            device_id: "attacker-device".into(),
            device_name: "Totally Legit Phone".into(),
            device_type: "Android".into(),
            sync_port: 42424,
            protocol_ver: 1,
            fingerprint: "deadbeef".into(),
            timestamp_ms: 1,
            is_reply: false,
            known_peers: Vec::new(),
        };
        let packet = crate::sync::protocol::encode_heartbeat_packet(1, &forged).expect("encode");
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", port)).expect("connect");
        stream.write_all(&packet).expect("send heartbeat");
        stream.flush().expect("flush");

        // 服务端先更新设备表再回 beacon，读到回包即说明处理已完成
        let mut reply = [0u8; 2048];
        let _ = stream.read(&mut reply);

        assert!(
            !peer_manager
                .get_all_peers()
                .iter()
                .any(|p| p.device_id == "attacker-device"),
            "未认证心跳不得在设备表中创建新条目（peer 表投毒）"
        );

        server.stop();
    }

    #[test]
    fn test_sync_server_file_transfer_e2e() {
        let key = derive_key("transfer-pin-1234", None).unwrap();
        let long_term_key = Arc::new(RwLock::new(Some(key)));
        let loopback = Arc::new(LoopbackFilter::new(100));
        let peer_manager = Arc::new(PeerManager::new("test-fp-ft".into()));

        let temp_dir =
            std::env::temp_dir().join(format!("muclip_test_trans_{}", rand::random::<u32>()));
        let recv_dir = temp_dir.join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let src_file = temp_dir.join("test.txt");
        std::fs::write(&src_file, b"Hello MuClip File Transfer!").unwrap();

        let ft_receiver = Arc::new(FileTransferManager::new(&recv_dir));
        let server = SyncServer::new(
            "device-receiver".into(),
            "Receiver Device".into(),
            long_term_key.clone(),
            loopback,
            Arc::clone(&peer_manager),
            ft_receiver,
        );

        let port = server.start(0).expect("start server");
        let peer_addr = format!("127.0.0.1:{}", port);

        // Sender manager
        let ft_sender = Arc::new(FileTransferManager::new(&temp_dir));

        // Sub-test 1: Not paired yet
        let send_res_unpaired = ft_sender.send_file(
            "tid_unpaired",
            &peer_addr,
            src_file.to_str().unwrap(),
            "device-sender",
            "Sender Device",
            &key,
        );
        println!("Unpaired send_res: {:?}", send_res_unpaired);

        // Now pair the device
        peer_manager.add_paired_device_id("device-sender".into());

        // Sub-test 2: Paired
        let send_res_paired = ft_sender.send_file(
            "tid_paired",
            &peer_addr,
            src_file.to_str().unwrap(),
            "device-sender",
            "Sender Device",
            &key,
        );
        println!("Paired send_res: {:?}", send_res_paired);

        // Sub-test 3: Key mismatch (different PIN)
        let wrong_key = derive_key("different-pin", None).unwrap();
        let send_res_wrong_key = ft_sender.send_file(
            "tid_wrong_key",
            &peer_addr,
            src_file.to_str().unwrap(),
            "device-sender",
            "Sender Device",
            &wrong_key,
        );
        println!("Wrong key send_res: {:?}", send_res_wrong_key);

        // Sub-test 4: Server has None session key
        *long_term_key.write().unwrap() = None;
        let send_res_no_key = ft_sender.send_file(
            "tid_no_key",
            &peer_addr,
            src_file.to_str().unwrap(),
            "device-sender",
            "Sender Device",
            &key,
        );
        println!("No server key send_res: {:?}", send_res_no_key);

        server.stop();
        let _ = std::fs::remove_dir_all(&temp_dir);

        assert!(
            send_res_paired.is_ok(),
            "Paired send should succeed, got: {:?}",
            send_res_paired
        );
    }
}

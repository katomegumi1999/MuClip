mod receiver;
mod sender;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

pub const BULK_CHUNK_SIZE: usize = 128 * 1024; // 128 KiB fixed chunk AEAD
pub const FILE_STREAM_BUFFER_SIZE: usize = BULK_CHUNK_SIZE;

/// Windows 保留设备名：这些名字（含带扩展名的形式）会被 OS 解析为设备而非文件。
const WINDOWS_RESERVED_NAMES: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// 把对端提供的文件名净化为**单个安全文件名**，供 `save_dir.join()` 使用。
///
/// 对端（`FileOfferPayload.file_name`）完全不可信。若直接 `save_dir.join(name)`：
/// - 绝对路径（`C:\Windows\System32\x.dll`）会**替换掉整个 save_dir**；
/// - `..\..\..\..\...\Startup\x.bat` 会逃出保存目录，落到登录启动项。
/// 二者都能让已配对（甚至仅完成 PFS 握手）的对端实现任意文件写入。
///
/// 规则：只保留最后一段路径组件，剔除 Windows 上会导致解析歧义的字符，拒绝保留设备名。
fn sanitize_file_name(raw: &str) -> String {
    // 1. 只取最后一段：挡掉目录穿越、绝对路径、盘符、UNC 前缀
    let base = std::path::Path::new(raw)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // 2. 剔除控制字符、路径分隔符（file_name() 一般已挡，防御式再查）、
    //    ':'（NTFS 备用数据流 `a.txt::$DATA`）与 Windows 非法字符
    let cleaned: String = base
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        })
        .collect();

    // 3. 去掉结尾的点与空格：Windows 会静默截断，导致 `a.` 变成 `a` 覆盖另一文件
    let trimmed = cleaned.trim_end_matches(['.', ' ']).trim_start();

    // 4. 空名 / "." / ".." 一律拒绝
    if trimmed.is_empty() || trimmed == "." || trimmed == ".." {
        return "unnamed_file".to_string();
    }

    // 5. 挡 Windows 保留设备名（比较时忽略扩展名）
    let stem_upper = trimmed
        .split('.')
        .next()
        .unwrap_or(trimmed)
        .to_ascii_uppercase();
    if WINDOWS_RESERVED_NAMES.contains(&stem_upper.as_str()) {
        return format!("_{}", trimmed);
    }

    // 6. 限制长度（按字符截断，避免切断 UTF-8 序列）
    const MAX_NAME_CHARS: usize = 180;
    if trimmed.chars().count() > MAX_NAME_CHARS {
        return trimmed.chars().take(MAX_NAME_CHARS).collect();
    }

    trimmed.to_string()
}

/// 把对端提供的 `transfer_id` 净化为安全的临时文件名主干。
/// 该值会被拼进 `.tmp` 文件名，同样存在穿越风险，且只应允许标识符字符。
fn sanitize_transfer_id(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
        .take(64)
        .collect();
    if cleaned.is_empty() {
        format!("t{}", rand::random::<u32>())
    } else {
        cleaned
    }
}

pub type FileProgressCallback = Arc<dyn Fn(&str, u64, u64, u64, bool) + Send + Sync + 'static>;
pub type FileCompletedCallback = Arc<dyn Fn(&str, &str, bool, bool, &str) + Send + Sync + 'static>;
pub type FileOfferCallback = Arc<dyn Fn(&str, &str, &str, &str, u64) + Send + Sync + 'static>;
pub type IncomingFileStreamCallback = Arc<
    dyn Fn(i32, &crate::sync::protocol::FileOfferPayload, &[u8; 32]) -> bool
        + Send
        + Sync
        + 'static,
>;

/// 取消原语已上移到 [`crate::sync::cancel`]：PFS 会话握手（transport 层）也要用
/// 同一套机制，而 transport 是 file_transfer 的下层，不能反过来依赖它。
///
/// 这里保留同名重导出，子模块（sender / receiver）继续用 `super::XXX` 引用。
pub(crate) use crate::sync::cancel::{
    CANCEL_POLL_INTERVAL, CancelToken, IoAbort, read_exact_cancellable, write_all_cancellable,
};

#[derive(Default)]
pub struct FileTransferManager {
    cancel_flags: Arc<Mutex<HashMap<String, Arc<CancelToken>>>>,
    save_directory: Arc<RwLock<PathBuf>>,
    progress_callback: Arc<RwLock<Option<FileProgressCallback>>>,
    completed_callback: Arc<RwLock<Option<FileCompletedCallback>>>,
    offer_callback: Arc<RwLock<Option<FileOfferCallback>>>,
    incoming_stream_callback: Arc<RwLock<Option<IncomingFileStreamCallback>>>,
}

impl FileTransferManager {
    pub fn new(default_save_dir: impl Into<PathBuf>) -> Self {
        Self {
            cancel_flags: Arc::new(Mutex::new(HashMap::new())),
            save_directory: Arc::new(RwLock::new(default_save_dir.into())),
            progress_callback: Arc::new(RwLock::new(None)),
            completed_callback: Arc::new(RwLock::new(None)),
            offer_callback: Arc::new(RwLock::new(None)),
            incoming_stream_callback: Arc::new(RwLock::new(None)),
        }
    }

    pub fn set_save_directory(&self, path: impl Into<PathBuf>) {
        if let Ok(mut g) = self.save_directory.write() {
            *g = path.into();
        }
    }

    pub fn get_save_directory(&self) -> PathBuf {
        self.save_directory
            .read()
            .map(|g| g.clone())
            .unwrap_or_else(|_| PathBuf::from("."))
    }

    pub fn set_progress_callback(&self, cb: FileProgressCallback) {
        if let Ok(mut g) = self.progress_callback.write() {
            *g = Some(cb);
        }
    }

    pub fn set_completed_callback(&self, cb: FileCompletedCallback) {
        if let Ok(mut g) = self.completed_callback.write() {
            *g = Some(cb);
        }
    }

    pub fn set_offer_callback(&self, cb: FileOfferCallback) {
        if let Ok(mut g) = self.offer_callback.write() {
            *g = Some(cb);
        }
    }

    pub fn set_incoming_stream_callback(&self, cb: IncomingFileStreamCallback) {
        if let Ok(mut g) = self.incoming_stream_callback.write() {
            *g = Some(cb);
        }
    }

    pub fn try_delegate_incoming_stream(
        &self,
        raw_fd: i32,
        offer: &crate::sync::protocol::FileOfferPayload,
        bulk_key: &[u8; 32],
    ) -> bool {
        // 同 notify_progress：克隆后立刻释放读锁，避免用户回调内再次设置回调时自死锁。
        let cb = self
            .incoming_stream_callback
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        match cb {
            Some(cb) => cb(raw_fd, offer, bulk_key),
            None => false,
        }
    }

    pub fn has_incoming_stream_callback(&self) -> bool {
        self.incoming_stream_callback
            .read()
            .map(|g| g.is_some())
            .unwrap_or(false)
    }

    /// 请求取消一次传输。
    ///
    /// 返回 `true` 表示找到并置位了该传输的取消令牌；`false` 表示该 transfer_id
    /// 不在进行中（已完成 / 不存在）。
    ///
    /// 真正的「停下来」由 `read_exact_cancellable` / `write_all_cancellable` 在
    /// 下一次轮询检查时完成，延迟上限 `CANCEL_POLL_INTERVAL`。
    pub fn cancel_transfer(&self, transfer_id: &str) -> bool {
        let token = self
            .cancel_flags
            .lock()
            .ok()
            .and_then(|flags| flags.get(transfer_id).map(Arc::clone));
        match token {
            Some(token) => {
                token.cancel();
                true
            }
            None => false,
        }
    }

    pub(super) fn register_cancel_flag(&self, transfer_id: &str) -> Arc<CancelToken> {
        let token = Arc::new(CancelToken::new());
        if let Ok(mut flags) = self.cancel_flags.lock() {
            flags.insert(transfer_id.to_string(), Arc::clone(&token));
        }
        token
    }

    pub(super) fn unregister_cancel_flag(&self, transfer_id: &str) {
        if let Ok(mut flags) = self.cancel_flags.lock() {
            flags.remove(transfer_id);
        }
    }

    /// 该传输是否已被请求取消。
    ///
    /// 用于在错误上报前做一次「兜底翻译」：取消会 shutdown socket，各处的阻塞
    /// IO 报上来都是网络错误，若不翻译，上层会提示「传输失败，请检查网络」。
    pub(super) fn is_transfer_cancelled(&self, transfer_id: &str) -> bool {
        self.cancel_flags
            .lock()
            .ok()
            .and_then(|flags| flags.get(transfer_id).map(Arc::clone))
            .map(|token| token.is_cancelled())
            .unwrap_or(false)
    }

    /// 回调派发：**先克隆 Arc 并释放读锁，再调用用户代码**。
    ///
    /// 原实现写作 `if let Ok(guard) = self.x.read() { cb(..) }`——读锁在整个调用期间
    /// 一直持有，而 std 的 `RwLock` **不可重入**。用户在回调里只要调一次对应的
    /// `set_*_callback`（需要写锁）就会自死锁：回调线程等写锁，写锁等读锁释放。
    /// 这类死锁不报错、不打日志，表现为整条同步线程静默卡死，只能杀进程。
    ///
    /// 克隆 `Arc<dyn Fn>` 的成本是一次原子自增，换掉一个不可诊断的挂起，值得。
    pub(super) fn notify_progress(
        &self,
        transfer_id: &str,
        transferred: u64,
        total: u64,
        speed_bps: u64,
        is_send: bool,
    ) {
        let cb = self
            .progress_callback
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        if let Some(cb) = cb {
            cb(transfer_id, transferred, total, speed_bps, is_send);
        }
    }

    /// 见 [`Self::notify_progress`] 关于「为什么不在持锁时调用回调」的说明。
    pub(super) fn notify_completed(
        &self,
        transfer_id: &str,
        file_path: &str,
        is_send: bool,
        success: bool,
        error_msg: &str,
    ) {
        let cb = self
            .completed_callback
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        if let Some(cb) = cb {
            cb(transfer_id, file_path, is_send, success, error_msg);
        }
    }

    /// 见 [`Self::notify_progress`] 关于「为什么不在持锁时调用回调」的说明。
    pub fn notify_offer(
        &self,
        transfer_id: &str,
        from_id: &str,
        from_name: &str,
        file_name: &str,
        file_size: u64,
    ) {
        let cb = self
            .offer_callback
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        if let Some(cb) = cb {
            cb(transfer_id, from_id, from_name, file_name, file_size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::derive_key;
    use crate::sync::protocol::{FileOfferPayload, HEADER_SIZE, SyncHeader};
    use std::io::Read;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    /// 回归测试：在回调内部重新设置同一个回调不得死锁。
    ///
    /// 修复前 `notify_progress` 在**持有读锁**期间调用用户回调，而 `set_progress_callback`
    /// 需要写锁，于是：回调线程等写锁、写锁等读锁释放 —— 永久挂起且没有任何报错。
    ///
    /// 这里把 `notify_progress` 放到独立线程跑，主线程带超时等待：如果回归了，
    /// 表现是 3 秒后 panic，而不是整个测试进程挂死（后者在 CI 上非常难诊断）。
    #[test]
    fn callback_reentrant_setter_does_not_deadlock() {
        let mgr = Arc::new(FileTransferManager::new(std::env::temp_dir()));

        let mgr_for_cb = Arc::clone(&mgr);
        mgr.set_progress_callback(Arc::new(move |_, _, _, _, _| {
            // 关键：回调里回头设置回调（需要写锁）
            mgr_for_cb.set_progress_callback(Arc::new(|_, _, _, _, _| {}));
        }));

        let mgr_for_thread = Arc::clone(&mgr);
        let worker = std::thread::spawn(move || {
            mgr_for_thread.notify_progress("t-reentrant", 1, 2, 3, true);
        });

        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while std::time::Instant::now() < deadline {
            if worker.is_finished() {
                // 已返回：正常。再 join 拿到可能存在的 panic。
                let _ = worker.join();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("回调内向同一管理器重设回调时发生死锁：3 秒内未返回");
    }

    #[test]
    fn test_sanitize_file_name_blocks_path_traversal() {
        // 对端可在 FileOfferPayload.file_name 里塞任意字符串，此处覆盖典型攻击形态
        let cases = [
            ("normal.txt", "normal.txt"),
            ("报告 2026.pdf", "报告 2026.pdf"),
            // 绝对路径：必须退化成末段文件名，绝不能替换 save_dir
            (r"C:\Windows\System32\evil.dll", "evil.dll"),
            ("/etc/passwd", "passwd"),
            // 目录穿越
            (r"..\..\..\..\Windows\System32\evil.dll", "evil.dll"),
            ("../../../../etc/cron.d/x", "x"),
            (
                r"..\..\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\x.bat",
                "x.bat",
            ),
            // 空名与点
            ("", "unnamed_file"),
            (".", "unnamed_file"),
            ("..", "unnamed_file"),
            // 结尾点/空格：Windows 会静默截断，导致覆盖同名文件
            ("evil.", "evil"),
            ("evil   ", "evil"),
            // Windows 保留设备名
            ("CON", "_CON"),
            ("nul.txt", "_nul.txt"),
            ("COM1.log", "_COM1.log"),
            // NTFS 备用数据流
            ("a.txt::$DATA", "a.txt$DATA"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sanitize_file_name(input),
                expected,
                "净化结果不符合预期，input={:?}",
                input
            );
        }
    }

    #[test]
    fn test_sanitize_transfer_id_keeps_only_identifier_chars() {
        assert_eq!(sanitize_transfer_id("tid-123_abc"), "tid-123_abc");
        assert_eq!(sanitize_transfer_id(r"..\..\evil"), "evil");
        assert_eq!(sanitize_transfer_id("a/b"), "ab");
        // 全非法时随机兜底，必须非空（否则会生成 ".tmp" 隐藏文件）
        assert!(!sanitize_transfer_id("......").is_empty());
    }

    #[test]
    fn test_file_transfer_end_to_end() {
        let key = derive_key("transfer_test_pin", None).unwrap();
        let temp_dir = std::env::temp_dir().join(format!("muclip_test_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let src_file = temp_dir.join("test_send.bin");
        let test_data = vec![0x42u8; 300 * 1024]; // 300 KB (3 chunks: 128KB + 128KB + 44KB)
        std::fs::write(&src_file, &test_data).unwrap();

        let recv_dir = temp_dir.join("recv");
        std::fs::create_dir_all(&recv_dir).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let peer_addr = format!("127.0.0.1:{}", port);

        let ft_receiver = Arc::new(FileTransferManager::new(&recv_dir));
        let ft_sender = Arc::new(FileTransferManager::new(&temp_dir));

        let progress_received = Arc::new(AtomicU64::new(0));
        let progress_clone = Arc::clone(&progress_received);
        ft_receiver.set_progress_callback(Arc::new(
            move |_tid, transferred, _total, _speed, is_send| {
                assert!(!is_send);
                progress_clone.store(transferred, Ordering::SeqCst);
            },
        ));

        let ft_recv_clone = Arc::clone(&ft_receiver);
        let key_clone = key;
        let recv_handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
            let mut header_buf = [0u8; HEADER_SIZE];
            stream.read_exact(&mut header_buf).unwrap();
            let header = SyncHeader::parse(&header_buf).unwrap();
            let mut raw_packet = vec![0u8; HEADER_SIZE + header.payload_len as usize];
            raw_packet[..HEADER_SIZE].copy_from_slice(&header_buf);
            stream.read_exact(&mut raw_packet[HEADER_SIZE..]).unwrap();

            let (offer, active_key) = if header.msg_type == crate::sync::protocol::MSG_SESSION_INIT
            {
                use std::io::Write;
                let (_h, init_payload) =
                    crate::sync::protocol::decode_session_init_packet_in_place(&mut raw_packet)
                        .unwrap();
                let server_ex = crate::sync::crypto::KeyExchangeSession::new();
                let server_pk = server_ex.public_key;
                let shared = server_ex.compute_shared_secret(&init_payload.ephemeral_pk);
                let pfs_key = *crate::sync::crypto::derive_pfs_session_key(
                    &*shared,
                    &key_clone,
                    &init_payload.challenge,
                );
                let resp_tag = crate::sync::crypto::compute_session_auth_tag(
                    &key_clone,
                    &init_payload.client_device_id,
                    "receiver_dev",
                    &server_pk,
                    Some(&init_payload.ephemeral_pk),
                    "responder",
                    &init_payload.challenge,
                );
                let resp_payload = crate::sync::protocol::SessionRespPayload {
                    responder_device_id: "receiver_dev".to_string(),
                    ephemeral_pk: server_pk,
                    auth_tag: resp_tag,
                    accepted: true,
                };
                let resp_pkt = crate::sync::protocol::encode_session_resp_packet(
                    header.sequence + 1,
                    &resp_payload,
                )
                .unwrap();
                stream.write_all(&resp_pkt).unwrap();
                stream.flush().unwrap();

                // Read subsequent file offer packet encrypted with negotiated PFS key
                stream.read_exact(&mut header_buf).unwrap();
                let next_header = SyncHeader::parse(&header_buf).unwrap();
                raw_packet.resize(HEADER_SIZE + next_header.payload_len as usize, 0);
                raw_packet[..HEADER_SIZE].copy_from_slice(&header_buf);
                stream.read_exact(&mut raw_packet[HEADER_SIZE..]).unwrap();
                let (_h, offer) =
                    crate::sync::protocol::decode_file_offer_packet(&pfs_key, &raw_packet).unwrap();
                (offer, pfs_key)
            } else {
                let (_h, offer) =
                    crate::sync::protocol::decode_file_offer_packet(&key_clone, &raw_packet)
                        .unwrap();
                (offer, key_clone)
            };
            ft_recv_clone.handle_incoming_file_stream(stream, offer, &active_key)
        });

        let send_res = ft_sender.send_file(
            "test_transfer_1",
            &peer_addr,
            src_file.to_str().unwrap(),
            "sender_dev",
            "Sender",
            &key,
        );

        assert!(send_res.is_ok(), "send_file error: {:?}", send_res);
        let recv_res = recv_handle.join().unwrap();
        assert!(recv_res.is_ok(), "receive error: {:?}", recv_res);

        let received_path = recv_res.unwrap();
        let received_data = std::fs::read(&received_path).unwrap();
        assert_eq!(received_data, test_data);
        // Ensure .tmp file is cleaned up / renamed
        assert!(!recv_dir.join("test_transfer_1.tmp").exists());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_file_transfer_notifies_completed_on_connection_failure() {
        let key = derive_key("transfer_fail_test", None).unwrap();
        let temp_dir =
            std::env::temp_dir().join(format!("muclip_test_fail_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let src_file = temp_dir.join("test_send.bin");
        std::fs::write(&src_file, b"test content").unwrap();

        let ft_sender = Arc::new(FileTransferManager::new(&temp_dir));

        let failed_tid = Arc::new(std::sync::Mutex::new(String::new()));
        let failed_err = Arc::new(std::sync::Mutex::new(String::new()));
        let failed_success = Arc::new(std::sync::atomic::AtomicBool::new(true));

        let tid_clone = Arc::clone(&failed_tid);
        let err_clone = Arc::clone(&failed_err);
        let succ_clone = Arc::clone(&failed_success);

        ft_sender.set_completed_callback(Arc::new(move |tid, _path, is_send, success, err| {
            assert!(is_send);
            succ_clone.store(success, Ordering::SeqCst);
            *tid_clone.lock().unwrap() = tid.to_string();
            *err_clone.lock().unwrap() = err.to_string();
        }));

        let unreachable_addr = "127.0.0.1:59999";
        let res = ft_sender.send_file(
            "transfer_err_123",
            unreachable_addr,
            src_file.to_str().unwrap(),
            "sender_dev",
            "Sender",
            &key,
        );

        assert!(
            res.is_err(),
            "Expected send_file to fail for unreachable peer"
        );
        assert_eq!(*failed_tid.lock().unwrap(), "transfer_err_123");
        assert!(!failed_success.load(Ordering::SeqCst));
        assert!(!failed_err.lock().unwrap().is_empty());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 取消必须能打断**阻塞在 `read_exact` 上**的接收端。
    ///
    /// 复现场景：对端发完 offer 就不再发送任何 chunk（WiFi 掉线 / 对端卡死）。
    /// - 修复前：`cancel_flag` 只在 128 KiB 块之间检查，而线程卡在 `read_exact`
    ///   里根本轮不到检查，取消要干等 30s 读超时才生效 —— 用户体感是
    ///   「点了取消，程序卡死了」。
    /// - 修复后：取消会 `shutdown` 底层 socket，阻塞读立刻返回。
    ///
    /// 同时断言错误被识别成「已取消」而不是网络故障，否则上层会提示
    /// 「传输失败，请检查网络」，把一次正常操作报成事故。
    #[test]
    fn cancel_interrupts_receiver_blocked_on_chunk_read() {
        let key = derive_key("cancel_test_pin", None).unwrap();
        let recv_dir =
            std::env::temp_dir().join(format!("muclip_cancel_recv_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&recv_dir).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // 假发送端：连上 -> 把接收端的 acceptance response 读掉 -> 之后一个字节都不发。
        // 读到 response 即证明接收端已完成初始化，下一步必然是阻塞在等第一个 chunk。
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let client = std::thread::spawn(move || {
            let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut hdr = [0u8; HEADER_SIZE];
            if stream.read_exact(&mut hdr).is_err() {
                return;
            }
            let h = SyncHeader::parse(&hdr).unwrap();
            let mut rest = vec![0u8; h.payload_len as usize];
            let _ = stream.read_exact(&mut rest);
            // 保持连接但静默，让接收端卡在 read_exact 上
            let _ = stop_rx.recv_timeout(Duration::from_secs(10));
        });

        let offer = FileOfferPayload {
            transfer_id: "cancel_tid".to_string(),
            from_device_id: "devA".to_string(),
            from_device_name: "A".to_string(),
            file_name: "big.bin".to_string(),
            // 远大于一个 chunk，确保一定会进入 chunk 循环
            file_size: 8 * 1024 * 1024,
            sha256: String::new(),
            mime_type: "application/octet-stream".to_string(),
            stream_nonce: None,
            stream_salt: Some([7u8; 16]),
            offset: 0,
            chunk_size: BULK_CHUNK_SIZE as u32,
            total_chunks: 64,
        };

        let mgr = Arc::new(FileTransferManager::new(&recv_dir));
        let mgr_recv = Arc::clone(&mgr);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let r = mgr_recv.handle_incoming_file_stream(stream, offer, &key);
            let _ = done_tx.send(r);
        });

        // 留出时间让接收端写完 response 并进入阻塞读
        std::thread::sleep(Duration::from_millis(400));

        let t0 = std::time::Instant::now();
        assert!(
            mgr.cancel_transfer("cancel_tid"),
            "取消请求应命中在途传输（说明 token 已注册）"
        );
        let res = done_rx.recv_timeout(Duration::from_secs(5)).expect(
            "取消后接收端必须尽快返回；若这里超时，说明 read_exact_cancellable 的轮询没生效",
        );
        let elapsed = t0.elapsed();

        let err = res.expect_err("被取消的传输不应返回成功");
        assert!(
            err.contains("canceled"),
            "取消应被识别成「已取消」，实际错误: {}",
            err
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "取消耗时 {:?}，远超预期（修复前是 30s 读超时），轮询间隔可能没被应用",
            elapsed
        );

        let _ = stop_tx.send(());
        let _ = client.join();
        let _ = std::fs::remove_dir_all(&recv_dir);
    }

    /// 取消必须能打断**发送端在等对端 response** 时的阻塞读。
    ///
    /// 真实场景：接收端弹窗问「是否接收」，用户迟迟不点，发送端一直卡在等
    /// response 的 read 上 —— 此前必须等 30s 读超时才能取消。
    ///
    /// 这条同时验证发送端的接线：`write_all_cancellable` /
    /// `read_exact_cancellable` 确实拿到了 cancel_flag。这类漏传在编译期发现不了
    /// （参数类型一致），只能靠端到端跑一次。
    #[test]
    fn cancel_interrupts_sender_waiting_for_peer_response() {
        let key = derive_key("cancel_send_pin", None).unwrap();
        let temp_dir =
            std::env::temp_dir().join(format!("muclip_cancel_send_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let src = temp_dir.join("payload.bin");
        std::fs::write(&src, vec![0x11u8; 256 * 1024]).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let key_clone = key;
        let server = std::thread::spawn(move || {
            use std::io::Write;
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));

            // 完成 PFS 握手（与 test_file_transfer_end_to_end 同一套流程）
            let mut header_buf = [0u8; HEADER_SIZE];
            if stream.read_exact(&mut header_buf).is_err() {
                return;
            }
            let header = SyncHeader::parse(&header_buf).unwrap();
            let mut raw_packet = vec![0u8; HEADER_SIZE + header.payload_len as usize];
            raw_packet[..HEADER_SIZE].copy_from_slice(&header_buf);
            if stream.read_exact(&mut raw_packet[HEADER_SIZE..]).is_err() {
                return;
            }
            let (_h, init_payload) =
                crate::sync::protocol::decode_session_init_packet_in_place(&mut raw_packet)
                    .unwrap();
            let server_ex = crate::sync::crypto::KeyExchangeSession::new();
            let server_pk = server_ex.public_key;
            let resp_tag = crate::sync::crypto::compute_session_auth_tag(
                &key_clone,
                &init_payload.client_device_id,
                "receiver_dev",
                &server_pk,
                Some(&init_payload.ephemeral_pk),
                "responder",
                &init_payload.challenge,
            );
            let resp_payload = crate::sync::protocol::SessionRespPayload {
                responder_device_id: "receiver_dev".to_string(),
                ephemeral_pk: server_pk,
                auth_tag: resp_tag,
                accepted: true,
            };
            let resp_pkt = crate::sync::protocol::encode_session_resp_packet(
                header.sequence + 1,
                &resp_payload,
            )
            .unwrap();
            if stream.write_all(&resp_pkt).is_err() {
                return;
            }
            let _ = stream.flush();

            // 握手完成后**故意不发 response**：让发送端卡在等 response 的 read 上
            let _ = stop_rx.recv_timeout(Duration::from_secs(10));
            drop(stream);
        });

        let mgr = Arc::new(FileTransferManager::new(&temp_dir));
        let mgr_send = Arc::clone(&mgr);
        let peer = format!("127.0.0.1:{}", port);
        let src_path = src.to_str().unwrap().to_string();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = mgr_send.send_file("cancel_send_tid", &peer, &src_path, "devA", "A", &key);
            let _ = done_tx.send(r);
        });

        // 留出时间完成握手并进入「等 response」的阻塞读
        std::thread::sleep(Duration::from_millis(700));

        let t0 = std::time::Instant::now();
        assert!(
            mgr.cancel_transfer("cancel_send_tid"),
            "取消请求应命中在途发送"
        );
        let res = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("取消后发送端必须尽快返回；超时说明轮询没生效");
        let elapsed = t0.elapsed();

        let err = res.expect_err("被取消的发送不应返回成功");
        assert!(
            err.contains("canceled"),
            "取消应被识别成「已取消」，实际错误: {}",
            err
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "取消耗时 {:?}，远超预期（修复前是 30s 读超时）",
            elapsed
        );

        let _ = stop_tx.send(());
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    /// 取消必须能打断**PFS 握手阶段**的阻塞读。
    ///
    /// 真实场景：对端 TCP 连接已建立（`connect_timeout` 成功），但进程卡死或
    /// 干脆是恶意的，一个字节的 `SESSION_RESP` 都不回。修复前握手走的是
    /// transport 层的裸 `read_exact` + 30s 读超时，用户点「取消」后要等满 30s
    /// （多轮往返最坏可达一分多钟）才生效——这是"点取消没反应"投诉的主因。
    ///
    /// 这条测试同时守住接线本身：`execute_pfs_client_handshake_cancellable` 必须
    /// 真的拿到 cancel_flag，而不是签名叫可取消、内部还在用裸 read_exact。
    #[test]
    fn cancel_interrupts_sender_blocked_in_pfs_handshake() {
        let key = derive_key("cancel_handshake_pin", None).unwrap();
        let temp_dir =
            std::env::temp_dir().join(format!("muclip_cancel_hs_{}", rand::random::<u32>()));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let src = temp_dir.join("payload.bin");
        std::fs::write(&src, vec![0x22u8; 256 * 1024]).unwrap();

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // 对端 accept 后彻底静默：不读也不写，发送端会卡在等 SESSION_RESP 上。
        let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let Ok((_stream, _)) = listener.accept() else {
                return;
            };
            let _ = stop_rx.recv_timeout(Duration::from_secs(10));
        });

        let mgr = Arc::new(FileTransferManager::new(&temp_dir));
        let mgr_send = Arc::clone(&mgr);
        let src_path = src.to_string_lossy().to_string();
        let peer = format!("127.0.0.1:{}", port);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let r = mgr_send.send_file("hs_tid", &peer, &src_path, "devA", "A", &key);
            let _ = done_tx.send(r);
        });

        // 留时间让发送端完成 connect 并阻塞在握手读上
        std::thread::sleep(Duration::from_millis(400));

        let t0 = std::time::Instant::now();
        assert!(
            mgr.cancel_transfer("hs_tid"),
            "取消请求应命中在途传输（说明 token 在连接前就已注册）"
        );
        let res = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("取消后握手必须尽快返回；这里超时说明握手阶段没有接上可取消 IO");
        let elapsed = t0.elapsed();

        let err = res.expect_err("被取消的握手不应返回成功");
        assert!(
            err.contains("canceled"),
            "取消应被识别成「已取消」，实际错误: {}",
            err
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "取消耗时 {:?}，远超预期（修复前要等 30s 握手读超时）",
            elapsed
        );

        let _ = stop_tx.send(());
        let _ = server.join();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}

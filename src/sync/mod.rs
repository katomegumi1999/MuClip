pub(crate) mod cancel;
pub mod crypto;
pub mod discovery;
pub mod file_transfer;
pub mod protocol;
pub mod transport;

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;

pub use crypto::{CryptoError, KEY_SIZE, compute_sha256_hex, derive_key};
pub use discovery::{
    DEFAULT_DISCOVERY_PORT, DiscoveryBeacon, DiscoveryService, LEGACY_MDNS_PORT, PeerInfo,
    PeerManager,
};
pub use file_transfer::{
    FileCompletedCallback, FileOfferCallback, FileProgressCallback, FileTransferManager,
};
pub use protocol::{PairRequestPayload, PairResponsePayload, SyncHeader, SyncPayload};
pub use transport::{
    ClipboardCallback, LoopbackFilter, PairRequestCallback, PairSuccessCallback, SyncClient,
    SyncServer, TransportError, UnpairCallback,
};

#[derive(Error, Debug)]
pub enum SyncError {
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Pairing PIN is invalid or empty")]
    InvalidPin,
}

pub const DEFAULT_SYNC_PORT: u16 = 42424;

/// 同一对端连续被会话握手拒绝多少次，才把「这配对可能已经废了」提示给宿主。
///
/// 为什么不是 1 次就提示：一次拒绝可能是启动竞态（对端还没把密钥写进内存）。
/// 为什么提示而不是自动解配：`SyncRejected` 是**笼统**的认证失败，服务端刻意不区分
/// 原因（对未认证方说「你没配对」等于泄露配对状态）。它可能是对端已解配，也可能是
/// 密钥不一致（改过 PIN / 重装 / 用别的 PIN 重配）或地址串到了另一台设备 ——
/// 后两种情况贸然自清会误伤一条本来还能恢复的配对。
pub const AUTH_REJECT_HINT_THRESHOLD: u32 = 3;

/// 会话握手连续被拒的通知：`(device_id, 连续次数)`。仅为提示，不做任何自动清理。
pub type AuthRejectedCallback = Arc<dyn Fn(&str, u32) + Send + Sync + 'static>;

#[derive(Debug, Clone)]
pub struct SyncConfig {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub sync_port: u16,      // TCP sync listening port (0 = default 42424)
    pub discovery_port: u16, // UDP discovery port (0 = default 42110)
    pub pairing_pin: String,
}

/// Unified LAN Cross-Device P2P Clipboard Synchronization Engine.
pub struct MuClipSyncEngine {
    config: SyncConfig,
    long_term_key: Arc<RwLock<Option<[u8; KEY_SIZE]>>>,
    peer_manager: Arc<PeerManager>,
    discovery: Arc<DiscoveryService>,
    server: Arc<SyncServer>,
    client: Arc<SyncClient>,
    loopback_filter: Arc<LoopbackFilter>,
    file_transfer_mgr: Arc<FileTransferManager>,
    manual_peers: Arc<RwLock<Vec<String>>>,
    bound_port: u16,
    /// 每个 peer 连续被会话握手拒绝的次数，成功一次即清零。
    auth_reject_streaks: Arc<Mutex<HashMap<String, u32>>>,
    auth_rejected_callback: Arc<RwLock<Option<AuthRejectedCallback>>>,
}

impl MuClipSyncEngine {
    pub fn start(config: SyncConfig) -> Result<Arc<Self>, SyncError> {
        let trimmed_pin = config.pairing_pin.trim();
        let key = if trimmed_pin.is_empty() || trimmed_pin == "000000" {
            // 没有可用 PIN 时走随机长期密钥 + SPAKE2 配对，而不是用弱 PIN 直接派生。
            // 这条日志很重要：现象是「两端都起来了但就是不同步」，
            // 而根因是两端密钥本就不同，必须先用配对码交换过才行。
            crate::log_info!(
                "未配置配对 PIN，本次使用随机长期密钥；设备间需先完成 SPAKE2 配对才能同步"
            );
            Some(crypto::generate_device_long_term_key())
        } else {
            Some(derive_key(trimmed_pin, None)?)
        };
        let long_term_key = Arc::new(RwLock::new(key));
        let loopback_filter = Arc::new(LoopbackFilter::new(256));
        let manual_peers = Arc::new(RwLock::new(Vec::new()));
        let file_transfer_mgr = Arc::new(FileTransferManager::new(std::env::temp_dir()));

        let fingerprint = if let Some(k) = key {
            compute_sha256_hex(&k)
        } else {
            "no-key".to_string()
        };

        let peer_manager = Arc::new(PeerManager::new(fingerprint.clone()));
        peer_manager.set_local_key(key);

        let server = Arc::new(SyncServer::new(
            config.device_id.clone(),
            config.device_name.clone(),
            Arc::clone(&long_term_key),
            Arc::clone(&loopback_filter),
            Arc::clone(&peer_manager),
            Arc::clone(&file_transfer_mgr),
        ));
        server.set_local_device_type(&config.device_type);

        let requested_sync_port = if config.sync_port > 0 {
            config.sync_port
        } else {
            DEFAULT_SYNC_PORT
        };
        let bound_port = server.start(requested_sync_port)?;
        crate::log_info!(
            "同步服务已监听 0.0.0.0:{}（设备 {} / {}）",
            bound_port,
            config.device_name,
            config.device_id
        );

        let discovery = Arc::new(DiscoveryService::new(
            config.device_id.clone(),
            config.device_name.clone(),
            config.device_type.clone(),
            bound_port,
            config.discovery_port,
            fingerprint,
            Arc::clone(&peer_manager),
            Arc::clone(&manual_peers),
        ));

        // 发现服务失败此前被 `let _ =` 完全吞掉，而它正是「设备列表里看不到对方」的头号原因。
        if let Err(e) = discovery.start() {
            crate::log_error!(
                "广播发现启动失败，本机不会出现在其他设备的设备列表中（仍可用手动添加 IP 连接）: {:?}",
                e
            );
        }
        let client = Arc::new(SyncClient::new());

        // Wire server pair success to automatic discovery paired device registration and keyring storage
        let discovery_ref = Arc::clone(&discovery);
        let client_ref = Arc::clone(&client);
        let peer_mgr_ref = Arc::clone(&peer_manager);
        server.set_pair_success_callback(Arc::new(move |dev_id, name, _ip, peer_key_hex| {
            if let Ok(pk) = crypto::hex_to_32bytes(peer_key_hex.trim()) {
                peer_mgr_ref.set_peer_key(&dev_id, pk);
            }
            discovery_ref.add_paired_device_id(dev_id.clone());
            client_ref.clear_connection_pool();
            crate::log_info!("配对成功 device={} name={}", dev_id, name);
        }));

        Ok(Arc::new(Self {
            config,
            long_term_key,
            peer_manager,
            discovery,
            server,
            client,
            loopback_filter,
            file_transfer_mgr,
            manual_peers,
            bound_port,
            auth_reject_streaks: Arc::new(Mutex::new(HashMap::new())),
            auth_rejected_callback: Arc::new(RwLock::new(None)),
        }))
    }

    /// Updates the local device's permanent secret key across runtime and notifies discovery.
    pub fn set_pairing_pin(&self, pin: &str) -> Result<(), SyncError> {
        let trimmed = pin.trim();
        let key = if !trimmed.is_empty() && trimmed != "000000" {
            Some(derive_key(trimmed, None)?)
        } else {
            Some(crypto::generate_device_long_term_key())
        };
        let fingerprint = if let Some(k) = key {
            compute_sha256_hex(&k)
        } else {
            "no-key".to_string()
        };
        if let Ok(mut k) = self.long_term_key.write() {
            *k = key;
        }
        self.peer_manager.set_local_key(key);
        self.client.clear_connection_pool();
        self.discovery.update_fingerprint(fingerprint);
        Ok(())
    }

    /// Sets callback when a remote clipboard payload is received.
    pub fn on_clipboard_received(&self, cb: ClipboardCallback) {
        self.server.set_callback(cb);
    }

    /// Sets callback when an incoming pairing request arrives (single-connection handshake).
    pub fn on_pair_request_received(&self, cb: PairRequestCallback) {
        self.server.set_pair_request_callback(cb);
    }

    /// Sets callback when incoming pairing succeeds.
    pub fn on_pair_success(&self, cb: PairSuccessCallback) {
        let discovery_ref = Arc::clone(&self.discovery);
        let client_ref = Arc::clone(&self.client);
        let peer_mgr_ref = Arc::clone(&self.peer_manager);
        let wrapped_cb: PairSuccessCallback = Arc::new(move |dev_id, name, ip, peer_key_hex| {
            if let Ok(pk) = crypto::hex_to_32bytes(peer_key_hex.trim()) {
                peer_mgr_ref.set_peer_key(&dev_id, pk);
            }
            discovery_ref.add_paired_device_id(dev_id.clone());
            client_ref.clear_connection_pool();
            cb(dev_id, name, ip, peer_key_hex);
        });
        self.server.set_pair_success_callback(wrapped_cb);
    }

    /// Sets callback when remote peer sends an unpair notice.
    pub fn on_peer_unpaired(&self, cb: UnpairCallback) {
        self.server.set_unpair_callback(cb);
    }

    /// 注册「同一对端连续被会话握手拒绝」的提示回调。
    ///
    /// 只在连续次数**首次**达到 [`AUTH_REJECT_HINT_THRESHOLD`] 时回调一次；期间任意一次
    /// 同步成功即清零重计。回调只做提示，core 不会因此删配对或销毁密钥 ——
    /// 用户看到提示后自己决定是「重新配对」还是「删除设备」。
    pub fn on_peer_auth_rejected(&self, cb: AuthRejectedCallback) {
        if let Ok(mut slot) = self.auth_rejected_callback.write() {
            *slot = Some(cb);
        }
    }

    /// 记一次会话握手被拒，返回该 peer 的连续次数。
    ///
    /// 日志频率是刻意压过的：第 1 次和每 10 次记一条 WARN。剪贴板每次复制都会触发一轮
    /// 同步，若每次拒绝都打日志，一个坏掉的配对几秒钟就能把环形缓冲刷满，真问题反而被埋掉。
    fn note_auth_rejected(&self, device_id: &str, addr: &str) -> u32 {
        let streak = {
            let mut map = self
                .auth_reject_streaks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let counter = map.entry(device_id.to_string()).or_insert(0);
            *counter += 1;
            *counter
        };

        if streak == 1 || streak % 10 == 0 {
            crate::log_warn!(
                "会话认证被 {} ({}) 拒绝，连续第 {} 次：可能是对端已解配、两两密钥不一致（改过 PIN / 重装 / 用别的 PIN 重配），或地址串到了另一台设备",
                device_id,
                addr,
                streak
            );
        }

        if streak == AUTH_REJECT_HINT_THRESHOLD {
            // 先放读锁再回调：回调里宿主很可能再调本引擎的接口（如重新配对），
            // 持锁回调会自死锁（同 notify_progress 的历史教训）。
            let cb = self
                .auth_rejected_callback
                .read()
                .ok()
                .and_then(|guard| guard.as_ref().map(Arc::clone));
            if let Some(cb) = cb {
                cb(device_id, streak);
            }
        }
        streak
    }

    /// 同步成功一次就把连续拒绝计数清零：说明这条配对其实还能正常工作。
    fn clear_auth_reject(&self, device_id: &str) {
        if let Ok(mut map) = self.auth_reject_streaks.lock() {
            map.remove(device_id);
        }
    }

    /// Responds to an incoming pairing request: 0 = success, 1 = not found/expired, 2 = wrong pin.
    pub fn respond_pair(&self, request_id: &str, pin: &str, accept: bool) -> i32 {
        self.server.respond_pair(request_id, pin, accept)
    }

    /// Initiates pairing with a peer over single-stream TCP handshake.
    pub fn request_pair(
        &self,
        peer_addr: &str,
        pin: &str,
        timeout_secs: u64,
    ) -> Result<PairResponsePayload, SyncError> {
        let current_key = self.long_term_key.read().ok().and_then(|g| *g);
        let resp = self.client.request_pair_with_context(
            peer_addr,
            &self.config.device_id,
            &self.config.device_name,
            pin,
            timeout_secs,
            current_key,
            Some(&self.peer_manager),
        )?;

        if let Some((host, port)) = discovery::parse_peer_endpoint(peer_addr, DEFAULT_SYNC_PORT) {
            self.peer_manager.resolve_manual_peer_from_pair(
                &host,
                port,
                &resp.responder_device_id,
                &resp.responder_device_name,
                resp.accepted,
            );
        }

        if resp.accepted {
            if let Some(ref peer_key_hex) = resp.long_term_key_hex {
                if let Ok(pk) = crypto::hex_to_32bytes(peer_key_hex.trim()) {
                    self.peer_manager
                        .set_peer_key(&resp.responder_device_id, pk);
                }
            }
            self.discovery
                .add_paired_device_id(resp.responder_device_id.clone());
            self.client.clear_connection_pool();
        }

        Ok(resp)
    }

    /// Manually marks a device ID as paired.
    pub fn add_paired_device(&self, device_id: &str) {
        self.discovery.add_paired_device_id(device_id.to_string());
    }

    /// Manually unpairs a device ID and sends an unpair notification to the peer.
    /// Supports both plain `"device_id"` and `"device_id|ip|port"` endpoint hints.
    pub fn remove_paired_device(&self, device_id: &str) {
        let parts: Vec<&str> = device_id.split('|').collect();
        let dev_id = parts.first().map(|s| s.trim()).unwrap_or("");
        if dev_id.is_empty() {
            return;
        }
        let hint_ip = parts.get(1).map(|s| s.trim()).unwrap_or("");
        let hint_port = parts
            .get(2)
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(DEFAULT_SYNC_PORT);

        let mut target_addrs = Vec::new();
        for peer in self.peer_manager.get_all_peers() {
            if peer.device_id == dev_id && !peer.ip.is_empty() {
                let port = if peer.sync_port > 0 {
                    peer.sync_port
                } else {
                    DEFAULT_SYNC_PORT
                };
                let addr = format!("{}:{}", peer.ip, port);
                if !target_addrs.contains(&addr) {
                    target_addrs.push(addr);
                }
            }
        }
        if !hint_ip.is_empty() {
            let hint_addr = format!("{}:{}", hint_ip, hint_port);
            if !target_addrs.contains(&hint_addr) {
                target_addrs.push(hint_addr);
            }
        }

        // ⚠️ 必须在 `remove_paired_device_id` 之前取密钥：那一步会连带删掉
        // `peer_keys[dev_id]`，之后再 `get_peer_key` 必然拿到 None，于是退回
        // 交给 `get_long_term_key()`（本机随机长期密钥）。而通告的 PFS 握手只认
        // 两两配对密钥，用错密钥的对端认证必然失败 → 通告发不出去 → 对端不会自动解配。
        // 这个顺序问题让「双方在线自动解配」长期静默失效（有测试覆盖）。
        let notice_key = self
            .peer_manager
            .get_peer_key(dev_id)
            .or_else(|| self.get_long_term_key());

        self.discovery.remove_paired_device_id(dev_id);

        for addr in &target_addrs {
            self.client.close_connection(addr);
        }

        if !target_addrs.is_empty() {
            if let Some(peer_key) = notice_key {
                let client_ref = Arc::clone(&self.client);
                let local_id = self.config.device_id.clone();
                let dev_id_owned = dev_id.to_string();
                std::thread::spawn(move || {
                    for addr in target_addrs {
                        // Best-effort: the peer only drops its side of the pairing after it has
                        // authenticated this notice, so a rejected/failed send leaves a stale
                        // record on the remote end. Retry once to absorb startup/connect races.
                        let mut last_err = match client_ref.send_unpair_notice(
                            &addr,
                            &local_id,
                            Some(&dev_id_owned),
                            &peer_key,
                        ) {
                            Ok(()) => None,
                            Err(e) => Some(e),
                        };
                        if last_err.is_some() {
                            last_err = match client_ref.send_unpair_notice(
                                &addr,
                                &local_id,
                                Some(&dev_id_owned),
                                &peer_key,
                            ) {
                                Ok(()) => None,
                                Err(e) => Some(e),
                            };
                        }
                        // 静默失败是这套逻辑最坑的地方：本端已经解配、UI 显示成功，
                        // 对端却毫无变化，用户只能靠「同步一直失败」反推。
                        if let Some(e) = last_err {
                            crate::log_warn!(
                                "解配通告未能送达 {}（对端可能离线）：{}；对端将在下次同步收到 ERR_NOT_PAIRED 时自行清理",
                                addr,
                                e
                            );
                        } else {
                            crate::log_info!("解配通告已送达 {}", addr);
                        }
                    }
                });
            }
        }
    }

    /// Sets known paired device IDs in batch.
    pub fn set_paired_devices(&self, device_ids: Vec<String>) {
        self.discovery.set_paired_device_ids(device_ids);
    }

    /// Manually marks a content hash as published locally to suppress loopback echoes.
    pub fn mark_published(&self, hash: &str) {
        self.loopback_filter.mark_published(hash);
    }

    /// Returns the active TCP sync port currently bound.
    pub fn bound_port(&self) -> u16 {
        self.bound_port
    }

    /// Returns a reference to the engine's configuration.
    pub fn config(&self) -> &SyncConfig {
        &self.config
    }

    /// Returns list of all active online peers discovered via UDP / mDNS and manual port mappings.
    pub fn get_active_peers(&self) -> Vec<PeerInfo> {
        self.peer_manager.get_active_peers()
    }

    /// Returns list of all known peers including recently disconnected ones and manual port mappings.
    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.peer_manager.get_all_peers()
    }

    /// Adds a static / port-mapped remote peer endpoint (e.g. "192.168.1.100:42424" or "myfrp.host.com:55555").
    /// Immediately registers the endpoint in `PeerManager` and triggers a background TCP discovery probe.
    pub fn add_manual_peer(&self, addr: &str) {
        if let Some((host, port)) = discovery::parse_peer_endpoint(addr, DEFAULT_SYNC_PORT) {
            let normalized = self.peer_manager.register_manual_endpoint(&host, port);
            if let Ok(mut peers) = self.manual_peers.write() {
                if !peers.iter().any(|p| p.eq_ignore_ascii_case(&normalized)) {
                    peers.push(normalized.clone());
                }
            }
            self.discovery.probe_manual_peer_async(&normalized);
        }
    }

    /// Removes a previously configured static / port-mapped remote peer (by `"host:port"`, `"host"`, or `device_id`).
    pub fn remove_manual_peer(&self, addr: &str) {
        let trimmed = addr.trim();
        let removed_keys = self
            .peer_manager
            .unregister_manual_endpoint(trimmed, DEFAULT_SYNC_PORT);
        if let Ok(mut peers) = self.manual_peers.write() {
            peers.retain(|p| {
                !p.eq_ignore_ascii_case(trimmed)
                    && !removed_keys.iter().any(|k| k.eq_ignore_ascii_case(p))
            });
        }
        self.client.close_connection(trimmed);
        for k in removed_keys {
            self.client.close_connection(&k);
        }
    }

    /// Retrieves all active static / port-mapped remote peer endpoints.
    pub fn get_manual_peers(&self) -> Vec<String> {
        self.manual_peers
            .read()
            .map(|p| p.clone())
            .unwrap_or_default()
    }

    /// Broadcasts local clipboard changes to all discovered online peers and manual port-mapped peers.
    /// Returns the number of peers successfully sent to.
    pub fn broadcast_clipboard(&self, text: &str, content_type: &str) -> usize {
        let key = match self.long_term_key.read() {
            Ok(k) => match *k {
                Some(k) => k,
                None => return 0,
            },
            Err(_) => return 0,
        };

        let mut payload =
            SyncPayload::new_text(&self.config.device_id, &self.config.device_name, text);
        payload.content_type = content_type.to_string();

        // Mark local publication in loopback filter
        self.loopback_filter.mark_published(&payload.content_hash);

        let all_peers = self.peer_manager.get_all_peers();
        let mut targets: Vec<(String, Option<String>)> = Vec::new();
        for peer in &all_peers {
            if peer.is_paired && !peer.ip.is_empty() && peer.sync_port > 0 {
                targets.push((
                    format!("{}:{}", peer.ip, peer.sync_port),
                    Some(peer.device_id.clone()),
                ));
            }
        }

        // Also broadcast to any static / port-mapped peers not yet tracked in all_peers
        let manual = self.get_manual_peers();
        for addr in manual {
            if !all_peers
                .iter()
                .any(|p| format!("{}:{}", p.ip, p.sync_port).eq_ignore_ascii_case(&addr))
            {
                targets.push((addr, None));
            }
        }

        if targets.is_empty() {
            return 0;
        }

        let sent_count = AtomicUsize::new(0);

        // Concurrently push directly to all target peers in parallel
        std::thread::scope(|s| {
            for (addr, dev_id_opt) in targets {
                let sent_ref = &sent_count;
                let payload_ref = &payload;
                let key_ref = &key;
                let discovery_ref = &self.discovery;
                let peer_mgr_ref = &self.peer_manager;
                s.spawn(move || {
                    let candidates =
                        peer_mgr_ref.get_candidate_keys(dev_id_opt.as_deref(), Some(*key_ref));
                    let mut last_err: Option<TransportError> = None;
                    let mut delivered = false;
                    for cand_key in candidates {
                        match self.client.send_payload(
                            &addr,
                            dev_id_opt.as_deref(),
                            &cand_key,
                            payload_ref,
                        ) {
                            Ok(_) => {
                                delivered = true;
                                sent_ref.fetch_add(1, Ordering::Relaxed);
                                if let Some(ref dev_id) = dev_id_opt {
                                    peer_mgr_ref.set_peer_key(dev_id, cand_key);
                                    discovery_ref.touch_peer(dev_id);
                                    // 这条配对还能用，把「连续被拒」的计数清零，
                                    // 否则一次偶发竞态会让后续计数一路累加到误报阈值。
                                    self.clear_auth_reject(dev_id);
                                } else if let Some((h, p)) =
                                    discovery::parse_peer_endpoint(&addr, DEFAULT_SYNC_PORT)
                                {
                                    peer_mgr_ref.touch_manual_endpoint(&h, p, true);
                                }
                                break;
                            }
                            Err(TransportError::SyncRejected) => {
                                self.client.close_connection(&addr);
                                last_err = Some(TransportError::SyncRejected);
                                continue;
                            }
                            Err(e) => {
                                self.client.close_connection(&addr);
                                last_err = Some(e);
                                break;
                            }
                        }
                    }

                    if !delivered {
                        if let Some(e) = last_err {
                            if matches!(e, TransportError::NotPairedByPeer) {
                                // 对端回 ERR_NOT_PAIRED：它已经把我们解掉了，而我们离线时
                                // 错过了 MSG_UNPAIR_NOTICE。这里必须跟着本地清理并回调宿主，
                                // 否则设备列表里会留一条「每条剪贴板都同步失败」的死记录，
                                // 用户还得手动删一次。
                                //
                                // 走 `notify_peer_unpaired`（只删本地 + 回调）而不是
                                // `remove_paired_device`（会再发一次通告）——对端早就解了，
                                // 反向再发通告只会在两端之间来回弹成回声。
                                let peer_dev = dev_id_opt.clone().or_else(|| {
                                    discovery::parse_peer_endpoint(&addr, DEFAULT_SYNC_PORT)
                                        .and_then(|(h, p)| {
                                            peer_mgr_ref.find_device_id_by_endpoint(&h, p)
                                        })
                                });
                                if let Some(peer_dev) = peer_dev {
                                    crate::log_info!(
                                        "对端 {} 已单方面解配（ERR_NOT_PAIRED），本地同步清除配对与密钥",
                                        peer_dev
                                    );
                                    self.server.notify_peer_unpaired(&peer_dev);
                                }
                            } else if matches!(e, TransportError::SyncRejected) {
                                // 对端活着并且回了帧，只是不认这次认证 —— 不能当离线处理，
                                // 也不做自动解配（原因可能是解配、密钥不一致或地址串台，
                                // 服务端刻意不区分）。计数到阈值后只提示宿主一次。
                                let peer_dev = dev_id_opt.clone().or_else(|| {
                                    discovery::parse_peer_endpoint(&addr, DEFAULT_SYNC_PORT)
                                        .and_then(|(h, p)| {
                                            peer_mgr_ref.find_device_id_by_endpoint(&h, p)
                                        })
                                });
                                if let Some(peer_dev) = peer_dev {
                                    self.note_auth_rejected(&peer_dev, &addr);
                                }
                            } else if let Some((h, p)) =
                                discovery::parse_peer_endpoint(&addr, DEFAULT_SYNC_PORT)
                            {
                                peer_mgr_ref.mark_peer_offline_if_stale(
                                    dev_id_opt.as_deref().unwrap_or(""),
                                    &h,
                                    p,
                                    discovery::PEER_TIMEOUT_SECS * 1000,
                                );
                            }
                        }
                    }
                });
            }
        });

        sent_count.load(Ordering::Relaxed)
    }

    /// Toggles automatic periodic discovery broadcasting.
    pub fn set_auto_discovery(&self, enabled: bool) {
        self.discovery.set_auto_discovery_enabled(enabled);
    }

    /// Checks if automatic periodic discovery broadcasting is enabled.
    pub fn is_auto_discovery_enabled(&self) -> bool {
        self.discovery.is_auto_discovery_enabled()
    }

    /// Manually triggers a single multi-interface discovery broadcast scan immediately.
    pub fn trigger_discovery_scan(&self) {
        self.discovery.trigger_scan();
    }

    /// Tests connection and encryption validity with a peer endpoint.
    /// Returns round-trip time in milliseconds if successful.
    pub fn test_peer_connection(&self, peer_addr: &str) -> Result<u64, SyncError> {
        let key = match self.long_term_key.read() {
            Ok(k) => match *k {
                Some(k) => k,
                None => return Err(SyncError::InvalidPin),
            },
            Err(_) => return Err(SyncError::InvalidPin),
        };

        let (host, port) = discovery::parse_peer_endpoint(peer_addr, DEFAULT_SYNC_PORT)
            .unwrap_or_else(|| (peer_addr.to_string(), DEFAULT_SYNC_PORT));
        let dev_id_opt = self.peer_manager.find_device_id_by_endpoint(&host, port);

        let payload = SyncPayload {
            msg_id: uuid::Uuid::now_v7().to_string(),
            source_device_id: self.config.device_id.clone(),
            source_device_name: self.config.device_name.clone(),
            content: "PING".to_string(),
            content_type: "system/ping".to_string(),
            content_hash: "system_ping".to_string(),
            timestamp_ms: 0,
        };

        let start = std::time::Instant::now();
        let candidates = self
            .peer_manager
            .get_candidate_keys(dev_id_opt.as_deref(), Some(key));
        let mut last_err: Option<TransportError> = None;
        for cand_key in candidates {
            match self
                .client
                .send_payload(peer_addr, dev_id_opt.as_deref(), &cand_key, &payload)
            {
                Ok(_) => {
                    if let Some(ref dev_id) = dev_id_opt {
                        self.peer_manager.set_peer_key(dev_id, cand_key);
                        self.discovery.touch_peer(dev_id);
                    } else if let Some((h, p)) =
                        discovery::parse_peer_endpoint(peer_addr, DEFAULT_SYNC_PORT)
                    {
                        self.peer_manager.touch_manual_endpoint(&h, p, true);
                    }
                    return Ok(start.elapsed().as_millis().max(1) as u64);
                }
                Err(TransportError::SyncRejected) => {
                    self.client.close_connection(peer_addr);
                    last_err = Some(TransportError::SyncRejected);
                    continue;
                }
                Err(e) => {
                    self.client.close_connection(peer_addr);
                    last_err = Some(e);
                    break;
                }
            }
        }

        if let Some((h, p)) = discovery::parse_peer_endpoint(peer_addr, DEFAULT_SYNC_PORT) {
            self.peer_manager.mark_peer_offline("", &h, p);
        }
        Err(SyncError::from(
            last_err.unwrap_or(TransportError::SyncRejected),
        ))
    }

    // -------------------------------------------------------------------------
    // High-Speed Encrypted File Transfer
    // -------------------------------------------------------------------------

    pub fn send_file(&self, peer_addr: &str, file_path: &str) -> Result<String, String> {
        self.send_file_with_name(peer_addr, file_path, None)
    }

    pub fn send_file_with_name(
        &self,
        peer_addr: &str,
        file_path: &str,
        custom_name: Option<&str>,
    ) -> Result<String, String> {
        let (actual_peer_addr, device_id_hint) = if let Some((addr_part, dev_hint)) = peer_addr
            .split_once('|')
            .or_else(|| peer_addr.split_once('#'))
        {
            (addr_part.trim(), Some(dev_hint.trim()))
        } else {
            (peer_addr.trim(), None)
        };

        let default_key = match self.long_term_key.read() {
            Ok(k) => match *k {
                Some(k) => k,
                None => {
                    #[cfg(unix)]
                    if let Some(fd_str) = file_path.strip_prefix("fd:") {
                        if let Ok(raw_fd) = fd_str.trim().parse::<i32>() {
                            if raw_fd >= 0 {
                                use std::os::unix::io::FromRawFd;
                                let _ = unsafe { std::fs::File::from_raw_fd(raw_fd) };
                            }
                        }
                    }
                    return Err("Session key not configured".to_string());
                }
            },
            Err(e) => return Err(e.to_string()),
        };

        // 目标设备 ID：优先取调用方通过 `addr|dev_id` 传入的 hint，
        // 否则按端点反查已知 peer。它会被用于 PFS 握手的目标绑定，
        // 使对端可以校验「这次会话确实是冲我来的」。
        let mut target_dev_id: Option<String> = device_id_hint
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let endpoint_hit = discovery::parse_peer_endpoint(actual_peer_addr, DEFAULT_SYNC_PORT)
            .and_then(|(h, p)| {
                self.peer_manager
                    .get_all_peers()
                    .into_iter()
                    .find(|peer| peer.ip.eq_ignore_ascii_case(&h) && peer.sync_port == p)
            });
        if target_dev_id.is_none() {
            target_dev_id = endpoint_hit.as_ref().map(|peer| peer.device_id.clone());
        }

        let key = target_dev_id
            .as_deref()
            .and_then(|dev_id| self.peer_manager.get_peer_key(dev_id))
            .or_else(|| {
                endpoint_hit
                    .as_ref()
                    .and_then(|peer| self.peer_manager.get_peer_key(&peer.device_id))
            })
            .unwrap_or(default_key);

        let ft_mgr = Arc::clone(&self.file_transfer_mgr);
        let p_addr = actual_peer_addr.to_string();
        let f_path = file_path.to_string();
        let c_name = custom_name.map(|s| s.to_string());
        let dev_id = self.config.device_id.clone();
        let dev_name = self.config.device_name.clone();
        let target_dev = target_dev_id.clone();

        let transfer_id = format!(
            "{}_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            rand::random::<u32>()
        );
        let tid_clone = transfer_id.clone();
        let tid_for_thread = transfer_id.clone();

        std::thread::spawn(move || {
            if let Err(e) = ft_mgr.send_file_with_name(
                &tid_for_thread,
                &p_addr,
                &f_path,
                c_name.as_deref(),
                &dev_id,
                &dev_name,
                target_dev.as_deref(),
                &key,
            ) {
                crate::log_warn!(
                    "发送文件失败 transfer={} 目标={}: {}",
                    tid_for_thread,
                    p_addr,
                    e
                );
            }
        });

        Ok(tid_clone)
    }

    pub fn cancel_file_transfer(&self, transfer_id: &str) -> bool {
        self.file_transfer_mgr.cancel_transfer(transfer_id)
    }

    pub fn set_file_save_directory(&self, path: impl Into<std::path::PathBuf>) {
        self.file_transfer_mgr.set_save_directory(path);
    }

    pub fn on_file_progress(&self, cb: FileProgressCallback) {
        self.file_transfer_mgr.set_progress_callback(cb);
    }

    pub fn on_file_completed(&self, cb: FileCompletedCallback) {
        self.file_transfer_mgr.set_completed_callback(cb);
    }

    pub fn on_file_offer(&self, cb: FileOfferCallback) {
        self.file_transfer_mgr.set_offer_callback(cb);
    }

    pub fn on_incoming_file_stream(&self, cb: file_transfer::IncomingFileStreamCallback) {
        self.file_transfer_mgr.set_incoming_stream_callback(cb);
    }

    pub fn get_long_term_key(&self) -> Option<[u8; KEY_SIZE]> {
        self.long_term_key.read().ok().and_then(|k| *k)
    }

    pub fn get_bulk_session_key(&self) -> Option<[u8; KEY_SIZE]> {
        self.get_long_term_key()
    }

    /// Stops the discovery and sync server threads.
    pub fn stop(&self) {
        crate::log_info!("正在停止同步服务（设备 {}）", self.config.device_id);
        self.discovery.stop();
        self.server.stop();
    }
}

impl Drop for MuClipSyncEngine {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 退出延迟回归：发现广播线程用 100ms tick、监听线程 1s 读超时，
    /// server accept 线程由回环连接唤醒。stop() 若超过 500ms，退出路径上的
    /// 托盘图标 / 进程残留就会被用户感知（参见 ShawMuOCR 的退出预算设计）。
    #[test]
    fn test_stop_latency_is_bounded() {
        let config = SyncConfig {
            device_id: "latency-node".into(),
            device_name: "Latency Node".into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "123456".into(),
        };

        let engine = MuClipSyncEngine::start(config).expect("start engine");
        // 进入稳态：广播循环已跑过前 2 次（2s 间隔档），监听线程阻塞在 recv 上
        std::thread::sleep(std::time::Duration::from_millis(1500));

        let t = std::time::Instant::now();
        engine.discovery.stop();
        let discovery_ms = t.elapsed().as_millis();

        let t = std::time::Instant::now();
        engine.server.stop();
        let server_ms = t.elapsed().as_millis();

        println!(
            "stop latency: discovery={} ms, server={} ms",
            discovery_ms, server_ms
        );
        assert!(
            discovery_ms < 300,
            "discovery.stop 过慢: {} ms（监听线程读超时过长？）",
            discovery_ms
        );
        assert!(
            server_ms < 300,
            "server.stop 过慢: {} ms（accept 唤醒失效？）",
            server_ms
        );
    }

    #[test]
    fn test_sync_engine_lifecycle() {
        let config = SyncConfig {
            device_id: "test-node-1".into(),
            device_name: "Test Node".into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "999888".into(),
        };

        let engine = MuClipSyncEngine::start(config).expect("start engine");
        assert!(engine.bound_port() > 0);

        let peers = engine.get_active_peers();
        println!("test_sync_engine_lifecycle peers: {:?}", peers);
        // Note: If another node or background app is running, peers may contain it.
        // What matters is that the engine started successfully and bound port > 0.
        engine.stop();
    }

    #[test]
    fn test_sync_engine_bulk_key_matches_sender_and_receiver() {
        let sender_cfg = SyncConfig {
            device_id: "sender-node".into(),
            device_name: "Sender".into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "123456".into(),
        };
        let receiver_cfg = SyncConfig {
            device_id: "receiver-node".into(),
            device_name: "Receiver".into(),
            device_type: "Android".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "123456".into(),
        };

        let sender = MuClipSyncEngine::start(sender_cfg).expect("start sender");
        let receiver = MuClipSyncEngine::start(receiver_cfg).expect("start receiver");
        receiver.add_paired_device("sender-node");
        sender.add_paired_device("receiver-node");

        // Verify both engines share the exact same unified 32-byte session_key
        let sender_bulk = sender.get_bulk_session_key().expect("sender session key");
        let receiver_bulk = receiver
            .get_bulk_session_key()
            .expect("receiver session key");
        assert_eq!(sender_bulk, receiver_bulk);

        let master = crypto::derive_key("123456", None).unwrap();
        assert_eq!(sender_bulk, master);

        sender.stop();
        receiver.stop();
    }

    #[test]
    fn test_three_device_mesh_pairing_and_sync_abc() {
        use std::sync::Mutex;
        use std::time::Duration;

        let cfg_a = SyncConfig {
            device_id: "node-a".into(),
            device_name: "Device A (Windows)".into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };
        let cfg_b = SyncConfig {
            device_id: "node-b".into(),
            device_name: "Device B (Android)".into(),
            device_type: "Android".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };
        let cfg_c = SyncConfig {
            device_id: "node-c".into(),
            device_name: "Device C (Tablet)".into(),
            device_type: "Android".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };

        let node_a = MuClipSyncEngine::start(cfg_a).expect("start A");
        let node_b = MuClipSyncEngine::start(cfg_b).expect("start B");
        let node_c = MuClipSyncEngine::start(cfg_c).expect("start C");
        node_a.set_auto_discovery(false);
        node_b.set_auto_discovery(false);
        node_c.set_auto_discovery(false);

        let port_a = node_a.bound_port();
        let port_b = node_b.bound_port();
        let port_c = node_c.bound_port();

        let rx_a = Arc::new(Mutex::new(Vec::<String>::new()));
        let rx_b = Arc::new(Mutex::new(Vec::<String>::new()));
        let rx_c = Arc::new(Mutex::new(Vec::<String>::new()));

        {
            let rx_a_ref = Arc::clone(&rx_a);
            node_a.on_clipboard_received(Arc::new(move |payload| {
                rx_a_ref.lock().unwrap().push(payload.content);
            }));
            let rx_b_ref = Arc::clone(&rx_b);
            node_b.on_clipboard_received(Arc::new(move |payload| {
                rx_b_ref.lock().unwrap().push(payload.content);
            }));
            let rx_c_ref = Arc::clone(&rx_c);
            node_c.on_clipboard_received(Arc::new(move |payload| {
                rx_c_ref.lock().unwrap().push(payload.content);
            }));
        }

        // Step 1: Pair A -> B using PIN "111222" (Derives mutual pairwise key K_AB)
        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let b_ref = Arc::clone(&node_b);
            node_b.on_pair_request_received(Arc::new(move |req_id, _from_id, _from_name, _ip| {
                let b_inner = Arc::clone(&b_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(b_inner.respond_pair(&req_id, "111222", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp_ab = node_a
                .request_pair(&format!("127.0.0.1:{}", port_b), "111222", 5)
                .expect("pair A->B");
            assert!(resp_ab.accepted);
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("B respond_pair done");
            node_b.add_paired_device(&format!("node-a|127.0.0.1|{}", port_a));
            node_a.add_paired_device(&format!("node-b|127.0.0.1|{}", port_b));
        }

        let key_ab = node_a
            .peer_manager
            .get_peer_key("node-b")
            .expect("key AB on A");
        assert_eq!(node_b.peer_manager.get_peer_key("node-a"), Some(key_ab));

        // Step 2: Pair C -> A using a DIFFERENT PIN "333444" (Derives mutual pairwise key K_AC)
        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let a_ref = Arc::clone(&node_a);
            node_a.on_pair_request_received(Arc::new(move |req_id, _from_id, _from_name, _ip| {
                let a_inner = Arc::clone(&a_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(a_inner.respond_pair(&req_id, "333444", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp_ca = node_c
                .request_pair(&format!("127.0.0.1:{}", port_a), "333444", 5)
                .expect("pair C->A");
            assert!(resp_ca.accepted);
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("A respond_pair done");
            node_a.add_paired_device(&format!("node-c|127.0.0.1|{}", port_c));
            node_c.add_paired_device(&format!("node-a|127.0.0.1|{}", port_a));
        }

        let key_ac = node_a
            .peer_manager
            .get_peer_key("node-c")
            .expect("key AC on A");
        assert_eq!(node_c.peer_manager.get_peer_key("node-a"), Some(key_ac));
        // Pairwise keys are mutually isolated
        assert_ne!(key_ab, key_ac);
        // Existing pairing A <-> B is completely unaffected by adding device C!
        assert_eq!(node_a.peer_manager.get_peer_key("node-b"), Some(key_ab));

        // Step 3: A pushes clipboard -> both B and C receive it directly
        assert_eq!(node_a.broadcast_clipboard("From A to BC", "text/plain"), 2);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(rx_b.lock().unwrap().as_slice(), &["From A to BC"]);
        assert_eq!(rx_c.lock().unwrap().as_slice(), &["From A to BC"]);

        // Step 4: B pushes clipboard -> only A receives directly!
        // A does NOT relay to C, preventing private clipboard leakage to un-paired 3rd parties.
        assert_eq!(node_b.broadcast_clipboard("From B to A", "text/plain"), 1);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(rx_a.lock().unwrap().as_slice(), &["From B to A"]);
        // C was NOT paired with B, so C did NOT receive B's clipboard!
        assert_eq!(rx_c.lock().unwrap().as_slice(), &["From A to BC"]);

        // Step 5: C pushes clipboard -> only A receives directly!
        // A does NOT relay to B, ensuring strict peer-to-peer confidentiality.
        assert_eq!(node_c.broadcast_clipboard("From C to A", "text/plain"), 1);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            rx_a.lock().unwrap().as_slice(),
            &["From B to A", "From C to A"]
        );
        // B was NOT paired with C, so B did NOT receive C's clipboard!
        assert_eq!(rx_b.lock().unwrap().as_slice(), &["From A to BC"]);

        // Step 6: User explicitly pairs B and C directly (PIN "555666")
        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let c_ref = Arc::clone(&node_c);
            node_c.on_pair_request_received(Arc::new(move |req_id, _from_id, _from_name, _ip| {
                let c_inner = Arc::clone(&c_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(c_inner.respond_pair(&req_id, "555666", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp_bc = node_b
                .request_pair(&format!("127.0.0.1:{}", port_c), "555666", 5)
                .expect("pair B->C");
            assert!(resp_bc.accepted);
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("C respond_pair done");
            node_b.add_paired_device(&format!("node-c|127.0.0.1|{}", port_c));
            node_c.add_paired_device(&format!("node-b|127.0.0.1|{}", port_b));
        }

        let key_bc = node_b
            .peer_manager
            .get_peer_key("node-c")
            .expect("key BC on B");
        assert_eq!(node_c.peer_manager.get_peer_key("node-b"), Some(key_bc));
        assert_ne!(key_bc, key_ab);
        assert_ne!(key_bc, key_ac);

        // Now that B is explicitly paired with both A and C, B broadcasts directly to both:
        assert_eq!(node_b.broadcast_clipboard("From B to AC", "text/plain"), 2);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            rx_a.lock().unwrap().as_slice(),
            &["From B to A", "From C to A", "From B to AC"]
        );
        assert_eq!(
            rx_c.lock().unwrap().as_slice(),
            &["From A to BC", "From B to AC"]
        );

        node_a.stop();
        node_b.stop();
        node_c.stop();
    }

    /// 双方同时在线时，一方解配必须把另一方也解开。
    ///
    /// 这是「解配」唯一有用户可感交互的路径：A 点「删除设备」，B 的列表里该设备也要
    /// 消失，而不是留一条每次同步都失败的死记录。
    ///
    /// 链路：A 本地删配对 → 后台线程连 B → PFS 握手 → `MSG_UNPAIR_NOTICE`
    /// → B 校验 from 与已认证身份一致 → B 删配对 + 销毁两两密钥 → 回调宿主落库。
    #[test]
    fn unpair_notice_auto_unpairs_online_peer() {
        use std::time::Duration;

        let make_cfg = |id: &str, name: &str| SyncConfig {
            device_id: id.into(),
            device_name: name.into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };

        let node_a = MuClipSyncEngine::start(make_cfg("unpair-a", "Device A")).expect("start A");
        let node_b = MuClipSyncEngine::start(make_cfg("unpair-b", "Device B")).expect("start B");
        node_a.set_auto_discovery(false);
        node_b.set_auto_discovery(false);

        let port_a = node_a.bound_port();
        let port_b = node_b.bound_port();

        // B 侧先挂好「被解配」通知，用通道带超时收，避免回归时整个测试挂死
        let (unpaired_tx, unpaired_rx) = std::sync::mpsc::channel::<String>();
        node_b.on_peer_unpaired(Arc::new(move |dev_id| {
            let _ = unpaired_tx.send(dev_id);
        }));

        // 配对：A 发请求，B 用 PIN 应答
        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let b_ref = Arc::clone(&node_b);
            node_b.on_pair_request_received(Arc::new(move |req_id, _from_id, _from_name, _ip| {
                let b_inner = Arc::clone(&b_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(b_inner.respond_pair(&req_id, "246813", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp = node_a
                .request_pair(&format!("127.0.0.1:{}", port_b), "246813", 5)
                .expect("pair A->B");
            assert!(resp.accepted, "配对应成功");
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("B respond_pair done");
            node_a.add_paired_device(&format!("unpair-b|127.0.0.1|{}", port_b));
            node_b.add_paired_device(&format!("unpair-a|127.0.0.1|{}", port_a));
        }

        let key_ab = node_a
            .peer_manager
            .get_peer_key("unpair-b")
            .expect("A 侧应有对等密钥");
        assert_eq!(node_b.peer_manager.get_peer_key("unpair-a"), Some(key_ab));
        assert!(node_a.peer_manager.is_paired("unpair-b"));
        assert!(node_b.peer_manager.is_paired("unpair-a"));

        // A 解配 B（带端点提示，等价于 UI 上点「删除设备」）
        node_a.remove_paired_device(&format!("unpair-b|127.0.0.1|{}", port_b));

        assert!(
            !node_a.peer_manager.is_paired("unpair-b"),
            "发起方必须立刻完成本地解配，不能等通告结果"
        );

        let got = unpaired_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("对端在线时必须收到解配通告；收不到说明通告没送达（密钥/握手/路由任一环断了）");
        assert_eq!(got, "unpair-a", "通告里的设备 id 必须是发起方");

        assert!(
            !node_b.peer_manager.is_paired("unpair-a"),
            "接收方必须自动解配，否则列表里会留下一条同步必败的死记录"
        );
        assert!(
            node_b.peer_manager.get_peer_key("unpair-a").is_none(),
            "解配必须连带销毁对等密钥，否则对端仍能完成 PFS 握手"
        );

        node_a.stop();
        node_b.stop();
    }

    /// 对端**离线时**被解配：等本端下次同步到它，收到 `ERR_NOT_PAIRED` 后本地自行清理。
    ///
    /// 这条补的是通告送不到的那一半：A 离线 → B 解配时发不出通告 → A 复网后仍以为
    /// 自己是配对的。修前这里只被用来「别把 peer 误标成离线」，配对记录与密钥都留着，
    /// UI 上表现为「每条剪贴板都同步失败」，用户还得再手动删一次。
    #[test]
    fn err_not_paired_clears_stale_pairing_locally() {
        use std::time::Duration;

        let make_cfg = |id: &str, name: &str| SyncConfig {
            device_id: id.into(),
            device_name: name.into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };

        let node_a = MuClipSyncEngine::start(make_cfg("stale-a", "Device A")).expect("start A");
        let node_b = MuClipSyncEngine::start(make_cfg("stale-b", "Device B")).expect("start B");
        node_a.set_auto_discovery(false);
        node_b.set_auto_discovery(false);
        let port_a = node_a.bound_port();
        let port_b = node_b.bound_port();

        // 配对（双方都建立两两密钥与白名单）
        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let b_ref = Arc::clone(&node_b);
            node_b.on_pair_request_received(Arc::new(move |req_id, _f, _n, _ip| {
                let b_inner = Arc::clone(&b_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    assert_eq!(b_inner.respond_pair(&req_id, "135790", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp = node_a
                .request_pair(&format!("127.0.0.1:{}", port_b), "135790", 5)
                .expect("pair A->B");
            assert!(resp.accepted);
            done_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("B respond_pair done");
            node_a.add_paired_device(&format!("stale-b|127.0.0.1|{}", port_b));
            node_b.add_paired_device(&format!("stale-a|127.0.0.1|{}", port_a));
        }

        let rx_b = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        {
            let rx_ref = Arc::clone(&rx_b);
            node_b.on_clipboard_received(Arc::new(move |p| {
                rx_ref.lock().unwrap().push(p.content);
            }));
        }

        // 先成功同步一次，让 A 侧建立长连接池（走的是「复用连接」那条分支，
        // 只有那条分支才会收到明文 `ERR_NOT_PAIRED` 应答）
        assert_eq!(node_a.broadcast_clipboard("warmup", "text/plain"), 1);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(rx_b.lock().unwrap().as_slice(), &["warmup"]);

        // B 单方面解配，但**不**发通告：模拟 B 在 A 离线时完成解配
        node_b.peer_manager.remove_paired_device_id("stale-a");

        // A 侧挂上「被解配」通知
        let (unpaired_tx, unpaired_rx) = std::sync::mpsc::channel::<String>();
        node_a.on_peer_unpaired(Arc::new(move |dev| {
            let _ = unpaired_tx.send(dev);
        }));

        // A 再同步：连接池复用 → B 回 ERR_NOT_PAIRED → A 必须自行清除
        assert_eq!(node_a.broadcast_clipboard("after-stale", "text/plain"), 0);

        let got = unpaired_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("收到 ERR_NOT_PAIRED 后必须回调宿主，让 UI 与持久化记录一起清掉");
        assert_eq!(got, "stale-b");
        assert!(
            !node_a.peer_manager.is_paired("stale-b"),
            "收到 ERR_NOT_PAIRED 后本地必须解除配对"
        );
        assert!(
            node_a.peer_manager.get_peer_key("stale-b").is_none(),
            "失效配对的对等密钥必须一起销毁"
        );
        // B 侧没收到第二条内容
        assert_eq!(rx_b.lock().unwrap().as_slice(), &["warmup"]);

        node_a.stop();
        node_b.stop();
    }

    /// 同一对端连续被会话握手拒绝到阈值时，提示宿主一次；中间成功一次则重新计数。
    ///
    /// `SyncRejected` 是笼统的认证失败（对端已解配 / 密钥不一致 / 地址串台），
    /// 服务端刻意不区分原因，所以 core **不自动解配**，只把「这配对可能废了」告诉宿主。
    /// 这条测试同时钉住「成功即清零」——否则偶发一次竞态就会让计数一路累加，
    /// 几天后弹出一个毫无意义的提示。
    #[test]
    fn auth_rejected_hint_fires_at_threshold_and_resets_on_success() {
        let make_cfg = |id: &str, name: &str| SyncConfig {
            device_id: id.into(),
            device_name: name.into(),
            device_type: "Windows".into(),
            sync_port: 0,
            discovery_port: 0,
            pairing_pin: "000000".into(),
        };

        let node_a = MuClipSyncEngine::start(make_cfg("hj-a", "Device A")).expect("start A");
        let node_b = MuClipSyncEngine::start(make_cfg("hj-b", "Device B")).expect("start B");
        node_a.set_auto_discovery(false);
        node_b.set_auto_discovery(false);
        let port_a = node_a.bound_port();
        let port_b = node_b.bound_port();

        {
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let b_ref = Arc::clone(&node_b);
            node_b.on_pair_request_received(Arc::new(move |req_id, _f, _n, _ip| {
                let b_inner = Arc::clone(&b_ref);
                let tx = done_tx.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    assert_eq!(b_inner.respond_pair(&req_id, "975310", true), 0);
                    let _ = tx.send(());
                });
            }));
            let resp = node_a
                .request_pair(&format!("127.0.0.1:{}", port_b), "975310", 5)
                .expect("pair A->B");
            assert!(resp.accepted);
            done_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("B respond_pair done");
            node_a.add_paired_device(&format!("hj-b|127.0.0.1|{}", port_b));
            node_b.add_paired_device(&format!("hj-a|127.0.0.1|{}", port_a));
        }

        let key_ab = node_a
            .peer_manager
            .get_peer_key("hj-b")
            .expect("A 侧对等密钥");

        // 每次尝试前清掉连接池：PFS 会话一旦建立，换掉 peer_key 也不会让旧连接失效，
        // 不清池就测不到「新建连接被拒」这个真实场景。
        let sync_once = |text: &str| -> usize {
            node_a.client.clear_connection_pool();
            node_a.broadcast_clipboard(text, "text/plain")
        };

        let (hint_tx, hint_rx) = std::sync::mpsc::channel::<(String, u32)>();
        node_a.on_peer_auth_rejected(Arc::new(move |dev, streak| {
            let _ = hint_tx.send((dev.to_string(), streak));
        }));

        // 让 B 侧的对等密钥变成"另一把"：白名单仍保留 A，但 auth_tag 对不上，
        // 于是每次 SESSION_INIT 都拿到 accepted=false（客户端视角就是 SyncRejected）。
        // 这比"把 A 从白名单删掉"更贴近真实成因之一（改过 PIN / 对端重装后重新配对），
        // 也避免踩到 ERR_NOT_PAIRED 那条分支（那是"对端确实解配了"，另有用例覆盖）。
        let wrong_key = crate::sync::crypto::derive_key("some-other-pin", None).unwrap();
        node_b.peer_manager.set_peer_key("hj-a", wrong_key);

        // 连续被拒 2 次：未到阈值，不能打扰用户
        assert_eq!(sync_once("hop 1"), 0);
        assert_eq!(sync_once("hop 2"), 0);
        assert!(
            hint_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "未到阈值就提示，会在正常的启动竞态里误报"
        );

        // 恢复密钥：成功同步一次必须把连续计数清零
        node_b.peer_manager.set_peer_key("hj-a", key_ab);
        assert_eq!(sync_once("recovered"), 1);

        // 再次把密钥弄错：又被打回原形，此时应从 1 重新数
        node_b.peer_manager.set_peer_key("hj-a", wrong_key);
        assert_eq!(sync_once("hop 3"), 0);
        assert_eq!(sync_once("hop 4"), 0);
        assert!(
            hint_rx
                .recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "成功一次后计数必须归零；不归零会提前触发提示"
        );

        // 第 3 次连续拒绝 —— 此时才提示
        assert_eq!(sync_once("hop 5"), 0);
        let (dev, streak) = hint_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("连续 3 次被拒必须提示宿主");
        assert_eq!(dev, "hj-b");
        assert_eq!(streak, AUTH_REJECT_HINT_THRESHOLD);

        // 提示归提示，配对与密钥一律不许动（解配必须是用户的决定）
        assert!(
            node_a.peer_manager.is_paired("hj-b"),
            "提示路径绝不能顺手解配"
        );
        assert!(node_a.peer_manager.get_peer_key("hj-b").is_some());

        node_a.stop();
        node_b.stop();
    }
}

pub mod net_utils;
pub mod peer_manager;
pub mod probe;

pub use net_utils::{get_local_ipv4_interfaces, parse_peer_endpoint};
pub use peer_manager::{
    BEACON_MAGIC, DEFAULT_DISCOVERY_PORT, DiscoveryBeacon, GossipPeerInfo, LEGACY_MDNS_PORT,
    MDNS_MULTICAST_IPV4, PEER_TIMEOUT_SECS, PeerInfo, PeerManager,
};
pub use probe::{probe_manual_peer_tcp, probe_paired_peer_tcp};

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use net_utils::create_discovery_rx_socket;
use probe::send_discovery_beacon_round;

pub struct DiscoveryService {
    local_beacon: Arc<RwLock<DiscoveryBeacon>>,
    peer_manager: Arc<PeerManager>,
    running: Arc<AtomicBool>,
    auto_discovery_enabled: Arc<AtomicBool>,
    broadcast_handle: Mutex<Option<JoinHandle<()>>>,
    listen_handle: Mutex<Option<JoinHandle<()>>>,
    discovery_port: u16,
    manual_peers: Arc<RwLock<Vec<String>>>,
}

impl DiscoveryService {
    pub fn new(
        device_id: String,
        device_name: String,
        device_type: String,
        sync_port: u16,
        discovery_port: u16,
        fingerprint: String,
        peer_manager: Arc<PeerManager>,
        manual_peers: Arc<RwLock<Vec<String>>>,
    ) -> Self {
        peer_manager.set_local_device_id(device_id.clone());
        let local_beacon = Arc::new(RwLock::new(DiscoveryBeacon {
            magic: BEACON_MAGIC.to_string(),
            device_id,
            device_name,
            device_type,
            sync_port,
            protocol_ver: 1,
            fingerprint,
            timestamp_ms: 0,
            is_reply: false,
            known_peers: Vec::new(),
        }));

        let port = if discovery_port > 0 {
            discovery_port
        } else {
            DEFAULT_DISCOVERY_PORT
        };

        Self {
            local_beacon,
            peer_manager,
            running: Arc::new(AtomicBool::new(false)),
            auto_discovery_enabled: Arc::new(AtomicBool::new(true)),
            broadcast_handle: Mutex::new(None),
            listen_handle: Mutex::new(None),
            discovery_port: port,
            manual_peers,
        }
    }

    pub fn set_auto_discovery_enabled(&self, enabled: bool) {
        self.auto_discovery_enabled.store(enabled, Ordering::SeqCst);
    }

    pub fn is_auto_discovery_enabled(&self) -> bool {
        self.auto_discovery_enabled.load(Ordering::SeqCst)
    }

    /// 立即在后台对指定的端口映射节点发起一次 TCP 握手探测
    pub fn probe_manual_peer_async(&self, peer_addr: &str) {
        let local_beacon_ref = Arc::clone(&self.local_beacon);
        let peer_mgr_ref = Arc::clone(&self.peer_manager);
        let addr_owned = peer_addr.to_string();
        thread::spawn(move || {
            if let Ok(mut b) = local_beacon_ref.read().map(|b| b.clone()) {
                b.timestamp_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                b.known_peers = peer_mgr_ref.get_gossip_peers(&b.device_id);
                probe_manual_peer_tcp(&b, &addr_owned, &peer_mgr_ref);
            }
        });
    }

    /// 立即触发一次全网卡单次探测广播与离线节点探测（无论自动广播是否开启）
    pub fn trigger_scan(&self) {
        let local_beacon_ref = Arc::clone(&self.local_beacon);
        let disc_port = self.discovery_port;
        let manual_peers_ref = Arc::clone(&self.manual_peers);
        let peer_mgr_ref = Arc::clone(&self.peer_manager);

        thread::spawn(move || {
            send_discovery_beacon_round(
                &local_beacon_ref,
                disc_port,
                &manual_peers_ref,
                &peer_mgr_ref,
                true,
                true,
            );
        });
    }

    pub fn update_fingerprint(&self, fp: String) {
        if let Ok(mut beacon) = self.local_beacon.write() {
            beacon.fingerprint = fp.clone();
        }
        self.peer_manager.set_local_fingerprint(fp);
    }

    pub fn set_paired_device_ids(&self, ids: Vec<String>) {
        self.peer_manager.set_paired_device_ids(ids);
    }

    pub fn add_paired_device_id(&self, id: String) {
        let parts: Vec<&str> = id.split('|').collect();
        let dev_id = parts.first().map(|s| s.trim()).unwrap_or("").to_string();
        let hint_ip = parts.get(1).map(|s| s.trim()).unwrap_or("").to_string();
        let hint_port = parts
            .get(2)
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(crate::sync::DEFAULT_SYNC_PORT);

        self.peer_manager.add_paired_device_id(id);

        // 首次注册带 IP 的已保存配对设备时，如果尚未探测过 (last_seen_ms == 0)，仅发起单次初始在线检查
        if !dev_id.is_empty() && !hint_ip.is_empty() && self.running.load(Ordering::Relaxed) {
            let should_probe = self
                .peer_manager
                .get_all_peers()
                .iter()
                .any(|p| p.device_id == dev_id && !p.is_online && p.last_seen_ms == 0);
            if should_probe {
                let local_beacon_ref = Arc::clone(&self.local_beacon);
                let peer_mgr_ref = Arc::clone(&self.peer_manager);
                let disc_port = self.discovery_port;
                thread::spawn(move || {
                    if let Ok(mut b) = local_beacon_ref.read().map(|b| b.clone()) {
                        b.is_reply = false;
                        b.timestamp_ms = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;
                        b.known_peers = peer_mgr_ref.get_gossip_peers(&b.device_id);
                        if let Ok(ip) = hint_ip.parse::<Ipv4Addr>() {
                            if let Ok(bytes) = serde_json::to_vec(&b) {
                                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                                    let _ = sock.send_to(
                                        &bytes,
                                        SocketAddr::V4(SocketAddrV4::new(ip, disc_port)),
                                    );
                                }
                            }
                        }
                        probe_paired_peer_tcp(&b, &dev_id, &hint_ip, hint_port, &peer_mgr_ref);
                    }
                });
            }
        }
    }

    pub fn remove_paired_device_id(&self, id: &str) {
        self.peer_manager.remove_paired_device_id(id);
    }

    pub fn is_paired(&self, id: &str) -> bool {
        self.peer_manager.is_paired(id)
    }

    pub fn touch_peer(&self, id: &str) {
        self.peer_manager.touch_peer(id);
    }

    pub fn update_sync_port(&self, port: u16) {
        if let Ok(mut beacon) = self.local_beacon.write() {
            beacon.sync_port = port;
        }
    }

    pub fn start(&self) -> Result<(), std::io::Error> {
        if self.running.swap(true, Ordering::SeqCst) {
            return Ok(()); // Already running
        }

        let local_beacon_ref = Arc::clone(&self.local_beacon);
        let local_beacon_for_reply = Arc::clone(&self.local_beacon);
        let local_id = self.local_beacon.read().unwrap().device_id.clone();
        let running_broadcast = Arc::clone(&self.running);
        let auto_discovery_ref = Arc::clone(&self.auto_discovery_enabled);
        let disc_port = self.discovery_port;
        let manual_peers_ref = Arc::clone(&self.manual_peers);
        let peer_mgr_for_tx = Arc::clone(&self.peer_manager);

        // 1. Broadcast / Keepalive thread:
        //    启动前 2 轮快速宣告上线（2s 间隔），进入稳态后每 5 秒发送一次轻量局域网心跳与已配对节点保活探测。
        let broadcast_thread = thread::Builder::new()
            .name("muclip-discovery-tx".into())
            .spawn(move || {
                let mut loop_count: u32 = 0;
                while running_broadcast.load(Ordering::Relaxed) {
                    if auto_discovery_ref.load(Ordering::Relaxed) {
                        let is_initial = loop_count < 2;
                        let is_full_broadcast = is_initial || (loop_count % 3 == 0);
                        send_discovery_beacon_round(
                            &local_beacon_ref,
                            disc_port,
                            &manual_peers_ref,
                            &peer_mgr_for_tx,
                            is_full_broadcast,
                            true,
                        );
                    }

                    loop_count = loop_count.wrapping_add(1);
                    let sleep_ms = if loop_count < 2 { 2000 } else { 5000 };
                    let ticks = sleep_ms / 100;
                    for _ in 0..ticks {
                        if !running_broadcast.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            })?;

        // 2. Primary listener thread: binds to discovery_port (e.g. 42110)
        let running_listen = Arc::clone(&self.running);
        let peer_mgr = Arc::clone(&self.peer_manager);
        let local_id_clone = local_id.clone();
        let listen_thread = thread::Builder::new()
            .name("muclip-discovery-rx".into())
            .spawn(move || {
                let socket = match create_discovery_rx_socket(disc_port) {
                    Ok(s) => s,
                    Err(_) => match UdpSocket::bind("0.0.0.0:0") {
                        Ok(s) => {
                            let _ =
                                s.join_multicast_v4(&MDNS_MULTICAST_IPV4, &Ipv4Addr::UNSPECIFIED);
                            s
                        }
                        Err(e) => {
                            crate::log_error!(
                                "发现服务无法绑定接收端口 {}，本机将收不到其他设备的广播: {:?}",
                                disc_port,
                                e
                            );
                            return;
                        }
                    },
                };

                let _ = socket.set_read_timeout(Some(Duration::from_millis(1000)));
                let mut buf = [0u8; 4096];
                let mut last_prune = Instant::now();
                let mut last_unicast_reply: HashMap<Ipv4Addr, Instant> = HashMap::new();

                while running_listen.load(Ordering::Relaxed) {
                    if last_prune.elapsed() > Duration::from_secs(2) {
                        peer_mgr.prune_stale_peers(PEER_TIMEOUT_SECS);
                        last_prune = Instant::now();
                    }

                    match socket.recv_from(&mut buf) {
                        Ok((len, src)) => {
                            if let Ok(beacon) =
                                serde_json::from_slice::<DiscoveryBeacon>(&buf[..len])
                            {
                                if beacon.magic == BEACON_MAGIC
                                    && beacon.device_id != local_id_clone
                                {
                                    let is_reply_beacon = beacon.is_reply;
                                    let is_new = peer_mgr.update_peer(beacon, src.ip().to_string());

                                    // 单播反向回应 (防风暴受控 Ping-Pong Reply)：
                                    // 仅当收到的不是单播回包 (!is_reply_beacon)，且为新发现设备或距上次向该 IP 单播回包已满 5 秒时才回发一次，
                                    // 彻底消除双端收到单播后无限 0ms 互发导致的网络风暴。
                                    if !is_reply_beacon {
                                        if let SocketAddr::V4(src_v4) = src {
                                            let src_ip = *src_v4.ip();
                                            let now = Instant::now();
                                            let should_reply = is_new
                                                || last_unicast_reply.get(&src_ip).map_or(
                                                    true,
                                                    |last| {
                                                        now.duration_since(*last)
                                                            >= Duration::from_secs(1)
                                                    },
                                                );
                                            if should_reply {
                                                last_unicast_reply.insert(src_ip, now);
                                                if let Ok(local_b) = local_beacon_for_reply.read() {
                                                    let mut reply_b = local_b.clone();
                                                    reply_b.is_reply = true;
                                                    reply_b.timestamp_ms = SystemTime::now()
                                                        .duration_since(UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_millis()
                                                        as u64;
                                                    reply_b.known_peers = peer_mgr
                                                        .get_gossip_peers(&reply_b.device_id);
                                                    if let Ok(resp_bytes) =
                                                        serde_json::to_vec(&reply_b)
                                                    {
                                                        let reply_target =
                                                            SocketAddrV4::new(src_ip, disc_port);
                                                        let _ = socket.send_to(
                                                            &resp_bytes,
                                                            SocketAddr::V4(reply_target),
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(ref e)
                            if e.kind() == std::io::ErrorKind::TimedOut
                                || e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {}
                    }
                }
            })?;

        if let Ok(mut guard) = self.broadcast_handle.lock() {
            *guard = Some(broadcast_thread);
        }
        if let Ok(mut guard) = self.listen_handle.lock() {
            *guard = Some(listen_thread);
        }

        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);

        if let Ok(mut guard) = self.broadcast_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
        if let Ok(mut guard) = self.listen_handle.lock() {
            if let Some(handle) = guard.take() {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for DiscoveryService {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_manager_pairing_and_lifecycle() {
        let mgr = PeerManager::new("my_local_fingerprint".to_string());
        let beacon = DiscoveryBeacon {
            magic: BEACON_MAGIC.to_string(),
            device_id: "android-phone-1".to_string(),
            device_name: "Pixel 8 Pro".to_string(),
            device_type: "Android".to_string(),
            sync_port: 42424,
            protocol_ver: 1,
            fingerprint: "my_local_fingerprint".to_string(),
            timestamp_ms: 1000,
            is_reply: false,
            known_peers: Vec::new(),
        };

        assert!(mgr.update_peer(beacon.clone(), "192.168.1.100".to_string()));
        let active = mgr.get_active_peers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].device_name, "Pixel 8 Pro");
        assert_eq!(active[0].ip, "192.168.1.100");
        assert!(active[0].is_online);
        assert!(!active[0].is_paired); // Initially unpaired

        // Explicitly pair device
        mgr.add_paired_device_id("android-phone-1".to_string());
        let active_paired = mgr.get_active_peers();
        assert_eq!(active_paired.len(), 1);
        assert!(active_paired[0].is_paired); // Now paired!

        // Unpair device
        mgr.remove_paired_device_id("android-phone-1");
        let active_unpaired = mgr.get_active_peers();
        assert_eq!(active_unpaired.len(), 1);
        assert!(!active_unpaired[0].is_paired); // Now unpaired!

        // Pruning with 0s timeout should mark peer offline
        mgr.prune_stale_peers(0);
        let active_after = mgr.get_active_peers();
        assert_eq!(active_after.len(), 0);
    }

    #[test]
    fn test_manual_port_mapped_peer_lifecycle() {
        let mgr = PeerManager::new("local_fp".to_string());

        // 1. Register manual port-mapped endpoint (before pairing or probe)
        let norm = mgr.register_manual_endpoint("frp.example.com", 55555);
        assert_eq!(norm, "frp.example.com:55555");

        let active = mgr.get_active_peers();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].ip, "frp.example.com");
        assert_eq!(active[0].sync_port, 55555);
        assert!(active[0].is_manual);
        assert!(!active[0].is_paired);

        // 2. Simulate TCP MSG_HEARTBEAT probe resolving real device info (whose internal port is 42424)
        let remote_beacon = DiscoveryBeacon {
            magic: BEACON_MAGIC.to_string(),
            device_id: "remote-pc-id".to_string(),
            device_name: "Office Workstation".to_string(),
            device_type: "Windows".to_string(),
            sync_port: 42424, // internal port
            protocol_ver: 1,
            fingerprint: "remote_fp".to_string(),
            timestamp_ms: 2000,
            is_reply: true,
            known_peers: Vec::new(),
        };
        mgr.update_peer_with_mapped_addr(remote_beacon, "frp.example.com".to_string(), 55555);

        let active_resolved = mgr.get_active_peers();
        assert_eq!(active_resolved.len(), 1);
        assert_eq!(active_resolved[0].device_id, "remote-pc-id");
        assert_eq!(active_resolved[0].device_name, "Office Workstation");
        assert_eq!(active_resolved[0].ip, "frp.example.com");
        assert_eq!(active_resolved[0].sync_port, 55555); // Preserves mapped port 55555!
        assert!(active_resolved[0].is_manual);

        // 3. Pair the resolved manual peer
        mgr.resolve_manual_peer_from_pair(
            "frp.example.com",
            55555,
            "remote-pc-id",
            "Office Workstation",
            true,
        );
        let active_paired = mgr.get_active_peers();
        assert_eq!(active_paired.len(), 1);
        assert!(active_paired[0].is_paired);

        // 4. Remove manual peer
        let removed = mgr.unregister_manual_endpoint("frp.example.com:55555", 42424);
        assert_eq!(removed, vec!["frp.example.com:55555".to_string()]);
        assert!(mgr.get_active_peers().is_empty());
    }

    #[test]
    fn test_local_ipv4_interfaces_discovery() {
        let interfaces = get_local_ipv4_interfaces();
        println!("Discovered local interfaces: {:?}", interfaces);
        #[cfg(windows)]
        {
            assert!(
                !interfaces.is_empty(),
                "Should discover at least one network interface"
            );
            for (ip, bcast) in interfaces {
                assert!(!ip.is_loopback());
                assert!(!bcast.is_loopback());
                println!("Interface: IP={}, Broadcast={}", ip, bcast);
            }
        }
    }
}

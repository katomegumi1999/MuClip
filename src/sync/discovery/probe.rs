use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::net_utils::{get_local_ipv4_interfaces, parse_peer_endpoint};
use super::peer_manager::{DiscoveryBeacon, MDNS_MULTICAST_IPV4, PeerManager};

/// Shared TCP `MSG_HEARTBEAT` request/response exchange over an established `TcpStream`.
fn exchange_tcp_heartbeat(
    stream: &mut TcpStream,
    local_beacon: &DiscoveryBeacon,
) -> Option<DiscoveryBeacon> {
    let pkt = crate::sync::protocol::encode_heartbeat_packet(1, local_beacon).ok()?;
    stream.write_all(&pkt).and_then(|_| stream.flush()).ok()?;

    let mut header_buf = [0u8; crate::sync::protocol::HEADER_SIZE];
    stream.read_exact(&mut header_buf).ok()?;
    let header = crate::sync::protocol::SyncHeader::parse(&header_buf).ok()?;
    let payload_len = header.payload_len as usize;
    if payload_len > 64 * 1024 {
        return None;
    }

    let mut raw_packet = vec![0u8; crate::sync::protocol::HEADER_SIZE + payload_len];
    raw_packet[..crate::sync::protocol::HEADER_SIZE].copy_from_slice(&header_buf);
    stream
        .read_exact(&mut raw_packet[crate::sync::protocol::HEADER_SIZE..])
        .ok()?;

    let (_h, remote_beacon) = crate::sync::protocol::decode_heartbeat_packet(&raw_packet).ok()?;
    Some(remote_beacon)
}

/// Probes a manual / port-mapped peer over TCP using `MSG_HEARTBEAT` (`PAIR_BOOTSTRAP_KEY`).
/// Works across NAT / FRP / SSH port forwarding even before the peer is paired.
pub fn probe_manual_peer_tcp(
    local_beacon: &DiscoveryBeacon,
    peer_addr: &str,
    peer_manager: &Arc<PeerManager>,
) {
    let (host, port) = match parse_peer_endpoint(peer_addr, crate::sync::DEFAULT_SYNC_PORT) {
        Some(hp) => hp,
        None => return,
    };
    let lookup_addr = format!("{}:{}", host, port);
    let sock_addr = match lookup_addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a,
        None => {
            peer_manager.touch_manual_endpoint(&host, port, false);
            return;
        }
    };

    let mut stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(1200)) {
        Ok(s) => s,
        Err(_) => {
            peer_manager.touch_manual_endpoint(&host, port, false);
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1200)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1200)));

    if let Some(remote_beacon) = exchange_tcp_heartbeat(&mut stream, local_beacon) {
        if remote_beacon.device_id != local_beacon.device_id {
            peer_manager.update_peer_with_mapped_addr(remote_beacon, host, port);
        }
    } else {
        peer_manager.touch_manual_endpoint(&host, port, false);
    }
}

/// Probes a known LAN paired peer over TCP using `MSG_HEARTBEAT`.
/// Never marks a peer offline immediately on single probe failure (e.g. Windows Firewall blocking
/// inbound TCP or brief Android Wi-Fi PSM wakeup); only marks offline if `last_seen_ms` has
/// genuinely exceeded `PEER_TIMEOUT_SECS`.
pub fn probe_paired_peer_tcp(
    local_beacon: &DiscoveryBeacon,
    device_id: &str,
    host: &str,
    port: u16,
    peer_manager: &Arc<PeerManager>,
) {
    let stale_ms = super::peer_manager::PEER_TIMEOUT_SECS * 1000;
    let lookup_addr = format!("{}:{}", host, port);
    let sock_addr = match lookup_addr
        .to_socket_addrs()
        .ok()
        .and_then(|mut it| it.next())
    {
        Some(a) => a,
        None => {
            peer_manager.mark_peer_offline_if_stale(device_id, host, port, stale_ms);
            return;
        }
    };

    let mut stream = match TcpStream::connect_timeout(&sock_addr, Duration::from_millis(1500)) {
        Ok(s) => s,
        Err(_) => {
            peer_manager.mark_peer_offline_if_stale(device_id, host, port, stale_ms);
            return;
        }
    };
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_millis(1500)));
    let _ = stream.set_read_timeout(Some(Duration::from_millis(1500)));

    if let Some(remote_beacon) = exchange_tcp_heartbeat(&mut stream, local_beacon) {
        if remote_beacon.device_id != local_beacon.device_id {
            peer_manager.update_peer(remote_beacon, host.to_string());
        }
    } else {
        peer_manager.mark_peer_offline_if_stale(device_id, host, port, stale_ms);
    }
}

pub(crate) fn send_discovery_beacon_round(
    local_beacon_ref: &Arc<RwLock<DiscoveryBeacon>>,
    disc_port: u16,
    manual_peers_ref: &Arc<RwLock<Vec<String>>>,
    peer_manager_ref: &Arc<PeerManager>,
    is_full_broadcast: bool,
    probe_offline_peers: bool,
) {
    let all_peers = peer_manager_ref.get_all_peers();

    // Steady-state fast path: when not doing a full LAN broadcast and not probing offline peers,
    // if there are no paired or manual peers with an IP, do nothing.
    if !is_full_broadcast && !probe_offline_peers {
        let has_known_target = all_peers
            .iter()
            .any(|p| !p.ip.is_empty() && (p.is_paired || p.is_manual || p.is_online));
        if !has_known_target {
            return;
        }
    }

    let mut beacon = match local_beacon_ref.read() {
        Ok(b) => b.clone(),
        Err(_) => return,
    };

    beacon.is_reply = false;
    beacon.timestamp_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    beacon.known_peers = peer_manager_ref.get_gossip_peers(&beacon.device_id);

    let bytes = match serde_json::to_vec(&beacon) {
        Ok(b) => b,
        Err(_) => return,
    };

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return,
    };

    if is_full_broadcast {
        let _ = socket.set_broadcast(true);
        let _ = socket.set_multicast_loop_v4(true);

        let target_multicast = SocketAddrV4::new(MDNS_MULTICAST_IPV4, disc_port);
        let target_broadcast = SocketAddrV4::new(Ipv4Addr::new(255, 255, 255, 255), disc_port);

        // 1. 全局受限广播与组播
        let _ = socket.send_to(&bytes, SocketAddr::V4(target_multicast));
        let _ = socket.send_to(&bytes, SocketAddr::V4(target_broadcast));

        // 2. 枚举本机所有活动物理与虚拟网络接口，从各网卡专用 Socket 发送定向子网广播与组播
        for (local_ip, bcast_ip) in get_local_ipv4_interfaces() {
            let target_subnet_bcast = SocketAddrV4::new(bcast_ip, disc_port);
            if let Ok(per_iface_socket) = UdpSocket::bind(SocketAddrV4::new(local_ip, 0)) {
                let _ = per_iface_socket.set_broadcast(true);
                let _ = per_iface_socket.send_to(&bytes, SocketAddr::V4(target_subnet_bcast));
                let _ = per_iface_socket.send_to(&bytes, SocketAddr::V4(target_multicast));
            } else {
                let _ = socket.send_to(&bytes, SocketAddr::V4(target_subnet_bcast));
            }
        }
    }

    // 3. 手动/端口映射节点保活与按需探测
    let manual_list = manual_peers_ref
        .read()
        .map(|p| p.clone())
        .unwrap_or_default();
    for peer_addr in &manual_list {
        if let Some((host, port)) = parse_peer_endpoint(peer_addr, crate::sync::DEFAULT_SYNC_PORT) {
            let matching_peer = all_peers
                .iter()
                .find(|p| p.ip.eq_ignore_ascii_case(&host) && p.sync_port == port);
            let is_online = matching_peer.map(|p| p.is_online).unwrap_or(false);

            if let Ok(ip) = host.parse::<Ipv4Addr>() {
                let target_unicast = SocketAddrV4::new(ip, disc_port);
                let _ = socket.send_to(&bytes, SocketAddr::V4(target_unicast));
            }

            if !is_online && !probe_offline_peers {
                continue;
            }

            let b_clone = beacon.clone();
            let addr_clone = peer_addr.clone();
            let pm_clone = Arc::clone(peer_manager_ref);
            std::thread::spawn(move || {
                probe_manual_peer_tcp(&b_clone, &addr_clone, &pm_clone);
            });
        }
    }

    // 4. 已配对/已知节点点对点 UDP 单播 + 异步 TCP MSG_HEARTBEAT 双向保活
    for peer in all_peers {
        if peer.ip.is_empty() || peer.is_manual || (!peer.is_paired && !peer.is_online) {
            continue;
        }
        if let Ok(ip) = peer.ip.parse::<Ipv4Addr>() {
            let target_unicast = SocketAddrV4::new(ip, disc_port);
            let _ = socket.send_to(&bytes, SocketAddr::V4(target_unicast));
        }
        let needs_tcp_probe = !peer.is_online
            || peer.last_seen_ms == 0
            || beacon.timestamp_ms.saturating_sub(peer.last_seen_ms) >= 6_000;
        if peer.sync_port > 0 && needs_tcp_probe {
            let b_clone = beacon.clone();
            let dev_id = peer.device_id.clone();
            let peer_ip = peer.ip.clone();
            let peer_port = peer.sync_port;
            let pm_clone = Arc::clone(peer_manager_ref);
            std::thread::spawn(move || {
                probe_paired_peer_tcp(&b_clone, &dev_id, &peer_ip, peer_port, &pm_clone);
            });
        }
    }
}

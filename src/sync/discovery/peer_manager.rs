use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use super::net_utils::parse_peer_endpoint;

pub const DEFAULT_DISCOVERY_PORT: u16 = 42110;
pub const LEGACY_MDNS_PORT: u16 = 5353;
pub const MDNS_MULTICAST_IPV4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
pub const BEACON_MAGIC: &str = "MUCLIP_MDNS_V1";
pub const PEER_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GossipPeerInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub ip: String,
    pub sync_port: u16,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrapped_peer_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoveryBeacon {
    pub magic: String,
    pub device_id: String,
    pub device_name: String,
    pub device_type: String, // "Windows", "Android", "Linux", "MacOS", "Avalonia"
    pub sync_port: u16,
    pub protocol_ver: u8,
    pub fingerprint: String,
    pub timestamp_ms: u64,
    #[serde(default)]
    pub is_reply: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub known_peers: Vec<GossipPeerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerInfo {
    pub device_id: String,
    pub device_name: String,
    pub device_type: String,
    pub ip: String,
    pub sync_port: u16,
    pub last_seen_ms: u64,
    pub is_online: bool,
    pub fingerprint: String,
    pub is_paired: bool,
    #[serde(default)]
    pub is_manual: bool,
}

pub struct PeerManager {
    peers: RwLock<HashMap<String, PeerInfo>>,
    local_device_id: RwLock<String>,
    local_fingerprint: RwLock<String>,
    local_key: RwLock<Option<[u8; crate::sync::crypto::KEY_SIZE]>>,
    paired_device_ids: RwLock<HashSet<String>>,
    /// Maps normalized manual endpoint `"host:port"` -> resolved `device_id` (if discovered/paired).
    manual_endpoints: RwLock<HashMap<String, Option<String>>>,
    /// Per-peer 256-bit permanent device keys (`device_id -> peer_key`).
    peer_keys: RwLock<HashMap<String, [u8; crate::sync::crypto::KEY_SIZE]>>,
}

impl PeerManager {
    pub fn new(local_fingerprint: String) -> Self {
        Self {
            peers: RwLock::new(HashMap::new()),
            local_device_id: RwLock::new(String::new()),
            local_fingerprint: RwLock::new(local_fingerprint),
            local_key: RwLock::new(None),
            paired_device_ids: RwLock::new(HashSet::new()),
            manual_endpoints: RwLock::new(HashMap::new()),
            peer_keys: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_local_device_id(&self, id: String) {
        if let Ok(mut lid) = self.local_device_id.write() {
            *lid = id;
        }
    }

    pub fn get_local_device_id(&self) -> String {
        self.local_device_id
            .read()
            .map(|id| id.clone())
            .unwrap_or_default()
    }

    pub fn set_local_fingerprint(&self, fp: String) {
        if let Ok(mut lfp) = self.local_fingerprint.write() {
            *lfp = fp;
        }
    }

    pub fn get_local_fingerprint(&self) -> String {
        self.local_fingerprint
            .read()
            .map(|fp| fp.clone())
            .unwrap_or_else(|_| "no-key".to_string())
    }

    pub fn set_local_key(&self, key: Option<[u8; crate::sync::crypto::KEY_SIZE]>) {
        if let Ok(mut lk) = self.local_key.write() {
            *lk = key.filter(|k| !crate::sync::crypto::is_default_key(k));
        }
    }

    pub fn get_local_key(&self) -> Option<[u8; crate::sync::crypto::KEY_SIZE]> {
        self.local_key.read().ok().and_then(|g| *g)
    }

    pub fn set_peer_key(&self, device_id: &str, key: [u8; crate::sync::crypto::KEY_SIZE]) {
        let trimmed = device_id.trim();
        if trimmed.is_empty() || crate::sync::crypto::is_default_key(&key) {
            return;
        }
        // 不再保留历史密钥：入向认证只认当前 `peer_key`，旧密钥永不被接受；
        // 出向逐个重试只会白跑完整握手。轮换密钥的正确路径是重新配对。
        if let Ok(mut map) = self.peer_keys.write() {
            map.insert(trimmed.to_string(), key);
        }
    }

    pub fn get_peer_key(&self, device_id: &str) -> Option<[u8; crate::sync::crypto::KEY_SIZE]> {
        self.peer_keys
            .read()
            .ok()
            .and_then(|map| map.get(device_id.trim()).copied())
    }

    pub fn get_candidate_keys(
        &self,
        device_id_hint: Option<&str>,
        primary_key: Option<[u8; crate::sync::crypto::KEY_SIZE]>,
    ) -> Vec<[u8; crate::sync::crypto::KEY_SIZE]> {
        let mut keys = Vec::with_capacity(4);
        if let Some(dev_id) = device_id_hint {
            if let Some(pk) = self.get_peer_key(dev_id) {
                keys.push(pk);
                if let Some(pk_local) = primary_key {
                    if pk_local != pk {
                        keys.push(pk_local);
                    }
                }
                return keys;
            }
        }
        if let Some(pk) = primary_key {
            keys.push(pk);
        }
        // 不再追加历史密钥（原 fallback_keys）：服务端入向认证只认当前 `peer_key` 或本地密钥，
        // 历史密钥永远不会被接受，逐个尝试只会白跑完整的 X25519 握手。
        keys
    }

    /// Looks up a discovered or manual peer device_id by its network endpoint `(host, port)`.
    pub fn find_device_id_by_endpoint(&self, host: &str, port: u16) -> Option<String> {
        let trimmed_host = host.trim();
        let target_key = format!("{}:{}", trimmed_host, port);
        if let Ok(manual_map) = self.manual_endpoints.read() {
            if let Some(Some(dev_id)) = manual_map.get(&target_key) {
                return Some(dev_id.clone());
            }
        }
        if let Ok(peers) = self.peers.read() {
            for (id, p) in peers.iter() {
                let host_matches = p.ip.eq_ignore_ascii_case(trimmed_host)
                    || (trimmed_host == "127.0.0.1" && p.ip.eq_ignore_ascii_case("localhost"))
                    || (trimmed_host == "localhost" && p.ip == "127.0.0.1");
                let port_matches = port == 0 || p.sync_port == port;
                if host_matches && port_matches && !id.starts_with("manual-") {
                    return Some(id.clone());
                }
            }
        }
        None
    }

    /// 判断一个 fingerprint 是否是「看起来合法」的集群指纹。
    ///
    /// 注意：本函数**只做格式校验**，不构成任何身份证明。调用方不得据此自动信任对端——
    /// fingerprint 在 `DiscoveryBeacon` 中明文传输，可被同网段任意主机原样复读。
    /// 历史版本曾用它做自动配对判据，已移除（详见 `update_peer` 内的说明）。
    pub fn is_valid_cluster_fingerprint(fp: &str) -> bool {
        if fp.len() != 64 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        let default_fp = crate::sync::crypto::derive_key("000000", None)
            .map(|k| crate::sync::crypto::compute_sha256_hex(&k))
            .unwrap_or_default();
        fp != default_fp
    }

    /// 已配对设备的端点清单，用于随广播/心跳做 gossip。
    ///
    /// **恒返回空。** 保留该函数只为不打断原有调用点与协议字段的兼容性。
    ///
    /// 停发原因：
    /// 1. **端点信息本就无需广播** —— 任何收到 beacon/心跳的一方，都能从 UDP/TCP 包的
    ///    **源地址**直接得知对端的 IP；`get_gossip_peers` 里带的是**第三方**的 IP，
    ///    即"我认识谁、他们分别在哪"，属于纯拓扑泄露。
    /// 2. **它原本想做的事没做成** —— `wrapped_peer_key` 恒为 `None`，学到 IP 的一方
    ///    没有对应的两两密钥，过不了 PFS 握手，拿到的只是一个连不上的条目。
    /// 3. 因此它的实际产出只剩"把已配对设备的完整内网 IP 清单交给同网段任何人
    ///    （连 MuClip 都不用装）"，收益为零、风险为正。
    pub fn get_gossip_peers(&self, _exclude_device_id: &str) -> Vec<GossipPeerInfo> {
        Vec::new()
    }

    fn ingest_gossip_peers(
        &self,
        _sender_device_id: &str,
        gossip_list: &[GossipPeerInfo],
        now_ms: u64,
    ) {
        if gossip_list.is_empty() {
            return;
        }
        let local_id = self.get_local_device_id();

        for gp in gossip_list {
            let dev_id = gp.device_id.trim();
            if dev_id.is_empty()
                || dev_id.starts_with("manual-")
                || gp.ip.trim().is_empty()
                || gp.sync_port == 0
                || (!local_id.is_empty() && dev_id == local_id)
            {
                continue;
            }

            let is_paired = self.is_paired(dev_id);

            if let Ok(mut map) = self.peers.write() {
                if let Some(existing) = map.get_mut(dev_id) {
                    if !existing.is_online && !existing.is_manual {
                        existing.ip = gp.ip.clone();
                        existing.sync_port = gp.sync_port;
                        existing.is_online = true;
                        existing.last_seen_ms = now_ms;
                    }
                    if !gp.device_name.is_empty()
                        && (existing.device_name.is_empty() || existing.device_name == dev_id)
                    {
                        existing.device_name = gp.device_name.clone();
                    }
                    if !gp.device_type.is_empty()
                        && (existing.device_type.is_empty()
                            || existing.device_type == "Paired"
                            || existing.device_type == "Remote")
                    {
                        existing.device_type = gp.device_type.clone();
                    }
                } else {
                    map.insert(
                        dev_id.to_string(),
                        PeerInfo {
                            device_id: dev_id.to_string(),
                            device_name: if gp.device_name.is_empty() {
                                dev_id.to_string()
                            } else {
                                gp.device_name.clone()
                            },
                            device_type: if gp.device_type.is_empty() {
                                "Windows".to_string()
                            } else {
                                gp.device_type.clone()
                            },
                            ip: gp.ip.clone(),
                            sync_port: gp.sync_port,
                            last_seen_ms: now_ms,
                            is_online: true,
                            fingerprint: gp.fingerprint.clone(),
                            is_paired,
                            is_manual: false,
                        },
                    );
                }
            }
        }
    }

    pub fn set_paired_device_ids(&self, ids: Vec<String>) {
        let set: HashSet<String> = ids.into_iter().collect();
        if let Ok(mut lock) = self.paired_device_ids.write() {
            *lock = set.clone();
        }
        if let Ok(mut map) = self.peers.write() {
            for peer in map.values_mut() {
                peer.is_paired = set.contains(&peer.device_id);
            }
        }
    }

    pub fn add_paired_device_id(&self, id: String) {
        let parts: Vec<&str> = id.split('|').collect();
        let dev_id = parts.first().map(|s| s.trim()).unwrap_or("").to_string();
        if dev_id.is_empty() {
            return;
        }
        let hint_ip = parts.get(1).map(|s| s.trim()).unwrap_or("");
        let hint_port = parts
            .get(2)
            .and_then(|s| s.trim().parse::<u16>().ok())
            .filter(|&p| p > 0)
            .unwrap_or(crate::sync::DEFAULT_SYNC_PORT);
        let hint_name = parts.get(3).map(|s| s.trim()).unwrap_or("");
        let hint_type = parts.get(4).map(|s| s.trim()).unwrap_or("");
        let hint_peer_key = parts
            .get(5)
            .map(|s| s.trim())
            .and_then(|s| crate::sync::crypto::hex_to_32bytes(s).ok());

        if let Some(pk) = hint_peer_key {
            self.set_peer_key(&dev_id, pk);
        }

        if let Ok(mut lock) = self.paired_device_ids.write() {
            lock.insert(dev_id.clone());
        }
        if let Ok(mut map) = self.peers.write() {
            if let Some(peer) = map.get_mut(&dev_id) {
                peer.is_paired = true;
                if !hint_ip.is_empty() {
                    peer.ip = hint_ip.to_string();
                    peer.sync_port = hint_port;
                }
                if !hint_name.is_empty()
                    && (peer.device_name.is_empty() || peer.device_name == dev_id)
                {
                    peer.device_name = hint_name.to_string();
                }
                if !hint_type.is_empty()
                    && (peer.device_type.is_empty()
                        || peer.device_type == "Paired"
                        || peer.device_type == "Remote")
                {
                    peer.device_type = hint_type.to_string();
                }
            } else if !hint_ip.is_empty() {
                map.insert(
                    dev_id.clone(),
                    PeerInfo {
                        device_id: dev_id.clone(),
                        device_name: if hint_name.is_empty() {
                            dev_id
                        } else {
                            hint_name.to_string()
                        },
                        device_type: if hint_type.is_empty() {
                            "Paired".to_string()
                        } else {
                            hint_type.to_string()
                        },
                        ip: hint_ip.to_string(),
                        sync_port: hint_port,
                        last_seen_ms: 0,
                        is_online: false,
                        fingerprint: "paired".to_string(),
                        is_paired: true,
                        is_manual: false,
                    },
                );
            }
        }
    }

    /// 解除配对：移除配对关系并销毁该设备的两两密钥。
    ///
    /// 销毁密钥是这一步的实质——对方失去与你通信所需的密钥，即使之后重新出现在
    /// 配对列表里也无法完成 PFS 握手。配对列表的持久化由客户端自行保证。
    pub fn remove_paired_device_id(&self, id: &str) {
        if let Ok(mut lock) = self.paired_device_ids.write() {
            lock.remove(id);
        }
        if let Ok(mut keys) = self.peer_keys.write() {
            keys.remove(id);
        }
        if let Ok(mut map) = self.peers.write() {
            if let Some(peer) = map.get_mut(id) {
                peer.is_paired = false;
            }
        }
    }

    pub fn is_paired(&self, id: &str) -> bool {
        self.paired_device_ids
            .read()
            .map(|set| set.contains(id))
            .unwrap_or(false)
    }

    /// Registers a manual / port-mapped endpoint (`host:port`) into `PeerManager` immediately
    /// so it appears in `get_active_peers()` and `get_all_peers()` even before pairing or UDP broadcast.
    pub fn register_manual_endpoint(&self, host: &str, port: u16) -> String {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let endpoint_key = format!("{}:{}", host, port);
        let placeholder_id = format!("manual-{}:{}", host, port);

        let mut existing_dev_id: Option<String> = None;
        if let Ok(mut map) = self.peers.write() {
            for peer in map.values_mut() {
                if peer.ip.eq_ignore_ascii_case(host) && peer.sync_port == port {
                    peer.is_manual = true;
                    peer.is_online = true;
                    peer.last_seen_ms = now_ms;
                    existing_dev_id = Some(peer.device_id.clone());
                    break;
                }
            }

            if existing_dev_id.is_none() {
                let is_paired = self.is_paired(&placeholder_id);
                map.insert(
                    placeholder_id.clone(),
                    PeerInfo {
                        device_id: placeholder_id,
                        device_name: format!("映射节点 ({}:{})", host, port),
                        device_type: "Manual".to_string(),
                        ip: host.to_string(),
                        sync_port: port,
                        last_seen_ms: now_ms,
                        is_online: true,
                        fingerprint: "manual".to_string(),
                        is_paired,
                        is_manual: true,
                    },
                );
            }
        }

        if let Ok(mut manual_map) = self.manual_endpoints.write() {
            manual_map.insert(endpoint_key.clone(), existing_dev_id);
        }

        endpoint_key
    }

    /// Removes a manual / port-mapped endpoint by `"host:port"`, `"host"`, or `device_id`.
    /// Returns the removed normalized `"host:port"` keys.
    pub fn unregister_manual_endpoint(&self, addr_or_id: &str, default_port: u16) -> Vec<String> {
        let trimmed = addr_or_id.trim();
        let mut removed_keys = Vec::new();
        let mut dev_ids_to_remove = Vec::new();

        if let Some((host, port)) = parse_peer_endpoint(trimmed, default_port) {
            let endpoint_key = format!("{}:{}", host, port);
            let placeholder_id = format!("manual-{}:{}", host, port);
            dev_ids_to_remove.push(placeholder_id);

            if let Ok(mut manual_map) = self.manual_endpoints.write() {
                if let Some(resolved_opt) = manual_map.remove(&endpoint_key) {
                    removed_keys.push(endpoint_key);
                    if let Some(dev_id) = resolved_opt {
                        dev_ids_to_remove.push(dev_id);
                    }
                }
            }
        }

        // Also support removing by device_id directly
        if let Ok(mut manual_map) = self.manual_endpoints.write() {
            let matching_keys: Vec<String> = manual_map
                .iter()
                .filter_map(|(k, v)| {
                    if v.as_deref() == Some(trimmed) || format!("manual-{}", k) == trimmed {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for k in matching_keys {
                if let Some(resolved_opt) = manual_map.remove(&k) {
                    if !removed_keys.contains(&k) {
                        removed_keys.push(k.clone());
                    }
                    dev_ids_to_remove.push(format!("manual-{}", k));
                    if let Some(dev_id) = resolved_opt {
                        dev_ids_to_remove.push(dev_id);
                    }
                }
            }
        }
        dev_ids_to_remove.push(trimmed.to_string());

        if let Ok(mut map) = self.peers.write() {
            for id in &dev_ids_to_remove {
                if let Some(peer) = map.get(id) {
                    if peer.is_manual || id.starts_with("manual-") {
                        map.remove(id);
                    }
                }
            }
            if let Some((host, port)) = parse_peer_endpoint(trimmed, default_port) {
                map.retain(|_, p| {
                    !(p.is_manual && p.ip.eq_ignore_ascii_case(&host) && p.sync_port == port)
                });
            }
        }

        removed_keys
    }

    /// Updates a manual endpoint when a TCP `MSG_HEARTBEAT` probe returns the remote peer's `DiscoveryBeacon`.
    /// Replaces the `"manual-host:port"` placeholder with the real `device_id` & `device_name`, while preserving the mapped `host:port`.
    pub fn update_peer_with_mapped_addr(
        &self,
        beacon: DiscoveryBeacon,
        mapped_host: String,
        mapped_port: u16,
    ) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let endpoint_key = format!("{}:{}", mapped_host, mapped_port);
        let placeholder_id = format!("manual-{}:{}", mapped_host, mapped_port);

        if let Ok(mut lock) = self.paired_device_ids.write() {
            if lock.remove(&placeholder_id) {
                lock.insert(beacon.device_id.clone());
            }
        }

        // SECURITY: 不再依据 beacon 自报的 fingerprint 自动配对。
        // fingerprint 会随 UDP 发现广播与 TCP 心跳明文发出，同网段任何主机都能原样抄一份，
        // 因此它无法证明发送者身份。配对只允许由用户显式操作触发
        // （`add_paired_device_id` / `set_paired_device_ids`）。
        let _ = &beacon.fingerprint;

        let is_paired = self.is_paired(&beacon.device_id);
        if is_paired && !beacon.known_peers.is_empty() {
            self.ingest_gossip_peers(&beacon.device_id, &beacon.known_peers, now_ms);
        }

        if let Ok(mut manual_map) = self.manual_endpoints.write() {
            manual_map.insert(endpoint_key, Some(beacon.device_id.clone()));
        }

        if let Ok(mut map) = self.peers.write() {
            if beacon.device_id != placeholder_id {
                map.remove(&placeholder_id);
            }
            map.insert(
                beacon.device_id.clone(),
                PeerInfo {
                    device_id: beacon.device_id,
                    device_name: beacon.device_name,
                    device_type: beacon.device_type,
                    ip: mapped_host,
                    sync_port: mapped_port,
                    last_seen_ms: now_ms,
                    is_online: true,
                    fingerprint: beacon.fingerprint,
                    is_paired,
                    is_manual: true,
                },
            );
        }
    }

    /// Updates or resolves a peer entry when TCP pairing (`request_pair`) completes against `host:port`.
    pub fn resolve_manual_peer_from_pair(
        &self,
        host: &str,
        port: u16,
        responder_id: &str,
        responder_name: &str,
        accepted: bool,
    ) {
        if responder_id.trim().is_empty() {
            return;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let endpoint_key = format!("{}:{}", host, port);
        let placeholder_id = format!("manual-{}:{}", host, port);

        if accepted {
            self.add_paired_device_id(responder_id.to_string());
        }
        let is_paired = accepted || self.is_paired(responder_id);

        let mut is_manual = false;
        if let Ok(mut manual_map) = self.manual_endpoints.write() {
            if manual_map.contains_key(&endpoint_key) {
                manual_map.insert(endpoint_key, Some(responder_id.to_string()));
                is_manual = true;
            }
        }

        if let Ok(mut map) = self.peers.write() {
            if map.remove(&placeholder_id).is_some() {
                is_manual = true;
            }
            let (dev_type, fp, prev_manual) = map
                .get(responder_id)
                .map(|p| (p.device_type.clone(), p.fingerprint.clone(), p.is_manual))
                .unwrap_or_else(|| ("Windows".to_string(), "paired".to_string(), false));

            map.insert(
                responder_id.to_string(),
                PeerInfo {
                    device_id: responder_id.to_string(),
                    device_name: if responder_name.trim().is_empty() {
                        format!("{} ({}:{})", responder_id, host, port)
                    } else {
                        responder_name.to_string()
                    },
                    device_type: if dev_type == "Manual" {
                        "Windows".to_string()
                    } else {
                        dev_type
                    },
                    ip: host.to_string(),
                    sync_port: port,
                    last_seen_ms: now_ms,
                    is_online: true,
                    fingerprint: fp,
                    is_paired,
                    is_manual: is_manual || prev_manual,
                },
            );
        }
    }

    /// Upserts an incoming TCP peer on the server side (e.g. when paired or syncing over NAT/port-mapping).
    pub fn upsert_incoming_peer(
        &self,
        device_id: &str,
        device_name: &str,
        remote_ip: &str,
        default_port: u16,
        is_paired: bool,
    ) {
        if device_id.trim().is_empty() {
            return;
        }
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let paired = is_paired || self.is_paired(device_id);
        if let Ok(mut map) = self.peers.write() {
            if let Some(peer) = map.get_mut(device_id) {
                peer.last_seen_ms = now_ms;
                peer.is_online = true;
                peer.is_paired = paired;
                if !peer.is_manual && !remote_ip.trim().is_empty() {
                    peer.ip = remote_ip.to_string();
                }
                if !device_name.trim().is_empty()
                    && (peer.device_name.is_empty()
                        || peer.device_name == device_id
                        || peer.device_type == "Manual")
                {
                    peer.device_name = device_name.to_string();
                }
            } else {
                map.insert(
                    device_id.to_string(),
                    PeerInfo {
                        device_id: device_id.to_string(),
                        device_name: if device_name.trim().is_empty() {
                            device_id.to_string()
                        } else {
                            device_name.to_string()
                        },
                        device_type: "Remote".to_string(),
                        ip: remote_ip.to_string(),
                        sync_port: default_port,
                        last_seen_ms: now_ms,
                        is_online: true,
                        fingerprint: "tcp".to_string(),
                        is_paired: paired,
                        is_manual: false,
                    },
                );
            }
        }
    }

    pub fn touch_manual_endpoint(&self, host: &str, port: u16, is_online: bool) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Ok(mut map) = self.peers.write() {
            for peer in map.values_mut() {
                if peer.ip.eq_ignore_ascii_case(host) && peer.sync_port == port {
                    if is_online {
                        peer.last_seen_ms = now_ms;
                    }
                    peer.is_online = is_online;
                }
            }
        }
    }

    pub fn mark_peer_offline(&self, device_id: &str, host: &str, port: u16) {
        if let Ok(mut map) = self.peers.write() {
            if !device_id.is_empty() {
                if let Some(peer) = map.get_mut(device_id) {
                    peer.is_online = false;
                    if peer.last_seen_ms == 0 {
                        peer.last_seen_ms = 1;
                    }
                }
            }
            for peer in map.values_mut() {
                if peer.ip.eq_ignore_ascii_case(host) && (port == 0 || peer.sync_port == port) {
                    peer.is_online = false;
                    if peer.last_seen_ms == 0 {
                        peer.last_seen_ms = 1;
                    }
                }
            }
        }
    }

    pub fn mark_peer_offline_if_stale(
        &self,
        device_id: &str,
        host: &str,
        port: u16,
        grace_ms: u64,
    ) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Ok(mut map) = self.peers.write() {
            if !device_id.is_empty() {
                if let Some(peer) = map.get_mut(device_id) {
                    if peer.last_seen_ms == 0
                        || now_ms.saturating_sub(peer.last_seen_ms) >= grace_ms
                    {
                        peer.is_online = false;
                        if peer.last_seen_ms == 0 {
                            peer.last_seen_ms = 1;
                        }
                    }
                }
            }
            for peer in map.values_mut() {
                if peer.ip.eq_ignore_ascii_case(host) && (port == 0 || peer.sync_port == port) {
                    if peer.last_seen_ms == 0
                        || now_ms.saturating_sub(peer.last_seen_ms) >= grace_ms
                    {
                        peer.is_online = false;
                        if peer.last_seen_ms == 0 {
                            peer.last_seen_ms = 1;
                        }
                    }
                }
            }
        }
    }

    pub fn touch_peer(&self, device_id: &str) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Ok(mut map) = self.peers.write() {
            if let Some(peer) = map.get_mut(device_id) {
                peer.last_seen_ms = now_ms;
                peer.is_online = true;
            }
        }
    }

    /// 只更新**已存在**的 peer 条目，未知 `device_id` 一律忽略并返回 `false`。
    ///
    /// 专供被动接收的 TCP `MSG_HEARTBEAT` 使用。该帧由 `PAIR_BOOTSTRAP_KEY`（编译进二进制的
    /// 公开常量）加密，同网段任何主机都能构造出合法帧，因此**不能凭它创建新身份**——
    /// 否则攻击者可以往设备列表里塞任意 `device_id` / 设备名，伪装成"待配对的某台设备"
    /// 诱导用户选择，或用同 ID 覆盖真实 peer 的端点。
    ///
    /// 探活与 DHCP 换 IP 的正常需求不受影响：`device_id` 已存在于表中时，
    /// 仍走完整的 `update_peer` 逻辑刷新地址与在线状态。
    ///
    /// 返回值语义：`true` = 命中已有条目并已刷新；`false` = 未知身份，未做任何修改。
    /// 注意不能直接返回 `update_peer` 的结果——那个 `bool` 表示的是「是否为新设备」，
    /// 与这里的语义相反。
    pub fn update_existing_peer_only(&self, beacon: DiscoveryBeacon, remote_ip: String) -> bool {
        let known = self
            .peers
            .read()
            .map(|map| map.contains_key(&beacon.device_id))
            .unwrap_or(false);
        if !known {
            return false;
        }
        let _ = self.update_peer(beacon, remote_ip);
        true
    }

    pub fn update_peer(&self, beacon: DiscoveryBeacon, remote_ip: String) -> bool {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check if this device_id or remote_ip matches an existing manual endpoint override
        let mut manual_override: Option<(String, u16)> = None;
        let direct_placeholder_key = format!("{}:{}", remote_ip, beacon.sync_port);
        if let Ok(mut manual_map) = self.manual_endpoints.write() {
            // 1. Check if already bound by device_id
            for (endpoint_key, dev_id_opt) in manual_map.iter_mut() {
                if dev_id_opt.as_deref() == Some(beacon.device_id.as_str()) {
                    if let Some((h, p)) = parse_peer_endpoint(endpoint_key, beacon.sync_port) {
                        manual_override = Some((h, p));
                        break;
                    }
                }
            }
            // 2. Or if there is an unbound manual endpoint matching remote_ip:sync_port or remote_ip:*
            if manual_override.is_none() {
                if manual_map.contains_key(&direct_placeholder_key) {
                    manual_map.insert(
                        direct_placeholder_key.clone(),
                        Some(beacon.device_id.clone()),
                    );
                    manual_override = Some((remote_ip.clone(), beacon.sync_port));
                } else {
                    for (endpoint_key, dev_id_opt) in manual_map.iter_mut() {
                        if dev_id_opt.is_none() {
                            if let Some((h, p)) =
                                parse_peer_endpoint(endpoint_key, beacon.sync_port)
                            {
                                if h.eq_ignore_ascii_case(&remote_ip) {
                                    *dev_id_opt = Some(beacon.device_id.clone());
                                    manual_override = Some((h, p));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        // SECURITY: 不再依据 beacon 自报的 fingerprint 自动配对。
        // fingerprint 会随 UDP 发现广播与 TCP 心跳明文发出，同网段任何主机都能原样抄一份，
        // 因此它无法证明发送者身份。配对只允许由用户显式操作触发
        // （`add_paired_device_id` / `set_paired_device_ids`）。
        let _ = &beacon.fingerprint;

        let is_paired = self
            .paired_device_ids
            .read()
            .map(|set| set.contains(&beacon.device_id))
            .unwrap_or(false);

        if is_paired && !beacon.known_peers.is_empty() {
            self.ingest_gossip_peers(&beacon.device_id, &beacon.known_peers, now_ms);
        }

        let mut map = match self.peers.write() {
            Ok(m) => m,
            Err(_) => return false,
        };

        let (final_ip, final_port, is_manual) = if let Some((mh, mp)) = manual_override {
            let placeholder_id = format!("manual-{}:{}", mh, mp);
            if beacon.device_id != placeholder_id {
                map.remove(&placeholder_id);
            }
            (mh, mp, true)
        } else {
            let prev_manual = map
                .get(&beacon.device_id)
                .map(|p| p.is_manual)
                .unwrap_or(false);
            (remote_ip, beacon.sync_port, prev_manual)
        };

        let is_new = !map.contains_key(&beacon.device_id);
        map.insert(
            beacon.device_id.clone(),
            PeerInfo {
                device_id: beacon.device_id,
                device_name: beacon.device_name,
                device_type: beacon.device_type,
                ip: final_ip,
                sync_port: final_port,
                last_seen_ms: now_ms,
                is_online: true,
                fingerprint: beacon.fingerprint,
                is_paired,
                is_manual,
            },
        );
        is_new
    }

    pub fn prune_stale_peers(&self, timeout_secs: u64) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let paired_timeout_ms = timeout_secs * 1000;
        let unpaired_timeout_ms = if timeout_secs == 0 {
            0
        } else {
            (timeout_secs * 1000).max(60_000)
        };

        if let Ok(mut map) = self.peers.write() {
            for peer in map.values_mut() {
                if !peer.is_manual {
                    let limit_ms = if peer.is_paired {
                        paired_timeout_ms
                    } else {
                        unpaired_timeout_ms
                    };
                    if now_ms.saturating_sub(peer.last_seen_ms) >= limit_ms {
                        peer.is_online = false;
                    }
                }
            }
        }
    }

    pub fn get_active_peers(&self) -> Vec<PeerInfo> {
        self.prune_stale_peers(PEER_TIMEOUT_SECS);
        let map = match self.peers.read() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        map.values()
            .filter(|p| p.is_online || p.is_manual)
            .cloned()
            .map(|mut p| {
                if p.is_paired {
                    if let Some(pk) = self.get_peer_key(&p.device_id) {
                        p.fingerprint = crate::sync::crypto::bytes_to_hex(&pk);
                    }
                }
                p
            })
            .collect()
    }

    pub fn get_all_peers(&self) -> Vec<PeerInfo> {
        self.prune_stale_peers(PEER_TIMEOUT_SECS);
        let map = match self.peers.read() {
            Ok(m) => m,
            Err(_) => return Vec::new(),
        };
        map.values()
            .cloned()
            .map(|mut p| {
                if p.is_paired {
                    if let Some(pk) = self.get_peer_key(&p.device_id) {
                        p.fingerprint = crate::sync::crypto::bytes_to_hex(&pk);
                    }
                }
                p
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beacon(device_id: &str, fingerprint: &str) -> DiscoveryBeacon {
        DiscoveryBeacon {
            magic: crate::sync::discovery::BEACON_MAGIC.to_string(),
            device_id: device_id.to_string(),
            device_name: "Spoofed".to_string(),
            device_type: "Windows".to_string(),
            sync_port: crate::sync::DEFAULT_SYNC_PORT,
            protocol_ver: 1,
            fingerprint: fingerprint.to_string(),
            timestamp_ms: 0,
            is_reply: false,
            known_peers: Vec::new(),
        }
    }

    /// 解绑的实质是销毁两两密钥：没有密钥的对方无法通过 PFS 握手。
    #[test]
    fn unpair_destroys_pairing_and_two_way_key() {
        let mgr = PeerManager::new("unused".to_string());
        let key = crate::sync::crypto::derive_key("legacy-pair-key", None).unwrap();
        mgr.add_paired_device_id("node-a".into());
        mgr.set_peer_key("node-a", key);

        mgr.remove_paired_device_id("node-a");

        assert!(!mgr.is_paired("node-a"));
        assert!(
            mgr.get_peer_key("node-a").is_none(),
            "解绑必须销毁两两密钥，否则对方仍能完成握手"
        );
    }

    /// 已配对设备的端点清单不得随广播外泄：接收方从包源地址即可得知对端 IP，
    /// gossip 里带的是**第三方** IP（纯拓扑泄露），且 `wrapped_peer_key` 恒为 `None`，
    /// 学到端点也过不了 PFS 握手。
    #[test]
    fn gossip_never_leaks_paired_peer_endpoints() {
        let mgr = PeerManager::new("fp".to_string());
        mgr.add_paired_device_id("phone-1".into());
        mgr.update_peer(beacon("phone-1", ""), "192.168.1.50".to_string());

        let leaked: Vec<(String, String)> = mgr
            .get_gossip_peers("someone-else")
            .into_iter()
            .map(|g| (g.device_id, g.ip))
            .collect();
        assert!(
            leaked.is_empty(),
            "不得广播已配对设备的端点，实际泄露了 {:?}",
            leaked
        );
    }

    /// `MSG_HEARTBEAT` 用公开的 `PAIR_BOOTSTRAP_KEY` 加密，同网段任何主机都能伪造合法帧。
    /// 因此它只能刷新**已存在**的 peer，绝不能创建设备身份。
    #[test]
    fn unauthenticated_heartbeat_cannot_create_peer_identity() {
        let mgr = PeerManager::new("fp".to_string());

        // 场景 A：未知 device_id —— 必须被忽略，且不落入设备表
        let injected =
            mgr.update_existing_peer_only(beacon("attacker-node", ""), "10.0.0.9".to_string());
        assert!(!injected, "未知 device_id 不得被心跳接受");
        assert!(
            !mgr.get_all_peers()
                .iter()
                .any(|p| p.device_id == "attacker-node"),
            "未认证心跳不得在设备表中创建新条目（否则可伪造待配对设备诱导用户）"
        );

        // 场景 B：已存在的 peer（如经 UDP 发现后）—— 探活与换 IP 必须仍然可用
        mgr.update_peer(beacon("phone-1", ""), "10.0.0.20".to_string());
        assert!(mgr.get_all_peers().iter().any(|p| p.device_id == "phone-1"));

        let mut refresh = beacon("phone-1", "");
        refresh.device_name = "Renamed".to_string();
        assert!(
            mgr.update_existing_peer_only(refresh, "10.0.0.21".to_string()),
            "已存在设备必须允许心跳刷新（DHCP 换 IP / 探活）"
        );
        let peer = mgr
            .get_all_peers()
            .into_iter()
            .find(|p| p.device_id == "phone-1")
            .expect("phone-1 仍在表中");
        assert_eq!(peer.ip, "10.0.0.21", "已存在设备的地址应被刷新");
        assert!(peer.is_online);
    }

    /// fingerprint 随广播明文发出，任何同网段主机都能原样复读。
    /// 因此它绝不能成为自动配对的判据。
    #[test]
    fn self_reported_fingerprint_cannot_auto_pair() {
        let local_fp = "a".repeat(64);
        let mgr = PeerManager::new(local_fp.clone());
        mgr.add_paired_device_id("node-a".into());

        mgr.update_peer(beacon("attacker-node", &local_fp), "10.0.0.9".to_string());

        assert!(
            !mgr.is_paired("attacker-node"),
            "自报告指纹不得触发自动配对"
        );
    }
}

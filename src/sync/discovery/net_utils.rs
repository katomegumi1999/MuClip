use socket2::{Domain, Protocol, Socket, Type};
#[cfg(not(windows))]
use std::net::SocketAddr;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

use super::peer_manager::MDNS_MULTICAST_IPV4;

#[cfg(windows)]
pub fn get_local_ipv4_interfaces() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    #[repr(C)]
    struct MibIpAddrRow {
        dw_addr: u32,
        dw_index: u32,
        dw_mask: u32,
        dw_bcast_addr: u32,
        dw_reasm_size: u32,
        unused1: u16,
        w_type: u16,
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetIpAddrTable(p_ip_addr_table: *mut u8, pdw_size: *mut u32, b_order: i32) -> u32;
    }

    let mut size: u32 = 0;
    unsafe {
        let _ = GetIpAddrTable(std::ptr::null_mut(), &mut size, 0);
    }
    if size == 0 {
        return Vec::new();
    }

    let mut buffer = vec![0u8; size as usize];
    let ret = unsafe { GetIpAddrTable(buffer.as_mut_ptr(), &mut size, 0) };
    if ret != 0 {
        return Vec::new();
    }

    let num_entries = unsafe { *(buffer.as_ptr() as *const u32) } as usize;
    let row_size = std::mem::size_of::<MibIpAddrRow>();
    let offset_start = 4;

    let mut result = Vec::new();
    for i in 0..num_entries {
        let entry_offset = offset_start + i * row_size;
        if entry_offset + row_size > buffer.len() {
            break;
        }
        let row = unsafe { &*(buffer.as_ptr().add(entry_offset) as *const MibIpAddrRow) };
        let ip_u32 = u32::from_be(row.dw_addr);
        let mask_u32 = u32::from_be(row.dw_mask);

        let ip = Ipv4Addr::from(ip_u32);
        if ip.is_loopback() || ip.is_unspecified() {
            continue;
        }

        let bcast_u32 = if mask_u32 != 0 {
            (ip_u32 & mask_u32) | (!mask_u32)
        } else {
            (ip_u32 & 0xFFFFFF00) | 0x000000FF
        };
        let bcast_ip = Ipv4Addr::from(bcast_u32);
        result.push((ip, bcast_ip));
    }
    result
}

#[cfg(not(windows))]
pub fn get_local_ipv4_interfaces() -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut result = Vec::new();
    let probe_targets = [
        "192.168.1.1:80",
        "192.168.0.1:80",
        "10.0.0.1:80",
        "172.16.0.1:80",
        "8.8.8.8:80",
        "224.0.0.251:42110",
    ];
    for target in probe_targets {
        if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
            if sock.connect(target).is_ok() {
                if let Ok(SocketAddr::V4(local_v4)) = sock.local_addr() {
                    let ip = *local_v4.ip();
                    if !ip.is_loopback()
                        && !ip.is_unspecified()
                        && !result.iter().any(|(existing, _)| *existing == ip)
                    {
                        let octets = ip.octets();
                        let bcast = Ipv4Addr::new(octets[0], octets[1], octets[2], 255);
                        result.push((ip, bcast));
                    }
                }
            }
        }
    }
    result
}

pub fn parse_peer_endpoint(addr: &str, default_port: u16) -> Option<(String, u16)> {
    let trimmed = addr.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(end_bracket) = rest.find(']') {
            let host = rest[..end_bracket].trim().to_string();
            let after = rest[end_bracket + 1..].trim();
            let port = if let Some(port_str) = after.strip_prefix(':') {
                port_str.parse::<u16>().ok().filter(|&p| p > 0)?
            } else {
                default_port
            };
            if host.is_empty() {
                return None;
            }
            return Some((host, port));
        }
    }
    if let Some(colon_idx) = trimmed.rfind(':') {
        let host_part = trimmed[..colon_idx].trim();
        let port_part = trimmed[colon_idx + 1..].trim();
        if !host_part.is_empty() {
            if let Ok(port) = port_part.parse::<u16>() {
                if port > 0 {
                    return Some((host_part.to_string(), port));
                }
            }
        }
    }
    Some((trimmed.to_string(), default_port))
}

pub(crate) fn create_discovery_rx_socket(port: u16) -> Result<UdpSocket, std::io::Error> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = socket.set_reuse_address(true);
    #[cfg(all(
        unix,
        not(target_os = "android"),
        not(target_os = "solaris"),
        not(target_os = "illumos")
    ))]
    let _ = socket.set_reuse_port(true);
    let _ = socket.set_nonblocking(false);
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    socket.bind(&addr.into())?;
    let udp: UdpSocket = socket.into();
    let _ = udp.set_broadcast(true);
    let _ = udp.join_multicast_v4(&MDNS_MULTICAST_IPV4, &Ipv4Addr::UNSPECIFIED);

    // 加入所有本地活动网卡接口的组播订阅，确保物理网卡与虚拟网卡均可接收组播
    for (local_ip, _) in get_local_ipv4_interfaces() {
        let _ = udp.join_multicast_v4(&MDNS_MULTICAST_IPV4, &local_ip);
    }
    Ok(udp)
}

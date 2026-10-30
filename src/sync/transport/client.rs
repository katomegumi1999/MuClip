use crate::sync::crypto::KEY_SIZE;
use crate::sync::protocol::{
    MSG_CLIPBOARD_SYNC, PairResponsePayload, SyncPayload, UnpairNoticePayload, encode_packet,
    encode_unpair_notice_packet,
};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::pairing::execute_client_pair_handshake;
use super::{TransportError, resolve_socket_addr};

pub struct PooledConnection {
    pub stream: Arc<Mutex<TcpStream>>,
    pub session_key: zeroize::Zeroizing<[u8; KEY_SIZE]>,
}

pub struct SyncClient {
    seq: AtomicU64,
    connection_pool: Arc<Mutex<HashMap<String, PooledConnection>>>,
}

/// PFS 会话握手（不可取消版本）。
///
/// 剪贴板同步这类「必须立刻完成或立刻失败」的场景用它：调用方已经把读写超时
/// 压到几秒，没有用户可点的取消按钮。大文件传输请用
/// [`execute_pfs_client_handshake_cancellable`]。
pub fn execute_pfs_client_handshake(
    stream: &mut TcpStream,
    local_device_id: &str,
    target_device_id: Option<&str>,
    long_term_key: &[u8; KEY_SIZE],
    seq: u64,
) -> Result<zeroize::Zeroizing<[u8; KEY_SIZE]>, TransportError> {
    execute_pfs_client_handshake_inner(
        stream,
        local_device_id,
        target_device_id,
        long_term_key,
        seq,
        None,
    )
}

/// PFS 会话握手（可取消版本）。
///
/// **调用前提**：socket 的读写超时已压到
/// [`crate::sync::cancel::CANCEL_POLL_INTERVAL`]，否则单次 `read` 会阻塞到长超时，
/// 令牌形同虚设。
///
/// 修复的是这样一类事故：对端完成 TCP 连接后一言不发（进程卡死 / 恶意），
/// 用户点「取消」却要等握手超时才生效——之前每个往返 30s，最多可达一分多钟。
pub(crate) fn execute_pfs_client_handshake_cancellable(
    stream: &mut TcpStream,
    local_device_id: &str,
    target_device_id: Option<&str>,
    long_term_key: &[u8; KEY_SIZE],
    seq: u64,
    cancel: &crate::sync::cancel::CancelToken,
) -> Result<zeroize::Zeroizing<[u8; KEY_SIZE]>, TransportError> {
    execute_pfs_client_handshake_inner(
        stream,
        local_device_id,
        target_device_id,
        long_term_key,
        seq,
        Some(cancel),
    )
}

fn execute_pfs_client_handshake_inner(
    stream: &mut TcpStream,
    local_device_id: &str,
    target_device_id: Option<&str>,
    long_term_key: &[u8; KEY_SIZE],
    seq: u64,
    cancel: Option<&crate::sync::cancel::CancelToken>,
) -> Result<zeroize::Zeroizing<[u8; KEY_SIZE]>, TransportError> {
    let key_ex = crate::sync::crypto::KeyExchangeSession::new();
    let client_pk = key_ex.public_key;
    let mut challenge = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge);

    let target_id_str = target_device_id.unwrap_or("");
    let auth_tag = crate::sync::crypto::compute_session_auth_tag(
        long_term_key,
        local_device_id,
        target_id_str,
        &client_pk,
        None,
        "initiator",
        &challenge,
    );

    let init_payload = crate::sync::protocol::SessionInitPayload {
        client_device_id: local_device_id.to_string(),
        target_device_id: target_device_id.map(|s| s.to_string()),
        ephemeral_pk: client_pk,
        challenge,
        auth_tag,
    };

    let init_pkt = crate::sync::protocol::encode_session_init_packet(seq, &init_payload)?;
    match cancel {
        Some(token) => {
            crate::sync::cancel::write_all_cancellable(stream, &init_pkt, token)
                .map_err(super::abort_to_transport)?;
        }
        None => stream.write_all(&init_pkt)?,
    }
    stream.flush()?;

    let (resp_header, mut resp_raw) = match cancel {
        Some(token) => {
            super::read_framed_packet_cancellable(stream, super::MAX_PAYLOAD_SIZE, token)?
        }
        None => super::read_framed_packet(stream, super::MAX_PAYLOAD_SIZE)?,
    };
    if resp_header.msg_type != crate::sync::protocol::MSG_SESSION_RESP {
        return Err(TransportError::SyncRejected);
    }

    let (_h, resp_payload) =
        crate::sync::protocol::decode_session_resp_packet_in_place(&mut resp_raw)?;
    if !resp_payload.accepted {
        return Err(TransportError::SyncRejected);
    }

    if let Some(target) = target_device_id {
        if !target.is_empty() && resp_payload.responder_device_id != target {
            return Err(TransportError::SyncRejected);
        }
    }

    let expected_tag = crate::sync::crypto::compute_session_auth_tag(
        long_term_key,
        local_device_id,
        &resp_payload.responder_device_id,
        &resp_payload.ephemeral_pk,
        Some(&client_pk),
        "responder",
        &challenge,
    );
    if !crate::sync::crypto::constant_time_eq_str(&expected_tag, &resp_payload.auth_tag) {
        return Err(TransportError::SyncRejected);
    }

    let shared = key_ex.compute_shared_secret(&resp_payload.ephemeral_pk);
    let session_key =
        crate::sync::crypto::derive_pfs_session_key(&*shared, long_term_key, &challenge);
    Ok(session_key)
}

impl SyncClient {
    pub fn new() -> Self {
        Self {
            seq: AtomicU64::new(1),
            connection_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn close_connection(&self, peer_addr: &str) {
        if let Ok(mut pool) = self.connection_pool.lock() {
            pool.remove(peer_addr);
        }
    }

    pub fn clear_connection_pool(&self) {
        if let Ok(mut pool) = self.connection_pool.lock() {
            pool.clear();
        }
    }

    pub fn send_payload(
        &self,
        peer_addr: &str,
        target_device_id: Option<&str>,
        key: &[u8; KEY_SIZE],
        payload: &SyncPayload,
    ) -> Result<(), TransportError> {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);

        // 1. Attempt reuse of existing persistent connection from pool
        let pooled_opt = {
            if let Ok(pool) = self.connection_pool.lock() {
                pool.get(peer_addr)
                    .map(|c| (Arc::clone(&c.stream), *c.session_key))
            } else {
                None
            }
        };

        if let Some((stream_lock, conn_session_key)) = pooled_opt {
            let packet = encode_packet(&conn_session_key, MSG_CLIPBOARD_SYNC, seq, payload)?;
            if let Ok(mut stream) = stream_lock.try_lock() {
                let write_res = stream.write_all(&packet).and_then(|_| stream.flush());
                if write_res.is_ok() {
                    let mut ack = [0u8; 16];
                    if let Ok(n) = stream.read(&mut ack) {
                        if n >= 14 && &ack[..14] == b"ERR_NOT_PAIRED" {
                            self.close_connection(peer_addr);
                            return Err(TransportError::NotPairedByPeer);
                        }
                        if n >= 2 && &ack[..2] == b"OK" {
                            return Ok(()); // Reused persistent connection successfully
                        }
                    }
                }
            }
            // Stream write/read failed -> drop stale connection from pool
            self.close_connection(peer_addr);
        }

        // 2. Establish a new persistent connection
        let socket_addr = resolve_socket_addr(peer_addr)?;
        let mut stream = match TcpStream::connect_timeout(&socket_addr, Duration::from_millis(2500))
        {
            Ok(s) => s,
            Err(_) => TcpStream::connect_timeout(&socket_addr, Duration::from_millis(2500))?,
        };
        let _ = stream.set_nodelay(true);
        stream.set_write_timeout(Some(Duration::from_millis(3500)))?;
        stream.set_read_timeout(Some(Duration::from_millis(3500)))?;

        // 3. Negotiate PFS Session Key via Ephemeral ECDHE Handshake (Mandatory)
        let active_key = execute_pfs_client_handshake(
            &mut stream,
            &payload.source_device_id,
            target_device_id,
            key,
            seq,
        )?;
        let mut active_stream = stream;

        let packet = encode_packet(&*active_key, MSG_CLIPBOARD_SYNC, seq, payload)?;
        active_stream.write_all(&packet)?;
        active_stream.flush()?;

        let mut ack = [0u8; 16];
        let n = active_stream.read(&mut ack).unwrap_or(0);
        if n >= 14 && &ack[..14] == b"ERR_NOT_PAIRED" {
            return Err(TransportError::NotPairedByPeer);
        }
        if n < 2 || &ack[..2] != b"OK" {
            return Err(TransportError::SyncRejected);
        }

        // Cache persistent connection with its negotiated session_key for future clipboard syncs
        if let Ok(mut pool) = self.connection_pool.lock() {
            pool.insert(
                peer_addr.to_string(),
                PooledConnection {
                    stream: Arc::new(Mutex::new(active_stream)),
                    session_key: active_key,
                },
            );
        }

        Ok(())
    }

    pub fn send_unpair_notice(
        &self,
        peer_addr: &str,
        local_device_id: &str,
        peer_device_id: Option<&str>,
        peer_key: &[u8; KEY_SIZE],
    ) -> Result<(), TransportError> {
        self.close_connection(peer_addr);
        let socket_addr = resolve_socket_addr(peer_addr)?;
        let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_millis(1500))?;
        let _ = stream.set_nodelay(true);
        stream.set_write_timeout(Some(Duration::from_millis(2000)))?;
        stream.set_read_timeout(Some(Duration::from_millis(2000)))?;

        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let pfs_key = execute_pfs_client_handshake(
            &mut stream,
            local_device_id,
            peer_device_id,
            peer_key,
            seq,
        )?;

        let payload = UnpairNoticePayload {
            from_device_id: local_device_id.to_string(),
        };
        let packet = encode_unpair_notice_packet(&*pfs_key, seq, &payload)?;
        stream.write_all(&packet)?;
        let _ = stream.flush();

        // The server only removes the pairing after verifying that the notice comes from the
        // identity authenticated by the PFS handshake. Surface its verdict instead of assuming
        // success, otherwise a rejected unpair is reported to the user as completed.
        let mut ack = [0u8; 16];
        let n = stream.read(&mut ack).unwrap_or(0);
        let reply = &ack[..n];
        if reply.starts_with(b"OK") {
            return Ok(());
        }
        if reply.starts_with(b"ERR_FORGERY") {
            return Err(TransportError::NotPairedByPeer);
        }
        Err(TransportError::SyncRejected)
    }

    pub fn request_pair(
        &self,
        peer_addr: &str,
        local_device_id: &str,
        local_device_name: &str,
        pin: &str,
        timeout_secs: u64,
    ) -> Result<PairResponsePayload, TransportError> {
        execute_client_pair_handshake(
            &self.seq,
            peer_addr,
            local_device_id,
            local_device_name,
            pin,
            timeout_secs,
            None,
            None,
        )
    }

    pub fn request_pair_with_context(
        &self,
        peer_addr: &str,
        local_device_id: &str,
        local_device_name: &str,
        pin: &str,
        timeout_secs: u64,
        current_key: Option<[u8; KEY_SIZE]>,
        peer_mgr: Option<&Arc<crate::sync::discovery::PeerManager>>,
    ) -> Result<PairResponsePayload, TransportError> {
        execute_client_pair_handshake(
            &self.seq,
            peer_addr,
            local_device_id,
            local_device_name,
            pin,
            timeout_secs,
            current_key,
            peer_mgr,
        )
    }
}

impl Default for SyncClient {
    fn default() -> Self {
        Self::new()
    }
}

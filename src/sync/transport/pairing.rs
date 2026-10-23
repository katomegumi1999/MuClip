use crate::sync::crypto::KEY_SIZE;
use crate::sync::discovery::PeerManager;
use crate::sync::protocol::{
    MSG_PAIR_ACK, MSG_PAIR_REQUEST, PROTOCOL_VERSION, PairRequestPayload, PairResponsePayload,
    ProtocolError, decode_pair_request_packet_in_place, decode_pair_response_packet_in_place,
    encode_pair_request_packet, encode_pair_response_packet,
};
use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use super::{
    MAX_PAYLOAD_SIZE, MAX_PIN_ATTEMPTS, PairAttemptCommand, PairRequestCallback,
    PairSuccessCallback, PendingPairRequest, TransportError, read_framed_packet,
    resolve_socket_addr,
};

/// Server-side handler for `MSG_PAIR_REQUEST` (strictly SPAKE2 mutual confirmation).
/// Each PIN attempt consumes the current `(challenge, initiator_spake2_msg)` state once;
/// if a PIN attempt fails and retries remain, the client must transmit a fresh `MSG_PAIR_REQUEST`
/// with a newly generated `challenge` and fresh SPAKE2 ephemeral public message before the next attempt.
pub(crate) fn handle_incoming_pair_request(
    stream: &mut TcpStream,
    raw_packet: &mut [u8],
    client_ip: &str,
    local_id: &str,
    local_name: &str,
    _key_lock: &Arc<RwLock<Option<[u8; KEY_SIZE]>>>,
    peer_mgr: &Arc<PeerManager>,
    pending_pairs: &Arc<Mutex<HashMap<String, PendingPairRequest>>>,
    pair_req_cb_lock: &Arc<RwLock<Option<PairRequestCallback>>>,
    pair_success_cb_lock: &Arc<RwLock<Option<PairSuccessCallback>>>,
) {
    let Ok((_h, req_payload)) = decode_pair_request_packet_in_place(raw_packet) else {
        return;
    };
    let Some(initial_spake2_msg) = req_payload.public_key else {
        return;
    };

    let (tx, rx) = std::sync::mpsc::channel::<PairAttemptCommand>();
    let req_id = req_payload.request_id.clone();
    let from_id = req_payload.from_device_id.clone();
    let from_name = req_payload.from_device_name.clone();
    let client_ip_owned = client_ip.to_string();

    // Single-use handshake state for the current attempt: (challenge_nonce, initiator_spake2_msg).
    // Consumed via `.take()` on each attempt so it can never be reused across retries.
    let mut current_handshake: Option<(String, [u8; 32])> =
        Some((req_payload.challenge, initial_spake2_msg));

    if let Ok(mut map) = pending_pairs.lock() {
        map.insert(
            req_id.clone(),
            PendingPairRequest {
                created_at: Instant::now(),
                tx,
            },
        );
    }

    // 克隆 Arc 后立刻释放读锁再回调：用户在回调里若重设配对回调（需要写锁），
    // 持锁调用会当场自死锁。见 file_transfer/mod.rs::notify_progress 的详细说明。
    let cb = pair_req_cb_lock
        .read()
        .ok()
        .and_then(|guard| guard.as_ref().map(Arc::clone));
    if let Some(cb) = cb {
        cb(
            req_id.clone(),
            from_id.clone(),
            from_name.clone(),
            client_ip_owned.clone(),
        );
    }

    let start_instant = Instant::now();
    let mut failed_attempts: u8 = 0;

    loop {
        let remaining = Duration::from_secs(60).saturating_sub(start_instant.elapsed());
        if remaining.is_zero() {
            send_timeout_response(stream, &req_id, local_id, local_name);
            break;
        }

        let cmd = match rx.recv_timeout(remaining) {
            Ok(c) => c,
            Err(_) => {
                send_timeout_response(stream, &req_id, local_id, local_name);
                break;
            }
        };

        if !cmd.accept {
            let resp = PairResponsePayload {
                request_id: req_id.clone(),
                accepted: false,
                responder_device_id: local_id.to_string(),
                responder_device_name: local_name.to_string(),
                error_code: 1,
                error_message: Some("对方拒绝了配对请求".to_string()),
                public_key: None,
                auth_tag: None,
                long_term_key_hex: None,
            };
            if let Ok(resp_packet) = encode_pair_response_packet(1, &resp) {
                let _ = stream.write_all(&resp_packet);
                let _ = stream.flush();
            }
            let _ = cmd.reply_tx.send(0);
            break;
        }

        let pin_auth_key = match crate::sync::crypto::derive_pin_auth_key(&cmd.pin) {
            Ok(k) => k,
            Err(_) => {
                let _ = cmd.reply_tx.send(-1);
                continue;
            }
        };

        // Consume the single-use (challenge, initiator_spake2_msg) for this attempt
        let Some((challenge, initiator_spake2_msg)) = current_handshake.take() else {
            let _ = cmd.reply_tx.send(1);
            break;
        };

        // Standard SPAKE2 (Ed25519Group) Responder step:
        // Computes Y = y*B + w*N and shared key K = y*(X - w*M)
        let (resp_spake2_msg, shared_secret) = match crate::sync::crypto::spake2_responder_exchange(
            &cmd.pin,
            &challenge,
            &initiator_spake2_msg,
        ) {
            Ok(pair) => pair,
            Err(_) => {
                let _ = cmd.reply_tx.send(1);
                break;
            }
        };

        let ltk_res = crate::sync::crypto::derive_long_term_key(
            &shared_secret,
            &pin_auth_key,
            &challenge,
            &initiator_spake2_msg,
            &resp_spake2_msg,
            PROTOCOL_VERSION,
        );
        let spake2_key = ltk_res.as_ref().copied().unwrap_or([0u8; 32]);
        let resp_tag = crate::sync::crypto::compute_ecdh_auth_tag(
            &spake2_key,
            &initiator_spake2_msg,
            &resp_spake2_msg,
            "responder",
            &challenge,
            PROTOCOL_VERSION,
        );

        // Message 2: send responder SPAKE2 message Y + responder key confirmation tag.
        // SECURITY: 长期配对密钥绝不上线——它只通过进程内回调（pair_success_callback）
        // 交给本地 UI/存储层。双方已各自本地派生出同一把 key，
        // msg3 的 initiator 确认 tag 也已双向完成验证。
        let msg2 = PairResponsePayload {
            request_id: req_id.clone(),
            accepted: true,
            responder_device_id: local_id.to_string(),
            responder_device_name: local_name.to_string(),
            error_code: 0,
            error_message: None,
            public_key: Some(resp_spake2_msg),
            auth_tag: Some(resp_tag),
            long_term_key_hex: None,
        };
        let Ok(msg2_pkt) = encode_pair_response_packet(1, &msg2) else {
            let _ = cmd.reply_tx.send(1);
            break;
        };
        if stream.write_all(&msg2_pkt).is_err() || stream.flush().is_err() {
            let _ = cmd.reply_tx.send(1);
            break;
        }

        // Message 3: read initiator mutual key confirmation
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let Ok((confirm_hdr, mut confirm_raw)) = read_framed_packet(stream, MAX_PAYLOAD_SIZE)
        else {
            let _ = cmd.reply_tx.send(1);
            break;
        };
        if confirm_hdr.msg_type != MSG_PAIR_ACK {
            let _ = cmd.reply_tx.send(1);
            break;
        }
        let Ok((_ch, confirm_payload)) = decode_pair_response_packet_in_place(&mut confirm_raw)
        else {
            let _ = cmd.reply_tx.send(1);
            break;
        };

        if !confirm_payload.accepted {
            failed_attempts += 1;
            if failed_attempts >= MAX_PIN_ATTEMPTS || confirm_payload.error_code == 3 {
                let _ = cmd.reply_tx.send(3);
                break;
            }

            // Before allowing the next PIN attempt, require a brand-new MSG_PAIR_REQUEST
            // with a fresh challenge and fresh SPAKE2 ephemeral public message from the client.
            let Ok((next_hdr, mut next_raw)) = read_framed_packet(stream, MAX_PAYLOAD_SIZE) else {
                let _ = cmd.reply_tx.send(1);
                break;
            };
            if next_hdr.msg_type != MSG_PAIR_REQUEST {
                let _ = cmd.reply_tx.send(1);
                break;
            };
            let Ok((_nh, next_req)) = decode_pair_request_packet_in_place(&mut next_raw) else {
                let _ = cmd.reply_tx.send(1);
                break;
            };
            let Some(next_spake2_msg) = next_req.public_key else {
                let _ = cmd.reply_tx.send(1);
                break;
            };
            if next_req.request_id != req_id
                || next_req.from_device_id != from_id
                || next_req.challenge == challenge
                || next_spake2_msg == initiator_spake2_msg
            {
                let _ = cmd.reply_tx.send(1);
                break;
            }

            current_handshake = Some((next_req.challenge, next_spake2_msg));
            let _ = cmd.reply_tx.send(2);
            continue;
        }

        let expected_init_tag = crate::sync::crypto::compute_ecdh_auth_tag(
            &spake2_key,
            &initiator_spake2_msg,
            &resp_spake2_msg,
            "initiator",
            &challenge,
            PROTOCOL_VERSION,
        );
        let tag_matches = confirm_payload
            .auth_tag
            .as_deref()
            .map(|t| crate::sync::crypto::constant_time_eq_str(t, &expected_init_tag))
            .unwrap_or(false);
        if ltk_res.is_err() || !tag_matches {
            let _ = cmd.reply_tx.send(3);
            break;
        }

        peer_mgr.set_peer_key(&from_id, spake2_key);

        peer_mgr.add_paired_device_id(from_id.clone());
        peer_mgr.upsert_incoming_peer(
            &from_id,
            &from_name,
            &client_ip_owned,
            crate::sync::DEFAULT_SYNC_PORT,
            true,
        );

        let peer_key_hex = crate::sync::crypto::bytes_to_hex(&spake2_key);
        let cb = pair_success_cb_lock
            .read()
            .ok()
            .and_then(|guard| guard.as_ref().map(Arc::clone));
        if let Some(cb) = cb {
            cb(
                from_id.clone(),
                from_name.clone(),
                client_ip_owned.clone(),
                peer_key_hex,
            );
        }

        let _ = cmd.reply_tx.send(0);
        break;
    }

    if let Ok(mut map) = pending_pairs.lock() {
        map.remove(&req_id);
    }
}

fn send_timeout_response(stream: &mut TcpStream, req_id: &str, local_id: &str, local_name: &str) {
    let resp = PairResponsePayload {
        request_id: req_id.to_string(),
        accepted: false,
        responder_device_id: local_id.to_string(),
        responder_device_name: local_name.to_string(),
        error_code: 3,
        error_message: Some("配对超时，对方未在60秒内确认".to_string()),
        public_key: None,
        auth_tag: None,
        long_term_key_hex: None,
    };
    if let Ok(resp_packet) = encode_pair_response_packet(1, &resp) {
        let _ = stream.write_all(&resp_packet);
        let _ = stream.flush();
    }
}

/// Client-side SPAKE2 3-step mutual key confirmation handshake over TCP.
/// Generates a brand-new `challenge` nonce and a fresh single-use `Spake2InitiatorSession`
/// for each attempt so ephemeral SPAKE2 state is never reused across PIN retries.
pub(crate) fn execute_client_pair_handshake(
    seq_counter: &AtomicU64,
    peer_addr: &str,
    local_device_id: &str,
    local_device_name: &str,
    pin: &str,
    timeout_secs: u64,
    _current_key: Option<[u8; KEY_SIZE]>,
    peer_mgr: Option<&Arc<PeerManager>>,
) -> Result<PairResponsePayload, TransportError> {
    let socket_addr = resolve_socket_addr(peer_addr)?;

    let mut stream = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(3))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    stream.set_read_timeout(Some(Duration::from_secs(timeout_secs)))?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let request_id = format!("req-{}", now_ms);
    let pin_auth_key = crate::sync::crypto::derive_pin_auth_key(pin.trim())?;

    let mut failed_attempts: u8 = 0;
    loop {
        // Generate a fresh 128-bit challenge nonce and a fresh single-use SPAKE2 session
        // (new ephemeral scalar x and new public message X = x*B + w*M) for this attempt.
        let challenge = crate::sync::crypto::generate_challenge_nonce();
        let spake2_session =
            crate::sync::crypto::Spake2InitiatorSession::new(pin.trim(), &challenge);
        let initiator_public_msg = spake2_session.public_message;

        let payload = PairRequestPayload {
            request_id: request_id.clone(),
            from_device_id: local_device_id.to_string(),
            from_device_name: local_device_name.to_string(),
            challenge: challenge.clone(),
            pin_hash: String::new(),
            public_key: Some(initiator_public_msg),
            auth_tag: None,
        };

        let seq = seq_counter.fetch_add(1, Ordering::Relaxed);
        let packet = encode_pair_request_packet(seq, &payload)?;
        stream.write_all(&packet)?;
        stream.flush()?;

        let (header, mut raw_packet) = read_framed_packet(&mut stream, MAX_PAYLOAD_SIZE)?;
        if header.msg_type != MSG_PAIR_ACK {
            return Err(TransportError::Protocol(ProtocolError::BufferTooShort(
                0, 1,
            )));
        }

        let (_h, mut resp_payload) = decode_pair_response_packet_in_place(&mut raw_packet)?;

        if !resp_payload.accepted {
            return Ok(resp_payload);
        }

        if let (Some(resp_spake2_msg), Some(resp_tag)) =
            (resp_payload.public_key, &resp_payload.auth_tag)
        {
            // Consume the single-use `spake2_session` by value using responder's Y = y*B + w*N
            if let Ok(shared_secret) = spake2_session.finish(&resp_spake2_msg) {
                if let Ok(spake2_key) = crate::sync::crypto::derive_long_term_key(
                    &shared_secret,
                    &pin_auth_key,
                    &challenge,
                    &initiator_public_msg,
                    &resp_spake2_msg,
                    PROTOCOL_VERSION,
                ) {
                    let expected_tag = crate::sync::crypto::compute_ecdh_auth_tag(
                        &spake2_key,
                        &initiator_public_msg,
                        &resp_spake2_msg,
                        "responder",
                        &challenge,
                        PROTOCOL_VERSION,
                    );
                    if crate::sync::crypto::constant_time_eq_str(&expected_tag, resp_tag) {
                        let responder_id = resp_payload.responder_device_id.as_str();
                        if let Some(pm) = peer_mgr {
                            if !responder_id.trim().is_empty() {
                                pm.set_peer_key(responder_id, spake2_key);
                            }
                        }

                        // Message 3: send initiator mutual key confirmation tag
                        let init_tag = crate::sync::crypto::compute_ecdh_auth_tag(
                            &spake2_key,
                            &initiator_public_msg,
                            &resp_spake2_msg,
                            "initiator",
                            &challenge,
                            PROTOCOL_VERSION,
                        );
                        let confirm_payload = PairResponsePayload {
                            request_id: request_id.clone(),
                            accepted: true,
                            responder_device_id: local_device_id.to_string(),
                            responder_device_name: local_device_name.to_string(),
                            error_code: 0,
                            error_message: None,
                            public_key: None,
                            auth_tag: Some(init_tag),
                            long_term_key_hex: None,
                        };
                        let confirm_seq = seq_counter.fetch_add(1, Ordering::Relaxed);
                        let confirm_pkt =
                            encode_pair_response_packet(confirm_seq, &confirm_payload)?;
                        stream.write_all(&confirm_pkt)?;
                        stream.flush()?;

                        // SECURITY: 无论对端是否在网络上传输了长期密钥（旧版服务端行为），
                        // 这里一律丢弃网络值，改用本地 SPAKE2 派生结果。
                        // 网络下发的密钥来自公开的 PAIR_BOOTSTRAP_KEY 加密帧，不可信。
                        let pairwise_key_hex = crate::sync::crypto::bytes_to_hex(&spake2_key);
                        resp_payload.long_term_key_hex = Some(pairwise_key_hex);
                        return Ok(resp_payload);
                    }
                }
            }

            // Wrong PIN entered on responder (or active MITM key mismatch):
            // `spake2_session` and `challenge` have already been consumed and discarded.
            failed_attempts += 1;
            let is_final = failed_attempts >= MAX_PIN_ATTEMPTS;
            let err_code = if is_final { 3 } else { 2 };
            let reject_confirm = PairResponsePayload {
                request_id: request_id.clone(),
                accepted: false,
                responder_device_id: local_device_id.to_string(),
                responder_device_name: local_device_name.to_string(),
                error_code: err_code,
                error_message: None,
                public_key: None,
                auth_tag: None,
                long_term_key_hex: None,
            };
            let confirm_seq = seq_counter.fetch_add(1, Ordering::Relaxed);
            if let Ok(confirm_pkt) = encode_pair_response_packet(confirm_seq, &reject_confirm) {
                let _ = stream.write_all(&confirm_pkt);
                let _ = stream.flush();
            }

            if is_final {
                return Ok(PairResponsePayload {
                    request_id,
                    accepted: false,
                    responder_device_id: resp_payload.responder_device_id,
                    responder_device_name: resp_payload.responder_device_name,
                    error_code: 2,
                    error_message: Some(
                        "对方连续 3 次输错配对码，本次配对已作废，请重新生成配对码".to_string(),
                    ),
                    public_key: None,
                    auth_tag: None,
                    long_term_key_hex: None,
                });
            }
            // Loop continues: immediately generates a brand-new challenge + Spake2InitiatorSession
            // and sends a fresh MSG_PAIR_REQUEST for the next attempt.
            continue;
        }

        return Ok(resp_payload);
    }
}

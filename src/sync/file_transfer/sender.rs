use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use socket2::{Domain, Socket, Type};

use crate::pool::PooledBuffer;
use crate::sync::crypto::{
    CHUNK_AAD_SIZE, KEY_SIZE, TAG_SIZE, build_chunk_aad, derive_bulk_key, derive_chunk_nonce,
    encrypt_in_place_with_aad,
};
use crate::sync::protocol::{
    FileFinishPayload, FileOfferPayload, HEADER_SIZE, PAIR_BOOTSTRAP_KEY, PROTOCOL_VERSION,
    SyncHeader, decode_file_response_packet, encode_file_finish_packet, encode_file_offer_packet,
};

use super::{BULK_CHUNK_SIZE, FileTransferManager};

impl FileTransferManager {
    /// Sends a file to a remote peer over high-speed encrypted TCP stream.
    pub fn send_file(
        self: &Arc<Self>,
        transfer_id: &str,
        peer_addr: &str,
        file_path: &str,
        local_id: &str,
        local_name: &str,
        session_key: &[u8; KEY_SIZE],
    ) -> Result<String, String> {
        self.send_file_with_name(
            transfer_id,
            peer_addr,
            file_path,
            None,
            local_id,
            local_name,
            None,
            session_key,
        )
    }

    /// Sends a file with an explicit display name.
    #[allow(clippy::too_many_arguments)]
    pub fn send_file_with_name(
        self: &Arc<Self>,
        transfer_id: &str,
        peer_addr: &str,
        file_path: &str,
        custom_file_name: Option<&str>,
        local_id: &str,
        local_name: &str,
        target_device_id: Option<&str>,
        session_key: &[u8; KEY_SIZE],
    ) -> Result<String, String> {
        let tid = if transfer_id.trim().is_empty() {
            format!(
                "{}_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                rand::random::<u32>()
            )
        } else {
            transfer_id.trim().to_string()
        };

        let display_path = if file_path.starts_with("fd:") {
            custom_file_name
                .filter(|s| !s.trim().is_empty())
                .unwrap_or(file_path)
        } else {
            file_path
        };

        match self.send_file_internal(
            &tid,
            peer_addr,
            file_path,
            custom_file_name,
            local_id,
            local_name,
            target_device_id,
            session_key,
        ) {
            Ok(ret_id) => {
                self.unregister_cancel_flag(&tid);
                crate::log_info!("文件发送完成 {} -> {}", display_path, peer_addr);
                self.notify_completed(&tid, display_path, true, true, "");
                Ok(ret_id)
            }
            Err(e) => {
                // 兜底翻译：取消会 shutdown socket，各阻塞点报上来的都是网络错误。
                // 必须在 unregister 之前查，否则标志位已被清掉。
                let cancelled = self.is_transfer_cancelled(&tid);
                let e = if cancelled {
                    "Transfer canceled by sender".to_string()
                } else {
                    e
                };
                self.unregister_cancel_flag(&tid);
                // 取消是用户主动行为，不是故障，不该占用 WARN 让人误以为出事了。
                if cancelled {
                    crate::log_info!("文件发送已取消 {} -> {}", display_path, peer_addr);
                } else {
                    crate::log_warn!("文件发送失败 {} -> {}: {}", display_path, peer_addr, e);
                }
                self.notify_completed(&tid, display_path, true, false, &e);
                Err(e)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn send_file_internal(
        self: &Arc<Self>,
        transfer_id: &str,
        peer_addr: &str,
        file_path: &str,
        custom_file_name: Option<&str>,
        local_id: &str,
        local_name: &str,
        target_device_id: Option<&str>,
        session_key: &[u8; KEY_SIZE],
    ) -> Result<String, String> {
        #[cfg(unix)]
        let mut file = if let Some(fd_str) = file_path.strip_prefix("fd:") {
            use std::os::unix::io::FromRawFd;
            let raw_fd: i32 = fd_str
                .trim()
                .parse()
                .map_err(|_| format!("Invalid raw file descriptor: {}", file_path))?;
            if raw_fd < 0 {
                return Err(format!("Negative file descriptor: {}", raw_fd));
            }
            unsafe { File::from_raw_fd(raw_fd) }
        } else {
            let path = Path::new(file_path);
            if !path.exists() || !path.is_file() {
                return Err(format!("File does not exist: {}", file_path));
            }
            File::open(path).map_err(|e| format!("Cannot open file: {}", e))?
        };

        #[cfg(not(unix))]
        let mut file = {
            let path = Path::new(file_path);
            if !path.exists() || !path.is_file() {
                return Err(format!("File does not exist: {}", file_path));
            }
            File::open(path).map_err(|e| format!("Cannot open file: {}", e))?
        };

        let total_size = match file.metadata() {
            Ok(m) if m.len() > 0 => m.len(),
            Ok(m) => {
                if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
                    let _ = file.seek(SeekFrom::Start(0));
                    end_pos
                } else {
                    m.len()
                }
            }
            Err(e) => {
                if let Ok(end_pos) = file.seek(SeekFrom::End(0)) {
                    let _ = file.seek(SeekFrom::Start(0));
                    end_pos
                } else {
                    return Err(format!("Cannot read metadata: {}", e));
                }
            }
        };

        let file_name = if let Some(custom) = custom_file_name.filter(|s| !s.trim().is_empty()) {
            custom.to_string()
        } else {
            Path::new(file_path)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|n| !n.starts_with("fd:"))
                .unwrap_or("unnamed_file")
                .to_string()
        };

        let cancel_flag = self.register_cancel_flag(transfer_id);

        let addr = crate::sync::transport::resolve_socket_addr(peer_addr)
            .map_err(|e| format!("Failed to resolve {}: {}", peer_addr, e))?;

        let domain = if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::STREAM, Some(socket2::Protocol::TCP))
            .map_err(|e| format!("Failed to create bulk socket: {}", e))?;

        // ⚠️ 禁止静态设置 SO_RCVBUF / SO_SNDBUF —— 详细病历见
        // `transport/server.rs` 的 `start()` 里那段注释（历史上因此掉到 20~30 MB/s）。
        // 微软明确指出静态分配 TCP 缓冲是「神话」，在非零 RTT 下反而劣化吞吐。
        let _ = socket.set_nodelay(true);

        socket
            .connect_timeout(&addr.into(), Duration::from_secs(10))
            .map_err(|e| format!("Failed to connect to {}: {}", peer_addr, e))?;

        let mut stream: TcpStream = socket.into();

        // ⚠️ 连接阶段（`connect_timeout`）本身不可取消，上限 10s 是刻意接受的成本：
        // 非阻塞 connect + 轮询能省掉这 10s，但复杂度与平台差异（WSAEINPROGRESS /
        // 错误码映射）不成比例，而真正的病灶是握手——对端 accept 后一言不发时，
        // 旧实现要等满 30s/轮次，最长可达一分多钟。
        //
        // 因此从握手开始就把超时压到轮询间隔，让每一步 IO 都能在 200ms 内响应取消。
        // 「对端死了」的判定由 `TRANSFER_IDLE_TIMEOUT`（30s 无进展）负责，
        // 不会被这次缩短影响。
        let _ = stream.set_read_timeout(Some(super::CANCEL_POLL_INTERVAL));
        let _ = stream.set_write_timeout(Some(super::CANCEL_POLL_INTERVAL));

        // Negotiate PFS session key on dedicated bulk stream (Mandatory)
        let active_session_key = crate::sync::transport::execute_pfs_client_handshake_cancellable(
            &mut stream,
            local_id,
            target_device_id,
            session_key,
            1,
            &cancel_flag,
        )
        .map_err(|e| match e {
            crate::sync::transport::TransportError::Cancelled => {
                "Transfer canceled by sender".to_string()
            }
            other => format!("PFS session handshake failed for {}: {}", peer_addr, other),
        })?;

        // 握手完成，后续所有阻塞 IO 继续走同一套短超时 + 可取消约定。

        // Generate a 16-byte random file nonce (stream salt) for deterministic chunk nonces
        let mut stream_salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut stream_salt);

        let total_chunks = if total_size == 0 {
            0
        } else {
            (total_size + BULK_CHUNK_SIZE as u64 - 1) / BULK_CHUNK_SIZE as u64
        };

        // 1. Send File Offer on dedicated Bulk TCP channel
        let offer = FileOfferPayload {
            transfer_id: transfer_id.to_string(),
            from_device_id: local_id.to_string(),
            from_device_name: local_name.to_string(),
            file_name: file_name.clone(),
            file_size: total_size,
            sha256: String::new(),
            mime_type: "application/octet-stream".to_string(),
            stream_nonce: None,
            stream_salt: Some(stream_salt),
            offset: 0,
            chunk_size: BULK_CHUNK_SIZE as u32,
            total_chunks,
        };

        let offer_packet = encode_file_offer_packet(&active_session_key, 1, &offer)
            .map_err(|e| format!("Failed to encode offer packet: {}", e))?;
        match super::write_all_cancellable(&mut stream, &offer_packet, &cancel_flag) {
            Ok(()) => {}
            Err(super::IoAbort::Cancelled) => {
                return Err("Transfer canceled by sender".to_string());
            }
            Err(super::IoAbort::Io(e)) => {
                return Err(format!("Failed to send offer packet: {}", e));
            }
        }
        stream.flush().map_err(|e| format!("Flush error: {}", e))?;

        // 2. Wait for Peer Response
        let mut header_buf = [0u8; HEADER_SIZE];
        match super::read_exact_cancellable(&mut stream, &mut header_buf, &cancel_flag) {
            Ok(()) => {}
            Err(super::IoAbort::Cancelled) => {
                return Err("Transfer canceled by sender".to_string());
            }
            Err(super::IoAbort::Io(e)) => {
                let msg = if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    "目标设备断开了握手连接 (未收到握手响应)。可能原因：\n1. 双方配对 PIN 码不一致（请确认两端 PIN 码相同并重新配对）\n2. 目标设备运行的是旧版应用，尚未开启文件互传支持\n3. 目标设备未配置加密密钥或被防火墙阻断".to_string()
                } else {
                    format!("Failed to read response header: {}", e)
                };
                return Err(msg);
            }
        }
        let header = SyncHeader::parse(&header_buf)
            .map_err(|e| format!("Invalid response header: {}", e))?;

        let mut resp_buf = vec![0u8; HEADER_SIZE + header.payload_len as usize];
        resp_buf[..HEADER_SIZE].copy_from_slice(&header_buf);
        match super::read_exact_cancellable(&mut stream, &mut resp_buf[HEADER_SIZE..], &cancel_flag)
        {
            Ok(()) => {}
            Err(super::IoAbort::Cancelled) => {
                return Err("Transfer canceled by sender".to_string());
            }
            Err(super::IoAbort::Io(e)) => {
                return Err(format!("Failed to read response payload: {}", e));
            }
        }

        let (_h, resp) = decode_file_response_packet(&active_session_key, &resp_buf)
            .or_else(|_| decode_file_response_packet(&PAIR_BOOTSTRAP_KEY, &resp_buf))
            .map_err(|e| format!("Failed to decode response: {}", e))?;

        if !resp.accepted {
            let reason = resp
                .error_message
                .unwrap_or_else(|| "Peer rejected file offer".to_string());
            return Err(reason);
        }

        let _ = file.seek(SeekFrom::Start(0));
        let mut hasher = Sha256::new();

        // 3. Stream File Chunks with 128 KiB Fixed Buffer + In-Place XChaCha20-Poly1305 AEAD
        let bulk_key = derive_bulk_key(&active_session_key, &stream_salt);
        let required_pool_cap = BULK_CHUNK_SIZE + TAG_SIZE;
        let mut pooled_buffer = PooledBuffer::acquire(required_pool_cap)
            .ok_or_else(|| "Failed to allocate pooled buffer for bulk sender".to_string())?;
        let mut aad_buf = [0u8; CHUNK_AAD_SIZE];
        let file_id_bytes = transfer_id.as_bytes();

        let mut sent_bytes = 0u64;
        let mut chunk_index = 0u64;
        let mut last_speed_time = Instant::now();
        let mut bytes_since_last = 0u64;

        while sent_bytes < total_size {
            if cancel_flag.is_cancelled() {
                return Err("Transfer canceled by user".to_string());
            }

            let to_read = std::cmp::min(BULK_CHUNK_SIZE as u64, total_size - sent_bytes) as usize;
            let buf_slice = pooled_buffer.as_mut_slice();

            let mut length = 0usize;
            while length < to_read {
                match file.read(&mut buf_slice[length..to_read]) {
                    Ok(0) => break,
                    Ok(n) => length += n,
                    Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.to_string()),
                }
            }
            if length == 0 {
                break;
            }

            hasher.update(&buf_slice[..length]);

            // Deterministic 192-bit (24-byte) chunk nonce: [fileNonce: 16B][chunkIndex: 8B BE]
            let chunk_nonce = derive_chunk_nonce(&stream_salt, chunk_index);

            // Build 57-byte binary AAD in-place
            build_chunk_aad(
                PROTOCOL_VERSION,
                file_id_bytes,
                chunk_index,
                length as u32,
                total_size,
                &mut aad_buf,
            );

            // In-place XChaCha20-Poly1305 AEAD encryption with HKDF-derived bulk_key
            let tag = encrypt_in_place_with_aad(
                &bulk_key,
                &chunk_nonce,
                &aad_buf,
                &mut buf_slice[..length],
            )
            .map_err(|e| format!("Chunk encryption error: {:?}", e))?;

            // Append 16-byte Poly1305 tag right after ciphertext
            let encrypted_len = length + TAG_SIZE;
            buf_slice[length..encrypted_len].copy_from_slice(&tag);

            // 可取消写：正常情况直接写完；对端不读时每 200ms 回来检查一次取消，
            // 而不是卡在 write_all 里等 30s 写超时。
            match super::write_all_cancellable(
                &mut stream,
                &buf_slice[..encrypted_len],
                &cancel_flag,
            ) {
                Ok(()) => {}
                Err(super::IoAbort::Cancelled) => {
                    return Err("Transfer canceled by sender".to_string());
                }
                Err(super::IoAbort::Io(e)) => return Err(e.to_string()),
            }

            sent_bytes += length as u64;
            bytes_since_last += length as u64;
            chunk_index += 1;

            let elapsed = last_speed_time.elapsed().as_secs_f64();
            if elapsed >= 0.25 || sent_bytes == total_size {
                let speed_bps = if elapsed > 0.0 {
                    (bytes_since_last as f64 / elapsed) as u64
                } else {
                    0
                };
                self.notify_progress(transfer_id, sent_bytes, total_size, speed_bps, true);
                last_speed_time = Instant::now();
                bytes_since_last = 0;
            }
        }

        if sent_bytes != total_size || chunk_index != total_chunks {
            return Err(format!(
                "Incomplete file read: sent {} / {} bytes ({} / {} chunks)",
                sent_bytes, total_size, chunk_index, total_chunks
            ));
        }

        stream.flush().map_err(|e| format!("Flush error: {}", e))?;

        // 4. Send Finish Frame with SHA-256 Checksum and total chunk count
        let final_sha256 = format!("{:x}", hasher.finalize());
        let finish_payload = FileFinishPayload {
            transfer_id: transfer_id.to_string(),
            sha256: final_sha256,
            total_chunks: chunk_index,
        };
        let finish_packet = encode_file_finish_packet(&active_session_key, 2, &finish_payload)
            .map_err(|e| format!("Encode finish error: {}", e))?;
        match super::write_all_cancellable(&mut stream, &finish_packet, &cancel_flag) {
            Ok(()) => {}
            Err(super::IoAbort::Cancelled) => {
                return Err("Transfer canceled by sender".to_string());
            }
            Err(super::IoAbort::Io(e)) => {
                return Err(format!("Send finish error: {}", e));
            }
        }
        stream.flush().map_err(|e| format!("Flush error: {}", e))?;

        // 5. Await and strictly verify 2-byte "OK" Confirmation from receiver
        let mut ack_buf = [0u8; 2];
        match super::read_exact_cancellable(&mut stream, &mut ack_buf, &cancel_flag) {
            Ok(()) => {}
            Err(super::IoAbort::Cancelled) => {
                return Err("Transfer canceled by sender".to_string());
            }
            Err(super::IoAbort::Io(_)) => {
                return Err("接收端未确认文件接收完成 (对方解密或完整性校验失败)".to_string());
            }
        }
        if &ack_buf != b"OK" {
            return Err("接收端完整性校验未通过".to_string());
        }

        Ok(transfer_id.to_string())
    }
}

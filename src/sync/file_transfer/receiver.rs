use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::pool::PooledBuffer;
use crate::sync::crypto::{
    CHUNK_AAD_SIZE, KEY_SIZE, TAG_SIZE, build_chunk_aad, decrypt_in_place_with_aad,
    derive_bulk_key, derive_chunk_nonce,
};
use crate::sync::protocol::{
    FileOfferPayload, FileResponsePayload, HEADER_SIZE, PROTOCOL_VERSION, SyncHeader,
    decode_file_finish_packet, encode_file_response_packet,
};

use super::{BULK_CHUNK_SIZE, FileTransferManager};

impl FileTransferManager {
    /// Handles an incoming file transfer stream from a peer on a dedicated Bulk TCP channel.
    pub fn handle_incoming_file_stream(
        self: &Arc<Self>,
        mut stream: TcpStream,
        offer: FileOfferPayload,
        session_key: &[u8; KEY_SIZE],
    ) -> Result<String, String> {
        let transfer_id = offer.transfer_id.clone();
        match self.handle_incoming_file_stream_internal(&mut stream, offer, session_key) {
            Ok(final_path) => {
                self.unregister_cancel_flag(&transfer_id);
                crate::log_info!("文件接收完成 -> {}", final_path);
                self.notify_completed(&transfer_id, &final_path, false, true, "");
                Ok(final_path)
            }
            Err(e) => {
                // 兜底翻译：取消会 shutdown socket，任何阻塞点（含写 response、
                // 写最终 OK）报上来的都会是网络错误。必须在 unregister 之前查。
                let cancelled = self.is_transfer_cancelled(&transfer_id);
                let e = if cancelled {
                    "Transfer canceled by receiver".to_string()
                } else {
                    e
                };
                self.unregister_cancel_flag(&transfer_id);
                // 取消是用户主动行为，记 INFO 而非 WARN，避免把正常操作报成故障。
                if cancelled {
                    crate::log_info!("文件接收已取消 transfer={}", transfer_id);
                } else {
                    crate::log_warn!("文件接收失败 transfer={}: {}", transfer_id, e);
                }
                self.notify_completed(&transfer_id, "", false, false, &e);
                Err(e)
            }
        }
    }

    fn handle_incoming_file_stream_internal(
        self: &Arc<Self>,
        stream: &mut TcpStream,
        offer: FileOfferPayload,
        session_key: &[u8; KEY_SIZE],
    ) -> Result<String, String> {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(Duration::from_secs(30)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));

        let transfer_id = offer.transfer_id.clone();
        let total_size = offer.file_size;
        // SECURITY: 对端提供的文件名不可信，必须先净化为单段安全文件名，
        // 否则绝对路径/`..` 穿越可导致任意文件写入（含登录启动项）。
        let file_name = super::sanitize_file_name(&offer.file_name);
        // .tmp 文件名同样来自对端字段，必须净化
        let tmp_stem = super::sanitize_transfer_id(&transfer_id);
        let stream_salt = offer.stream_salt.unwrap_or([0u8; 16]);
        let chunk_size = if offer.chunk_size > 0 && offer.chunk_size as usize <= BULK_CHUNK_SIZE {
            offer.chunk_size as usize
        } else {
            BULK_CHUNK_SIZE
        };
        let expected_chunk_count = if offer.total_chunks > 0 {
            offer.total_chunks
        } else if total_size == 0 {
            0
        } else {
            (total_size + chunk_size as u64 - 1) / chunk_size as u64
        };

        let cancel_flag = self.register_cancel_flag(&transfer_id);

        // 进入可取消阶段：把读超时压到轮询间隔，配合 `read_exact_cancellable`，
        // 让用户点取消后最多 200ms 就停下（原来要等 30s 读超时）。
        // 真正的「对端死了」判定由 `TRANSFER_IDLE_TIMEOUT` 在辅助函数里维护，
        // 所以这里缩短超时不会把慢速对端误判成断线。
        //
        // 注意：**本函数之前**的窗口（服务端读完 PFS 握手、等 offer 帧）仍是
        // `transport/server.rs` 里 15s 超时的裸读，且不可取消——这不是遗漏：
        // 那一刻 transfer_id 还没到，系统不知道用户要取消的是哪一次传输。
        // 该窗口在正常链路上只有几毫秒，恶意对端制造的也不过是 15s 的连接占用。
        let _ = stream.set_read_timeout(Some(super::CANCEL_POLL_INTERVAL));
        let _ = stream.set_write_timeout(Some(super::CANCEL_POLL_INTERVAL));

        let save_dir = self.get_save_directory();
        if !save_dir.exists() {
            let _ = std::fs::create_dir_all(&save_dir);
        }

        // Determine destination file path with strict path traversal prevention
        let safe_name = sanitize_file_name(&file_name);
        let mut dest_path = save_dir.join(&safe_name);
        if dest_path.exists() {
            let stem = dest_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("file");
            let ext = dest_path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| format!(".{}", e))
                .unwrap_or_default();
            let mut counter = 1;
            loop {
                let candidate = save_dir.join(format!("{}_{}{}", stem, counter, ext));
                if !candidate.exists() {
                    dest_path = candidate;
                    break;
                }
                counter += 1;
            }
        }

        let tmp_path = save_dir.join(format!("{}.tmp", tmp_stem));

        let res = (|| -> Result<String, String> {
            // 用 BufWriter 包裹：聚合多个 128 KiB 块后再落盘，
            // 避免每个块一次 write系统调用（实测这是接收端的主要开销）
            let file = match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
            {
                Ok(f) => f,
                Err(e) => {
                    let resp = FileResponsePayload {
                        transfer_id: transfer_id.clone(),
                        accepted: false,
                        error_code: 3,
                        error_message: Some(format!("Cannot create file on disk: {}", e)),
                        offset: 0,
                    };
                    if let Ok(pkt) = encode_file_response_packet(session_key, 1, &resp) {
                        let _ = stream.write_all(&pkt);
                        let _ = stream.flush();
                    }
                    return Err(format!("Disk write error: {}", e));
                }
            };

            let mut file = std::io::BufWriter::with_capacity(1024 * 1024, file);
            let _ = file.get_ref().seek(SeekFrom::Start(0));

            // Send Acceptance Response
            let resp = FileResponsePayload {
                transfer_id: transfer_id.clone(),
                accepted: true,
                error_code: 0,
                error_message: None,
                offset: 0,
            };
            let resp_packet = encode_file_response_packet(session_key, 1, &resp)
                .map_err(|e| format!("Encode response error: {}", e))?;
            stream
                .write_all(&resp_packet)
                .map_err(|e| format!("Send response error: {}", e))?;
            stream.flush().map_err(|e| format!("Flush error: {}", e))?;

            // Receive Chunk AEAD Stream with Fixed Buffer Reuse
            let bulk_key = derive_bulk_key(session_key, &stream_salt);
            let mut received_bytes = 0u64;
            let mut chunk_index = 0u64;
            let mut last_chunk_verified = total_size == 0;
            let mut last_speed_time = Instant::now();
            let mut bytes_since_last = 0u64;
            let mut hasher = Sha256::new();

            let required_pool_cap = chunk_size + TAG_SIZE;
            let mut pooled_buffer = PooledBuffer::acquire(required_pool_cap)
                .ok_or_else(|| "Failed to allocate pooled buffer for bulk receiver".to_string())?;
            let mut aad_buf = [0u8; CHUNK_AAD_SIZE];
            let file_id_bytes = transfer_id.as_bytes();

            while received_bytes < total_size {
                if cancel_flag.is_cancelled() {
                    return Err("Transfer canceled by receiver".to_string());
                }

                let expected_plain_len =
                    std::cmp::min(chunk_size as u64, total_size - received_bytes) as usize;
                let expected_encrypted_len = expected_plain_len + TAG_SIZE;

                let buf_slice = pooled_buffer.as_mut_slice();
                match super::read_exact_cancellable(
                    stream,
                    &mut buf_slice[..expected_encrypted_len],
                    &cancel_flag,
                ) {
                    Ok(()) => {}
                    // 取消不该被上报成网络故障，否则上层会提示「请检查网络」
                    Err(super::IoAbort::Cancelled) => {
                        return Err("Transfer canceled by receiver".to_string());
                    }
                    Err(super::IoAbort::Io(e)) => {
                        return Err(format!("Failed to read chunk ciphertext: {}", e));
                    }
                }

                // Derive deterministic 24-byte chunk nonce from (stream_salt, chunk_index)
                let chunk_nonce = derive_chunk_nonce(&stream_salt, chunk_index);

                // Build 57-byte binary AAD in-place
                build_chunk_aad(
                    PROTOCOL_VERSION,
                    file_id_bytes,
                    chunk_index,
                    expected_plain_len as u32,
                    total_size,
                    &mut aad_buf,
                );

                // Extract 16-byte Poly1305 tag and decrypt in-place with HKDF-derived bulk_key
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&buf_slice[expected_plain_len..expected_encrypted_len]);

                decrypt_in_place_with_aad(
                    &bulk_key,
                    &chunk_nonce,
                    &aad_buf,
                    &mut buf_slice[..expected_plain_len],
                    &tag,
                )
                .map_err(|_| format!("Poly1305 authentication failed at chunk {}", chunk_index))?;

                // Write verified plaintext directly to .tmp file
                file.write_all(&buf_slice[..expected_plain_len])
                    .map_err(|e| format!("Write file error: {}", e))?;

                hasher.update(&buf_slice[..expected_plain_len]);

                received_bytes += expected_plain_len as u64;
                bytes_since_last += expected_plain_len as u64;
                chunk_index += 1;

                if chunk_index == expected_chunk_count && received_bytes == total_size {
                    last_chunk_verified = true;
                }

                let elapsed = last_speed_time.elapsed().as_secs_f64();
                if elapsed >= 0.25 || received_bytes == total_size {
                    let speed_bps = if elapsed > 0.0 {
                        (bytes_since_last as f64 / elapsed) as u64
                    } else {
                        0
                    };
                    self.notify_progress(
                        &transfer_id,
                        received_bytes,
                        total_size,
                        speed_bps,
                        false,
                    );
                    last_speed_time = Instant::now();
                    bytes_since_last = 0;
                }
            }

            file.flush()
                .map_err(|e| format!("Flush file error: {}", e))?;
            // 落盘顺序：BufWriter flush -> sync_data -> rename。
            //
            // PERF: 这里用 `sync_data()` 而不是 `sync_all()`。`sync_all()` 额外要求把
            // 元数据（mtime、文件大小等）也提交到磁盘，而 `rename` 之后我们只关心「内容
            // 是否已经落盘」，元数据由后续的 rename 本身带出。Windows 上两者等价
            // （都是 FlushFileBuffers），但在 Android/Linux 上 fdatasync 可以跳过
            // 一次日志元数据提交，小文件连续传输时收益明显（每个文件一次 fsync 的
            // 固定开销才是这里的瓶颈，而不是数据量）。
            //
            // 注意：这里**没有**对父目录做 fsync，所以真正的保证是「内容已落盘，
            // 但 rename 这一步本身可能被掉电回滚」。回滚的最坏结果是留下一个 `.tmp`
            // 残留（孤儿文件），不会出现「最终文件名 + 空内容」这种静默损坏 ——
            // 后者正是这个 fsync 存在的唯一目的。
            let inner = file
                .into_inner()
                .map_err(|e| format!("Finalize buffer error: {}", e))?;
            inner
                .sync_data()
                .map_err(|e| format!("Sync file error: {}", e))?;
            drop(inner);

            // Strict Integrity Verification (Section 九)
            if chunk_index != expected_chunk_count {
                return Err(format!(
                    "Integrity check failed: receivedChunkCount ({}) != expectedChunkCount ({})",
                    chunk_index, expected_chunk_count
                ));
            }
            if received_bytes != total_size {
                return Err(format!(
                    "Integrity check failed: receivedBytes ({}) != expectedFileSize ({})",
                    received_bytes, total_size
                ));
            }
            if !last_chunk_verified {
                return Err("Integrity check failed: final chunk was not AEAD verified".to_string());
            }

            // Receive Finish Frame and verify SHA-256 & total_chunks
            let mut finish_header_buf = [0u8; HEADER_SIZE];
            match super::read_exact_cancellable(stream, &mut finish_header_buf, &cancel_flag) {
                Ok(()) => {}
                Err(super::IoAbort::Cancelled) => {
                    return Err("Transfer canceled by receiver".to_string());
                }
                Err(super::IoAbort::Io(e)) => {
                    return Err(format!("Failed to read finish frame header: {}", e));
                }
            }
            let header = SyncHeader::parse(&finish_header_buf)
                .map_err(|e| format!("Invalid finish frame header: {}", e))?;
            let mut finish_pkt = vec![0u8; HEADER_SIZE + header.payload_len as usize];
            finish_pkt[..HEADER_SIZE].copy_from_slice(&finish_header_buf);
            match super::read_exact_cancellable(
                stream,
                &mut finish_pkt[HEADER_SIZE..],
                &cancel_flag,
            ) {
                Ok(()) => {}
                Err(super::IoAbort::Cancelled) => {
                    return Err("Transfer canceled by receiver".to_string());
                }
                Err(super::IoAbort::Io(e)) => {
                    return Err(format!("Failed to read finish frame payload: {}", e));
                }
            }
            let (_h, finish) = decode_file_finish_packet(session_key, &finish_pkt)
                .map_err(|e| format!("Failed to decode finish frame: {}", e))?;

            if finish.total_chunks != expected_chunk_count {
                return Err(format!(
                    "Finish frame chunk count mismatch: {} != {}",
                    finish.total_chunks, expected_chunk_count
                ));
            }
            let computed_sha256 = format!("{:x}", hasher.finalize());
            if !finish.sha256.is_empty() && finish.sha256 != computed_sha256 {
                return Err("SHA-256 checksum mismatch on received file".to_string());
            }

            // Finalize File: ensure dest_path is strictly inside save_dir and rename .tmp
            if !dest_path.starts_with(&save_dir) {
                return Err("Security error: destination path escapes save directory".to_string());
            }
            std::fs::rename(&tmp_path, &dest_path).map_err(|e| format!("Rename error: {}", e))?;

            let _ = stream.write_all(b"OK");
            let _ = stream.flush();

            Ok(dest_path.to_string_lossy().to_string())
        })();

        // If verification or transfer failed, always delete the temporary .tmp file!
        if res.is_err() && tmp_path.exists() {
            let _ = std::fs::remove_file(&tmp_path);
        }

        res
    }
}

/// Sanitizes untrusted file names received over the network to prevent Directory Traversal (CWE-22).
/// Strips all leading directory components (e.g. `../../` or absolute drive roots) and invalid characters.
pub fn sanitize_file_name(raw_name: &str) -> String {
    let base_name = std::path::Path::new(raw_name)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.trim())
        .unwrap_or("");

    let cleaned: String = base_name
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|' | '\0'..='\x1f'
            )
        })
        .collect();

    let cleaned = cleaned.trim();
    if cleaned.is_empty() || cleaned == "." || cleaned == ".." {
        "unnamed_file".to_string()
    } else {
        cleaned.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_file_name_prevents_traversal() {
        assert_eq!(sanitize_file_name("../../../evil.bat"), "evil.bat");
        assert_eq!(
            sanitize_file_name("C:\\Windows\\System32\\bad.dll"),
            "bad.dll"
        );
        assert_eq!(sanitize_file_name("/etc/passwd"), "passwd");
        assert_eq!(sanitize_file_name(".."), "unnamed_file");
        assert_eq!(sanitize_file_name("."), "unnamed_file");
        assert_eq!(sanitize_file_name("   "), "unnamed_file");
        assert_eq!(sanitize_file_name("normal_file.png"), "normal_file.png");
        assert_eq!(sanitize_file_name("test:invalid?.txt"), "testinvalid.txt");
    }
}

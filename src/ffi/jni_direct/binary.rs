use crate::content::ContentAnalysis;
use crate::database::{HistoryItem, PhraseItem};
use crate::sync::{PairResponsePayload, PeerInfo};
use jni::sys::jint;

/// Zero-allocation Little-Endian binary cursor writer operating directly on an off-heap
/// `DirectByteBuffer` slice (`&mut [u8]`).
///
/// If the payload exceeds the slice capacity, `BinaryCursorWriter` stops writing bytes
/// but continues accumulating `pos` so the caller can return `-(required_bytes as jint)`
/// to let the JVM side resize its pooled `DirectByteBuffer` and retry.
pub struct BinaryCursorWriter<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> BinaryCursorWriter<'a> {
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        let end = self.pos + bytes.len();
        if end <= self.buf.len() {
            self.buf[self.pos..end].copy_from_slice(bytes);
        }
        self.pos = end;
    }

    #[inline]
    pub fn write_u8(&mut self, val: u8) {
        self.write_bytes(&[val]);
    }

    #[inline]
    pub fn write_bool(&mut self, val: bool) {
        self.write_u8(if val { 1 } else { 0 });
    }

    #[inline]
    pub fn write_i32(&mut self, val: i32) {
        self.write_bytes(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_u32(&mut self, val: u32) {
        self.write_bytes(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_i64(&mut self, val: i64) {
        self.write_bytes(&val.to_le_bytes());
    }

    #[inline]
    pub fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_i32(bytes.len() as i32);
        self.write_bytes(bytes);
    }

    #[inline]
    pub fn write_opt_str(&mut self, opt: Option<&str>) {
        match opt {
            Some(s) => self.write_str(s),
            None => self.write_i32(-1),
        }
    }

    /// Finishes writing and returns:
    /// - `>= 0`: exact number of bytes written into `buf`
    /// - `< -1`: `-(required_len as jint)` when `buf` capacity was insufficient
    #[inline]
    pub fn finish(self) -> jint {
        if self.pos <= self.buf.len() {
            self.pos as jint
        } else {
            // Ensure negative return is strictly < -1 so -1 remains reserved for general errors
            let req = (self.pos as jint).max(2);
            -req
        }
    }
}

/// Encodes a slice of `HistoryItem` directly into `out_buf` in Little-Endian binary wire format.
///
/// Layout:
/// - `count: u32`
/// - For each item:
///   - `id: i64`
///   - `char_count: i32`
///   - `line_count: i32`
///   - `byte_count: i32`
///   - `content: String` (`[i32 len][utf8]`)
///   - `content_type: String` (`[i32 len][utf8]`)
///   - `preview: String` (`[i32 len][utf8]`)
///   - `created_at: String` (`[i32 len][utf8]`)
///   - `last_used_at: String` (`[i32 len][utf8]`)
pub fn encode_history_items(items: &[HistoryItem], out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_u32(items.len() as u32);
    for item in items {
        w.write_i64(item.id);
        w.write_i32(item.char_count as i32);
        w.write_i32(item.line_count as i32);
        w.write_i32(item.byte_count as i32);
        w.write_str(&item.content);
        w.write_str(item.content_type.as_str());
        w.write_str(&item.preview);
        w.write_str(&item.created_at);
        w.write_str(&item.last_used_at);
    }
    w.finish()
}

/// Encodes a slice of `PhraseItem` directly into `out_buf` in Little-Endian binary wire format.
///
/// Layout:
/// - `count: u32`
/// - For each item:
///   - `id: i64`
///   - `sort_order: i64`
///   - `char_count: i32`
///   - `line_count: i32`
///   - `byte_count: i32`
///   - `content: String`
///   - `content_type: String`
///   - `preview: String`
///   - `created_at: String`
///   - `last_used_at: String`
pub fn encode_phrase_items(items: &[PhraseItem], out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_u32(items.len() as u32);
    for item in items {
        w.write_i64(item.id);
        w.write_i64(item.sort_order);
        w.write_i32(item.char_count as i32);
        w.write_i32(item.line_count as i32);
        w.write_i32(item.byte_count as i32);
        w.write_str(&item.content);
        w.write_str(item.content_type.as_str());
        w.write_str(&item.preview);
        w.write_str(&item.created_at);
        w.write_str(&item.last_used_at);
    }
    w.finish()
}

/// Encodes `ContentAnalysis` directly into `out_buf` in Little-Endian binary wire format.
///
/// Layout:
/// - `char_count: i32`
/// - `line_count: i32`
/// - `byte_count: i32`
/// - `content_type: String`
/// - `preview: String`
pub fn encode_content_analysis(analysis: &ContentAnalysis, out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_i32(analysis.char_count as i32);
    w.write_i32(analysis.line_count as i32);
    w.write_i32(analysis.byte_count as i32);
    w.write_str(analysis.content_type.as_str());
    w.write_str(&analysis.preview);
    w.finish()
}

/// Encodes a slice of `PeerInfo` directly into `out_buf` in Little-Endian binary wire format.
///
/// Layout:
/// - `count: u32`
/// - For each peer:
///   - `sync_port: i32`
///   - `last_seen_ms: i64`
///   - `is_online: u8`
///   - `is_paired: u8`
///   - `is_manual: u8`
///   - `device_id: String`
///   - `device_name: String`
///   - `device_type: String`
///   - `ip: String`
///   - `fingerprint: String`
pub fn encode_peers(peers: &[PeerInfo], out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_u32(peers.len() as u32);
    for peer in peers {
        w.write_i32(peer.sync_port as i32);
        w.write_i64(peer.last_seen_ms as i64);
        w.write_bool(peer.is_online);
        w.write_bool(peer.is_paired);
        w.write_bool(peer.is_manual);
        w.write_str(&peer.device_id);
        w.write_str(&peer.device_name);
        w.write_str(&peer.device_type);
        w.write_str(&peer.ip);
        w.write_str(&peer.fingerprint);
    }
    w.finish()
}

/// Encodes a list of `String` (e.g. manual peer endpoints) into `out_buf`.
///
/// Layout:
/// - `count: u32`
/// - For each string: `[i32 len][utf8]`
pub fn encode_string_list(items: &[String], out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_u32(items.len() as u32);
    for s in items {
        w.write_str(s);
    }
    w.finish()
}

/// Encodes a pairing handshake result (`PairResponsePayload` or error) into `out_buf`.
///
/// Layout:
/// - `success: u8`
/// - `error_code: i32`
/// - `responder_device_id: String`
/// - `responder_device_name: String`
/// - `error_message: Option<String>`
/// - `long_term_key: Option<String>`
pub fn encode_pair_response(resp: &PairResponsePayload, out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_bool(resp.accepted);
    w.write_i32(resp.error_code);
    w.write_str(&resp.responder_device_id);
    w.write_str(&resp.responder_device_name);
    w.write_opt_str(resp.error_message.as_deref());
    w.write_opt_str(resp.long_term_key_hex.as_deref());
    w.finish()
}

/// Encodes a pairing error into `out_buf` using the same binary layout as `encode_pair_response`.
pub fn encode_pair_error(error_code: i32, error_message: &str, out_buf: &mut [u8]) -> jint {
    let mut w = BinaryCursorWriter::new(out_buf);
    w.write_bool(false);
    w.write_i32(error_code);
    w.write_str("");
    w.write_str("");
    w.write_opt_str(Some(error_message));
    w.write_opt_str(None);
    w.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content::ContentType;

    #[test]
    fn test_encode_history_items_and_overflow() {
        let item = HistoryItem {
            id: 42,
            content: "Hello 世界".to_string(),
            content_type: ContentType::PlainText,
            char_count: 8,
            line_count: 1,
            byte_count: 12,
            preview: "Hello 世界".to_string(),
            created_at: "2026-10-08 14:00:00".to_string(),
            last_used_at: "2026-10-08 14:00:00".to_string(),
        };

        let mut small_buf = [0u8; 8];
        let res_small = encode_history_items(&[item.clone()], &mut small_buf);
        assert!(
            res_small < -1,
            "Expected negative required size, got {}",
            res_small
        );

        let required = (-res_small) as usize;
        let mut exact_buf = vec![0u8; required];
        let written = encode_history_items(&[item], &mut exact_buf);
        assert_eq!(written as usize, required);

        // Verify header count = 1
        assert_eq!(u32::from_le_bytes(exact_buf[0..4].try_into().unwrap()), 1);
        // Verify id = 42
        assert_eq!(i64::from_le_bytes(exact_buf[4..12].try_into().unwrap()), 42);
        // Verify char_count = 8, line_count = 1, byte_count = 12
        assert_eq!(i32::from_le_bytes(exact_buf[12..16].try_into().unwrap()), 8);
        assert_eq!(i32::from_le_bytes(exact_buf[16..20].try_into().unwrap()), 1);
        assert_eq!(
            i32::from_le_bytes(exact_buf[20..24].try_into().unwrap()),
            12
        );
    }

    #[test]
    fn test_encode_peers_binary() {
        let peer = PeerInfo {
            device_id: "dev-1".to_string(),
            device_name: "Pixel 9".to_string(),
            device_type: "Android".to_string(),
            ip: "192.168.1.50".to_string(),
            sync_port: 42424,
            last_seen_ms: 1700000000000,
            is_online: true,
            fingerprint: "abcd".to_string(),
            is_paired: true,
            is_manual: false,
        };

        let mut buf = [0u8; 512];
        let written = encode_peers(&[peer], &mut buf);
        assert!(written > 0);
        assert_eq!(u32::from_le_bytes(buf[0..4].try_into().unwrap()), 1);
        assert_eq!(i32::from_le_bytes(buf[4..8].try_into().unwrap()), 42424);
        assert_eq!(
            i64::from_le_bytes(buf[8..16].try_into().unwrap()),
            1700000000000
        );
        assert_eq!(buf[16], 1); // is_online
        assert_eq!(buf[17], 1); // is_paired
        assert_eq!(buf[18], 0); // is_manual
    }
}

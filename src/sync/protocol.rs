use crate::sync::crypto::{
    CryptoError, KEY_SIZE, NONCE_SIZE, TAG_SIZE, compute_sha256_hex, decrypt_in_place_with_aad,
    encrypt_in_place_with_aad, generate_nonce,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

pub const PROTOCOL_MAGIC: &[u8; 4] = b"MUCL";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 44;
pub const FRAME_AAD_SIZE: usize = 16;

pub const MSG_HEARTBEAT: u8 = 1;
pub const MSG_CLIPBOARD_SYNC: u8 = 2;
pub const MSG_ACK: u8 = 3;
pub const MSG_PAIR_REQUEST: u8 = 4;
pub const MSG_PAIR_ACK: u8 = 5;
pub const MSG_UNPAIR_NOTICE: u8 = 6;
pub const MSG_FILE_OFFER: u8 = 10;
pub const MSG_FILE_RESPONSE: u8 = 11;
pub const MSG_FILE_FINISH: u8 = 13;
pub const MSG_SESSION_INIT: u8 = 20;
pub const MSG_SESSION_RESP: u8 = 21;

pub const PAIR_BOOTSTRAP_KEY: [u8; KEY_SIZE] = [
    0x4d, 0x75, 0x43, 0x6c, 0x69, 0x70, 0x50, 0x61, // "MuClipPa"
    0x69, 0x72, 0x42, 0x6f, 0x6f, 0x74, 0x73, 0x74, // "irBootst"
    0x72, 0x61, 0x70, 0x4b, 0x65, 0x79, 0x32, 0x30, // "rapKey20"
    0x32, 0x36, 0x5f, 0x53, 0x65, 0x63, 0x75, 0x72, // "26_Secur"
];

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("Invalid magic: expected {expected:?}, got {actual:?}")]
    InvalidMagic { expected: [u8; 4], actual: [u8; 4] },
    #[error("Unsupported protocol version: {0}")]
    UnsupportedVersion(u8),
    #[error("Buffer too short: length {0}, minimum {1}")]
    BufferTooShort(usize, usize),
    #[error("Payload exceeds maximum size: {0} > {1}")]
    PayloadTooLarge(usize, usize),
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Binary frame header: 44 bytes
/// [0..4]   Magic (MUCL)
/// [4]      Version (1)
/// [5]      MessageType (1=Heartbeat, 2=ClipboardSync, 3=Ack, ...)
/// [6..8]   Flags (u16 big endian)
/// [8..16]  Sequence (u64 big endian)
/// [16..40] Nonce (24 bytes)
/// [40..44] PayloadLen (u32 big endian - includes 16B Poly1305 tag)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncHeader {
    pub version: u8,
    pub msg_type: u8,
    pub flags: u16,
    pub sequence: u64,
    pub nonce: [u8; NONCE_SIZE],
    pub payload_len: u32,
}

impl SyncHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::BufferTooShort(buf.len(), HEADER_SIZE));
        }

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&buf[0..4]);
        if &magic != PROTOCOL_MAGIC {
            return Err(ProtocolError::InvalidMagic {
                expected: *PROTOCOL_MAGIC,
                actual: magic,
            });
        }

        let version = buf[4];
        if version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        let msg_type = buf[5];
        let flags = u16::from_be_bytes([buf[6], buf[7]]);
        let sequence = u64::from_be_bytes(buf[8..16].try_into().unwrap());

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&buf[16..40]);

        let payload_len = u32::from_be_bytes(buf[40..44].try_into().unwrap());

        Ok(Self {
            version,
            msg_type,
            flags,
            sequence,
            nonce,
            payload_len,
        })
    }

    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), ProtocolError> {
        if buf.len() < HEADER_SIZE {
            return Err(ProtocolError::BufferTooShort(buf.len(), HEADER_SIZE));
        }

        buf[0..4].copy_from_slice(PROTOCOL_MAGIC);
        buf[4] = self.version;
        buf[5] = self.msg_type;
        buf[6..8].copy_from_slice(&self.flags.to_be_bytes());
        buf[8..16].copy_from_slice(&self.sequence.to_be_bytes());
        buf[16..40].copy_from_slice(&self.nonce);
        buf[40..44].copy_from_slice(&self.payload_len.to_be_bytes());

        Ok(())
    }

    /// Associated Authenticated Data (AAD) for framed packets (16 bytes):
    /// Cryptographically binds Magic (4B), Version (1B), MsgType (1B), Flags (2B),
    /// and Sequence (8B) into the Poly1305 authentication tag.
    #[inline]
    pub fn aad(&self) -> [u8; FRAME_AAD_SIZE] {
        build_frame_aad(self.version, self.msg_type, self.flags, self.sequence)
    }
}

/// Helper function to construct the 16-byte frame AAD before or during packet encoding.
/// Layout: [Magic: 4B][Version: 1B][MsgType: 1B][Flags: 2B BE][Sequence: 8B BE] = 16 bytes.
#[inline]
pub fn build_frame_aad(
    version: u8,
    msg_type: u8,
    flags: u16,
    sequence: u64,
) -> [u8; FRAME_AAD_SIZE] {
    let mut aad = [0u8; FRAME_AAD_SIZE];
    aad[0..4].copy_from_slice(PROTOCOL_MAGIC);
    aad[4] = version;
    aad[5] = msg_type;
    aad[6..8].copy_from_slice(&flags.to_be_bytes());
    aad[8..16].copy_from_slice(&sequence.to_be_bytes());
    aad
}

/// Encodes `payload` into a single `Vec<u8>` wire packet and encrypts it in-place
/// using `encrypt_in_place_with_aad` with 16-byte header AAD binding.
fn encode_encrypted_frame<T: Serialize>(
    key: &[u8; KEY_SIZE],
    msg_type: u8,
    sequence: u64,
    payload: &T,
) -> Result<Vec<u8>, ProtocolError> {
    let mut packet = Vec::with_capacity(HEADER_SIZE + 256);
    packet.resize(HEADER_SIZE, 0);
    serde_json::to_writer(&mut packet, payload)?;
    packet.reserve(TAG_SIZE);

    let nonce = generate_nonce();
    let aad = build_frame_aad(PROTOCOL_VERSION, msg_type, 0, sequence);
    let tag = encrypt_in_place_with_aad(key, &nonce, &aad, &mut packet[HEADER_SIZE..])?;
    packet.extend_from_slice(&tag);

    let cipher_len = packet.len() - HEADER_SIZE;
    let header = SyncHeader {
        version: PROTOCOL_VERSION,
        msg_type,
        flags: 0,
        sequence,
        nonce,
        payload_len: cipher_len as u32,
    };
    header.write_to(&mut packet[..HEADER_SIZE])?;
    Ok(packet)
}

/// Encodes `payload` directly into caller-provided `out_buf` and encrypts in-place
/// with 16-byte header AAD binding (zero heap allocations). Returns total packet length written.
pub fn encode_encrypted_frame_into<T: Serialize>(
    key: &[u8; KEY_SIZE],
    msg_type: u8,
    sequence: u64,
    payload: &T,
    out_buf: &mut [u8],
) -> Result<usize, ProtocolError> {
    if out_buf.len() < HEADER_SIZE + TAG_SIZE {
        return Err(ProtocolError::BufferTooShort(
            out_buf.len(),
            HEADER_SIZE + TAG_SIZE,
        ));
    }

    let max_plain_len = out_buf.len() - HEADER_SIZE - TAG_SIZE;
    let plain_len = {
        let mut cursor =
            std::io::Cursor::new(&mut out_buf[HEADER_SIZE..HEADER_SIZE + max_plain_len]);
        serde_json::to_writer(&mut cursor, payload)?;
        cursor.position() as usize
    };

    let nonce = generate_nonce();
    let aad = build_frame_aad(PROTOCOL_VERSION, msg_type, 0, sequence);
    let tag = encrypt_in_place_with_aad(
        key,
        &nonce,
        &aad,
        &mut out_buf[HEADER_SIZE..HEADER_SIZE + plain_len],
    )?;
    let tag_start = HEADER_SIZE + plain_len;
    let total_len = tag_start + TAG_SIZE;
    out_buf[tag_start..total_len].copy_from_slice(&tag);

    let header = SyncHeader {
        version: PROTOCOL_VERSION,
        msg_type,
        flags: 0,
        sequence,
        nonce,
        payload_len: (plain_len + TAG_SIZE) as u32,
    };
    header.write_to(&mut out_buf[..HEADER_SIZE])?;
    Ok(total_len)
}

/// Decrypts a framed packet in-place inside `raw_packet` using `decrypt_in_place_with_aad`
/// with 16-byte header AAD verification, and deserializes `T` directly from the decrypted slice.
pub fn decode_encrypted_frame_in_place<T: DeserializeOwned>(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, T), ProtocolError> {
    let header = SyncHeader::parse(raw_packet)?;
    let cipher_len = header.payload_len as usize;
    let expected_total_len = HEADER_SIZE + cipher_len;

    if raw_packet.len() < expected_total_len {
        return Err(ProtocolError::BufferTooShort(
            raw_packet.len(),
            expected_total_len,
        ));
    }
    if cipher_len < TAG_SIZE {
        return Err(ProtocolError::Crypto(CryptoError::DecryptionFailed));
    }

    let plain_len = cipher_len - TAG_SIZE;
    let (body, tag_slice) = raw_packet[HEADER_SIZE..expected_total_len].split_at_mut(plain_len);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    let aad = header.aad();
    decrypt_in_place_with_aad(key, &header.nonce, &aad, body, &tag)?;
    let payload: T = serde_json::from_slice(body)?;
    Ok((header, payload))
}

/// Decrypts a framed packet in-place trying `primary_key` first, then `fallback_key` if authentication fails,
/// with 16-byte header AAD verification.
pub fn decode_encrypted_frame_in_place_with_fallback<T: DeserializeOwned>(
    primary_key: &[u8; KEY_SIZE],
    fallback_key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, T), ProtocolError> {
    let header = SyncHeader::parse(raw_packet)?;
    let cipher_len = header.payload_len as usize;
    let expected_total_len = HEADER_SIZE + cipher_len;

    if raw_packet.len() < expected_total_len {
        return Err(ProtocolError::BufferTooShort(
            raw_packet.len(),
            expected_total_len,
        ));
    }
    if cipher_len < TAG_SIZE {
        return Err(ProtocolError::Crypto(CryptoError::DecryptionFailed));
    }

    let plain_len = cipher_len - TAG_SIZE;
    let (body, tag_slice) = raw_packet[HEADER_SIZE..expected_total_len].split_at_mut(plain_len);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    let aad = header.aad();
    if decrypt_in_place_with_aad(primary_key, &header.nonce, &aad, body, &tag).is_err() {
        decrypt_in_place_with_aad(fallback_key, &header.nonce, &aad, body, &tag)?;
    }
    let payload: T = serde_json::from_slice(body)?;
    Ok((header, payload))
}

/// Decrypts a framed packet from an immutable slice by copying only the ciphertext body
/// and decrypting in-place via `decrypt_in_place_with_aad` with 16-byte header AAD verification.
fn decode_encrypted_frame<T: DeserializeOwned>(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, T), ProtocolError> {
    let header = SyncHeader::parse(raw_packet)?;
    let cipher_len = header.payload_len as usize;
    let expected_total_len = HEADER_SIZE + cipher_len;

    if raw_packet.len() < expected_total_len {
        return Err(ProtocolError::BufferTooShort(
            raw_packet.len(),
            expected_total_len,
        ));
    }
    if cipher_len < TAG_SIZE {
        return Err(ProtocolError::Crypto(CryptoError::DecryptionFailed));
    }

    let plain_len = cipher_len - TAG_SIZE;
    let (cipher_body, tag_slice) = raw_packet[HEADER_SIZE..expected_total_len].split_at(plain_len);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    let mut body = cipher_body.to_vec();
    let aad = header.aad();
    decrypt_in_place_with_aad(key, &header.nonce, &aad, &mut body, &tag)?;
    let payload: T = serde_json::from_slice(&body)?;
    Ok((header, payload))
}

/// Structured plaintext payload transmitted directly between paired MuClip nodes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SyncPayload {
    /// Unique message ID generated via UUID v7 (time-ordered, millisecond precision).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub msg_id: String,
    /// SHA-256 hex hash of the content - critical for loopback suppression and deduplication.
    pub content_hash: String,
    /// Originating device ID.
    pub source_device_id: String,
    /// Originating device human-readable name.
    pub source_device_name: String,
    /// Creation timestamp in milliseconds since epoch.
    pub timestamp_ms: u64,
    /// Data type: "text", "image", "code", etc.
    pub content_type: String,
    /// UTF-8 clipboard content or base64 binary.
    pub content: String,
}

impl SyncPayload {
    pub fn new_text(
        source_id: impl Into<String>,
        source_name: impl Into<String>,
        text: &str,
    ) -> Self {
        let content_hash = compute_sha256_hex(text.as_bytes());
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let msg_id = uuid::Uuid::now_v7().to_string();

        Self {
            msg_id,
            content_hash,
            source_device_id: source_id.into(),
            source_device_name: source_name.into(),
            timestamp_ms,
            content_type: "text".to_string(),
            content: text.to_string(),
        }
    }
}

/// Encodes and encrypts a `SyncPayload` in-place into a binary Wire packet.
pub fn encode_packet(
    key: &[u8; KEY_SIZE],
    msg_type: u8,
    sequence: u64,
    payload: &SyncPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(key, msg_type, sequence, payload)
}

/// Decodes and decrypts a binary Wire packet in-place into `(SyncHeader, SyncPayload)`.
pub fn decode_packet_in_place(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, SyncPayload), ProtocolError> {
    decode_encrypted_frame_in_place(key, raw_packet)
}

/// Decodes and decrypts a binary Wire packet in-place trying multiple candidate keys in order.
/// Returns `(SyncHeader, SyncPayload, matched_key)`.
pub fn decode_packet_with_keys_in_place(
    candidate_keys: &[[u8; KEY_SIZE]],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, SyncPayload, [u8; KEY_SIZE]), ProtocolError> {
    let header = SyncHeader::parse(raw_packet)?;
    let cipher_len = header.payload_len as usize;
    let expected_total_len = HEADER_SIZE + cipher_len;

    if raw_packet.len() < expected_total_len {
        return Err(ProtocolError::BufferTooShort(
            raw_packet.len(),
            expected_total_len,
        ));
    }
    if cipher_len < TAG_SIZE {
        return Err(ProtocolError::Crypto(CryptoError::DecryptionFailed));
    }

    let plain_len = cipher_len - TAG_SIZE;
    let (body, tag_slice) = raw_packet[HEADER_SIZE..expected_total_len].split_at_mut(plain_len);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    let aad = header.aad();
    for key in candidate_keys {
        if decrypt_in_place_with_aad(key, &header.nonce, &aad, body, &tag).is_ok() {
            let payload: SyncPayload = serde_json::from_slice(body)?;
            return Ok((header, payload, *key));
        }
    }
    Err(ProtocolError::Crypto(CryptoError::DecryptionFailed))
}

/// Decodes and decrypts a binary Wire packet into `(SyncHeader, SyncPayload)`.
pub fn decode_packet(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, SyncPayload), ProtocolError> {
    decode_encrypted_frame(key, raw_packet)
}

/// Lightweight payload for initiating pairing with a random PIN
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairRequestPayload {
    pub request_id: String,
    pub from_device_id: String,
    pub from_device_name: String,
    pub challenge: String,
    pub pin_hash: String,
    #[serde(default)]
    pub public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub auth_tag: Option<String>,
}

/// Lightweight payload for responding to a pairing request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PairResponsePayload {
    pub request_id: String,
    pub accepted: bool,
    pub responder_device_id: String,
    pub responder_device_name: String,
    pub error_code: i32, // 0 = ok, 1 = rejected, 2 = wrong pin, 3 = timeout
    pub error_message: Option<String>,
    #[serde(default)]
    pub public_key: Option<[u8; 32]>,
    #[serde(default)]
    pub auth_tag: Option<String>,
    /// **进程内字段，永不上线路。**
    ///
    /// 长期配对密钥由双方各自通过 SPAKE2 共享秘密 + HKDF 本地派生（`derive_long_term_key`），
    /// 不需要任何一方把它发出去。该字段只用于把本地派生结果带回给 FFI 调用方
    /// （`execute_client_pair_handshake` 在收到网络响应后本地回填）。
    ///
    /// `encode_pair_response_packet` 会在编码前强制清除该字段，因此即使调用方误填，
    /// 密钥也不会进入任何 Wire 帧。
    #[serde(default)]
    pub long_term_key_hex: Option<String>,
}

/// Encodes and encrypts a PairRequestPayload into a binary Wire packet using PAIR_BOOTSTRAP_KEY.
pub fn encode_pair_request_packet(
    seq: u64,
    payload: &PairRequestPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, MSG_PAIR_REQUEST, seq, payload)
}

/// Decodes and decrypts a binary Wire packet in-place into `(SyncHeader, PairRequestPayload)`.
pub fn decode_pair_request_packet_in_place(
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, PairRequestPayload), ProtocolError> {
    decode_encrypted_frame_in_place(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Decodes and decrypts a binary Wire packet into `(SyncHeader, PairRequestPayload)`.
pub fn decode_pair_request_packet(
    raw_packet: &[u8],
) -> Result<(SyncHeader, PairRequestPayload), ProtocolError> {
    decode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Encodes and encrypts a PairResponsePayload into a binary Wire packet using PAIR_BOOTSTRAP_KEY.
///
/// **SECURITY**: 长期配对密钥绝不允许出现在网络上。`PAIR_BOOTSTRAP_KEY` 是编译进二进制的
/// 公开常量，任何能嗅探局域网的人都能用它解密本帧；若把 256-bit 长期密钥放进这个帧里，
/// SPAKE2 提供的「PIN 不可离线爆破」保证会被完全抵消（攻击者无需知道 PIN）。
///
/// 因此这里在唯一的网络出口处强制清除 `long_term_key_hex`，不依赖各调用点自觉。
pub fn encode_pair_response_packet(
    seq: u64,
    payload: &PairResponsePayload,
) -> Result<Vec<u8>, ProtocolError> {
    let mut safe_payload = payload.clone();
    safe_payload.long_term_key_hex = None;
    encode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, MSG_PAIR_ACK, seq, &safe_payload)
}

/// Decodes and decrypts a binary Wire packet in-place into `(SyncHeader, PairResponsePayload)`.
pub fn decode_pair_response_packet_in_place(
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, PairResponsePayload), ProtocolError> {
    decode_encrypted_frame_in_place(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Decodes and decrypts a binary Wire packet into `(SyncHeader, PairResponsePayload)`.
pub fn decode_pair_response_packet(
    raw_packet: &[u8],
) -> Result<(SyncHeader, PairResponsePayload), ProtocolError> {
    decode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Payload for notifying remote peer that it has been unpaired
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnpairNoticePayload {
    pub from_device_id: String,
}

pub fn encode_unpair_notice_packet(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &UnpairNoticePayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(key, MSG_UNPAIR_NOTICE, seq, payload)
}

pub fn decode_unpair_notice_packet_in_place(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, UnpairNoticePayload), ProtocolError> {
    decode_encrypted_frame_in_place(key, raw_packet)
}

pub fn decode_unpair_notice_packet(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, UnpairNoticePayload), ProtocolError> {
    decode_encrypted_frame(key, raw_packet)
}

/// Payload for initiating a PFS Ephemeral Session Key negotiation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInitPayload {
    pub client_device_id: String,
    #[serde(default)]
    pub target_device_id: Option<String>,
    pub ephemeral_pk: [u8; 32],
    pub challenge: [u8; 16],
    pub auth_tag: String,
}

/// Payload for responding to a PFS Ephemeral Session Key negotiation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionRespPayload {
    pub responder_device_id: String,
    pub ephemeral_pk: [u8; 32],
    pub auth_tag: String,
    pub accepted: bool,
}

pub fn encode_session_init_packet(
    seq: u64,
    payload: &SessionInitPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, MSG_SESSION_INIT, seq, payload)
}

pub fn decode_session_init_packet_in_place(
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, SessionInitPayload), ProtocolError> {
    decode_encrypted_frame_in_place(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

pub fn encode_session_resp_packet(
    seq: u64,
    payload: &SessionRespPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, MSG_SESSION_RESP, seq, payload)
}

pub fn decode_session_resp_packet_in_place(
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, SessionRespPayload), ProtocolError> {
    decode_encrypted_frame_in_place(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Encodes and encrypts a `DiscoveryBeacon` into a TCP `MSG_HEARTBEAT` frame using `PAIR_BOOTSTRAP_KEY`.
/// This allows discovering and probing port-mapped peers over TCP even before pairing.
pub fn encode_heartbeat_packet(
    seq: u64,
    beacon: &crate::sync::discovery::DiscoveryBeacon,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, MSG_HEARTBEAT, seq, beacon)
}

/// Decodes and decrypts a TCP `MSG_HEARTBEAT` frame in-place into `(SyncHeader, DiscoveryBeacon)`.
pub fn decode_heartbeat_packet_in_place(
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, crate::sync::discovery::DiscoveryBeacon), ProtocolError> {
    decode_encrypted_frame_in_place(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Decodes and decrypts a TCP `MSG_HEARTBEAT` frame into `(SyncHeader, DiscoveryBeacon)`.
pub fn decode_heartbeat_packet(
    raw_packet: &[u8],
) -> Result<(SyncHeader, crate::sync::discovery::DiscoveryBeacon), ProtocolError> {
    decode_encrypted_frame(&PAIR_BOOTSTRAP_KEY, raw_packet)
}

/// Payload sent to initiate a file transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileOfferPayload {
    pub transfer_id: String,
    pub from_device_id: String,
    pub from_device_name: String,
    pub file_name: String,
    pub file_size: u64,
    pub sha256: String,
    pub mime_type: String,
    #[serde(default)]
    pub stream_nonce: Option<[u8; NONCE_SIZE]>,
    #[serde(default)]
    pub stream_salt: Option<[u8; 16]>,
    #[serde(default)]
    pub offset: u64,
    #[serde(default)]
    pub chunk_size: u32,
    #[serde(default)]
    pub total_chunks: u64,
}

pub fn encode_file_offer_packet(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileOfferPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(key, MSG_FILE_OFFER, seq, payload)
}

pub fn encode_file_offer_packet_into(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileOfferPayload,
    out_buf: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_encrypted_frame_into(key, MSG_FILE_OFFER, seq, payload, out_buf)
}

pub fn decode_file_offer_packet_in_place(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, FileOfferPayload), ProtocolError> {
    let (_, bulk_key) = crate::sync::crypto::derive_session_subkeys(key).unwrap_or((*key, *key));
    decode_encrypted_frame_in_place_with_fallback(&bulk_key, key, raw_packet)
}

pub fn decode_file_offer_with_keys_in_place(
    candidate_keys: &[[u8; KEY_SIZE]],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, FileOfferPayload, [u8; KEY_SIZE]), ProtocolError> {
    for key in candidate_keys {
        if let Ok((hdr, offer)) = decode_file_offer_packet_in_place(key, raw_packet) {
            return Ok((hdr, offer, *key));
        }
    }
    Err(ProtocolError::Crypto(CryptoError::DecryptionFailed))
}

pub fn decode_file_offer_packet(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, FileOfferPayload), ProtocolError> {
    let mut owned = raw_packet.to_vec();
    decode_file_offer_packet_in_place(key, &mut owned)
}

/// Payload responding to a file transfer offer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileResponsePayload {
    pub transfer_id: String,
    pub accepted: bool,
    pub error_code: i32, // 0 = ok, 1 = rejected by user, 2 = not paired, 3 = disk error
    pub error_message: Option<String>,
    #[serde(default)]
    pub offset: u64,
}

pub fn encode_file_response_packet(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileResponsePayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(key, MSG_FILE_RESPONSE, seq, payload)
}

pub fn encode_file_response_packet_into(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileResponsePayload,
    out_buf: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_encrypted_frame_into(key, MSG_FILE_RESPONSE, seq, payload, out_buf)
}

pub fn decode_file_response_packet_in_place(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, FileResponsePayload), ProtocolError> {
    let (_, bulk_key) = crate::sync::crypto::derive_session_subkeys(key).unwrap_or((*key, *key));
    decode_encrypted_frame_in_place_with_fallback(&bulk_key, key, raw_packet)
}

pub fn decode_file_response_packet(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, FileResponsePayload), ProtocolError> {
    let mut owned = raw_packet.to_vec();
    decode_file_response_packet_in_place(key, &mut owned)
}

/// Payload notifying completion of file transfer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileFinishPayload {
    pub transfer_id: String,
    pub sha256: String,
    #[serde(default)]
    pub total_chunks: u64,
}

pub fn encode_file_finish_packet(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileFinishPayload,
) -> Result<Vec<u8>, ProtocolError> {
    encode_encrypted_frame(key, MSG_FILE_FINISH, seq, payload)
}

pub fn encode_file_finish_packet_into(
    key: &[u8; KEY_SIZE],
    seq: u64,
    payload: &FileFinishPayload,
    out_buf: &mut [u8],
) -> Result<usize, ProtocolError> {
    encode_encrypted_frame_into(key, MSG_FILE_FINISH, seq, payload, out_buf)
}

pub fn decode_file_finish_packet_in_place(
    key: &[u8; KEY_SIZE],
    raw_packet: &mut [u8],
) -> Result<(SyncHeader, FileFinishPayload), ProtocolError> {
    let (_, bulk_key) = crate::sync::crypto::derive_session_subkeys(key).unwrap_or((*key, *key));
    decode_encrypted_frame_in_place_with_fallback(&bulk_key, key, raw_packet)
}

pub fn decode_file_finish_packet(
    key: &[u8; KEY_SIZE],
    raw_packet: &[u8],
) -> Result<(SyncHeader, FileFinishPayload), ProtocolError> {
    let mut owned = raw_packet.to_vec();
    decode_file_finish_packet_in_place(key, &mut owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::crypto::derive_key;

    #[test]
    fn test_protocol_packet_roundtrip() {
        let key = derive_key("pairing-pin-654321", None).unwrap();
        let payload = SyncPayload::new_text(
            "device-win-1",
            "Windows Workstation",
            "Hello from P2P Sync!",
        );

        let packet = encode_packet(&key, MSG_CLIPBOARD_SYNC, 42, &payload).expect("encode packet");
        assert!(packet.len() > HEADER_SIZE);

        let (header, decoded_payload) = decode_packet(&key, &packet).expect("decode packet");
        assert_eq!(header.msg_type, MSG_CLIPBOARD_SYNC);
        assert_eq!(header.sequence, 42);
        assert_eq!(decoded_payload.content, "Hello from P2P Sync!");
        assert_eq!(decoded_payload.source_device_id, "device-win-1");
        assert_eq!(decoded_payload.content_hash, payload.content_hash);
    }

    #[test]
    fn test_pair_request_response_roundtrip() {
        let req = PairRequestPayload {
            request_id: "req-123".to_string(),
            from_device_id: "dev-a".to_string(),
            from_device_name: "Device A".to_string(),
            challenge: "chall-xyz".to_string(),
            pin_hash: "hash123".to_string(),
            public_key: Some([42u8; 32]),
            auth_tag: Some("test-auth-tag-abcdef".to_string()),
        };

        let req_packet = encode_pair_request_packet(1, &req).expect("encode req");
        let (req_header, decoded_req) =
            decode_pair_request_packet(&req_packet).expect("decode req");
        assert_eq!(req_header.msg_type, MSG_PAIR_REQUEST);
        assert_eq!(decoded_req, req);

        let resp = PairResponsePayload {
            request_id: "req-123".to_string(),
            accepted: true,
            responder_device_id: "dev-b".to_string(),
            responder_device_name: "Device B".to_string(),
            error_code: 0,
            error_message: None,
            public_key: Some([84u8; 32]),
            auth_tag: Some("test-resp-auth-tag".to_string()),
            long_term_key_hex: Some(
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            ),
        };

        let resp_packet = encode_pair_response_packet(2, &resp).expect("encode resp");
        let (resp_header, decoded_resp) =
            decode_pair_response_packet(&resp_packet).expect("decode resp");
        assert_eq!(resp_header.msg_type, MSG_PAIR_ACK);
        // 除长期密钥外必须无损往返；密钥字段在编码时被强制清空（见
        // test_pair_response_never_transmits_long_term_key）
        let expected = PairResponsePayload {
            long_term_key_hex: None,
            ..resp
        };
        assert_eq!(decoded_resp, expected);
    }

    /// SECURITY 回归测试：`PAIR_BOOTSTRAP_KEY` 是编译进二进制的公开常量，
    /// 任何嗅探局域网的人都能用它解密 MSG_PAIR_ACK。因此长期配对密钥绝不能出现在该帧里，
    /// 否则 SPAKE2 的抗离线爆破保证会被完全抵消（攻击者无需 PIN 即可拿到 256-bit 长期密钥）。
    #[test]
    fn test_pair_response_never_transmits_long_term_key() {
        let secret_hex = "a".repeat(64);
        let resp = PairResponsePayload {
            request_id: "req-x".to_string(),
            accepted: true,
            responder_device_id: "dev-b".to_string(),
            responder_device_name: "Device B".to_string(),
            error_code: 0,
            error_message: None,
            public_key: Some([7u8; 32]),
            auth_tag: Some("tag".to_string()),
            // 故意填入密钥，验证编码器会在网络出口处强制清除
            long_term_key_hex: Some(secret_hex.clone()),
        };

        let pkt = encode_pair_response_packet(1, &resp).expect("encode");

        assert!(
            !pkt.windows(secret_hex.len())
                .any(|w| w == secret_hex.as_bytes()),
            "长期密钥的明文形式不得出现在网络帧的任何位置"
        );

        // 模拟攻击者：用公开的 PAIR_BOOTSTRAP_KEY 解密该帧
        let (_h, decoded) = decode_pair_response_packet(&pkt).expect("decode");
        assert!(
            decoded.long_term_key_hex.is_none(),
            "攻击者用 PAIR_BOOTSTRAP_KEY 解密后必须拿不到长期密钥"
        );
        // 握手本身仍然完整可用
        assert!(decoded.accepted);
        assert_eq!(decoded.responder_device_id, "dev-b");
        assert!(decoded.public_key.is_some());
        assert!(decoded.auth_tag.is_some());
    }

    #[test]
    fn test_header_roundtrip_is_byte_exact() {
        let header = SyncHeader {
            version: PROTOCOL_VERSION,
            msg_type: MSG_HEARTBEAT,
            flags: 0x1234,
            sequence: u64::MAX,
            nonce: [0x5A; NONCE_SIZE],
            payload_len: 4096,
        };

        let mut buf = vec![0u8; HEADER_SIZE];
        header.write_to(&mut buf).expect("write header");

        assert_eq!(&buf[0..4], PROTOCOL_MAGIC, "魔数必须位于帧首");
        assert_eq!(buf[4], PROTOCOL_VERSION);

        let parsed = SyncHeader::parse(&buf).expect("parse header");
        assert_eq!(parsed, header, "头部序列化必须可无损还原");
        assert_eq!(parsed.flags, 0x1234, "flags 必须按大端序写入");
        assert_eq!(parsed.sequence, u64::MAX, "sequence 必须支持 u64 全量");
    }

    #[test]
    fn test_header_rejects_bad_magic_and_version() {
        let header = SyncHeader {
            version: PROTOCOL_VERSION,
            msg_type: MSG_ACK,
            flags: 0,
            sequence: 1,
            nonce: [0u8; NONCE_SIZE],
            payload_len: 0,
        };
        let mut buf = vec![0u8; HEADER_SIZE];
        header.write_to(&mut buf).unwrap();

        let mut bad_magic = buf.clone();
        bad_magic[0] = b'X';
        assert!(matches!(
            SyncHeader::parse(&bad_magic),
            Err(ProtocolError::InvalidMagic { .. })
        ));

        let mut bad_version = buf.clone();
        bad_version[4] = PROTOCOL_VERSION + 1;
        assert!(matches!(
            SyncHeader::parse(&bad_version),
            Err(ProtocolError::UnsupportedVersion(_))
        ));

        assert!(matches!(
            SyncHeader::parse(&buf[..HEADER_SIZE - 1]),
            Err(ProtocolError::BufferTooShort(_, _))
        ));
    }

    #[test]
    fn test_tampered_ciphertext_is_rejected_end_to_end() {
        let key = derive_key("pairing-pin-999999", None).unwrap();
        let payload = SyncPayload::new_text("dev-a", "Device A", "原始剪贴板内容");

        let packet = encode_packet(&key, MSG_CLIPBOARD_SYNC, 7, &payload).expect("encode");
        let mut tampered = packet.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;

        assert!(
            decode_packet(&key, &tampered).is_err(),
            "被篡改的帧必须在 AEAD 认证阶段被拒绝，绝不能交付明文"
        );
    }

    #[test]
    fn test_wrong_pin_cannot_decode_packet() {
        let key_a = derive_key("111222", None).unwrap();
        let key_b = derive_key("222111", None).unwrap();
        let payload = SyncPayload::new_text("dev-a", "Device A", "confidential");

        let packet = encode_packet(&key_a, MSG_CLIPBOARD_SYNC, 1, &payload).unwrap();
        assert!(
            decode_packet(&key_b, &packet).is_err(),
            "PIN 不一致的双方无法解密，配对密钥即访问控制边界"
        );
    }

    #[test]
    fn test_truncated_packet_is_rejected() {
        let key = derive_key("333444", None).unwrap();
        let payload = SyncPayload::new_text("dev-a", "Device A", "truncation test");
        let packet = encode_packet(&key, MSG_CLIPBOARD_SYNC, 3, &payload).unwrap();

        for cut in [1usize, 8, HEADER_SIZE - 1] {
            let truncated = &packet[..packet.len().saturating_sub(cut)];
            assert!(
                decode_packet(&key, truncated).is_err(),
                "截断 {} 字节后必须被拒绝",
                cut
            );
        }
    }

    #[test]
    fn test_tampered_header_metadata_is_rejected_by_aead_aad() {
        let key = derive_key("pairing-pin-888888", None).unwrap();
        let payload = SyncPayload::new_text("dev-a", "Device A", "aad-protected-message");
        let packet = encode_packet(&key, MSG_CLIPBOARD_SYNC, 100, &payload).expect("encode");

        // 1. 篡改包头里的 MsgType (字节 5: MSG_CLIPBOARD_SYNC -> MSG_HEARTBEAT)
        let mut tampered_msg_type = packet.clone();
        tampered_msg_type[5] = MSG_HEARTBEAT;
        assert!(
            matches!(
                decode_packet(&key, &tampered_msg_type),
                Err(ProtocolError::Crypto(CryptoError::DecryptionFailed))
            ),
            "篡改 MsgType 必须被 Poly1305 AAD 验签拦截并拒绝，绝不能静默放行"
        );

        // 2. 篡改包头里的 Sequence 序号 (字节 8..16)
        let mut tampered_seq = packet.clone();
        tampered_seq[8] ^= 0x01;
        assert!(
            matches!(
                decode_packet(&key, &tampered_seq),
                Err(ProtocolError::Crypto(CryptoError::DecryptionFailed))
            ),
            "篡改 Sequence 序号必须被 Poly1305 AAD 验签拦截并拒绝"
        );

        // 3. 篡改包头里的 Flags 标志 (字节 6..8)
        let mut tampered_flags = packet.clone();
        tampered_flags[6] ^= 0x01;
        assert!(
            matches!(
                decode_packet(&key, &tampered_flags),
                Err(ProtocolError::Crypto(CryptoError::DecryptionFailed))
            ),
            "篡改 Flags 标志必须被 Poly1305 AAD 验签拦截并拒绝"
        );
    }

    #[test]
    fn test_zero_alloc_frame_into_and_decode_in_place_with_aad() {
        let key = derive_key("pairing-pin-333222", None).unwrap();
        let payload = SyncPayload::new_text("dev-x", "Device X", "zero-alloc-test");

        let mut buf = vec![0u8; 1024];
        let written_len =
            encode_encrypted_frame_into(&key, MSG_CLIPBOARD_SYNC, 77, &payload, &mut buf)
                .expect("encode into");
        assert!(written_len > HEADER_SIZE);

        let (header, decoded): (SyncHeader, SyncPayload) =
            decode_encrypted_frame_in_place(&key, &mut buf[..written_len])
                .expect("decode in place");
        assert_eq!(header.msg_type, MSG_CLIPBOARD_SYNC);
        assert_eq!(header.sequence, 77);
        assert_eq!(decoded.content, "zero-alloc-test");
    }
}

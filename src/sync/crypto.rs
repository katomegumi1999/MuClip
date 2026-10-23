use chacha20::XChaCha20;
use chacha20::cipher::KeyIvInit;
#[cfg(test)]
use chacha20::cipher::StreamCipher;
use chacha20poly1305::aead::{Aead, AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use thiserror::Error;

use x25519_dalek::{PublicKey, StaticSecret};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 24; // 192-bit Extended Nonce for XChaCha20
pub const TAG_SIZE: usize = 16;
pub const DEFAULT_SALT: &[u8] = b"muclip-e2ee-sync-salt-v1";

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Key derivation failed")]
    KeyDerivationFailed,
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("Decryption failed / authentication tag mismatch")]
    DecryptionFailed,
    #[error("Buffer too small: capacity {cap}, required {required}")]
    BufferTooSmall { cap: usize, required: usize },
    #[error("Invalid ECDH public key")]
    InvalidPublicKey,
}

/// Helper to parse 64 hex characters into a 32-byte array
pub fn hex_to_32bytes(hex: &str) -> Result<[u8; 32], CryptoError> {
    if hex.len() != 64 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        bytes[i] =
            u8::from_str_radix(byte_str, 16).map_err(|_| CryptoError::KeyDerivationFailed)?;
    }
    Ok(bytes)
}

/// Converts a 32-byte array into a 64-char lowercase hex string
pub fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Derives a 256-bit symmetric session key from a pairing PIN, passphrase, or 64-char hex key.
/// If `pin_or_pass` is already a 64-char hex key, it directly parses the 32-byte key without re-hashing!
pub fn derive_key(pin_or_pass: &str, salt: Option<&[u8]>) -> Result<[u8; KEY_SIZE], CryptoError> {
    let trimmed = pin_or_pass.trim();
    if trimmed.len() == 64 {
        if let Ok(bytes) = hex_to_32bytes(trimmed) {
            return Ok(bytes);
        }
    }
    let actual_salt = salt.unwrap_or(DEFAULT_SALT);
    let hk = Hkdf::<Sha256>::new(Some(actual_salt), trimmed.as_bytes());
    let mut key = [0u8; KEY_SIZE];
    hk.expand(b"muclip-p2p-chacha20-poly1305-key", &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Generates a cryptographically random 256-bit (32-byte) permanent device `long_term_key` using `OsRng`.
pub fn generate_device_long_term_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::rngs::OsRng.fill_bytes(&mut key);
    key
}

/// Generates a cryptographically random 256-bit (64-char lowercase hex) permanent device `long_term_key`.
pub fn generate_device_long_term_key_hex() -> String {
    bytes_to_hex(&generate_device_long_term_key())
}

/// Checks whether `key` is the weak default key derived from `"000000"` or all zeros.
pub fn is_default_key(key: &[u8; KEY_SIZE]) -> bool {
    if key.iter().all(|&b| b == 0) {
        return true;
    }
    derive_key("000000", None)
        .map(|def_k| &def_k == key)
        .unwrap_or(false)
}

/// Wraps (encrypts + authenticates) an existing 32-byte cluster `long_term_key` under the
/// ephemeral SPAKE2-derived key (`spake2_key`) using XChaCha20-Poly1305 and a deterministic
/// HKDF-derived nonce bound to `challenge_nonce`.
/// Returns a 96-character lowercase hex string (32B ciphertext + 16B Poly1305 tag).
pub fn wrap_cluster_key(
    spake2_key: &[u8; KEY_SIZE],
    cluster_key: &[u8; KEY_SIZE],
    challenge_nonce: &str,
) -> Result<String, CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(challenge_nonce.as_bytes()), spake2_key);
    let mut nonce = [0u8; NONCE_SIZE];
    hk.expand(b"MuClip-ClusterKeyWrap-Nonce-v1", &mut nonce)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut buf = *cluster_key;
    let tag = encrypt_in_place_with_aad(
        spake2_key,
        &nonce,
        b"MuClip-ClusterKeyWrap-AAD-v1",
        &mut buf,
    )?;

    let mut out_hex = String::with_capacity(96);
    for b in buf.iter().chain(tag.iter()) {
        use std::fmt::Write;
        let _ = write!(out_hex, "{:02x}", b);
    }
    Ok(out_hex)
}

/// Unwraps and authenticates a 96-character hex wrapped cluster key using `spake2_key`
/// and `challenge_nonce`. Returns the 32-byte cluster key if and only if the Poly1305 tag is valid.
pub fn unwrap_cluster_key(
    spake2_key: &[u8; KEY_SIZE],
    wrapped_hex: &str,
    challenge_nonce: &str,
) -> Result<[u8; KEY_SIZE], CryptoError> {
    let trimmed = wrapped_hex.trim();
    if trimmed.len() != 96 {
        return Err(CryptoError::DecryptionFailed);
    }
    let mut raw = [0u8; 48];
    for i in 0..48 {
        raw[i] = u8::from_str_radix(&trimmed[i * 2..i * 2 + 2], 16)
            .map_err(|_| CryptoError::DecryptionFailed)?;
    }

    let hk = Hkdf::<Sha256>::new(Some(challenge_nonce.as_bytes()), spake2_key);
    let mut nonce = [0u8; NONCE_SIZE];
    hk.expand(b"MuClip-ClusterKeyWrap-Nonce-v1", &mut nonce)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;

    let mut body = [0u8; KEY_SIZE];
    body.copy_from_slice(&raw[..32]);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&raw[32..48]);

    decrypt_in_place_with_aad(
        spake2_key,
        &nonce,
        b"MuClip-ClusterKeyWrap-AAD-v1",
        &mut body,
        &tag,
    )?;
    Ok(body)
}

/// Ephemeral X25519 ECDH key exchange session for pairing handshake.
pub struct KeyExchangeSession {
    secret: StaticSecret,
    pub public_key: [u8; 32],
}

impl KeyExchangeSession {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = zeroize::Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut *secret_bytes);
        let secret = StaticSecret::from(*secret_bytes);
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public_key: *public.as_bytes(),
        }
    }

    /// Computes Diffie-Hellman shared secret with the peer's public key.
    pub fn compute_shared_secret(
        &self,
        peer_public_key: &[u8; 32],
    ) -> zeroize::Zeroizing<[u8; 32]> {
        let peer_pub = PublicKey::from(*peer_public_key);
        let shared = self.secret.diffie_hellman(&peer_pub);
        zeroize::Zeroizing::new(*shared.as_bytes())
    }
}

/// Derives a PIN authentication key used to authenticate PAKE / ECDH exchange.
pub fn derive_pin_auth_key(pin: &str) -> Result<[u8; KEY_SIZE], CryptoError> {
    derive_key(pin, Some(b"muclip-pin-auth-salt-v1"))
}

pub const PAIR_ALG_ID: &[u8] = b"SPAKE2-Ed25519-XChaCha20Poly1305";
pub const SPAKE2_ID_INITIATOR: &[u8] = b"MuClip-SPAKE2-Initiator-v1";

/// Standard SPAKE2 (RFC 9382 / Ed25519Group) single-use Initiator session (`Side::A`).
/// Blinds the ephemeral Ed25519 point inside the prime-order group (`X = x*B + w*M`),
/// leaking zero bits of the 6-digit PIN to passive or active adversaries.
/// Consumed on `finish(self, ...)` so ephemeral SPAKE2 state is never reused across PIN attempts.
pub struct Spake2InitiatorSession {
    state: Spake2<Ed25519Group>,
    /// The 32-byte compressed Ed25519 group element `X = x*B + w*M` (from `msg1[1..33]`).
    pub public_message: [u8; 32],
}

impl Spake2InitiatorSession {
    pub fn new(pin: &str, challenge_nonce: &str) -> Self {
        let password = Password::new(pin.trim().as_bytes());
        let id_a = Identity::new(SPAKE2_ID_INITIATOR);
        let id_b_str = format!("MuClip-SPAKE2-Responder-v1:{}", challenge_nonce);
        let id_b = Identity::new(id_b_str.as_bytes());

        let (state, msg_a) = Spake2::<Ed25519Group>::start_a(&password, &id_a, &id_b);
        let mut public_message = [0u8; 32];
        public_message.copy_from_slice(&msg_a[1..33]);

        Self {
            state,
            public_message,
        }
    }

    /// Consumes this single-use SPAKE2 session and evaluates `Spake2::<Ed25519Group>::finish`
    /// against the Responder's 32-byte SPAKE2 message `Y = y*B + w*N`.
    pub fn finish(self, responder_msg_point: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        let mut full_msg_b = [0u8; 33];
        full_msg_b[0] = 0x42; // 'B'
        full_msg_b[1..33].copy_from_slice(responder_msg_point);

        let shared_vec = self
            .state
            .finish(&full_msg_b)
            .map_err(|_| CryptoError::InvalidPublicKey)?;
        if shared_vec.len() != 32 {
            return Err(CryptoError::KeyDerivationFailed);
        }
        let mut shared_secret = [0u8; 32];
        shared_secret.copy_from_slice(&shared_vec);
        Ok(shared_secret)
    }
}

/// Executes the Responder (`Side::B`) step of SPAKE2 (`Ed25519Group`):
/// Given `pin`, `challenge_nonce`, and the Initiator's 32-byte SPAKE2 point `X = x*B + w*M`,
/// generates a fresh Responder ephemeral scalar `y`, computes `Y = y*B + w*N` (32 bytes) and
/// the 32-byte SPAKE2 shared key `K_shared`.
pub fn spake2_responder_exchange(
    pin: &str,
    challenge_nonce: &str,
    initiator_msg_point: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), CryptoError> {
    let password = Password::new(pin.trim().as_bytes());
    let id_a = Identity::new(SPAKE2_ID_INITIATOR);
    let id_b_str = format!("MuClip-SPAKE2-Responder-v1:{}", challenge_nonce);
    let id_b = Identity::new(id_b_str.as_bytes());

    let (s_b, msg_b) = Spake2::<Ed25519Group>::start_b(&password, &id_a, &id_b);
    if msg_b.len() != 33 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut responder_msg_point = [0u8; 32];
    responder_msg_point.copy_from_slice(&msg_b[1..33]);

    let mut full_msg_a = [0u8; 33];
    full_msg_a[0] = 0x41; // 'A'
    full_msg_a[1..33].copy_from_slice(initiator_msg_point);

    let shared_vec = s_b
        .finish(&full_msg_a)
        .map_err(|_| CryptoError::InvalidPublicKey)?;
    if shared_vec.len() != 32 {
        return Err(CryptoError::KeyDerivationFailed);
    }
    let mut shared_secret = [0u8; 32];
    shared_secret.copy_from_slice(&shared_vec);
    Ok((responder_msg_point, shared_secret))
}

/// Generates a random 16-byte challenge nonce formatted as a 32-char lowercase hex string.
pub fn generate_challenge_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    let mut hex = String::with_capacity(32);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Derives the high-entropy 256-bit long-term key from SPAKE2/ECDH shared secret and PIN authentication via HKDF-SHA256.
/// - Rejects all-zero low-order shared secrets (`CryptoError::InvalidPublicKey`)
/// - IKM = shared_secret || pin_auth_key
/// - salt = challenge_nonce
/// - info = "MuClip-LTK-v1" || initiator_pk || responder_pk || protocol_ver
pub fn derive_long_term_key(
    shared_secret: &[u8; 32],
    pin_auth_key: &[u8; KEY_SIZE],
    challenge_nonce: &str,
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    protocol_ver: u8,
) -> Result<[u8; KEY_SIZE], CryptoError> {
    if shared_secret.iter().all(|&b| b == 0) {
        return Err(CryptoError::InvalidPublicKey);
    }
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(shared_secret);
    ikm[32..].copy_from_slice(pin_auth_key);

    let hk = Hkdf::<Sha256>::new(Some(challenge_nonce.as_bytes()), &ikm);
    let mut info = Vec::with_capacity(80);
    info.extend_from_slice(b"MuClip-LTK-v1");
    info.extend_from_slice(initiator_pk);
    info.extend_from_slice(responder_pk);
    info.push(protocol_ver);

    let mut key = [0u8; KEY_SIZE];
    hk.expand(&info, &mut key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok(key)
}

/// Derives a 256-bit bulk file transfer subkey from `session_key` and `stream_salt` via HKDF-SHA256:
/// bulk_key = HKDF-Expand(HKDF-Extract(salt = stream_salt, ikm = session_key), info = "MuClip-BulkFile-SubKey-v1", 32)
pub fn derive_bulk_key(session_key: &[u8; KEY_SIZE], stream_salt: &[u8; 16]) -> [u8; KEY_SIZE] {
    let hk = Hkdf::<Sha256>::new(Some(stream_salt), session_key);
    let mut bulk_key = [0u8; KEY_SIZE];
    hk.expand(b"MuClip-BulkFile-SubKey-v1", &mut bulk_key)
        .expect("32-byte HKDF expand cannot fail");
    bulk_key
}

/// Derives independent 256-bit Control Channel Key and Bulk Channel Key from a Session Master Key.
/// Enforces cryptographic domain separation via HKDF-Expand with distinct labels ("muclip-control-v1" and "MuClip-BulkFile-SubKey-v1").
pub fn derive_session_subkeys(
    master_key: &[u8; KEY_SIZE],
) -> Result<([u8; KEY_SIZE], [u8; KEY_SIZE]), CryptoError> {
    let hk = Hkdf::<Sha256>::new(Some(DEFAULT_SALT), master_key);
    let mut control_key = [0u8; KEY_SIZE];
    let mut bulk_key = [0u8; KEY_SIZE];
    hk.expand(b"muclip-control-v1", &mut control_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    hk.expand(b"MuClip-BulkFile-SubKey-v1", &mut bulk_key)
        .map_err(|_| CryptoError::KeyDerivationFailed)?;
    Ok((control_key, bulk_key))
}

/// Computes an HMAC-SHA256 (HKDF) authentication tag binding:
/// - both ephemeral public keys (`initiator_pk`, `responder_pk`)
/// - `role` ("initiator" or "responder")
/// - `challenge_nonce`
/// - `protocol_ver`
/// - algorithm identifier (`PAIR_ALG_ID`)
pub fn compute_ecdh_auth_tag(
    auth_key: &[u8; KEY_SIZE],
    initiator_pk: &[u8; 32],
    responder_pk: &[u8; 32],
    role: &str,
    challenge_nonce: &str,
    protocol_ver: u8,
) -> String {
    let hk = Hkdf::<Sha256>::new(Some(challenge_nonce.as_bytes()), auth_key);
    let mut info = Vec::with_capacity(128);
    info.extend_from_slice(b"MuClip-Auth-v1|");
    info.extend_from_slice(PAIR_ALG_ID);
    info.push(protocol_ver);
    info.extend_from_slice(role.as_bytes());
    info.extend_from_slice(initiator_pk);
    info.extend_from_slice(responder_pk);

    let mut tag = [0u8; 32];
    let _ = hk.expand(&info, &mut tag);
    bytes_to_hex(&tag)
}

/// Computes an HMAC-SHA256 authentication tag binding:
/// - long_term_key (auth_key)
/// - initiator_id (client device ID)
/// - responder_id (server device ID)
/// - ephemeral_pk
/// - peer_ephemeral_pk
/// - role ("initiator" / "responder")
/// - challenge
pub fn compute_session_auth_tag(
    long_term_key: &[u8; KEY_SIZE],
    initiator_id: &str,
    responder_id: &str,
    ephemeral_pk: &[u8; 32],
    peer_ephemeral_pk: Option<&[u8; 32]>,
    role: &str,
    challenge: &[u8; 16],
) -> String {
    let hk = Hkdf::<Sha256>::new(Some(challenge), long_term_key);
    let mut info = Vec::with_capacity(160);
    info.extend_from_slice(b"MuClip-PFS-Auth-v2|");
    info.extend_from_slice(initiator_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(responder_id.as_bytes());
    info.extend_from_slice(b"|");
    info.extend_from_slice(role.as_bytes());
    info.extend_from_slice(ephemeral_pk);
    if let Some(peer_pk) = peer_ephemeral_pk {
        info.extend_from_slice(peer_pk);
    }
    let mut tag = [0u8; 32];
    let _ = hk.expand(&info, &mut tag);
    bytes_to_hex(&tag)
}

/// Derives a 256-bit PFS Ephemeral Session Key from an Ephemeral Diffie-Hellman shared secret
/// and long_term_key via HKDF-SHA256:
/// session_key = HKDF-Expand(HKDF-Extract(salt = challenge, ikm = shared_secret || long_term_key), info = "MuClip-PFS-SessionKey-v1", 32)
/// Automatically zeroes the intermediate IKM memory buffer on drop.
pub fn derive_pfs_session_key(
    shared_secret: &[u8; 32],
    long_term_key: &[u8; KEY_SIZE],
    challenge: &[u8; 16],
) -> zeroize::Zeroizing<[u8; KEY_SIZE]> {
    let mut ikm = zeroize::Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(shared_secret);
    ikm[32..].copy_from_slice(long_term_key);

    let hk = Hkdf::<Sha256>::new(Some(challenge), &*ikm);
    let mut key = zeroize::Zeroizing::new([0u8; KEY_SIZE]);
    hk.expand(b"MuClip-PFS-SessionKey-v1", &mut *key)
        .expect("32-byte HKDF expand cannot fail");
    key
}

/// Derives a deterministic chunk nonce using a 16-byte stream salt and a 64-bit sequence counter.
/// Layout: [salt: 16 bytes][counter: 8 bytes big-endian] = 24 bytes (192 bits).
/// This prevents nonce collisions in streaming AEAD and detects chunk reordering or replay.
pub fn derive_chunk_nonce(stream_salt: &[u8; 16], chunk_counter: u64) -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    nonce[..16].copy_from_slice(stream_salt);
    nonce[16..24].copy_from_slice(&chunk_counter.to_be_bytes());
    nonce
}

/// Extracts the 16-byte stream salt and counter from a 24-byte chunk nonce.
pub fn parse_chunk_nonce(nonce: &[u8; NONCE_SIZE]) -> ([u8; 16], u64) {
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&nonce[..16]);
    let counter = u64::from_be_bytes(nonce[16..24].try_into().unwrap_or([0u8; 8]));
    (salt, counter)
}

/// Generates a cryptographically secure 192-bit (24-byte) random nonce for XChaCha20.
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Creates an XChaCha20 streaming cipher instance initialized with a 256-bit key and 192-bit nonce.
/// Enables continuous zero-allocation in-place stream encryption/decryption at gigabytes-per-second throughput.
pub fn create_xchacha20_stream(key: &[u8; KEY_SIZE], nonce: &[u8; NONCE_SIZE]) -> XChaCha20 {
    XChaCha20::new(key.into(), nonce.into())
}

/// Computes SHA-256 hash of content, formatted as a lowercase hex string.
pub fn compute_sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hex = String::with_capacity(64);
    for b in result {
        use std::fmt::Write;
        let _ = write!(hex, "{:02x}", b);
    }
    hex
}

/// Constant-time string equality comparison using subtle::ConstantTimeEq.
/// Prevents timing side-channel attacks when verifying authentication tags or HMACs.
pub fn constant_time_eq_str(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Constant-time byte slice equality comparison.
pub fn constant_time_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Encrypts `plaintext` using XChaCha20-Poly1305 AEAD.
/// Returns ciphertext with the 16-byte Poly1305 authentication tag appended.
pub fn encrypt_payload(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(cipher_nonce, plaintext)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{:?}", e)))
}

/// Decrypts `ciphertext` (which includes 16-byte authentication tag) using XChaCha20-Poly1305.
pub fn decrypt_payload(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(cipher_nonce, ciphertext)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypts `plaintext` using XChaCha20-Poly1305 with Associated Data (`aad`).
/// Returns ciphertext with the 16-byte Poly1305 authentication tag appended.
pub fn encrypt_payload_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, Payload};
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);

    cipher
        .encrypt(
            cipher_nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::EncryptionFailed(format!("{:?}", e)))
}

/// Decrypts `ciphertext` (which includes 16-byte authentication tag) using XChaCha20-Poly1305 with Associated Data (`aad`).
pub fn decrypt_payload_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::aead::{Aead, Payload};
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(
            cipher_nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Derives a 256-bit encryption key from user password and salt using PBKDF2-HMAC-SHA256.
/// Result is wrapped in `zeroize::Zeroizing` to ensure memory is securely erased when dropped.
pub fn derive_backup_key(
    password: &str,
    salt: &[u8; 32],
    rounds: u32,
) -> zeroize::Zeroizing<[u8; KEY_SIZE]> {
    let mut key = zeroize::Zeroizing::new([0u8; KEY_SIZE]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, rounds, &mut *key);
    key
}

/// Fixed 57-byte AAD binary layout for chunk context authentication:
/// [0]      protocol_version (u8)
/// [1..37]  file_id (36 bytes, ASCII/UTF-8 zero-padded)
/// [37..45] chunk_index (u64 big-endian)
/// [45..49] chunk_length (u32 big-endian, plaintext length)
/// [49..57] total_file_size (u64 big-endian)
pub const FILE_CHUNK_SIZE: usize = 128 * 1024;
pub const FILE_ID_AAD_LEN: usize = 36;
pub const CHUNK_AAD_SIZE: usize = 1 + FILE_ID_AAD_LEN + 8 + 4 + 8; // 57 bytes

/// Writes the fixed 57-byte binary AAD into `out_aad` in-place with zero heap allocation.
pub fn build_chunk_aad(
    protocol_version: u8,
    file_id: &[u8],
    chunk_index: u64,
    chunk_length: u32,
    total_file_size: u64,
    out_aad: &mut [u8; CHUNK_AAD_SIZE],
) {
    out_aad[0] = protocol_version;
    out_aad[1..1 + FILE_ID_AAD_LEN].fill(0);
    let copy_len = file_id.len().min(FILE_ID_AAD_LEN);
    out_aad[1..1 + copy_len].copy_from_slice(&file_id[..copy_len]);
    out_aad[37..45].copy_from_slice(&chunk_index.to_be_bytes());
    out_aad[45..49].copy_from_slice(&chunk_length.to_be_bytes());
    out_aad[49..57].copy_from_slice(&total_file_size.to_be_bytes());
}

/// Encrypts `buffer` in-place using XChaCha20-Poly1305 with associated data (`aad`).
/// Overwrites `buffer` with ciphertext and returns the 16-byte Poly1305 authentication tag.
pub fn encrypt_in_place_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    buffer: &mut [u8],
) -> Result<[u8; TAG_SIZE], CryptoError> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);

    let tag = cipher
        .encrypt_in_place_detached(cipher_nonce, aad, buffer)
        .map_err(|e| CryptoError::EncryptionFailed(format!("{:?}", e)))?;

    let mut tag_bytes = [0u8; TAG_SIZE];
    tag_bytes.copy_from_slice(tag.as_slice());
    Ok(tag_bytes)
}

/// Decrypts `buffer` in-place using XChaCha20-Poly1305 with associated data (`aad`).
/// Overwrites `buffer` with decrypted plaintext and verifies the 16-byte authentication tag.
pub fn decrypt_in_place_with_aad(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> Result<(), CryptoError> {
    let cipher_key = Key::from_slice(key);
    let cipher = XChaCha20Poly1305::new(cipher_key);
    let cipher_nonce = XNonce::from_slice(nonce);
    let cipher_tag = chacha20poly1305::Tag::from_slice(tag);

    cipher
        .decrypt_in_place_detached(cipher_nonce, aad, buffer, cipher_tag)
        .map_err(|_| CryptoError::DecryptionFailed)
}

/// Encrypts `buffer` in-place using XChaCha20-Poly1305 (empty AAD).
/// Overwrites `buffer` with ciphertext and returns the 16-byte Poly1305 authentication tag.
pub fn encrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    buffer: &mut [u8],
) -> Result<[u8; TAG_SIZE], CryptoError> {
    encrypt_in_place_with_aad(key, nonce, b"", buffer)
}

/// Decrypts `buffer` in-place using XChaCha20-Poly1305 (empty AAD).
/// Overwrites `buffer` with decrypted plaintext and verifies the 16-byte authentication tag.
pub fn decrypt_in_place(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    buffer: &mut [u8],
    tag: &[u8; TAG_SIZE],
) -> Result<(), CryptoError> {
    decrypt_in_place_with_aad(key, nonce, b"", buffer, tag)
}

/// Zero-copy in-buffer encryption: copies `plaintext` into `out_buffer` and encrypts in-place
/// without allocating any intermediate `Vec<u8>`.
/// Returns the number of bytes written (`plaintext.len() + TAG_SIZE`).
pub fn encrypt_zero_copy(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    plaintext: &[u8],
    out_buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    let plain_len = plaintext.len();
    let required = plain_len + TAG_SIZE;
    if out_buffer.len() < required {
        return Err(CryptoError::BufferTooSmall {
            cap: out_buffer.len(),
            required,
        });
    }

    let (body, tag_out) = out_buffer[..required].split_at_mut(plain_len);
    body.copy_from_slice(plaintext);
    let tag = encrypt_in_place_with_aad(key, nonce, b"", body)?;
    tag_out.copy_from_slice(&tag);
    Ok(required)
}

/// Zero-copy in-buffer decryption: copies `ciphertext` body into `out_buffer` and decrypts in-place
/// without allocating any intermediate `Vec<u8>`.
/// Returns the number of plaintext bytes written.
pub fn decrypt_zero_copy(
    key: &[u8; KEY_SIZE],
    nonce: &[u8; NONCE_SIZE],
    ciphertext: &[u8],
    out_buffer: &mut [u8],
) -> Result<usize, CryptoError> {
    if ciphertext.len() < TAG_SIZE {
        return Err(CryptoError::DecryptionFailed);
    }
    let expected_len = ciphertext.len() - TAG_SIZE;
    if out_buffer.len() < expected_len {
        return Err(CryptoError::BufferTooSmall {
            cap: out_buffer.len(),
            required: expected_len,
        });
    }

    let (cipher_body, tag_slice) = ciphertext.split_at(expected_len);
    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(tag_slice);

    let out_body = &mut out_buffer[..expected_len];
    out_body.copy_from_slice(cipher_body);
    if let Err(e) = decrypt_in_place_with_aad(key, nonce, b"", out_body, &tag) {
        out_body.fill(0);
        return Err(e);
    }
    Ok(expected_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_e2ee_encryption_and_decryption() {
        let pin = "982341";
        let key = derive_key(pin, None).expect("derive key");
        let nonce = generate_nonce();
        let message = b"Hello, MuClip Cross-Device P2P Clipboard!";

        let encrypted = encrypt_payload(&key, &nonce, message).expect("encrypt");
        assert_eq!(encrypted.len(), message.len() + TAG_SIZE);

        let decrypted = decrypt_payload(&key, &nonce, &encrypted).expect("decrypt");
        assert_eq!(decrypted, message);

        // Verification of tampering: modify 1 byte in ciphertext
        let mut tampered = encrypted.clone();
        tampered[0] ^= 0xFF;
        assert!(decrypt_payload(&key, &nonce, &tampered).is_err());
    }

    #[test]
    fn test_zero_copy_crypto() {
        let key = derive_key("my-secret-pin-888", None).unwrap();
        let nonce = generate_nonce();
        let plain = b"High performance zero-copy memory transfer test";

        let mut out_encrypted = vec![0u8; 256];
        let enc_len = encrypt_zero_copy(&key, &nonce, plain, &mut out_encrypted).unwrap();
        assert_eq!(enc_len, plain.len() + TAG_SIZE);

        let mut out_decrypted = vec![0u8; 256];
        let dec_len =
            decrypt_zero_copy(&key, &nonce, &out_encrypted[..enc_len], &mut out_decrypted).unwrap();
        assert_eq!(&out_decrypted[..dec_len], plain);

        // Tampered ciphertext must fail and zero out the output buffer slice
        let mut tampered = out_encrypted[..enc_len].to_vec();
        tampered[0] ^= 0x55;
        assert!(decrypt_zero_copy(&key, &nonce, &tampered, &mut out_decrypted).is_err());
        assert!(out_decrypted[..plain.len()].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_content_hashing() {
        let hash1 = compute_sha256_hex(b"test clipboard 1");
        let hash2 = compute_sha256_hex(b"test clipboard 1");
        let hash3 = compute_sha256_hex(b"test clipboard 2");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_wrong_pin_cannot_decrypt() {
        let key_a = derive_key("123456", None).expect("derive key a");
        let key_b = derive_key("654321", None).expect("derive key b");
        let nonce = generate_nonce();

        let ct = encrypt_payload(&key_a, &nonce, b"secret clipboard").expect("encrypt");
        assert!(
            decrypt_payload(&key_b, &nonce, &ct).is_err(),
            "PIN 不同必须解密失败，而不是解出乱码"
        );
    }

    #[test]
    fn test_key_derivation_is_deterministic_and_salt_sensitive() {
        let k1 = derive_key("123456", None).unwrap();
        let k2 = derive_key("123456", None).unwrap();
        assert_eq!(
            k1, k2,
            "HKDF 必须是确定性的，否则双方永远无法协商出同一把密钥"
        );

        let k3 = derive_key("123456", Some(b"another-salt-value")).unwrap();
        assert_ne!(k1, k3, "不同 salt 必须派生出不同密钥");
    }

    #[test]
    fn test_nonce_uniqueness() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(
                seen.insert(generate_nonce()),
                "nonce 重复会直接导致密钥流复用"
            );
        }
        assert_eq!(seen.len(), 10_000);
    }

    #[test]
    fn test_nonce_reuse_produces_identical_ciphertext() {
        let key = derive_key("112233", None).unwrap();
        let nonce = generate_nonce();

        let a1 = encrypt_payload(&key, &nonce, b"AAAA").unwrap();
        let a2 = encrypt_payload(&key, &nonce, b"AAAA").unwrap();
        assert_eq!(a1, a2, "同 (key, nonce) 下相同明文必然产生相同密文");

        let b = encrypt_payload(&key, &nonce, b"BBBB").unwrap();
        assert_ne!(a1, b, "不同明文在同 nonce 下密文不同，但可被异或推导密钥流");
    }

    #[test]
    fn test_empty_and_large_payload_roundtrip() {
        let key = derive_key("777777", None).unwrap();
        let nonce = generate_nonce();

        let empty_ct = encrypt_payload(&key, &nonce, b"").expect("encrypt empty");
        assert_eq!(
            empty_ct.len(),
            TAG_SIZE,
            "空明文也必须带 16 字节 Poly1305 认证标签"
        );
        assert_eq!(
            decrypt_payload(&key, &nonce, &empty_ct).unwrap(),
            Vec::<u8>::new()
        );

        let big = vec![0xABu8; 1024 * 1024];
        let big_ct = encrypt_payload(&key, &nonce, &big).expect("encrypt 1MB");
        assert_eq!(big_ct.len(), big.len() + TAG_SIZE);
        assert_eq!(decrypt_payload(&key, &nonce, &big_ct).unwrap(), big);
    }

    #[test]
    fn test_truncated_and_tag_tampering_rejected() {
        let key = derive_key("246810", None).unwrap();
        let nonce = generate_nonce();
        let ct = encrypt_payload(&key, &nonce, b"tamper me").unwrap();

        assert!(
            decrypt_payload(&key, &nonce, &ct[..ct.len() - 1]).is_err(),
            "截断密文必须被拒绝"
        );

        let mut tag_flipped = ct.clone();
        let last = tag_flipped.len() - 1;
        tag_flipped[last] ^= 0x01;
        assert!(
            decrypt_payload(&key, &nonce, &tag_flipped).is_err(),
            "翻转认证标签 1 个比特也必须被拒绝"
        );
    }

    #[test]
    fn test_zero_copy_rejects_undersized_buffer() {
        let key = derive_key("135790", None).unwrap();
        let nonce = generate_nonce();
        let mut too_small = vec![0u8; 8];

        assert!(
            matches!(
                encrypt_zero_copy(&key, &nonce, b"needs much more room", &mut too_small),
                Err(CryptoError::BufferTooSmall { .. })
            ),
            "缓冲区不足必须返回明确错误，绝不能越界写"
        );
    }

    #[test]
    fn test_in_place_crypto_roundtrip() {
        let key = derive_key("inplace-pin-999", None).unwrap();
        let nonce = generate_nonce();
        let original_data = b"Testing in-place 128KB zero-allocation buffer encryption!".to_vec();

        let mut buffer = original_data.clone();
        let tag = encrypt_in_place(&key, &nonce, &mut buffer).expect("in-place encrypt");

        // Verify buffer is actually encrypted (not equal to original)
        assert_ne!(buffer, original_data);
        assert_eq!(buffer.len(), original_data.len());

        // Verify in-place decrypt restores original plaintext
        decrypt_in_place(&key, &nonce, &mut buffer, &tag).expect("in-place decrypt");
        assert_eq!(buffer, original_data);

        // Tampering tag should fail
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert!(decrypt_in_place(&key, &nonce, &mut buffer, &bad_tag).is_err());
    }

    #[test]
    fn test_chunk_counter_nonce_and_in_place_stream() {
        let key = derive_key("stream-counter-test", None).unwrap();
        let salt = [0xAA; 16];

        for counter in 0..10u64 {
            let nonce = derive_chunk_nonce(&salt, counter);
            let (parsed_salt, parsed_counter) = parse_chunk_nonce(&nonce);
            assert_eq!(parsed_salt, salt);
            assert_eq!(parsed_counter, counter);

            let original = format!("chunk_data_{}", counter).into_bytes();
            let mut buf = original.clone();
            let tag = encrypt_in_place(&key, &nonce, &mut buf).unwrap();
            assert_ne!(buf, original);

            decrypt_in_place(&key, &nonce, &mut buf, &tag).unwrap();
            assert_eq!(buf, original);
        }
    }

    #[test]
    fn test_xchacha20_continuous_stream() {
        let key = derive_key("stream-xchacha-speed-test", None).unwrap();
        let nonce = generate_nonce();
        let original_data =
            b"Large 1MB continuous stream block through XChaCha20 dedicated pipe".repeat(100);

        let mut cipher_enc = create_xchacha20_stream(&key, &nonce);
        let mut cipher_dec = create_xchacha20_stream(&key, &nonce);

        let mut encrypted = original_data.clone();
        cipher_enc.apply_keystream(&mut encrypted);
        assert_ne!(encrypted, original_data);

        let mut decrypted = encrypted.clone();
        cipher_dec.apply_keystream(&mut decrypted);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_ecdh_key_exchange_with_pin_auth() {
        let pin = "839201";
        let challenge = generate_challenge_nonce();
        let protocol_ver = 1u8;

        // Alice (initiator)
        let alice_pin_auth = derive_pin_auth_key(pin).unwrap();
        let alice_ecdh = KeyExchangeSession::new();
        let alice_tag = compute_ecdh_auth_tag(
            &alice_pin_auth,
            &alice_ecdh.public_key,
            &[0u8; 32],
            "initiator",
            &challenge,
            protocol_ver,
        );

        // Bob (responder) verifies Alice's auth tag with PIN
        let bob_pin_auth = derive_pin_auth_key(pin).unwrap();
        let expected_alice_tag = compute_ecdh_auth_tag(
            &bob_pin_auth,
            &alice_ecdh.public_key,
            &[0u8; 32],
            "initiator",
            &challenge,
            protocol_ver,
        );
        assert_eq!(alice_tag, expected_alice_tag);

        // Wrong PIN test
        let wrong_pin_auth = derive_pin_auth_key("000000").unwrap();
        let wrong_tag = compute_ecdh_auth_tag(
            &wrong_pin_auth,
            &alice_ecdh.public_key,
            &[0u8; 32],
            "initiator",
            &challenge,
            protocol_ver,
        );
        assert_ne!(alice_tag, wrong_tag);

        // Bob creates his ECDH session & computes shared secret
        let bob_ecdh = KeyExchangeSession::new();
        let bob_shared_secret = bob_ecdh.compute_shared_secret(&alice_ecdh.public_key);
        let bob_long_term_key = derive_long_term_key(
            &bob_shared_secret,
            &bob_pin_auth,
            &challenge,
            &alice_ecdh.public_key,
            &bob_ecdh.public_key,
            protocol_ver,
        )
        .unwrap();

        let bob_tag = compute_ecdh_auth_tag(
            &bob_long_term_key,
            &alice_ecdh.public_key,
            &bob_ecdh.public_key,
            "responder",
            &challenge,
            protocol_ver,
        );

        // Alice computes shared secret & derives long-term key
        let alice_shared_secret = alice_ecdh.compute_shared_secret(&bob_ecdh.public_key);
        let alice_long_term_key = derive_long_term_key(
            &alice_shared_secret,
            &alice_pin_auth,
            &challenge,
            &alice_ecdh.public_key,
            &bob_ecdh.public_key,
            protocol_ver,
        )
        .unwrap();

        // High-entropy 256-bit long term keys MUST be strictly identical!
        assert_eq!(alice_long_term_key, bob_long_term_key);

        // Alice verifies Bob's response tag (which binds both public keys and shared secret)
        let expected_bob_tag = compute_ecdh_auth_tag(
            &alice_long_term_key,
            &alice_ecdh.public_key,
            &bob_ecdh.public_key,
            "responder",
            &challenge,
            protocol_ver,
        );
        assert_eq!(bob_tag, expected_bob_tag);

        // Hex serialization and direct session derivation
        let hex_key = bytes_to_hex(&alice_long_term_key);
        assert_eq!(hex_key.len(), 64);
        let direct_key = derive_key(&hex_key, None).unwrap();
        assert_eq!(direct_key, alice_long_term_key);

        // Subkey domain separation & bulk_key derivation via HKDF
        let (k_ctrl, k_bulk) = derive_session_subkeys(&alice_long_term_key).unwrap();
        assert_ne!(k_ctrl, alice_long_term_key);
        assert_ne!(k_bulk, alice_long_term_key);
        assert_ne!(k_ctrl, k_bulk);

        let stream_salt = [0x5Au8; 16];
        let alice_bulk_file = derive_bulk_key(&alice_long_term_key, &stream_salt);
        let bob_bulk_file = derive_bulk_key(&bob_long_term_key, &stream_salt);
        assert_eq!(alice_bulk_file, bob_bulk_file);
        assert_ne!(alice_bulk_file, alice_long_term_key);

        // Standard SPAKE2 (Ed25519Group) single-use session per attempt test
        let challenge_1 = generate_challenge_nonce();
        let alice_spake2_1 = Spake2InitiatorSession::new(pin, &challenge_1);
        let msg_a_1 = alice_spake2_1.public_message;
        // Attempt 1 with wrong PIN -> shared secrets must NOT match, session 1 is consumed
        let (bob_wrong_msg, bob_wrong_shared) =
            spake2_responder_exchange("000000", &challenge_1, &msg_a_1).unwrap();
        let alice_attempt1_shared = alice_spake2_1.finish(&bob_wrong_msg).unwrap();
        assert_ne!(alice_attempt1_shared, bob_wrong_shared);

        // Attempt 2 starts a brand-new SPAKE2 session with a fresh challenge and fresh ephemeral scalar
        let challenge_2 = generate_challenge_nonce();
        assert_ne!(challenge_1, challenge_2);
        let alice_spake2_2 = Spake2InitiatorSession::new(pin, &challenge_2);
        assert_ne!(msg_a_1, alice_spake2_2.public_message);
        let (bob_ok_msg, bob_ok_shared) =
            spake2_responder_exchange(pin, &challenge_2, &alice_spake2_2.public_message).unwrap();
        let alice_attempt2_shared = alice_spake2_2.finish(&bob_ok_msg).unwrap();
        assert_eq!(alice_attempt2_shared, bob_ok_shared);
    }

    #[test]
    fn test_pfs_session_key_derivation_and_auth() {
        let long_term_key = generate_device_long_term_key();
        let mut challenge = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut challenge);

        // Client initiates ephemeral ECDH
        let client_ex = KeyExchangeSession::new();
        let client_pk = client_ex.public_key;
        let client_auth = compute_session_auth_tag(
            &long_term_key,
            "client-node",
            "server-node",
            &client_pk,
            None,
            "initiator",
            &challenge,
        );

        // Server verifies client auth
        let expected_client_auth = compute_session_auth_tag(
            &long_term_key,
            "client-node",
            "server-node",
            &client_pk,
            None,
            "initiator",
            &challenge,
        );
        assert_eq!(client_auth, expected_client_auth);

        // Server responds with its ephemeral ECDH
        let server_ex = KeyExchangeSession::new();
        let server_pk = server_ex.public_key;
        let server_auth = compute_session_auth_tag(
            &long_term_key,
            "client-node",
            "server-node",
            &server_pk,
            Some(&client_pk),
            "responder",
            &challenge,
        );

        // Client verifies server auth
        let expected_server_auth = compute_session_auth_tag(
            &long_term_key,
            "client-node",
            "server-node",
            &server_pk,
            Some(&client_pk),
            "responder",
            &challenge,
        );
        assert_eq!(server_auth, expected_server_auth);

        // Both compute shared secret
        let client_shared = client_ex.compute_shared_secret(&server_pk);
        let server_shared = server_ex.compute_shared_secret(&client_pk);
        assert_eq!(client_shared, server_shared);

        // Both derive PFS session key
        let client_session_key = derive_pfs_session_key(&client_shared, &long_term_key, &challenge);
        let server_session_key = derive_pfs_session_key(&server_shared, &long_term_key, &challenge);
        assert_eq!(client_session_key, server_session_key);

        // Key is strictly isolated from long_term_key
        assert_ne!(*client_session_key, long_term_key);
    }
}

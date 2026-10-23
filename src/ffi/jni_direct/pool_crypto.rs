use jni::JNIEnv;
use jni::objects::{JByteArray, JClass, JLongArray, JObject, JString, ReleaseMode};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use std::slice;

use crate::pool::global_buffer_pool;
use crate::sync::crypto::{
    CHUNK_AAD_SIZE, FILE_ID_AAD_LEN, KEY_SIZE, NONCE_SIZE, TAG_SIZE, build_chunk_aad,
    decrypt_in_place_with_aad, decrypt_zero_copy, derive_chunk_nonce, derive_key,
    encrypt_in_place_with_aad, encrypt_zero_copy,
};

// -----------------------------------------------------------------------------
// Buffer Pool Leases
// -----------------------------------------------------------------------------

/// Rents an off-heap direct buffer of `min_capacity` bytes.
/// Writes `[lease_id, capacity]` into `out_info` (jlongArray of size >= 2).
/// Returns a Java `DirectByteBuffer` wrapping the off-heap pointer with zero JVM allocation.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAcquireBuffer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    min_capacity: jlong,
    out_info: JLongArray<'local>,
) -> JObject<'local> {
    let pool = global_buffer_pool();
    let req_cap = (min_capacity as usize).max(4096);

    match pool.acquire(req_cap) {
        Some((id, ptr, cap)) => {
            let info = [id as jlong, cap as jlong, ptr as usize as jlong];
            if env.set_long_array_region(&out_info, 0, &info).is_err() {
                pool.release(id);
                return JObject::null();
            }

            match unsafe { env.new_direct_byte_buffer(ptr, cap) } {
                Ok(buf) => buf.into(),
                Err(_) => {
                    pool.release(id);
                    JObject::null()
                }
            }
        }
        None => JObject::null(),
    }
}

/// Releases a previously rented off-heap direct buffer back to the native pool.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeReleaseBuffer(
    _env: JNIEnv,
    _class: JClass,
    lease_id: jlong,
) -> jboolean {
    let pool = global_buffer_pool();
    if pool.release(lease_id as u64) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// Wraps an existing raw off-heap pointer into a Java `DirectByteBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeWrapDirectBuffer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    raw_ptr: jlong,
    capacity: jlong,
) -> JObject<'local> {
    if raw_ptr == 0 || capacity <= 0 {
        return JObject::null();
    }
    match unsafe { env.new_direct_byte_buffer(raw_ptr as *mut u8, capacity as usize) } {
        Ok(buf) => buf.into(),
        Err(_) => JObject::null(),
    }
}

// -----------------------------------------------------------------------------
// Zero-Copy & In-Place Crypto Operations (XChaCha20-Poly1305)
// -----------------------------------------------------------------------------

/// Derives a 32-byte session key from PIN/password and writes it into `out_key_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeriveKey(
    mut env: JNIEnv,
    _class: JClass,
    pin: JString,
    out_key_ptr: jlong,
) -> jint {
    if out_key_ptr == 0 {
        return -1;
    }
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    match derive_key(&pin_str, None) {
        Ok(key) => {
            let out_slice =
                unsafe { slice::from_raw_parts_mut(out_key_ptr as usize as *mut u8, KEY_SIZE) };
            out_slice.copy_from_slice(&key);
            0
        }
        Err(_) => -1,
    }
}

/// Derives a unique 24-byte XChaCha20 chunk nonce from `file_nonce` (16 bytes) and `chunk_index`
/// directly into the pre-allocated `out_nonce` (24 bytes) with zero heap allocation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeriveChunkNonce<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    file_nonce: JByteArray<'local>,
    chunk_index: jlong,
    out_nonce: JByteArray<'local>,
) -> jint {
    let mut salt_i8 = [0i8; 16];
    if env
        .get_byte_array_region(&file_nonce, 0, &mut salt_i8)
        .is_err()
    {
        return -1;
    }
    let salt_u8: [u8; 16] = unsafe { std::mem::transmute(salt_i8) };
    let derived_u8 = derive_chunk_nonce(&salt_u8, chunk_index as u64);
    let derived_i8: [i8; NONCE_SIZE] = unsafe { std::mem::transmute(derived_u8) };
    if env
        .set_byte_array_region(&out_nonce, 0, &derived_i8)
        .is_err()
    {
        return -1;
    }
    0
}

/// Builds the fixed 57-byte binary AAD structure directly into `out_aad` with zero heap allocation.
/// Returns `0` on success, `-1` on error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeBuildChunkAad<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    file_id_bytes: JByteArray<'local>,
    chunk_index: jlong,
    chunk_length: jint,
    total_file_size: jlong,
    out_aad: JByteArray<'local>,
) -> jint {
    let arr_len = env.get_array_length(&file_id_bytes).unwrap_or(0).max(0) as usize;
    let copy_len = arr_len.min(FILE_ID_AAD_LEN);
    let mut fid_i8 = [0i8; FILE_ID_AAD_LEN];
    if copy_len > 0 {
        if env
            .get_byte_array_region(&file_id_bytes, 0, &mut fid_i8[..copy_len])
            .is_err()
        {
            return -1;
        }
    }
    let fid_u8: [u8; FILE_ID_AAD_LEN] = unsafe { std::mem::transmute(fid_i8) };
    let mut aad_u8 = [0u8; CHUNK_AAD_SIZE];
    build_chunk_aad(
        1,
        &fid_u8[..copy_len],
        chunk_index as u64,
        chunk_length as u32,
        total_file_size as u64,
        &mut aad_u8,
    );
    let aad_i8: [i8; CHUNK_AAD_SIZE] = unsafe { std::mem::transmute(aad_u8) };
    if env.set_byte_array_region(&out_aad, 0, &aad_i8).is_err() {
        return -1;
    }
    0
}

/// In-place XChaCha20-Poly1305 AEAD encryption on a pre-allocated Java `ByteArray`.
/// Encrypts `buffer[0..plaintext_length]` in-place and appends the 16-byte Poly1305 tag
/// at `buffer[plaintext_length..plaintext_length + 16]`.
/// Returns `plaintext_length + 16` on success, or `-1` on error.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeEncryptInPlace<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    buffer: JByteArray<'local>,
    plaintext_length: jint,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
) -> jint {
    if plaintext_length < 0 {
        return -1;
    }
    let plain_len = plaintext_length as usize;

    let mut key_i8 = [0i8; KEY_SIZE];
    if env.get_byte_array_region(&key, 0, &mut key_i8).is_err() {
        return -1;
    }
    let key_u8: [u8; KEY_SIZE] = unsafe { std::mem::transmute(key_i8) };

    let mut nonce_i8 = [0i8; NONCE_SIZE];
    if env.get_byte_array_region(&nonce, 0, &mut nonce_i8).is_err() {
        return -1;
    }
    let nonce_u8: [u8; NONCE_SIZE] = unsafe { std::mem::transmute(nonce_i8) };

    let aad_len = match env.get_array_length(&aad) {
        Ok(l) if l >= 0 && (l as usize) <= 256 => l as usize,
        _ => return -1,
    };
    let mut aad_i8 = [0i8; 256];
    if aad_len > 0 {
        if env
            .get_byte_array_region(&aad, 0, &mut aad_i8[..aad_len])
            .is_err()
        {
            return -1;
        }
    }
    let aad_u8: [u8; 256] = unsafe { std::mem::transmute(aad_i8) };

    let total_out_len = plain_len + TAG_SIZE;
    let mut critical =
        match unsafe { env.get_array_elements_critical(&buffer, ReleaseMode::CopyBack) } {
            Ok(c) => c,
            Err(_) => return -1,
        };
    if critical.len() < total_out_len {
        return -1;
    }

    let buf_u8: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(critical.as_mut_ptr() as *mut u8, total_out_len) };

    match encrypt_in_place_with_aad(
        &key_u8,
        &nonce_u8,
        &aad_u8[..aad_len],
        &mut buf_u8[..plain_len],
    ) {
        Ok(tag) => {
            buf_u8[plain_len..total_out_len].copy_from_slice(&tag);
            total_out_len as jint
        }
        Err(_) => -1,
    }
}

/// In-place XChaCha20-Poly1305 AEAD decryption on a pre-allocated Java `ByteArray`.
/// Verifies the 16-byte Poly1305 tag at `buffer[ciphertext_length - 16..ciphertext_length]`
/// and decrypts `buffer[0..ciphertext_length - 16]` in-place.
/// Returns `plaintext_length` (`ciphertext_length - 16`) on success, or `-1` if authentication fails.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDecryptInPlace<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    key: JByteArray<'local>,
    buffer: JByteArray<'local>,
    ciphertext_length: jint,
    nonce: JByteArray<'local>,
    aad: JByteArray<'local>,
) -> jint {
    if (ciphertext_length as usize) < TAG_SIZE {
        return -1;
    }
    let cipher_len = ciphertext_length as usize;
    let plain_len = cipher_len - TAG_SIZE;

    let mut key_i8 = [0i8; KEY_SIZE];
    if env.get_byte_array_region(&key, 0, &mut key_i8).is_err() {
        return -1;
    }
    let key_u8: [u8; KEY_SIZE] = unsafe { std::mem::transmute(key_i8) };

    let mut nonce_i8 = [0i8; NONCE_SIZE];
    if env.get_byte_array_region(&nonce, 0, &mut nonce_i8).is_err() {
        return -1;
    }
    let nonce_u8: [u8; NONCE_SIZE] = unsafe { std::mem::transmute(nonce_i8) };

    let aad_len = match env.get_array_length(&aad) {
        Ok(l) if l >= 0 && (l as usize) <= 256 => l as usize,
        _ => return -1,
    };
    let mut aad_i8 = [0i8; 256];
    if aad_len > 0 {
        if env
            .get_byte_array_region(&aad, 0, &mut aad_i8[..aad_len])
            .is_err()
        {
            return -1;
        }
    }
    let aad_u8: [u8; 256] = unsafe { std::mem::transmute(aad_i8) };

    let mut critical =
        match unsafe { env.get_array_elements_critical(&buffer, ReleaseMode::CopyBack) } {
            Ok(c) => c,
            Err(_) => return -1,
        };
    if critical.len() < cipher_len {
        return -1;
    }

    let buf_u8: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(critical.as_mut_ptr() as *mut u8, cipher_len) };

    let mut tag = [0u8; TAG_SIZE];
    tag.copy_from_slice(&buf_u8[plain_len..cipher_len]);

    match decrypt_in_place_with_aad(
        &key_u8,
        &nonce_u8,
        &aad_u8[..aad_len],
        &mut buf_u8[..plain_len],
        &tag,
    ) {
        Ok(()) => plain_len as jint,
        Err(_) => {
            buf_u8[..plain_len].fill(0);
            -1
        }
    }
}

/// Zero-copy XChaCha20-Poly1305 encryption on off-heap `DirectByteBuffer` pointers.
/// Supports both separate input/output buffers and true in-place encryption (`in_ptr == out_ptr`).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeEncryptZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    key_ptr: jlong,
    nonce_ptr: jlong,
    in_ptr: jlong,
    in_len: jint,
    out_ptr: jlong,
    out_cap: jint,
) -> jint {
    if key_ptr == 0 || nonce_ptr == 0 || in_ptr == 0 || in_len <= 0 || out_ptr == 0 || out_cap <= 0
    {
        return -1;
    }

    let plain_len = in_len as usize;
    let required = plain_len + TAG_SIZE;
    if (out_cap as usize) < required {
        return -1;
    }

    let key_slice = unsafe { slice::from_raw_parts(key_ptr as usize as *const u8, KEY_SIZE) };
    let nonce_slice = unsafe { slice::from_raw_parts(nonce_ptr as usize as *const u8, NONCE_SIZE) };

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(key_slice);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(nonce_slice);

    if in_ptr == out_ptr {
        let buf_slice = unsafe { slice::from_raw_parts_mut(out_ptr as usize as *mut u8, required) };
        let (body, tag_out) = buf_slice.split_at_mut(plain_len);
        match encrypt_in_place_with_aad(&key, &nonce, b"", body) {
            Ok(tag) => {
                tag_out.copy_from_slice(&tag);
                required as jint
            }
            Err(_) => -1,
        }
    } else {
        let in_slice = unsafe { slice::from_raw_parts(in_ptr as usize as *const u8, plain_len) };
        let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_ptr, out_cap) }) else {
            return -1;
        };
        match encrypt_zero_copy(&key, &nonce, in_slice, out_slice) {
            Ok(written) => written as jint,
            Err(_) => -1,
        }
    }
}

/// Zero-copy XChaCha20-Poly1305 decryption on off-heap `DirectByteBuffer` pointers.
/// Supports both separate input/output buffers and true in-place decryption (`in_ptr == out_ptr`).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDecryptZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    key_ptr: jlong,
    nonce_ptr: jlong,
    in_ptr: jlong,
    in_len: jint,
    out_ptr: jlong,
    out_cap: jint,
) -> jint {
    if key_ptr == 0 || nonce_ptr == 0 || in_ptr == 0 || in_len <= 0 || out_ptr == 0 || out_cap <= 0
    {
        return -1;
    }

    let cipher_len = in_len as usize;
    if cipher_len < TAG_SIZE {
        return -1;
    }
    let plain_len = cipher_len - TAG_SIZE;
    if (out_cap as usize) < plain_len {
        return -1;
    }

    let key_slice = unsafe { slice::from_raw_parts(key_ptr as usize as *const u8, KEY_SIZE) };
    let nonce_slice = unsafe { slice::from_raw_parts(nonce_ptr as usize as *const u8, NONCE_SIZE) };

    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(key_slice);

    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(nonce_slice);

    if in_ptr == out_ptr && (out_cap as usize) >= cipher_len {
        let buf_slice =
            unsafe { slice::from_raw_parts_mut(out_ptr as usize as *mut u8, cipher_len) };
        let (body, tag_slice) = buf_slice.split_at_mut(plain_len);
        let mut tag = [0u8; TAG_SIZE];
        tag.copy_from_slice(tag_slice);
        match decrypt_in_place_with_aad(&key, &nonce, b"", body, &tag) {
            Ok(()) => plain_len as jint,
            Err(_) => {
                body.fill(0);
                -1
            }
        }
    } else if in_ptr != out_ptr {
        let in_slice = unsafe { slice::from_raw_parts(in_ptr as usize as *const u8, cipher_len) };
        let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_ptr, out_cap) }) else {
            return -1;
        };
        match decrypt_zero_copy(&key, &nonce, in_slice, out_slice) {
            Ok(written) => written as jint,
            Err(_) => -1,
        }
    } else {
        -1
    }
}

use crate::content::analyze_content;
use crate::ffi::jni_direct::binary::{
    encode_content_analysis, encode_history_items, encode_peers, encode_phrase_items,
    encode_string_list,
};
use crate::pool::global_buffer_pool;
use jni::sys::jint;
use std::ffi::c_char;

use super::c_char_to_str;
use super::core::{MuClipCoreEngine, MuClipCoreHandle};
use super::sync::MuClipSyncHandle;

/// Rents an off-heap native buffer of at least `min_capacity` bytes.
/// Writes the raw buffer pointer to `out_ptr` and the allocated capacity to `out_cap`.
/// Returns the `lease_id` (a positive u64) on success, or 0 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_pool_acquire(
    min_capacity: usize,
    out_ptr: *mut *mut u8,
    out_cap: *mut usize,
) -> u64 {
    if out_ptr.is_null() || out_cap.is_null() {
        return 0;
    }
    let pool = global_buffer_pool();
    if let Some((id, ptr, cap)) = pool.acquire(min_capacity) {
        unsafe {
            *out_ptr = ptr;
            *out_cap = cap;
        }
        id
    } else {
        0
    }
}

/// Releases a previously rented buffer back to the native pool using its `lease_id`.
/// Returns 0 on success, or -1 if the lease was not found.
#[unsafe(no_mangle)]
pub extern "C" fn muclip_pool_release(lease_id: u64) -> i32 {
    let pool = global_buffer_pool();
    if pool.release(lease_id) { 0 } else { -1 }
}

/// Clears all free buffers currently cached in the native buffer pool.
#[unsafe(no_mangle)]
pub extern "C" fn muclip_pool_clear() {
    global_buffer_pool().clear();
}

/// Encodes binary payload directly into a leased native buffer from `global_buffer_pool()`
/// with zero intermediate `Vec<u8>` allocation. Automatically resizes if the payload exceeds 64KB.
fn write_binary_to_pooled_buffer<F>(mut encoder: F) -> Option<(u64, *const u8, usize)>
where
    F: FnMut(&mut [u8]) -> jint,
{
    let pool = global_buffer_pool();
    let (id, ptr, cap) = pool.acquire(65536)?;
    let slice = unsafe { std::slice::from_raw_parts_mut(ptr, cap) };
    let res = encoder(slice);
    if res >= 0 {
        return Some((id, ptr as *const u8, res as usize));
    }
    pool.release(id);
    if res == -1 {
        return None;
    }
    // res < -1 表示所需的字节数；i32::MIN 取负会溢出，显式兜底
    let required = match res.checked_neg() {
        Some(n) if n > 0 => n as usize,
        _ => return None,
    };
    let (id2, ptr2, cap2) = pool.acquire(required)?;
    let slice2 = unsafe { std::slice::from_raw_parts_mut(ptr2, cap2) };
    let res2 = encoder(slice2);
    if res2 >= 0 {
        Some((id2, ptr2 as *const u8, res2 as usize))
    } else {
        pool.release(id2);
        None
    }
}

/// Queries recent history items and writes Little-Endian binary wire format directly into a leased memory pool buffer.
/// Sets `out_ptr` to the buffer address and `out_len` to the byte count.
/// Returns `lease_id` (>0). Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_history_pooled(
    handle: *mut MuClipCoreHandle,
    limit: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    unsafe { muclip_core_query_history_page_pooled(handle, 0, limit, out_ptr, out_len) }
}

/// Queries history items with pagination (`offset`, `limit`) and writes Little-Endian binary wire format
/// directly into a leased memory pool buffer. Serves from hot memory cache when covered, otherwise queries SQLite.
/// Sets `out_ptr` to the buffer address and `out_len` to the byte count.
/// Returns `lease_id` (>0). Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_history_page_pooled(
    handle: *mut MuClipCoreHandle,
    offset: usize,
    limit: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let cached = engine.cache.get_items();
        // SECURITY: offset/limit 来自 FFI 调用方（C# / Kotlin），完全不可信。
        // `offset + limit` 在 `offset = usize::MAX` 时会 wrap（release 下静默回绕为 0），
        // 使下方的边界判断通过，随后切片索引 panic。本 crate 的 release profile 是
        // `panic = "abort"`，一次 panic 会直接杀掉宿主进程（桌面端闪退 / Android 崩溃）。
        let cache_end = offset.checked_add(limit).filter(|&end| end <= cached.len());
        if let Some(end) = cache_end {
            let slice = &cached[offset..end];
            if let Some((id, ptr, len)) =
                write_binary_to_pooled_buffer(|buf| encode_history_items(slice, buf))
            {
                unsafe {
                    *out_ptr = ptr;
                    *out_len = len;
                }
                return id;
            }
            return 0;
        }

        let items = match engine.db.query_history_page(offset, limit) {
            Ok(res) => res,
            Err(_) => cached.iter().skip(offset).take(limit).cloned().collect(),
        };
        if let Some((id, ptr, len)) =
            write_binary_to_pooled_buffer(|buf| encode_history_items(&items, buf))
        {
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            return id;
        }
    }
    0
}

/// Gets top hot cached items writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_get_cached_items_pooled(
    handle: *mut MuClipCoreHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.cache.get_items();
        if let Some((id, ptr, len)) =
            write_binary_to_pooled_buffer(|buf| encode_history_items(items, buf))
        {
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            return id;
        }
    }
    0
}

/// Searches history items writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_search_history_pooled(
    handle: *mut MuClipCoreHandle,
    query: *const c_char,
    limit: usize,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let q = match unsafe { c_char_to_str(query) } {
        Some(text) => text,
        None => return 0,
    };
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.search_history(q, limit).unwrap_or_default();
        if let Some((id, ptr, len)) =
            write_binary_to_pooled_buffer(|buf| encode_history_items(&items, buf))
        {
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            return id;
        }
    }
    0
}

/// Analyzes content and writes Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_analyze_content_pooled(
    text: *const c_char,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if text.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let s = match unsafe { c_char_to_str(text) } {
        Some(val) => val,
        None => return 0,
    };
    let analysis = analyze_content(s);
    if let Some((id, ptr, len)) =
        write_binary_to_pooled_buffer(|buf| encode_content_analysis(&analysis, buf))
    {
        unsafe {
            *out_ptr = ptr;
            *out_len = len;
        }
        return id;
    }
    0
}

/// Queries all phrases writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_phrases_pooled(
    handle: *mut MuClipCoreHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.query_phrases().unwrap_or_default();
        if let Some((id, ptr, len)) =
            write_binary_to_pooled_buffer(|buf| encode_phrase_items(&items, buf))
        {
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            return id;
        }
    }
    0
}

/// Searches phrases writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_search_phrases_pooled(
    handle: *mut MuClipCoreHandle,
    query: *const c_char,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let q = match unsafe { c_char_to_str(query) } {
        Some(text) => text,
        None => return 0,
    };
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.search_phrases(q).unwrap_or_default();
        if let Some((id, ptr, len)) =
            write_binary_to_pooled_buffer(|buf| encode_phrase_items(&items, buf))
        {
            unsafe {
                *out_ptr = ptr;
                *out_len = len;
            }
            return id;
        }
    }
    0
}

/// Adds a history record from a leased or raw byte buffer (UTF-8 bytes, not necessarily null-terminated).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_add_history_buffer(
    handle: *mut MuClipCoreHandle,
    data_ptr: *const u8,
    data_len: usize,
) -> i64 {
    if handle.is_null() || data_ptr.is_null() || data_len == 0 {
        return -1;
    }
    let slice = unsafe { std::slice::from_raw_parts(data_ptr, data_len) };
    let text = match std::str::from_utf8(slice) {
        Ok(t) => t,
        Err(_) => return -1,
    };
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        cache.add_item(text.to_string(), Some(db));
        if let Some(first) = cache.get_items().first() {
            return first.id;
        }
    }
    -1
}

/// Gets active discovered and manual peers writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_active_peers_pooled(
    handle: *mut MuClipSyncHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_active_peers();
    if let Some((id, ptr, len)) = write_binary_to_pooled_buffer(|buf| encode_peers(&peers, buf)) {
        unsafe {
            *out_ptr = ptr;
            *out_len = len;
        }
        return id;
    }
    0
}

/// Gets all known peers (including offline and manual port-mapped nodes) writing Little-Endian binary wire format
/// into a leased memory pool buffer. Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_all_peers_pooled(
    handle: *mut MuClipSyncHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_all_peers();
    if let Some((id, ptr, len)) = write_binary_to_pooled_buffer(|buf| encode_peers(&peers, buf)) {
        unsafe {
            *out_ptr = ptr;
            *out_len = len;
        }
        return id;
    }
    0
}

/// Gets configured manual peer endpoints writing Little-Endian binary wire format into a leased memory pool buffer.
/// Returns `lease_id`. Caller must release via `muclip_pool_release(lease_id)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_manual_peers_pooled(
    handle: *mut MuClipSyncHandle,
    out_ptr: *mut *const u8,
    out_len: *mut usize,
) -> u64 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return 0;
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_manual_peers();
    if let Some((id, ptr, len)) =
        write_binary_to_pooled_buffer(|buf| encode_string_list(&peers, buf))
    {
        unsafe {
            *out_ptr = ptr;
            *out_len = len;
        }
        return id;
    }
    0
}

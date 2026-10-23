use crate::cache::MemoryCache;
use crate::content::{analyze_content, format_preview};
use crate::database::{Database, PhraseRule, PhraseRuleTemplate};
use std::ffi::{CString, c_char};
use std::sync::Mutex;

use super::{c_char_to_str, string_to_c_char};

pub struct MuClipCoreEngine {
    pub db: Database,
    pub cache: MemoryCache,
}

pub struct MuClipCoreHandle {
    pub inner: Mutex<MuClipCoreEngine>,
}

/// Frees a string previously allocated and returned by `muclip-core`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            drop(CString::from_raw(s));
        }
    }
}

/// Returns the semantic version of the core library.
#[unsafe(no_mangle)]
pub extern "C" fn muclip_core_version() -> *mut c_char {
    string_to_c_char(env!("CARGO_PKG_VERSION").to_string())
}

/// Initializes a new MuClipCore engine backed by an SQLite database file at `db_path`.
/// Returns a pointer handle to `MuClipCoreHandle`, or null on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_new(db_path: *const c_char) -> *mut MuClipCoreHandle {
    unsafe { muclip_core_new_with_key(db_path, std::ptr::null()) }
}

/// Initializes a new MuClipCore engine backed by an SQLite database file at `db_path`,
/// optionally taking an encryption key in `key_hex`.
/// If `key_hex` is null or empty, the database is opened without encryption (plain SQLite).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_new_with_key(
    db_path: *const c_char,
    key_hex: *const c_char,
) -> *mut MuClipCoreHandle {
    let path = match unsafe { c_char_to_str(db_path) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    let key_opt = if !key_hex.is_null() {
        unsafe { c_char_to_str(key_hex) }
    } else {
        None
    };

    let db = match Database::open_with_key(path, key_opt) {
        Ok(db) => db,
        Err(e) => {
            // 此前这里静默返回 null，宿主只看到「打不开」，拿不到任何原因。
            crate::log_error!("打开数据库失败 path={}: {}", path, e);
            return std::ptr::null_mut();
        }
    };

    let mut cache = MemoryCache::new();
    let _ = cache.load_from_db(&db);

    let engine = MuClipCoreEngine { db, cache };
    Box::into_raw(Box::new(MuClipCoreHandle {
        inner: Mutex::new(engine),
    }))
}

/// 查询数据库是否**确实**处于加密状态。
///
/// 返回三态，刻意不用 bool：
/// - `1` 已加密（构建启用了 SEE/SQLCipher 且成功设置密钥）
/// - `0` 未加密（密钥被忽略，磁盘上是明文）
/// - `-1` 句柄无效或内部锁中毒
///
/// 把 `-1` 和 `0` 分开是有意的：宿主要是把「查询失败」当成「未加密」还无害，
/// 反过来把「查询失败」当成「已加密」就会在界面上谎报安全。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_is_encrypted(handle: *mut MuClipCoreHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    match engine_guard.inner.lock() {
        Ok(engine) => engine.db.is_encrypted() as i32,
        Err(_) => -1,
    }
}

/// Initializes an in-memory MuClipCore engine (useful for tests or volatile sessions).
#[unsafe(no_mangle)]
pub extern "C" fn muclip_core_new_in_memory() -> *mut MuClipCoreHandle {
    let db = match Database::open_in_memory() {
        Ok(db) => db,
        Err(_) => return std::ptr::null_mut(),
    };

    let cache = MemoryCache::new();
    let engine = MuClipCoreEngine { db, cache };
    Box::into_raw(Box::new(MuClipCoreHandle {
        inner: Mutex::new(engine),
    }))
}

/// Frees the MuClipCore engine handle and flushes unwritten cache to SQLite.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_free(handle: *mut MuClipCoreHandle) {
    if !handle.is_null() {
        unsafe {
            let handle_box = Box::from_raw(handle);
            if let Ok(mut engine) = handle_box.inner.lock() {
                let MuClipCoreEngine { cache, db } = &mut *engine;
                let _ = cache.flush_to_db(db);
            }
        }
    }
}

/// Adds a history record. Returns record ID, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_add_history(
    handle: *mut MuClipCoreHandle,
    content: *const c_char,
) -> i64 {
    if handle.is_null() {
        return -1;
    }
    let text = match unsafe { c_char_to_str(content) } {
        Some(t) => t,
        None => return -1,
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

/// Queries recent history items. Returns a JSON string array of `HistoryItem`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_history(
    handle: *mut MuClipCoreHandle,
    limit: usize,
) -> *mut c_char {
    unsafe { muclip_core_query_history_page(handle, 0, limit) }
}

/// Queries history items with pagination (`offset`, `limit`).
/// Serves from hot memory cache when covered, otherwise queries SQLite.
/// Returns a JSON string array of `HistoryItem`. Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_history_page(
    handle: *mut MuClipCoreHandle,
    offset: usize,
    limit: usize,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let cached = engine.cache.get_items();
        if offset + limit <= cached.len() {
            let slice = &cached[offset..offset + limit];
            let json = serde_json::to_string(slice).unwrap_or_else(|_| "[]".to_string());
            return string_to_c_char(json);
        }
        let items = match engine.db.query_history_page(offset, limit) {
            Ok(res) => res,
            Err(_) => cached.iter().skip(offset).take(limit).cloned().collect(),
        };
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Returns total count of persisted history items in SQLite, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_count_history(handle: *mut MuClipCoreHandle) -> i64 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        if let Ok(count) = engine.db.count_history() {
            return count as i64;
        }
        return engine.cache.get_items().len() as i64;
    }
    -1
}

/// Searches history items. Returns a JSON string array of `HistoryItem`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_search_history(
    handle: *mut MuClipCoreHandle,
    query: *const c_char,
    limit: usize,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let q = match unsafe { c_char_to_str(query) } {
        Some(text) => text,
        None => return string_to_c_char("[]".to_string()),
    };

    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.search_history(q, limit).unwrap_or_default();
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Deletes a history item by ID. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_delete_history(handle: *mut MuClipCoreHandle, id: i64) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        let was_in_cache = cache.remove_item(id);
        if db.delete_history(id).is_ok() {
            if was_in_cache {
                let _ = cache.load_from_db(db);
            }
            return 0;
        }
    }
    -1
}

/// Clears all history items. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_clear_history(handle: *mut MuClipCoreHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        cache.clear();
        if db.clear_all_history().is_ok() {
            return 0;
        }
    }
    -1
}

/// Cleans up history items older than `days` retention. Returns count of deleted rows, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_cleanup_history(
    handle: *mut MuClipCoreHandle,
    days: u32,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        match db.cleanup_expired_history(days) {
            Ok(count) => {
                if count > 0 {
                    let _ = cache.load_from_db(db);
                }
                return count as i32;
            }
            Err(_) => return -1,
        }
    }
    -1
}

/// Adds a new phrase. Returns phrase ID, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_add_phrase(
    handle: *mut MuClipCoreHandle,
    content: *const c_char,
) -> i64 {
    if handle.is_null() {
        return -1;
    }
    let text = match unsafe { c_char_to_str(content) } {
        Some(t) => t.trim(),
        None => return -1,
    };
    if text.is_empty() {
        return -1;
    }

    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if let Ok(id) = engine.db.add_phrase(text) {
            return id;
        }
    }
    -1
}

/// Edits a phrase. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_edit_phrase(
    handle: *mut MuClipCoreHandle,
    id: i64,
    new_content: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let text = match unsafe { c_char_to_str(new_content) } {
        Some(t) => t.trim(),
        None => return -1,
    };
    if text.is_empty() {
        return -1;
    }

    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.edit_phrase(id, text).is_ok() {
            return 0;
        }
    }
    -1
}

/// Deletes a phrase by ID. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_delete_phrase(handle: *mut MuClipCoreHandle, id: i64) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.delete_phrase(id).is_ok() {
            return 0;
        }
    }
    -1
}

/// Updates phrase `last_used_at`. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_update_phrase_used(
    handle: *mut MuClipCoreHandle,
    id: i64,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.update_phrase_used(id).is_ok() {
            return 0;
        }
    }
    -1
}

/// 批量按传入的 ID 顺序更新 sort_order (0, 1, 2...)
/// 返回 0 表示成功，-1 表示失败。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_reorder_phrases(
    handle: *mut MuClipCoreHandle,
    ids: *const i64,
    count: usize,
) -> i32 {
    if handle.is_null() || ids.is_null() || count == 0 {
        return -1;
    }
    let id_slice = unsafe { std::slice::from_raw_parts(ids, count) };
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.reorder_phrases(id_slice).is_ok() {
            return 0;
        }
    }
    -1
}

/// Queries all phrases. Returns a JSON string array of `PhraseItem`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_phrases(handle: *mut MuClipCoreHandle) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.query_phrases().unwrap_or_default();
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Searches phrases. Returns a JSON string array of `PhraseItem`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_search_phrases(
    handle: *mut MuClipCoreHandle,
    query: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let q = match unsafe { c_char_to_str(query) } {
        Some(text) => text,
        None => return string_to_c_char("[]".to_string()),
    };

    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.search_phrases(q).unwrap_or_default();
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

// -----------------------------------------------------------------------------
// Phrase Rules & Rule Templates FFI
// -----------------------------------------------------------------------------

/// Adds or updates a phrase rule from a JSON string.
/// Returns rule ID string, or null on error. Must be freed with `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_add_phrase_rule(
    handle: *mut MuClipCoreHandle,
    rule_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let json_str = match unsafe { c_char_to_str(rule_json) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let rule: PhraseRule = match serde_json::from_str(json_str) {
        Ok(r) => r,
        Err(_) => return std::ptr::null_mut(),
    };

    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if let Ok(id) = engine.db.add_or_update_phrase_rule(&rule) {
            return string_to_c_char(id);
        }
    }
    std::ptr::null_mut()
}

/// Deletes a phrase rule by its ID string. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_delete_phrase_rule(
    handle: *mut MuClipCoreHandle,
    id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let id_str = match unsafe { c_char_to_str(id) } {
        Some(s) => s,
        None => return -1,
    };
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.delete_phrase_rule(id_str).is_ok() {
            return 0;
        }
    }
    -1
}

/// Queries rules for a given phrase ID (or all rules if phrase_id <= 0).
/// Returns a JSON string array of `PhraseRule`. Must be freed with `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_phrase_rules(
    handle: *mut MuClipCoreHandle,
    phrase_id: i64,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = if phrase_id > 0 {
            engine.db.query_phrase_rules(phrase_id).unwrap_or_default()
        } else {
            engine.db.query_all_phrase_rules().unwrap_or_default()
        };
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Saves or updates a phrase rule template from a JSON string.
/// Returns template ID string, or null on error. Must be freed with `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_save_template(
    handle: *mut MuClipCoreHandle,
    template_json: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let json_str = match unsafe { c_char_to_str(template_json) } {
        Some(s) => s,
        None => return std::ptr::null_mut(),
    };
    let template: PhraseRuleTemplate = match serde_json::from_str(json_str) {
        Ok(t) => t,
        Err(_) => return std::ptr::null_mut(),
    };

    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if let Ok(id) = engine.db.save_phrase_rule_template(&template) {
            return string_to_c_char(id);
        }
    }
    std::ptr::null_mut()
}

/// Deletes a rule template by its ID string. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_delete_template(
    handle: *mut MuClipCoreHandle,
    id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let id_str = match unsafe { c_char_to_str(id) } {
        Some(s) => s,
        None => return -1,
    };
    let engine_guard = unsafe { &*handle };
    if let Ok(mut engine) = engine_guard.inner.lock() {
        if engine.db.delete_phrase_rule_template(id_str).is_ok() {
            return 0;
        }
    }
    -1
}

/// Queries all phrase rule templates.
/// Returns a JSON string array of `PhraseRuleTemplate`. Must be freed with `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_query_templates(handle: *mut MuClipCoreHandle) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.db.query_phrase_rule_templates().unwrap_or_default();
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Formats text into single-line preview. Returns C-string.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_format_preview(
    text: *const c_char,
    max_chars: usize,
) -> *mut c_char {
    let s = match unsafe { c_char_to_str(text) } {
        Some(t) => t,
        None => "",
    };
    let preview = format_preview(s, max_chars);
    string_to_c_char(preview)
}

/// Analyzes content characteristics (type, length, lines, preview). Returns JSON string of `ContentAnalysis`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_analyze_content(text: *const c_char) -> *mut c_char {
    let s = match unsafe { c_char_to_str(text) } {
        Some(t) => t,
        None => "",
    };
    let analysis = analyze_content(s);
    let json = serde_json::to_string(&analysis).unwrap_or_else(|_| "{}".to_string());
    string_to_c_char(json)
}

/// Returns recent items from memory cache (hot LRU cache, max 100 items / 5MB).
/// Returns a JSON string array of `HistoryItem`. Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_get_cached_items(
    handle: *mut MuClipCoreHandle,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine_guard = unsafe { &*handle };
    if let Ok(engine) = engine_guard.inner.lock() {
        let items = engine.cache.get_items();
        let json = serde_json::to_string(items).unwrap_or_else(|_| "[]".to_string());
        return string_to_c_char(json);
    }
    string_to_c_char("[]".to_string())
}

/// Sets a persistent configuration key-value pair in SQLite.
/// Returns 0 on success, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_set_config(
    handle: *mut MuClipCoreHandle,
    key: *const c_char,
    val: *const c_char,
) -> i32 {
    let key_str = match unsafe { c_char_to_str(key) } {
        Some(k) => k,
        None => return -1,
    };
    let val_str = match unsafe { c_char_to_str(val) } {
        Some(v) => v,
        None => return -1,
    };
    if let Some(h) = unsafe { handle.as_ref() } {
        if let Ok(mut engine) = h.inner.lock() {
            if engine.db.set_config(key_str, val_str).is_ok() {
                return 0;
            }
        }
    }
    -1
}

/// Gets a persistent configuration value by key from SQLite.
/// Returns a C-string if found, or NULL if not found or on error.
/// The returned string must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_get_config(
    handle: *mut MuClipCoreHandle,
    key: *const c_char,
) -> *mut c_char {
    let key_str = match unsafe { c_char_to_str(key) } {
        Some(k) => k,
        None => return std::ptr::null_mut(),
    };
    if let Some(h) = unsafe { handle.as_ref() } {
        if let Ok(engine) = h.inner.lock() {
            if let Ok(Some(val)) = engine.db.get_config(key_str) {
                return string_to_c_char(val);
            }
        }
    }
    std::ptr::null_mut()
}

/// Exports the SQLite database (history, phrases, rules, templates, and config)
/// into an encrypted single-file backup using XChaCha20-Poly1305 and PBKDF2.
/// Returns a JSON string of `BackupSummary` on success (must be freed with `muclip_core_free_string`),
/// or NULL on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_export_db(
    handle: *mut MuClipCoreHandle,
    export_path: *const c_char,
    password: *const c_char,
) -> *mut c_char {
    let path_str = match unsafe { c_char_to_str(export_path) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };
    let pwd_str = match unsafe { c_char_to_str(password) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    if let Some(h) = unsafe { handle.as_ref() } {
        if let Ok(engine) = h.inner.lock() {
            if let Ok(summary) = engine.db.export_encrypted(path_str, pwd_str) {
                let json = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
                return string_to_c_char(json);
            }
        }
    }
    std::ptr::null_mut()
}

/// Imports an encrypted database backup file.
/// If `replace_all` is true (non-zero), existing data is cleared before restoring.
/// If `replace_all` is false (zero), records are merged and deduplicated.
/// After successful import, in-memory cache is automatically reloaded from the database.
/// Returns a JSON string of `BackupSummary` on success (must be freed with `muclip_core_free_string`),
/// or NULL on error (e.g. wrong password, corrupted file, invalid format).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_core_import_db(
    handle: *mut MuClipCoreHandle,
    import_path: *const c_char,
    password: *const c_char,
    replace_all: i32,
) -> *mut c_char {
    let path_str = match unsafe { c_char_to_str(import_path) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };
    let pwd_str = match unsafe { c_char_to_str(password) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };

    if let Some(h) = unsafe { handle.as_ref() } {
        if let Ok(mut engine) = h.inner.lock() {
            let MuClipCoreEngine { cache, db } = &mut *engine;
            match db.import_encrypted(path_str, pwd_str, replace_all != 0) {
                Ok(summary) => {
                    let _ = cache.load_from_db(db);
                    let json = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
                    return string_to_c_char(json);
                }
                Err(_) => return std::ptr::null_mut(),
            }
        }
    }
    std::ptr::null_mut()
}

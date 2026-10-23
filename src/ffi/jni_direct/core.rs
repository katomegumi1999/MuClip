use jni::JNIEnv;
use jni::objects::{JClass, JLongArray, JObject, JString};
use jni::sys::{jint, jlong};
use std::slice;

use crate::cache::MemoryCache;
use crate::content::{analyze_content, format_preview};
use crate::database::Database;
use crate::ffi::exports::{MuClipCoreEngine, MuClipCoreHandle};
use crate::ffi::jni_direct::binary::{
    encode_content_analysis, encode_history_items, encode_phrase_items,
};

// -----------------------------------------------------------------------------
// Engine Lifecycle
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
) -> jlong {
    let path_str: String = match env.get_string(&db_path) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let db = match Database::open(&path_str) {
        Ok(db) => db,
        Err(_) => return 0,
    };

    let mut cache = MemoryCache::new();
    let _ = cache.load_from_db(&db);

    let engine = MuClipCoreEngine { db, cache };
    let handle = Box::into_raw(Box::new(MuClipCoreHandle {
        inner: std::sync::Mutex::new(engine),
    }));

    handle as usize as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeInitWithKey(
    mut env: JNIEnv,
    _class: JClass,
    db_path: JString,
    key_hex: JString,
) -> jlong {
    let path_str: String = match env.get_string(&db_path) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };

    let key_opt: Option<String> = if !key_hex.is_null() {
        env.get_string(&key_hex).ok().map(|s| s.into())
    } else {
        None
    };

    let db = match Database::open_with_key(&path_str, key_opt.as_deref()) {
        Ok(db) => db,
        Err(_) => return 0,
    };

    let mut cache = MemoryCache::new();
    let _ = cache.load_from_db(&db);

    let engine = MuClipCoreEngine { db, cache };
    let handle = Box::into_raw(Box::new(MuClipCoreHandle {
        inner: std::sync::Mutex::new(engine),
    }));

    handle as usize as jlong
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeInitInMemory(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    let db = match Database::open_in_memory() {
        Ok(db) => db,
        Err(_) => return 0,
    };

    let cache = MemoryCache::new();
    let engine = MuClipCoreEngine { db, cache };
    let handle = Box::into_raw(Box::new(MuClipCoreHandle {
        inner: std::sync::Mutex::new(engine),
    }));

    handle as usize as jlong
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeClose(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle != 0 {
        let ptr = handle as usize as *mut MuClipCoreHandle;
        unsafe {
            let handle_box = Box::from_raw(ptr);
            if let Ok(mut engine) = handle_box.inner.lock() {
                let MuClipCoreEngine { cache, db } = &mut *engine;
                let _ = cache.flush_to_db(db);
            }
        }
    }
}

/// Sets a persistent configuration key-value pair in SQLite.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeSetConfig(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    key: JString,
    value: JString,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let val_str: String = match env.get_string(&value) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let ptr = handle as usize as *mut MuClipCoreHandle;
    if let Some(h) = unsafe { ptr.as_ref() } {
        if let Ok(mut engine) = h.inner.lock() {
            if engine.db.set_config(&key_str, &val_str).is_ok() {
                return 0;
            }
        }
    }
    -1
}

/// Gets a persistent configuration value by key from SQLite.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetConfig<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    key: JString<'local>,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let key_str: String = match env.get_string(&key) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };

    let ptr = handle as usize as *mut MuClipCoreHandle;
    if let Some(h) = unsafe { ptr.as_ref() } {
        if let Ok(engine) = h.inner.lock() {
            if let Ok(Some(val)) = engine.db.get_config(&key_str) {
                if let Ok(js) = env.new_string(val) {
                    return js;
                }
            }
        }
    }
    JString::from(JObject::null())
}

// -----------------------------------------------------------------------------
// Zero-Copy Clipboard Operations
// -----------------------------------------------------------------------------

/// Adds a clipboard history record directly from off-heap memory pointer.
/// 0 JNI string copying, 0 JVM GC overhead!
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAddHistoryZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buffer_ptr: jlong,
    length: jint,
) -> jlong {
    if handle == 0 || buffer_ptr == 0 || length <= 0 {
        return -1;
    }

    let ptr = buffer_ptr as usize as *const u8;
    let slice = unsafe { slice::from_raw_parts(ptr, length as usize) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        cache.add_item(text.to_string(), Some(db));
        if let Some(first) = cache.get_items().first() {
            return first.id;
        }
    }
    -1
}

/// Queries clipboard history items and writes Little-Endian binary wire format directly into `out_buffer_ptr`.
/// Returns number of bytes written (`>= 0`), `-required_len` (`< -1`) if buffer capacity is too small, or `-1` on error.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeQueryHistoryZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    limit: jint,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if handle == 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        let items = match engine.db.query_history(limit as usize) {
            Ok(res) => res,
            Err(_) => engine
                .cache
                .get_items()
                .iter()
                .take(limit as usize)
                .cloned()
                .collect(),
        };

        let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
        else {
            return -1;
        };
        return encode_history_items(&items, out_slice);
    }
    -1
}

/// Searches clipboard history items and writes Little-Endian binary wire format directly into `out_buffer_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeSearchHistoryZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    query_ptr: jlong,
    query_len: jint,
    limit: jint,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if handle == 0 || query_ptr == 0 || query_len <= 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }

    let query_slice =
        unsafe { slice::from_raw_parts(query_ptr as usize as *const u8, query_len as usize) };
    let query_str = match std::str::from_utf8(query_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        let items = engine
            .db
            .search_history(query_str, limit as usize)
            .unwrap_or_default();
        let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
        else {
            return -1;
        };
        return encode_history_items(&items, out_slice);
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeleteHistory(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    id: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        cache.remove_item(id);
        if db.delete_history(id).is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeClearHistory(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        cache.clear();
        if db.clear_all_history().is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeCleanupHistory(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    days: jint,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        match engine.db.cleanup_expired_history(days as u32) {
            Ok(count) => return count as jint,
            Err(_) => return -1,
        }
    }
    -1
}

// -----------------------------------------------------------------------------
// Phrases Zero-Copy Operations
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAddPhraseZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    buffer_ptr: jlong,
    length: jint,
) -> jlong {
    if handle == 0 || buffer_ptr == 0 || length <= 0 {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(buffer_ptr as usize as *const u8, length as usize) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s.trim(),
        Err(_) => return -1,
    };
    if text.is_empty() {
        return -1;
    }

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if let Ok(id) = engine.db.add_phrase(text) {
            return id;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeQueryPhrasesZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if handle == 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        let items = engine.db.query_phrases().unwrap_or_default();
        let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
        else {
            return -1;
        };
        return encode_phrase_items(&items, out_slice);
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeletePhrase(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    id: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if engine.db.delete_phrase(id).is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeClearPhrases(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if engine.db.clear_all_phrases().is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeReorderPhrases(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
    ids: JLongArray,
) -> jint {
    if handle == 0 || ids.is_null() {
        return -1;
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    let len = match env.get_array_length(&ids) {
        Ok(l) => l as usize,
        Err(_) => return -1,
    };
    if len == 0 {
        return 0;
    }
    let mut buf = vec![0i64; len];
    if env.get_long_array_region(&ids, 0, &mut buf).is_err() {
        return -1;
    }
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if engine.db.reorder_phrases(&buf).is_ok() {
            return 0;
        }
    }
    -1
}

// -----------------------------------------------------------------------------
// Phrase Rules & Rule Templates JNI
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAddPhraseRule<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    rule_json: JString<'local>,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let json_str: String = match env.get_string(&rule_json) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };
    let rule: crate::database::PhraseRule = match serde_json::from_str(&json_str) {
        Ok(r) => r,
        Err(_) => return JString::from(JObject::null()),
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if let Ok(id) = engine.db.add_or_update_phrase_rule(&rule) {
            if let Ok(js) = env.new_string(id) {
                return js;
            }
        }
    }
    JString::from(JObject::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeletePhraseRule(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    id: JString,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let id_str: String = match env.get_string(&id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if engine.db.delete_phrase_rule(&id_str).is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeQueryPhraseRules<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    phrase_id: jlong,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        let items = if phrase_id > 0 {
            engine.db.query_phrase_rules(phrase_id).unwrap_or_default()
        } else {
            engine.db.query_all_phrase_rules().unwrap_or_default()
        };
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        if let Ok(js) = env.new_string(json) {
            return js;
        }
    }
    JString::from(JObject::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeSaveRuleTemplate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    template_json: JString<'local>,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let json_str: String = match env.get_string(&template_json) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };
    let template: crate::database::PhraseRuleTemplate = match serde_json::from_str(&json_str) {
        Ok(t) => t,
        Err(_) => return JString::from(JObject::null()),
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if let Ok(id) = engine.db.save_phrase_rule_template(&template) {
            if let Ok(js) = env.new_string(id) {
                return js;
            }
        }
    }
    JString::from(JObject::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeleteRuleTemplate(
    mut env: JNIEnv,
    _class: JClass,
    handle: jlong,
    id: JString,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let id_str: String = match env.get_string(&id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        if engine.db.delete_phrase_rule_template(&id_str).is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeQueryRuleTemplates<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        let items = engine.db.query_phrase_rule_templates().unwrap_or_default();
        let json = serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
        if let Ok(js) = env.new_string(json) {
            return js;
        }
    }
    JString::from(JObject::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeExportDb<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    export_path: JString<'local>,
    password: JString<'local>,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let path_str: String = match env.get_string(&export_path) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };
    let pwd_str: String = match env.get_string(&password) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(engine) = engine_handle.inner.lock() {
        if let Ok(summary) = engine.db.export_encrypted(&path_str, &pwd_str) {
            let json = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
            if let Ok(js) = env.new_string(json) {
                return js;
            }
        }
    }
    JString::from(JObject::null())
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeImportDb<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    import_path: JString<'local>,
    password: JString<'local>,
    replace_all: jint,
) -> JString<'local> {
    if handle == 0 {
        return JString::from(JObject::null());
    }
    let path_str: String = match env.get_string(&import_path) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };
    let pwd_str: String = match env.get_string(&password) {
        Ok(s) => s.into(),
        Err(_) => return JString::from(JObject::null()),
    };

    let engine_handle = unsafe { &*(handle as usize as *mut MuClipCoreHandle) };
    if let Ok(mut engine) = engine_handle.inner.lock() {
        let MuClipCoreEngine { cache, db } = &mut *engine;
        if let Ok(summary) = db.import_encrypted(&path_str, &pwd_str, replace_all != 0) {
            let _ = cache.load_from_db(db);
            let json = serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string());
            if let Ok(js) = env.new_string(json) {
                return js;
            }
        }
    }
    JString::from(JObject::null())
}

// -----------------------------------------------------------------------------
// Content Analysis & Preview Zero-Copy Operations
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeFormatPreviewZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    text_ptr: jlong,
    text_len: jint,
    max_chars: jint,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if text_ptr == 0 || text_len <= 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(text_ptr as usize as *const u8, text_len as usize) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let preview = format_preview(text, max_chars as usize);
    let preview_bytes = preview.as_bytes();
    if preview_bytes.len() > out_capacity as usize {
        return -(preview_bytes.len() as jint);
    }
    let out_slice = unsafe {
        slice::from_raw_parts_mut(out_buffer_ptr as usize as *mut u8, preview_bytes.len())
    };
    out_slice.copy_from_slice(preview_bytes);
    preview_bytes.len() as jint
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAnalyzeContentZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    text_ptr: jlong,
    text_len: jint,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if text_ptr == 0 || text_len <= 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(text_ptr as usize as *const u8, text_len as usize) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    let analysis = analyze_content(text);
    let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
    else {
        return -1;
    };
    encode_content_analysis(&analysis, out_slice)
}

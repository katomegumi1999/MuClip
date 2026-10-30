mod core;
mod diag;
mod file_transfer;
mod pool;
mod sync;

pub use self::core::*;
pub use self::diag::*;
pub use self::file_transfer::*;
pub use self::pool::*;
pub use self::sync::*;

use std::ffi::{CStr, CString, c_char};

pub(super) unsafe fn c_char_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(p).to_str().ok() }
}

pub(super) fn string_to_c_char(s: String) -> *mut c_char {
    CString::new(s).unwrap_or_default().into_raw()
}

pub(super) fn copy_str_to_fixed_buf<const N: usize>(src: &str, dest: &mut [u8; N]) {
    dest.fill(0);
    let bytes = src.as_bytes();
    let len = bytes.len().min(N - 1);
    dest[..len].copy_from_slice(&bytes[..len]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    /// SECURITY 回归测试：offset 来自 C# / Kotlin，不可信。
    /// 修复前 `offset + limit` 在 offset = usize::MAX 时回绕为 0 通过边界判断，
    /// 随后切片越界 panic；release profile 是 `panic = "abort"`，会直接杀掉宿主进程。
    #[test]
    fn test_pooled_page_query_survives_overflow_offset() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            let text = CString::new("overflow guard").unwrap();
            assert!(muclip_core_add_history(handle, text.as_ptr()) > 0);

            let mut out_ptr: *const u8 = std::ptr::null();
            let mut out_len: usize = 0;
            let lease = muclip_core_query_history_page_pooled(
                handle,
                usize::MAX,
                1,
                &mut out_ptr,
                &mut out_len,
            );
            // 关键断言：不 panic（能跑到这里就说明没崩），且返回有效租约供释放
            assert!(lease > 0, "溢出 offset 必须安全降级，而不是崩溃");
            assert_eq!(muclip_pool_release(lease), 0);

            muclip_core_free(handle);
        }
    }

    /// 结构化搜索的 FFI 往返：JSON 请求 → 池化二进制 → count。
    ///
    /// C# 侧依赖 `muclip_core_search_history_page_pooled` 与
    /// `muclip_core_search_history_count` 两个新符号，符号缺失会在宿主运行期抛
    /// EntryPointNotFoundException（编译期发现不了），所以这里必须覆盖。
    #[test]
    fn test_pooled_search_page_and_count_with_types() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            for s in ["普通文本一", "普通文本二", "https://example.com/a"] {
                let c = CString::new(s).unwrap();
                assert!(muclip_core_add_history(handle, c.as_ptr()) > 0);
            }

            let mut out_ptr: *const u8 = std::ptr::null();
            let mut out_len: usize = 0;

            // 只要 URL（类型编号 1）
            let url_only =
                CString::new(r#"{"query":"","types":[1],"offset":0,"limit":50}"#).unwrap();
            let lease = muclip_core_search_history_page_pooled(
                handle,
                url_only.as_ptr(),
                &mut out_ptr,
                &mut out_len,
            );
            assert!(lease > 0, "分页搜索应当返回有效租约");
            let slice = std::slice::from_raw_parts(out_ptr, out_len);
            let count = u32::from_le_bytes(slice[0..4].try_into().unwrap());
            assert_eq!(count, 1, "类型筛选应当只回传那条 URL");
            assert_eq!(muclip_pool_release(lease), 0);

            assert_eq!(
                muclip_core_search_history_count(handle, url_only.as_ptr()),
                1
            );

            let all = CString::new(r#"{"query":"","types":[],"offset":0,"limit":50}"#).unwrap();
            assert_eq!(muclip_core_search_history_count(handle, all.as_ptr()), 3);

            // 关键词按字面量匹配：搜 % 不能命中全部
            let pct = CString::new(r#"{"query":"%","types":[],"offset":0,"limit":50}"#).unwrap();
            assert_eq!(muclip_core_search_history_count(handle, pct.as_ptr()), 0);

            // 非法 JSON 退化成「无条件分页」，不能让调用方拿到空租约而误判成「无结果」
            let bad = CString::new("{not json").unwrap();
            let lease2 = muclip_core_search_history_page_pooled(
                handle,
                bad.as_ptr(),
                &mut out_ptr,
                &mut out_len,
            );
            assert!(lease2 > 0);
            let slice2 = std::slice::from_raw_parts(out_ptr, out_len);
            assert_eq!(u32::from_le_bytes(slice2[0..4].try_into().unwrap()), 3);
            assert_eq!(muclip_pool_release(lease2), 0);

            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_memory_pool_lease_and_pooled_queries() {
        unsafe {
            let mut buf_ptr: *mut u8 = std::ptr::null_mut();
            let mut buf_cap: usize = 0;
            let lease_id = muclip_pool_acquire(8192, &mut buf_ptr, &mut buf_cap);
            assert!(lease_id > 0);
            assert!(!buf_ptr.is_null());
            assert!(buf_cap >= 8192);

            let rel_res = muclip_pool_release(lease_id);
            assert_eq!(rel_res, 0);

            let handle = muclip_core_new_in_memory();
            let test_text = b"Leased Memory Test Item";
            let rec_id =
                muclip_core_add_history_buffer(handle, test_text.as_ptr(), test_text.len());
            assert!(rec_id > 0);

            let mut out_ptr: *const u8 = std::ptr::null();
            let mut out_len: usize = 0;
            let q_lease = muclip_core_get_cached_items_pooled(handle, &mut out_ptr, &mut out_len);
            assert!(q_lease > 0);
            assert!(!out_ptr.is_null());
            assert!(out_len > 24);

            let slice = std::slice::from_raw_parts(out_ptr, out_len);
            // Verify binary header: count = 1 (u32 LE)
            let count = u32::from_le_bytes(slice[0..4].try_into().unwrap());
            assert_eq!(count, 1);
            // Verify id (i64 LE) == rec_id
            let decoded_id = i64::from_le_bytes(slice[4..12].try_into().unwrap());
            assert_eq!(decoded_id, rec_id);
            // Verify content length and UTF-8 bytes at offset 24
            let content_len = i32::from_le_bytes(slice[24..28].try_into().unwrap()) as usize;
            let content_str = std::str::from_utf8(&slice[28..28 + content_len]).unwrap();
            assert_eq!(content_str, "Leased Memory Test Item");

            assert_eq!(muclip_pool_release(q_lease), 0);
            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_ffi_lifecycle_and_crud() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            assert!(!handle.is_null());

            let text = CString::new("Hello from FFI").unwrap();
            let id = muclip_core_add_history(handle, text.as_ptr());
            assert!(id > 0);

            let cached_ptr = muclip_core_get_cached_items(handle);
            assert!(!cached_ptr.is_null());
            let cached_str = CStr::from_ptr(cached_ptr).to_str().unwrap();
            assert!(cached_str.contains("Hello from FFI"));
            muclip_core_free_string(cached_ptr);

            let json_ptr = muclip_core_query_history(handle, 10);
            assert!(!json_ptr.is_null());
            let json_str = CStr::from_ptr(json_ptr).to_str().unwrap();
            assert!(json_str.contains("Hello from FFI"));
            muclip_core_free_string(json_ptr);

            let analysis_ptr = muclip_core_analyze_content(text.as_ptr());
            let analysis_str = CStr::from_ptr(analysis_ptr).to_str().unwrap();
            assert!(analysis_str.contains("plain_text"));
            muclip_core_free_string(analysis_ptr);

            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_ffi_sync_lifecycle() {
        unsafe {
            let dev_id = CString::new("test-dev-1").unwrap();
            let dev_name = CString::new("Node 1").unwrap();
            let dev_type = CString::new("Windows").unwrap();
            let pin = CString::new("123456").unwrap();

            let sync_handle = muclip_sync_start(
                dev_id.as_ptr(),
                dev_name.as_ptr(),
                dev_type.as_ptr(),
                0,
                0,
                pin.as_ptr(),
            );
            assert!(!sync_handle.is_null());

            let bound = muclip_sync_get_bound_port(sync_handle);
            assert!(bound > 0);

            let peers_ptr = muclip_sync_get_active_peers(sync_handle);
            assert!(!peers_ptr.is_null());
            let peers_str = CStr::from_ptr(peers_ptr).to_str().unwrap();
            assert!(peers_str.starts_with('[') && peers_str.ends_with(']'));
            muclip_core_free_string(peers_ptr);

            assert_eq!(muclip_sync_is_auto_discovery(sync_handle), 1);
            assert_eq!(muclip_sync_set_auto_discovery(sync_handle, 0), 0);
            assert_eq!(muclip_sync_is_auto_discovery(sync_handle), 0);
            assert_eq!(muclip_sync_trigger_scan(sync_handle), 0);
            assert_eq!(muclip_sync_set_auto_discovery(sync_handle, 1), 0);
            assert_eq!(muclip_sync_is_auto_discovery(sync_handle), 1);

            muclip_sync_stop(sync_handle);
        }
    }

    #[test]
    fn test_ffi_secure_config() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            assert!(!handle.is_null());

            let key = CString::new("test_token").unwrap();
            let val = CString::new("secret_value_xyz").unwrap();

            let initial = muclip_core_get_config(handle, key.as_ptr());
            assert!(initial.is_null());

            assert_eq!(
                muclip_core_set_config(handle, key.as_ptr(), val.as_ptr()),
                0
            );

            let res_ptr = muclip_core_get_config(handle, key.as_ptr());
            assert!(!res_ptr.is_null());
            let res_str = CStr::from_ptr(res_ptr).to_str().unwrap();
            assert_eq!(res_str, "secret_value_xyz");
            muclip_core_free_string(res_ptr);

            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_ffi_history_pagination_beyond_100() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            assert!(!handle.is_null());

            // Insert 135 distinct items
            for i in 1..=135 {
                let text = format!("History Item #{i}");
                let id = muclip_core_add_history_buffer(handle, text.as_ptr(), text.len());
                assert!(id > 0);
            }

            // Total persisted in SQLite must be 135
            assert_eq!(muclip_core_count_history(handle), 135);

            // Hot memory cache preloads max 100 items
            let mut out_ptr: *const u8 = std::ptr::null();
            let mut out_len: usize = 0;
            let lease_hot = muclip_core_get_cached_items_pooled(handle, &mut out_ptr, &mut out_len);
            assert!(lease_hot > 0);
            let slice_hot = std::slice::from_raw_parts(out_ptr, out_len);
            let hot_count = u32::from_le_bytes(slice_hot[0..4].try_into().unwrap());
            assert_eq!(hot_count, 100);
            assert_eq!(muclip_pool_release(lease_hot), 0);

            // Page 2 from SQLite (offset 100, limit 50) must return the remaining 35 items
            let mut page_ptr: *const u8 = std::ptr::null();
            let mut page_len: usize = 0;
            let lease_page = muclip_core_query_history_page_pooled(
                handle,
                100,
                50,
                &mut page_ptr,
                &mut page_len,
            );
            assert!(lease_page > 0);
            let slice_page = std::slice::from_raw_parts(page_ptr, page_len);
            let page_count = u32::from_le_bytes(slice_page[0..4].try_into().unwrap());
            assert_eq!(page_count, 35);
            assert_eq!(muclip_pool_release(lease_page), 0);

            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_ffi_phrases_reorder() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            assert!(!handle.is_null());

            let c1 = CString::new("Phrase 1").unwrap();
            let c2 = CString::new("Phrase 2").unwrap();
            let c3 = CString::new("Phrase 3").unwrap();
            let p1 = muclip_core_add_phrase(handle, c1.as_ptr());
            let p2 = muclip_core_add_phrase(handle, c2.as_ptr());
            let p3 = muclip_core_add_phrase(handle, c3.as_ptr());
            assert!(p1 > 0 && p2 > 0 && p3 > 0);

            let reorder_ids = [p3, p1, p2];
            let res = muclip_core_reorder_phrases(handle, reorder_ids.as_ptr(), reorder_ids.len());
            assert_eq!(res, 0);

            let json_ptr = muclip_core_query_phrases(handle);
            assert!(!json_ptr.is_null());
            let json_str = CStr::from_ptr(json_ptr).to_str().unwrap();
            let parsed: Vec<crate::database::PhraseItem> = serde_json::from_str(json_str).unwrap();
            assert_eq!(parsed.len(), 3);
            assert_eq!(parsed[0].id, p3);
            assert_eq!(parsed[1].id, p1);
            assert_eq!(parsed[2].id, p2);
            assert_eq!(parsed[0].sort_order, 0);
            assert_eq!(parsed[1].sort_order, 1);
            assert_eq!(parsed[2].sort_order, 2);

            muclip_core_free_string(json_ptr);
            muclip_core_free(handle);
        }
    }

    #[test]
    fn test_ffi_phrase_rules_and_templates() {
        unsafe {
            let handle = muclip_core_new_in_memory();
            assert!(!handle.is_null());

            let phrase_text = CString::new("FFI Phrase").unwrap();
            let pid = muclip_core_add_phrase(handle, phrase_text.as_ptr());
            assert!(pid > 0);

            // Add rule
            let rule_json = format!(
                r#"{{"phrase_id":{},"is_enabled":true,"insert_position":0,"position_mode":1,"start_time":"08:00","end_time":"18:00","append_text":" (Work)"}}"#,
                pid
            );
            let c_rule_json = CString::new(rule_json).unwrap();
            let rule_id_ptr = muclip_core_add_phrase_rule(handle, c_rule_json.as_ptr());
            assert!(!rule_id_ptr.is_null());
            let rule_id = CStr::from_ptr(rule_id_ptr).to_str().unwrap().to_string();
            muclip_core_free_string(rule_id_ptr);
            assert!(!rule_id.is_empty());

            // Query rule
            let rules_ptr = muclip_core_query_phrase_rules(handle, pid);
            assert!(!rules_ptr.is_null());
            let rules_json = CStr::from_ptr(rules_ptr).to_str().unwrap();
            let rules: Vec<crate::database::PhraseRule> = serde_json::from_str(rules_json).unwrap();
            assert_eq!(rules.len(), 1);
            assert_eq!(rules[0].id, rule_id);
            assert_eq!(rules[0].append_text, " (Work)");
            assert_eq!(rules[0].is_enabled, 1);
            muclip_core_free_string(rules_ptr);

            // Save template
            let tpl_json = r#"{"name":"Morning","insert_position":0,"position_mode":1,"start_time":"06:00","end_time":"10:00","append_text":" Good Morning"}"#;
            let c_tpl_json = CString::new(tpl_json).unwrap();
            let tpl_id_ptr = muclip_core_save_template(handle, c_tpl_json.as_ptr());
            assert!(!tpl_id_ptr.is_null());
            let tpl_id = CStr::from_ptr(tpl_id_ptr).to_str().unwrap().to_string();
            muclip_core_free_string(tpl_id_ptr);
            assert!(!tpl_id.is_empty());

            // Query templates
            let tpls_ptr = muclip_core_query_templates(handle);
            assert!(!tpls_ptr.is_null());
            let tpls_json = CStr::from_ptr(tpls_ptr).to_str().unwrap();
            let templates: Vec<crate::database::PhraseRuleTemplate> =
                serde_json::from_str(tpls_json).unwrap();
            assert_eq!(templates.len(), 1);
            assert_eq!(templates[0].id, tpl_id);
            assert_eq!(templates[0].name, "Morning");
            muclip_core_free_string(tpls_ptr);

            // Delete template
            let c_tid = CString::new(tpl_id).unwrap();
            assert_eq!(muclip_core_delete_template(handle, c_tid.as_ptr()), 0);

            // Delete rule
            let c_rid = CString::new(rule_id).unwrap();
            assert_eq!(muclip_core_delete_phrase_rule(handle, c_rid.as_ptr()), 0);

            muclip_core_free(handle);
        }
    }
}

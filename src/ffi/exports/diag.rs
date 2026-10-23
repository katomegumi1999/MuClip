//! 诊断日志的 C ABI 表面。
//!
//! 宿主接入分两步，**都不影响现有调用方**：
//!
//! 1. 已有日志自动进入环形缓冲，随时可拉：
//!    `muclip_diag_snapshot()` → JSON 数组 → `muclip_core_free_string()`。
//! 2. 想要实时日志就注册回调：
//!    `muclip_diag_set_sink(cb)`，注销传 `NULL`。
//!
//! 返回的字符串一律由 `muclip_core_free_string()` 释放，与本库其他字符串接口一致。

use crate::diag::{self, LogSink};
use std::ffi::c_char;

use super::string_to_c_char;

/// 把环形缓冲序列化为 JSON 数组。事件按时间从旧到新。
///
/// 形如：`[{"level":"warn","msg":"..."}]`。**不清空**缓冲，可重复调用。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_snapshot() -> *mut c_char {
    string_to_c_char(encode(&diag::snapshot()))
}

/// 同 [`muclip_diag_snapshot`]，但取走并清空缓冲。
///
/// 宿主上报诊断信息时应用这个，避免同一条日志被上报两次。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_drain() -> *mut c_char {
    string_to_c_char(encode(&diag::drain()))
}

fn encode(items: &[(u8, String)]) -> String {
    let arr: Vec<serde_json::Value> = items
        .iter()
        .map(|(level, msg)| {
            serde_json::json!({
                "level": diag::level_name(*level),
                "msg": msg,
            })
        })
        .collect();
    serde_json::Value::Array(arr).to_string()
}

/// 注册宿主日志接收器。传 `NULL` 注销。
///
/// 回调签名：`void (*)(uint8_t level, const char* msg)`。
/// `msg` 仅在本次调用内有效，宿主必须立即拷贝。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_set_sink(sink: Option<LogSink>) {
    diag::set_sink(sink);
}

/// 设置最低记录级别：0=ERROR, 1=WARN, 2=INFO(默认), 3=DEBUG。
///
/// 超出范围的值会被钳到 3（DEBUG），而不是拒绝——日志配置不值得让宿主调用失败。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_set_level(level: u8) {
    diag::set_level(level);
}

/// 读取当前最低记录级别。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_get_level() -> u8 {
    diag::level()
}

/// 开关 stderr 输出。`on` 传 0 关闭。
///
/// GUI 宿主建议关掉：没有控制台时每次输出都是一次注定失败的 syscall，
/// 而环形缓冲和 sink 已经完整覆盖了诊断需求。
#[unsafe(no_mangle)]
pub extern "C" fn muclip_diag_set_stderr(on: i32) {
    diag::set_stderr_enabled(on != 0);
}

/// 记录一条来自宿主的日志，便于把 C# / Kotlin 侧的事件与核心引擎的顺序对齐。
///
/// 只接受静态文案或已格式化好的字符串；用于想在同一条时间线上看到两端事件时。
///
/// # Safety
///
/// `msg` 必须指向一段以 NUL 结尾的有效 C 字符串，且在本次调用期间保持有效。
/// 传空指针会直接返回；非 UTF-8 内容会被忽略。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_diag_write(level: u8, msg: *const c_char) {
    let Some(text) = (unsafe { super::c_char_to_str(msg) }) else {
        return;
    };
    diag::log(level, text.to_string());
}

//! 诊断日志：进程内日志通道，零第三方依赖。
//!
//! ## 为什么需要它
//!
//! 本仓此前直接用 `eprintln!` 输出诊断信息。这在 `cargo run` 和测试里没问题，
//! 但 **Windows GUI 程序由用户双击启动时没有控制台**，stderr 句柄不存在，
//! 写入被直接丢弃——真实使用中等于零诊断能力，而这类问题只在用户机器上发生，
//! 开发机永远复现不出来。
//!
//! ## 三层设计
//!
//! - **环形缓冲**：最近 [`RING_CAPACITY`] 条常驻内存。宿主即使完全不接回调，
//!   也能在出问题后调 `muclip_diag_snapshot()` 一次性取走。这是「事后取证」能力，
//!   是这套设计的核心价值——不需要事先配置任何东西就已经在记录。
//! - **外部 sink**：宿主要实时日志（C# 写文件、Kotlin 写 logcat）就注册回调。
//! - **stderr 兜底**：有控制台时照常输出，方便开发期排查。可用
//!   [`set_stderr_enabled`] 关掉，避免 GUI 宿主每写一条付一次失败的 syscall。
//!
//! ## 两条硬约束
//!
//! 1. **绝不持锁调用 sink**。sink 是宿主代码，完全可能反过来调用本库任意 API；
//!    若此时仍持有内部锁，宿主一旦调用到需要同一把锁的函数就当场自死锁。
//!    所以 [`log`] 里的顺序是固定的：取 sink 句柄 → 立刻解锁 → 记环形缓冲
//!    → 写 stderr → 才调 sink。调整这个顺序前请先想清楚死锁场景。
//! 2. **级别过滤必须在格式化之前**。`log(LEVEL_DEBUG, format!(..))` 即使该级别
//!    不启用，`format!` 也已经执行完了。所以调用方一律走 [`log_warn!`] 这类宏，
//!    宏内部先问 [`enabled`] 再格式化。
//!
//! ## 用法
//!
//! ```
//! use muclip_core::{log_info, log_warn};
//! log_info!("服务已启动，端口 {}", 42424);
//! log_warn!("SQLite 加密未启用，key 参数被忽略");
//! ```

use std::collections::VecDeque;
use std::ffi::{CString, c_char};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};

/// 错误：功能不可用或数据可能受损，需要用户知晓。
pub const LEVEL_ERROR: u8 = 0;
/// 警告：功能降级但可继续（加密未生效、参数被忽略、重试中）。
pub const LEVEL_WARN: u8 = 1;
/// 信息：正常生命周期事件（启动、配对成功、传输完成）。默认级别。
pub const LEVEL_INFO: u8 = 2;
/// 调试：逐包 / 逐块级细节。默认关闭，打开会显著影响吞吐。
pub const LEVEL_DEBUG: u8 = 3;

/// 环形缓冲容量。单条约 200 字节，常驻约 100 KiB，对桌面/移动端都可忽略。
const RING_CAPACITY: usize = 512;

/// 宿主提供的日志接收器。
///
/// `msg` 以 NUL 结尾，**仅在本次调用期间有效**，宿主必须立即拷贝。
/// `level` 取值见 [`LEVEL_ERROR`] ~ [`LEVEL_DEBUG`]。
///
/// 在 sink 内**不要**调用本库的其他 API 以外的阻塞操作，也不要长时间占用线程。
pub type LogSink = extern "C" fn(level: u8, msg: *const c_char);

struct State {
    /// 最近若干条日志，`(level, formatted message)`。
    ring: Mutex<VecDeque<(u8, String)>>,
    /// 宿主回调。用 Mutex 而非 AtomicPtr，是为了让 `set_sink` 与并发 `log` 有明确顺序。
    sink: Mutex<Option<LogSink>>,
    min_level: AtomicU8,
    stderr_enabled: AtomicBool,
}

static STATE: OnceLock<State> = OnceLock::new();

fn state() -> &'static State {
    STATE.get_or_init(|| State {
        ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
        sink: Mutex::new(None),
        min_level: AtomicU8::new(LEVEL_INFO),
        stderr_enabled: AtomicBool::new(true),
    })
}

/// 该级别是否会被记录。
///
/// 存在的唯一理由是让 [`log_warn!`] 这类宏在**格式化之前**短路，
/// 避免为一条注定被丢弃的 DEBUG 日志付 `format!` 的代价。
#[inline]
pub fn enabled(level: u8) -> bool {
    level <= state().min_level.load(Ordering::Relaxed)
}

/// 记录一条日志。调用方应优先使用 [`log_error!`] / [`log_warn!`] / [`log_info!`] / [`log_debug!`]。
///
/// 本函数不会 panic：环形缓冲锁中毒时按「已恢复」处理（日志系统宁可有损也不能中断业务）。
pub fn log(level: u8, message: String) {
    let st = state();
    if level > st.min_level.load(Ordering::Relaxed) {
        return;
    }

    // 顺序有讲究，见模块文档「两条硬约束」第 1 条。
    let sink = *st.sink.lock().unwrap_or_else(|e| e.into_inner());

    {
        let mut ring = st.ring.lock().unwrap_or_else(|e| e.into_inner());
        if ring.len() >= RING_CAPACITY {
            ring.pop_front();
        }
        ring.push_back((level, message.clone()));
    }

    if st.stderr_enabled.load(Ordering::Relaxed) {
        let tag = match level {
            LEVEL_ERROR => "ERROR",
            LEVEL_WARN => "WARN ",
            LEVEL_INFO => "INFO ",
            _ => "DEBUG",
        };
        eprintln!("[MuClip][{tag}] {message}");
    }

    // 此处已不持有任何内部锁，可以安全地把控制权交给宿主。
    if let Some(cb) = sink {
        if let Ok(c) = CString::new(message) {
            cb(level, c.as_ptr());
        }
    }
}

/// 注册 / 注销宿主日志接收器。传 `None` 即注销。
pub fn set_sink(sink: Option<LogSink>) {
    let st = state();
    *st.sink.lock().unwrap_or_else(|e| e.into_inner()) = sink;
}

/// 设置最低记录级别。低于该级别的日志在格式化阶段就会被丢弃。
pub fn set_level(level: u8) {
    state()
        .min_level
        .store(level.min(LEVEL_DEBUG), Ordering::Relaxed);
}

/// 当前最低记录级别。
pub fn level() -> u8 {
    state().min_level.load(Ordering::Relaxed)
}

/// 开关 stderr 输出。GUI 宿主建议关闭，避免每条日志一次注定失败的写调用。
pub fn set_stderr_enabled(on: bool) {
    state().stderr_enabled.store(on, Ordering::Relaxed);
}

/// 取走环形缓冲里所有日志，并清空缓冲。
///
/// 返回 `(level, message)` 列表，按时间从旧到新排列。
/// 典型用途：宿主在「导出诊断信息」时调用，或崩溃现场取证。
pub fn drain() -> Vec<(u8, String)> {
    let st = state();
    let mut ring = st.ring.lock().unwrap_or_else(|e| e.into_inner());
    ring.drain(..).collect()
}

/// 环形缓冲的只读快照（不清空）。
pub fn snapshot() -> Vec<(u8, String)> {
    let st = state();
    let ring = st.ring.lock().unwrap_or_else(|e| e.into_inner());
    ring.iter().cloned().collect()
}

/// 级别数字转字符串，供快照序列化使用。
pub fn level_name(level: u8) -> &'static str {
    match level {
        LEVEL_ERROR => "error",
        LEVEL_WARN => "warn",
        LEVEL_INFO => "info",
        _ => "debug",
    }
}

/// 记录一条 ERROR 级日志。
#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if $crate::diag::enabled($crate::diag::LEVEL_ERROR) {
            $crate::diag::log($crate::diag::LEVEL_ERROR, format!($($arg)*));
        }
    };
}

/// 记录一条 WARN 级日志。
#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if $crate::diag::enabled($crate::diag::LEVEL_WARN) {
            $crate::diag::log($crate::diag::LEVEL_WARN, format!($($arg)*));
        }
    };
}

/// 记录一条 INFO 级日志。
#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if $crate::diag::enabled($crate::diag::LEVEL_INFO) {
            $crate::diag::log($crate::diag::LEVEL_INFO, format!($($arg)*));
        }
    };
}

/// 记录一条 DEBUG 级日志。默认级别下不会产生任何格式化开销。
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if $crate::diag::enabled($crate::diag::LEVEL_DEBUG) {
            $crate::diag::log($crate::diag::LEVEL_DEBUG, format!($($arg)*));
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 日志系统是全局状态，并行测试会互相干扰，所以本模块的用例串行执行。
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 本用例写入的日志前缀。其他测试线程可能同时往环形缓冲里写，
    /// 断言前必须先把自己那几条筛出来，否则测试会随机失败。
    const TAG: &str = "diag-test/";

    fn mine(items: Vec<(u8, String)>) -> Vec<(u8, String)> {
        items
            .into_iter()
            .filter(|(_, m)| m.starts_with(TAG))
            .collect()
    }

    fn reset() {
        set_level(LEVEL_INFO);
        set_stderr_enabled(false);
        set_sink(None);
        let _ = drain();
    }

    #[test]
    fn records_into_ring_and_drains_once() {
        let _g = guard();
        reset();

        log_info!("{TAG}hello {}", 42);
        log_warn!("{TAG}careful");

        let got = mine(drain());
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, LEVEL_INFO);
        assert_eq!(got[0].1, format!("{TAG}hello 42"));
        assert_eq!(got[1].0, LEVEL_WARN);
        assert_eq!(got[1].1, format!("{TAG}careful"));

        // drain 之后必须为空，否则宿主会重复上报
        assert!(mine(drain()).is_empty());
    }

    #[test]
    fn filters_below_min_level_without_formatting() {
        let _g = guard();
        reset();
        set_level(LEVEL_WARN);

        // 用副作用标记证明 DEBUG 分支连格式化都没执行
        let mut formatted = false;
        macro_rules! probe {
            () => {{
                formatted = true;
                "debug"
            }};
        }
        if enabled(LEVEL_DEBUG) {
            log(LEVEL_DEBUG, format!("{TAG}{}", probe!()));
        }
        assert!(!formatted, "低于级别的日志必须在格式化前短路");

        log_info!("{TAG}dropped");
        assert!(mine(drain()).is_empty(), "INFO 低于 WARN 门槛，不应入库");

        log_error!("{TAG}kept");
        assert_eq!(mine(drain()).len(), 1);

        set_level(LEVEL_INFO);
    }

    #[test]
    fn ring_capacity_is_bounded() {
        let _g = guard();
        reset();

        for i in 0..(RING_CAPACITY + 100) {
            log_info!("{TAG}line {i}");
        }
        let got = snapshot();
        assert_eq!(got.len(), RING_CAPACITY, "环形缓冲必须封顶");
        // 淘汰的是最旧的：留在尾部的一定是本次最后写入的那条
        assert_eq!(
            got.last().unwrap().1,
            format!("{TAG}line {}", RING_CAPACITY + 99)
        );
        let _ = drain();
    }

    /// 回归测试：sink 内部回头调用本库 API 不得死锁。
    /// `log` / `drain` / `set_level` 共用环形缓冲与 sink 两把锁，
    /// 若 sink 是在持锁状态下被调用，这里会直接挂死（表现为测试超时而非断言失败）。
    #[test]
    fn sink_calling_back_into_library_does_not_deadlock() {
        let _g = guard();
        reset();

        extern "C" fn reentrant_sink(level: u8, msg: *const c_char) {
            // 故意在 sink 里调回本模块：若 log() 持锁调 sink，这一句即死锁
            let n = crate::diag::snapshot().len();
            let _ = (level, n, msg);
            crate::diag::set_level(crate::diag::LEVEL_INFO);
        }

        set_sink(Some(reentrant_sink));
        log_error!("{TAG}trigger");
        set_sink(None);

        let got = mine(drain());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, format!("{TAG}trigger"));
    }

    #[test]
    fn level_names_are_stable() {
        // 宿主按字符串解析，改名即破坏兼容
        assert_eq!(level_name(LEVEL_ERROR), "error");
        assert_eq!(level_name(LEVEL_WARN), "warn");
        assert_eq!(level_name(LEVEL_INFO), "info");
        assert_eq!(level_name(LEVEL_DEBUG), "debug");
    }
}

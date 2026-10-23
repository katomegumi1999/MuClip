pub mod binary;
mod core;
mod pool_crypto;
mod sync;

pub use self::binary::*;
pub use self::core::*;
pub use self::pool_crypto::*;
pub use self::sync::*;

use jni::sys::{jint, jlong};

/// JNI 输出缓冲区的防御性容量上限（256 MiB）。
///
/// 实际使用中最大的是大段剪贴板文本（协议上限 16 MiB），以及 `limit` 很大的历史查询。
/// 这里取 256 MiB：既远高于任何正常需求（不误伤），又能挡住 `i32::MAX` 这类错误参数
/// 造成的灾难性越界写。
pub(crate) const MAX_FFI_OUT_BUFFER: usize = 256 * 1024 * 1024;

/// 把 Kotlin 传入的 `(裸地址, 声明容量)` 转成可写切片，并做防御性校验。
///
/// # Safety
///
/// 调用方（Kotlin 侧）必须保证：
/// - `ptr` 指向一块在**本次 JNI 调用期间有效**、且**独占可写（无别名）**的内存；
/// - `declared_cap` 不超过该内存的真实容量。
///
/// JNI 只传递裸地址，本函数**无法**验证真实容量，只能拦住明显异常的取值
/// （0、负数、被符号扩展成巨大数）。`declared_cap > MAX_FFI_OUT_BUFFER` 一律拒绝，
/// 避免单个错误参数直接造成上百 MB 的越界写。
///
/// 返回 `None` 时调用方必须立即返回错误码，不得继续写入。
pub(crate) unsafe fn out_slice_from_raw<'a>(
    ptr: jlong,
    declared_cap: jint,
) -> Option<&'a mut [u8]> {
    if ptr == 0 || declared_cap <= 0 {
        return None;
    }
    let cap = declared_cap as usize;
    if cap > MAX_FFI_OUT_BUFFER {
        return None;
    }
    Some(unsafe { std::slice::from_raw_parts_mut(ptr as usize as *mut u8, cap) })
}

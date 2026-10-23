use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

/// Alignment for off-heap direct memory buffers (64-byte alignment for cache line & SIMD).
const BUFFER_ALIGNMENT: usize = 64;

/// 归还到池中的单个缓冲区最大容量。
///
/// 池只限制缓存**个数**（`max_cached_buffers`），若不限单块大小，一次 16 MiB 的租约
/// 回收后会长期占坑，32 个超大块就是数百 MiB 常驻内存。超过此阈值的块直接释放，
/// 让 allocator 回收；这类大块本来就是低频路径（大剪贴板/大文件），重建成本可接受。
const MAX_CACHED_BUFFER_SIZE: usize = 1024 * 1024; // 1 MiB

/// 已租出但未归还的缓冲区数量告警阈值。
///
/// 本池不做过期强制回收——文件传输可能持续数分钟，强行回收未归还的块会导致
/// use-after-free。因此对泄漏只做可观测性：超过阈值时打一条告警，便于定位漏调
/// `muclip_pool_release` 的调用路径。
const RENTED_WARN_THRESHOLD: usize = 256;

/// A single allocated off-heap buffer block.
pub struct RawBuffer {
    pub ptr: *mut u8,
    pub capacity: usize,
    pub layout: Layout,
}

unsafe impl Send for RawBuffer {}
unsafe impl Sync for RawBuffer {}

impl RawBuffer {
    pub fn new(capacity: usize) -> Option<Self> {
        let aligned_cap = (capacity + BUFFER_ALIGNMENT - 1) & !(BUFFER_ALIGNMENT - 1);
        let layout = Layout::from_size_align(aligned_cap, BUFFER_ALIGNMENT).ok()?;
        let ptr = unsafe { alloc_zeroed(layout) };
        if ptr.is_null() {
            None
        } else {
            Some(Self {
                ptr,
                capacity: aligned_cap,
                layout,
            })
        }
    }
}

impl Drop for RawBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.layout.size() > 0 {
            unsafe {
                dealloc(self.ptr, self.layout);
            }
            self.ptr = std::ptr::null_mut();
        }
    }
}

/// Thread-safe off-heap native buffer pool.
/// Allows renting raw pointers with zero JVM heap overhead.
pub struct NativeBufferPool {
    free_buffers: Mutex<Vec<RawBuffer>>,
    rented_buffers: Mutex<HashMap<u64, RawBuffer>>,
    next_id: AtomicU64,
    default_chunk_size: usize,
    max_cached_buffers: usize,
}

impl NativeBufferPool {
    pub fn new(default_chunk_size: usize, max_cached_buffers: usize) -> Self {
        Self {
            free_buffers: Mutex::new(Vec::new()),
            rented_buffers: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            default_chunk_size: default_chunk_size.max(4096),
            max_cached_buffers: max_cached_buffers.max(8),
        }
    }

    /// Acquires a direct buffer of at least `min_capacity` bytes.
    /// Returns `(lease_id, raw_pointer, actual_capacity)`.
    pub fn acquire(&self, min_capacity: usize) -> Option<(u64, *mut u8, usize)> {
        let req_cap = min_capacity.max(self.default_chunk_size);
        let mut free = self.free_buffers.lock().ok()?;

        // Look for existing buffer with sufficient capacity
        let mut buffer = None;
        if let Some(pos) = free.iter().position(|b| b.capacity >= req_cap) {
            buffer = Some(free.swap_remove(pos));
        }

        // If not found in pool, allocate new off-heap block
        let buf = match buffer {
            Some(b) => b,
            None => RawBuffer::new(req_cap)?,
        };

        let ptr = buf.ptr;
        let cap = buf.capacity;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);

        let mut rented = self.rented_buffers.lock().ok()?;
        if rented.len() >= RENTED_WARN_THRESHOLD {
            crate::log_warn!(
                "内存池已租出 {} 个缓冲区未归还，可能存在 muclip_pool_release 漏调用",
                rented.len()
            );
        }
        rented.insert(id, buf);

        Some((id, ptr, cap))
    }

    /// Releases a rented buffer back to the pool by its lease ID.
    ///
    /// SECURITY: 归还前将整块内存清零。池里的块会被下一个租约直接复用，
    /// 若不清零，上一条文件传输/剪贴板的明文会残留在池中，被后续调用方读到——
    /// 这条路径会跨过 FFI/JNI 边界（Kotlin 侧拿到的就是同一块内存），
    /// 等于让敏感数据在语言边界上泄漏。
    pub fn release(&self, lease_id: u64) -> bool {
        let mut rented = match self.rented_buffers.lock() {
            Ok(r) => r,
            Err(_) => return false,
        };

        if let Some(buf) = rented.remove(&lease_id) {
            drop(rented);

            // 清零：即使这块稍后被丢弃而不是入池，也不留下明文
            if !buf.ptr.is_null() && buf.capacity > 0 {
                unsafe {
                    std::ptr::write_bytes(buf.ptr, 0, buf.capacity);
                }
            }

            // 超大块不缓存，交给 allocator 回收，避免池里长期占坑
            if buf.capacity > MAX_CACHED_BUFFER_SIZE {
                return true;
            }

            if let Ok(mut free) = self.free_buffers.lock() {
                if free.len() < self.max_cached_buffers {
                    free.push(buf);
                    return true;
                }
            }
            // If cache is full, dropping `buf` will automatically deallocate
            true
        } else {
            false
        }
    }

    /// Retrieves the pointer and capacity for an actively rented buffer.
    pub fn get_rented(&self, lease_id: u64) -> Option<(*mut u8, usize)> {
        let rented = self.rented_buffers.lock().ok()?;
        rented.get(&lease_id).map(|b| (b.ptr, b.capacity))
    }

    /// Clears and deallocates all free buffers in the pool.
    pub fn clear(&self) {
        if let Ok(mut free) = self.free_buffers.lock() {
            free.clear();
        }
    }

    /// 当前已租出但未归还的缓冲区数量（诊断泄漏用）。
    pub fn rented_count(&self) -> usize {
        self.rented_buffers.lock().map(|r| r.len()).unwrap_or(0)
    }
}

// Global default pool: 64KB chunks, max 32 cached buffers
static GLOBAL_POOL: std::sync::OnceLock<NativeBufferPool> = std::sync::OnceLock::new();

pub fn global_buffer_pool() -> &'static NativeBufferPool {
    GLOBAL_POOL.get_or_init(|| NativeBufferPool::new(64 * 1024, 32))
}

/// RAII lease wrapper around an off-heap buffer from `global_buffer_pool()`.
/// Automatically returns the rented block back to the pool when dropped.
pub struct PooledBuffer {
    lease_id: u64,
    ptr: *mut u8,
    capacity: usize,
}

unsafe impl Send for PooledBuffer {}
unsafe impl Sync for PooledBuffer {}

impl PooledBuffer {
    pub fn acquire(min_capacity: usize) -> Option<Self> {
        let (lease_id, ptr, capacity) = global_buffer_pool().acquire(min_capacity)?;
        Some(Self {
            lease_id,
            ptr,
            capacity,
        })
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.capacity) }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.capacity) }
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        global_buffer_pool().release(self.lease_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_pool_acquire_and_release() {
        let pool = NativeBufferPool::new(4096, 4);
        let (id1, ptr1, cap1) = pool.acquire(2048).expect("acquire buffer 1");
        assert!(!ptr1.is_null());
        assert!(cap1 >= 2048);

        // Write test data to off-heap memory
        unsafe {
            std::ptr::write_bytes(ptr1, 0xAA, 1024);
            let slice = std::slice::from_raw_parts(ptr1, 1024);
            assert_eq!(slice[0], 0xAA);
            assert_eq!(slice[1023], 0xAA);
        }

        assert!(pool.release(id1));

        // Re-acquire should reuse the cached block
        let (id2, ptr2, cap2) = pool.acquire(2048).expect("acquire buffer 2");
        assert_eq!(ptr1, ptr2);
        assert_eq!(cap1, cap2);
        assert_ne!(id1, id2);
        assert!(pool.release(id2));
    }

    /// 池中的块会被下一个租约直接复用。归还时若不清零，上一条传输的明文
    /// （经 FFI/JNI 边界由 Kotlin/C# 侧读同一块内存）就会泄露给后续调用方。
    #[test]
    fn test_release_zeroizes_buffer_before_reuse() {
        let pool = NativeBufferPool::new(4096, 4);
        let (id, ptr, cap) = pool.acquire(1024).expect("acquire");
        unsafe {
            std::ptr::write_bytes(ptr, 0xAB, cap);
        }
        assert!(pool.release(id));

        let (id2, ptr2, cap2) = pool.acquire(1024).expect("re-acquire");
        assert_eq!(ptr, ptr2, "小请求应复用池中缓存块");
        let slice = unsafe { std::slice::from_raw_parts(ptr2, cap2) };
        assert!(
            slice.iter().all(|&b| b == 0),
            "归还时必须清零，否则上一次的明文会被下一个租约读到"
        );
        assert!(pool.release(id2));
    }

    /// 超大块不得长期占用池容量（池只限个数，不限单块大小）。
    #[test]
    fn test_oversized_buffer_is_not_cached() {
        let pool = NativeBufferPool::new(4096, 8);
        let (id, _ptr, cap) = pool.acquire(2 * 1024 * 1024).expect("acquire big");
        assert!(cap > MAX_CACHED_BUFFER_SIZE, "请求应拿到超过缓存阈值的大块");
        assert!(pool.release(id));
        assert_eq!(
            pool.free_buffers.lock().unwrap().len(),
            0,
            "超过 MAX_CACHED_BUFFER_SIZE 的块必须直接释放，不能入池"
        );
        assert_eq!(pool.rented_count(), 0);
    }
}

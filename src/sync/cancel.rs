//! 阻塞 IO 的取消原语。
//!
//! 大文件传输与 PFS 会话握手都会被一个「对端不说话」的 socket 卡住，用户点取消时
//! 必须能把线程从 `read` / `write` 里拽出来。这里放的是两边共用的最小机制，
//! 不掺任何业务语义 —— 谁需要取消，谁自己持有 [`CancelToken`]。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// 单次操作的取消令牌。
///
/// 只有 `AtomicBool` 是不够的：传输线程可能正阻塞在 `read_exact` / `write_all`
/// 上（对端不发数据、或接收端不读 socket），此时它根本没机会回到循环开头去检查
/// 标志位。所以真正让取消生效的是下面那对 `*_cancellable` IO 辅助函数里的
/// 「短超时轮询」。
///
/// **为什么不用 `shutdown()` 打断阻塞读**：Windows 上 `shutdown()` 只会改变 socket
/// 状态，**不会唤醒已经阻塞在 `recv()` 上的调用**（Linux 会）。实测对一个
/// `try_clone()` 出来的句柄调用 `shutdown(Both)`，阻塞中的 read 依然要等到对端发
/// 数据或读超时才返回。因此这里走跨平台一致的超时轮询，不依赖 shutdown 的语义差异。
pub(crate) struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub(crate) fn new() -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// 置位取消标志。真正的停止动作发生在下一次 IO 轮询检查时。
    pub(crate) fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }
}

/// 取消轮询间隔：每次读写超时后都会回来检查一次取消标志。
/// 直接决定用户点「取消」到真正停下的延迟上限。
pub(crate) const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// 相邻两次「有进展」之间允许的最长空闲时间。
///
/// 超时轮询只是为了能感知取消，**不能**把「对端死了」的判定缩短到 200ms，
/// 否则慢速对端会被误判成断线。真正的活死判定仍用这个值（与原 30s 读超时一致）。
pub(crate) const TRANSFER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// 可取消 IO 的失败原因。
///
/// 必须把 `Cancelled` 和真正的 IO 失败区分开：取消是我们自己触发的，若上报成
/// 网络错误，上层会提示「传输失败，请检查网络」，把一次正常操作说成事故。
#[derive(Debug)]
pub(crate) enum IoAbort {
    Cancelled,
    Io(std::io::Error),
}

/// 超时类错误：Windows 返回 `TimedOut`（WSAETIMEDOUT），Unix 返回 `WouldBlock`。
fn is_poll_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// `read_exact` 的可取消版本：保证读满 `buf`，但每 `CANCEL_POLL_INTERVAL` 回来
/// 检查一次取消标志。
///
/// 不能直接用 `read_exact` + 短超时：`read_exact` 中途超时会丢失「已经读了多少」，
/// 这部分数据就永久错位了（后续 chunk 全部解密失败）。所以这里自己维护 `filled`。
///
/// **前提**：调用方必须已把 socket 的读写超时设成 `CANCEL_POLL_INTERVAL`，
/// 否则一次 `read` 就会阻塞到原来的长超时，轮询形同虚设。
pub(crate) fn read_exact_cancellable(
    stream: &mut TcpStream,
    buf: &mut [u8],
    cancel: &CancelToken,
) -> Result<(), IoAbort> {
    read_exact_cancellable_split(stream, &mut [buf], cancel)
}

/// 一次读满多个区段，空闲计时跨区段连续。
///
/// 为什么不做成两次独立调用：两段之间若各自重新计时，「30s 无进展」的判定就会
/// 被悄悄放大成「每段各 30s」。需要在同一口气里读完的区段，交给本函数。
///
/// 注意：调用方只有在**事先知道各段长度**时才能用上。像「先读 44 字节头、
/// 解析出载荷长度再读载荷」这种有依赖的读取天然只能分两次，边界上空闲计时会重置
/// 一次——这个缺口只在对端恰好卡在帧边界时存在，可以接受。
pub(crate) fn read_exact_cancellable_split(
    stream: &mut TcpStream,
    parts: &mut [&mut [u8]],
    cancel: &CancelToken,
) -> Result<(), IoAbort> {
    let mut last_progress = Instant::now();
    for part in parts.iter_mut() {
        let mut filled = 0usize;
        while filled < part.len() {
            if cancel.is_cancelled() {
                return Err(IoAbort::Cancelled);
            }
            match stream.read(&mut part[filled..]) {
                Ok(0) => {
                    return Err(IoAbort::Io(std::io::Error::from(
                        std::io::ErrorKind::UnexpectedEof,
                    )));
                }
                Ok(n) => {
                    filled += n;
                    last_progress = Instant::now();
                }
                Err(ref e) if is_poll_timeout(e) => {
                    if last_progress.elapsed() >= TRANSFER_IDLE_TIMEOUT {
                        return Err(IoAbort::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "peer idle timeout: no data for 30s",
                        )));
                    }
                    // 继续下一轮 —— 回到循环顶部就会检查取消标志
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(IoAbort::Io(e)),
            }
        }
    }
    Ok(())
}

/// `write_all` 的可取消版本。语义与 `read_exact_cancellable` 对称。
pub(crate) fn write_all_cancellable(
    stream: &mut TcpStream,
    buf: &[u8],
    cancel: &CancelToken,
) -> Result<(), IoAbort> {
    let mut written = 0usize;
    let mut last_progress = Instant::now();
    while written < buf.len() {
        if cancel.is_cancelled() {
            return Err(IoAbort::Cancelled);
        }
        match stream.write(&buf[written..]) {
            Ok(0) => {
                return Err(IoAbort::Io(std::io::Error::from(
                    std::io::ErrorKind::WriteZero,
                )));
            }
            Ok(n) => {
                written += n;
                last_progress = Instant::now();
            }
            Err(ref e) if is_poll_timeout(e) => {
                if last_progress.elapsed() >= TRANSFER_IDLE_TIMEOUT {
                    return Err(IoAbort::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "peer not reading: write stalled for 30s",
                    )));
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(IoAbort::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    /// 可取消读必须能在对端静默时按轮询间隔返回，而不是等满 30s 空闲超时。
    #[test]
    fn cancellable_read_returns_on_cancel_while_peer_silent() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let _server = std::thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            // 保持连接但一个字节都不发
            std::thread::sleep(Duration::from_secs(3));
            drop(socket);
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(CANCEL_POLL_INTERVAL)).unwrap();

        let token = Arc::new(CancelToken::new());
        let canceller = Arc::clone(&token);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            canceller.cancel();
        });

        let mut buf = [0u8; 4096];
        let started = Instant::now();
        let result = read_exact_cancellable(&mut stream, &mut buf, &token);
        let elapsed = started.elapsed();

        assert!(matches!(result, Err(IoAbort::Cancelled)));
        // 300ms 置位 + 200ms 轮询 + 余量
        assert!(
            elapsed < Duration::from_millis(1500),
            "取消应在轮询间隔内生效，实际耗时 {elapsed:?}"
        );
    }

    /// 分区读取（header + payload）在取消时也必须干净返回，且不误报分区间空闲超时。
    #[test]
    fn split_read_completes_across_two_parts() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.write_all(b"ABCDEFGH").unwrap();
            socket.write_all(b"1234").unwrap();
            std::thread::sleep(Duration::from_millis(300));
            drop(socket);
        });

        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let token = CancelToken::new();

        let mut head = [0u8; 8];
        let mut tail = [0u8; 4];
        {
            let mut parts: [&mut [u8]; 2] = [&mut head, &mut tail];
            read_exact_cancellable_split(&mut stream, &mut parts, &token).unwrap();
        }
        assert_eq!(&head, b"ABCDEFGH");
        assert_eq!(&tail, b"1234");
        server.join().unwrap();
    }
}

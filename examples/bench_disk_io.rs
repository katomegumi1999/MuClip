//! 磁盘 I/O 与串行 / 流水线对比：这些环节各自吃掉多少时间。
//! 运行：cargo run --release --example bench_disk_io
//!
//! 网络侧的精确归因见 `bench_pipeline`，端到端文件传输见 `bench_transfer`。

use muclip_core::sync::crypto::{TAG_SIZE, build_chunk_aad, derive_key, encrypt_in_place_with_aad};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const TOTAL: u64 = 256 * 1024 * 1024;

fn mbps(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn tmpfile(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("muclip_bp_{}_{}", tag, rand::random::<u32>()));
    let _ = std::fs::remove_file(&p);
    p
}

fn make_src(path: &std::path::Path) {
    let mut f = std::fs::File::create(path).unwrap();
    let block = vec![0xA7u8; 1024 * 1024];
    for _ in 0..(TOTAL / (1024 * 1024)) as usize {
        f.write_all(&block).unwrap();
    }
    f.flush().unwrap();
}

/// A. 磁盘顺序读：128KiB vs 1MiB 读块
fn bench_disk_read(path: &std::path::Path) {
    for &cs in &[128 * 1024usize, 1024 * 1024] {
        let mut f = std::fs::File::open(path).unwrap();
        let mut buf = vec![0u8; cs];
        // 预热
        let _ = f.read_exact(&mut buf);
        let t0 = Instant::now();
        let mut n = 0u64;
        while n < TOTAL {
            if f.read_exact(&mut buf).is_err() {
                break;
            }
            n += cs as u64;
        }
        let el = t0.elapsed().as_secs_f64();
        println!(
            "[DISK-READ ]  {:>5} KiB/read  => {:>7.1} MiB/s",
            cs / 1024,
            mbps(n, el)
        );
    }
}

/// B. 磁盘顺序写：裸 write_all(128KiB)  vs  BufWriter(1MiB)  vs  BufWriter+sync_all
fn bench_disk_write() {
    for &cs in &[128 * 1024usize, 1024 * 1024] {
        let p = tmpfile("w");
        let data = vec![0x5Au8; cs];
        let t0 = Instant::now();
        let mut f = std::fs::File::create(&p).unwrap();
        for _ in 0..(TOTAL / cs as u64) {
            f.write_all(&data).unwrap();
        }
        f.flush().unwrap();
        let el = t0.elapsed().as_secs_f64();
        println!(
            "[DISK-WRITE]  {:>5} KiB/write (裸 write_all) => {:>7.1} MiB/s",
            cs / 1024,
            mbps(TOTAL, el)
        );
        drop(f);
        let _ = std::fs::remove_file(&p);
    }

    for &cs in &[128 * 1024usize, 1024 * 1024] {
        let p = tmpfile("bw");
        let data = vec![0x5Au8; cs];
        let t0 = Instant::now();
        {
            let f = std::fs::File::create(&p).unwrap();
            let mut bw = std::io::BufWriter::with_capacity(1024 * 1024, f);
            for _ in 0..(TOTAL / cs as u64) {
                bw.write_all(&data).unwrap();
            }
            bw.flush().unwrap();
        }
        let el = t0.elapsed().as_secs_f64();
        println!(
            "[DISK-WRITE]  {:>5} KiB/write (BufWriter 1MiB)  => {:>7.1} MiB/s",
            cs / 1024,
            mbps(TOTAL, el)
        );
        let _ = std::fs::remove_file(&p);
    }

    // 单独量化 sync_all 的固定代价（这是接收端必经的一步）
    let p = tmpfile("sync");
    {
        let f = std::fs::File::create(&p).unwrap();
        let mut bw = std::io::BufWriter::with_capacity(1024 * 1024, f);
        let data = vec![0x5Au8; 1024 * 1024];
        for _ in 0..(TOTAL / (1024 * 1024)) {
            bw.write_all(&data).unwrap();
        }
        bw.flush().unwrap();
    }
    let t0 = Instant::now();
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.sync_all().unwrap();
    let el = t0.elapsed().as_secs_f64();
    println!(
        "[SYNC_ALL ]  固定刷盘代价 on {} MiB file => {:.3}s  <-- 全部发生在 ACK 之前",
        TOTAL / 1024 / 1024,
        el
    );
    drop(f);
    let _ = std::fs::remove_file(&p);
}

/// C. 核心对照：当前「串行」设计 vs 「流水线」设计，环回 TCP 上跑同样的加解密负载
fn bench_serial_vs_pipelined() {
    let key = derive_key("bench-pin", None).unwrap();

    // ---- C1. 串行：read -> hash -> encrypt -> write（与现有 sender.rs 完全同构）
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let src = tmpfile("serial");
        make_src(&src);

        let rx = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
            let mut scratch = vec![0u8; 256 * 1024];
            let mut got = 0u64;
            while got < TOTAL {
                let want = std::cmp::min(scratch.len() as u64, TOTAL - got) as usize;
                if s.read_exact(&mut scratch[..want]).is_err() {
                    break;
                }
                got += want as u64;
            }
            got
        });

        let t0 = Instant::now();
        let mut f = std::fs::File::open(&src).unwrap();
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_nodelay(true).unwrap();
        let mut hasher = Sha256::new();
        // 与 sender.rs 完全同构：同一块buffer 先读明文、再原地加密、再把tag 追加到尾部
        let mut buf = vec![0u8; 128 * 1024 + TAG_SIZE];
        let mut aad = [0u8; 57];
        let mut n = 0u64;
        let mut idx = 0u64;
        while n < TOTAL {
            let want = std::cmp::min(128 * 1024usize, (TOTAL - n) as usize);
            if f.read_exact(&mut buf[..want]).is_err() {
                break;
            }
            hasher.update(&buf[..want]);
            build_chunk_aad(1, b"bench", idx, want as u32, TOTAL, &mut aad);
            let tag = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf[..want]).unwrap();
            buf[want..want + TAG_SIZE].copy_from_slice(&tag);
            stream.write_all(&buf[..want + TAG_SIZE]).unwrap();
            n += want as u64;
            idx += 1;
        }
        let el = t0.elapsed().as_secs_f64();
        let _got = rx.join().unwrap();
        println!(
            "[SERIAL   ]  read+hash+encrypt+write 单线程 => {:>7.1} MiB/s",
            mbps(n, el)
        );
        let _ = std::fs::remove_file(&src);
    }

    // ---- C2. 流水线：读盘线程 -> 加密线程 -> socket，独立背压缓冲
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let src = tmpfile("pipe");
        make_src(&src);

        let rx = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
            let mut scratch = vec![0u8; 256 * 1024];
            let mut got = 0u64;
            while got < TOTAL {
                let want = std::cmp::min(scratch.len() as u64, TOTAL - got) as usize;
                if s.read_exact(&mut scratch[..want]).is_err() {
                    break;
                }
                got += want as u64;
            }
            got
        });

        let t0 = Instant::now();
        let stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_nodelay(true).unwrap();
        let s = stream.try_clone().unwrap();

        let (raw_tx, raw_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (enc_tx, enc_rx) = std::sync::mpsc::channel::<Vec<u8>>();

        // 读盘 + SHA
        let reader = std::thread::spawn({
            let src = src.clone();
            move || {
                let mut f = std::fs::File::open(&src).unwrap();
                let mut hasher = Sha256::new();
                let mut buf = vec![0u8; 256 * 1024];
                let mut n = 0u64;
                while n < TOTAL {
                    if f.read_exact(&mut buf).is_err() {
                        break;
                    }
                    hasher.update(&buf);
                    let _ = hasher;
                    let _ = raw_tx.send(buf.clone());
                    n += buf.len() as u64;
                }
            }
        });

        // 加密
        let enc = std::thread::spawn(move || {
            let mut aad = [0u8; 57];
            let mut idx = 0u64;
            for mut chunk in raw_rx {
                build_chunk_aad(1, b"bench", idx, chunk.len() as u32, TOTAL, &mut aad);
                let tag = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut chunk).unwrap();
                chunk.extend_from_slice(&tag);
                let _ = enc_tx.send(chunk);
                idx += 1;
            }
        });

        // 写 socket
        let mut n = 0u64;
        let mut wr = s;
        for chunk in enc_rx {
            n += chunk.len() as u64;
            wr.write_all(&chunk).unwrap();
        }
        let el = t0.elapsed().as_secs_f64();
        let _got = rx.join().unwrap();
        let _ = reader.join();
        let _ = enc.join();
        println!(
            "[PIPELINED]  读盘||加密||写socket 三级流水线   => {:>7.1} MiB/s",
            mbps(n, el)
        );
        let _ = std::fs::remove_file(&src);
    }
}

fn main() {
    println!("=== 定位 E2E 损耗来源 ===\n");
    let src = tmpfile("main");
    make_src(&src);
    bench_disk_read(&src);
    println!();
    bench_disk_write();
    println!();
    bench_serial_vs_pipelined();
    let _ = std::fs::remove_file(&src);
}

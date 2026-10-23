//! 精确归因：真实 TCP 上限 / 生产同构双端 / 流水线改造后的收益。
//! 运行：cargo run --release --example bench_pipeline
//!
//! 磁盘侧与串行对比见 `bench_disk_io`，端到端文件传输见 `bench_transfer`。
//!
//! 注：不能用 std::io::copy 测 TCP 上限——它对 TcpStream 只用 8 KiB 内部缓冲，
//! 会把上限压低到~700 MiB/s，产生"流水线比裸 TCP 还快"的伪矛盾。

use muclip_core::sync::crypto::{
    TAG_SIZE, build_chunk_aad, decrypt_in_place_with_aad, derive_key, encrypt_in_place_with_aad,
};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

const TOTAL: u64 = 256 * 1024 * 1024;
const CHUNK: usize = 128 * 1024;
const PROTOCOL_VERSION: u8 = 1;

fn mbps(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn tmpfile(tag: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("muclip_v2_{}_{}", tag, rand::random::<u32>()));
    let _ = std::fs::remove_file(&p);
    p
}

fn make_src(path: &std::path::Path) {
    let mut f = std::fs::File::create(path).unwrap();
    let block = vec![0xA7u8; 1024 * 1024];
    for _ in 0..(TOTAL / (1024 * 1024)) {
        f.write_all(&block).unwrap();
    }
    f.flush().unwrap();
}

fn spawn_dumb_receiver(listener: TcpListener) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(180))).unwrap();
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
    })
}

fn connect(port: u16) -> TcpStream {
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_nodelay(true).unwrap();
    let _ = socket2::SockRef::from(&s).set_send_buffer_size(4 * 1024 * 1024);
    let _ = socket2::SockRef::from(&s).set_recv_buffer_size(4 * 1024 * 1024);
    s
}

fn listener() -> (TcpListener, u16) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let p = l.local_addr().unwrap().port();
    (l, p)
}

/// 1. 真实 TCP 上限：128 KiB write_all，与生产写侧完全一致的块大小
fn bench_true_tcp_ceiling() {
    let (l, port) = listener();
    let rx = spawn_dumb_receiver(l);
    let mut s = connect(port);
    let t0 = Instant::now();
    let buf = vec![0x11u8; CHUNK];
    let mut n = 0u64;
    while n < TOTAL {
        s.write_all(&buf).unwrap();
        n += CHUNK as u64;
    }
    let el = t0.elapsed().as_secs_f64();
    let got = rx.join().unwrap();
    println!(
        "[TCP-CEILING ] 128 KiB write_all, dumb receiver      => {:>7.1} MiB/s (recv {} MiB)",
        mbps(n, el),
        got / 1024 / 1024
    );
}

/// 2. 生产同构：串行发送端（读盘+sha+加密+write）+ 串行接收端（read+解密+sha+落盘）
fn bench_production_shape() {
    let key = derive_key("bench-pin", None).unwrap();
    let src = tmpfile("prod");
    make_src(&src);
    let dst = tmpfile("prod_out");
    let (l, port) = listener();

    let rx = std::thread::spawn({
        let key = key;
        let dst = dst.clone();
        move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(180))).unwrap();
            let mut f = std::fs::File::create(&dst).unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; CHUNK + TAG_SIZE];
            let mut aad = [0u8; 57];
            let mut got = 0u64;
            let mut idx = 0u64;
            while got < TOTAL {
                let want = std::cmp::min(CHUNK as u64, TOTAL - got) as usize;
                if s.read_exact(&mut buf[..want + TAG_SIZE]).is_err() {
                    break;
                }
                build_chunk_aad(
                    PROTOCOL_VERSION,
                    b"bench",
                    idx,
                    want as u32,
                    TOTAL,
                    &mut aad,
                );
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&buf[want..want + TAG_SIZE]);
                if decrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf[..want], &tag)
                    .is_err()
                {
                    break;
                }
                f.write_all(&buf[..want]).unwrap();
                hasher.update(&buf[..want]);
                got += want as u64;
                idx += 1;
            }
            f.sync_all().unwrap();
            got
        }
    });

    let t0 = Instant::now();
    let mut f = std::fs::File::open(&src).unwrap();
    let mut s = connect(port);
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK + TAG_SIZE];
    let mut aad = [0u8; 57];
    let mut n = 0u64;
    let mut idx = 0u64;
    while n < TOTAL {
        let want = std::cmp::min(CHUNK as u64, TOTAL - n) as usize;
        if f.read_exact(&mut buf[..want]).is_err() {
            break;
        }
        hasher.update(&buf[..want]);
        build_chunk_aad(
            PROTOCOL_VERSION,
            b"bench",
            idx,
            want as u32,
            TOTAL,
            &mut aad,
        );
        let tag = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf[..want]).unwrap();
        buf[want..want + TAG_SIZE].copy_from_slice(&tag);
        s.write_all(&buf[..want + TAG_SIZE]).unwrap();
        n += want as u64;
        idx += 1;
    }
    let el = t0.elapsed().as_secs_f64();
    let got = rx.join().unwrap();
    println!(
        "[PRODUCTION  ] 串行发送 + 串行接收（当前实现形状）=> {:>7.1} MiB/s (recv {} MiB)",
        mbps(got, el),
        got / 1024 / 1024
    );
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

/// 3. 发送端三级流水线 + 接收端串行 —— 隔离「发送端串行化」单独的收益
fn bench_pipelined_sender_only() {
    let key = derive_key("bench-pin", None).unwrap();
    let src = tmpfile("ps");
    make_src(&src);
    let dst = tmpfile("ps_out");
    let (l, port) = listener();

    let rx = std::thread::spawn({
        let key = key;
        let dst = dst.clone();
        move || {
            let (mut s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(180))).unwrap();
            let mut f = std::fs::File::create(&dst).unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; CHUNK + TAG_SIZE];
            let mut aad = [0u8; 57];
            let mut got = 0u64;
            let mut idx = 0u64;
            while got < TOTAL {
                let want = std::cmp::min(CHUNK as u64, TOTAL - got) as usize;
                if s.read_exact(&mut buf[..want + TAG_SIZE]).is_err() {
                    break;
                }
                build_chunk_aad(
                    PROTOCOL_VERSION,
                    b"bench",
                    idx,
                    want as u32,
                    TOTAL,
                    &mut aad,
                );
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&buf[want..want + TAG_SIZE]);
                if decrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf[..want], &tag)
                    .is_err()
                {
                    break;
                }
                f.write_all(&buf[..want]).unwrap();
                hasher.update(&buf[..want]);
                got += want as u64;
                idx += 1;
            }
            f.sync_all().unwrap();
            got
        }
    });

    let t0 = Instant::now();
    let s = connect(port);
    let (raw_tx, raw_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);
    let (enc_tx, enc_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);

    let reader = std::thread::spawn({
        let src = src.clone();
        move || {
            let mut f = std::fs::File::open(&src).unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; CHUNK];
            let mut n = 0u64;
            while n < TOTAL {
                if f.read_exact(&mut buf).is_err() {
                    break;
                }
                hasher.update(&buf);
                let _ = hasher;
                if raw_tx.send(buf.clone()).is_err() {
                    break;
                }
                n += CHUNK as u64;
            }
        }
    });

    let enc = std::thread::spawn(move || {
        let mut aad = [0u8; 57];
        let mut idx = 0u64;
        for mut chunk in raw_rx {
            build_chunk_aad(
                PROTOCOL_VERSION,
                b"bench",
                idx,
                chunk.len() as u32,
                TOTAL,
                &mut aad,
            );
            let tag = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut chunk).unwrap();
            chunk.extend_from_slice(&tag);
            let _ = chunk;
            let _ = enc_tx.send(chunk);
            idx += 1;
        }
    });

    let mut s = s;
    for chunk in enc_rx {
        if s.write_all(&chunk).is_err() {
            break;
        }
    }
    let el = t0.elapsed().as_secs_f64();
    let got = rx.join().unwrap();
    let _ = reader.join();
    let _ = enc.join();
    println!(
        "[PIPE-SENDER ] 流水线发送 + 串行接收              => {:>7.1} MiB/s (recv {} MiB)",
        mbps(got, el),
        got / 1024 / 1024
    );
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

/// 4. 双端全流水线：发送端读盘||加密||写，接收端 read+解密+sha || BufWriter 落盘
fn bench_fully_pipelined() {
    let key = derive_key("bench-pin", None).unwrap();
    let src = tmpfile("fp");
    make_src(&src);
    let dst = tmpfile("fp_out");
    let (l, port) = listener();

    // ---- 接收端
    let rx = std::thread::spawn({
        let key = key;
        let dst = dst.clone();
        move || {
            let (s, _) = l.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(180))).unwrap();
            let mut r = s.try_clone().unwrap();
            // 读密文 + 解密 + sha + BufWriter 落盘（接收端流水线：网络读与解密解耦）
            let f = std::fs::File::create(&dst).unwrap();
            let mut bw = std::io::BufWriter::with_capacity(1024 * 1024, f);
            let mut aad = [0u8; 57];
            let mut buf = vec![0u8; CHUNK + TAG_SIZE];
            let mut got = 0u64;
            let mut idx = 0u64;
            let mut hasher = Sha256::new();
            while got < TOTAL {
                let want = std::cmp::min(CHUNK as u64, TOTAL - got) as usize;
                if r.read_exact(&mut buf[..want + TAG_SIZE]).is_err() {
                    break;
                }
                build_chunk_aad(
                    PROTOCOL_VERSION,
                    b"bench",
                    idx,
                    want as u32,
                    TOTAL,
                    &mut aad,
                );
                let mut tag = [0u8; TAG_SIZE];
                tag.copy_from_slice(&buf[want..want + TAG_SIZE]);
                if decrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf[..want], &tag)
                    .is_err()
                {
                    break;
                }
                hasher.update(&buf[..want]);
                bw.write_all(&buf[..want]).unwrap();
                got += want as u64;
                idx += 1;
            }
            let _ = hasher;
            let f = bw.into_inner().unwrap();
            f.sync_all().unwrap();
            got
        }
    });

    // ---- 发送端（与 bench_pipelined_sender 相同）
    let s = connect(port);
    let (raw_tx, raw_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);
    let (enc_tx, enc_rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(16);

    let reader = std::thread::spawn({
        let src = src.clone();
        move || {
            let mut f = std::fs::File::open(&src).unwrap();
            let mut hasher = Sha256::new();
            let mut buf = vec![0u8; CHUNK];
            let mut n = 0u64;
            while n < TOTAL {
                if f.read_exact(&mut buf).is_err() {
                    break;
                }
                hasher.update(&buf);
                let _ = hasher;
                if raw_tx.send(buf.clone()).is_err() {
                    break;
                }
                n += CHUNK as u64;
            }
        }
    });

    let enc = std::thread::spawn(move || {
        let mut aad = [0u8; 57];
        let mut idx = 0u64;
        for mut chunk in raw_rx {
            build_chunk_aad(
                PROTOCOL_VERSION,
                b"bench",
                idx,
                chunk.len() as u32,
                TOTAL,
                &mut aad,
            );
            let tag = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut chunk).unwrap();
            chunk.extend_from_slice(&tag);
            let _ = enc_tx.send(chunk);
            idx += 1;
        }
    });

    let t0 = Instant::now();
    let mut s = s;
    for chunk in enc_rx {
        if s.write_all(&chunk).is_err() {
            break;
        }
    }
    let el = t0.elapsed().as_secs_f64();
    let got = rx.join().unwrap();
    let _ = reader.join();
    let _ = enc.join();
    println!(
        "[PIPE-BOTH   ] 流水线发送 + 流水线接收(BufWriter)  => {:>7.1} MiB/s (recv {} MiB)",
        mbps(got, el),
        got / 1024 / 1024
    );
    let _ = std::fs::remove_file(&src);
    let _ = std::fs::remove_file(&dst);
}

fn main() {
    println!("=== 精确归因（256 MiB, 128 KiB chunk）===\n");
    bench_true_tcp_ceiling();
    println!();
    bench_production_shape();
    println!();
    bench_pipelined_sender_only();
    println!();
    bench_fully_pipelined();
}

//! 文件传输性能基准：定位瓶颈环节。
//! 运行：cargo run --release --example bench_transfer

use muclip_core::sync::crypto::{derive_key, encrypt_in_place_with_aad};
use muclip_core::sync::file_transfer::FileTransferManager;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const CHUNK: usize = 128 * 1024;
const TOTAL_MB: usize = 64;

fn mbps(bytes: u64, secs: f64) -> f64 {
    (bytes as f64 / (1024.0 * 1024.0)) / secs
}

fn bench_encrypt_only() {
    let key = derive_key("bench-pin", None).unwrap();
    let mut buf = vec![0x5Au8; CHUNK];
    let aad = [0u8; 57];
    for _ in 0..10 {
        let _ = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf);
    }
    let iters = 200;
    let t0 = Instant::now();
    for _ in 0..iters {
        let _ = encrypt_in_place_with_aad(&key, &[0u8; 24], &aad, &mut buf);
    }
    let el = t0.elapsed().as_secs_f64();
    let bytes = (iters * CHUNK) as u64;
    println!(
        "[ENCRYPT-ONLY] {} MiB in {:.3}s => {:.1} MiB/s ({:.0} chunks/s)",
        bytes / 1024 / 1024,
        el,
        mbps(bytes, el),
        iters as f64 / el
    );
}

fn bench_sha256_only() {
    let buf = vec![0x33u8; CHUNK];
    let mut h = Sha256::new();
    let iters = 400;
    let t0 = Instant::now();
    for _ in 0..iters {
        h.update(&buf);
    }
    let el = t0.elapsed().as_secs_f64();
    let _ = h.finalize();
    let bytes = (iters * CHUNK) as u64;
    println!(
        "[SHA256-ONLY]   {} MiB in {:.3}s => {:.1} MiB/s",
        bytes / 1024 / 1024,
        el,
        mbps(bytes, el)
    );
}

fn bench_raw_tcp_loopback() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let total_bytes = (TOTAL_MB * 1024 * 1024) as u64;

    let rx = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        let mut got = 0u64;
        let mut scratch = vec![0u8; CHUNK];
        while got < total_bytes {
            let want = std::cmp::min(CHUNK as u64, total_bytes - got) as usize;
            if s.read_exact(&mut scratch[..want]).is_err() {
                break;
            }
            got += want as u64;
        }
        got
    });

    let t0 = Instant::now();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream.set_nodelay(true).unwrap();
    let sent = std::io::copy(&mut std::io::repeat(0x11).take(total_bytes), &mut stream).unwrap();
    let el = t0.elapsed().as_secs_f64();
    let got = rx.join().unwrap();
    println!(
        "[RAW-TCP] sent {} MiB / recv {} MiB in {:.3}s => {:.1} MiB/s",
        sent / 1024 / 1024,
        got / 1024 / 1024,
        el,
        mbps(sent as u64, el)
    );
}

fn bench_end_to_end_real_pipeline() {
    // 注意：`FileTransferManager::send_file` 现在**强制**在数据流上先做 PFS 会话握手，
    // 所以旧版本这里那个「裸 TcpListener + 手工 decode_file_offer_packet」的假接收端
    // 已经无法工作（它会把 SESSION_INIT 帧当成 FILE_OFFER 去解，直接 panic）。
    // 要测真实 E2E 就只能起一个真正的 SyncServer，让生产代码自己完成握手。
    use muclip_core::sync::discovery::PeerManager;
    use muclip_core::sync::transport::{LoopbackFilter, SyncServer};
    use std::sync::RwLock;

    let key = derive_key("bench-pin", None).unwrap();

    let tmp = std::env::temp_dir().join(format!("muclip_bench_{}", rand::random::<u32>()));
    let recv_dir = tmp.join("recv");
    std::fs::create_dir_all(&recv_dir).unwrap();
    let src = tmp.join("bench.bin");

    let total = (TOTAL_MB * 1024 * 1024) as u64;
    {
        let mut f = std::fs::File::create(&src).unwrap();
        let block = vec![0xA7u8; 1024 * 1024];
        for _ in 0..TOTAL_MB {
            f.write_all(&block).unwrap();
        }
        f.flush().unwrap();
    }

    let progress_calls = Arc::new(AtomicU64::new(0));
    let pc = Arc::clone(&progress_calls);

    let recv_mgr = Arc::new(FileTransferManager::new(&recv_dir));
    recv_mgr.set_progress_callback(Arc::new(move |_t, _x, _y, _s, _send| {
        pc.fetch_add(1, Ordering::Relaxed);
    }));

    // 发送方必须已在接收方的配对白名单里，否则服务端会在握手阶段直接拒绝
    let peer_mgr = Arc::new(PeerManager::new("bench-fp".into()));
    peer_mgr.add_paired_device_id("devA".into());

    let server = SyncServer::new(
        "devB".into(),
        "Receiver".into(),
        Arc::new(RwLock::new(Some(key))),
        Arc::new(LoopbackFilter::new(64)),
        Arc::clone(&peer_mgr),
        Arc::clone(&recv_mgr),
    );
    let port = server.start(0).expect("start server");
    let peer = format!("127.0.0.1:{}", port);

    let send_mgr = Arc::new(FileTransferManager::new(&tmp));

    let t0 = Instant::now();
    send_mgr
        .send_file("bench_1", &peer, src.to_str().unwrap(), "devA", "A", &key)
        .expect("send");
    let el = t0.elapsed().as_secs_f64();

    println!(
        "[E2E-REAL] {} MiB in {:.3}s => {:.2} MiB/s (progress callbacks: {})",
        TOTAL_MB,
        el,
        mbps(total, el),
        progress_calls.load(Ordering::Relaxed)
    );
    server.stop();
    let _ = std::fs::remove_dir_all(&tmp);
}

fn bench_tcp_chunk_size_scaling() {
    for &cs in &[
        128 * 1024usize,
        256 * 1024,
        512 * 1024,
        1024 * 1024,
        4 * 1024 * 1024,
    ] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let total = 256u64 * 1024 * 1024;

        let rx = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
            let mut scratch = vec![0u8; cs];
            let mut got = 0u64;
            while got < total {
                let want = std::cmp::min(cs as u64, total - got) as usize;
                if s.read_exact(&mut scratch[..want]).is_err() {
                    break;
                }
                got += want as u64;
            }
            got
        });

        let t0 = Instant::now();
        let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream.set_nodelay(true).unwrap();
        let sent = std::io::copy(&mut std::io::repeat(0x11).take(total), &mut stream).unwrap();
        let el = t0.elapsed().as_secs_f64();
        let _got = rx.join().unwrap();
        println!(
            "[TCP-CHUNK] {:>5} KiB/block => {:.2} MiB/s ({} blocks, {:.3}s)",
            cs / 1024,
            mbps(sent as u64, el),
            total / cs as u64,
            el
        );
    }
}

fn main() {
    println!("=== MuClip 文件传输性能基准 ===\n");
    bench_encrypt_only();
    println!();
    bench_sha256_only();
    println!();
    bench_raw_tcp_loopback();
    println!();
    bench_tcp_chunk_size_scaling();
    println!();
    bench_end_to_end_real_pipeline();
}

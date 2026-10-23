//! 重启后密钥生命周期探针。
//!
//! 核心的链路密钥有两层：
//!   - `peer_keys[device_id]`：SPAKE2 配对派生的两两密钥，只在内存；
//!   - `session_key`：`derive_key(启动时传入的 key 材料)`，即 HKDF-SHA256(6 位 PIN)
//!     或直接使用 64 位 hex 长期密钥。
//!
//! `MuClipSyncEngine::add_paired_device` 接受形如
//! `device_id|ip|port|name|type|peer_key_hex` 的复合串，第 6 段会被
//! `PeerManager::add_paired_device_id` 解析并回灌到 `peer_keys`。这是重启后恢复
//! 两两密钥的唯一通道。
//!
//! 三个用例分别钉住：
//!   1. 同进程配对后同步可用（基线）；
//!   2. **带 peer_key 重启 → 仍可用**（回灌通道有效）；
//!   3. **不带 peer_key 重启 → 静默回落到 session_key**，两端长期密钥不同时
//!      解密失败、投递为 0，且没有任何报错提示。

use muclip_core::{MuClipSyncEngine, SyncConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// 64 个 hex 字符 → derive_key 直接当作 32 字节密钥使用（不走 HKDF）。
/// 模拟 C# 客户端默认各设备独立生成的长期密钥。
const LTK_A: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const LTK_B: &str = "2222222222222222222222222222222222222222222222222222222222222222";

fn spawn(id: &str, key_material: &str) -> Arc<MuClipSyncEngine> {
    let engine = MuClipSyncEngine::start(SyncConfig {
        device_id: id.to_string(),
        device_name: id.to_string(),
        device_type: "Windows".to_string(),
        sync_port: 0,
        discovery_port: 0,
        pairing_pin: key_material.to_string(),
    })
    .expect("engine start");
    engine.set_auto_discovery(false);
    engine
}

fn recorder(engine: &Arc<MuClipSyncEngine>) -> Arc<Mutex<Vec<String>>> {
    let rx = Arc::new(Mutex::new(Vec::<String>::new()));
    let handle = Arc::clone(&rx);
    engine.on_clipboard_received(Arc::new(move |payload| {
        handle.lock().unwrap().push(payload.content);
    }));
    rx
}

/// 在同一进程生命周期内配对，返回 (A, B, A 端口, B 端口, 配对派生的两两密钥 hex)。
fn pair_once(
    ltk_a: &str,
    ltk_b: &str,
    pin: &str,
) -> (
    Arc<MuClipSyncEngine>,
    Arc<MuClipSyncEngine>,
    u16,
    u16,
    String,
) {
    let a = spawn("node-a", ltk_a);
    let b = spawn("node-b", ltk_b);
    let port_a = a.bound_port();
    let port_b = b.bound_port();

    // 响应方在配对成功时拿到两两密钥（两端相同）
    let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let cap_ref = Arc::clone(&captured);
    b.on_pair_success(Arc::new(move |_dev_id, _name, _ip, peer_key_hex| {
        if let Ok(mut slot) = cap_ref.lock() {
            *slot = Some(peer_key_hex);
        }
    }));

    let b_ref = Arc::clone(&b);
    let pin_owned = pin.to_string();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    b.on_pair_request_received(Arc::new(move |req_id, _from_id, _from_name, _ip| {
        let b_inner = Arc::clone(&b_ref);
        let pin_inner = pin_owned.clone();
        let tx = done_tx.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            let _ = b_inner.respond_pair(&req_id, &pin_inner, true);
            let _ = tx.send(());
        });
    }));

    let resp = a
        .request_pair(&format!("127.0.0.1:{}", port_b), pin, 5)
        .expect("request_pair");
    assert!(resp.accepted, "配对应被接受");
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .expect("respond_pair 完成");
    std::thread::sleep(Duration::from_millis(50));

    let key = captured
        .lock()
        .unwrap()
        .clone()
        .expect("配对成功回调应带回两两密钥");

    // 基线场景仍用带端点 hints 的复合串，保证投递目标可达
    a.add_paired_device(&format!("node-b|127.0.0.1|{}|B|Windows|{}", port_b, key));
    b.add_paired_device(&format!("node-a|127.0.0.1|{}|A|Windows|{}", port_a, key));

    (a, b, port_a, port_b, key)
}

#[test]
fn baseline_paired_in_process_syncs() {
    let (a, b, _pa, _pb, _key) = pair_once(LTK_A, LTK_B, "111222");
    let rx_b = recorder(&b);

    assert_eq!(a.broadcast_clipboard("baseline", "text"), 1);
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(rx_b.lock().unwrap().as_slice(), &["baseline"]);

    a.stop();
    b.stop();
}

#[test]
fn restart_with_restored_peer_key_still_syncs() {
    // 正确用法：客户端把配对成功回调里的 peer_key_hex 落盘，重启时回灌。
    let (a1, b1, _pa, pb, key) = pair_once(LTK_A, LTK_B, "111222");
    let rx_b1 = recorder(&b1);
    assert_eq!(a1.broadcast_clipboard("before-restart", "text"), 1);
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(rx_b1.lock().unwrap().as_slice(), &["before-restart"]);

    // 模拟进程退出
    a1.stop();
    b1.stop();
    std::thread::sleep(Duration::from_millis(120));

    // 重启：device_id / 长期密钥 / 两两密钥都不变
    let a2 = spawn("node-a", LTK_A);
    let b2 = spawn("node-b", LTK_B);
    let port_a2 = a2.bound_port();
    let port_b2 = b2.bound_port();
    let rx_b2 = recorder(&b2);

    a2.add_paired_device(&format!("node-b|127.0.0.1|{}|B|Windows|{}", port_b2, key));
    b2.add_paired_device(&format!("node-a|127.0.0.1|{}|A|Windows|{}", port_a2, key));
    let _ = pb;

    let delivered = a2.broadcast_clipboard("after-restart", "text");
    std::thread::sleep(Duration::from_millis(150));

    assert_eq!(delivered, 1, "回灌两两密钥后，重启仍应可同步");
    assert_eq!(rx_b2.lock().unwrap().as_slice(), &["after-restart"]);

    a2.stop();
    b2.stop();
}

#[test]
fn restart_without_peer_key_silently_falls_back_to_session_key() {
    // 异常用法：调用方只回灌了 device_id + 端点，漏掉第 6 段 peer_key。
    // 端点可达 → 确实发出了包，但两端 session_key 不同 → 解密失败 → 投递 0，
    // 且没有任何错误/告警暴露给调用方。
    let (a1, b1, _pa, pb, _key) = pair_once(LTK_A, LTK_B, "111222");
    assert_eq!(a1.broadcast_clipboard("before-restart", "text"), 1);
    std::thread::sleep(Duration::from_millis(150));

    a1.stop();
    b1.stop();
    std::thread::sleep(Duration::from_millis(120));

    let a2 = spawn("node-a", LTK_A);
    let b2 = spawn("node-b", LTK_B);
    let port_a2 = a2.bound_port();
    let port_b2 = b2.bound_port();
    let rx_b2 = recorder(&b2);

    // 端点齐全，但没有第 6 段
    a2.add_paired_device(&format!("node-b|127.0.0.1|{}|B|Windows", port_b2));
    b2.add_paired_device(&format!("node-a|127.0.0.1|{}|A|Windows", port_a2));
    let _ = pb;

    let delivered = a2.broadcast_clipboard("after-restart", "text");
    std::thread::sleep(Duration::from_millis(150));

    eprintln!(
        "[no-peer-key] restart delivered={} received={:?}",
        delivered,
        rx_b2.lock().unwrap()
    );

    // 记录当前行为：静默失败。修复后（例如回落时返回明确错误）此断言应更新。
    assert_eq!(delivered, 0, "缺少 peer_key 时应无法解密对端帧");
    assert!(rx_b2.lock().unwrap().is_empty());

    a2.stop();
    b2.stop();
}

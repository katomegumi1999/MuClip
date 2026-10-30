use crate::sync::{MuClipSyncEngine, SyncConfig};
use std::ffi::{CString, c_char};
use std::sync::Arc;

use super::{c_char_to_str, copy_str_to_fixed_buf, string_to_c_char};

pub struct MuClipSyncHandle {
    pub inner: Arc<MuClipSyncEngine>,
}

pub type MuClipClipboardCallback = unsafe extern "C" fn(
    content: *const c_char,
    content_type: *const c_char,
    device_id: *const c_char,
    device_name: *const c_char,
    user_data: *mut std::ffi::c_void,
);

struct SyncCallbackWrapper {
    cb: MuClipClipboardCallback,
    user_data: usize,
}
unsafe impl Send for SyncCallbackWrapper {}
unsafe impl Sync for SyncCallbackWrapper {}

/// Starts the P2P LAN sync engine.
/// Returns pointer to `MuClipSyncHandle` or null on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_start(
    device_id: *const c_char,
    device_name: *const c_char,
    device_type: *const c_char,
    sync_port: u16,
    discovery_port: u16,
    pairing_pin: *const c_char,
) -> *mut MuClipSyncHandle {
    let dev_id = unsafe { c_char_to_str(device_id) }
        .unwrap_or("muclip-node")
        .to_string();
    let dev_name = unsafe { c_char_to_str(device_name) }
        .unwrap_or("MuClip Device")
        .to_string();
    let dev_type = unsafe { c_char_to_str(device_type) }
        .unwrap_or("Windows")
        .to_string();
    let pin = unsafe { c_char_to_str(pairing_pin) }
        .unwrap_or("")
        .to_string();

    let config = SyncConfig {
        device_id: dev_id,
        device_name: dev_name,
        device_type: dev_type,
        sync_port,
        discovery_port,
        pairing_pin: pin,
    };

    match MuClipSyncEngine::start(config) {
        Ok(engine) => Box::into_raw(Box::new(MuClipSyncHandle { inner: engine })),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Stops and frees the sync engine handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_stop(handle: *mut MuClipSyncHandle) {
    if !handle.is_null() {
        unsafe {
            let handle_box = Box::from_raw(handle);
            handle_box.inner.stop();
        }
    }
}

/// Returns the active TCP sync port currently bound.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_bound_port(handle: *mut MuClipSyncHandle) -> u16 {
    if handle.is_null() {
        return 0;
    }
    let engine = unsafe { &*handle };
    engine.inner.bound_port()
}

/// Returns discovered active online peers as a JSON string array of `PeerInfo`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_active_peers(
    handle: *mut MuClipSyncHandle,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_active_peers();
    let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
    string_to_c_char(json)
}

/// Returns all known peers (including offline) as a JSON string array of `PeerInfo`.
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_all_peers(handle: *mut MuClipSyncHandle) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_all_peers();
    let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
    string_to_c_char(json)
}

/// Updates pairing PIN at runtime. Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_pairing_pin(
    handle: *mut MuClipSyncHandle,
    pin: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let p = unsafe { c_char_to_str(pin) }.unwrap_or("");
    let engine = unsafe { &*handle };
    if engine.inner.set_pairing_pin(p).is_ok() {
        0
    } else {
        -1
    }
}

/// Adds a static / port-mapped remote peer endpoint (e.g. "192.168.1.100:42424" or "myfrp.host.com:55555").
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_add_manual_peer(
    handle: *mut MuClipSyncHandle,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let a = match unsafe { c_char_to_str(addr) } {
        Some(s) => s,
        None => return -1,
    };
    let engine = unsafe { &*handle };
    engine.inner.add_manual_peer(a);
    0
}

/// Removes a static / port-mapped remote peer endpoint (by `"host:port"`, `"host"`, or `device_id`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_remove_manual_peer(
    handle: *mut MuClipSyncHandle,
    addr: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let a = match unsafe { c_char_to_str(addr) } {
        Some(s) => s,
        None => return -1,
    };
    let engine = unsafe { &*handle };
    engine.inner.remove_manual_peer(a);
    0
}

/// Returns all configured static / port-mapped peer endpoints as a JSON string array (`string[]`).
/// Must be freed using `muclip_core_free_string`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_get_manual_peers(
    handle: *mut MuClipSyncHandle,
) -> *mut c_char {
    if handle.is_null() {
        return string_to_c_char("[]".to_string());
    }
    let engine = unsafe { &*handle };
    let peers = engine.inner.get_manual_peers();
    let json = serde_json::to_string(&peers).unwrap_or_else(|_| "[]".to_string());
    string_to_c_char(json)
}

/// Toggles automatic periodic discovery broadcasting.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_auto_discovery(
    handle: *mut MuClipSyncHandle,
    enabled: i32,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine = unsafe { &*handle };
    engine.inner.set_auto_discovery(enabled != 0);
    0
}

/// Checks if automatic periodic discovery broadcasting is enabled.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_is_auto_discovery(handle: *mut MuClipSyncHandle) -> i32 {
    if handle.is_null() {
        return 0;
    }
    let engine = unsafe { &*handle };
    if engine.inner.is_auto_discovery_enabled() {
        1
    } else {
        0
    }
}

/// Manually triggers a single multi-interface discovery broadcast scan immediately.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_trigger_scan(handle: *mut MuClipSyncHandle) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let engine = unsafe { &*handle };
    engine.inner.trigger_discovery_scan();
    0
}

/// Tests connection and encryption validity with a peer endpoint.
/// Returns round-trip time in milliseconds if successful, or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_test_peer(
    handle: *mut MuClipSyncHandle,
    peer_addr: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let addr = match unsafe { c_char_to_str(peer_addr) } {
        Some(a) => a,
        None => return -1,
    };
    let engine = unsafe { &*handle };
    match engine.inner.test_peer_connection(addr) {
        Ok(ms) => ms.max(1) as i32,
        Err(_) => -1,
    }
}

/// Broadcasts clipboard content to all online discovered peers and static peers.
/// Returns number of peers successfully sent to.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_broadcast(
    handle: *mut MuClipSyncHandle,
    text: *const c_char,
    content_type: *const c_char,
) -> usize {
    if handle.is_null() {
        return 0;
    }
    let t = match unsafe { c_char_to_str(text) } {
        Some(s) => s,
        None => return 0,
    };
    let ctype = unsafe { c_char_to_str(content_type) }.unwrap_or("text");
    let engine = unsafe { &*handle };
    engine.inner.broadcast_clipboard(t, ctype)
}

/// Registers a callback invoked whenever incoming clipboard payload arrives from a remote peer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_callback(
    handle: *mut MuClipSyncHandle,
    callback: Option<MuClipClipboardCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    if let Some(cb_fn) = callback {
        let wrapper = Arc::new(SyncCallbackWrapper {
            cb: cb_fn,
            user_data: user_data as usize,
        });
        engine.inner.on_clipboard_received(Arc::new(move |payload| {
            let content_c = CString::new(payload.content.as_str()).unwrap_or_default();
            let ctype_c = CString::new(payload.content_type.as_str()).unwrap_or_default();
            let dev_id_c = CString::new(payload.source_device_id.as_str()).unwrap_or_default();
            let dev_name_c = CString::new(payload.source_device_name.as_str()).unwrap_or_default();
            let cb = wrapper.cb;
            let ud = wrapper.user_data as *mut std::ffi::c_void;
            unsafe {
                cb(
                    content_c.as_ptr(),
                    ctype_c.as_ptr(),
                    dev_id_c.as_ptr(),
                    dev_name_c.as_ptr(),
                    ud,
                );
            }
        }));
    }
}

pub type MuClipPairCallback = unsafe extern "C" fn(
    device_id: *const c_char,
    device_name: *const c_char,
    pin: *const c_char,
    user_data: *mut std::ffi::c_void,
);

pub type MuClipPairRequestCallback = unsafe extern "C" fn(
    request_id: *const c_char,
    device_id: *const c_char,
    device_name: *const c_char,
    peer_ip: *const c_char,
    user_data: *mut std::ffi::c_void,
);

struct SyncPairRequestCallbackWrapper {
    cb: MuClipPairRequestCallback,
    user_data: usize,
}
unsafe impl Send for SyncPairRequestCallbackWrapper {}
unsafe impl Sync for SyncPairRequestCallbackWrapper {}

pub type MuClipPairSuccessCallback = unsafe extern "C" fn(
    device_id: *const c_char,
    device_name: *const c_char,
    peer_ip: *const c_char,
    pin: *const c_char,
    user_data: *mut std::ffi::c_void,
);

struct SyncPairSuccessCallbackWrapper {
    cb: MuClipPairSuccessCallback,
    user_data: usize,
}
unsafe impl Send for SyncPairSuccessCallbackWrapper {}
unsafe impl Sync for SyncPairSuccessCallbackWrapper {}

#[repr(C)]
pub struct MuClipPairResult {
    pub success: i32, // 0=ok, 1=rejected, 2=wrong pin, 3=timeout, -1=network/internal error
    pub responder_device_id: [u8; 128],
    pub responder_device_name: [u8; 128],
    pub error_message: [u8; 256],
    pub long_term_key: [u8; 65],
}

/// Registers callback for incoming single-connection pairing requests.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_pair_request_callback(
    handle: *mut MuClipSyncHandle,
    callback: Option<MuClipPairRequestCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    if let Some(cb_fn) = callback {
        let wrapper = Arc::new(SyncPairRequestCallbackWrapper {
            cb: cb_fn,
            user_data: user_data as usize,
        });
        engine.inner.on_pair_request_received(Arc::new(
            move |req_id, dev_id, dev_name, peer_ip| {
                let req_id_c = CString::new(req_id.as_str()).unwrap_or_default();
                let dev_id_c = CString::new(dev_id.as_str()).unwrap_or_default();
                let dev_name_c = CString::new(dev_name.as_str()).unwrap_or_default();
                let peer_ip_c = CString::new(peer_ip.as_str()).unwrap_or_default();
                let cb = wrapper.cb;
                let ud = wrapper.user_data as *mut std::ffi::c_void;
                unsafe {
                    cb(
                        req_id_c.as_ptr(),
                        dev_id_c.as_ptr(),
                        dev_name_c.as_ptr(),
                        peer_ip_c.as_ptr(),
                        ud,
                    );
                }
            },
        ));
    }
}

/// Registers callback for when an incoming pairing successfully establishes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_pair_success_callback(
    handle: *mut MuClipSyncHandle,
    callback: Option<MuClipPairSuccessCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    if let Some(cb_fn) = callback {
        let wrapper = Arc::new(SyncPairSuccessCallbackWrapper {
            cb: cb_fn,
            user_data: user_data as usize,
        });
        engine
            .inner
            .on_pair_success(Arc::new(move |dev_id, dev_name, peer_ip, pin| {
                let dev_id_c = CString::new(dev_id.as_str()).unwrap_or_default();
                let dev_name_c = CString::new(dev_name.as_str()).unwrap_or_default();
                let peer_ip_c = CString::new(peer_ip.as_str()).unwrap_or_default();
                let pin_c = CString::new(pin.as_str()).unwrap_or_default();
                let cb = wrapper.cb;
                let ud = wrapper.user_data as *mut std::ffi::c_void;
                unsafe {
                    cb(
                        dev_id_c.as_ptr(),
                        dev_name_c.as_ptr(),
                        peer_ip_c.as_ptr(),
                        pin_c.as_ptr(),
                        ud,
                    );
                }
            }));
    }
}

/// Responds to an incoming pairing request: 0 = success, 1 = not found/expired, 2 = wrong pin, -1 = error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_respond_pair(
    handle: *mut MuClipSyncHandle,
    request_id: *const c_char,
    pin: *const c_char,
    accept: i32,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let req_id = match unsafe { c_char_to_str(request_id) } {
        Some(s) => s,
        None => return -1,
    };
    let pin_str = unsafe { c_char_to_str(pin) }.unwrap_or("");
    let engine = unsafe { &*handle };
    engine.inner.respond_pair(req_id, pin_str, accept != 0)
}

/// Initiates pairing with a peer over single-stream TCP handshake.
/// Blocks until response is received or timeout occurs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_request_pair(
    handle: *mut MuClipSyncHandle,
    peer_addr: *const c_char,
    pin: *const c_char,
    timeout_secs: u32,
    out_result: *mut MuClipPairResult,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let addr = match unsafe { c_char_to_str(peer_addr) } {
        Some(a) => a,
        None => return -1,
    };
    let pin_str = match unsafe { c_char_to_str(pin) } {
        Some(p) => p,
        None => return -1,
    };

    let engine = unsafe { &*handle };
    let tout = if timeout_secs > 0 {
        timeout_secs as u64
    } else {
        60
    };

    match engine.inner.request_pair(addr, pin_str, tout) {
        Ok(resp) => {
            if !out_result.is_null() {
                unsafe {
                    (*out_result).success = if resp.accepted { 0 } else { resp.error_code };
                    copy_str_to_fixed_buf(
                        &resp.responder_device_id,
                        &mut (*out_result).responder_device_id,
                    );
                    copy_str_to_fixed_buf(
                        &resp.responder_device_name,
                        &mut (*out_result).responder_device_name,
                    );
                    let err_msg = resp.error_message.unwrap_or_default();
                    copy_str_to_fixed_buf(&err_msg, &mut (*out_result).error_message);
                    let ltk = resp.long_term_key_hex.unwrap_or_default();
                    copy_str_to_fixed_buf(&ltk, &mut (*out_result).long_term_key);
                }
            }
            if resp.accepted { 0 } else { resp.error_code }
        }
        Err(e) => {
            if !out_result.is_null() {
                unsafe {
                    (*out_result).success = -1;
                    let err_str = format!("{}", e);
                    copy_str_to_fixed_buf(&err_str, &mut (*out_result).error_message);
                    (*out_result).long_term_key.fill(0);
                }
            }
            -1
        }
    }
}

/// Marks a device ID as paired in the discovery table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_add_paired_device(
    handle: *mut MuClipSyncHandle,
    device_id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    if let Some(id) = unsafe { c_char_to_str(device_id) } {
        let engine = unsafe { &*handle };
        engine.inner.add_paired_device(id);
        0
    } else {
        -1
    }
}

/// Unpairs a device ID from the discovery table.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_remove_paired_device(
    handle: *mut MuClipSyncHandle,
    device_id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    if let Some(id) = unsafe { c_char_to_str(device_id) } {
        let engine = unsafe { &*handle };
        engine.inner.remove_paired_device(id);
        0
    } else {
        -1
    }
}

/// Deprecated legacy C ABI stub (no-op; all pairing now uses SPAKE2 `muclip_sync_request_pair` / `muclip_sync_set_pair_request_callback`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_pair_callback(
    _handle: *mut MuClipSyncHandle,
    _callback: Option<MuClipPairCallback>,
    _user_data: *mut std::ffi::c_void,
) {
}

/// Deprecated legacy C ABI stub (always returns -1; all pairing now uses SPAKE2 `muclip_sync_request_pair`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_send_pair_request(
    _handle: *mut MuClipSyncHandle,
    _peer_addr: *const c_char,
    _pin: *const c_char,
) -> i32 {
    -1
}

pub type MuClipUnpairCallback =
    unsafe extern "C" fn(device_id: *const c_char, user_data: *mut std::ffi::c_void);

struct SyncUnpairCallbackWrapper {
    cb: MuClipUnpairCallback,
    user_data: usize,
}
unsafe impl Send for SyncUnpairCallbackWrapper {}
unsafe impl Sync for SyncUnpairCallbackWrapper {}

pub type MuClipAuthRejectedCallback =
    unsafe extern "C" fn(device_id: *const c_char, streak: u32, user_data: *mut std::ffi::c_void);

struct SyncAuthRejectedCallbackWrapper {
    cb: MuClipAuthRejectedCallback,
    user_data: usize,
}
unsafe impl Send for SyncAuthRejectedCallbackWrapper {}
unsafe impl Sync for SyncAuthRejectedCallbackWrapper {}

/// 注册「同一对端连续被会话握手拒绝」的提示回调。
///
/// 触发条件：连续 `AUTH_REJECT_HINT_THRESHOLD`（3）次认证被拒，中途任意一次同步成功
/// 即清零。**只提示，不解配** —— `SyncRejected` 是笼统的认证失败，可能是对端已解配、
/// 密钥不一致或地址串台，服务端刻意不区分原因（对未认证方暴露「你没配对」等于泄露
/// 配对状态）。宿主收到后应提示用户「建议重新配对或删除该设备」，而不是自行删数据。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_auth_rejected_callback(
    handle: *mut MuClipSyncHandle,
    callback: Option<MuClipAuthRejectedCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    if let Some(cb_fn) = callback {
        let wrapper = Arc::new(SyncAuthRejectedCallbackWrapper {
            cb: cb_fn,
            user_data: user_data as usize,
        });
        engine
            .inner
            .on_peer_auth_rejected(Arc::new(move |dev_id, streak| {
                let dev_id_c = CString::new(dev_id).unwrap_or_default();
                let cb = wrapper.cb;
                let ud = wrapper.user_data as *mut std::ffi::c_void;
                unsafe {
                    cb(dev_id_c.as_ptr(), streak, ud);
                }
            }));
    }
}

/// Registers a callback invoked whenever a remote peer unpairs this device (`MSG_UNPAIR_NOTICE` or `ERR_NOT_PAIRED`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_unpair_callback(
    handle: *mut MuClipSyncHandle,
    callback: Option<MuClipUnpairCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    if let Some(cb_fn) = callback {
        let wrapper = Arc::new(SyncUnpairCallbackWrapper {
            cb: cb_fn,
            user_data: user_data as usize,
        });
        engine.inner.on_peer_unpaired(Arc::new(move |dev_id| {
            let dev_id_c = CString::new(dev_id.as_str()).unwrap_or_default();
            let cb = wrapper.cb;
            let ud = wrapper.user_data as *mut std::ffi::c_void;
            unsafe {
                cb(dev_id_c.as_ptr(), ud);
            }
        }));
    }
}

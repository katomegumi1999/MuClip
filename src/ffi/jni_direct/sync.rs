use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{JNI_FALSE, JNI_TRUE, jboolean, jint, jlong};
use std::slice;
use std::sync::Arc;

use crate::ffi::jni_direct::binary::{
    encode_pair_error, encode_pair_response, encode_peers, encode_string_list,
};
use crate::sync::{MuClipSyncEngine, SyncConfig};

// -----------------------------------------------------------------------------
// P2P Sync Engine JNI Bridge
// -----------------------------------------------------------------------------

struct SyncEngineWrapper {
    engine: Arc<MuClipSyncEngine>,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeStartSync(
    mut env: JNIEnv,
    _class: JClass,
    device_id: JString,
    device_name: JString,
    device_type: JString,
    sync_port: jint,
    pairing_pin: JString,
) -> jlong {
    let dev_id: String = match env.get_string(&device_id) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let dev_name: String = match env.get_string(&device_name) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let dev_type: String = match env.get_string(&device_type) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let pin: String = match env.get_string(&pairing_pin) {
        Ok(s) => s.into(),
        Err(_) => String::new(),
    };

    let config = SyncConfig {
        device_id: dev_id,
        device_name: dev_name,
        device_type: dev_type,
        sync_port: if sync_port > 0 { sync_port as u16 } else { 0 },
        discovery_port: 0,
        pairing_pin: pin,
    };

    match MuClipSyncEngine::start(config) {
        Ok(engine) => {
            let wrapper = Box::new(SyncEngineWrapper { engine });
            Box::into_raw(wrapper) as usize as jlong
        }
        Err(_) => 0,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeStopSync(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
) {
    if sync_handle != 0 {
        let ptr = sync_handle as usize as *mut SyncEngineWrapper;
        unsafe {
            let wrapper = Box::from_raw(ptr);
            wrapper.engine.stop();
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeBroadcastClipboardZeroCopy(
    mut env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    buffer_ptr: jlong,
    length: jint,
    content_type: JString,
) -> jint {
    if sync_handle == 0 || buffer_ptr == 0 || length <= 0 {
        return 0;
    }
    let ctype: String = match env.get_string(&content_type) {
        Ok(s) => s.into(),
        Err(_) => "text".to_string(),
    };

    let slice = unsafe { slice::from_raw_parts(buffer_ptr as usize as *const u8, length as usize) };
    let text = match std::str::from_utf8(slice) {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.broadcast_clipboard(text, &ctype) as jint
}

/// Writes active discovered and manual peers in Little-Endian binary wire format into `out_buffer_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetActivePeersZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if sync_handle == 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let peers = wrapper.engine.get_active_peers();
    let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
    else {
        return -1;
    };
    encode_peers(&peers, out_slice)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetActivePeersJson(
    env: JNIEnv,
    class: JClass,
    sync_handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    unsafe {
        Java_com_muclip_core_MuClipNative_nativeGetActivePeersZeroCopy(
            env,
            class,
            sync_handle,
            out_buffer_ptr,
            out_capacity,
        )
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeSetPairingPin(
    mut env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    pairing_pin: JString,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let pin: String = match env.get_string(&pairing_pin) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    if wrapper.engine.set_pairing_pin(&pin).is_ok() {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeAddManualPeer(
    mut env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    peer_addr: JString,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let addr: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.add_manual_peer(&addr);
    0
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_muclip_core_MuClipNative_nativeRemoveManualPeer(
    mut env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    peer_addr: JString,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let addr: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.remove_manual_peer(&addr);
    0
}

/// Writes all known peers (including offline and manual peers) in Little-Endian binary wire format into `out_buffer_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetAllPeersZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if sync_handle == 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let peers = wrapper.engine.get_all_peers();
    let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
    else {
        return -1;
    };
    encode_peers(&peers, out_slice)
}

/// Writes configured manual peer endpoints in Little-Endian binary wire format into `out_buffer_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetManualPeersZeroCopy(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if sync_handle == 0 || out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let peers = wrapper.engine.get_manual_peers();
    let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
    else {
        return -1;
    };
    encode_string_list(&peers, out_slice)
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetManualPeersJson(
    env: JNIEnv,
    class: JClass,
    sync_handle: jlong,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    unsafe {
        Java_com_muclip_core_MuClipNative_nativeGetManualPeersZeroCopy(
            env,
            class,
            sync_handle,
            out_buffer_ptr,
            out_capacity,
        )
    }
}

// -----------------------------------------------------------------------------
// Selective Scan & Discovery Controls
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeSetAutoDiscovery(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
    enabled: jboolean,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.set_auto_discovery(enabled == JNI_TRUE);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeIsAutoDiscovery(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
) -> jboolean {
    if sync_handle == 0 {
        return JNI_FALSE;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    if wrapper.engine.is_auto_discovery_enabled() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeTriggerScan(
    _env: JNIEnv,
    _class: JClass,
    sync_handle: jlong,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.trigger_discovery_scan();
    0
}

// -----------------------------------------------------------------------------
// Paired Devices Management
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeAddPairedDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    device_id: JString<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let id: String = match env.get_string(&device_id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.add_paired_device(&id);
    0
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeRemovePairedDevice<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    device_id: JString<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let id: String = match env.get_string(&device_id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.remove_paired_device(&id);
    0
}

// -----------------------------------------------------------------------------
// Single-Stream Random PIN Handshake Pairing (One-Way)
// -----------------------------------------------------------------------------

/// Initiates a single-stream TCP handshake pairing and writes the `PairResult` binary wire format
/// directly into `out_buffer_ptr`.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeRequestPairZeroCopy<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    peer_addr: JString<'local>,
    pin: JString<'local>,
    timeout_secs: jint,
    out_buffer_ptr: jlong,
    out_capacity: jint,
) -> jint {
    if out_buffer_ptr == 0 || out_capacity <= 0 {
        return -1;
    }
    let Some(out_slice) = (unsafe { super::out_slice_from_raw(out_buffer_ptr, out_capacity) })
    else {
        return -1;
    };

    if sync_handle == 0 {
        return encode_pair_error(-1, "Invalid sync handle", out_slice);
    }
    let addr: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return encode_pair_error(-1, "Invalid peer address", out_slice),
    };
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => return encode_pair_error(-1, "Invalid pin", out_slice),
    };

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let tout = if timeout_secs > 0 {
        timeout_secs as u64
    } else {
        60
    };

    match wrapper.engine.request_pair(&addr, &pin_str, tout) {
        Ok(resp) => encode_pair_response(&resp, out_slice),
        Err(e) => {
            let msg = format!("{}", e);
            encode_pair_error(-1, &msg, out_slice)
        }
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeRespondPair<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    request_id: JString<'local>,
    pin: JString<'local>,
    accept: jboolean,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let req_id: String = match env.get_string(&request_id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let pin_str: String = match env.get_string(&pin) {
        Ok(s) => s.into(),
        Err(_) => String::new(),
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper
        .engine
        .respond_pair(&req_id, &pin_str, accept == JNI_TRUE)
}

// -----------------------------------------------------------------------------
// Test Paired Peer Connection
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeTestPeer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    peer_addr: JString<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let addr: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    match wrapper.engine.test_peer_connection(&addr) {
        Ok(ms) => ms.max(1) as jint,
        Err(_) => -1,
    }
}

// -----------------------------------------------------------------------------
// Asynchronous Event Callbacks (Incoming Clipboard, Pair Request, Pair Success)
// -----------------------------------------------------------------------------

struct JniCallbackHolder {
    vm: jni::JavaVM,
    callback: jni::objects::GlobalRef,
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeRegisterSyncCallback<
    'local,
>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    callback_obj: JObject<'local>,
) -> jint {
    if sync_handle == 0 || callback_obj.is_null() {
        return -1;
    }
    let vm = match env.get_java_vm() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let global_cb = match env.new_global_ref(callback_obj) {
        Ok(r) => r,
        Err(_) => return -1,
    };

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let holder = Arc::new(JniCallbackHolder {
        vm,
        callback: global_cb,
    });

    // 1. Incoming clipboard sync callback
    let h1 = Arc::clone(&holder);
    wrapper
        .engine
        .on_clipboard_received(Arc::new(move |payload| {
            if payload.content_type == "system/ping" {
                return;
            }
            if let Ok(mut env) = h1.vm.attach_current_thread() {
                let j_src_id = env
                    .new_string(&payload.source_device_id)
                    .unwrap_or_default();
                let j_src_name = env
                    .new_string(&payload.source_device_name)
                    .unwrap_or_default();
                let j_content = env.new_string(&payload.content).unwrap_or_default();
                let j_type = env.new_string(&payload.content_type).unwrap_or_default();

                let _ = env.call_method(
                    &h1.callback,
                    "onClipboardReceived",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                    &[
                        (&j_src_id).into(),
                        (&j_src_name).into(),
                        (&j_content).into(),
                        (&j_type).into(),
                    ],
                );
            }
        }));

    // 2. Incoming pairing request callback
    let h2 = Arc::clone(&holder);
    wrapper.engine.on_pair_request_received(Arc::new(
        move |req_id, from_id, from_name, client_ip| {
            if let Ok(mut env) = h2.vm.attach_current_thread() {
                let j_req_id = env.new_string(&req_id).unwrap_or_default();
                let j_from_id = env.new_string(&from_id).unwrap_or_default();
                let j_from_name = env.new_string(&from_name).unwrap_or_default();
                let j_ip = env.new_string(&client_ip).unwrap_or_default();

                let _ = env.call_method(
                    &h2.callback,
                    "onPairRequestReceived",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                    &[
                        (&j_req_id).into(),
                        (&j_from_id).into(),
                        (&j_from_name).into(),
                        (&j_ip).into(),
                    ],
                );
            }
        },
    ));

    // 3. Pairing established success callback
    let h3 = Arc::clone(&holder);
    wrapper
        .engine
        .on_pair_success(Arc::new(move |from_id, from_name, client_ip, pin| {
            if let Ok(mut env) = h3.vm.attach_current_thread() {
                let j_from_id = env.new_string(&from_id).unwrap_or_default();
                let j_from_name = env.new_string(&from_name).unwrap_or_default();
                let j_ip = env.new_string(&client_ip).unwrap_or_default();
                let j_pin = env.new_string(&pin).unwrap_or_default();

                let _ = env.call_method(
                    &h3.callback,
                    "onPairSuccess",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                    &[
                        (&j_from_id).into(),
                        (&j_from_name).into(),
                        (&j_ip).into(),
                        (&j_pin).into(),
                    ],
                );
            }
        }));

    // 4. Remote peer unpaired notification callback
    let h4 = Arc::clone(&holder);
    wrapper
        .engine
        .on_peer_unpaired(Arc::new(move |unpaired_device_id| {
            if let Ok(mut env) = h4.vm.attach_current_thread() {
                let j_id = env.new_string(&unpaired_device_id).unwrap_or_default();
                let _ = env.call_method(
                    &h4.callback,
                    "onPeerUnpaired",
                    "(Ljava/lang/String;)V",
                    &[(&j_id).into()],
                );
            }
        }));

    // 5. Incoming file transfer offer callback
    let h5 = Arc::clone(&holder);
    wrapper.engine.on_file_offer(Arc::new(
        move |transfer_id, from_id, from_name, file_name, file_size| {
            if let Ok(mut env) = h5.vm.attach_current_thread() {
                let j_tid = env.new_string(transfer_id).unwrap_or_default();
                let j_from_id = env.new_string(from_id).unwrap_or_default();
                let j_from_name = env.new_string(from_name).unwrap_or_default();
                let j_file_name = env.new_string(file_name).unwrap_or_default();

                let _ = env.call_method(
                    &h5.callback,
                    "onFileOffer",
                    "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V",
                    &[
                        (&j_tid).into(),
                        (&j_from_id).into(),
                        (&j_from_name).into(),
                        (&j_file_name).into(),
                        (file_size as jlong).into(),
                    ],
                );
            }
        },
    ));

    // 6. File transfer progress callback
    let h6 = Arc::clone(&holder);
    wrapper.engine.on_file_progress(Arc::new(
        move |transfer_id, transferred, total, speed_bps, is_send| {
            if let Ok(mut env) = h6.vm.attach_current_thread() {
                let j_tid = env.new_string(transfer_id).unwrap_or_default();
                let _ = env.call_method(
                    &h6.callback,
                    "onFileProgress",
                    "(Ljava/lang/String;JJJZ)V",
                    &[
                        (&j_tid).into(),
                        (transferred as jlong).into(),
                        (total as jlong).into(),
                        (speed_bps as jlong).into(),
                        (if is_send { JNI_TRUE } else { JNI_FALSE }).into(),
                    ],
                );
            }
        },
    ));

    // 7. File transfer completed callback
    let h7 = Arc::clone(&holder);
    wrapper.engine.on_file_completed(Arc::new(
        move |transfer_id, file_path, is_send, success, error_msg| {
            if let Ok(mut env) = h7.vm.attach_current_thread() {
                let j_tid = env.new_string(transfer_id).unwrap_or_default();
                let j_path = env.new_string(file_path).unwrap_or_default();
                let j_err = env.new_string(error_msg).unwrap_or_default();

                let _ = env.call_method(
                    &h7.callback,
                    "onFileCompleted",
                    "(Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;)V",
                    &[
                        (&j_tid).into(),
                        (&j_path).into(),
                        (if is_send { JNI_TRUE } else { JNI_FALSE }).into(),
                        (if success { JNI_TRUE } else { JNI_FALSE }).into(),
                        (&j_err).into(),
                    ],
                );
            }
        },
    ));

    // 8. Incoming file stream delegation callback.
    // Hands the raw POSIX socket fd to the Kotlin receiver so it can stream directly into
    // a MediaStore-backed OutputStream, bypassing the private staging file + copy path.
    // Returning false makes the Rust side fall back to its own receiver.
    let h8 = Arc::clone(&holder);
    wrapper.engine.on_incoming_file_stream(Arc::new(
        move |raw_fd: i32, offer: &crate::sync::protocol::FileOfferPayload, bulk_key: &[u8; 32]| {
            let Ok(mut env) = h8.vm.attach_current_thread() else {
                return false;
            };

            let j_tid = env.new_string(&offer.transfer_id).unwrap_or_default();
            let j_from_id = env.new_string(&offer.from_device_id).unwrap_or_default();
            let j_from_name = env.new_string(&offer.from_device_name).unwrap_or_default();
            let j_file_name = env.new_string(&offer.file_name).unwrap_or_default();
            let j_salt = match env.byte_array_from_slice(&offer.stream_salt.unwrap_or([0u8; 16])) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let j_key = match env.byte_array_from_slice(bulk_key) {
                Ok(k) => k,
                Err(_) => return false,
            };

            let result = env.call_method(
                &h8.callback,
                "onIncomingFileStream",
                "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;JIJ[BI[B)Z",
                &[
                    (&j_tid).into(),
                    (&j_from_id).into(),
                    (&j_from_name).into(),
                    (&j_file_name).into(),
                    (offer.file_size as jlong).into(),
                    (offer.chunk_size as jint).into(),
                    (offer.total_chunks as jlong).into(),
                    (&j_salt).into(),
                    (raw_fd as jint).into(),
                    (&j_key).into(),
                ],
            );

            match result {
                Ok(v) => matches!(v.z(), Ok(true)),
                Err(_) => {
                    let _ = env.exception_clear();
                    false
                }
            }
        },
    ));

    0
}

// -----------------------------------------------------------------------------
// High-Speed Encrypted File Transfer JNI Exports
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeGetBulkSessionKey<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    out_key: jni::objects::JByteArray<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    if let Some(session_key) = wrapper.engine.get_bulk_session_key() {
        let mut salt_i8 = [0i8; 16];
        let derived_key = if env.get_byte_array_region(&out_key, 0, &mut salt_i8).is_ok()
            && salt_i8.iter().any(|&b| b != 0)
        {
            let salt_u8: [u8; 16] = unsafe { std::mem::transmute(salt_i8) };
            crate::sync::crypto::derive_bulk_key(&session_key, &salt_u8)
        } else {
            session_key
        };
        let key_i8: [i8; 32] = unsafe { std::mem::transmute(derived_key) };
        if env.set_byte_array_region(&out_key, 0, &key_i8).is_ok() {
            return 0;
        }
    }
    -1
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDeriveBulkKey<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    peer_key: jni::objects::JByteArray<'local>,
    stream_salt: jni::objects::JByteArray<'local>,
    out_bulk_key: jni::objects::JByteArray<'local>,
) -> jint {
    if peer_key.is_null() || stream_salt.is_null() || out_bulk_key.is_null() {
        return -1;
    }
    if env.get_array_length(&peer_key).unwrap_or(0) != 32
        || env.get_array_length(&stream_salt).unwrap_or(0) < 16
        || env.get_array_length(&out_bulk_key).unwrap_or(0) < 32
    {
        return -1;
    }
    let mut key_i8 = [0i8; 32];
    let mut salt_i8 = [0i8; 16];
    if env
        .get_byte_array_region(&peer_key, 0, &mut key_i8)
        .is_err()
        || env
            .get_byte_array_region(&stream_salt, 0, &mut salt_i8)
            .is_err()
    {
        return -1;
    }
    let key_u8: [u8; 32] = unsafe { std::mem::transmute(key_i8) };
    let salt_u8: [u8; 16] = unsafe { std::mem::transmute(salt_i8) };
    let derived = crate::sync::crypto::derive_bulk_key(&key_u8, &salt_u8);
    let derived_i8: [i8; 32] = unsafe { std::mem::transmute(derived) };
    if env
        .set_byte_array_region(&out_bulk_key, 0, &derived_i8)
        .is_ok()
    {
        0
    } else {
        -1
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeEncodeFileOfferPacket<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    transfer_id: JString<'local>,
    file_name: JString<'local>,
    file_size: jlong,
    chunk_size: jint,
    total_chunks: jlong,
    stream_salt: jni::objects::JByteArray<'local>,
    out_packet: jni::objects::JByteArray<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let bulk_key = match wrapper.engine.get_bulk_session_key() {
        Some(k) => k,
        None => return -1,
    };

    let mut salt_i8 = [0i8; 16];
    if env
        .get_byte_array_region(&stream_salt, 0, &mut salt_i8)
        .is_err()
    {
        return -1;
    }
    let salt_u8: [u8; 16] = unsafe { std::mem::transmute(salt_i8) };

    let tid: String = env
        .get_string(&transfer_id)
        .map(|s| s.into())
        .unwrap_or_default();
    let fname: String = env
        .get_string(&file_name)
        .map(|s| s.into())
        .unwrap_or_default();

    let cfg = wrapper.engine.config();
    let offer = crate::sync::protocol::FileOfferPayload {
        transfer_id: tid,
        from_device_id: cfg.device_id.clone(),
        from_device_name: cfg.device_name.clone(),
        file_name: fname,
        file_size: file_size as u64,
        sha256: String::new(),
        mime_type: "application/octet-stream".to_string(),
        stream_nonce: None,
        stream_salt: Some(salt_u8),
        offset: 0,
        chunk_size: chunk_size as u32,
        total_chunks: total_chunks as u64,
    };

    match crate::sync::protocol::encode_file_offer_packet(&bulk_key, 1, &offer) {
        Ok(pkt) => {
            let out_len = env.get_array_length(&out_packet).unwrap_or(0) as usize;
            if pkt.len() > out_len {
                return -1;
            }
            let pkt_i8: &[i8] =
                unsafe { slice::from_raw_parts(pkt.as_ptr() as *const i8, pkt.len()) };
            if env.set_byte_array_region(&out_packet, 0, pkt_i8).is_ok() {
                pkt.len() as jint
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Decodes a framed `FileResponse` packet and returns:
/// - `1` if `resp.accepted && resp.transfer_id == transfer_id`
/// - `0` if `!resp.accepted`
/// - `-1` on decode or verification failure
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDecodeFileResponsePacket<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    packet: jni::objects::JByteArray<'local>,
    packet_len: jint,
    transfer_id: JString<'local>,
) -> jint {
    if sync_handle == 0 || packet_len <= 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let bulk_key = match wrapper.engine.get_bulk_session_key() {
        Some(k) => k,
        None => return -1,
    };

    let expected_tid: String = match env.get_string(&transfer_id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let len = packet_len as usize;
    let mut pkt_i8 = vec![0i8; len];
    if env.get_byte_array_region(&packet, 0, &mut pkt_i8).is_err() {
        return -1;
    }
    let pkt_u8: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(pkt_i8.as_mut_ptr() as *mut u8, len) };

    let decoded = crate::sync::protocol::decode_encrypted_frame_in_place_with_fallback::<
        crate::sync::protocol::FileResponsePayload,
    >(
        &bulk_key,
        &crate::sync::protocol::PAIR_BOOTSTRAP_KEY,
        pkt_u8,
    );

    match decoded {
        Ok((_h, resp)) => {
            if !expected_tid.is_empty() && resp.transfer_id != expected_tid {
                return -1;
            }
            if resp.accepted { 1 } else { 0 }
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeEncodeFileResponsePacket<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    peer_key: jni::objects::JByteArray<'local>,
    transfer_id: JString<'local>,
    accepted: jboolean,
    reason: JString<'local>,
    out_packet: jni::objects::JByteArray<'local>,
) -> jint {
    let key_to_use = if !peer_key.is_null() && env.get_array_length(&peer_key).unwrap_or(0) == 32 {
        let mut k_i8 = [0i8; 32];
        if env.get_byte_array_region(&peer_key, 0, &mut k_i8).is_ok() {
            Some(unsafe { std::mem::transmute::<[i8; 32], [u8; 32]>(k_i8) })
        } else {
            None
        }
    } else {
        None
    };

    let bulk_key = match key_to_use {
        Some(k) => k,
        None => {
            if sync_handle == 0 {
                return -1;
            }
            let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
            match wrapper.engine.get_bulk_session_key() {
                Some(k) => k,
                None => return -1,
            }
        }
    };

    let tid: String = env
        .get_string(&transfer_id)
        .map(|s| s.into())
        .unwrap_or_default();
    let emsg: String = env
        .get_string(&reason)
        .map(|s| s.into())
        .unwrap_or_default();

    let is_accepted = accepted == JNI_TRUE;
    let resp = crate::sync::protocol::FileResponsePayload {
        transfer_id: tid,
        accepted: is_accepted,
        error_code: if is_accepted { 0 } else { 1 },
        error_message: if emsg.is_empty() { None } else { Some(emsg) },
        offset: 0,
    };

    match crate::sync::protocol::encode_file_response_packet(&bulk_key, 1, &resp) {
        Ok(pkt) => {
            let out_len = env.get_array_length(&out_packet).unwrap_or(0) as usize;
            if pkt.len() > out_len {
                return -1;
            }
            let pkt_i8: &[i8] =
                unsafe { slice::from_raw_parts(pkt.as_ptr() as *const i8, pkt.len()) };
            if env.set_byte_array_region(&out_packet, 0, pkt_i8).is_ok() {
                pkt.len() as jint
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeEncodeFileFinishPacket<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    transfer_id: JString<'local>,
    total_chunks: jlong,
    _total_bytes: jlong,
    out_packet: jni::objects::JByteArray<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let bulk_key = match wrapper.engine.get_bulk_session_key() {
        Some(k) => k,
        None => return -1,
    };

    let tid: String = env
        .get_string(&transfer_id)
        .map(|s| s.into())
        .unwrap_or_default();

    let finish = crate::sync::protocol::FileFinishPayload {
        transfer_id: tid,
        sha256: String::new(),
        total_chunks: total_chunks as u64,
    };

    match crate::sync::protocol::encode_file_finish_packet(&bulk_key, 2, &finish) {
        Ok(pkt) => {
            let out_len = env.get_array_length(&out_packet).unwrap_or(0) as usize;
            if pkt.len() > out_len {
                return -1;
            }
            let pkt_i8: &[i8] =
                unsafe { slice::from_raw_parts(pkt.as_ptr() as *const i8, pkt.len()) };
            if env.set_byte_array_region(&out_packet, 0, pkt_i8).is_ok() {
                pkt.len() as jint
            } else {
                -1
            }
        }
        Err(_) => -1,
    }
}

/// Decodes and authenticates a framed `FileFinish` packet, returning `1` if valid, `-1` on error.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeDecodeFileFinishPacket<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    peer_key: jni::objects::JByteArray<'local>,
    packet: jni::objects::JByteArray<'local>,
    packet_len: jint,
    transfer_id: JString<'local>,
    expected_chunks: jlong,
    _expected_bytes: jlong,
) -> jint {
    if packet_len <= 0 {
        return -1;
    }
    let key_to_use = if !peer_key.is_null() && env.get_array_length(&peer_key).unwrap_or(0) == 32 {
        let mut k_i8 = [0i8; 32];
        if env.get_byte_array_region(&peer_key, 0, &mut k_i8).is_ok() {
            Some(unsafe { std::mem::transmute::<[i8; 32], [u8; 32]>(k_i8) })
        } else {
            None
        }
    } else {
        None
    };

    let bulk_key = match key_to_use {
        Some(k) => k,
        None => {
            if sync_handle == 0 {
                return -1;
            }
            let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
            match wrapper.engine.get_bulk_session_key() {
                Some(k) => k,
                None => return -1,
            }
        }
    };

    let expected_tid: String = match env.get_string(&transfer_id) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };

    let len = packet_len as usize;
    let mut pkt_i8 = vec![0i8; len];
    if env.get_byte_array_region(&packet, 0, &mut pkt_i8).is_err() {
        return -1;
    }
    let pkt_u8: &mut [u8] =
        unsafe { slice::from_raw_parts_mut(pkt_i8.as_mut_ptr() as *mut u8, len) };

    match crate::sync::protocol::decode_file_finish_packet_in_place(&bulk_key, pkt_u8) {
        Ok((_h, finish)) => {
            if !expected_tid.is_empty() && finish.transfer_id != expected_tid {
                return -1;
            }
            if expected_chunks >= 0 && finish.total_chunks != expected_chunks as u64 {
                return -1;
            }
            1
        }
        Err(_) => -1,
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeSendFile<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    peer_addr: JString<'local>,
    file_path: JString<'local>,
    display_name: JString<'local>,
) -> JString<'local> {
    if sync_handle == 0 {
        return env.new_string("").unwrap_or_default();
    }
    let p_addr: String = match env.get_string(&peer_addr) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap_or_default(),
    };
    let f_path: String = match env.get_string(&file_path) {
        Ok(s) => s.into(),
        Err(_) => return env.new_string("").unwrap_or_default(),
    };
    let d_name: String = match env.get_string(&display_name) {
        Ok(s) => s.into(),
        Err(_) => String::new(),
    };

    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    let custom_opt = if d_name.trim().is_empty() {
        None
    } else {
        Some(d_name.as_str())
    };
    match wrapper
        .engine
        .send_file_with_name(&p_addr, &f_path, custom_opt)
    {
        Ok(tid) => env.new_string(tid).unwrap_or_default(),
        Err(_) => env.new_string("").unwrap_or_default(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeCancelFileTransfer<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    transfer_id: JString<'local>,
) -> jboolean {
    if sync_handle == 0 {
        return JNI_FALSE;
    }
    let tid: String = match env.get_string(&transfer_id) {
        Ok(s) => s.into(),
        Err(_) => return JNI_FALSE,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    if wrapper.engine.cancel_file_transfer(&tid) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_com_muclip_core_MuClipNative_nativeSetFileSaveDir<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    sync_handle: jlong,
    save_dir: JString<'local>,
) -> jint {
    if sync_handle == 0 {
        return -1;
    }
    let s_dir: String = match env.get_string(&save_dir) {
        Ok(s) => s.into(),
        Err(_) => return -1,
    };
    let wrapper = unsafe { &*(sync_handle as usize as *mut SyncEngineWrapper) };
    wrapper.engine.set_file_save_directory(s_dir);
    0
}

use std::ffi::{CString, c_char};
use std::sync::Arc;

use super::sync::MuClipSyncHandle;
use super::{c_char_to_str, string_to_c_char};

pub type MuClipFileProgressCallback = unsafe extern "C" fn(
    transfer_id: *const c_char,
    transferred_bytes: u64,
    total_bytes: u64,
    speed_bps: u64,
    is_send: i32,
    user_data: *mut std::ffi::c_void,
);

pub type MuClipFileCompletedCallback = unsafe extern "C" fn(
    transfer_id: *const c_char,
    file_path: *const c_char,
    is_send: i32,
    success: i32,
    error_msg: *const c_char,
    user_data: *mut std::ffi::c_void,
);

pub type MuClipFileOfferCallback = unsafe extern "C" fn(
    transfer_id: *const c_char,
    from_device_id: *const c_char,
    from_device_name: *const c_char,
    file_name: *const c_char,
    file_size: u64,
    user_data: *mut std::ffi::c_void,
);

struct FileCallbackWrapper {
    progress_cb: Option<MuClipFileProgressCallback>,
    completed_cb: Option<MuClipFileCompletedCallback>,
    offer_cb: Option<MuClipFileOfferCallback>,
    user_data: usize,
}
unsafe impl Send for FileCallbackWrapper {}
unsafe impl Sync for FileCallbackWrapper {}

/// Initiates sending a file to remote peer endpoint. Returns transfer ID string (must be freed), or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_send_file(
    handle: *mut MuClipSyncHandle,
    peer_addr: *const c_char,
    file_path: *const c_char,
) -> *mut c_char {
    if handle.is_null() {
        return std::ptr::null_mut();
    }
    let p_addr = match unsafe { c_char_to_str(peer_addr) } {
        Some(a) => a,
        None => return std::ptr::null_mut(),
    };
    let f_path = match unsafe { c_char_to_str(file_path) } {
        Some(p) => p,
        None => return std::ptr::null_mut(),
    };
    let engine = unsafe { &*handle };
    match engine.inner.send_file(p_addr, f_path) {
        Ok(tid) => string_to_c_char(tid),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Cancels an in-progress file transfer. Returns 0 if canceled, -1 otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_cancel_file_transfer(
    handle: *mut MuClipSyncHandle,
    transfer_id: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let tid = match unsafe { c_char_to_str(transfer_id) } {
        Some(t) => t,
        None => return -1,
    };
    let engine = unsafe { &*handle };
    if engine.inner.cancel_file_transfer(tid) {
        0
    } else {
        -1
    }
}

/// Sets the destination directory for received incoming files.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_file_save_dir(
    handle: *mut MuClipSyncHandle,
    save_dir: *const c_char,
) -> i32 {
    if handle.is_null() {
        return -1;
    }
    let dir = match unsafe { c_char_to_str(save_dir) } {
        Some(d) => d,
        None => return -1,
    };
    let engine = unsafe { &*handle };
    engine
        .inner
        .set_file_save_directory(std::path::PathBuf::from(dir));
    0
}

/// Registers callbacks for file transfer progress, completion, and incoming offers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn muclip_sync_set_file_callbacks(
    handle: *mut MuClipSyncHandle,
    progress_cb: Option<MuClipFileProgressCallback>,
    completed_cb: Option<MuClipFileCompletedCallback>,
    offer_cb: Option<MuClipFileOfferCallback>,
    user_data: *mut std::ffi::c_void,
) {
    if handle.is_null() {
        return;
    }
    let engine = unsafe { &*handle };
    let wrapper = Arc::new(FileCallbackWrapper {
        progress_cb,
        completed_cb,
        offer_cb,
        user_data: user_data as usize,
    });

    if progress_cb.is_some() {
        let w = Arc::clone(&wrapper);
        engine
            .inner
            .on_file_progress(Arc::new(move |tid, transferred, total, speed, is_send| {
                if let Some(cb) = w.progress_cb {
                    let tid_c = CString::new(tid).unwrap_or_default();
                    let ud = w.user_data as *mut std::ffi::c_void;
                    unsafe {
                        cb(
                            tid_c.as_ptr(),
                            transferred,
                            total,
                            speed,
                            if is_send { 1 } else { 0 },
                            ud,
                        );
                    }
                }
            }));
    }

    if completed_cb.is_some() {
        let w = Arc::clone(&wrapper);
        engine
            .inner
            .on_file_completed(Arc::new(move |tid, path, is_send, success, err| {
                if let Some(cb) = w.completed_cb {
                    let tid_c = CString::new(tid).unwrap_or_default();
                    let path_c = CString::new(path).unwrap_or_default();
                    let err_c = CString::new(err).unwrap_or_default();
                    let ud = w.user_data as *mut std::ffi::c_void;
                    unsafe {
                        cb(
                            tid_c.as_ptr(),
                            path_c.as_ptr(),
                            if is_send { 1 } else { 0 },
                            if success { 1 } else { 0 },
                            err_c.as_ptr(),
                            ud,
                        );
                    }
                }
            }));
    }

    if offer_cb.is_some() {
        let w = Arc::clone(&wrapper);
        engine.inner.on_file_offer(Arc::new(
            move |tid, from_id, from_name, file_name, file_size| {
                if let Some(cb) = w.offer_cb {
                    let tid_c = CString::new(tid).unwrap_or_default();
                    let from_id_c = CString::new(from_id).unwrap_or_default();
                    let from_name_c = CString::new(from_name).unwrap_or_default();
                    let file_name_c = CString::new(file_name).unwrap_or_default();
                    let ud = w.user_data as *mut std::ffi::c_void;
                    unsafe {
                        cb(
                            tid_c.as_ptr(),
                            from_id_c.as_ptr(),
                            from_name_c.as_ptr(),
                            file_name_c.as_ptr(),
                            file_size,
                            ud,
                        );
                    }
                }
            },
        ));
    }
}

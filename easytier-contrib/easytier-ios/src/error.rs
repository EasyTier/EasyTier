use std::{
    cell::RefCell,
    ffi::{CStr, CString, c_char},
    ptr,
};

thread_local! {
    // Thread-local last error for the easytier-ios C ABI. `easytier_ios_*`
    // wrappers record forwarder-side failures here (instance APIs record
    // theirs in easytier-ffi's own buffer); `last_error` merges both layers.
    static LAST_ERROR: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn set_error(message: &str) {
    LAST_ERROR.with(|cell| {
        let mut buffer = cell.borrow_mut();
        buffer.clear();
        buffer.extend_from_slice(message.as_bytes());
    });
}

pub(crate) fn clear_error() {
    LAST_ERROR.with(|cell| cell.borrow_mut().clear());
}

fn thread_local_error() -> Option<String> {
    LAST_ERROR.with(|cell| {
        let buffer = cell.borrow();
        if buffer.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&buffer).into_owned())
        }
    })
}

fn ffi_error() -> Option<String> {
    unsafe {
        let mut error_ptr: *const c_char = ptr::null();
        easytier_ffi::get_error_msg(&mut error_ptr);
        if error_ptr.is_null() {
            None
        } else {
            let error_str = CStr::from_ptr(error_ptr).to_string_lossy().into_owned();
            easytier_ffi::free_string(error_ptr);
            Some(error_str)
        }
    }
}

/// Merge both error layers: the iOS wrapper's own thread-local buffer and
/// easytier-ffi's last FFI error.
pub(crate) fn last_error() -> Option<String> {
    match (ffi_error(), thread_local_error()) {
        (Some(ffi_error), Some(local_error)) => Some(format!("{local_error}; {ffi_error}")),
        (Some(ffi_error), None) => Some(ffi_error),
        (None, Some(local_error)) => Some(local_error),
        (None, None) => None,
    }
}

/// Alias kept under the android-jni name so the shared forwarder test suite
/// stays byte-identical across both crates.
#[cfg(test)]
pub(crate) fn get_last_error() -> Option<String> {
    last_error()
}

/// Copy the merged last error into a newly allocated C string (null when
/// there is no error). The caller owns the result and must release it with
/// `easytier_ios_free_string`.
pub(crate) fn last_error_raw() -> *mut c_char {
    match last_error().and_then(|message| CString::new(message).ok()) {
        Some(message) => message.into_raw(),
        None => ptr::null_mut(),
    }
}

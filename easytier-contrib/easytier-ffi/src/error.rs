use std::{
    cell::RefCell,
    ffi::{CString, c_char},
};

thread_local! {
    // # Thread Safety
    // set_error_msg and get_error_msg must be called on the same thread to
    // get correct error. And since `Handle::block_on` polls the top-level
    // future on the calling thread, set_error_msg always runs on the same
    // thread as the corresponding get_error_msg.
    static ERROR_MSG: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub(crate) fn set_error_msg(msg: &str) {
    ERROR_MSG.with(|cell| {
        let mut buf = cell.borrow_mut();
        buf.clear();
        buf.extend_from_slice(msg.as_bytes());
    });
}

fn thread_local_error_msg() -> Option<String> {
    ERROR_MSG.with(|cell| {
        let buf = cell.borrow();
        if buf.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&buf).into_owned())
        }
    })
}

pub(crate) unsafe fn get_error_msg(out: *mut *const c_char) {
    let msg = match (
        thread_local_error_msg(),
        crate::config_server::last_callback_error(),
    ) {
        (Some(error), Some(callback_error)) => Some(format!(
            "{}; config server callback error: {}",
            error, callback_error
        )),
        (Some(error), None) => Some(error),
        (None, Some(callback_error)) => {
            Some(format!("config server callback error: {}", callback_error))
        }
        (None, None) => None,
    };
    let cstr = msg.and_then(|msg| CString::new(msg).ok());
    unsafe {
        *out = match cstr {
            Some(s) => s.into_raw() as *const c_char,
            None => std::ptr::null(),
        };
    }
}

pub(crate) fn free_string(s: *const c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(s as *mut c_char);
    }
}

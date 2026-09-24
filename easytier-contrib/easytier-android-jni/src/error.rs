use std::{
    ffi::{CStr, c_char},
    ptr,
    sync::Mutex,
};

use easytier_ffi::{free_string, get_error_msg};
use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jstring;
use once_cell::sync::Lazy;

static JNI_CALLBACK_ERROR: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

pub(crate) fn set_callback_error(error: String) {
    log::error!("{}", error);
    if let Ok(mut guard) = JNI_CALLBACK_ERROR.lock() {
        *guard = Some(error);
    }
}

pub(crate) fn clear_callback_error() {
    if let Ok(mut guard) = JNI_CALLBACK_ERROR.lock() {
        *guard = None;
    }
}

fn take_callback_error() -> Option<String> {
    JNI_CALLBACK_ERROR
        .lock()
        .ok()
        .and_then(|mut guard| guard.take())
}

fn get_ffi_last_error() -> Option<String> {
    unsafe {
        let mut error_ptr: *const c_char = ptr::null();
        get_error_msg(&mut error_ptr);
        if error_ptr.is_null() {
            None
        } else {
            let error_cstr = CStr::from_ptr(error_ptr);
            let error_str = error_cstr.to_string_lossy().into_owned();
            free_string(error_ptr);
            Some(error_str)
        }
    }
}

pub(crate) fn get_last_error() -> Option<String> {
    match (get_ffi_last_error(), take_callback_error()) {
        (Some(ffi_error), Some(callback_error)) => Some(format!(
            "{}; config server callback error: {}",
            ffi_error, callback_error
        )),
        (Some(ffi_error), None) => Some(ffi_error),
        (None, Some(callback_error)) => Some(callback_error),
        (None, None) => None,
    }
}

pub(crate) fn throw_exception(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", message);
}

pub(crate) fn get_last_error_jni(env: JNIEnv, _class: JClass) -> jstring {
    match get_last_error() {
        Some(error) => match env.new_string(&error) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}

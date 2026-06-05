use std::ffi::{c_char, c_void};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValuePair {
    pub key: *const c_char,
    pub value: *const c_char,
}

pub type ConfigServerEventCallback = Option<unsafe extern "C" fn(*const c_char, *mut c_void)>;

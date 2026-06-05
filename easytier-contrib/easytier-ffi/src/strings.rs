use std::ffi::{CStr, c_char};

pub(crate) unsafe fn c_str_to_string(ptr: *const c_char, name: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("{} is null", name));
    }

    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map(|value| value.to_string())
        .map_err(|err| format!("{} is not valid UTF-8: {}", name, err))
}

pub(crate) unsafe fn optional_c_str_to_string(
    ptr: *const c_char,
    name: &str,
) -> Result<Option<String>, String> {
    if ptr.is_null() {
        return Ok(None);
    }

    unsafe { c_str_to_string(ptr, name) }.map(Some)
}

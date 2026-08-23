use std::ffi::CString;

use jni::JNIEnv;
use jni::objects::JString;

pub(crate) fn jstring_to_cstring(env: &mut JNIEnv, jstr: &JString) -> Result<CString, String> {
    let java_str = env
        .get_string(jstr)
        .map_err(|e| format!("Failed to get string: {:?}", e))?;
    let rust_str = java_str.to_str().map_err(|_| "Invalid UTF-8".to_string())?;
    CString::new(rust_str).map_err(|_| "String contains null byte".to_string())
}

pub(crate) fn optional_jstring_to_cstring(
    env: &mut JNIEnv,
    jstr: &JString,
) -> Result<Option<CString>, String> {
    if jstr.is_null() {
        return Ok(None);
    }

    jstring_to_cstring(env, jstr).map(Some)
}

/// Build a NUL-terminated C string from a Rust string for FFI calls.
pub(crate) fn cstring_for(value: &str, what: &str) -> std::io::Result<CString> {
    CString::new(value)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{what} contains a null byte")))
}

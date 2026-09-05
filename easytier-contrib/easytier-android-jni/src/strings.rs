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

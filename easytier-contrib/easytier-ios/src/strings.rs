use std::ffi::CString;

/// Build a NUL-terminated C string from a Rust string for FFI calls.
pub(crate) fn cstring_for(value: &str, what: &str) -> std::io::Result<CString> {
    CString::new(value)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{what} contains a null byte")))
}

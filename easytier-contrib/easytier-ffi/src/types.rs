use std::ffi::{c_char, c_void};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValuePair {
    pub key: *const c_char,
    pub value: *const c_char,
}

pub type ConfigServerEventCallback = Option<unsafe extern "C" fn(*const c_char, *mut c_void)>;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPlaneSocketAddr {
    /// `4` for IPv4. Other families are reserved for later ABI versions.
    pub family: u16,
    /// Native-endian port number.
    pub port: u16,
    /// Network-order address bytes. IPv4 uses the first four bytes.
    pub address: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DataPlaneCompletion {
    pub operation_id: u64,
    pub operation_kind: u16,
    /// `0` for success, otherwise a stable `DataPlaneErrorKind` value.
    pub status: u16,
}

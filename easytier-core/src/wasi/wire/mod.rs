//! WASI host ABI codecs shared by concrete adapters.

pub(crate) mod common;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) mod data_plane;
pub(crate) mod dns;
pub(crate) mod options;
pub(crate) mod socket;

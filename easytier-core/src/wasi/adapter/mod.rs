//! Concrete implementations of portable Host capability seams for WASI.

pub mod dns;
pub mod environment;
pub mod event;
#[cfg(feature = "management")]
pub mod management;
pub mod packet;
pub mod socket;

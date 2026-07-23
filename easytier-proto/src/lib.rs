#[cfg(feature = "core")]
pub mod rpc_types;

#[cfg(feature = "core")]
pub mod acl;
#[cfg(feature = "api")]
pub mod api;
#[cfg(feature = "core")]
pub mod common;
#[cfg(feature = "core")]
pub mod core_config;
#[cfg(feature = "core")]
pub mod core_peer;
#[cfg(feature = "core")]
pub mod error;
#[cfg(all(feature = "api", feature = "magic-dns"))]
pub mod magic_dns;
#[cfg(feature = "core")]
pub mod peer_rpc;
#[cfg(feature = "api")]
pub mod tests;
#[cfg(feature = "utils")]
pub mod utils;
#[cfg(feature = "api")]
pub mod web;

pub const DESCRIPTOR_POOL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

pub const ALL_DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));

pub mod proto {
    pub use crate::*;
}

pub mod rpc_impl;
pub mod rpc_types;

pub mod acl;
pub mod api;
pub mod common;
pub mod error;
#[cfg(feature = "magic-dns")]
pub mod magic_dns;
pub mod peer_rpc;
pub mod web;

#[cfg(test)]
pub mod tests;
pub mod utils;

pub const DESCRIPTOR_POOL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

pub const ALL_DESCRIPTOR_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/descriptors.bin"));

pub mod rpc_impl;
pub mod rpc_types;

pub mod acl;
pub mod cli;
pub mod common;
pub mod error;
pub mod magic_dns;
pub mod peer_rpc;
pub mod web;

#[cfg(test)]
pub mod tests;

const DESCRIPTOR_POOL_BYTES: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/file_descriptor_set.bin"));

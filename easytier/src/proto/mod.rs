pub use easytier_proto::api;
#[cfg(feature = "web-client")]
pub use easytier_proto::web;
pub use easytier_proto::{
    ALL_DESCRIPTOR_BYTES, acl, common, core_config, error, peer_rpc, rpc_types,
};

#[cfg(feature = "magic-dns")]
pub mod dns;
#[cfg(feature = "magic-dns")]
pub mod utils;

#[cfg(test)]
pub mod tests;

pub mod rpc;

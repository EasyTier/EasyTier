pub use easytier_proto::{ALL_DESCRIPTOR_BYTES, DESCRIPTOR_POOL_BYTES};
pub use easytier_proto::{acl, api, common, core_config, error, peer_rpc, rpc_types, utils, web};

#[cfg(feature = "magic-dns")]
pub use easytier_proto::magic_dns;

#[cfg(test)]
pub mod tests;

pub mod rpc;

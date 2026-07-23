#[cfg(any(feature = "management", feature = "magic-dns"))]
pub use easytier_proto::api;
pub use easytier_proto::{acl, common, core_config, error, peer_rpc, rpc_types};
#[cfg(feature = "management")]
pub use easytier_proto::{utils, web};

#[cfg(feature = "magic-dns")]
pub use easytier_proto::magic_dns;

#[cfg(test)]
pub mod tests;

pub mod rpc;

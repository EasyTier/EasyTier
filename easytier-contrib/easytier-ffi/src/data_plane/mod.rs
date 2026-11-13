//! Native C ABI adapter for the instance-scoped data-plane operation broker.

#[cfg(feature = "ffi-dataplane")]
mod abi;
#[cfg(feature = "ffi-dataplane")]
mod session;

#[cfg(feature = "ffi-dataplane")]
pub use abi::*;
#[cfg(feature = "ffi-dataplane")]
pub(crate) use session::{
    lock_for_config_server_start, remove_data_plane_sessions_by_instance_ids,
};

#[cfg(not(feature = "ffi-dataplane"))]
pub(crate) fn remove_data_plane_sessions_by_instance_ids(_ids: &[uuid::Uuid]) {}

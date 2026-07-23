#[cfg(not(feature = "management"))]
#[path = "projection/compact.rs"]
mod implementation;
#[cfg(feature = "management")]
#[path = "projection/full.rs"]
mod implementation;

pub(super) use implementation::{format_last_update, node_config};

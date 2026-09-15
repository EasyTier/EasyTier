//! Access-control list packet filtering: the per-rule processor and the
//! filter wiring it into the peer/NIC packet pipelines.

pub(crate) mod filter;
pub(crate) mod processor;

pub(crate) use filter::AclFilter;

#[cfg(not(feature = "proxy-packet"))]
#[path = "packet_proxy/disabled.rs"]
mod implementation;
#[cfg(feature = "proxy-packet")]
#[path = "packet_proxy/enabled.rs"]
mod implementation;

pub(in crate::management) type JsonCall =
    Result<crate::proto::rpc_types::error::Result<serde_json::Value>, serde_json::Value>;

pub(in crate::management) use implementation::{call_json, register};

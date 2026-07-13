//! Native SOCKS5 command runtime around the portable core wire protocol.

#![forbid(unsafe_code)]

pub mod server;
pub mod util;

pub use easytier_core::proxy::socks5_protocol::*;

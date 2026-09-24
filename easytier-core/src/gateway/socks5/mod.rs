//! SOCKS5 protocol and Host-listener Adapter for the gateway data plane.

#![forbid(unsafe_code)]

mod adapter;
mod codec;
mod host;
mod server;

pub(crate) use adapter::Socks5GatewayAdapter;
pub(crate) use codec::{Result, SocksError};
pub(crate) use host::HostSocks5ServerRuntime;
pub(crate) use server::{AcceptAuthentication, AsyncTcpConnector, Config, Socks5Socket};

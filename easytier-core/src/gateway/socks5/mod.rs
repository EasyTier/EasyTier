//! SOCKS5 server stack and entry routing behind the gateway dataplane.

#![forbid(unsafe_code)]

mod codec;
mod entry_table;
mod host;
mod route;
mod server;

pub(crate) use codec::{Result, SocksError};
pub(crate) use entry_table::{Socks5Entry, Socks5EntryGuard, Socks5EntryKind, Socks5EntryTable};
pub(crate) use host::{HostSocks5ServerRuntime, HostSocks5TcpConnector};
pub(crate) use route::{Socks5PeerPacketRoute, Socks5TcpConnectPlan, Socks5TcpRoute};
pub(crate) use server::{
    AcceptAuthentication, AsyncTcpConnector, Config, Socks5ServerRuntime, Socks5Socket,
};

use async_trait::async_trait;
use url::Url;

use crate::{socket::tcp::VirtualTcpSocket, tunnel::Tunnel};

use super::transport::ConnectedTransport;

pub mod raw;

#[async_trait]
pub trait ClientProtocolUpgrader<TcpSocket>: Send + Sync + 'static {
    fn supports_scheme(&self, scheme: &str) -> bool;

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>>;
}

/// Core's built-in TCP and UDP tunnel framing.
///
/// Hosts only need to provide a different upgrader when they enable an
/// optional protocol whose implementation has not moved into core yet.
#[derive(Debug, Default)]
pub struct RawClientProtocolUpgrader;

#[async_trait]
impl<TcpSocket> ClientProtocolUpgrader<TcpSocket> for RawClientProtocolUpgrader
where
    TcpSocket: VirtualTcpSocket,
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "tcp" | "udp")
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(raw::upgrade_connected(connected, requested_url)?)
    }
}

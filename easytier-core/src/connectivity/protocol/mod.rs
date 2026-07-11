use async_trait::async_trait;
use url::Url;

use crate::tunnel::Tunnel;

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

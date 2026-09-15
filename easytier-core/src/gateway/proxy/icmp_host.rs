use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

#[derive(Debug, thiserror::Error)]
pub enum ProxyRuntimeError {
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<std::io::Error> for ProxyRuntimeError {
    fn from(value: std::io::Error) -> Self {
        Self::Other(value.into())
    }
}

#[async_trait::async_trait]
pub trait IcmpProxySocket: Send + Sync + 'static {
    async fn send(&self, destination: Ipv4Addr, packet: &[u8]) -> Result<(), ProxyRuntimeError>;

    async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError>;

    fn close(&self) {}
}

#[async_trait::async_trait]
pub trait IcmpProxyHost: Send + Sync + 'static {
    async fn open_icmp_v4(
        &self,
        context: crate::socket::SocketContext,
    ) -> Result<Arc<dyn IcmpProxySocket>, ProxyRuntimeError>;
}

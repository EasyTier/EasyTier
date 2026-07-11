use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use tokio::time::timeout;

use crate::socket::tcp::{TcpConnectOptions, VirtualTcpSocketFactory};

use super::{runtime::TcpProxyDestinationConnector, tcp_proxy_engine::TcpProxyMode};

pub struct TcpSocketProxyConnector<F: VirtualTcpSocketFactory> {
    socket_factory: Arc<F>,
}

impl<F: VirtualTcpSocketFactory> TcpSocketProxyConnector<F> {
    pub fn new(socket_factory: Arc<F>) -> Self {
        Self { socket_factory }
    }
}

#[async_trait::async_trait]
impl<F: VirtualTcpSocketFactory> TcpProxyDestinationConnector for TcpSocketProxyConnector<F> {
    type DstStream = F::Socket;

    async fn connect(&self, _src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream> {
        timeout(
            Duration::from_secs(10),
            self.socket_factory
                .connect_tcp(TcpConnectOptions::proxy_nat(dst)),
        )
        .await?
        .with_context(|| format!("connect to nat dst failed: {dst:?}"))
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::Tcp
    }
}

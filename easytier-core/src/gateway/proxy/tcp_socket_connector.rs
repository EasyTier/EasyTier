use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;

use crate::{
    foundation::time::timeout,
    socket::{
        SocketContext,
        tcp::{TcpConnectOptions, VirtualTcpSocketFactory},
    },
};

use super::{tcp_proxy_engine::TcpProxyMode, traits::TcpProxyDestinationConnector};

pub struct TcpSocketProxyConnector<F: VirtualTcpSocketFactory> {
    socket_factory: Arc<F>,
    socket_context: SocketContext,
}

impl<F: VirtualTcpSocketFactory> TcpSocketProxyConnector<F> {
    pub fn new(socket_factory: Arc<F>) -> Self {
        Self {
            socket_factory,
            socket_context: SocketContext::default(),
        }
    }

    pub fn with_socket_context(mut self, socket_context: SocketContext) -> Self {
        self.socket_context = socket_context;
        self
    }
}

#[async_trait::async_trait]
impl<F: VirtualTcpSocketFactory> TcpProxyDestinationConnector for TcpSocketProxyConnector<F> {
    type DstStream = F::Socket;

    async fn connect(&self, _src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream> {
        timeout(
            Duration::from_secs(10),
            self.socket_factory.connect_tcp(
                TcpConnectOptions::proxy_nat(dst).with_bind(
                    crate::socket::tcp::TcpBindOptions::default().with_context(
                        self.socket_context
                            .clone()
                            .with_ip_version(if dst.is_ipv4() {
                                crate::socket::IpVersion::V4
                            } else {
                                crate::socket::IpVersion::V6
                            }),
                    ),
                ),
            ),
        )
        .await?
        .with_context(|| format!("connect to nat dst failed: {dst:?}"))
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::Tcp
    }
}

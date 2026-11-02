use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;

use super::{tcp_proxy_engine::TcpProxyMode, traits::TcpProxyDestinationConnector};
use crate::socket::SocketContext;
use crate::{
    foundation::time::timeout,
    socket::tcp::{TcpConnectOptions, VirtualTcpSocketFactory},
};
use crate::{socket::BindConfig, socket::IpVersion};

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
            self.socket_factory
                .connect_tcp(TcpConnectOptions::proxy_nat(dst).with_bind(BindConfig {
                    context: SocketContext {
                        ip_version: if dst.is_ipv4() {
                            IpVersion::V4
                        } else {
                            IpVersion::V6
                        },
                        ..self.socket_context.clone()
                    },
                    ..BindConfig::default()
                })),
        )
        .await?
        .with_context(|| format!("connect to nat dst failed: {dst:?}"))
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        TcpProxyMode::Tcp
    }
}

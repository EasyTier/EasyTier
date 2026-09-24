use std::fmt::Debug;
use url::Url;

use easytier_core::{socket::SocketListener, tunnel::Tunnel};

use crate::proto::rpc::standalone::{
    RuntimeRpcDialer, RuntimeRpcListener, runtime_rpc_dialer, runtime_rpc_listener,
};

#[derive(Debug)]
pub struct TcpTunnelListener(RuntimeRpcListener);

impl TcpTunnelListener {
    pub fn new(addr: Url) -> Self {
        let socket_addr = addr.socket_addrs(|| None).unwrap()[0];
        Self(runtime_rpc_listener(socket_addr))
    }
}

#[async_trait::async_trait]
impl SocketListener for TcpTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.0.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.0.accept().await?)
    }

    fn local_url(&self) -> Url {
        self.0.local_url()
    }
}

pub struct TcpTunnelConnector(RuntimeRpcDialer);

impl TcpTunnelConnector {
    pub fn new(addr: Url) -> Self {
        Self(runtime_rpc_dialer(addr))
    }
}

#[async_trait::async_trait]
impl easytier_core::connectivity::protocol::raw::TunnelDialer for TcpTunnelConnector {
    async fn connect(&self) -> Result<Box<dyn Tunnel>, anyhow::Error> {
        self.0.connect().await
    }

    fn remote_url(&self) -> Url {
        self.0.remote_url()
    }
}

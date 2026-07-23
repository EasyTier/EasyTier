use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::Bytes;

use crate::gateway::proxy::{
    traits::TcpProxyStream, wrapped_transport_destination::WrappedTransportDestinationIngress,
};

use super::{WrappedTransportDatagram, WrappedTransportDirections, WrappedTransportRole};

#[derive(Clone)]
pub struct WrappedTransportEngineStart {
    pub directions: WrappedTransportDirections,
    pub my_peer_id: u32,
    pub datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
    pub destination_ingress: Option<WrappedTransportDestinationIngress>,
}

#[derive(Debug, Clone, Copy)]
pub struct WrappedTransportConnect {
    pub my_peer_id: u32,
    pub dst_peer_id: u32,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

pub struct WrappedTransportAcceptedStream {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub initial_acl_packet_size: usize,
    pub stream: Box<dyn TcpProxyStream>,
}

#[async_trait]
pub trait WrappedTransportEngine: Send + Sync + 'static {
    async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()>;
    async fn activate(&self) -> anyhow::Result<()>;
    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()>;
    async fn connect_source(
        &self,
        request: WrappedTransportConnect,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>>;
    async fn stop(&self);
}

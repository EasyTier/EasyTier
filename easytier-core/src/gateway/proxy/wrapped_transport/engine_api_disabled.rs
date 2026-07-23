use async_trait::async_trait;
use bytes::Bytes;

use super::{WrappedTransportDatagram, WrappedTransportDirections, WrappedTransportRole};

#[derive(Clone)]
pub struct WrappedTransportEngineStart {
    pub directions: WrappedTransportDirections,
    pub my_peer_id: u32,
    pub datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
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
    async fn stop(&self);
}

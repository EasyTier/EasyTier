pub mod packet;
pub mod peer;
pub mod peer_conn;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_rip_route;
pub mod peer_rpc;
pub mod route_trait;
pub mod rpc_service;

pub mod foreign_network_client;
pub mod foreign_network_manager;

#[cfg(test)]
pub mod tests;

use tokio_util::bytes::{Bytes, BytesMut};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(
        &self,
        _packet: &packet::ArchivedPacket,
        _data: &Bytes,
    ) -> Option<()> {
        None
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: BytesMut) -> BytesMut;
}

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

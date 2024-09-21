pub mod peer;
// pub mod peer_conn;
pub mod peer_conn;
pub mod peer_conn_ping;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_rpc_service;
pub mod route_trait;
pub mod rpc_service;

pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;

#[cfg(test)]
pub mod tests;

use crate::tunnel::packet_def::ZCPacket;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(&self, _zc_packet: ZCPacket) -> Option<ZCPacket> {
        Some(_zc_packet)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket);
}

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

pub type PacketRecvChan = tokio::sync::mpsc::Sender<ZCPacket>;
pub type PacketRecvChanReceiver = tokio::sync::mpsc::Receiver<ZCPacket>;

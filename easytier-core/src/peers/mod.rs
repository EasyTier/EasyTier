pub mod acl_config;
pub(crate) mod acl_filter;
pub(crate) mod acl_processor;
pub mod context;
pub mod credential_manager;
pub(crate) mod encrypt;
pub mod error;
pub(crate) mod foreign_network_client;
pub mod foreign_network_manager;
pub(crate) mod graph_algo;
pub(crate) mod peer;
pub mod peer_center;
pub(crate) mod peer_conn;
pub(crate) mod peer_conn_ping;
pub mod peer_manager;
pub(crate) mod peer_map;
pub(crate) mod peer_ospf_route;
pub(crate) mod peer_rpc;
pub(crate) mod peer_session;
pub mod public_ipv6;
pub(crate) mod relay_peer_map;
pub(crate) mod route_trait;
pub(crate) mod secure_datagram;
pub(crate) mod traffic_metrics;
mod util;

#[cfg(test)]
mod tests;

use crate::packet::ZCPacket;

pub type PacketRecvChan = tokio::sync::mpsc::Sender<ZCPacket>;
pub type PacketRecvChanReceiver = tokio::sync::mpsc::Receiver<ZCPacket>;

pub fn create_packet_recv_chan() -> (PacketRecvChan, PacketRecvChanReceiver) {
    tokio::sync::mpsc::channel(128)
}

pub async fn recv_packet_from_chan(
    packet_recv_chan_receiver: &mut PacketRecvChanReceiver,
) -> Result<ZCPacket, anyhow::Error> {
    packet_recv_chan_receiver
        .recv()
        .await
        .ok_or(anyhow::anyhow!("recv_packet_from_chan failed"))
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerPacketFilter {
    async fn try_process_packet_from_peer(&self, zc_packet: ZCPacket) -> Option<ZCPacket> {
        Some(zc_packet)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait NicPacketFilter {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool;

    fn id(&self) -> String {
        format!("{:p}", self)
    }
}

pub type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
pub type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

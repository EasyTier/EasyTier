pub mod context;
pub mod credential_manager;
pub mod encrypt;
pub mod error;
pub mod graph_algo;
pub mod peer;
pub mod peer_conn;
pub mod peer_conn_ping;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_session;
pub mod route_trait;
pub mod secure_datagram;
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

mod graph_algo;

pub mod acl_filter;
pub mod credential_manager;
pub mod peer;
pub mod peer_conn;
pub mod peer_conn_ping;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_rpc_service;
pub mod peer_session;
pub(crate) mod public_ipv6;
pub mod relay_peer_map;
pub mod route_trait;
pub mod rpc_service;
mod traffic_metrics;

pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;
pub(crate) mod secure_datagram;

pub mod peer_task;

#[cfg(test)]
pub mod tests;

use crate::tunnel::packet_def::ZCPacket;

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

type BoxPeerPacketFilter = Box<dyn PeerPacketFilter + Send + Sync>;
type BoxNicPacketFilter = Box<dyn NicPacketFilter + Send + Sync>;

pub use easytier_core::peers::{
    PacketRecvChan, PacketRecvChanReceiver, create_packet_recv_chan, recv_packet_from_chan,
};

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

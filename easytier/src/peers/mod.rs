pub mod acl_filter;
pub mod credential_manager;
pub mod peer;
pub mod peer_conn;
pub mod peer_manager;
pub mod peer_map;
pub mod peer_ospf_route;
pub mod peer_rpc;
pub mod peer_rpc_service;
pub(crate) mod public_ipv6;
pub mod relay_peer_map;
pub mod rpc_service;
mod traffic_metrics;

pub mod foreign_network_client;
pub mod foreign_network_manager;

pub mod encrypt;

pub mod peer_task;

#[cfg(test)]
pub mod tests;

pub(crate) use easytier_core::peers::secure_datagram;
pub use easytier_core::peers::{
    BoxNicPacketFilter, BoxPeerPacketFilter, NicPacketFilter, PacketRecvChan,
    PacketRecvChanReceiver, PeerPacketFilter, create_packet_recv_chan, peer_conn_ping,
    peer_session, recv_packet_from_chan, route_trait,
};

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

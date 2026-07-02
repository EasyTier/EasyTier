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

pub use easytier_core::peers::{
    BoxNicPacketFilter, BoxPeerPacketFilter, NicPacketFilter, PacketRecvChan,
    PacketRecvChanReceiver, PeerPacketFilter, create_packet_recv_chan, recv_packet_from_chan,
};

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

pub use easytier_core::peers::{
    acl_filter, foreign_network_client, peer_map, peer_ospf_route, peer_task,
};

pub mod credential_manager {
    pub use crate::common::credential_manager::*;
}

pub mod peer_conn;
pub mod peer_manager;
pub mod peer_rpc_service;
pub mod relay_peer_map;
pub mod rpc_service;
pub(crate) use easytier_core::peers::traffic_metrics;

pub mod foreign_network_manager;

pub mod encrypt;

#[cfg(test)]
pub mod tests;

pub mod peer_rpc {
    pub use easytier_core::peers::peer_rpc::*;

    pub use crate::common::stats_manager::StatsRpcMetrics;
}

pub(crate) use easytier_core::peers::secure_datagram;
pub use easytier_core::peers::{
    BoxNicPacketFilter, BoxPeerPacketFilter, NicPacketFilter, PacketRecvChan,
    PacketRecvChanReceiver, PeerPacketFilter, create_packet_recv_chan, peer, peer_conn_ping,
    peer_session, recv_packet_from_chan, route_trait,
};

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

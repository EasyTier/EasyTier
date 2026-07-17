use async_trait::async_trait;
use quanta::Instant;

use crate::{peers::peer_manager::PeerManagerCore, tunnel::Tunnel};

use super::{
    tcp::TcpHolePunchTunnelSink,
    udp::{UdpHolePunchPeerSource, UdpHolePunchTunnelSink, UdpPunchCandidate},
};

#[async_trait]
impl UdpHolePunchPeerSource for PeerManagerCore {
    fn local_peer_id(&self) -> crate::config::PeerId {
        PeerManagerCore::my_peer_id(self)
    }

    fn network_name(&self) -> &str {
        PeerManagerCore::network_name(self)
    }

    fn p2p_policy_flags(&self) -> crate::config::P2pPolicyFlags {
        PeerManagerCore::p2p_policy_flags(self)
    }

    async fn candidates(&self) -> Vec<UdpPunchCandidate> {
        let now = Instant::now();
        let peer_map = self.get_peer_map();
        self.list_route_snapshots()
            .await
            .into_iter()
            .filter_map(|route| {
                let udp_nat_type = route
                    .stun_info
                    .as_ref()
                    .map(|info| info.udp_nat_type)
                    .unwrap_or_default();
                let Ok(udp_nat_type) = crate::proto::common::NatType::try_from(udp_nat_type) else {
                    return None;
                };
                Some(UdpPunchCandidate {
                    peer_id: route.peer_id,
                    udp_nat_type,
                    feature_flag: route.feature_flag,
                    has_direct_connection: peer_map.has_peer(route.peer_id),
                    has_recent_traffic: self.has_recent_traffic(route.peer_id, now),
                })
            })
            .collect()
    }
}

#[async_trait]
impl UdpHolePunchTunnelSink for PeerManagerCore {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_client_tunnel(self, tunnel, false)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_tunnel_as_server(self, tunnel, false)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl TcpHolePunchTunnelSink for PeerManagerCore {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_client_tunnel(self, tunnel, false)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_tunnel_as_server(self, tunnel, false)
            .await
            .map_err(anyhow::Error::from)
    }
}

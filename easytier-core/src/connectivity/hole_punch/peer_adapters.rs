use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use async_trait::async_trait;
use quanta::Instant;

use crate::{
    config::{P2pPolicyFlags, PeerId},
    foundation::task::ExternalTaskSignal,
    peers::peer_manager::PeerManagerCore,
    proto::{
        common::NatType,
        peer_rpc::{
            TcpHolePunchRpc, TcpHolePunchRpcClientFactory, UdpHolePunchRpc,
            UdpHolePunchRpcClientFactory,
        },
        rpc_types::{controller::BaseController, handler::Handler},
    },
    tunnel::Tunnel,
};

use super::{
    HolePunchRpcRegistry, HolePunchTunnelSink,
    tcp::{TcpHolePunchPeerSource, TcpPunchCandidate},
    udp::{UdpHolePunchPeerSource, UdpHolePunchRpcSource, UdpPunchCandidate},
};

#[async_trait]
impl UdpHolePunchPeerSource for PeerManagerCore {
    fn local_peer_id(&self) -> PeerId {
        PeerManagerCore::my_peer_id(self)
    }

    fn p2p_policy_flags(&self) -> P2pPolicyFlags {
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

    fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        PeerManagerCore::p2p_demand_notify(self)
    }

    fn is_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        PeerManagerCore::is_local_virtual_ip(self, ip)
    }

    async fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        PeerManagerCore::is_easytier_managed_ipv6(self, ip).await
    }
}

impl UdpHolePunchRpcSource for PeerManagerCore {
    fn local_peer_id(&self) -> PeerId {
        PeerManagerCore::my_peer_id(self)
    }

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn UdpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static> {
        PeerManagerCore::get_peer_rpc_mgr(self)
            .rpc_client()
            .scoped_client::<UdpHolePunchRpcClientFactory<BaseController>>(
                PeerManagerCore::my_peer_id(self),
                dst_peer_id,
                PeerManagerCore::network_name(self).to_owned(),
            )
    }
}

#[async_trait]
impl HolePunchTunnelSink for PeerManagerCore {
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
impl TcpHolePunchPeerSource for PeerManagerCore {
    fn local_peer_id(&self) -> PeerId {
        PeerManagerCore::my_peer_id(self)
    }

    fn p2p_policy_flags(&self) -> P2pPolicyFlags {
        PeerManagerCore::p2p_policy_flags(self)
    }

    fn tcp_hole_punching_disabled(&self) -> bool {
        PeerManagerCore::tcp_hole_punching_disabled(self)
    }

    fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        PeerManagerCore::p2p_demand_notify(self)
    }

    async fn candidates(&self) -> Vec<TcpPunchCandidate> {
        let now = Instant::now();
        let peer_map = self.get_peer_map();
        self.list_route_snapshots()
            .await
            .into_iter()
            .map(|route| TcpPunchCandidate {
                peer_id: route.peer_id,
                tcp_nat_type: route
                    .stun_info
                    .as_ref()
                    .map(|info| info.tcp_nat_type)
                    .and_then(|nat_type| NatType::try_from(nat_type).ok())
                    .unwrap_or(NatType::Unknown),
                feature_flag: route.feature_flag,
                has_direct_connection: peer_map.has_peer(route.peer_id),
                has_recent_traffic: self.has_recent_traffic(route.peer_id, now),
            })
            .collect()
    }

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn TcpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static> {
        PeerManagerCore::get_peer_rpc_mgr(self)
            .rpc_client()
            .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
                PeerManagerCore::my_peer_id(self),
                dst_peer_id,
                PeerManagerCore::network_name(self).to_owned(),
            )
    }
}

#[async_trait]
impl HolePunchRpcRegistry for PeerManagerCore {
    fn register_rpc_service<H>(&self, service: H)
    where
        H: Handler<Controller = BaseController>,
    {
        PeerManagerCore::get_peer_rpc_mgr(self)
            .rpc_server()
            .registry()
            .register(service, PeerManagerCore::network_name(self));
    }

    fn unregister_rpc_service<H>(&self, service: H)
    where
        H: Handler<Controller = BaseController>,
    {
        PeerManagerCore::get_peer_rpc_mgr(self)
            .rpc_server()
            .registry()
            .unregister(service, PeerManagerCore::network_name(self));
    }
}

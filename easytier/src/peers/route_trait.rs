use std::{net::{Ipv4Addr, Ipv6Addr}, sync::Arc};

use dashmap::DashMap;

use crate::{
    common::{global_ctx::NetworkIdentity, PeerId},
    proto::peer_rpc::{
        ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, RouteForeignNetworkInfos,
        RoutePeerInfo,
    },
};

#[derive(Clone, Debug)]
pub enum NextHopPolicy {
    LeastHop,
    LeastCost,
}

impl Default for NextHopPolicy {
    fn default() -> Self {
        NextHopPolicy::LeastHop
    }
}

pub type ForeignNetworkRouteInfoMap =
    DashMap<ForeignNetworkRouteInfoKey, ForeignNetworkRouteInfoEntry>;

#[async_trait::async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
    fn my_peer_id(&self) -> PeerId;
    async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
        DashMap::new()
    }
}

pub type RouteInterfaceBox = Box<dyn RouteInterface + Send + Sync>;

#[auto_impl::auto_impl(Box , &mut)]
pub trait RouteCostCalculatorInterface: Send + Sync {
    fn begin_update(&mut self) {}
    fn end_update(&mut self) {}

    fn calculate_cost(&self, _src: PeerId, _dst: PeerId) -> i32 {
        1
    }

    fn need_update(&self) -> bool {
        false
    }

    fn dump(&self) -> String {
        "All routes have cost 1".to_string()
    }
}

#[derive(Clone, Debug, Default)]
pub struct DefaultRouteCostCalculator;

impl RouteCostCalculatorInterface for DefaultRouteCostCalculator {}

pub type RouteCostCalculator = Box<dyn RouteCostCalculatorInterface>;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box, Arc)]
pub trait Route {
    async fn open(&self, interface: RouteInterfaceBox) -> Result<u8, ()>;
    async fn close(&self);

    async fn get_next_hop(&self, peer_id: PeerId) -> Option<PeerId>;
    async fn get_next_hop_with_policy(
        &self,
        peer_id: PeerId,
        _policy: NextHopPolicy,
    ) -> Option<PeerId> {
        self.get_next_hop(peer_id).await
    }

    async fn list_routes(&self) -> Vec<crate::proto::cli::Route>;

    async fn get_peer_id_by_ipv4(&self, _ipv4: &Ipv4Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ipv6(&self, _ipv6: &Ipv6Addr) -> Option<PeerId> {
        None
    }

    async fn get_peer_id_by_ip(&self, ip: &std::net::IpAddr) -> Option<PeerId> {
        match ip {
            std::net::IpAddr::V4(v4) => self.get_peer_id_by_ipv4(v4).await,
            std::net::IpAddr::V6(v6) => self.get_peer_id_by_ipv6(v6).await,
        }
    }

    async fn list_peers_own_foreign_network(
        &self,
        _network_identity: &NetworkIdentity,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn list_foreign_network_info(&self) -> RouteForeignNetworkInfos {
        Default::default()
    }

    // my peer id in foreign network is different from the one in local network
    // this function is used to get the peer id in local network
    async fn get_origin_my_peer_id(
        &self,
        _network_name: &str,
        _foreign_my_peer_id: PeerId,
    ) -> Option<PeerId> {
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {}

    async fn get_peer_info(&self, peer_id: PeerId) -> Option<RoutePeerInfo>;

    async fn get_peer_info_last_update_time(&self) -> std::time::Instant;

    async fn dump(&self) -> String {
        "this route implementation does not support dump".to_string()
    }
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;

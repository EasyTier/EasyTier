use std::{net::Ipv4Addr, sync::Arc};

use async_trait::async_trait;
use tokio_util::bytes::Bytes;

use crate::common::{error::Error, PeerId};

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

#[async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
    async fn send_route_packet(
        &self,
        msg: Bytes,
        route_id: u8,
        dst_peer_id: PeerId,
    ) -> Result<(), Error>;
    fn my_peer_id(&self) -> PeerId;
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

#[async_trait]
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

    async fn list_routes(&self) -> Vec<crate::rpc::Route>;

    async fn get_peer_id_by_ipv4(&self, _ipv4: &Ipv4Addr) -> Option<PeerId> {
        None
    }

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {}
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;

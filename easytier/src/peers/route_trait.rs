use std::{net::Ipv4Addr, sync::Arc};

use crate::common::PeerId;

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

#[async_trait::async_trait]
pub trait RouteInterface {
    async fn list_peers(&self) -> Vec<PeerId>;
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

    async fn set_route_cost_fn(&self, _cost_fn: RouteCostCalculator) {}

    async fn dump(&self) -> String {
        "this route implementation does not support dump".to_string()
    }
}

pub type ArcRoute = Arc<Box<dyn Route + Send + Sync>>;

use std::sync::{Arc, Weak};

pub use easytier_core::peer_center::instance::{
    PeerCenterInstance, PeerCenterInstanceService, PeerCenterPeerManagerTrait,
};

use crate::{
    common::{PeerId, global_ctx::GlobalCtx},
    peers::{
        peer_manager::PeerManager, peer_map::PeerMap, peer_rpc::PeerRpcManager,
        rpc_service::PeerManagerRpcService,
    },
    proto::peer_rpc::{DirectConnectedPeerInfo, PeerInfoForGlobalMap},
};

pub struct PeerMapWithPeerRpcManager {
    pub peer_map: Arc<PeerMap>,
    pub rpc_mgr: Arc<PeerRpcManager>,
    pub global_ctx: Arc<GlobalCtx>,
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        PeerManagerRpcService::list_peers(self).await.into()
    }

    fn my_peer_id(&self) -> PeerId {
        self.get_peer_map().my_peer_id()
    }

    fn network_name(&self) -> String {
        self.get_global_ctx().get_network_name()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.get_peer_rpc_mgr())
    }

    async fn list_routes(&self) -> Vec<easytier_core::proto::core_peer::peer::Route> {
        self.get_route().list_routes().await
    }
}

#[async_trait::async_trait]
impl PeerCenterPeerManagerTrait for PeerMapWithPeerRpcManager {
    async fn list_peers(&self) -> PeerInfoForGlobalMap {
        // TODO: currently latency between public server cannot be calculated because one public-server pair
        // has no connection between them. (hard to get latency from peer manager because it's hard to transform the peer id)
        // but it's fine because we don't want too much traffic between public servers.
        let peers = self.peer_map.list_peers();
        let mut ret = PeerInfoForGlobalMap::default();
        for peer in peers {
            if let Some(conns) = self.peer_map.list_peer_conns(peer).await {
                let Some(min_lat) = conns
                    .iter()
                    .map(|conn| conn.stats.as_ref().unwrap().latency_us)
                    .min()
                else {
                    continue;
                };

                ret.direct_peers.insert(
                    peer,
                    DirectConnectedPeerInfo {
                        latency_ms: std::cmp::max(1, (min_lat as u32 / 1000) as i32),
                    },
                );
            }
        }

        ret
    }

    fn my_peer_id(&self) -> PeerId {
        self.peer_map.my_peer_id()
    }

    fn network_name(&self) -> String {
        self.global_ctx.get_network_name()
    }

    fn get_rpc_mgr(&self) -> Weak<PeerRpcManager> {
        Arc::downgrade(&self.rpc_mgr)
    }

    async fn list_routes(&self) -> Vec<easytier_core::proto::core_peer::peer::Route> {
        self.peer_map.list_route_infos().await
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{
        peers::tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        proto::{
            peer_rpc::{GetGlobalPeerMapRequest, PeerCenterRpc},
            rpc_types::controller::BaseController,
        },
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    #[tokio::test]
    async fn test_peer_center_instance() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        let peer_mgr_c = create_mock_peer_manager().await;

        let peer_center_a = PeerCenterInstance::new(peer_mgr_a.clone());
        let peer_center_b = PeerCenterInstance::new(peer_mgr_b.clone());
        let peer_center_c = PeerCenterInstance::new(peer_mgr_c.clone());

        let peer_centers = [&peer_center_a, &peer_center_b, &peer_center_c];
        for pc in peer_centers.iter() {
            pc.init().await;
        }

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let mut digest = None;
        for pc in peer_centers.iter() {
            let rpc_service = pc.get_rpc_service();
            wait_for_condition(
                || {
                    let rpc_service = rpc_service.clone();
                    async move {
                        rpc_service
                            .get_global_peer_map(
                                BaseController::default(),
                                GetGlobalPeerMapRequest { digest: 0 },
                            )
                            .await
                            .unwrap()
                            .global_peer_map
                            .len()
                            == 3
                    }
                },
                Duration::from_secs(20),
            )
            .await;
            let resp = rpc_service
                .get_global_peer_map(
                    BaseController::default(),
                    GetGlobalPeerMapRequest { digest: 0 },
                )
                .await
                .unwrap();

            if let Some(prev) = digest {
                let v = resp.digest.unwrap_or_default();
                assert_eq!(prev, v);
                digest = Some(prev);
            } else {
                digest = resp.digest;
            }

            let mut route_cost = pc.get_cost_calculator();
            assert!(route_cost.need_update());

            route_cost.begin_update();
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_a.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_c.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_a.my_peer_id()) > 50
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_c.my_peer_id()) > 50
            );
            route_cost.end_update();
            assert!(!route_cost.need_update());
        }
    }
}

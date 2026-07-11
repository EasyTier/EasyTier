pub use easytier_core::peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService};

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

        let peer_center_a = PeerCenterInstance::new(peer_mgr_a.core());
        let peer_center_b = PeerCenterInstance::new(peer_mgr_b.core());
        let peer_center_c = PeerCenterInstance::new(peer_mgr_c.core());

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

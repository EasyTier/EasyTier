#[cfg(test)]
use easytier_core::peer_center::instance::PeerCenterInstance;
pub use easytier_core::peer_center::instance::PeerCenterInstanceService;

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use easytier_core::{
        connectivity::manual::{
            ManualConnectorManager as CoreManualConnectorManager,
            discovery::CoreManualEndpointResolver,
        },
        peers::peer_manager::PeerManagerCore,
    };

    use crate::{
        connector::{
            core_instance::{
                runtime_core_instance_adapters_with_ring_registry,
                runtime_endpoint_discovery_config, runtime_manual_options,
            },
            runtime::RuntimeConnectorHost,
        },
        instance::listeners::ListenerManager,
        peers::{
            peer_manager::PeerManager,
            tests::{create_mock_peer_manager, wait_route_appear},
        },
        proto::{
            peer_rpc::{GetGlobalPeerMapRequest, PeerCenterRpc},
            rpc_types::controller::BaseController,
        },
        tunnel::common::tests::wait_for_condition,
    };

    use super::*;

    async fn connect_through_core(
        client: Arc<PeerManager>,
        server: Arc<PeerManager>,
    ) -> (
        Arc<CoreManualConnectorManager<RuntimeConnectorHost>>,
        ListenerManager<PeerManagerCore>,
    ) {
        server
            .get_global_ctx()
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let mut listener = ListenerManager::new(server.get_global_ctx(), server.core());
        listener.prepare_listeners().await.unwrap();
        listener.run().await.unwrap();
        let listener_url = server
            .get_global_ctx()
            .get_running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "tcp")
            .unwrap();

        let global_ctx = client.get_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.bind_device = false;
        global_ctx.set_flags(flags);
        let adapters = runtime_core_instance_adapters_with_ring_registry(
            global_ctx.clone(),
            client.ring_registry(),
        );
        let endpoint_resolver = Arc::new(CoreManualEndpointResolver::new(
            adapters.host.clone(),
            adapters.dns.clone(),
            adapters.dns_records.clone(),
            runtime_endpoint_discovery_config(&global_ctx),
        ));
        let connector = Arc::new(CoreManualConnectorManager::new_with_events(
            client.core(),
            adapters.host,
            adapters.dns,
            endpoint_resolver,
            adapters.protocol.unwrap(),
            adapters.ring_registry,
            runtime_manual_options(&global_ctx),
            adapters.manual_events.unwrap(),
        ));
        connector.start();
        connector.add_connector(listener_url).unwrap();
        (connector, listener)
    }

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

        let (_connector_ab, _listener_b) =
            connect_through_core(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        let (_connector_bc, _listener_c) =
            connect_through_core(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

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

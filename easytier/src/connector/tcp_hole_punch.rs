use std::sync::Arc;

use easytier_core::hole_punch::tcp::TcpHolePunchConnector as CoreTcpHolePunchConnector;

use crate::{connector::runtime::RuntimeConnectorHost, peers::peer_manager::PeerManager};

pub(crate) type RuntimeTcpHolePunchConnector = CoreTcpHolePunchConnector<RuntimeConnectorHost>;

pub(crate) fn runtime_tcp_hole_punch_connector(
    peer_manager: Arc<PeerManager>,
) -> RuntimeTcpHolePunchConnector {
    let global_ctx = peer_manager.get_global_ctx();
    RuntimeTcpHolePunchConnector::new(
        peer_manager.core(),
        Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
        super::protocol::runtime_client_protocol_upgrader(global_ctx.clone()),
        super::protocol::runtime_server_protocol_upgrader(global_ctx),
    )
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use crate::{
        common::{error::Error, stun::StunInfoCollectorTrait},
        connector::tcp_hole_punch::{
            RuntimeTcpHolePunchConnector, runtime_tcp_hole_punch_connector,
        },
        peers::{
            peer_manager::PeerManager,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::common::{NatType, StunInfo},
        tunnel::common::tests::wait_for_condition,
    };

    struct MockStunInfoCollector {
        udp_nat_type: NatType,
        tcp_nat_type: NatType,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for MockStunInfoCollector {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                udp_nat_type: self.udp_nat_type as i32,
                tcp_nat_type: self.tcp_nat_type as i32,
                last_update_time: 0,
                public_ip: vec!["127.0.0.1".to_string(), "::1".to_string()],
                min_port: 100,
                max_port: 200,
            }
        }

        async fn get_udp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }

        async fn get_udp_port_mapping_with_socket(
            &self,
            udp: std::sync::Arc<tokio::net::UdpSocket>,
        ) -> Result<SocketAddr, Error> {
            self.get_udp_port_mapping(udp.local_addr()?.port()).await
        }

        async fn get_tcp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }
    }

    fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, tcp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
            tcp_nat_type,
        });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    async fn collect_lazy_punch_peers(connector: &RuntimeTcpHolePunchConnector) -> Vec<u32> {
        connector.collect_peers_need_task().await
    }

    #[tokio::test]
    async fn tcp_hole_punch_connects() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let hole_punching_a = runtime_tcp_hole_punch_connector(p_a.clone());
        let hole_punching_c = runtime_tcp_hole_punch_connector(p_c.clone());
        hole_punching_a.run();
        hole_punching_c.run();

        hole_punching_a.run_immediately().await;
        hole_punching_c.run_immediately().await;

        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                async move {
                    let a_has = p_a
                        .core()
                        .get_peer_map()
                        .list_peer_conns(p_c.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    let c_has = p_c
                        .core()
                        .get_peer_map()
                        .list_peer_conns(p_a.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    a_has || c_has
                }
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[tokio::test]
    async fn tcp_hole_punch_skip_symmetric_peer() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::Symmetric);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::Symmetric);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let hole_punching_a = runtime_tcp_hole_punch_connector(p_a.clone());
        let hole_punching_c = runtime_tcp_hole_punch_connector(p_c.clone());
        hole_punching_a.run();
        hole_punching_c.run();

        hole_punching_a.run_immediately().await;
        hole_punching_c.run_immediately().await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(
            p_a.core()
                .get_peer_map()
                .list_peer_conns(p_c.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
        assert!(
            p_c.core()
                .get_peer_map()
                .list_peer_conns(p_a.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn lazy_p2p_collects_tcp_hole_punch_tasks_only_after_recent_traffic() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        p_a.get_global_ctx().set_flags(flags);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();
        let connector = runtime_tcp_hole_punch_connector(p_a.clone());

        assert!(
            !collect_lazy_punch_peers(&connector)
                .await
                .contains(&p_c.my_peer_id())
        );

        p_a.core().mark_recent_traffic(p_c.my_peer_id());

        assert!(
            collect_lazy_punch_peers(&connector)
                .await
                .contains(&p_c.my_peer_id())
        );

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.disable_p2p = true;
        p_a.get_global_ctx().set_flags(flags);
        assert!(
            !collect_lazy_punch_peers(&connector)
                .await
                .contains(&p_c.my_peer_id())
        );
    }
}

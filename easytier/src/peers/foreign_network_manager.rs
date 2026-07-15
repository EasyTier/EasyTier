/*
foreign_network_manager is used to forward packets of other networks.  currently
only forward packets of peers that directly connected to this node.

in the future, with the help wo peer center we can forward packets of peers that
connected to any node in the local network.
*/
use std::sync::Arc;

use easytier_core::peers::context::TrustedKeySource;
use easytier_core::peers::foreign_network_manager as core_foreign_network_manager;

#[cfg(test)]
use crate::common::global_ctx::NetworkIdentity;
use crate::proto::api::instance::{
    ForeignNetworkEntryPb, PeerInfo, TrustedKeyInfoPb, TrustedKeySourcePb,
};

#[cfg(test)]
use super::create_packet_recv_chan;
pub(crate) fn foreign_network_info_to_api(
    info: core_foreign_network_manager::ForeignNetworkEntryInfo,
) -> ForeignNetworkEntryPb {
    ForeignNetworkEntryPb {
        network_secret_digest: info.network_secret_digest,
        my_peer_id_for_this_network: info.my_peer_id_for_this_network,
        peers: info
            .peers
            .into_iter()
            .map(|peer| PeerInfo {
                peer_id: peer.peer_id,
                conns: peer.conns.into_iter().map(Into::into).collect(),
                ..Default::default()
            })
            .collect(),
        trusted_keys: info
            .trusted_keys
            .into_iter()
            .map(|key| TrustedKeyInfoPb {
                pubkey: key.pubkey,
                source: match key.source {
                    TrustedKeySource::OspfNode => TrustedKeySourcePb::OspfNode.into(),
                    TrustedKeySource::OspfCredential => TrustedKeySourcePb::OspfCredential.into(),
                },
                expiry_unix: key.expiry_unix,
            })
            .collect(),
    }
}

#[cfg(test)]
pub mod tests {
    use easytier_core::peers::context::PeerContext as _;
    use easytier_core::stats_manager::{LabelSet, LabelType, MetricName};
    use easytier_core::tunnel::ring::RingTunnelRegistry;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        connector::udp_hole_punch::tests::{
            create_mock_peer_manager_with_mock_stun, replace_stun_info_collector,
        },
        peers::{
            peer_conn::tests::set_secure_mode_cfg,
            peer_manager::{PeerManager, RouteAlgoType},
            tests::{connect_peer_manager, wait_route_appear},
        },
        proto::common::NatType,
        set_global_var,
        tunnel::{
            common::tests::wait_for_condition,
            packet_def::{PacketType, ZCPacket},
        },
    };
    use std::time::Duration;

    use super::*;

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: LabelSet) -> u64 {
        peer_mgr
            .stats_manager()
            .get_metric(metric, &labels)
            .map(|metric| metric.value)
            .unwrap_or(0)
    }

    async fn create_mock_peer_manager_for_foreign_network_ext(
        network: &str,
        secret: &str,
    ) -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                network.to_string(),
                secret.to_string(),
            ))),
            s,
        ));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.core().run_for_test().await.unwrap();
        peer_mgr
    }

    async fn create_mock_credential_peer_manager_for_foreign_network(
        network: &str,
    ) -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new_credential(
            network.to_string(),
        )));
        set_secure_mode_cfg(&global_ctx, true);
        let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, global_ctx, s));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.core().run_for_test().await.unwrap();
        peer_mgr
    }

    pub async fn create_mock_peer_manager_for_foreign_network(network: &str) -> Arc<PeerManager> {
        create_mock_peer_manager_for_foreign_network_ext(network, network).await
    }

    pub async fn create_mock_peer_manager_for_secure_foreign_network(
        network: &str,
    ) -> Arc<PeerManager> {
        let (s, _r) = create_packet_recv_chan();
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network.to_string(),
            network.to_string(),
        )));
        set_secure_mode_cfg(&global_ctx, true);
        let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, global_ctx, s));
        replace_stun_info_collector(peer_mgr.clone(), NatType::Unknown);
        peer_mgr.core().run_for_test().await.unwrap();
        peer_mgr
    }

    #[tokio::test]
    async fn foreign_network_basic() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());

        println!("{:?}", pmb_net1.list_routes().await);

        let foreign_infos = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert_eq!(1, foreign_infos.len());
        assert_eq!(2, foreign_infos["net1"].peers.len());
    }

    #[tokio::test]
    async fn foreign_network_forwarding_records_traffic_metrics() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let center_peer_id = pm_center
            .get_foreign_network_manager()
            .get_network_peer_id("net1")
            .unwrap();

        let mut rx_pkt = ZCPacket::new_with_payload(b"foreign-rx");
        rx_pkt.fill_peer_manager_hdr(
            pma_net1.my_peer_id(),
            center_peer_id,
            PacketType::Data as u8,
        );
        pma_net1
            .core()
            .get_foreign_network_client()
            .send_msg(rx_pkt, center_peer_id)
            .await
            .unwrap();

        let mut tx_pkt = ZCPacket::new_with_payload(b"foreign-tx");
        tx_pkt.fill_peer_manager_hdr(
            center_peer_id,
            pmb_net1.my_peer_id(),
            PacketType::Data as u8,
        );
        pm_center
            .get_foreign_network_manager()
            .forward_foreign_network_packet("net1", pmb_net1.my_peer_id(), tx_pkt)
            .await
            .unwrap();

        let network_labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("net1".to_string()));
        let tx_instance_labels = network_labels
            .clone()
            .with_label_type(LabelType::ToInstanceId(
                pmb_net1.get_global_ctx().get_id().to_string(),
            ));
        let rx_instance_labels = network_labels
            .clone()
            .with_label_type(LabelType::FromInstanceId(
                pma_net1.get_global_ctx().get_id().to_string(),
            ));

        wait_for_condition(
            || {
                let pm_center = pm_center.clone();
                let network_labels = network_labels.clone();
                let tx_instance_labels = tx_instance_labels.clone();
                let rx_instance_labels = rx_instance_labels.clone();
                async move {
                    metric_value(
                        &pm_center,
                        MetricName::TrafficBytesTx,
                        network_labels.clone(),
                    ) > 0
                        && metric_value(
                            &pm_center,
                            MetricName::TrafficBytesRx,
                            network_labels.clone(),
                        ) > 0
                        && metric_value(
                            &pm_center,
                            MetricName::TrafficBytesTxByInstance,
                            tx_instance_labels.clone(),
                        ) > 0
                        && metric_value(
                            &pm_center,
                            MetricName::TrafficBytesRxByInstance,
                            rx_instance_labels.clone(),
                        ) > 0
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn foreign_network_transit_forwarding_only_records_forwarded_metrics() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let center_peer_id = pm_center
            .get_foreign_network_manager()
            .get_network_peer_id("net1")
            .unwrap();
        let network_labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("net1".to_string()));
        let forwarded_bytes_before = metric_value(
            &pm_center,
            MetricName::TrafficBytesForwarded,
            network_labels.clone(),
        );
        let forwarded_packets_before = metric_value(
            &pm_center,
            MetricName::TrafficPacketsForwarded,
            network_labels.clone(),
        );
        let rx_bytes_before = metric_value(
            &pm_center,
            MetricName::TrafficBytesRx,
            network_labels.clone(),
        );
        let rx_packets_before = metric_value(
            &pm_center,
            MetricName::TrafficPacketsRx,
            network_labels.clone(),
        );
        let tx_bytes_before = metric_value(
            &pm_center,
            MetricName::TrafficBytesTx,
            network_labels.clone(),
        );
        let tx_packets_before = metric_value(
            &pm_center,
            MetricName::TrafficPacketsTx,
            network_labels.clone(),
        );

        let mut transit_pkt = ZCPacket::new_with_payload(b"foreign-transit");
        transit_pkt.fill_peer_manager_hdr(
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id(),
            PacketType::Data as u8,
        );
        let transit_pkt_len = transit_pkt.buf_len() as u64;
        pma_net1
            .core()
            .get_foreign_network_client()
            .send_msg(transit_pkt, center_peer_id)
            .await
            .unwrap();
        wait_for_condition(
            || {
                let pm_center = pm_center.clone();
                let network_labels = network_labels.clone();
                async move {
                    metric_value(
                        &pm_center,
                        MetricName::TrafficBytesForwarded,
                        network_labels.clone(),
                    ) >= forwarded_bytes_before + transit_pkt_len
                        && metric_value(
                            &pm_center,
                            MetricName::TrafficPacketsForwarded,
                            network_labels.clone(),
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            metric_value(
                &pm_center,
                MetricName::TrafficBytesRx,
                network_labels.clone()
            ),
            rx_bytes_before
        );
        assert_eq!(
            metric_value(
                &pm_center,
                MetricName::TrafficPacketsRx,
                network_labels.clone()
            ),
            rx_packets_before
        );
        assert_eq!(
            metric_value(
                &pm_center,
                MetricName::TrafficBytesTx,
                network_labels.clone()
            ),
            tx_bytes_before
        );
        assert_eq!(
            metric_value(&pm_center, MetricName::TrafficPacketsTx, network_labels),
            tx_packets_before
        );
    }

    #[tokio::test]
    async fn disable_relay_data_blocks_foreign_network_transit_data() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let mut flags = pm_center.get_global_ctx().get_flags();
        flags.disable_relay_data = true;
        pm_center.get_global_ctx().set_flags(flags);
        pm_center.refresh_runtime_config();

        let center_peer_id = pm_center
            .get_foreign_network_manager()
            .get_network_peer_id("net1")
            .unwrap();
        wait_for_condition(
            || {
                let pma_net1 = pma_net1.clone();
                async move {
                    pma_net1.list_routes().await.iter().any(|route| {
                        route.peer_id == center_peer_id
                            && route
                                .feature_flag
                                .as_ref()
                                .map(|flag| flag.avoid_relay_data)
                                .unwrap_or(false)
                    })
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let network_labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("net1".to_string()));
        let forwarded_bytes_before = metric_value(
            &pm_center,
            MetricName::TrafficBytesForwarded,
            network_labels.clone(),
        );
        let forwarded_packets_before = metric_value(
            &pm_center,
            MetricName::TrafficPacketsForwarded,
            network_labels.clone(),
        );

        let mut transit_pkt = ZCPacket::new_with_payload(b"foreign-transit-disabled");
        transit_pkt.fill_peer_manager_hdr(
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id(),
            PacketType::Data as u8,
        );
        pma_net1
            .core()
            .get_foreign_network_client()
            .send_msg(transit_pkt, center_peer_id)
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;

        assert_eq!(
            metric_value(
                &pm_center,
                MetricName::TrafficBytesForwarded,
                network_labels.clone()
            ),
            forwarded_bytes_before
        );
        assert_eq!(
            metric_value(
                &pm_center,
                MetricName::TrafficPacketsForwarded,
                network_labels
            ),
            forwarded_packets_before
        );
    }

    #[tokio::test]
    async fn foreign_network_transit_control_forwarding_records_control_forwarded_metrics() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let mut flags = pm_center.get_global_ctx().get_flags();
        flags.disable_relay_data = true;
        pm_center.get_global_ctx().set_flags(flags);
        pm_center.refresh_runtime_config();

        let center_peer_id = pm_center
            .get_foreign_network_manager()
            .get_network_peer_id("net1")
            .unwrap();
        let network_labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("net1".to_string()));
        let forwarded_bytes_before = metric_value(
            &pm_center,
            MetricName::TrafficControlBytesForwarded,
            network_labels.clone(),
        );
        let forwarded_packets_before = metric_value(
            &pm_center,
            MetricName::TrafficControlPacketsForwarded,
            network_labels.clone(),
        );

        let mut transit_pkt = ZCPacket::new_with_payload(b"foreign-control-transit");
        transit_pkt.fill_peer_manager_hdr(
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let transit_pkt_len = transit_pkt.buf_len() as u64;
        pma_net1
            .core()
            .get_foreign_network_client()
            .send_msg(transit_pkt, center_peer_id)
            .await
            .unwrap();

        wait_for_condition(
            || {
                let pm_center = pm_center.clone();
                let network_labels = network_labels.clone();
                async move {
                    metric_value(
                        &pm_center,
                        MetricName::TrafficControlBytesForwarded,
                        network_labels.clone(),
                    ) >= forwarded_bytes_before + transit_pkt_len
                        && metric_value(
                            &pm_center,
                            MetricName::TrafficControlPacketsForwarded,
                            network_labels.clone(),
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn failed_new_foreign_peer_conn_rolls_back_entry_maps() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let foreign_mgr = pm_center.get_foreign_network_manager();

        foreign_mgr.fail_next_add_peer_conn_after_entry_insert();

        let (a_ring, b_ring) = easytier_core::tunnel::ring::create_ring_tunnel_pair();
        let (client_ret, server_ret) = tokio::time::timeout(Duration::from_secs(5), async {
            let pma_net1_core = pma_net1.core();
            let pm_center_core = pm_center.core();
            tokio::join!(
                pma_net1_core.add_client_tunnel(a_ring, false),
                pm_center_core.add_tunnel_as_server(b_ring, true)
            )
        })
        .await
        .unwrap();

        assert!(client_ret.is_ok());
        assert!(server_ret.is_err());
        assert!(foreign_mgr.get_network_peer_id("net1").is_none());
        assert!(
            foreign_mgr
                .list_foreign_network_infos(false)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn foreign_network_peer_removed_clears_traffic_metric_peer_cache() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        wait_for_condition(
            || {
                let pm_center = pm_center.clone();
                async move {
                    pm_center
                        .get_foreign_network_manager()
                        .get_network_peer_id("net1")
                        .is_some()
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let foreign_mgr = pm_center.get_foreign_network_manager();
        assert!(
            foreign_mgr
                .record_rx_traffic_for_test(
                    "net1",
                    pma_net1.my_peer_id(),
                    PacketType::Data as u8,
                    128
                )
                .await
        );

        assert!(
            foreign_mgr.contains_traffic_metric_peer_cache_for_test("net1", pma_net1.my_peer_id())
        );

        pm_center
            .foreign_peer_context_for_test("net1")
            .unwrap()
            .issue_event(easytier_core::peers::context::PeerEvent::PeerRemoved(
                pma_net1.my_peer_id(),
            ));

        wait_for_condition(
            || {
                let foreign_mgr = foreign_mgr.clone();
                let peer_id = pma_net1.my_peer_id();
                async move {
                    !foreign_mgr.contains_traffic_metric_peer_cache_for_test("net1", peer_id)
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn foreign_network_encapsulated_forwarding_records_tx_metrics() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let center_peer_id = pm_center1
            .get_foreign_network_manager()
            .get_network_peer_id("net1")
            .unwrap();

        let mut encapsulated_tx_pkt = ZCPacket::new_with_payload(b"foreign-encap-tx");
        encapsulated_tx_pkt.fill_peer_manager_hdr(
            center_peer_id,
            pmb_net1.my_peer_id(),
            PacketType::Data as u8,
        );
        pma_net1
            .core()
            .get_foreign_network_client()
            .send_msg(encapsulated_tx_pkt, center_peer_id)
            .await
            .unwrap();

        let network_labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("net1".to_string()));
        let tx_instance_labels = network_labels
            .clone()
            .with_label_type(LabelType::ToInstanceId(
                pmb_net1.get_global_ctx().get_id().to_string(),
            ));

        wait_for_condition(
            || {
                let pm_center1 = pm_center1.clone();
                let network_labels = network_labels.clone();
                let tx_instance_labels = tx_instance_labels.clone();
                async move {
                    metric_value(
                        &pm_center1,
                        MetricName::TrafficBytesTx,
                        network_labels.clone(),
                    ) > 0
                        && metric_value(
                            &pm_center1,
                            MetricName::TrafficBytesTxByInstance,
                            tx_instance_labels.clone(),
                        ) > 0
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn foreign_network_list_can_include_trusted_keys() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        set_secure_mode_cfg(&pm_center.get_global_ctx(), true);
        pm_center.refresh_runtime_config();

        let pma_net1 = create_mock_peer_manager_for_secure_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_secure_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let without_trusted_keys = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert!(without_trusted_keys["net1"].trusted_keys.is_empty());

        let foreign_mgr = pm_center.get_foreign_network_manager();
        wait_for_condition(
            || {
                let foreign_mgr = foreign_mgr.clone();
                async move {
                    foreign_mgr
                        .list_foreign_network_infos(true)
                        .await
                        .get("net1")
                        .map(|entry| !entry.trusted_keys.is_empty())
                        .unwrap_or(false)
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let core_infos = pm_center.core().list_foreign_network_infos(true).await;
        assert!(!core_infos["net1"].trusted_keys.is_empty());

        let with_trusted_keys = foreign_mgr.list_foreign_network_infos(true).await;
        assert!(!with_trusted_keys["net1"].trusted_keys.is_empty());
    }

    #[tokio::test]
    async fn secure_center_can_serve_legacy_and_secure_foreign_networks() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        set_secure_mode_cfg(&pm_center.get_global_ctx(), true);
        pm_center.refresh_runtime_config();

        let legacy_a = create_mock_peer_manager_for_foreign_network("legacy-net").await;
        let legacy_b = create_mock_peer_manager_for_foreign_network("legacy-net").await;
        connect_peer_manager(legacy_a.clone(), pm_center.clone()).await;
        connect_peer_manager(legacy_b.clone(), pm_center.clone()).await;
        wait_route_appear(legacy_a.clone(), legacy_b.clone())
            .await
            .unwrap();

        let secure_a = create_mock_peer_manager_for_secure_foreign_network("secure-net").await;
        let secure_b = create_mock_peer_manager_for_secure_foreign_network("secure-net").await;
        connect_peer_manager(secure_a.clone(), pm_center.clone()).await;
        connect_peer_manager(secure_b.clone(), pm_center.clone()).await;
        wait_route_appear(secure_a.clone(), secure_b.clone())
            .await
            .unwrap();

        assert_eq!(2, legacy_a.list_routes().await.len());
        assert_eq!(2, legacy_b.list_routes().await.len());
        assert_eq!(2, secure_a.list_routes().await.len());
        assert_eq!(2, secure_b.list_routes().await.len());

        let foreign_infos = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert_eq!(2, foreign_infos.len());
        assert_eq!(2, foreign_infos["legacy-net"].peers.len());
        assert_eq!(2, foreign_infos["secure-net"].peers.len());
    }

    #[tokio::test]
    async fn parent_config_reads_require_peer_snapshot_refresh() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let config =
            crate::peers::context::runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        let (runtime_config, parent_context) =
            crate::peers::context::build_core_peer_context(&global_ctx, &config);
        let parent_flags = parent_context.flags();
        assert!(!parent_flags.relay_all_peer_rpc);
        assert!(
            easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist(
                &parent_flags.relay_network_whitelist,
                "net1",
            )
            .is_ok()
        );

        let mut flags = global_ctx.get_flags();
        flags.relay_all_peer_rpc = true;
        flags.relay_network_whitelist.clear();
        global_ctx.set_flags(flags);
        let parent_flags = parent_context.flags();
        assert!(!parent_flags.relay_all_peer_rpc);
        assert!(
            easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist(
                &parent_flags.relay_network_whitelist,
                "net1",
            )
            .is_ok()
        );

        runtime_config.update_peer(Arc::new(
            crate::peers::context::runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf)
                .snapshot,
        ));
        let parent_flags = parent_context.flags();
        assert!(parent_flags.relay_all_peer_rpc);
        assert!(
            easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist(
                &parent_flags.relay_network_whitelist,
                "net1",
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn zero_digest_peer_cannot_bootstrap_foreign_network() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        set_secure_mode_cfg(&pm_center.get_global_ctx(), true);
        pm_center.refresh_runtime_config();

        let pma_net1 = create_mock_credential_peer_manager_for_foreign_network("net1").await;

        let (a_ring, b_ring) = easytier_core::tunnel::ring::create_ring_tunnel_pair();
        let a_mgr_copy = pma_net1.clone();
        let client =
            tokio::spawn(async move { a_mgr_copy.core().add_client_tunnel(a_ring, false).await });
        let b_mgr_copy = pm_center.clone();
        let server =
            tokio::spawn(async move { b_mgr_copy.core().add_tunnel_as_server(b_ring, true).await });

        assert!(client.await.unwrap().is_ok());
        assert!(server.await.unwrap().is_err());
        assert!(
            pm_center
                .get_foreign_network_manager()
                .list_foreign_network_infos(false)
                .await
                .is_empty()
        );
    }

    async fn foreign_network_whitelist_helper(name: String) {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.relay_network_whitelist = ["net1".to_string(), "net2*".to_string()].join(" ");
        pm_center.get_global_ctx().set_flags(flag);
        pm_center.refresh_runtime_config();

        let pma_net1 = create_mock_peer_manager_for_foreign_network(name.as_str()).await;

        let (a_ring, b_ring) = easytier_core::tunnel::ring::create_ring_tunnel_pair();
        let b_mgr_copy = pm_center.clone();
        let s_ret =
            tokio::spawn(async move { b_mgr_copy.core().add_tunnel_as_server(b_ring, true).await });

        pma_net1
            .core()
            .add_client_tunnel(a_ring, false)
            .await
            .unwrap();

        s_ret.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn foreign_network_whitelist() {
        foreign_network_whitelist_helper("net1".to_string()).await;
        foreign_network_whitelist_helper("net2".to_string()).await;
        foreign_network_whitelist_helper("net2abc".to_string()).await;
    }

    #[tokio::test]
    async fn only_relay_peer_rpc() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.relay_network_whitelist = "".to_string();
        flag.relay_all_peer_rpc = true;
        pm_center.get_global_ctx().set_flags(flag);
        pm_center.refresh_runtime_config();
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());
    }

    #[tokio::test]
    #[should_panic]
    async fn foreign_network_whitelist_fail() {
        foreign_network_whitelist_helper("net3".to_string()).await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(pm_center.clone(), pm_center2.clone()).await;

        tracing::debug!(
            "pm_center: {:?}, pm_center2: {:?}",
            pm_center.my_peer_id(),
            pm_center2.my_peer_id()
        );

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;

        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        assert_eq!(
            vec![
                pm_center
                    .get_foreign_network_manager()
                    .get_network_peer_id("net1")
                    .unwrap()
            ],
            pma_net1
                .core()
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
        );
        assert_eq!(
            vec![
                pm_center
                    .get_foreign_network_manager()
                    .get_network_peer_id("net1")
                    .unwrap()
            ],
            pmb_net1
                .core()
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
        );

        assert_eq!(2, pma_net1.list_routes().await.len());
        assert_eq!(2, pmb_net1.list_routes().await.len());

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        wait_route_appear(pmb_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        assert_eq!(3, pmc_net1.list_routes().await.len());

        tracing::debug!("pmc_net1: {:?}", pmc_net1.my_peer_id());

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        tracing::debug!(
            "pma_net2: {:?}, pmb_net2: {:?}",
            pma_net2.my_peer_id(),
            pmb_net2.my_peer_id()
        );
        connect_peer_manager(pma_net2.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        assert_eq!(2, pma_net2.list_routes().await.len());
        assert_eq!(2, pmb_net2.list_routes().await.len());

        let foreign_infos = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert_eq!(2, foreign_infos.len());
        assert_eq!(3, foreign_infos["net1"].peers.len());
        assert_eq!(2, foreign_infos["net2"].peers.len());
        assert_eq!(
            5,
            foreign_infos
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );

        drop(pmb_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let foreign_infos = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert_eq!(
            4,
            foreign_infos
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );
        drop(pma_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let foreign_infos = pm_center
            .get_foreign_network_manager()
            .list_foreign_network_infos(false)
            .await;
        assert_eq!(
            3,
            foreign_infos
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );
        assert_eq!(1, foreign_infos.len());
    }

    #[tokio::test]
    async fn test_disconnect_foreign_network() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        tracing::debug!("pma_net1: {:?}", pma_net1.my_peer_id(),);

        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;

        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        drop(pm_center);
        wait_for_condition(
            || async { pma_net1.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn stopped_populated_foreign_manager_closes_admission() {
        let center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let foreign = create_mock_peer_manager_for_foreign_network("net1").await;
        let registry = Arc::new(RingTunnelRegistry::default());
        let listener_id = uuid::Uuid::new_v4();
        let mut listener = registry.bind(listener_id).unwrap();
        let client_tunnel = registry.connect(listener_id).unwrap().into_tunnel();
        let server_tunnel = listener.accept().await.unwrap().into_tunnel();
        let foreign_core = foreign.core();
        let center_core = center.core();
        let (client_result, server_result) = tokio::join!(
            foreign_core.add_client_tunnel(client_tunnel, false),
            center_core.add_tunnel_as_server(server_tunnel, true),
        );
        client_result.unwrap();
        server_result.unwrap();

        let manager = center.get_foreign_network_manager();
        wait_for_condition(
            || {
                let manager = manager.clone();
                async move { !manager.list_foreign_network_infos(false).await.is_empty() }
            },
            Duration::from_secs(5),
        )
        .await;

        manager.stop().await;

        assert!(manager.list_foreign_network_infos(false).await.is_empty());
        assert!(manager.is_stopped_for_test().await);
        assert!(!manager.admission_is_open_for_test().await);
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_simple() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center2.clone()).await;

        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_multiple_hops() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center4 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;
        connect_peer_manager(pm_center3.clone(), pm_center4.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center3.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center4.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center4.clone()).await;
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        drop(pmb_net2);
        wait_for_condition(
            || async { pma_net2.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        tracing::debug!(
            "pm_center: {:?}, pm_center2: {:?}",
            pm_center1.my_peer_id(),
            pm_center2.my_peer_id()
        );

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        tracing::debug!(
            "pma_net1: {:?}, pmb_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id()
        );

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        assert_eq!(3, pma_net1.list_routes().await.len(),);

        let pmc_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pmc_net1.clone(), pm_center3.clone()).await;
        wait_route_appear(pma_net1.clone(), pmc_net1.clone())
            .await
            .unwrap();
        assert_eq!(5, pma_net1.list_routes().await.len(),);

        println!(
            "pm_center1: {:?}, pm_center2: {:?}, pm_center3: {:?}",
            pm_center1.my_peer_id(),
            pm_center2.my_peer_id(),
            pm_center3.my_peer_id()
        );
        println!(
            "pma_net1: {:?}, pmb_net1: {:?}, pmc_net1: {:?}",
            pma_net1.my_peer_id(),
            pmb_net1.my_peer_id(),
            pmc_net1.my_peer_id()
        );

        println!("drop pmc_net1, id: {:?}", pmc_net1.my_peer_id());

        // foreign network node disconnect
        drop(pmc_net1);
        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 3 },
            Duration::from_secs(15),
        )
        .await;

        println!("drop pm_center1, id: {:?}", pm_center1.my_peer_id());
        drop(pm_center1);
        wait_for_condition(
            || async { pma_net1.list_routes().await.is_empty() },
            Duration::from_secs(5),
        )
        .await;
        wait_for_condition(
            || async {
                let n = pmb_net1
                    .core()
                    .get_route()
                    .get_next_hop(pma_net1.my_peer_id())
                    .await;
                n.is_none()
            },
            Duration::from_secs(5),
        )
        .await;
        wait_for_condition(
            || async {
                // only remain pmb center
                pmb_net1.list_routes().await.len() == 1
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_multi_net() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center2.clone()).await;

        let pma_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        let pmb_net2 = create_mock_peer_manager_for_foreign_network("net2").await;
        connect_peer_manager(pma_net2.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmb_net2.clone(), pm_center3.clone()).await;

        let pma_net3 = create_mock_peer_manager_for_foreign_network("net3").await;
        let pmb_net3 = create_mock_peer_manager_for_foreign_network("net3").await;
        connect_peer_manager(pma_net3.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net3.clone(), pm_center3.clone()).await;

        let pma_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        let pmb_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        let pmc_net4 = create_mock_peer_manager_for_foreign_network("net4").await;
        connect_peer_manager(pma_net4.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net4.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmc_net4.clone(), pm_center3.clone()).await;

        tokio::time::sleep(Duration::from_secs(5)).await;

        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net2.clone(), pmb_net2.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net3.clone(), pmb_net3.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net4.clone(), pmb_net4.clone())
            .await
            .unwrap();
        wait_route_appear(pma_net4.clone(), pmc_net4.clone())
            .await
            .unwrap();
        wait_route_appear(pmb_net4.clone(), pmc_net4.clone())
            .await
            .unwrap();

        assert_eq!(3, pma_net1.list_routes().await.len());
        assert_eq!(3, pmb_net1.list_routes().await.len());

        assert_eq!(3, pma_net2.list_routes().await.len());
        assert_eq!(3, pmb_net2.list_routes().await.len());

        assert_eq!(3, pma_net3.list_routes().await.len());
        assert_eq!(3, pmb_net3.list_routes().await.len());

        assert_eq!(5, pma_net4.list_routes().await.len());
        assert_eq!(5, pmb_net4.list_routes().await.len());
        assert_eq!(5, pmc_net4.list_routes().await.len());

        drop(pm_center3);
        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(1, pma_net2.list_routes().await.len());
        assert_eq!(1, pma_net3.list_routes().await.len());
        assert_eq!(3, pma_net4.list_routes().await.len());
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_secret_mismatch() {
        set_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center2 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let pm_center3 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(pm_center1.clone(), pm_center2.clone()).await;
        connect_peer_manager(pm_center2.clone(), pm_center3.clone()).await;

        let pma_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "1").await;
        let pmb_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "2").await;
        let pmc_net4 = create_mock_peer_manager_for_foreign_network_ext("net4", "3").await;
        connect_peer_manager(pma_net4.clone(), pm_center1.clone()).await;
        connect_peer_manager(pmb_net4.clone(), pm_center2.clone()).await;
        connect_peer_manager(pmc_net4.clone(), pm_center3.clone()).await;

        tokio::time::sleep(Duration::from_secs(5)).await;
        assert_eq!(1, pma_net4.list_routes().await.len());
        assert_eq!(1, pmb_net4.list_routes().await.len());
        assert_eq!(1, pmc_net4.list_routes().await.len());
    }

    #[tokio::test]
    async fn test_foreign_network_manager_cluster_max_direct_conns() {
        set_global_var!(MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK, 1);

        let pm_center1 = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let pma_net1 = create_mock_peer_manager_for_foreign_network("net1").await;

        connect_peer_manager(pma_net1.clone(), pm_center1.clone()).await;
        wait_for_condition(
            || async { pma_net1.list_routes().await.len() == 1 },
            Duration::from_secs(5),
        )
        .await;

        println!("routes: {:?}", pma_net1.list_routes().await);

        let (a_ring, b_ring) = easytier_core::tunnel::ring::create_ring_tunnel_pair();
        let a_mgr_copy = pma_net1.clone();
        tokio::spawn(async move {
            a_mgr_copy
                .core()
                .add_client_tunnel(a_ring, false)
                .await
                .unwrap();
        });
        let b_mgr_copy = pm_center1.clone();

        assert!(
            b_mgr_copy
                .core()
                .add_tunnel_as_server(b_ring, true)
                .await
                .is_err()
        );
    }
}

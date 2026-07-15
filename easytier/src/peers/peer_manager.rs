use crate::{
    common::{PeerId, credential_manager::CredentialManager, global_ctx::ArcGlobalCtx},
    connector::{core_instance::runtime_socket_context, runtime::runtime_connector_host},
    host_runtime::native_host_runtime,
    proto::api::instance,
    tunnel::packet_def::compressor_algo_from_pb,
};
use easytier_core::connectivity::direct::ForeignDirectConnectorRpcRegistrar;
use easytier_core::peers::encrypt::{derive_key_128, derive_key_256};
pub use easytier_core::peers::peer_manager::RouteAlgoType;
use easytier_core::peers::peer_manager::{DnsAddressResolver, PeerManagerCore};
use easytier_core::tunnel::ring::RingTunnelRegistry;
use easytier_core::{
    peers::{
        acl_filter::AclFilter,
        context::{CorePeerContext, TrustedKeyMapManager, TrustedKeySource},
        foreign_network_manager::ForeignNetworkManager,
    },
    runtime_config::CoreRuntimeConfigStore,
    stats_manager::StatsManager,
};
use std::{fmt::Debug, sync::Arc};

use super::{
    PacketRecvChan,
    context::{
        build_core_peer_context, initialize_runtime_peer_host_state, runtime_peer_manager_config,
    },
    encrypt::NullCipher,
};

pub struct PeerManager {
    global_ctx: ArcGlobalCtx,
    route_algo: RouteAlgoType,
    core: Arc<PeerManagerCore>,
    peer_context: Arc<CorePeerContext>,
    runtime_config: CoreRuntimeConfigStore,
    credential_manager: Arc<CredentialManager>,
    ring_registry: Arc<RingTunnelRegistry>,

    foreign_network_manager: Arc<ForeignNetworkManager>,
}

impl Debug for PeerManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerManager")
            .field("my_peer_id", &self.my_peer_id())
            .field("instance_name", &self.global_ctx.inst_name)
            .field("net_ns", &self.global_ctx.net_ns.name())
            .finish()
    }
}

impl PeerManager {
    pub fn new(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        nic_channel: PacketRecvChan,
    ) -> Self {
        Self::new_with_ring_registry(
            route_algo,
            global_ctx,
            nic_channel,
            Arc::new(RingTunnelRegistry::default()),
        )
    }

    pub(crate) fn new_with_ring_registry(
        route_algo: RouteAlgoType,
        global_ctx: ArcGlobalCtx,
        nic_channel: PacketRecvChan,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        let my_peer_id = rand::random();

        initialize_runtime_peer_host_state(&global_ctx);

        let config = runtime_peer_manager_config(&global_ctx, route_algo);
        let flags = &config.snapshot.flags;
        let encryptor = if flags.enable_encryption {
            // 只有在启用加密时才使用工厂函数选择算法
            let algorithm = &flags.encryption_algorithm;
            let secret = config
                .snapshot
                .runtime
                .network_identity
                .network_secret
                .as_deref()
                .unwrap_or_default();
            super::encrypt::create_encryptor(
                algorithm,
                derive_key_128(secret),
                derive_key_256(secret),
            )
        } else {
            // disable_encryption = true 时使用 NullCipher
            Arc::new(NullCipher)
        };

        let is_secure_mode_enabled = config
            .snapshot
            .runtime
            .secure_mode
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);

        let data_compress_algo = compressor_algo_from_pb(flags.data_compress_algo())
            .expect("invalid data compress algo, maybe some features not enabled");
        let (runtime_config, peer_context) = build_core_peer_context(&global_ctx, &config);

        let foreign_rpc_registrar = Arc::new(ForeignDirectConnectorRpcRegistrar::new(
            runtime_connector_host(global_ctx.clone()),
            global_ctx.get_stun_info_collector(),
        ));
        let build_result = PeerManagerCore::new_with_foreign_rpc_registrar(
            config.route_algo,
            my_peer_id,
            peer_context.clone(),
            global_ctx.clone(),
            nic_channel,
            encryptor,
            is_secure_mode_enabled,
            data_compress_algo,
            config.exit_nodes,
            Arc::new(
                DnsAddressResolver::new(native_host_runtime())
                    .with_context(runtime_socket_context(&global_ctx)),
            ),
            config.foreign_context_default_flags,
            foreign_rpc_registrar,
        );
        let credential_manager = Arc::new(CredentialManager::from_core(
            peer_context.credential_manager(),
        ));

        PeerManager {
            global_ctx,
            route_algo,
            core: Arc::new(build_result.core),
            peer_context,
            runtime_config,
            credential_manager,
            ring_registry,
            foreign_network_manager: build_result.foreign_network_manager,
        }
    }

    pub(crate) fn refresh_runtime_config(&self) {
        let config = runtime_peer_manager_config(&self.global_ctx, self.route_algo);
        self.runtime_config.update_peer(Arc::new(config.snapshot));
    }

    pub(crate) fn runtime_config_store(&self) -> CoreRuntimeConfigStore {
        self.runtime_config.clone()
    }

    pub fn core(&self) -> Arc<PeerManagerCore> {
        self.core.clone()
    }

    pub fn stats_manager(&self) -> Arc<StatsManager> {
        self.core.stats_manager()
    }

    pub fn acl_filter(&self) -> Arc<AclFilter> {
        self.core.acl_filter()
    }

    pub fn credential_manager(&self) -> Arc<CredentialManager> {
        self.credential_manager.clone()
    }

    pub(crate) fn trusted_key_manager(&self) -> Arc<TrustedKeyMapManager> {
        self.peer_context.trusted_key_manager()
    }

    pub(crate) fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.trusted_key_manager().verify_trusted_key_with_source(
            pubkey,
            network_name,
            Some(source),
        )
    }

    pub(crate) fn ring_registry(&self) -> Arc<RingTunnelRegistry> {
        self.ring_registry.clone()
    }

    pub async fn list_routes(&self) -> Vec<instance::Route> {
        self.core
            .list_route_snapshots()
            .await
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.global_ctx.get_id()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.core.my_peer_id()
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_global_ctx_ref(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    #[cfg(test)]
    pub(crate) fn foreign_peer_context_for_test(
        &self,
        network_name: &str,
    ) -> Option<Arc<CorePeerContext>> {
        self.foreign_network_manager
            .foreign_peer_context_for_test(network_name)
    }

    pub async fn update_exit_nodes(&self) {
        let exit_nodes = self.global_ctx.config.get_exit_nodes();
        self.core.update_exit_nodes(exit_nodes).await;
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use easytier_core::connectivity::manual::{
        ManualConnectorManager as CoreManualConnectorManager, discovery::CoreManualEndpointResolver,
    };
    use easytier_core::peers::peer_manager::{self as core_peer_manager, PeerManagerCore};
    use easytier_core::stats_manager::{LabelSet, LabelType, MetricName};
    use easytier_core::tunnel::{
        SinkItem,
        filter::{TunnelFilter, TunnelWithFilter},
    };
    use std::{
        collections::HashMap,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        time::Duration,
    };

    use quanta::Instant;

    use crate::{
        common::{
            PeerId,
            config::Flags,
            global_ctx::{NetworkIdentity, tests::get_mock_global_ctx},
        },
        connector::{
            core_instance::{
                runtime_core_instance_adapters_with_ring_registry,
                runtime_endpoint_discovery_config, runtime_manual_options,
            },
            runtime::RuntimeConnectorHost,
            udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        },
        instance::listeners::ListenerManager,
        peers::{
            create_packet_recv_chan,
            peer_conn::tests::set_secure_mode_cfg,
            peer_manager::RouteAlgoType,
            route_trait::{NextHopPolicy, RouteCostCalculatorInterface},
            tests::{
                connect_peer_manager, create_mock_peer_manager_with_name, wait_route_appear,
                wait_route_appear_with_cost,
            },
        },
        proto::{
            common::{CompressionAlgoPb, NatType, SecureModeConfig},
            peer_rpc::SecureAuthLevel,
        },
        tunnel::{
            common::tests::wait_for_condition,
            packet_def::{PacketType, ZCPacket},
        },
    };
    use easytier_core::tunnel::ring::create_ring_tunnel_pair;

    use super::PeerManager;

    struct DropSendTunnelFilter {
        start: u32,
        end: u32,
        current: AtomicU32,
    }

    impl DropSendTunnelFilter {
        fn new(start: u32, end: u32) -> Self {
            Self {
                start,
                end,
                current: AtomicU32::new(0),
            }
        }
    }

    impl TunnelFilter for DropSendTunnelFilter {
        type FilterOutput = ();

        fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
            let current = self.current.fetch_add(1, Ordering::SeqCst) + 1;
            if current >= self.start && current < self.end {
                tracing::trace!(?data, "drop packet");
                return None;
            }
            Some(data)
        }

        fn filter_output(&self) {}
    }

    fn register_service(
        rpc_mgr: &crate::peers::peer_rpc::PeerRpcManager,
        domain: &str,
        delay_ms: u64,
        prefix: &str,
    ) {
        use crate::proto::tests::{GreetingServer, GreetingService};

        rpc_mgr.rpc_server().registry().register(
            GreetingServer::new(GreetingService {
                delay_ms,
                prefix: prefix.to_string(),
            }),
            domain,
        );
    }

    async fn create_lazy_peer_manager() -> Arc<PeerManager> {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let mut flags = peer_mgr.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        peer_mgr.get_global_ctx().set_flags(flags);
        peer_mgr.refresh_runtime_config();
        peer_mgr
    }

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: &LabelSet) -> u64 {
        peer_mgr
            .stats_manager()
            .get_metric(metric, labels)
            .map(|metric| metric.value)
            .unwrap_or(0)
    }

    fn network_labels(peer_mgr: &PeerManager) -> LabelSet {
        LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ))
    }

    async fn send_msg_internal_for_test(
        peer_mgr: &PeerManager,
        pkt: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), easytier_core::peers::error::Error> {
        let peer_map = peer_mgr.core().get_peer_map();
        let foreign_network_client = peer_mgr.core().get_foreign_network_client();
        let relay_peer_map = peer_mgr.core().get_relay_peer_map();
        let traffic_metrics = peer_mgr.core().traffic_metrics();
        core_peer_manager::send_msg_internal(
            peer_map.as_ref(),
            &foreign_network_client,
            &relay_peer_map,
            Some(&traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await
    }

    struct TestCostCalculator {
        costs: HashMap<(PeerId, PeerId), i32>,
    }

    impl RouteCostCalculatorInterface for TestCostCalculator {
        fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
            *self.costs.get(&(src, dst)).unwrap_or(&1)
        }
    }

    #[test]
    fn recent_traffic_fanout_policy_only_marks_single_peer() {
        assert!(core_peer_manager::should_mark_recent_traffic_for_fanout(0));
        assert!(core_peer_manager::should_mark_recent_traffic_for_fanout(1));
        assert!(!core_peer_manager::should_mark_recent_traffic_for_fanout(2));
    }

    #[tokio::test]
    async fn native_peer_manager_projects_core_owned_peer_resources() {
        let global_ctx = get_mock_global_ctx();
        let (packet_tx, _packet_rx) = create_packet_recv_chan();
        let peer_manager = PeerManager::new(RouteAlgoType::Ospf, global_ctx.clone(), packet_tx);
        let core = peer_manager.core();
        let core_stats = core.stats_manager();
        let core_acl = core.acl_filter();
        let core_credentials = core.credential_manager();
        let core_trusted_keys = peer_manager.peer_context.trusted_key_manager();

        assert!(Arc::ptr_eq(&peer_manager.stats_manager(), &core_stats));
        assert!(Arc::ptr_eq(&peer_manager.acl_filter(), &core_acl));
        assert!(Arc::ptr_eq(
            &peer_manager.credential_manager().core(),
            &core_credentials,
        ));
        assert!(Arc::ptr_eq(
            &peer_manager.trusted_key_manager(),
            &core_trusted_keys,
        ));
    }

    #[tokio::test]
    async fn recent_traffic_skips_direct_peers_and_clears_after_direct_connect() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a.core().mark_recent_traffic(peer_b_id);
        assert!(
            peer_mgr_a
                .core()
                .has_recent_traffic(peer_b_id, Instant::now())
        );

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let peer_mgr_a_core = peer_mgr_a.core();
        let peer_mgr_b_core = peer_mgr_b.core();
        let (client_ret, server_ret) = tokio::join!(
            peer_mgr_a_core.add_client_tunnel(a_ring, true),
            peer_mgr_b_core.add_tunnel_as_server(b_ring, true)
        );
        client_ret.unwrap();
        server_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { peer_mgr_a.core().has_directly_connected_conn(peer_b_id) }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    !peer_mgr_a
                        .core()
                        .has_recent_traffic(peer_b_id, Instant::now())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        peer_mgr_a.core().mark_recent_traffic(peer_b_id);
        assert!(
            !peer_mgr_a
                .core()
                .has_recent_traffic(peer_b_id, Instant::now()),
            "directly connected peers should not be tracked as lazy-p2p demand"
        );
    }

    #[tokio::test]
    async fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();
        let signal = peer_mgr_a.core().p2p_demand_notify();

        let initial_version = signal.version();
        peer_mgr_a.core().mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 1);

        tokio::time::sleep(Duration::from_millis(5)).await;
        peer_mgr_a.core().mark_recent_traffic(peer_b_id);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "fresh demand should not wake all p2p workers again"
        );
    }

    #[tokio::test]
    async fn non_whitelisted_network_avoid_relay_survives_disable_relay_data_toggle() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        flags.relay_network_whitelist = "other-network".to_string();
        global_ctx.set_flags(flags);

        let (packet_send, _packet_recv) = create_packet_recv_chan();
        let _peer_mgr = PeerManager::new(RouteAlgoType::Ospf, global_ctx.clone(), packet_send);

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_on_failed_delivery() {
        let peer_mgr = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let dst_peer_id = peer_mgr.my_peer_id().wrapping_add(1);
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        let result = send_msg_internal_for_test(&peer_mgr, pkt, dst_peer_id).await;

        assert!(result.is_err());
        assert_eq!(
            peer_mgr
                .stats_manager()
                .get_metric(MetricName::TrafficBytesTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            peer_mgr
                .stats_manager()
                .get_metric(MetricName::TrafficPacketsTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert!(
            peer_mgr
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .stats_manager()
                .get_metric(
                    MetricName::TrafficPacketsTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_does_not_record_tx_metrics_for_self_loop() {
        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            get_mock_global_ctx(),
            s,
        ));
        let dst_peer_id = peer_mgr.my_peer_id();
        let network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr.get_global_ctx().get_network_name(),
        ));

        let mut pkt = ZCPacket::new_with_payload(b"tx");
        pkt.fill_peer_manager_hdr(peer_mgr.my_peer_id(), dst_peer_id, PacketType::Data as u8);

        send_msg_internal_for_test(&peer_mgr, pkt, dst_peer_id)
            .await
            .unwrap();

        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficBytesTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(&peer_mgr, MetricName::TrafficPacketsTx, &network_labels),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlBytesTx,
                &network_labels
            ),
            0
        );
        assert_eq!(
            metric_value(
                &peer_mgr,
                MetricName::TrafficControlPacketsTx,
                &network_labels
            ),
            0
        );
        assert!(
            peer_mgr
                .stats_manager()
                .get_metric(
                    MetricName::TrafficBytesTxByInstance,
                    &network_labels
                        .clone()
                        .with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
        assert!(
            peer_mgr
                .stats_manager()
                .get_metric(
                    MetricName::TrafficControlBytesTxByInstance,
                    &network_labels.with_label_type(LabelType::ToInstanceId("unknown".to_string())),
                )
                .is_none()
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);
        let mut pkt = ZCPacket::new_with_payload(b"data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        send_msg_internal_for_test(&peer_mgr_a, pkt, peer_mgr_b.my_peer_id())
            .await
            .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels)
                        >= a_data_tx_before + pkt_len
                        && metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels)
                            >= b_data_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_uses_latency_first_gateway_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_b.clone(), peer_mgr_c.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        peer_mgr_a
            .core()
            .get_route()
            .set_route_cost_fn(Box::new(TestCostCalculator {
                costs: HashMap::from([
                    ((peer_mgr_a.my_peer_id(), peer_mgr_c.my_peer_id()), 100),
                    ((peer_mgr_a.my_peer_id(), peer_mgr_b.my_peer_id()), 1),
                    ((peer_mgr_b.my_peer_id(), peer_mgr_c.my_peer_id()), 1),
                ]),
            }))
            .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let peer_mgr_c = peer_mgr_c.clone();
                async move {
                    peer_mgr_a
                        .core()
                        .get_route()
                        .get_next_hop_with_policy(peer_mgr_c.my_peer_id(), NextHopPolicy::LeastCost)
                        .await
                        == Some(peer_mgr_b.my_peer_id())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"latency-first");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::Data as u8,
        );
        pkt.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(true);
        let pkt_len = pkt.buf_len() as u64;

        send_msg_internal_for_test(&peer_mgr_a, pkt, peer_mgr_c.my_peer_id())
            .await
            .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_metrics_for_direct_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let a_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_a.get_global_ctx().get_network_name(),
        ));
        let b_network_labels = LabelSet::new().with_label_type(LabelType::NetworkName(
            peer_mgr_b.get_global_ctx().get_network_name(),
        ));

        let a_control_tx_before = metric_value(
            &peer_mgr_a,
            MetricName::TrafficControlBytesTx,
            &a_network_labels,
        );
        let b_control_rx_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesRx,
            &b_network_labels,
        );
        let a_data_tx_before =
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels);
        let b_data_rx_before =
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels);

        let mut pkt = ZCPacket::new_with_payload(b"ctrl");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_b.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        send_msg_internal_for_test(&peer_mgr_a, pkt, peer_mgr_b.my_peer_id())
            .await
            .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                let peer_mgr_b = peer_mgr_b.clone();
                let a_network_labels = a_network_labels.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_a,
                        MetricName::TrafficControlBytesTx,
                        &a_network_labels,
                    ) >= a_control_tx_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlBytesRx,
                            &b_network_labels,
                        ) >= b_control_rx_before + pkt_len
                }
            },
            Duration::from_secs(5),
        )
        .await;

        assert_eq!(
            metric_value(&peer_mgr_a, MetricName::TrafficBytesTx, &a_network_labels),
            a_data_tx_before
        );
        assert_eq!(
            metric_value(&peer_mgr_b, MetricName::TrafficBytesRx, &b_network_labels),
            b_data_rx_before
        );
    }

    #[tokio::test]
    async fn send_msg_internal_records_data_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-data");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::Data as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        send_msg_internal_for_test(&peer_mgr_a, pkt, peer_mgr_c.my_peer_id())
            .await
            .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn send_msg_internal_records_control_forwarded_metrics_for_transit_peer() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let b_network_labels = network_labels(&peer_mgr_b);
        let forwarded_bytes_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlBytesForwarded,
            &b_network_labels,
        );
        let forwarded_packets_before = metric_value(
            &peer_mgr_b,
            MetricName::TrafficControlPacketsForwarded,
            &b_network_labels,
        );

        let mut pkt = ZCPacket::new_with_payload(b"forward-control");
        pkt.fill_peer_manager_hdr(
            peer_mgr_a.my_peer_id(),
            peer_mgr_c.my_peer_id(),
            PacketType::RpcReq as u8,
        );
        let pkt_len = pkt.buf_len() as u64;

        send_msg_internal_for_test(&peer_mgr_a, pkt, peer_mgr_c.my_peer_id())
            .await
            .unwrap();

        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                let b_network_labels = b_network_labels.clone();
                async move {
                    metric_value(
                        &peer_mgr_b,
                        MetricName::TrafficControlBytesForwarded,
                        &b_network_labels,
                    ) >= forwarded_bytes_before + pkt_len
                        && metric_value(
                            &peer_mgr_b,
                            MetricName::TrafficControlPacketsForwarded,
                            &b_network_labels,
                        ) > forwarded_packets_before
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn drop_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        // wait mgr_a have 2 peers
        wait_for_condition(
            || async {
                peer_mgr_a
                    .core()
                    .get_peer_map()
                    .list_peers_with_conn()
                    .await
                    .len()
                    == 2
            },
            std::time::Duration::from_secs(5),
        )
        .await;

        drop(peer_mgr_b);

        wait_for_condition(
            || async {
                peer_mgr_a
                    .core()
                    .get_peer_map()
                    .list_peers_with_conn()
                    .await
                    .len()
                    == 1
            },
            std::time::Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_connect_between_peers() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_a
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_b
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_a.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_b.get_global_ctx(), true);
        peer_mgr_a.refresh_runtime_config();
        peer_mgr_b.refresh_runtime_config();

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let peer_mgr_a_core = peer_mgr_a.core();
        let peer_mgr_b_core = peer_mgr_b.core();
        let (a_ret, b_ret) = tokio::join!(
            peer_mgr_a_core.add_client_tunnel(a_ring, false),
            peer_mgr_b_core.add_tunnel_as_server(b_ring, true)
        );
        let (peer_b_id, _) = a_ret.unwrap();
        b_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    if !peer_mgr_a
                        .core()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_b_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_a
                        .core()
                        .get_peer_map()
                        .list_peer_conns(peer_b_id)
                        .await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        let peer_a_id = peer_mgr_a.my_peer_id();
        wait_for_condition(
            || {
                let peer_mgr_b = peer_mgr_b.clone();
                async move {
                    if !peer_mgr_b
                        .core()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_a_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_b
                        .core()
                        .get_peer_map()
                        .list_peer_conns(peer_a_id)
                        .await
                    else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                            && c.secure_auth_level == SecureAuthLevel::NetworkSecretConfirmed as i32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_same_network_secure_mode_mismatch_rejected() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);
        peer_mgr_client.refresh_runtime_config();
        peer_mgr_server.refresh_runtime_config();

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let peer_mgr_client_core = peer_mgr_client.core();
        let peer_mgr_server_core = peer_mgr_server.core();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client_core.add_client_tunnel(c_ring, false),
            peer_mgr_server_core.add_tunnel_as_server(s_ring, true)
        );
        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "same-network peer with mismatched secure mode should be rejected"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .core()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn credential_node_rejects_legacy_client() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));

        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);
        peer_mgr_client.refresh_runtime_config();
        peer_mgr_server.refresh_runtime_config();

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let peer_mgr_client_core = peer_mgr_client.core();
        let peer_mgr_server_core = peer_mgr_server.core();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client_core.add_client_tunnel(c_ring, false),
            peer_mgr_server_core.add_tunnel_as_server(s_ring, true)
        );

        let _ = c_ret;
        assert!(
            s_ret.is_err(),
            "credential server should reject legacy client"
        );

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    peer_mgr_server
                        .core()
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .is_empty()
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn peer_manager_safe_mode_shared_node_pinning_connect() {
        let peer_mgr_client = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_server = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        peer_mgr_client
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        peer_mgr_server
            .get_global_ctx()
            .config
            .set_network_identity(NetworkIdentity {
                network_name: "shared".to_string(),
                network_secret: None,
                network_secret_digest: None,
            });

        set_secure_mode_cfg(&peer_mgr_client.get_global_ctx(), true);
        set_secure_mode_cfg(&peer_mgr_server.get_global_ctx(), true);

        let server_pub_b64 = peer_mgr_server
            .get_global_ctx()
            .config
            .get_secure_mode()
            .unwrap()
            .local_public_key
            .unwrap();

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let server_remote_url: url::Url = a_ring
            .info()
            .unwrap()
            .remote_addr
            .unwrap()
            .url
            .parse()
            .unwrap();
        peer_mgr_client.get_global_ctx().config.set_peers(vec![
            crate::common::config::PeerConfig {
                uri: server_remote_url,
                peer_public_key: Some(server_pub_b64.clone()),
            },
        ]);
        peer_mgr_client.refresh_runtime_config();
        peer_mgr_server.refresh_runtime_config();

        let peer_mgr_client_core = peer_mgr_client.core();
        let peer_mgr_server_core = peer_mgr_server.core();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client_core.add_client_tunnel(a_ring, false),
            peer_mgr_server_core.add_tunnel_as_server(b_ring, true)
        );
        c_ret.unwrap();
        s_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_client = peer_mgr_client.clone();
                async move {
                    let foreign_peer_map = peer_mgr_client
                        .core()
                        .get_foreign_network_client()
                        .get_peer_map();
                    if foreign_peer_map.list_peers_with_conn().await.len() != 1 {
                        return false;
                    }
                    let Some(peer_id) = foreign_peer_map
                        .list_peers_with_conn()
                        .await
                        .into_iter()
                        .next()
                    else {
                        return false;
                    };
                    let Some(conns) = foreign_peer_map.list_peer_conns(peer_id).await else {
                        return false;
                    };
                    conns.iter().any(|c| {
                        c.secure_auth_level == SecureAuthLevel::PeerVerified as i32
                            && c.noise_local_static_pubkey.len() == 32
                            && c.noise_remote_static_pubkey.len() == 32
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_server = peer_mgr_server.clone();
                async move {
                    let foreigns = peer_mgr_server
                        .get_foreign_network_manager()
                        .list_foreign_network_infos(false)
                        .await;
                    let Some(entry) = foreigns.get("user") else {
                        return false;
                    };
                    entry.peers.iter().any(|p| {
                        p.conns
                            .iter()
                            .any(|c| c.noise_local_static_pubkey.len() == 32)
                    })
                }
            },
            Duration::from_secs(10),
        )
        .await;
    }

    async fn connect_peer_managers_through_core(
        client: Arc<PeerManager>,
        server: Arc<PeerManager>,
        protocol: &str,
        port: u16,
    ) -> (
        Arc<CoreManualConnectorManager<RuntimeConnectorHost>>,
        ListenerManager<PeerManagerCore>,
    ) {
        server.get_global_ctx().config.set_listeners(vec![
            format!("{protocol}://0.0.0.0:{port}").parse().unwrap(),
        ]);
        let mut listener = ListenerManager::new(server.get_global_ctx(), server.core());
        listener.prepare_listeners().await.unwrap();
        listener.run().await.unwrap();

        let mut flags = client.get_global_ctx().get_flags();
        flags.bind_device = false;
        client.get_global_ctx().set_flags(flags);
        let global_ctx = client.get_global_ctx();
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
        connector
            .add_connector(format!("{protocol}://127.0.0.1:{port}").parse().unwrap())
            .unwrap();
        (connector, listener)
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial(forward_packet_test)]
    async fn forward_packet(
        #[values("tcp", "udp", "wg", "quic")] proto1: &str,
        #[values("tcp", "udp", "wg", "quic")] proto2: &str,
    ) {
        use crate::proto::{
            rpc_impl::RpcController,
            tests::{GreetingClientFactory, SayHelloRequest},
        };

        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_a.core().get_peer_rpc_mgr(), "", 0, "hello a");

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_c.core().get_peer_rpc_mgr(), "", 0, "hello c");

        let (_connector1, _listener1) = connect_peer_managers_through_core(
            peer_mgr_a.clone(),
            peer_mgr_b.clone(),
            proto1,
            31013,
        )
        .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let (_connector2, _listener2) = connect_peer_managers_through_core(
            peer_mgr_b.clone(),
            peer_mgr_c.clone(),
            proto2,
            31014,
        )
        .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let stub = peer_mgr_a
            .core()
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id(),
                peer_mgr_c.my_peer_id(),
                "".to_string(),
            );

        let ret = stub
            .say_hello(
                RpcController::default(),
                SayHelloRequest {
                    name: "abc".to_string(),
                },
            )
            .await
            .unwrap();

        assert_eq!(ret.greeting, "hello c abc!");
    }

    #[tokio::test]
    async fn communicate_between_enc_and_non_enc() {
        let create_mgr = |enable_encryption| async move {
            let (s, _r) = create_packet_recv_chan();
            let mock_global_ctx = get_mock_global_ctx();
            mock_global_ctx.set_flags(Flags {
                enable_encryption,
                data_compress_algo: CompressionAlgoPb::Zstd.into(),
                ..Default::default()
            });
            let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, mock_global_ctx, s));
            peer_mgr.core().run_for_test().await.unwrap();
            peer_mgr
        };

        let peer_mgr_a = create_mgr(true).await;
        let peer_mgr_b = create_mgr(false).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;

        // wait 5sec should not crash.
        tokio::time::sleep(Duration::from_secs(5)).await;

        // both mgr should alive
        let mgr_c = create_mgr(true).await;
        connect_peer_manager(peer_mgr_a.clone(), mgr_c.clone()).await;
        wait_route_appear(mgr_c, peer_mgr_a).await.unwrap();

        let mgr_d = create_mgr(false).await;
        connect_peer_manager(peer_mgr_b.clone(), mgr_d.clone()).await;
        wait_route_appear(mgr_d, peer_mgr_b).await.unwrap();
    }

    #[tokio::test]
    async fn test_avoid_relay_data() {
        // a->b->c
        // a->d->e->c
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_d = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_e = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        println!("peer_mgr_a: {}", peer_mgr_a.my_peer_id());
        println!("peer_mgr_b: {}", peer_mgr_b.my_peer_id());
        println!("peer_mgr_c: {}", peer_mgr_c.my_peer_id());
        println!("peer_mgr_d: {}", peer_mgr_d.my_peer_id());
        println!("peer_mgr_e: {}", peer_mgr_e.my_peer_id());

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_d.clone()).await;
        connect_peer_manager(peer_mgr_d.clone(), peer_mgr_e.clone()).await;
        connect_peer_manager(peer_mgr_e.clone(), peer_mgr_c.clone()).await;

        // when b's avoid_relay_data is false, a->c should route through b and cost is 2
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id(), Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .core()
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id(), NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id()));

        // when b's avoid_relay_data is true, a->c should route through d and e, cost is 3
        peer_mgr_b
            .core()
            .get_peer_map()
            .context()
            .set_avoid_relay_data_preference(true);
        tokio::time::sleep(Duration::from_secs(2)).await;
        if wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id(), Some(3))
            .await
            .is_err()
        {
            panic!(
                "route not appear, a route table: {}, table: {:#?}",
                peer_mgr_a.core().get_route().dump().await,
                peer_mgr_a.core().get_route().list_routes().await
            )
        }

        let ret = peer_mgr_a
            .core()
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id(), NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_d.my_peer_id()));

        println!("route table: {:#?}", peer_mgr_a.list_routes().await);

        // drop e, path should go back to through b
        drop(peer_mgr_e);
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id(), Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .core()
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id(), NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id()));
    }

    #[tokio::test]
    async fn test_client_inbound_blackhole() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        // a is client, b is server

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let a_ring = Box::new(TunnelWithFilter::new(
            a_ring,
            DropSendTunnelFilter::new(2, 50000),
        ));

        let a_mgr_copy = peer_mgr_a.clone();
        tokio::spawn(async move {
            a_mgr_copy
                .core()
                .add_client_tunnel(a_ring, false)
                .await
                .unwrap();
        });
        let b_mgr_copy = peer_mgr_b.clone();
        tokio::spawn(async move {
            b_mgr_copy
                .core()
                .add_tunnel_as_server(b_ring, true)
                .await
                .unwrap();
        });

        wait_for_condition(
            || async { peer_mgr_a.list_routes().await.is_empty() },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_peer_map() {
        let peer_mgr_a = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let conns = peer_mgr_a
            .core()
            .get_peer_map()
            .list_peer_conns(peer_mgr_b.my_peer_id())
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();

        peer_mgr_a
            .core()
            .close_peer_conn(peer_mgr_b.my_peer_id(), &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async { peer_mgr_a.list_routes().await.is_empty() },
            Duration::from_secs(10),
        )
        .await;
        // a is client, b is server
    }

    #[tokio::test]
    async fn expired_credential_peer_conn_is_closed_without_ospf() {
        let (admin_ch, _admin_rx) = create_packet_recv_chan();
        let admin_ctx = get_mock_global_ctx();
        admin_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&admin_ctx, true);
        let admin = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            admin_ctx.clone(),
            admin_ch,
        ));
        admin.core().run_for_test().await.unwrap();

        let (_cred_id, cred_secret) = admin.credential_manager().generate_credential(
            vec![],
            false,
            vec![],
            Duration::from_secs(1),
        );
        let privkey_bytes: [u8; 32] = base64::engine::general_purpose::STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        let public = x25519_dalek::PublicKey::from(&private);
        let (credential_ch, _credential_rx) = create_packet_recv_chan();
        let credential_ctx = get_mock_global_ctx();
        credential_ctx
            .config
            .set_network_identity(NetworkIdentity::new_credential("net1".to_string()));
        credential_ctx
            .config
            .set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(private.as_bytes()),
                ),
                local_public_key: Some(
                    base64::engine::general_purpose::STANDARD.encode(public.as_bytes()),
                ),
            }));
        let credential = Arc::new(PeerManager::new(
            RouteAlgoType::None,
            credential_ctx,
            credential_ch,
        ));
        credential.core().run_for_test().await.unwrap();
        let credential_peer_id = credential.my_peer_id();

        connect_peer_manager(credential.clone(), admin.clone()).await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .core()
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_some_and(|conns| !conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
                        .core()
                        .get_peer_map()
                        .list_peer_conns(credential_peer_id)
                        .await
                        .is_none_or(|conns| conns.is_empty())
                }
            },
            Duration::from_secs(5),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_client() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .core()
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let peer_id = peer_mgr_client
            .core()
            .get_foreign_network_client()
            .list_public_peers()
            .await[0];
        let conns = peer_mgr_client
            .core()
            .get_foreign_network_client()
            .get_peer_map()
            .list_peer_conns(peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();
        peer_mgr_client
            .core()
            .close_peer_conn(peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .core()
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }

    #[tokio::test]
    async fn close_conn_in_foreign_network_manager() {
        let peer_mgr_server = create_mock_peer_manager_with_name("server".to_string()).await;
        let peer_mgr_client = create_mock_peer_manager_with_name("client".to_string()).await;
        connect_peer_manager(peer_mgr_client.clone(), peer_mgr_server.clone()).await;
        wait_for_condition(
            || async {
                peer_mgr_client
                    .core()
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .len()
                    == 1
            },
            Duration::from_secs(3),
        )
        .await;

        let conns = peer_mgr_server
            .foreign_network_manager
            .list_foreign_network_infos(false)
            .await;
        let client_info = conns["client"].peers[0].clone();
        let conn_info = client_info.conns[0].clone();
        peer_mgr_server
            .core()
            .close_peer_conn(client_info.peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
                    .core()
                    .get_foreign_network_client()
                    .list_public_peers()
                    .await
                    .is_empty()
            },
            Duration::from_secs(10),
        )
        .await;
    }
}

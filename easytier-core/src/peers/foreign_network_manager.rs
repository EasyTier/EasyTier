use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    future,
    sync::{Arc, Weak},
    time::SystemTime,
};

use dashmap::{DashMap, DashSet};
use easytier_proto::common::FlagsInConfig;
use guarden::{Guard, defer};
use tokio::sync::{
    Mutex, RwLock, RwLockReadGuard,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio::task::JoinSet;

use crate::{
    config::runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    config::{CoreConfig, NodeConfig, PeerId},
    foundation::stats::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager},
    foundation::time::timeout,
    packet::{PacketType, ZCPacket},
    peer_center::instance::{PeerCenterInstance, PeerMapWithPeerRpcManager},
    peers::{PacketRecvChan, PacketRecvChanReceiver, recv_packet_from_chan},
    proto::core_peer::peer::PeerConnInfo,
    socket::SocketContext,
};

use super::{
    context::{
        ArcByteLimiter, ArcPeerContext, CorePeerContext, CorePeerContextAdapters, NetworkIdentity,
        PeerContext, PeerContextEvent, PeerRuntimeConfig, PeerRuntimeSnapshot, PeerStunInfoSource,
        TrustedKeySource,
    },
    error::Error,
    peer_conn::{PeerConn, PeerConnId},
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    peer_session::PeerSessionStore,
    public_ipv6::{DisabledPublicIpv6Runtime, PublicIpv6Runtime},
    relay_peer_map::RelayPeerMap,
    route_trait::{NextHopPolicy, Route, RouteInterface},
    traffic_metrics::{
        TrafficKind, TrafficMetricRecorder, is_relay_data_packet_type, traffic_kind,
    },
    util::shrink_dashmap,
};
use crate::proto::peer_rpc::PeerIdentityType;

pub const PUBLIC_SERVER_HOSTNAME_PREFIX: &str = "PublicServer_";

pub(crate) fn check_network_in_relay_whitelist(
    relay_network_whitelist: &str,
    network_name: &str,
) -> Result<(), anyhow::Error> {
    if relay_network_whitelist
        .split(' ')
        .map(wildmatch::WildMatch::new)
        .any(|whitelist| whitelist.matches(network_name))
    {
        Ok(())
    } else {
        Err(anyhow::anyhow!("network {} not in whitelist", network_name))
    }
}

pub(crate) fn desired_foreign_avoid_relay_data(
    parent_context: &ArcPeerContext,
    relay_data: bool,
) -> bool {
    !relay_data || parent_context.feature_flags().avoid_relay_data
}

pub(crate) fn sync_foreign_avoid_relay_data(
    parent_context: &ArcPeerContext,
    foreign_context: &ArcPeerContext,
    relay_data: bool,
) -> bool {
    let desired = desired_foreign_avoid_relay_data(parent_context, relay_data);
    if foreign_context.feature_flags().avoid_relay_data == desired {
        return false;
    }
    foreign_context.set_avoid_relay_data_preference(desired)
}

fn build_foreign_peer_context(
    network: &NetworkIdentity,
    parent_context: &Arc<CorePeerContext>,
    relay_data: bool,
    mut flags: FlagsInConfig,
) -> Arc<CorePeerContext> {
    let parent_context_dyn: ArcPeerContext = parent_context.clone();
    let parent_flags = parent_context_dyn.flags();
    flags.disable_relay_kcp = !parent_flags.enable_relay_foreign_network_kcp;
    flags.disable_relay_quic = !parent_flags.enable_relay_foreign_network_quic;
    flags.socket_mark = parent_flags.socket_mark;

    let mut feature_flags = parent_context_dyn.feature_flags();
    feature_flags.is_public_server = true;
    feature_flags.avoid_relay_data =
        desired_foreign_avoid_relay_data(&parent_context_dyn, relay_data);
    feature_flags.kcp_input = !flags.disable_kcp_input;
    feature_flags.no_relay_kcp = flags.disable_relay_kcp;
    feature_flags.support_conn_list_sync = true;
    feature_flags.quic_input = !flags.disable_quic_input;
    feature_flags.no_relay_quic = flags.disable_relay_quic;
    feature_flags.need_p2p = flags.need_p2p;
    feature_flags.disable_p2p = flags.disable_p2p;
    feature_flags.ipv6_public_addr_provider = false;

    let instance_id = uuid::Uuid::new_v4();
    let runtime = PeerRuntimeConfig {
        core: CoreConfig {
            node: NodeConfig {
                instance_id: Some(*instance_id.as_bytes()),
                hostname: Some(format!(
                    "{PUBLIC_SERVER_HOSTNAME_PREFIX}{}",
                    parent_context_dyn.hostname()
                )),
                network_name: network.network_name.clone(),
                ..Default::default()
            },
            ..Default::default()
        },
        network_identity: network.clone(),
        stun_info: parent_context_dyn.stun_info(),
        feature_flags,
        secure_mode: parent_context_dyn.secure_mode(),
        host_routing: parent_context_dyn.host_routing_policy(),
    };
    let mut snapshot = PeerRuntimeSnapshot::new(runtime, flags);
    snapshot.easytier_version = parent_context_dyn.easytier_version();
    snapshot.ospf_update_my_foreign_network_interval_sec =
        parent_context_dyn.ospf_update_my_foreign_network_interval_sec();
    snapshot.max_direct_conns_per_peer_in_foreign_network =
        parent_context_dyn.max_direct_conns_per_peer_in_foreign_network();
    snapshot.hmac_secret_digest = parent_context_dyn.hmac_secret_digest();

    Arc::new(CorePeerContext::new_foreign(
        CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(snapshot)),
        CorePeerContextAdapters {
            stun_info_source: Some(Arc::new(ParentStunInfoSource(parent_context_dyn))),
            event_sink: Arc::new(()),
            credential_storage: None,
            credential_event_sink: Arc::new(()),
        },
        parent_context,
    ))
}

struct ParentStunInfoSource(ArcPeerContext);

impl PeerStunInfoSource for ParentStunInfoSource {
    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.0.stun_info()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    use easytier_proto::common::{FlagsInConfig, PeerFeatureFlag};

    use super::{
        ForeignNetworkManager, abort_and_join_persistent_tasks, build_foreign_peer_context,
        check_network_in_relay_whitelist, desired_foreign_avoid_relay_data,
        sync_foreign_avoid_relay_data,
    };

    use crate::{
        config::runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        foundation::stats::{LabelSet, LabelType, MetricName},
        peers::{
            context::{
                ArcPeerContext, CorePeerContext, CorePeerContextAdapters, NetworkIdentity,
                PeerContext, PeerRuntimeSnapshot,
            },
            error::Error,
        },
        proto::common::StunInfo,
    };

    impl ForeignNetworkManager {
        pub(crate) async fn is_stopped_for_test(&self) -> bool {
            *self.lifecycle.read().await == super::ForeignNetworkManagerState::Stopped
                && self.task_reaper.lock().await.is_none()
                && self.tasks.lock().unwrap().is_empty()
                && self.data.network_peer_maps.is_empty()
                && self.data.peer_network_map.is_empty()
        }

        pub(crate) async fn admission_is_open_for_test(&self) -> bool {
            self.admission_guard().await.is_ok()
        }

        pub(crate) async fn hold_admission_for_test(
            &self,
            entered: Arc<tokio::sync::Notify>,
            release: Arc<tokio::sync::Notify>,
        ) -> Result<(), Error> {
            let _admission = self.admission_guard().await?;
            entered.notify_one();
            release.notified().await;
            Ok(())
        }
    }

    #[tokio::test]
    async fn cancelled_join_wait_keeps_persistent_task_ownership() {
        struct DropFlag(Arc<AtomicBool>);

        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let tasks = std::sync::Mutex::new(tokio::task::JoinSet::new());
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicBool::new(false));
        let task_entered = entered.clone();
        let task_dropped = dropped.clone();
        tasks.lock().unwrap().spawn(async move {
            let _drop = DropFlag(task_dropped);
            task_entered.notify_one();
            std::future::pending::<()>().await;
        });
        entered.notified().await;

        {
            let first_wait = abort_and_join_persistent_tasks(&tasks);
            tokio::pin!(first_wait);
            assert!(matches!(
                futures::poll!(first_wait.as_mut()),
                std::task::Poll::Pending
            ));
        }

        abort_and_join_persistent_tasks(&tasks).await;
        assert!(dropped.load(Ordering::Acquire));
        assert!(tasks.lock().unwrap().is_empty());
    }

    struct FeatureContext {
        avoid_relay_data: AtomicBool,
        flags: FlagsInConfig,
        hostname: String,
    }

    impl FeatureContext {
        fn new(avoid_relay_data: bool) -> Self {
            Self {
                avoid_relay_data: AtomicBool::new(avoid_relay_data),
                flags: FlagsInConfig::default(),
                hostname: String::new(),
            }
        }
    }

    impl PeerContext for FeatureContext {
        fn network_identity(&self) -> NetworkIdentity {
            NetworkIdentity::default()
        }

        fn feature_flags(&self) -> PeerFeatureFlag {
            PeerFeatureFlag {
                avoid_relay_data: self.avoid_relay_data.load(Ordering::Acquire),
                ..Default::default()
            }
        }

        fn flags(&self) -> FlagsInConfig {
            self.flags.clone()
        }

        fn hostname(&self) -> String {
            self.hostname.clone()
        }

        fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
            self.avoid_relay_data
                .swap(avoid_relay_data, Ordering::AcqRel)
                != avoid_relay_data
        }
    }

    #[test]
    fn relay_whitelist_supports_exact_wildcard_and_empty_rules() {
        assert!(check_network_in_relay_whitelist("net1 net2*", "net1").is_ok());
        assert!(check_network_in_relay_whitelist("net1 net2*", "net2-west").is_ok());
        assert!(check_network_in_relay_whitelist("*", "any-network").is_ok());
        assert!(check_network_in_relay_whitelist("", "net1").is_err());
        assert!(check_network_in_relay_whitelist("net1 net2*", "net3").is_err());
    }

    #[test]
    fn foreign_avoid_relay_data_policy_tracks_parent_and_relay_permission() {
        let parent_state = Arc::new(FeatureContext::new(false));
        let parent: ArcPeerContext = parent_state.clone();
        let foreign_state = Arc::new(FeatureContext::new(true));
        let foreign: ArcPeerContext = foreign_state.clone();

        assert!(!desired_foreign_avoid_relay_data(&parent, true));
        assert!(sync_foreign_avoid_relay_data(&parent, &foreign, true));
        assert!(!foreign.feature_flags().avoid_relay_data);
        assert!(!sync_foreign_avoid_relay_data(&parent, &foreign, true));

        parent_state.avoid_relay_data.store(true, Ordering::Release);
        assert!(sync_foreign_avoid_relay_data(&parent, &foreign, true));
        assert!(foreign.feature_flags().avoid_relay_data);

        parent_state
            .avoid_relay_data
            .store(false, Ordering::Release);
        assert!(!sync_foreign_avoid_relay_data(&parent, &foreign, false));
        assert!(foreign.feature_flags().avoid_relay_data);
    }

    #[test]
    fn foreign_context_resources_are_assembled_in_core() {
        let mut parent_snapshot = PeerRuntimeSnapshot::default();
        parent_snapshot.runtime.core.node.hostname = Some("parent".to_owned());
        parent_snapshot.runtime.stun_info = StunInfo {
            public_ip: vec!["198.51.100.1".to_owned()],
            ..Default::default()
        };
        parent_snapshot
            .runtime
            .host_routing
            .local_exit_node_fallback = true;
        parent_snapshot.flags.enable_relay_foreign_network_kcp = true;
        parent_snapshot.flags.enable_relay_foreign_network_quic = false;
        parent_snapshot.flags.socket_mark = Some(7);
        parent_snapshot.hmac_secret_digest = true;
        let parent_config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(parent_snapshot.clone()),
        );
        let parent = Arc::new(CorePeerContext::new(
            parent_config.clone(),
            Arc::new(()),
            CorePeerContextAdapters {
                stun_info_source: None,
                event_sink: Arc::new(()),
                credential_storage: None,
                credential_event_sink: Arc::new(()),
            },
        ));
        let network = NetworkIdentity {
            network_name: "foreign".to_owned(),
            network_secret: Some("secret".to_owned()),
            network_secret_digest: None,
        };
        let mut defaults = FlagsInConfig::default();
        defaults.mtu = 1400;
        defaults.relay_network_whitelist = "baseline".to_owned();
        let foreign = build_foreign_peer_context(&network, &parent, false, defaults);

        assert!(Arc::ptr_eq(
            &parent.stats_manager(),
            &foreign.stats_manager(),
        ));
        assert!(!Arc::ptr_eq(
            &parent.credential_manager(),
            &foreign.credential_manager(),
        ));
        assert!(!Arc::ptr_eq(
            &parent.trusted_key_manager(),
            &foreign.trusted_key_manager(),
        ));
        assert_eq!(foreign.network_name(), "foreign");
        assert_eq!(foreign.hostname(), "PublicServer_parent");
        assert!(foreign.secure_mode().is_none());
        assert!(!foreign.flags().disable_relay_kcp);
        assert!(foreign.flags().disable_relay_quic);
        assert_eq!(foreign.flags().socket_mark, Some(7));
        assert_eq!(foreign.flags().mtu, 1400);
        assert_eq!(foreign.flags().relay_network_whitelist, "baseline");
        assert!(foreign.feature_flags().is_public_server);
        assert!(foreign.feature_flags().avoid_relay_data);
        assert_eq!(foreign.stun_info().public_ip, vec!["198.51.100.1"]);
        assert!(foreign.host_routing_policy().local_exit_node_fallback);
        assert!(foreign.hmac_secret_digest());

        parent_snapshot.runtime.stun_info.public_ip = vec!["203.0.113.2".to_owned()];
        parent_config.update_peer(Arc::new(parent_snapshot));
        assert_eq!(foreign.stun_info().public_ip, vec!["203.0.113.2"]);

        foreign.record_control_tx("foreign", 64);
        let labels = LabelSet::new().with_label_type(LabelType::NetworkName("foreign".to_owned()));
        assert_eq!(
            parent
                .stats_manager()
                .get_metric(MetricName::TrafficControlBytesTx, &labels)
                .unwrap()
                .value,
            64
        );
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ForeignNetworkRouteInfo {
    pub network_name: String,
    pub peer_ids: Vec<PeerId>,
    pub network_secret_digest: Vec<u8>,
    pub my_peer_id_for_this_network: PeerId,
}

struct ForeignNetworkRouteInterface {
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,
    network_identity: NetworkIdentity,
    global_peer_map: Weak<PeerMap>,
}

#[async_trait::async_trait]
impl RouteInterface for ForeignNetworkRouteInterface {
    async fn list_peers(&self) -> Vec<PeerId> {
        let Some(peer_map) = self.peer_map.upgrade() else {
            return vec![];
        };

        let mut global = if let Some(global_peer_map) = self.global_peer_map.upgrade() {
            global_peer_map
                .list_peers_own_foreign_network(&self.network_identity)
                .await
        } else {
            vec![]
        };
        let local = peer_map.list_peers_with_conn().await;
        global.extend(local.iter().cloned());
        global
            .into_iter()
            .filter(|peer_id| *peer_id != self.my_peer_id)
            .collect()
    }

    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    fn need_periodic_requery_peers(&self) -> bool {
        true
    }

    async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        let peer_map = self.peer_map.upgrade()?;
        peer_map.get_peer_identity_type(peer_id)
    }

    async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let peer_map = self.peer_map.upgrade()?;
        peer_map.get_peer_public_key(peer_id)
    }

    async fn close_peer(&self, peer_id: PeerId) {
        if let Some(peer_map) = self.peer_map.upgrade() {
            let _ = peer_map.close_peer(peer_id).await;
        }
    }
}

struct RpcTransport {
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()> {
        tracing::debug!(
            "foreign network manager send rpc to peer: {:?}",
            dst_peer_id
        );
        let peer_map = self
            .peer_map
            .upgrade()
            .ok_or(anyhow::anyhow!("peer map is gone"))?;

        // send to ourselves so we can handle it in forward logic.
        peer_map.send_msg_directly(msg, self.my_peer_id).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<ZCPacket> {
        if let Some(packet) = self.packet_recv.lock().await.recv().await {
            tracing::trace!("recv rpc packet in foreign network manager rpc transport");
            Ok(packet)
        } else {
            Err(anyhow::anyhow!("unknown data store error"))
        }
    }
}

impl Drop for RpcTransport {
    fn drop(&mut self) {
        tracing::debug!(
            "drop rpc transport for foreign network manager, my_peer_id: {:?}",
            self.my_peer_id
        );
    }
}

#[derive(Clone, Debug)]
pub struct ForeignNetworkTrustedKeyInfo {
    pub pubkey: Vec<u8>,
    pub source: TrustedKeySource,
    pub expiry_unix: Option<i64>,
}

#[derive(Clone, Debug, Default)]
pub struct ForeignNetworkPeerInfo {
    pub peer_id: PeerId,
    pub conns: Vec<PeerConnInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct ForeignNetworkEntryInfo {
    pub network_secret_digest: Vec<u8>,
    pub my_peer_id_for_this_network: PeerId,
    pub peers: Vec<ForeignNetworkPeerInfo>,
    pub trusted_keys: Vec<ForeignNetworkTrustedKeyInfo>,
}

#[auto_impl::auto_impl(&, Arc)]
pub(crate) trait ForeignNetworkRpcRegistrar: Send + Sync + 'static {
    fn register_peer_rpc_services(
        &self,
        _peer_rpc: &Arc<PeerRpcManager>,
        _network_name: &str,
        _socket_context: SocketContext,
    ) {
    }
}

impl ForeignNetworkRpcRegistrar for () {}

fn join_joinset_background(
    js: Arc<std::sync::Mutex<JoinSet<()>>>,
    origin: &'static str,
) -> tokio::task::JoinHandle<()> {
    let js = Arc::downgrade(&js);
    tokio::spawn(async move {
        while js.strong_count() > 0 {
            crate::foundation::time::sleep(std::time::Duration::from_secs(1)).await;

            let fut = future::poll_fn(|cx| {
                let Some(js) = js.upgrade() else {
                    return std::task::Poll::Ready(());
                };

                let mut js = js.lock().unwrap();
                while !js.is_empty() {
                    match js.poll_join_next(cx) {
                        std::task::Poll::Ready(Some(_)) => continue,
                        std::task::Poll::Ready(None) => break,
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                    }
                }

                std::task::Poll::Ready(())
            });

            let _ = timeout(std::time::Duration::from_secs(5), fut).await;
        }

        tracing::debug!(origin, "joinset task exit");
    })
}

async fn abort_and_join_persistent_tasks(tasks: &std::sync::Mutex<JoinSet<()>>) {
    tasks.lock().unwrap().abort_all();
    future::poll_fn(|cx| {
        let mut tasks = tasks.lock().unwrap();
        loop {
            match tasks.poll_join_next(cx) {
                std::task::Poll::Ready(Some(_)) => continue,
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    })
    .await;
}

struct ForeignNetworkEntry {
    my_peer_id: PeerId,

    parent_context: ArcPeerContext,
    peer_context: Arc<CorePeerContext>,
    network: NetworkIdentity,
    peer_map: Arc<PeerMap>,
    relay_peer_map: Arc<RelayPeerMap>,
    relay_data: bool,
    pm_packet_sender: Mutex<Option<PacketRecvChan>>,

    peer_rpc: Arc<PeerRpcManager>,
    rpc_sender: UnboundedSender<ZCPacket>,

    packet_recv: Mutex<Option<PacketRecvChanReceiver>>,

    bps_limiter: Option<ArcByteLimiter>,

    peer_center: Arc<PeerCenterInstance>,

    traffic_metrics: Arc<TrafficMetricRecorder>,
    event_handler_started: AtomicBool,

    tasks: Mutex<JoinSet<()>>,

    lock: Mutex<()>,
}

impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        my_peer_id: PeerId,
        rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
        parent_context: Arc<CorePeerContext>,
        foreign_context_default_flags: FlagsInConfig,
        relay_data: bool,
        peer_session_store: Arc<PeerSessionStore>,
        pm_packet_sender: PacketRecvChan,
    ) -> Self {
        let parent_context_dyn: ArcPeerContext = parent_context.clone();
        let peer_context = build_foreign_peer_context(
            &network,
            &parent_context,
            relay_data,
            foreign_context_default_flags,
        );
        let socket_mark = peer_context.flags().socket_mark;
        let stats_mgr = peer_context.stats_manager();
        let network_name = network.network_name.clone();

        let (packet_sender, packet_recv) = super::create_packet_recv_chan();

        let peer_map = Arc::new(PeerMap::new(
            packet_sender,
            peer_context.clone(),
            my_peer_id,
        ));
        let traffic_metrics = Arc::new(TrafficMetricRecorder::new(
            my_peer_id,
            Arc::new(super::traffic_metrics::LogicalTrafficMetrics::new(
                stats_mgr.clone(),
                network_name.clone(),
                MetricName::TrafficBytesTx,
                MetricName::TrafficPacketsTx,
                MetricName::TrafficBytesTxByInstance,
                MetricName::TrafficPacketsTxByInstance,
                super::traffic_metrics::InstanceLabelKind::To,
            )),
            Arc::new(super::traffic_metrics::LogicalTrafficMetrics::new(
                stats_mgr.clone(),
                network_name.clone(),
                MetricName::TrafficControlBytesTx,
                MetricName::TrafficControlPacketsTx,
                MetricName::TrafficControlBytesTxByInstance,
                MetricName::TrafficControlPacketsTxByInstance,
                super::traffic_metrics::InstanceLabelKind::To,
            )),
            Arc::new(super::traffic_metrics::LogicalTrafficMetrics::new(
                stats_mgr.clone(),
                network_name.clone(),
                MetricName::TrafficBytesRx,
                MetricName::TrafficPacketsRx,
                MetricName::TrafficBytesRxByInstance,
                MetricName::TrafficPacketsRxByInstance,
                super::traffic_metrics::InstanceLabelKind::From,
            )),
            Arc::new(super::traffic_metrics::LogicalTrafficMetrics::new(
                stats_mgr.clone(),
                network_name.clone(),
                MetricName::TrafficControlBytesRx,
                MetricName::TrafficControlPacketsRx,
                MetricName::TrafficControlBytesRxByInstance,
                MetricName::TrafficControlPacketsRxByInstance,
                super::traffic_metrics::InstanceLabelKind::From,
            )),
            {
                let peer_map = Arc::downgrade(&peer_map);
                move |peer_id| {
                    let peer_map = peer_map.clone();
                    async move {
                        let peer_map = peer_map.upgrade()?;
                        peer_map
                            .get_route_peer_info(peer_id)
                            .await
                            .as_ref()
                            .and_then(super::traffic_metrics::route_peer_info_instance_id)
                    }
                }
            },
        ));
        let relay_peer_map = super::relay_peer_map::new_relay_peer_map(
            peer_map.clone(),
            None,
            peer_context.clone(),
            my_peer_id,
            peer_session_store.clone(),
        );

        let (rpc_transport_sender, rpc_packet_recv) = mpsc::unbounded_channel();
        let peer_rpc = Arc::new(PeerRpcManager::new(RpcTransport {
            my_peer_id,
            peer_map: Arc::downgrade(&peer_map),
            packet_recv: Mutex::new(rpc_packet_recv),
        }));

        rpc_registrar.register_peer_rpc_services(
            &peer_rpc,
            &network.network_name,
            SocketContext::default().with_socket_mark(socket_mark),
        );

        let bps_limiter = parent_context.foreign_forward_limiter(&network.network_name);

        let peer_center = Arc::new(PeerCenterInstance::new(Arc::new(
            PeerMapWithPeerRpcManager {
                peer_map: peer_map.clone(),
                rpc_mgr: peer_rpc.clone(),
                network_name: peer_context.network_name(),
            },
        )));

        Self {
            my_peer_id,

            parent_context: parent_context_dyn,
            peer_context,
            network,
            peer_map,
            relay_peer_map,
            relay_data,
            pm_packet_sender: Mutex::new(Some(pm_packet_sender)),

            peer_rpc,
            rpc_sender: rpc_transport_sender,

            packet_recv: Mutex::new(Some(packet_recv)),

            bps_limiter,

            traffic_metrics,
            event_handler_started: AtomicBool::new(false),

            tasks: Mutex::new(JoinSet::new()),

            peer_center,

            lock: Mutex::new(()),
        }
    }

    async fn prepare_route(&self, global_peer_map: Weak<PeerMap>) {
        let public_ipv6_runtime: Arc<dyn PublicIpv6Runtime> =
            Arc::new(DisabledPublicIpv6Runtime::new(
                self.peer_context.instance_id(),
                self.network.network_name.clone(),
            ));
        let route = PeerRoute::new(
            self.my_peer_id,
            self.peer_context.clone(),
            public_ipv6_runtime,
            self.peer_rpc.clone(),
        );
        route
            .open(Box::new(ForeignNetworkRouteInterface {
                my_peer_id: self.my_peer_id,
                peer_map: Arc::downgrade(&self.peer_map),
                network_identity: self.network.clone(),
                global_peer_map,
            }))
            .await
            .unwrap();

        route
            .set_route_cost_fn(self.peer_center.get_cost_calculator())
            .await;

        self.peer_map.add_route(route).await;
    }

    async fn start_packet_recv(&self) {
        let packet_recv = self.packet_recv.lock().await.take().unwrap();
        let pm_sender = self.pm_packet_sender.lock().await.take().unwrap();
        let router = ForeignNetworkPacketRouter::new(
            self.my_peer_id,
            packet_recv,
            self.rpc_sender.clone(),
            self.peer_map.clone(),
            self.relay_peer_map.clone(),
            self.traffic_metrics.clone(),
            self.parent_context.clone(),
            self.relay_data,
            pm_sender,
            self.network.network_name.clone(),
            self.bps_limiter.clone(),
            self.peer_context.stats_manager(),
        );

        self.tasks.lock().await.spawn(router.run());
    }

    async fn run_relay_session_gc_routine(&self) {
        let relay_peer_map = self.relay_peer_map.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                relay_peer_map.evict_idle_sessions(std::time::Duration::from_secs(60));
                crate::foundation::time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn run_parent_feature_flag_sync_routine(&self) {
        let parent_context = self.parent_context.clone();
        let foreign_peer_context: ArcPeerContext = self.peer_context.clone();
        let relay_data = self.relay_data;
        let runtime_changes = parent_context.subscribe_runtime_changes();
        sync_foreign_avoid_relay_data(&parent_context, &foreign_peer_context, relay_data);
        let Some(mut runtime_changes) = runtime_changes else {
            return;
        };
        self.tasks.lock().await.spawn(async move {
            loop {
                if runtime_changes.changed().await.is_err() {
                    break;
                }
                sync_foreign_avoid_relay_data(&parent_context, &foreign_peer_context, relay_data);
            }
        });
    }

    async fn prepare(&self, global_peer_map: Weak<PeerMap>) {
        self.prepare_route(global_peer_map).await;
        self.start_packet_recv().await;
        self.run_relay_session_gc_routine().await;
        self.run_parent_feature_flag_sync_routine().await;
        self.peer_rpc.run();
        self.peer_center.init().await;
    }

    async fn stop(&self) {
        let mut tasks = self.tasks.lock().await;
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        drop(tasks);
        self.peer_center.stop().await;
        self.peer_rpc.stop().await;
        self.peer_map.clear_resources().await;
        self.peer_context.stop().await;
    }
}

impl Drop for ForeignNetworkEntry {
    fn drop(&mut self) {
        self.peer_rpc
            .rpc_server()
            .registry()
            .unregister_by_domain(&self.network.network_name);
        self.peer_context
            .remove_trusted_keys(&self.network.network_name);

        tracing::debug!(self.my_peer_id, ?self.network, "drop foreign network entry");
    }
}

struct ForeignNetworkManagerData {
    network_peer_maps: DashMap<String, Arc<ForeignNetworkEntry>>,
    peer_network_map: DashMap<PeerId, DashSet<String>>,
    network_peer_last_update: DashMap<String, SystemTime>,
    global_peer_map: Weak<PeerMap>,
    lock: std::sync::Mutex<()>,
}

impl ForeignNetworkManagerData {
    fn get_peer_network(&self, peer_id: PeerId) -> Option<DashSet<String>> {
        self.peer_network_map.get(&peer_id).map(|v| v.clone())
    }

    fn get_network_entry(&self, network_name: &str) -> Option<Arc<ForeignNetworkEntry>> {
        self.network_peer_maps.get(network_name).map(|v| v.clone())
    }

    fn remove_peer(&self, peer_id: PeerId, network_name: &String) {
        let _l = self.lock.lock().unwrap();
        self.peer_network_map.remove_if(&peer_id, |_, v| {
            let _ = v.remove(network_name);
            v.is_empty()
        });
        if self
            .network_peer_maps
            .remove_if(network_name, |_, v| v.peer_map.is_empty())
            .is_some()
        {
            self.network_peer_last_update.remove(network_name);
        }
        shrink_dashmap(&self.peer_network_map, None);
        shrink_dashmap(&self.network_peer_maps, None);
        shrink_dashmap(&self.network_peer_last_update, None);
    }

    async fn clear_no_conn_peer(&self, network_name: &String) {
        let Some(peer_map) = self
            .network_peer_maps
            .get(network_name)
            .map(|v| v.peer_map.clone())
        else {
            return;
        };
        peer_map.clean_peer_without_conn().await;
    }

    fn remove_network_if_current(
        &self,
        network_name: &String,
        expected_entry: &Weak<ForeignNetworkEntry>,
    ) {
        let _l = self.lock.lock().unwrap();
        let Some(expected_entry) = expected_entry.upgrade() else {
            return;
        };
        let old = self
            .network_peer_maps
            .remove_if(network_name, |_, entry| Arc::ptr_eq(entry, &expected_entry));
        let Some((_, old)) = old else {
            return;
        };

        old.traffic_metrics.clear_peer_cache();
        let to_remove_peers = old.peer_map.list_peers();
        for p in to_remove_peers {
            self.peer_network_map.remove_if(&p, |_, v| {
                v.remove(network_name);
                v.is_empty()
            });
        }
        self.network_peer_last_update.remove(network_name);
        shrink_dashmap(&self.peer_network_map, None);
        shrink_dashmap(&self.network_peer_maps, None);
        shrink_dashmap(&self.network_peer_last_update, None);
    }

    #[allow(clippy::too_many_arguments)]
    async fn get_or_insert_entry(
        &self,
        network_identity: &NetworkIdentity,
        my_peer_id: PeerId,
        dst_peer_id: PeerId,
        relay_data: bool,
        rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
        parent_context: Arc<CorePeerContext>,
        foreign_context_default_flags: FlagsInConfig,
        peer_session_store: Arc<PeerSessionStore>,
        pm_packet_sender: &PacketRecvChan,
    ) -> (Arc<ForeignNetworkEntry>, bool) {
        let mut new_added = false;

        let l = self.lock.lock().unwrap();
        let entry = self
            .network_peer_maps
            .entry(network_identity.network_name.clone())
            .or_insert_with(|| {
                new_added = true;
                Arc::new(ForeignNetworkEntry::new(
                    network_identity.clone(),
                    my_peer_id,
                    rpc_registrar,
                    parent_context,
                    foreign_context_default_flags,
                    relay_data,
                    peer_session_store,
                    pm_packet_sender.clone(),
                ))
            })
            .clone();

        self.peer_network_map
            .entry(dst_peer_id)
            .or_default()
            .insert(network_identity.network_name.clone());

        self.network_peer_last_update
            .insert(network_identity.network_name.clone(), SystemTime::now());

        drop(l);

        if new_added {
            entry.prepare(self.global_peer_map.clone()).await;
        }

        (entry, new_added)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ForeignNetworkManagerState {
    Running,
    Stopping,
    Stopped,
}

pub(crate) struct ForeignNetworkManager {
    rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
    parent_context: Arc<CorePeerContext>,
    foreign_context_default_flags: FlagsInConfig,
    peer_session_store: Arc<PeerSessionStore>,
    packet_sender_to_mgr: PacketRecvChan,

    data: Arc<ForeignNetworkManagerData>,

    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    task_reaper: Mutex<Option<tokio::task::JoinHandle<()>>>,
    lifecycle: RwLock<ForeignNetworkManagerState>,
}

impl ForeignNetworkManager {
    fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
        network
            .network_secret_digest
            .as_ref()
            .is_none_or(|d| d.iter().all(|b| *b == 0))
    }

    fn should_reject_credential_trust_path(identity_type: PeerIdentityType) -> bool {
        matches!(identity_type, PeerIdentityType::Admin)
    }

    fn credential_pubkey_is_trusted(
        entry: &ForeignNetworkEntry,
        remote_static_pubkey: &[u8],
    ) -> bool {
        remote_static_pubkey.len() == 32
            && entry.peer_context.is_pubkey_trusted_with_source(
                remote_static_pubkey,
                &entry.network.network_name,
                TrustedKeySource::OspfCredential,
            )
    }

    pub fn new(
        rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
        parent_context: Arc<CorePeerContext>,
        foreign_context_default_flags: FlagsInConfig,
        peer_session_store: Arc<PeerSessionStore>,
        packet_sender_to_mgr: PacketRecvChan,
        global_peer_map: Weak<PeerMap>,
    ) -> Self {
        let data = Arc::new(ForeignNetworkManagerData {
            network_peer_maps: DashMap::new(),
            peer_network_map: DashMap::new(),
            network_peer_last_update: DashMap::new(),
            global_peer_map,
            lock: std::sync::Mutex::new(()),
        });

        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        let task_reaper = join_joinset_background(tasks.clone(), "ForeignNetworkManager");

        Self {
            rpc_registrar,
            parent_context,
            foreign_context_default_flags,
            peer_session_store,
            packet_sender_to_mgr,
            data,
            tasks,
            task_reaper: Mutex::new(Some(task_reaper)),
            lifecycle: RwLock::new(ForeignNetworkManagerState::Running),
        }
    }

    async fn admission_guard(
        &self,
    ) -> Result<RwLockReadGuard<'_, ForeignNetworkManagerState>, Error> {
        let guard = self.lifecycle.read().await;
        if *guard != ForeignNetworkManagerState::Running {
            return Err(anyhow::anyhow!("foreign network manager is stopping").into());
        }
        Ok(guard)
    }

    pub async fn stop(&self) {
        let mut lifecycle = self.lifecycle.write().await;
        if *lifecycle == ForeignNetworkManagerState::Stopped {
            return;
        }
        // Set this before the first await so cancellation permanently closes
        // admission. A later stop call can safely resume the idempotent
        // teardown while admissions remain rejected.
        *lifecycle = ForeignNetworkManagerState::Stopping;

        let mut reaper = self.task_reaper.lock().await;
        if let Some(reaper) = reaper.as_mut() {
            reaper.abort();
            let _ = reaper.await;
        }
        reaper.take();
        drop(reaper);
        abort_and_join_persistent_tasks(&self.tasks).await;

        let entries = self
            .data
            .network_peer_maps
            .iter()
            .map(|entry| entry.value().clone())
            .collect::<Vec<_>>();
        for entry in entries {
            entry.stop().await;
        }
        // Keep entries discoverable until every nested graph is stopped. If
        // this future is cancelled, the next stop call can snapshot and retry
        // the remaining idempotent teardown instead of losing ownership.
        self.data.peer_network_map.clear();
        self.data.network_peer_maps.clear();
        self.data.network_peer_last_update.clear();
        *lifecycle = ForeignNetworkManagerState::Stopped;
    }

    pub fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId> {
        self.data
            .network_peer_maps
            .get(network_name)
            .map(|v| v.my_peer_id)
    }

    pub fn is_existing_credential_pubkey_trusted(
        &self,
        network_name: &str,
        remote_static_pubkey: &[u8],
    ) -> bool {
        self.data
            .get_network_entry(network_name)
            .is_some_and(|entry| Self::credential_pubkey_is_trusted(&entry, remote_static_pubkey))
    }

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        let _admission = self.admission_guard().await?;
        let conn_info = peer_conn.get_conn_info();
        let peer_network = peer_conn.get_network_identity();
        tracing::info!(peer_conn = ?conn_info, network = ?peer_network, "add new peer conn in foreign network manager");

        let parent_flags = self.parent_context.flags();
        let ret = check_network_in_relay_whitelist(
            &parent_flags.relay_network_whitelist,
            &peer_network.network_name,
        );
        if ret.is_err() && !parent_flags.relay_all_peer_rpc {
            return ret.map_err(Error::Other);
        }

        let peer_digest_empty = Self::network_secret_digest_is_empty(&peer_network);
        if peer_digest_empty
            && self
                .data
                .get_network_entry(&peer_network.network_name)
                .is_none()
        {
            return Err(anyhow::anyhow!(
                "foreign network {} is not established by a secret-verified peer yet",
                peer_network.network_name
            )
            .into());
        }

        let (entry, new_added) = self
            .data
            .get_or_insert_entry(
                &peer_network,
                peer_conn.get_my_peer_id(),
                peer_conn.get_peer_id(),
                ret.is_ok(),
                self.rpc_registrar.clone(),
                self.parent_context.clone(),
                self.foreign_context_default_flags.clone(),
                self.peer_session_store.clone(),
                &self.packet_sender_to_mgr,
            )
            .await;

        defer!(rollback_new_entry => sync [
            data = self.data.clone(),
            network_name = entry.network.network_name.clone(),
            peer_id = peer_conn.get_peer_id(),
            should_rollback = new_added
        ] {
            if should_rollback {
                tracing::warn!(
                    %network_name,
                    "rollback newly added foreign network entry after add_peer_conn returned error"
                );
                data.remove_peer(peer_id, &network_name);
            }
        });

        self.ensure_event_handler_started(&entry);

        let same_identity = entry.network == peer_network;
        let peer_identity_type = peer_conn.get_peer_identity_type();
        let credential_peer_trusted = peer_digest_empty
            && Self::credential_pubkey_is_trusted(&entry, &conn_info.noise_remote_static_pubkey);
        let credential_identity_mismatch = credential_peer_trusted
            && Self::should_reject_credential_trust_path(peer_identity_type);

        let _g = entry.lock.lock().await;

        if (!(same_identity || credential_peer_trusted))
            || credential_identity_mismatch
            || entry.my_peer_id != peer_conn.get_my_peer_id()
        {
            let err = if entry.my_peer_id != peer_conn.get_my_peer_id() {
                anyhow::anyhow!(
                    "my peer id not match. exp: {:?} real: {:?}, need retry connect",
                    entry.my_peer_id,
                    peer_conn.get_my_peer_id()
                )
            } else if credential_identity_mismatch {
                anyhow::anyhow!(
                    "credential-trusted foreign peer has invalid identity type: {:?}",
                    peer_identity_type
                )
            } else {
                anyhow::anyhow!(
                    "foreign peer identity not trusted. exp: {:?} real: {:?}, remote_pubkey_len: {}, credential_trusted: {}",
                    entry.network,
                    peer_network,
                    conn_info.noise_remote_static_pubkey.len(),
                    credential_peer_trusted,
                )
            };
            tracing::error!(?err, "foreign network entry not match, disconnect peer");
            return Err(err.into());
        }

        if !new_added && let Some(peer) = entry.peer_map.get_peer_by_id(peer_conn.get_peer_id()) {
            let direct_conns_len = peer.get_directly_connections().len();
            let max_count = self
                .parent_context
                .max_direct_conns_per_peer_in_foreign_network();
            if direct_conns_len >= max_count {
                return Err(anyhow::anyhow!(
                    "too many direct conns, cur: {}, max: {}",
                    direct_conns_len,
                    max_count
                )
                .into());
            }
        }

        entry.peer_map.add_new_peer_conn(peer_conn).await?;
        let _ = rollback_new_entry.defuse();
        Ok(())
    }

    fn ensure_event_handler_started(&self, entry: &Arc<ForeignNetworkEntry>) {
        if entry.event_handler_started.swap(true, Ordering::AcqRel) {
            return;
        }

        let Some(mut s) = entry.peer_context.subscribe_peer_events() else {
            return;
        };
        let data = self.data.clone();
        let network_name = entry.network.network_name.clone();
        let entry_for_cleanup = Arc::downgrade(entry);
        let traffic_metrics = Arc::downgrade(&entry.traffic_metrics);
        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(e) = s.recv().await {
                match &e {
                    PeerContextEvent::PeerRemoved(peer_id) => {
                        tracing::info!(?e, "remove peer from foreign network manager");
                        if let Some(traffic_metrics) = traffic_metrics.upgrade() {
                            traffic_metrics.remove_peer(*peer_id);
                        }
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                        data.remove_peer(*peer_id, &network_name);
                    }
                    PeerContextEvent::PeerConnRemoved => {
                        tracing::info!(?e, "clear no conn peer from foreign network manager");
                        data.clear_no_conn_peer(&network_name).await;
                    }
                    PeerContextEvent::PeerAdded(_) => {
                        tracing::info!(?e, "add peer to foreign network manager");
                        data.network_peer_last_update
                            .insert(network_name.clone(), SystemTime::now());
                    }
                    _ => continue,
                }
            }
            tracing::error!("global event handler at foreign network manager exit");
            if let Some(traffic_metrics) = traffic_metrics.upgrade() {
                traffic_metrics.clear_peer_cache();
            }
            data.remove_network_if_current(&network_name, &entry_for_cleanup);
        });
    }

    pub async fn list_foreign_network_infos(
        &self,
        include_trusted_keys: bool,
    ) -> std::collections::HashMap<String, ForeignNetworkEntryInfo> {
        let mut ret = std::collections::HashMap::new();
        let networks = self
            .data
            .network_peer_maps
            .iter()
            .map(|v| v.key().clone())
            .collect::<Vec<_>>();

        for network_name in networks {
            let Some(item) = self
                .data
                .network_peer_maps
                .get(&network_name)
                .map(|v| v.clone())
            else {
                continue;
            };

            let mut entry = ForeignNetworkEntryInfo {
                network_secret_digest: item
                    .network
                    .network_secret_digest
                    .unwrap_or_default()
                    .to_vec(),
                my_peer_id_for_this_network: item.my_peer_id,
                peers: Default::default(),
                trusted_keys: if include_trusted_keys {
                    item.peer_context
                        .list_trusted_keys(&item.network.network_name)
                        .into_iter()
                        .map(|(pubkey, metadata)| ForeignNetworkTrustedKeyInfo {
                            pubkey,
                            source: metadata.source,
                            expiry_unix: metadata.expiry_unix,
                        })
                        .collect()
                } else {
                    Default::default()
                },
            };
            for peer in item.peer_map.list_peers() {
                let peer_info = ForeignNetworkPeerInfo {
                    peer_id: peer,
                    conns: item.peer_map.list_peer_conns(peer).await.unwrap_or(vec![]),
                };
                entry.peers.push(peer_info);
            }

            ret.insert(network_name, entry);
        }
        ret
    }

    pub async fn list_foreign_network_route_infos(&self) -> Vec<ForeignNetworkRouteInfo> {
        self.list_foreign_network_infos(false)
            .await
            .into_iter()
            .map(|(network_name, info)| ForeignNetworkRouteInfo {
                network_name,
                peer_ids: info.peers.into_iter().map(|peer| peer.peer_id).collect(),
                network_secret_digest: info.network_secret_digest,
                my_peer_id_for_this_network: info.my_peer_id_for_this_network,
            })
            .collect()
    }

    pub fn get_foreign_network_last_update(&self, network_name: &str) -> Option<SystemTime> {
        self.data
            .network_peer_last_update
            .get(network_name)
            .map(|v| *v)
    }

    pub async fn forward_foreign_network_packet(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> Result<(), Error> {
        if let Some(entry) = self.data.get_network_entry(network_name) {
            let packet_type = msg
                .peer_manager_header()
                .map(|hdr| hdr.packet_type)
                .unwrap_or(0);
            let msg_len = msg.buf_len() as u64;
            let send_result = entry
                .peer_map
                .send_msg(msg, dst_peer_id, NextHopPolicy::LeastHop)
                .await;
            if send_result.is_ok() {
                entry
                    .traffic_metrics
                    .record_tx(dst_peer_id, packet_type, msg_len)
                    .await;
            }
            send_result
        } else {
            Err(Error::RouteError(Some("network not found".to_string())))
        }
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        let network_names = self.data.get_peer_network(peer_id).unwrap_or_default();
        for network_name in network_names {
            if let Some(entry) = self.data.get_network_entry(&network_name) {
                let ret = entry.peer_map.close_peer_conn(peer_id, conn_id).await;
                if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
                    return ret;
                }
            }
        }
        Err(Error::NotFound)
    }
}

impl Drop for ForeignNetworkManager {
    fn drop(&mut self) {
        if let Ok(mut reaper) = self.task_reaper.try_lock()
            && let Some(reaper) = reaper.take()
        {
            reaper.abort();
        }
        self.tasks.lock().unwrap().abort_all();
        self.data.peer_network_map.clear();
        self.data.network_peer_maps.clear();
    }
}

struct ForeignNetworkForwardCounters {
    forward_data_bytes: CounterHandle,
    forward_data_packets: CounterHandle,
    forward_control_bytes: CounterHandle,
    forward_control_packets: CounterHandle,
    rx_bytes: CounterHandle,
    rx_packets: CounterHandle,
}

pub(crate) struct ForeignNetworkPacketRouter {
    my_node_id: PeerId,
    packet_recv: PacketRecvChanReceiver,
    rpc_sender: UnboundedSender<ZCPacket>,
    peer_map: Arc<PeerMap>,
    relay_peer_map: Arc<RelayPeerMap>,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    parent_context: ArcPeerContext,
    relay_data: bool,
    pm_sender: PacketRecvChan,
    network_name: String,
    bps_limiter: Option<ArcByteLimiter>,
    counters: ForeignNetworkForwardCounters,
}

impl ForeignNetworkPacketRouter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        my_node_id: PeerId,
        packet_recv: PacketRecvChanReceiver,
        rpc_sender: UnboundedSender<ZCPacket>,
        peer_map: Arc<PeerMap>,
        relay_peer_map: Arc<RelayPeerMap>,
        traffic_metrics: Arc<TrafficMetricRecorder>,
        parent_context: ArcPeerContext,
        relay_data: bool,
        pm_sender: PacketRecvChan,
        network_name: String,
        bps_limiter: Option<ArcByteLimiter>,
        stats_mgr: Arc<StatsManager>,
    ) -> Self {
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));
        let counters = ForeignNetworkForwardCounters {
            forward_data_bytes: stats_mgr
                .get_counter(MetricName::TrafficBytesForwarded, label_set.clone()),
            forward_data_packets: stats_mgr
                .get_counter(MetricName::TrafficPacketsForwarded, label_set.clone()),
            forward_control_bytes: stats_mgr
                .get_counter(MetricName::TrafficControlBytesForwarded, label_set.clone()),
            forward_control_packets: stats_mgr.get_counter(
                MetricName::TrafficControlPacketsForwarded,
                label_set.clone(),
            ),
            rx_bytes: stats_mgr.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone()),
            rx_packets: stats_mgr.get_counter(MetricName::TrafficPacketsRx, label_set),
        };

        Self {
            my_node_id,
            packet_recv,
            rpc_sender,
            peer_map,
            relay_peer_map,
            traffic_metrics,
            parent_context,
            relay_data,
            pm_sender,
            network_name,
            bps_limiter,
            counters,
        }
    }

    pub async fn run(self) {
        let Self {
            my_node_id,
            mut packet_recv,
            rpc_sender,
            peer_map,
            relay_peer_map,
            traffic_metrics,
            parent_context,
            relay_data,
            pm_sender,
            network_name,
            bps_limiter,
            counters,
        } = self;

        while let Ok(mut zc_packet) = recv_packet_from_chan(&mut packet_recv).await {
            let buf_len = zc_packet.buf_len();
            let Some(hdr) = zc_packet.peer_manager_header() else {
                tracing::warn!("invalid packet, skip");
                continue;
            };
            tracing::trace!(?hdr, "recv packet in foreign network manager");
            let from_peer_id = hdr.from_peer_id.get();
            let packet_type = hdr.packet_type;
            let len = hdr.len.get();
            let to_peer_id = hdr.to_peer_id.get();
            let is_local_delivery = to_peer_id == my_node_id;
            let is_locally_originated = from_peer_id == my_node_id;
            if is_local_delivery && !is_locally_originated {
                traffic_metrics
                    .record_rx(from_peer_id, packet_type, buf_len as u64)
                    .await;
            }
            if is_local_delivery {
                if packet_type == PacketType::RelayHandshake as u8
                    || packet_type == PacketType::RelayHandshakeAck as u8
                {
                    let _ = relay_peer_map.handle_handshake_packet(zc_packet).await;
                    continue;
                }

                if relay_peer_map.is_secure_mode_enabled() && hdr.is_encrypted() {
                    match relay_peer_map.decrypt_if_needed(&mut zc_packet).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::error!("secure session not found");
                            continue;
                        }
                        Err(e) => {
                            tracing::error!(?e, "secure decrypt failed");
                            continue;
                        }
                    }
                }

                if packet_type == PacketType::TaRpc as u8
                    || packet_type == PacketType::RpcReq as u8
                    || packet_type == PacketType::RpcResp as u8
                {
                    counters.rx_bytes.add(buf_len as u64);
                    counters.rx_packets.inc();
                    rpc_sender.send(zc_packet).unwrap();
                    continue;
                }
                tracing::trace!(
                    ?packet_type,
                    ?len,
                    ?from_peer_id,
                    ?to_peer_id,
                    "ignore packet in foreign network"
                );
            } else {
                if is_relay_data_packet_type(packet_type) {
                    let disable_relay_data = parent_context.disable_relay_data();
                    if !relay_data || disable_relay_data {
                        tracing::debug!(
                            ?from_peer_id,
                            ?to_peer_id,
                            packet_type,
                            disable_relay_data,
                            "drop foreign network relay data"
                        );
                        continue;
                    }
                    if let Some(bps_limiter) = bps_limiter.as_ref()
                        && !bps_limiter.try_consume(len.into())
                    {
                        continue;
                    }
                }

                match traffic_kind(packet_type) {
                    TrafficKind::Data => {
                        counters.forward_data_bytes.add(buf_len as u64);
                        counters.forward_data_packets.inc();
                    }
                    TrafficKind::Control => {
                        counters.forward_control_bytes.add(buf_len as u64);
                        counters.forward_control_packets.inc();
                    }
                }

                let gateway_peer_id = peer_map
                    .get_gateway_peer_id(to_peer_id, NextHopPolicy::LeastHop)
                    .await;

                match gateway_peer_id {
                    Some(peer_id) if peer_map.has_peer(peer_id) => {
                        if peer_id != to_peer_id && hdr.from_peer_id.get() == my_node_id {
                            if let Err(e) = relay_peer_map
                                .send_msg(zc_packet, to_peer_id, NextHopPolicy::LeastHop)
                                .await
                            {
                                tracing::error!(
                                    ?e,
                                    "send packet to foreign peer inside relay peer map failed"
                                );
                            } else if is_locally_originated {
                                traffic_metrics
                                    .record_tx(to_peer_id, packet_type, buf_len as u64)
                                    .await;
                            }
                        } else if let Err(e) = peer_map.send_msg_directly(zc_packet, peer_id).await
                        {
                            tracing::error!(
                                ?e,
                                "send packet to foreign peer inside peer map failed"
                            );
                        } else if is_locally_originated {
                            traffic_metrics
                                .record_tx(to_peer_id, packet_type, buf_len as u64)
                                .await;
                        }
                    }
                    _ => {
                        let mut foreign_packet = ZCPacket::new_for_foreign_network(
                            &network_name,
                            to_peer_id,
                            &zc_packet,
                        );
                        let via_peer = gateway_peer_id.unwrap_or(to_peer_id);
                        foreign_packet.fill_peer_manager_hdr(
                            my_node_id,
                            via_peer,
                            PacketType::ForeignNetworkPacket as u8,
                        );
                        if let Err(e) = pm_sender.send(foreign_packet).await {
                            tracing::error!("send packet to peer with pm failed: {:?}", e);
                        } else if is_locally_originated {
                            traffic_metrics
                                .record_tx(to_peer_id, packet_type, buf_len as u64)
                                .await;
                        }
                    }
                };
            }
        }
    }
}

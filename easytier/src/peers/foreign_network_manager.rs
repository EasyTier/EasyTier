/*
foreign_network_manager is used to forward packets of other networks.  currently
only forward packets of peers that directly connected to this node.

in the future, with the help wo peer center we can forward packets of peers that
connected to any node in the local network.
*/
use std::{sync::Arc, time::SystemTime};

use dashmap::DashMap;
use easytier_core::connectivity::direct::DirectConnectorRpcHandler;
use easytier_core::peers::context::ArcPeerContext;
use easytier_core::peers::foreign_network_manager as core_foreign_network_manager;
pub use easytier_core::peers::foreign_network_manager::{
    ForeignNetworkInfoProvider, ForeignNetworkRouteInfo, ForeignNetworkRouteInfoProvider,
    GlobalForeignNetworkAccessor,
};
use easytier_core::peers::peer_manager::{self as core_peer_manager, ForeignNetworkPacketHandler};
use easytier_core::tunnel::ring::RingTunnelRegistry;
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::task::JoinSet;

#[cfg(test)]
use crate::{common::global_ctx::GlobalCtxEvent, proto::peer_rpc::PeerIdentityType};
use crate::{
    common::{
        PeerId,
        config::{ConfigLoader, TomlConfigLoader},
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtx, NetworkIdentity, TrustedKeySource},
        shrink_dashmap,
    },
    connector::runtime::RuntimeConnectorHost,
    proto::{
        api::instance::{
            ForeignNetworkEntryPb, ListForeignNetworkResponse, PeerInfo, TrustedKeyInfoPb,
            TrustedKeySourcePb,
        },
        peer_rpc::DirectConnectorRpcServer,
    },
    tunnel::packet_def::ZCPacket,
};

#[cfg(test)]
use super::create_packet_recv_chan;
use super::{
    PUBLIC_SERVER_HOSTNAME_PREFIX, PacketRecvChan, peer_conn::PeerConn, peer_rpc::PeerRpcManager,
    peer_session::PeerSessionStore,
};

#[cfg(test)]
struct ForeignNetworkEntry {
    parent_global_ctx: ArcGlobalCtx,
    global_ctx: ArcGlobalCtx,
    network: NetworkIdentity,
    relay_data: bool,
    tasks: Mutex<JoinSet<()>>,
}

#[cfg(test)]
impl ForeignNetworkEntry {
    fn new(
        network: NetworkIdentity,
        _my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        relay_data: bool,
        _peer_session_store: Arc<PeerSessionStore>,
        _pm_packet_sender: PacketRecvChan,
    ) -> Self {
        let foreign_global_ctx = ForeignNetworkRuntimeImpl::build_foreign_global_ctx(
            &network,
            global_ctx.clone(),
            global_ctx.clone(),
            relay_data,
        );
        Self {
            parent_global_ctx: global_ctx,
            global_ctx: foreign_global_ctx,
            network,
            relay_data,
            tasks: Mutex::new(JoinSet::new()),
        }
    }

    fn sync_parent_relay_data_feature_flag(
        parent_global_ctx: &ArcGlobalCtx,
        global_ctx: &ArcGlobalCtx,
        relay_data: bool,
    ) -> bool {
        let parent_context: ArcPeerContext = parent_global_ctx.clone();
        ForeignNetworkRuntimeImpl::sync_parent_relay_data_feature_flag(
            &parent_context,
            global_ctx,
            relay_data,
        )
    }

    async fn run_parent_feature_flag_sync_routine(&self) {
        let parent_global_ctx = self.parent_global_ctx.clone();
        let global_ctx = self.global_ctx.clone();
        let relay_data = self.relay_data;
        self.tasks.lock().await.spawn(async move {
            let mut parent_events = parent_global_ctx.subscribe();
            loop {
                ForeignNetworkEntry::sync_parent_relay_data_feature_flag(
                    &parent_global_ctx,
                    &global_ctx,
                    relay_data,
                );

                let _ = parent_events.recv().await;
            }
        });
    }
}

pub const FOREIGN_NETWORK_SERVICE_ID: u32 =
    core_foreign_network_manager::FOREIGN_NETWORK_SERVICE_ID;

struct RuntimeForeignNetworkContext {
    global_ctx: ArcGlobalCtx,
    parent_events: Mutex<crate::common::global_ctx::EventBusSubscriber>,
    lifecycle_token: Arc<()>,
}

struct ForeignNetworkRuntimeImpl {
    global_ctx: ArcGlobalCtx,
    parent_context: ArcPeerContext,
    ring_registry: Arc<RingTunnelRegistry>,
    foreign_contexts: DashMap<String, Arc<RuntimeForeignNetworkContext>>,
}

impl ForeignNetworkRuntimeImpl {
    fn new(global_ctx: ArcGlobalCtx, parent_context: ArcPeerContext) -> Self {
        Self::new_with_ring_registry(
            global_ctx,
            parent_context,
            Arc::new(RingTunnelRegistry::default()),
        )
    }

    fn new_with_ring_registry(
        global_ctx: ArcGlobalCtx,
        parent_context: ArcPeerContext,
        ring_registry: Arc<RingTunnelRegistry>,
    ) -> Self {
        Self {
            global_ctx,
            parent_context,
            ring_registry,
            foreign_contexts: DashMap::new(),
        }
    }

    fn get_runtime_foreign_context(
        &self,
        network_name: &str,
        foreign_context: &core_foreign_network_manager::ForeignNetworkContext,
    ) -> Option<Arc<RuntimeForeignNetworkContext>> {
        let current = self.foreign_contexts.get(network_name)?;
        Arc::ptr_eq(&current.lifecycle_token, &foreign_context.lifecycle_token)
            .then(|| current.clone())
    }

    fn desired_avoid_relay_data_feature_flag(
        parent_context: &ArcPeerContext,
        relay_data: bool,
    ) -> bool {
        !relay_data || parent_context.feature_flags().avoid_relay_data
    }

    fn sync_parent_relay_data_feature_flag(
        parent_context: &ArcPeerContext,
        global_ctx: &ArcGlobalCtx,
        relay_data: bool,
    ) -> bool {
        let avoid_relay_data =
            Self::desired_avoid_relay_data_feature_flag(parent_context, relay_data);
        if global_ctx.get_feature_flags().avoid_relay_data == avoid_relay_data {
            return false;
        }

        global_ctx.set_avoid_relay_data_preference(avoid_relay_data)
    }

    fn build_foreign_global_ctx(
        network: &NetworkIdentity,
        global_ctx: ArcGlobalCtx,
        parent_context: ArcPeerContext,
        relay_data: bool,
    ) -> ArcGlobalCtx {
        let config = TomlConfigLoader::default();
        config.set_network_identity(network.clone());
        config.set_hostname(Some(format!(
            "{}{}",
            PUBLIC_SERVER_HOSTNAME_PREFIX,
            parent_context.hostname()
        )));
        config.set_secure_mode(parent_context.secure_mode());

        let mut flags = config.get_flags();
        let parent_flags = parent_context.flags();
        flags.disable_relay_kcp = !parent_flags.enable_relay_foreign_network_kcp;
        flags.disable_relay_quic = !parent_flags.enable_relay_foreign_network_quic;
        flags.socket_mark = parent_flags.socket_mark;
        config.set_flags(flags);

        config.set_mapped_listeners(Some(global_ctx.config.get_mapped_listeners()));

        let foreign_global_ctx = Arc::new(GlobalCtx::new(config));
        foreign_global_ctx
            .replace_stun_info_collector(Box::new(global_ctx.get_stun_info_collector().clone()));

        let mut feature_flag = parent_context.feature_flags();
        feature_flag.is_public_server = true;
        feature_flag.avoid_relay_data =
            Self::desired_avoid_relay_data_feature_flag(&parent_context, relay_data);
        foreign_global_ctx.set_base_advertised_feature_flags(feature_flag);

        for u in global_ctx.get_running_listeners().into_iter() {
            foreign_global_ctx.add_running_listener(u);
        }

        foreign_global_ctx
    }
}

#[async_trait::async_trait]
impl core_foreign_network_manager::ForeignNetworkRuntime for ForeignNetworkRuntimeImpl {
    fn parent_context(&self) -> easytier_core::peers::context::ArcPeerContext {
        self.parent_context.clone()
    }

    fn build_foreign_context(
        &self,
        network: &easytier_core::peers::context::NetworkIdentity,
        relay_data: bool,
    ) -> core_foreign_network_manager::ForeignNetworkContext {
        let foreign_global_ctx = ForeignNetworkRuntimeImpl::build_foreign_global_ctx(
            &network.clone().into(),
            self.global_ctx.clone(),
            self.parent_context.clone(),
            relay_data,
        );
        let lifecycle_token = Arc::new(());
        self.foreign_contexts.insert(
            network.network_name.clone(),
            Arc::new(RuntimeForeignNetworkContext {
                global_ctx: foreign_global_ctx.clone(),
                parent_events: Mutex::new(self.global_ctx.subscribe()),
                lifecycle_token: lifecycle_token.clone(),
            }),
        );
        core_foreign_network_manager::ForeignNetworkContext {
            peer_context: foreign_global_ctx.clone(),
            public_ipv6_runtime: foreign_global_ctx,
            lifecycle_token,
        }
    }

    fn remove_foreign_context(
        &self,
        network_name: &str,
        foreign_context: &core_foreign_network_manager::ForeignNetworkContext,
    ) {
        self.foreign_contexts.remove_if(network_name, |_, current| {
            Arc::ptr_eq(&current.lifecycle_token, &foreign_context.lifecycle_token)
        });
        shrink_dashmap(&self.foreign_contexts, None);
    }

    fn register_peer_rpc_services(
        &self,
        peer_rpc: &Arc<PeerRpcManager>,
        foreign_context: &core_foreign_network_manager::ForeignNetworkContext,
        network_name: &str,
    ) {
        let foreign_global_ctx = self
            .get_runtime_foreign_context(network_name, foreign_context)
            .expect("foreign context should be built before use")
            .global_ctx
            .clone();
        peer_rpc.rpc_server().registry().register(
            DirectConnectorRpcServer::new(DirectConnectorRpcHandler::new(Arc::new(
                RuntimeConnectorHost::new_with_ring_registry(
                    foreign_global_ctx,
                    self.ring_registry.clone(),
                ),
            ))),
            network_name,
        );
    }

    fn sync_parent_relay_data_feature_flag(
        &self,
        foreign_context: &core_foreign_network_manager::ForeignNetworkContext,
        relay_data: bool,
    ) {
        let network_name = foreign_context.peer_context.network_name();
        let Some(foreign_context) =
            self.get_runtime_foreign_context(&network_name, foreign_context)
        else {
            return;
        };
        ForeignNetworkRuntimeImpl::sync_parent_relay_data_feature_flag(
            &self.parent_context,
            &foreign_context.global_ctx,
            relay_data,
        );
    }

    async fn wait_parent_feature_change(
        &self,
        foreign_context: &core_foreign_network_manager::ForeignNetworkContext,
    ) {
        let network_name = foreign_context.peer_context.network_name();
        let Some(foreign_context) =
            self.get_runtime_foreign_context(&network_name, foreign_context)
        else {
            std::future::pending::<()>().await;
            return;
        };
        let mut parent_events = foreign_context.parent_events.lock().await;
        let _ = parent_events.recv().await;
    }
}

pub struct ForeignNetworkManager {
    core: core_foreign_network_manager::ForeignNetworkManager,
    runtime: Arc<ForeignNetworkRuntimeImpl>,
}

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

impl ForeignNetworkManager {
    #[cfg(test)]
    fn should_reject_credential_trust_path(identity_type: PeerIdentityType) -> bool {
        matches!(identity_type, PeerIdentityType::Admin)
    }

    #[cfg(test)]
    fn is_credential_pubkey_trusted(
        entry: &ForeignNetworkEntry,
        remote_static_pubkey: &[u8],
    ) -> bool {
        remote_static_pubkey.len() == 32
            && entry.global_ctx.is_pubkey_trusted_with_source(
                remote_static_pubkey,
                &entry.network.network_name,
                TrustedKeySource::OspfCredential,
            )
    }

    pub fn new(
        _my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        parent_context: ArcPeerContext,
        ring_registry: Arc<RingTunnelRegistry>,
        peer_session_store: Arc<PeerSessionStore>,
        packet_sender_to_mgr: PacketRecvChan,
        accessor: Box<dyn GlobalForeignNetworkAccessor>,
    ) -> Self {
        let stats_mgr = global_ctx.stats_manager().clone();
        let runtime = Arc::new(ForeignNetworkRuntimeImpl::new_with_ring_registry(
            global_ctx,
            parent_context,
            ring_registry,
        ));
        Self {
            core: core_foreign_network_manager::ForeignNetworkManager::new(
                runtime.clone(),
                stats_mgr,
                peer_session_store,
                packet_sender_to_mgr,
                accessor,
            ),
            runtime,
        }
    }

    #[cfg(test)]
    fn fail_next_add_peer_conn_after_entry_insert(&self) {
        self.core.fail_next_add_peer_conn_after_entry_insert();
    }

    #[cfg(test)]
    fn foreign_global_ctx_for_test(&self, network_name: &str) -> Option<ArcGlobalCtx> {
        self.runtime
            .foreign_contexts
            .get(network_name)
            .map(|ctx| ctx.global_ctx.clone())
    }

    #[cfg(test)]
    async fn record_rx_traffic_for_test(
        &self,
        network_name: &str,
        peer_id: PeerId,
        packet_type: u8,
        bytes: u64,
    ) -> bool {
        self.core
            .record_rx_traffic_for_test(network_name, peer_id, packet_type, bytes)
            .await
    }

    #[cfg(test)]
    fn contains_traffic_metric_peer_cache_for_test(
        &self,
        network_name: &str,
        peer_id: PeerId,
    ) -> bool {
        self.core
            .contains_traffic_metric_peer_cache_for_test(network_name, peer_id)
    }

    pub fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId> {
        self.core.get_network_peer_id(network_name)
    }

    pub(crate) fn is_existing_credential_pubkey_trusted(
        &self,
        network_name: &str,
        remote_static_pubkey: &[u8],
    ) -> bool {
        self.core
            .is_existing_credential_pubkey_trusted(network_name, remote_static_pubkey)
    }

    pub async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        self.core.add_peer_conn(peer_conn).await.map_err(Into::into)
    }

    pub async fn list_foreign_networks(&self) -> ListForeignNetworkResponse {
        self.list_foreign_networks_with_options(false).await
    }

    pub async fn list_foreign_networks_with_options(
        &self,
        include_trusted_keys: bool,
    ) -> ListForeignNetworkResponse {
        let mut ret = ListForeignNetworkResponse::default();
        let networks = self
            .core
            .list_foreign_network_infos(include_trusted_keys)
            .await;

        for (network_name, info) in networks {
            ret.foreign_networks
                .insert(network_name, foreign_network_info_to_api(info));
        }

        ret
    }

    pub fn get_foreign_network_last_update(&self, network_name: &str) -> Option<SystemTime> {
        self.core.get_foreign_network_last_update(network_name)
    }

    pub async fn forward_foreign_network_packet(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> Result<(), Error> {
        self.core
            .forward_foreign_network_packet(network_name, dst_peer_id, msg)
            .await
            .map_err(Into::into)
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &super::peer_conn::PeerConnId,
    ) -> Result<(), Error> {
        self.core
            .close_peer_conn(peer_id, conn_id)
            .await
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl ForeignNetworkInfoProvider for ForeignNetworkManager {
    async fn list_foreign_network_infos(
        &self,
        include_trusted_keys: bool,
    ) -> std::collections::HashMap<String, core_foreign_network_manager::ForeignNetworkEntryInfo>
    {
        self.core
            .list_foreign_network_infos(include_trusted_keys)
            .await
    }
}

#[async_trait::async_trait]
impl ForeignNetworkRouteInfoProvider for ForeignNetworkManager {
    async fn list_foreign_network_route_infos(&self) -> Vec<ForeignNetworkRouteInfo> {
        self.core.list_foreign_network_route_infos().await
    }

    fn get_foreign_network_last_update(&self, network_name: &str) -> Option<SystemTime> {
        ForeignNetworkManager::get_foreign_network_last_update(self, network_name)
    }
}

#[async_trait::async_trait]
impl ForeignNetworkPacketHandler for ForeignNetworkManager {
    fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId> {
        ForeignNetworkManager::get_network_peer_id(self, network_name)
    }

    async fn forward_foreign_network_packet(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> anyhow::Result<()> {
        ForeignNetworkManager::forward_foreign_network_packet(self, network_name, dst_peer_id, msg)
            .await
            .map_err(Into::into)
    }
}

#[async_trait::async_trait]
impl core_peer_manager::ForeignNetworkConnectionAdmission for ForeignNetworkManager {
    fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId> {
        ForeignNetworkManager::get_network_peer_id(self, network_name)
    }

    fn is_existing_credential_pubkey_trusted(
        &self,
        network_name: &str,
        remote_static_pubkey: &[u8],
    ) -> bool {
        ForeignNetworkManager::is_existing_credential_pubkey_trusted(
            self,
            network_name,
            remote_static_pubkey,
        )
    }

    async fn add_peer_conn(
        &self,
        peer_conn: super::peer_conn::PeerConn,
    ) -> Result<(), easytier_core::peers::error::Error> {
        self.core.add_peer_conn(peer_conn).await
    }
}

#[async_trait::async_trait]
impl core_peer_manager::ForeignPeerConnectionCloser for ForeignNetworkManager {
    async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &super::peer_conn::PeerConnId,
    ) -> Result<(), easytier_core::peers::error::Error> {
        self.core.close_peer_conn(peer_id, conn_id).await
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx_with_network,
        common::stats_manager::{LabelSet, LabelType, MetricName},
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
    use std::{collections::HashMap, time::Duration};

    use super::*;

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: LabelSet) -> u64 {
        peer_mgr
            .get_global_ctx()
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
        peer_mgr.run().await.unwrap();
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
        peer_mgr.run().await.unwrap();
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
        peer_mgr.run().await.unwrap();
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

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(1, rpc_resp.foreign_networks.len());
        assert_eq!(2, rpc_resp.foreign_networks["net1"].peers.len());
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
        pm_center
            .get_global_ctx()
            .issue_event(GlobalCtxEvent::ConfigPatched(Default::default()));

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

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let (client_ret, server_ret) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                pma_net1.add_client_tunnel(a_ring, false),
                pm_center.add_tunnel_as_server(b_ring, true)
            )
        })
        .await
        .unwrap();

        assert!(client_ret.is_ok());
        assert!(server_ret.is_err());
        assert!(foreign_mgr.get_network_peer_id("net1").is_none());
        assert!(
            foreign_mgr
                .list_foreign_networks()
                .await
                .foreign_networks
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

        foreign_mgr
            .foreign_global_ctx_for_test("net1")
            .unwrap()
            .issue_event(GlobalCtxEvent::PeerRemoved(pma_net1.my_peer_id()));

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

        let pma_net1 = create_mock_peer_manager_for_secure_foreign_network("net1").await;
        let pmb_net1 = create_mock_peer_manager_for_secure_foreign_network("net1").await;
        connect_peer_manager(pma_net1.clone(), pm_center.clone()).await;
        connect_peer_manager(pmb_net1.clone(), pm_center.clone()).await;
        wait_route_appear(pma_net1.clone(), pmb_net1.clone())
            .await
            .unwrap();

        let without_trusted_keys = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert!(
            without_trusted_keys.foreign_networks["net1"]
                .trusted_keys
                .is_empty()
        );

        let foreign_mgr = pm_center.get_foreign_network_manager();
        wait_for_condition(
            || {
                let foreign_mgr = foreign_mgr.clone();
                async move {
                    foreign_mgr
                        .list_foreign_networks_with_options(true)
                        .await
                        .foreign_networks
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

        let with_trusted_keys = foreign_mgr.list_foreign_networks_with_options(true).await;
        assert!(
            !with_trusted_keys.foreign_networks["net1"]
                .trusted_keys
                .is_empty()
        );
    }

    #[tokio::test]
    async fn secure_center_can_serve_legacy_and_secure_foreign_networks() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        set_secure_mode_cfg(&pm_center.get_global_ctx(), true);

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

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(2, rpc_resp.foreign_networks.len());
        assert_eq!(2, rpc_resp.foreign_networks["legacy-net"].peers.len());
        assert_eq!(2, rpc_resp.foreign_networks["secure-net"].peers.len());
    }

    #[tokio::test]
    async fn credential_pubkey_trust_requires_ospf_credential_source() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let foreign_network = NetworkIdentity::new("net1".to_string(), "net1_secret".to_string());
        let (pm_packet_sender, _pm_packet_recv) = create_packet_recv_chan();
        let entry = ForeignNetworkEntry::new(
            foreign_network.clone(),
            1,
            global_ctx.clone(),
            false,
            Arc::new(PeerSessionStore::new()),
            pm_packet_sender,
        );
        let pubkey = vec![7; 32];

        entry.global_ctx.update_trusted_keys(
            HashMap::from([(
                pubkey.clone(),
                crate::common::global_ctx::TrustedKeyMetadata {
                    source: TrustedKeySource::OspfNode,
                    expiry_unix: None,
                },
            )]),
            &foreign_network.network_name,
        );
        assert!(!ForeignNetworkManager::is_credential_pubkey_trusted(
            &entry, &pubkey
        ));

        entry.global_ctx.update_trusted_keys(
            HashMap::from([(
                pubkey.clone(),
                crate::common::global_ctx::TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
            &foreign_network.network_name,
        );
        assert!(ForeignNetworkManager::is_credential_pubkey_trusted(
            &entry, &pubkey
        ));
    }

    #[tokio::test]
    async fn foreign_entry_feature_flag_tracks_parent_disable_relay_data_toggle() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let foreign_network = NetworkIdentity::new("net1".to_string(), "net1_secret".to_string());
        let (pm_packet_sender, _pm_packet_recv) = create_packet_recv_chan();
        let entry = ForeignNetworkEntry::new(
            foreign_network,
            1,
            global_ctx.clone(),
            true,
            Arc::new(PeerSessionStore::new()),
            pm_packet_sender,
        );
        assert!(!entry.global_ctx.get_feature_flags().avoid_relay_data);

        entry.run_parent_feature_flag_sync_routine().await;

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(Default::default()));

        wait_for_condition(
            || async { entry.global_ctx.get_feature_flags().avoid_relay_data },
            Duration::from_secs(2),
        )
        .await;

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);
        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(Default::default()));

        wait_for_condition(
            || async { !entry.global_ctx.get_feature_flags().avoid_relay_data },
            Duration::from_secs(2),
        )
        .await;
    }

    #[tokio::test]
    async fn parent_config_reads_require_peer_snapshot_refresh() {
        use easytier_core::peers::foreign_network_manager::ForeignNetworkRuntime as _;

        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let runtime_config = easytier_core::instance::CoreRuntimeConfigStore::new(
            easytier_core::instance::CoreRuntimeConfig::default(),
            Arc::new(crate::peers::context::runtime_peer_snapshot(&global_ctx)),
        );
        let parent_context = Arc::new(easytier_core::peers::context::SubmittedPeerContext::new(
            Arc::new(runtime_config.clone()),
            global_ctx.clone(),
        ));
        let runtime = ForeignNetworkRuntimeImpl::new(global_ctx.clone(), parent_context.clone());
        let parent_flags = runtime.parent_context().flags();
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
        let parent_flags = runtime.parent_context().flags();
        assert!(!parent_flags.relay_all_peer_rpc);
        assert!(
            easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist(
                &parent_flags.relay_network_whitelist,
                "net1",
            )
            .is_ok()
        );

        runtime_config.update_peer(Arc::new(crate::peers::context::runtime_peer_snapshot(
            &global_ctx,
        )));
        let parent_flags = runtime.parent_context().flags();
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
    async fn parent_feature_flag_change_reaches_each_foreign_context() {
        use easytier_core::peers::foreign_network_manager::ForeignNetworkRuntime as _;

        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let runtime = Arc::new(ForeignNetworkRuntimeImpl::new(
            global_ctx.clone(),
            global_ctx.clone(),
        ));
        let net1 = easytier_core::peers::context::NetworkIdentity {
            network_name: "net1".to_string(),
            network_secret: Some("net1_secret".to_string()),
            network_secret_digest: None,
        };
        let net2 = easytier_core::peers::context::NetworkIdentity {
            network_name: "net2".to_string(),
            network_secret: Some("net2_secret".to_string()),
            network_secret_digest: None,
        };
        let foreign_context1 = runtime.build_foreign_context(&net1, true);
        let foreign_context2 = runtime.build_foreign_context(&net2, true);
        assert!(
            !foreign_context1
                .peer_context
                .feature_flags()
                .avoid_relay_data
        );
        assert!(
            !foreign_context2
                .peer_context
                .feature_flags()
                .avoid_relay_data
        );

        let task1 = tokio::spawn({
            let runtime = runtime.clone();
            let foreign_context = foreign_context1.clone();
            async move {
                runtime.wait_parent_feature_change(&foreign_context).await;
                runtime.sync_parent_relay_data_feature_flag(&foreign_context, true);
            }
        });
        let task2 = tokio::spawn({
            let runtime = runtime.clone();
            let foreign_context = foreign_context2.clone();
            async move {
                runtime.wait_parent_feature_change(&foreign_context).await;
                runtime.sync_parent_relay_data_feature_flag(&foreign_context, true);
            }
        });
        tokio::time::sleep(Duration::from_millis(10)).await;

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        global_ctx.issue_event(GlobalCtxEvent::ConfigPatched(Default::default()));

        tokio::time::timeout(Duration::from_secs(2), async {
            task1.await.unwrap();
            task2.await.unwrap();
        })
        .await
        .unwrap();
        assert!(
            foreign_context1
                .peer_context
                .feature_flags()
                .avoid_relay_data
        );
        assert!(
            foreign_context2
                .peer_context
                .feature_flags()
                .avoid_relay_data
        );
    }

    #[tokio::test]
    async fn stale_foreign_context_removal_keeps_replacement() {
        use easytier_core::peers::foreign_network_manager::ForeignNetworkRuntime as _;

        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let runtime = ForeignNetworkRuntimeImpl::new(global_ctx.clone(), global_ctx);
        let network = easytier_core::peers::context::NetworkIdentity {
            network_name: "net1".to_string(),
            network_secret: Some("net1_secret".to_string()),
            network_secret_digest: None,
        };

        let old_context = runtime.build_foreign_context(&network, false);
        let replacement_context = runtime.build_foreign_context(&network, true);
        runtime.sync_parent_relay_data_feature_flag(&old_context, false);
        assert!(
            !replacement_context
                .peer_context
                .feature_flags()
                .avoid_relay_data
        );
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                runtime.wait_parent_feature_change(&old_context)
            )
            .await
            .is_err()
        );

        runtime.remove_foreign_context("net1", &old_context);
        let current = runtime.foreign_contexts.get("net1").unwrap();
        assert!(Arc::ptr_eq(
            &current.lifecycle_token,
            &replacement_context.lifecycle_token
        ));
        drop(current);

        runtime.remove_foreign_context("net1", &replacement_context);
        assert!(runtime.foreign_contexts.get("net1").is_none());
    }

    #[tokio::test]
    async fn foreign_entry_without_relay_data_keeps_avoid_feature_flag() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "__access__".to_string(),
            "access_secret".to_string(),
        )));
        let foreign_network = NetworkIdentity::new("net1".to_string(), "net1_secret".to_string());
        let (pm_packet_sender, _pm_packet_recv) = create_packet_recv_chan();
        let entry = ForeignNetworkEntry::new(
            foreign_network,
            1,
            global_ctx.clone(),
            false,
            Arc::new(PeerSessionStore::new()),
            pm_packet_sender,
        );

        assert!(entry.global_ctx.get_feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        ForeignNetworkEntry::sync_parent_relay_data_feature_flag(
            &global_ctx,
            &entry.global_ctx,
            entry.relay_data,
        );

        assert!(entry.global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[test]
    fn credential_trust_path_rejects_admin_identity() {
        assert!(ForeignNetworkManager::should_reject_credential_trust_path(
            PeerIdentityType::Admin
        ));
        assert!(!ForeignNetworkManager::should_reject_credential_trust_path(
            PeerIdentityType::Credential
        ));
        assert!(!ForeignNetworkManager::should_reject_credential_trust_path(
            PeerIdentityType::SharedNode
        ));
    }

    #[tokio::test]
    async fn zero_digest_peer_cannot_bootstrap_foreign_network() {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        set_secure_mode_cfg(&pm_center.get_global_ctx(), true);

        let pma_net1 = create_mock_credential_peer_manager_for_foreign_network("net1").await;

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let a_mgr_copy = pma_net1.clone();
        let client = tokio::spawn(async move { a_mgr_copy.add_client_tunnel(a_ring, false).await });
        let b_mgr_copy = pm_center.clone();
        let server =
            tokio::spawn(async move { b_mgr_copy.add_tunnel_as_server(b_ring, true).await });

        assert!(client.await.unwrap().is_ok());
        assert!(server.await.unwrap().is_err());
        assert!(
            pm_center
                .get_foreign_network_manager()
                .list_foreign_networks()
                .await
                .foreign_networks
                .is_empty()
        );
    }

    async fn foreign_network_whitelist_helper(name: String) {
        let pm_center = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        tracing::debug!("pm_center: {:?}", pm_center.my_peer_id());
        let mut flag = pm_center.get_global_ctx().get_flags();
        flag.relay_network_whitelist = ["net1".to_string(), "net2*".to_string()].join(" ");
        pm_center.get_global_ctx().set_flags(flag);

        let pma_net1 = create_mock_peer_manager_for_foreign_network(name.as_str()).await;

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let b_mgr_copy = pm_center.clone();
        let s_ret =
            tokio::spawn(async move { b_mgr_copy.add_tunnel_as_server(b_ring, true).await });

        pma_net1.add_client_tunnel(a_ring, false).await.unwrap();

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

        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(2, rpc_resp.foreign_networks.len());
        assert_eq!(3, rpc_resp.foreign_networks["net1"].peers.len());
        assert_eq!(2, rpc_resp.foreign_networks["net2"].peers.len());
        assert_eq!(
            5,
            rpc_resp
                .foreign_networks
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );

        drop(pmb_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(
            4,
            rpc_resp
                .foreign_networks
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );
        drop(pma_net2);
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let rpc_resp = pm_center
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        assert_eq!(
            3,
            rpc_resp
                .foreign_networks
                .values()
                .map(|entry| entry.peers.len())
                .sum::<usize>()
        );
        assert_eq!(1, rpc_resp.foreign_networks.len());
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

        let (a_ring, b_ring) = crate::tunnel::ring::create_ring_tunnel_pair();
        let a_mgr_copy = pma_net1.clone();
        tokio::spawn(async move {
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = pm_center1.clone();

        assert!(b_mgr_copy.add_tunnel_as_server(b_ring, true).await.is_err());
    }
}

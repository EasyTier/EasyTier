use cidr::{Ipv4Cidr, Ipv6Cidr};
use dashmap::DashMap;
use easytier_core::peers::{
    foreign_network_manager::{self as core_foreign_network_manager, GlobalForeignNetworkAccessor},
    peer_manager as core_peer_manager,
};
use quanta::Instant;
use std::collections::BTreeSet;
use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
};

use tokio::sync::{Mutex, RwLock};
use tokio::{sync::mpsc::UnboundedSender, task::JoinSet};

use crate::{
    common::{
        PeerId,
        constants::EASYTIER_VERSION,
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent, NetworkIdentity},
        shrink_dashmap,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        stun::StunInfoCollectorTrait,
    },
    peers::{
        PeerPacketFilter,
        peer_conn::PeerConn,
        peer_session::PeerSessionStore,
        route_trait::MockRoute,
        traffic_metrics::{
            InstanceLabelKind, LogicalTrafficMetrics, TrafficMetricRecorder,
            route_peer_info_instance_id,
        },
    },
    proto::{
        api::instance::{
            self, ListGlobalForeignNetworkResponse,
            list_global_foreign_network_response::OneForeignNetwork,
        },
        peer_rpc::{PeerIdentityType, RouteForeignNetworkSummary},
    },
    tunnel::{
        Tunnel, TunnelConnector,
        packet_def::{CompressorAlgo, PacketType, ZCPacket, compressor_algo_from_pb},
    },
};

use super::{
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChan, PacketRecvChanReceiver,
    create_packet_recv_chan,
    encrypt::{Encryptor, NullCipher},
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{ForeignNetworkManager, ForeignNetworkRouteInfoProvider},
    peer_conn::PeerConnId,
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManager,
    peer_task::ExternalTaskSignal,
    relay_peer_map::{RelayPeerMap, new_relay_peer_map},
    route_trait::{ArcRoute, Route},
};

pub enum RouteAlgoType {
    Ospf,
    None,
}

enum RouteAlgoInst {
    Ospf(Arc<PeerRoute>),
    None,
}

impl Clone for RouteAlgoInst {
    fn clone(&self) -> Self {
        match self {
            RouteAlgoInst::Ospf(route) => RouteAlgoInst::Ospf(route.clone()),
            RouteAlgoInst::None => RouteAlgoInst::None,
        }
    }
}

struct SelfTxCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
}

pub struct PeerManager {
    my_peer_id: PeerId,

    global_ctx: ArcGlobalCtx,
    nic_channel: PacketRecvChan,

    tasks: Mutex<JoinSet<()>>,

    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,

    peers: Arc<PeerMap>,

    peer_rpc_mgr: Arc<PeerRpcManager>,
    peer_rpc_tspt: Arc<core_peer_manager::RpcTransport>,

    peer_packet_process_pipeline: Arc<RwLock<Vec<BoxPeerPacketFilter>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<BoxNicPacketFilter>>>,

    route_algo_inst: RouteAlgoInst,

    foreign_network_manager: Arc<ForeignNetworkManager>,
    foreign_network_client: Arc<ForeignNetworkClient>,
    relay_peer_map: Arc<RelayPeerMap>,

    peer_connection_admission: core_peer_manager::PeerConnectionAdmission,
    outbound_packet_router: core_peer_manager::PeerOutboundPacketRouter,

    encryptor: Arc<dyn Encryptor + 'static>,
    data_compress_algo: CompressorAlgo,

    exit_nodes: Arc<RwLock<Vec<IpAddr>>>,

    reserved_my_peer_id_map: DashMap<String, PeerId>,
    recent_traffic: core_peer_manager::RecentTrafficTracker,

    allow_loopback_tunnel: AtomicBool,

    self_tx_counters: SelfTxCounters,
    traffic_metrics: Arc<TrafficMetricRecorder>,

    peer_session_store: Arc<PeerSessionStore>,
    is_secure_mode_enabled: bool,
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
        let my_peer_id = rand::random();

        let (packet_send, packet_recv) = create_packet_recv_chan();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            global_ctx.clone(),
            my_peer_id,
        ));
        let peer_session_store = Arc::new(PeerSessionStore::new());

        let encryptor = if global_ctx.get_flags().enable_encryption {
            // 只有在启用加密时才使用工厂函数选择算法
            let algorithm = &global_ctx.get_flags().encryption_algorithm;
            super::encrypt::create_encryptor(
                algorithm,
                global_ctx.get_128_key(),
                global_ctx.get_256_key(),
            )
        } else {
            // disable_encryption = true 时使用 NullCipher
            Arc::new(NullCipher)
        };

        if global_ctx
            .check_network_in_whitelist(&global_ctx.get_network_name())
            .is_err()
        {
            // if local network is not in whitelist, avoid relay data when exist any other route path
            global_ctx.set_avoid_relay_data_preference(true);
        }

        let is_secure_mode_enabled = global_ctx
            .config
            .get_secure_mode()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);

        let rpc_tspt = core_peer_manager::RpcTransport::new(
            my_peer_id,
            Arc::downgrade(&peers),
            encryptor.clone(),
            is_secure_mode_enabled,
        );
        let peer_rpc_mgr = Arc::new(PeerRpcManager::new_with_stats_manager(
            rpc_tspt.clone(),
            global_ctx.stats_manager().clone(),
        ));

        let route_algo_inst = match route_algo {
            RouteAlgoType::Ospf => RouteAlgoInst::Ospf(PeerRoute::new(
                my_peer_id,
                global_ctx.clone(),
                global_ctx.clone(),
                peer_rpc_mgr.clone(),
            )),
            RouteAlgoType::None => RouteAlgoInst::None,
        };

        let foreign_network_manager = Arc::new(ForeignNetworkManager::new(
            my_peer_id,
            global_ctx.clone(),
            peer_session_store.clone(),
            packet_send.clone(),
            Self::build_foreign_network_manager_accessor(&peers),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            global_ctx.clone(),
            packet_send,
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        let data_compress_algo =
            compressor_algo_from_pb(global_ctx.get_flags().data_compress_algo())
                .expect("invalid data compress algo, maybe some features not enabled");

        let exit_nodes = global_ctx.config.get_exit_nodes();

        let stats_manager = global_ctx.stats_manager();
        let network_name = global_ctx.get_network_name();
        let traffic_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficBytesTx,
            MetricName::TrafficPacketsTx,
            MetricName::TrafficBytesTxByInstance,
            MetricName::TrafficPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let traffic_control_tx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
            MetricName::TrafficControlBytesTxByInstance,
            MetricName::TrafficControlPacketsTxByInstance,
            InstanceLabelKind::To,
        ));
        let relay_peer_map = new_relay_peer_map(
            peers.clone(),
            Some(foreign_network_client.clone()),
            global_ctx.clone(),
            my_peer_id,
            peer_session_store.clone(),
        );
        let self_tx_counters = SelfTxCounters {
            self_tx_packets: stats_manager.get_counter(
                MetricName::TrafficPacketsSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            self_tx_bytes: stats_manager.get_counter(
                MetricName::TrafficBytesSelfTx,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_before: stats_manager.get_counter(
                MetricName::CompressionBytesTxBefore,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
            compress_tx_bytes_after: stats_manager.get_counter(
                MetricName::CompressionBytesTxAfter,
                LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone())),
            ),
        };
        let traffic_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name,
            MetricName::TrafficBytesRx,
            MetricName::TrafficPacketsRx,
            MetricName::TrafficBytesRxByInstance,
            MetricName::TrafficPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let traffic_control_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            global_ctx.get_network_name(),
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
            MetricName::TrafficControlBytesRxByInstance,
            MetricName::TrafficControlPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let route_algo_inst_for_metrics = route_algo_inst.clone();
        let traffic_metrics = Arc::new(TrafficMetricRecorder::new(
            my_peer_id,
            traffic_tx_metrics,
            traffic_control_tx_metrics,
            traffic_rx_metrics,
            traffic_control_rx_metrics,
            move |peer_id| {
                let route_algo_inst = route_algo_inst_for_metrics.clone();
                async move {
                    match &route_algo_inst {
                        RouteAlgoInst::Ospf(route) => route
                            .get_peer_info(peer_id)
                            .await
                            .as_ref()
                            .and_then(route_peer_info_instance_id),
                        RouteAlgoInst::None => None,
                    }
                }
            },
        ));
        let peer_packet_process_pipeline = Arc::new(RwLock::new(Vec::new()));
        let nic_packet_process_pipeline = Arc::new(RwLock::new(Vec::new()));
        let exit_nodes = Arc::new(RwLock::new(exit_nodes));
        let recent_traffic = core_peer_manager::RecentTrafficTracker::new(my_peer_id);
        let peer_connection_admission = core_peer_manager::PeerConnectionAdmission::new(
            my_peer_id,
            global_ctx.clone(),
            peers.clone(),
            foreign_network_client.clone(),
            peer_session_store.clone(),
            recent_traffic.clone(),
        );
        let outbound_packet_router = core_peer_manager::PeerOutboundPacketRouter::new(
            my_peer_id,
            global_ctx.clone(),
            peers.clone(),
            Self::route_arc_from_algo(&route_algo_inst),
            foreign_network_client.clone(),
            relay_peer_map.clone(),
            nic_packet_process_pipeline.clone(),
            encryptor.clone(),
            data_compress_algo,
            exit_nodes.clone(),
            recent_traffic.clone(),
            traffic_metrics.clone(),
            global_ctx.get_acl_filter().clone(),
            is_secure_mode_enabled,
            self_tx_counters.self_tx_packets.clone(),
            self_tx_counters.self_tx_bytes.clone(),
            self_tx_counters.compress_tx_bytes_before.clone(),
            self_tx_counters.compress_tx_bytes_after.clone(),
        );

        PeerManager {
            my_peer_id,

            global_ctx,
            nic_channel,

            tasks: Mutex::new(JoinSet::new()),

            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),

            peers,

            peer_rpc_mgr,
            peer_rpc_tspt: rpc_tspt,

            peer_packet_process_pipeline,
            nic_packet_process_pipeline,

            route_algo_inst,

            foreign_network_manager,
            foreign_network_client,
            relay_peer_map,

            peer_connection_admission,
            outbound_packet_router,

            encryptor,
            data_compress_algo,

            exit_nodes,

            reserved_my_peer_id_map: DashMap::new(),
            recent_traffic,

            allow_loopback_tunnel: AtomicBool::new(true),

            self_tx_counters,
            traffic_metrics,

            peer_session_store,
            is_secure_mode_enabled,
        }
    }

    pub fn set_allow_loopback_tunnel(&self, allow_loopback_tunnel: bool) {
        self.allow_loopback_tunnel
            .store(allow_loopback_tunnel, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn mark_recent_traffic(&self, dst_peer_id: PeerId) {
        let flags = self.global_ctx.flags_arc();
        self.recent_traffic
            .mark(dst_peer_id, flags.disable_p2p, flags.lazy_p2p, |peer_id| {
                self.has_directly_connected_conn(peer_id)
            });
    }

    pub fn has_recent_traffic(&self, peer_id: PeerId, now: Instant) -> bool {
        self.recent_traffic.has(peer_id, now, |peer_id| {
            self.has_directly_connected_conn(peer_id)
        })
    }

    pub fn clear_recent_traffic(&self, peer_id: PeerId) {
        self.recent_traffic.clear(peer_id);
    }

    pub fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        self.recent_traffic.p2p_demand_notify()
    }

    fn gc_recent_traffic(&self) {
        self.recent_traffic.gc(Instant::now(), |peer_id| {
            self.has_directly_connected_conn(peer_id)
        });
    }

    fn build_foreign_network_manager_accessor(
        peer_map: &Arc<PeerMap>,
    ) -> Box<dyn GlobalForeignNetworkAccessor> {
        core_foreign_network_manager::peer_map_foreign_network_accessor(Arc::downgrade(peer_map))
    }

    async fn add_new_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error> {
        let my_identity = self.global_ctx.get_network_identity();
        let local_secure_mode = self
            .global_ctx
            .config
            .get_secure_mode()
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);
        let my_identity = easytier_core::peers::context::NetworkIdentity {
            network_name: my_identity.network_name,
            network_secret: my_identity.network_secret,
            network_secret_digest: my_identity.network_secret_digest,
        };
        let peer_id = core_peer_manager::add_new_peer_conn(
            self.peers.as_ref(),
            &my_identity,
            local_secure_mode,
            peer_conn,
        )
        .await
        .map_err(Error::from)?;
        self.clear_recent_traffic(peer_id);
        Ok(())
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.peer_connection_admission
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
            .map_err(Error::from)
    }

    pub async fn add_client_tunnel_with_peer_id_hint(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.peer_connection_admission
            .add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, peer_id_hint)
            .await
            .map_err(Error::from)
    }

    pub fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    #[tracing::instrument]
    pub async fn try_direct_connect<C>(&self, connector: C) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        self.try_direct_connect_with_peer_id_hint(connector, None)
            .await
    }

    #[tracing::instrument]
    pub async fn try_direct_connect_with_peer_id_hint<C>(
        &self,
        connector: C,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error>
    where
        C: TunnelConnector + Debug,
    {
        let t = self.connect_tunnel(connector).await?;
        self.add_client_tunnel_with_peer_id_hint(t, true, peer_id_hint)
            .await
    }

    pub(crate) async fn connect_tunnel<C>(&self, mut connector: C) -> Result<Box<dyn Tunnel>, Error>
    where
        C: TunnelConnector + Debug,
    {
        let ns = self.global_ctx.net_ns.clone();
        Ok(ns
            .run_async(|| async move { connector.connect().await })
            .await?)
    }

    // avoid loop back to virtual network
    fn check_remote_addr_not_from_virtual_network(
        &self,
        tunnel: &dyn Tunnel,
    ) -> Result<(), anyhow::Error> {
        tracing::info!("check remote addr not from virtual network");
        let Some(tunnel_info) = tunnel.info() else {
            anyhow::bail!("tunnel info is not set");
        };
        let Some(src) = tunnel_info.remote_addr.map(url::Url::from) else {
            anyhow::bail!("tunnel info remote addr is not set");
        };
        if src.scheme() == "ring" {
            return Ok(());
        }
        let Ok(Some(addr)) = src.socket_addrs(|| Some(1)).map(|x| x.first().cloned()) else {
            // if the tunnel is not rely on ip address, skip check
            return Ok(());
        };

        // if no-tun is enabled, the src ip of packet in virtual network is converted to loopback address
        // we already filter out the connection in tcp/quic/kcp proxy so no need check here.
        if addr.ip().is_loopback() {
            // allow other loopback address, good for conn from cdn/l4 connection
            return Ok(());
        }

        if self.global_ctx.is_ip_in_same_network(&addr.ip()) {
            anyhow::bail!(
                "tunnel src {} is from the same network (ignore this error please)",
                addr
            );
        }

        Ok(())
    }

    fn release_reserved_peer_id(&self, network_name: &str) {
        self.reserved_my_peer_id_map.remove(network_name);
        shrink_dashmap(&self.reserved_my_peer_id_map, None);
    }

    #[tracing::instrument(ret)]
    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        self.check_remote_addr_not_from_virtual_network(&tunnel)?;

        let mut conn = PeerConn::new(
            self.my_peer_id,
            self.global_ctx.clone(),
            tunnel,
            self.peer_session_store.clone(),
        );
        let mut reserved_peer_id_network_name = None;
        let handshake_ret = conn.do_handshake_as_server_ext(|peer, network_name:&str| {
            if network_name
                == self.global_ctx.get_network_identity().network_name
            {
                return Ok(());
            }

            let mut peer_id = self
                .foreign_network_manager
                .get_network_peer_id(network_name);
            if peer_id.is_none() {
                reserved_peer_id_network_name = Some(network_name.to_string());
                peer_id = Some(*self.reserved_my_peer_id_map.entry(network_name.to_string()).or_insert_with(|| {
                    rand::random::<PeerId>()
                }).value());
            }
            peer.set_peer_id(peer_id.unwrap());

            tracing::info!(
                ?peer_id,
                ?network_name,
                "handshake as server with foreign network, new peer id: {}, peer id in foreign manager: {:?}",
                peer.get_my_peer_id(), peer_id
            );

            Ok(())
        })
        .await;

        if let Err(err) = handshake_ret {
            if let Some(network_name) = reserved_peer_id_network_name {
                self.release_reserved_peer_id(&network_name);
            }
            return Err(err.into());
        }

        let peer_identity: NetworkIdentity = conn.get_network_identity().into();
        let peer_network_name = peer_identity.network_name.clone();
        let my_identity = self.global_ctx.get_network_identity();
        let is_local_network = peer_network_name == my_identity.network_name;
        let trusted_foreign_credential =
            matches!(conn.get_peer_identity_type(), PeerIdentityType::Credential)
                && self
                    .foreign_network_manager
                    .is_existing_credential_pubkey_trusted(
                        &peer_network_name,
                        &conn.get_conn_info().noise_remote_static_pubkey,
                    );
        let foreign_network_allowed =
            conn.matches_local_network_secret() || trusted_foreign_credential;

        if !is_local_network && self.global_ctx.get_flags().private_mode && !foreign_network_allowed
        {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(Error::SecretKeyError(
                "private mode is turned on, foreign network secret mismatch".to_string(),
            ));
        }

        conn.set_is_hole_punched(!is_directly_connected);

        let add_peer_ret = if is_local_network {
            self.add_new_peer_conn(conn).await
        } else {
            self.foreign_network_manager.add_peer_conn(conn).await
        };

        if let Err(err) = add_peer_ret {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(err);
        }

        self.release_reserved_peer_id(&peer_network_name);

        tracing::info!("add tunnel as server done");
        Ok(())
    }

    async fn start_peer_recv(&self) {
        let packet_recv = self.packet_recv.lock().await.take().unwrap();
        let is_credential_node = self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none()
            && self.is_secure_mode_enabled;
        let context: easytier_core::peers::context::ArcPeerContext = self.global_ctx.clone();
        let foreign_network_handler: Arc<dyn core_peer_manager::ForeignNetworkPacketHandler> =
            self.foreign_network_manager.clone();
        let router = core_peer_manager::PeerPacketRouter::new(
            packet_recv,
            self.my_peer_id,
            self.peers.clone(),
            self.peer_packet_process_pipeline.clone(),
            self.foreign_network_client.clone(),
            self.relay_peer_map.clone(),
            foreign_network_handler,
            self.encryptor.clone(),
            self.data_compress_algo,
            self.global_ctx.get_acl_filter().clone(),
            context,
            self.is_secure_mode_enabled,
            self.get_route().into(),
            is_credential_node,
            self.traffic_metrics.clone(),
            self.global_ctx.stats_manager().clone(),
            self.global_ctx.get_network_name(),
            self.self_tx_counters.self_tx_packets.clone(),
            self.self_tx_counters.self_tx_bytes.clone(),
            self.self_tx_counters.compress_tx_bytes_before.clone(),
            self.self_tx_counters.compress_tx_bytes_after.clone(),
        );

        self.tasks.lock().await.spawn(router.run());
    }

    pub async fn add_packet_process_pipeline(&self, pipeline: BoxPeerPacketFilter) {
        // newest pipeline will be executed first
        self.peer_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    pub async fn add_nic_packet_process_pipeline(&self, pipeline: BoxNicPacketFilter) {
        // newest pipeline will be executed first
        self.nic_packet_process_pipeline
            .write()
            .await
            .push(pipeline);
    }

    async fn init_packet_process_pipeline(&self) {
        // for tun/tap ip/eth packet.
        struct NicPacketProcessor {
            nic_channel: PacketRecvChan,
        }
        #[async_trait::async_trait]
        impl PeerPacketFilter for NicPacketProcessor {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::Data as u8 && !hdr.is_not_send_to_tun() {
                    if hdr.is_encrypted() || hdr.is_compressed() {
                        tracing::warn!(
                            from_peer_id = hdr.from_peer_id.get(),
                            to_peer_id = hdr.to_peer_id.get(),
                            encrypted = hdr.is_encrypted(),
                            compressed = hdr.is_compressed(),
                            "dropping packet before nic because it is not fully decoded"
                        );
                        return None;
                    }
                    tracing::trace!(?packet, "send packet to nic channel");
                    // TODO: use a function to get the body ref directly for zero copy
                    let _ = self.nic_channel.send(packet).await;
                    None
                } else {
                    Some(packet)
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(NicPacketProcessor {
            nic_channel: self.nic_channel.clone(),
        }))
        .await;

        // for peer rpc packet
        struct PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
        }

        #[async_trait::async_trait]
        impl PeerPacketFilter for PeerRpcPacketProcessor {
            async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
                let hdr = packet.peer_manager_header().unwrap();
                if hdr.packet_type == PacketType::TaRpc as u8
                    || hdr.packet_type == PacketType::RpcReq as u8
                    || hdr.packet_type == PacketType::RpcResp as u8
                {
                    self.peer_rpc_tspt_sender.send(packet).unwrap();
                    None
                } else {
                    Some(packet)
                }
            }
        }
        self.add_packet_process_pipeline(Box::new(PeerRpcPacketProcessor {
            peer_rpc_tspt_sender: self.peer_rpc_tspt.packet_sender(),
        }))
        .await;
    }

    pub async fn add_route<T>(&self, route: T)
    where
        T: Route + PeerPacketFilter + Send + Sync + Clone + 'static,
    {
        // for route
        self.add_packet_process_pipeline(Box::new(route.clone()))
            .await;

        let foreign_network_provider: Arc<dyn ForeignNetworkRouteInfoProvider> =
            self.foreign_network_manager.clone();
        let my_peer_id = self.my_peer_id;
        let _route_id = route
            .open(core_peer_manager::peer_manager_route_interface(
                my_peer_id,
                Arc::downgrade(&self.peers),
                Arc::downgrade(&self.foreign_network_client),
                Arc::downgrade(&foreign_network_provider),
            ))
            .await
            .unwrap();

        let arc_route: ArcRoute = Arc::new(Box::new(route));
        self.peers.add_route(arc_route).await;
    }

    fn route_box_from_algo(
        route_algo_inst: &RouteAlgoInst,
    ) -> Box<dyn Route + Send + Sync + 'static> {
        match route_algo_inst {
            RouteAlgoInst::Ospf(route) => Box::new(route.clone()),
            RouteAlgoInst::None => Box::new(MockRoute {}),
        }
    }

    fn route_arc_from_algo(route_algo_inst: &RouteAlgoInst) -> ArcRoute {
        Arc::new(Self::route_box_from_algo(route_algo_inst))
    }

    pub fn get_route(&self) -> Box<dyn Route + Send + Sync + 'static> {
        Self::route_box_from_algo(&self.route_algo_inst)
    }

    pub async fn list_routes(&self) -> Vec<instance::Route> {
        self.get_route()
            .list_routes()
            .await
            .into_iter()
            .map(Into::into)
            .collect()
    }

    pub async fn get_route_peer_info_last_update_time(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }

    pub async fn list_proxy_cidrs(&self) -> BTreeSet<Ipv4Cidr> {
        self.get_route().list_proxy_cidrs().await
    }

    pub async fn list_proxy_cidrs_v6(&self) -> BTreeSet<Ipv6Cidr> {
        self.get_route().list_proxy_cidrs_v6().await
    }

    pub async fn list_public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.get_route().list_public_ipv6_routes().await
    }

    pub async fn get_my_public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.get_route().get_my_public_ipv6_addr().await
    }

    pub async fn get_local_public_ipv6_info(&self) -> instance::ListPublicIpv6InfoResponse {
        self.get_route().get_local_public_ipv6_info().await.into()
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    pub async fn list_global_foreign_network(&self) -> ListGlobalForeignNetworkResponse {
        let mut resp = ListGlobalForeignNetworkResponse::default();
        let ret = self.get_route().list_foreign_network_info().await;
        for info in ret.infos.iter() {
            let entry = resp
                .foreign_networks
                .entry(info.key.as_ref().unwrap().peer_id)
                .or_insert_with(Default::default);
            let Some(route_info) = info.value.as_ref() else {
                continue;
            };

            let f = OneForeignNetwork {
                network_name: info.key.as_ref().unwrap().network_name.clone(),
                peer_ids: route_info.foreign_peer_ids.clone(),
                last_updated: serde_json::to_string(&route_info.last_update.unwrap()).unwrap(),
                version: route_info.version,
            };

            entry.foreign_networks.push(f);
        }

        resp
    }

    pub async fn get_foreign_network_summary(&self) -> RouteForeignNetworkSummary {
        self.get_route().get_foreign_network_summary().await
    }

    pub async fn remove_nic_packet_process_pipeline(&self, id: String) -> Result<(), Error> {
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        if let Some(pos) = pipelines.iter().position(|x| x.id() == id) {
            pipelines.remove(pos);
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    pub async fn send_msg_for_proxy(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.outbound_packet_router
            .send_msg_for_proxy(msg, dst_peer_id)
            .await
            .map_err(Error::from)
    }

    pub async fn get_msg_dst_peer(&self, addr: &IpAddr) -> (Vec<PeerId>, bool) {
        self.outbound_packet_router.get_msg_dst_peer(addr).await
    }

    pub async fn get_msg_dst_peer_ipv4(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        self.outbound_packet_router
            .get_msg_dst_peer_ipv4(ipv4_addr)
            .await
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        self.outbound_packet_router
            .get_msg_dst_peer_ipv6(ipv6_addr)
            .await
    }

    pub async fn send_msg_by_ip(
        &self,
        msg: ZCPacket,
        ip_addr: IpAddr,
        not_send_to_self: bool,
    ) -> Result<(), Error> {
        self.outbound_packet_router
            .send_msg_by_ip(msg, ip_addr, not_send_to_self)
            .await
            .map_err(Error::from)
    }

    async fn run_credential_gc_routine(&self) {
        let global_ctx = self.global_ctx.clone();
        let peer_map = self.peers.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                if global_ctx.get_network_identity().network_secret.is_some() {
                    if global_ctx
                        .get_credential_manager()
                        .remove_expired_credentials()
                    {
                        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);
                    }

                    let network_name = global_ctx.get_network_name();
                    core_peer_manager::close_untrusted_credential_peers(
                        peer_map.as_ref(),
                        &network_name,
                        |pubkey, network_name| global_ctx.is_pubkey_trusted(pubkey, network_name),
                    )
                    .await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    async fn run_traffic_metrics_gc_routine(&self) {
        let mut event_receiver = self.global_ctx.subscribe();
        let traffic_metrics = self.traffic_metrics.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                match event_receiver.recv().await {
                    Ok(GlobalCtxEvent::PeerRemoved(peer_id)) => {
                        traffic_metrics.remove_peer(peer_id);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "traffic metrics GC receiver lagged; clearing peer cache to avoid stale metric attribution"
                        );
                        traffic_metrics.clear_peer_cache();
                        event_receiver = event_receiver.resubscribe();
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }

    async fn run_foriegn_network(&self) {
        self.peer_rpc_tspt
            .set_foreign_peers(Some(Arc::downgrade(&self.foreign_network_client)))
            .await;

        self.foreign_network_client.run().await;
    }

    pub async fn run(&self) -> Result<(), Error> {
        match &self.route_algo_inst {
            RouteAlgoInst::Ospf(route) => self.add_route(route.clone()).await,
            RouteAlgoInst::None => {}
        };

        self.init_packet_process_pipeline().await;
        self.peer_rpc_mgr.run();

        self.start_peer_recv().await;
        core_peer_manager::PeerMaintenanceTasks::new(
            self.peers.clone(),
            self.relay_peer_map.clone(),
            self.recent_traffic.clone(),
            self.foreign_network_client.clone(),
            self.peer_session_store.clone(),
        )
        .spawn_into(&self.tasks)
        .await;
        self.run_credential_gc_routine().await;
        self.run_traffic_metrics_gc_routine().await;

        self.run_foriegn_network().await;

        Ok(())
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_relay_peer_map(&self) -> Arc<RelayPeerMap> {
        self.relay_peer_map.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn get_peer_session_store(&self) -> Arc<PeerSessionStore> {
        self.peer_session_store.clone()
    }

    pub fn my_node_id(&self) -> uuid::Uuid {
        self.global_ctx.get_id()
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_global_ctx_ref(&self) -> &ArcGlobalCtx {
        &self.global_ctx
    }

    pub fn get_nic_channel(&self) -> PacketRecvChan {
        self.nic_channel.clone()
    }

    pub fn get_foreign_network_manager(&self) -> Arc<ForeignNetworkManager> {
        self.foreign_network_manager.clone()
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub async fn get_my_info(&self) -> instance::NodeInfo {
        instance::NodeInfo {
            peer_id: self.my_peer_id,
            ipv4_addr: self
                .global_ctx
                .get_ipv4()
                .map(|x| x.to_string())
                .unwrap_or_default(),
            proxy_cidrs: self
                .global_ctx
                .config
                .get_proxy_cidrs()
                .into_iter()
                .map(|x| match x.mapped_cidr {
                    None => x.cidr.to_string(),
                    Some(mapped) => format!("{}->{}", x.cidr, mapped),
                })
                .collect(),
            hostname: self.global_ctx.get_hostname(),
            stun_info: Some(self.global_ctx.get_stun_info_collector().get_stun_info()),
            inst_id: self.global_ctx.get_id().to_string(),
            listeners: self
                .global_ctx
                .get_running_listeners()
                .iter()
                .map(|x| x.to_string())
                .collect(),
            config: self.global_ctx.config.dump(),
            version: EASYTIER_VERSION.to_string(),
            feature_flag: Some(self.global_ctx.get_feature_flags()),
            ip_list: Some(self.global_ctx.get_ip_collector().collect_ip_addrs().await),
            public_ipv6_addr: self.get_my_public_ipv6_addr().await.map(Into::into),
            ipv6_public_addr_prefix: self
                .global_ctx
                .get_advertised_ipv6_public_addr_prefix()
                .map(|prefix| {
                    cidr::Ipv6Inet::new(prefix.first_address(), prefix.network_length())
                        .unwrap()
                        .into()
                }),
        }
    }

    pub async fn wait(&self) {
        while !self.tasks.lock().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn clear_resources(&self) {
        let mut peer_pipeline = self.peer_packet_process_pipeline.write().await;
        peer_pipeline.clear();
        let mut nic_pipeline = self.nic_packet_process_pipeline.write().await;
        nic_pipeline.clear();

        self.peer_rpc_mgr.rpc_server().registry().unregister_all();
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), Error> {
        core_peer_manager::close_peer_conn(
            self.peers.as_ref(),
            &self.foreign_network_client,
            self.foreign_network_manager.as_ref(),
            peer_id,
            conn_id,
        )
        .await
        .map_err(Error::from)
    }

    pub async fn check_allow_kcp_to_dst(&self, dst_ip: &IpAddr) -> bool {
        self.outbound_packet_router
            .check_allow_kcp_to_dst(dst_ip)
            .await
    }

    pub async fn check_allow_quic_to_dst(&self, dst_ip: &IpAddr) -> bool {
        self.outbound_packet_router
            .check_allow_quic_to_dst(dst_ip)
            .await
    }

    pub async fn update_exit_nodes(&self) {
        let exit_nodes = self.global_ctx.config.get_exit_nodes();
        *self.exit_nodes.write().await = exit_nodes;
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use easytier_core::peers::peer_manager as core_peer_manager;
    use std::{collections::HashMap, fmt::Debug, sync::Arc, time::Duration};

    use quanta::Instant;

    use crate::{
        common::{
            PeerId,
            config::Flags,
            global_ctx::{NetworkIdentity, tests::get_mock_global_ctx},
            stats_manager::{LabelSet, LabelType, MetricName},
        },
        connector::{
            create_connector_by_url, direct::PeerManagerForDirectConnector,
            udp_hole_punch::tests::create_mock_peer_manager_with_mock_stun,
        },
        instance::listeners::create_listener_by_url,
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
            TunnelConnector, TunnelListener,
            common::tests::wait_for_condition,
            filter::{TunnelWithFilter, tests::DropSendTunnelFilter},
            packet_def::{PacketType, ZCPacket},
            ring::create_ring_tunnel_pair,
        },
    };

    use super::PeerManager;

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
        peer_mgr
    }

    fn metric_value(peer_mgr: &PeerManager, metric: MetricName, labels: &LabelSet) -> u64 {
        peer_mgr
            .get_global_ctx()
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
    async fn recent_traffic_skips_direct_peers_and_clears_after_direct_connect() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()));

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (client_ret, server_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, true),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        client_ret.unwrap();
        server_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { peer_mgr_a.has_directly_connected_conn(peer_b_id) }
            },
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move { !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()) }
            },
            Duration::from_secs(5),
        )
        .await;

        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert!(
            !peer_mgr_a.has_recent_traffic(peer_b_id, Instant::now()),
            "directly connected peers should not be tracked as lazy-p2p demand"
        );
    }

    #[tokio::test]
    async fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let peer_mgr_a = create_lazy_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        let peer_b_id = peer_mgr_b.my_peer_id();
        let signal = peer_mgr_a.p2p_demand_notify();

        let initial_version = signal.version();
        peer_mgr_a.mark_recent_traffic(peer_b_id);
        assert_eq!(signal.version(), initial_version + 1);

        tokio::time::sleep(Duration::from_millis(5)).await;
        peer_mgr_a.mark_recent_traffic(peer_b_id);
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

        let result = core_peer_manager::send_msg_internal(
            peer_mgr.peers.as_ref(),
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
        .await;

        assert!(result.is_err());
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficBytesTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert_eq!(
            peer_mgr
                .get_global_ctx()
                .stats_manager()
                .get_metric(MetricName::TrafficPacketsTx, &network_labels)
                .unwrap()
                .value,
            0
        );
        assert!(
            peer_mgr
                .get_global_ctx()
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
                .get_global_ctx()
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

        core_peer_manager::send_msg_internal(
            peer_mgr.peers.as_ref(),
            &peer_mgr.foreign_network_client,
            &peer_mgr.relay_peer_map,
            Some(&peer_mgr.traffic_metrics),
            pkt,
            dst_peer_id,
        )
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
                .get_global_ctx()
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
                .get_global_ctx()
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

        core_peer_manager::send_msg_internal(
            peer_mgr_a.peers.as_ref(),
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
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

        core_peer_manager::send_msg_internal(
            peer_mgr_a.peers.as_ref(),
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
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

        core_peer_manager::send_msg_internal(
            peer_mgr_a.peers.as_ref(),
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_b.my_peer_id(),
        )
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

        core_peer_manager::send_msg_internal(
            peer_mgr_a.peers.as_ref(),
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
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

        core_peer_manager::send_msg_internal(
            peer_mgr_a.peers.as_ref(),
            &peer_mgr_a.foreign_network_client,
            &peer_mgr_a.relay_peer_map,
            Some(&peer_mgr_a.traffic_metrics),
            pkt,
            peer_mgr_c.my_peer_id(),
        )
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
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 2 },
            std::time::Duration::from_secs(5),
        )
        .await;

        drop(peer_mgr_b);

        wait_for_condition(
            || async { peer_mgr_a.get_peer_map().list_peers_with_conn().await.len() == 1 },
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

        let (a_ring, b_ring) = create_ring_tunnel_pair();
        let (a_ret, b_ret) = tokio::join!(
            peer_mgr_a.add_client_tunnel(a_ring, false),
            peer_mgr_b.add_tunnel_as_server(b_ring, true)
        );
        let (peer_b_id, _) = a_ret.unwrap();
        b_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_a = peer_mgr_a.clone();
                async move {
                    if !peer_mgr_a
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_b_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_a.get_peer_map().list_peer_conns(peer_b_id).await
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
                        .get_peer_map()
                        .list_peers_with_conn()
                        .await
                        .contains(&peer_a_id)
                    {
                        return false;
                    }
                    let Some(conns) = peer_mgr_b.get_peer_map().list_peer_conns(peer_a_id).await
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

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
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

        let (c_ring, s_ring) = create_ring_tunnel_pair();
        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(c_ring, false),
            peer_mgr_server.add_tunnel_as_server(s_ring, true)
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

        let (c_ret, s_ret) = tokio::join!(
            peer_mgr_client.add_client_tunnel(a_ring, false),
            peer_mgr_server.add_tunnel_as_server(b_ring, true)
        );
        c_ret.unwrap();
        s_ret.unwrap();

        wait_for_condition(
            || {
                let peer_mgr_client = peer_mgr_client.clone();
                async move {
                    let foreign_peer_map =
                        peer_mgr_client.get_foreign_network_client().get_peer_map();
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
                        .list_foreign_networks()
                        .await;
                    let Some(entry) = foreigns.foreign_networks.get("user") else {
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

    async fn connect_peer_manager_with<C: TunnelConnector + Debug + 'static, L: TunnelListener>(
        client_mgr: Arc<PeerManager>,
        server_mgr: &Arc<PeerManager>,
        mut client: C,
        server: &mut L,
    ) {
        server.listen().await.unwrap();

        tokio::spawn(async move {
            client.set_bind_addrs(vec![]);
            client_mgr.try_direct_connect(client).await.unwrap();
        });

        server_mgr
            .add_client_tunnel(server.accept().await.unwrap(), false)
            .await
            .unwrap();
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
        register_service(&peer_mgr_a.peer_rpc_mgr, "", 0, "hello a");

        let peer_mgr_b = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;

        let peer_mgr_c = create_mock_peer_manager_with_mock_stun(NatType::Unknown).await;
        register_service(&peer_mgr_c.peer_rpc_mgr, "", 0, "hello c");

        let mut listener1 = create_listener_by_url(
            &format!("{}://0.0.0.0:31013", proto1).parse().unwrap(),
            peer_mgr_b.get_global_ctx(),
        )
        .unwrap();
        let connector1 = create_connector_by_url(
            format!("{}://127.0.0.1:31013", proto1).as_str(),
            &peer_mgr_a.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_a.clone(), &peer_mgr_b, connector1, &mut listener1)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        let mut listener2 = create_listener_by_url(
            &format!("{}://0.0.0.0:31014", proto2).parse().unwrap(),
            peer_mgr_c.get_global_ctx(),
        )
        .unwrap();
        let connector2 = create_connector_by_url(
            format!("{}://127.0.0.1:31014", proto2).as_str(),
            &peer_mgr_b.get_global_ctx(),
            crate::tunnel::IpVersion::Both,
        )
        .await
        .unwrap();
        connect_peer_manager_with(peer_mgr_b.clone(), &peer_mgr_c, connector2, &mut listener2)
            .await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let stub = peer_mgr_a
            .peer_rpc_mgr
            .rpc_client()
            .scoped_client::<GreetingClientFactory<RpcController>>(
                peer_mgr_a.my_peer_id,
                peer_mgr_c.my_peer_id,
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
            peer_mgr.run().await.unwrap();
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

        println!("peer_mgr_a: {}", peer_mgr_a.my_peer_id);
        println!("peer_mgr_b: {}", peer_mgr_b.my_peer_id);
        println!("peer_mgr_c: {}", peer_mgr_c.my_peer_id);
        println!("peer_mgr_d: {}", peer_mgr_d.my_peer_id);
        println!("peer_mgr_e: {}", peer_mgr_e.my_peer_id);

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_d.clone()).await;
        connect_peer_manager(peer_mgr_d.clone(), peer_mgr_e.clone()).await;
        connect_peer_manager(peer_mgr_e.clone(), peer_mgr_c.clone()).await;

        // when b's avoid_relay_data is false, a->c should route through b and cost is 2
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));

        // when b's avoid_relay_data is true, a->c should route through d and e, cost is 3
        peer_mgr_b
            .get_global_ctx()
            .set_avoid_relay_data_preference(true);
        tokio::time::sleep(Duration::from_secs(2)).await;
        if wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(3))
            .await
            .is_err()
        {
            panic!(
                "route not appear, a route table: {}, table: {:#?}",
                peer_mgr_a.get_route().dump().await,
                peer_mgr_a.get_route().list_routes().await
            )
        }

        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_d.my_peer_id));

        println!("route table: {:#?}", peer_mgr_a.list_routes().await);

        // drop e, path should go back to through b
        drop(peer_mgr_e);
        wait_route_appear_with_cost(peer_mgr_a.clone(), peer_mgr_c.my_peer_id, Some(2))
            .await
            .unwrap();
        let ret = peer_mgr_a
            .get_route()
            .get_next_hop_with_policy(peer_mgr_c.my_peer_id, NextHopPolicy::LeastCost)
            .await;
        assert_eq!(ret, Some(peer_mgr_b.my_peer_id));
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
            a_mgr_copy.add_client_tunnel(a_ring, false).await.unwrap();
        });
        let b_mgr_copy = peer_mgr_b.clone();
        tokio::spawn(async move {
            b_mgr_copy.add_tunnel_as_server(b_ring, true).await.unwrap();
        });

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
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
            .get_peer_map()
            .list_peer_conns(peer_mgr_b.my_peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();

        peer_mgr_a
            .close_peer_conn(peer_mgr_b.my_peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                let peers = peer_mgr_a.list_peers().await;
                peers.is_empty()
            },
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
        admin.run().await.unwrap();

        let (_cred_id, cred_secret) = admin_ctx.get_credential_manager().generate_credential(
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
        credential.run().await.unwrap();
        let credential_peer_id = credential.my_peer_id();

        connect_peer_manager(credential.clone(), admin.clone()).await;

        wait_for_condition(
            || {
                let admin = admin.clone();
                async move {
                    admin
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
            .foreign_network_client
            .list_public_peers()
            .await[0];
        let conns = peer_mgr_client
            .foreign_network_client
            .get_peer_map()
            .list_peer_conns(peer_id)
            .await;
        assert!(conns.is_some());
        let conn_info = conns.as_ref().unwrap().first().unwrap();
        peer_mgr_client
            .close_peer_conn(peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
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
            .list_foreign_networks()
            .await;
        let client_info = conns.foreign_networks["client"].peers[0].clone();
        let conn_info = client_info.conns[0].clone();
        peer_mgr_server
            .close_peer_conn(client_info.peer_id, &conn_info.conn_id.parse().unwrap())
            .await
            .unwrap();

        wait_for_condition(
            || async {
                peer_mgr_client
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

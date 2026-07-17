use std::time::{Duration, SystemTime};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Context;
use dashmap::DashMap;
use parking_lot::RwLock as SyncRwLock;
use quanta::Instant;
use serde::{Deserialize, Serialize};
use tokio::sync::{
    Mutex, RwLock,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};
use tokio::task::JoinSet;
use url::Url;

use crate::{
    compressor::{Compressor as _, DefaultCompressor},
    config::{P2pPolicyFlags, PeerId, ProxyNetworkConfig},
    magic_dns::{MagicDnsRouteAdvertisement, MagicDnsRouteSnapshot, MagicDnsRouteSource},
    packet::{CompressorAlgo, PacketType, ZCPacket},
    proto::common::{FlagsInConfig, PeerFeatureFlag, StunInfo},
    proto::core_peer::peer::{ListPublicIpv6InfoResponse, PeerConnInfo, Route as CoreRoute},
    runtime_config::CoreRuntimeConfigStore,
    socket::{
        SocketContext,
        dns::{DnsQuery, DnsResolver},
    },
    task::ExternalTaskSignal,
    tunnel::Tunnel,
};

use super::{
    BoxNicPacketFilter, BoxPeerPacketFilter, PacketRecvChan, PacketRecvChanReceiver,
    PeerPacketFilter,
    acl_filter::AclFilter,
    context::{
        ArcPeerContext, CorePeerContext, CorePeerContextAdapters, HostRoutingPolicy,
        NetworkIdentity, PeerContext, PeerCredentialEventSink, PeerEventSink, PeerRelayStateSink,
        PeerRuntimeConfig, PeerRuntimeSnapshot, PeerStunInfoSource,
    },
    credential_manager::{CredentialManager, CredentialStorage},
    encrypt::{Encryptor, NullCipher, create_encryptor, derive_key_128, derive_key_256},
    error::Error,
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::{
        ForeignNetworkEntryInfo, ForeignNetworkInfoProvider, ForeignNetworkManager,
        ForeignNetworkRouteInfoProvider, ForeignNetworkRpcRegistrar,
        peer_map_foreign_network_accessor,
    },
    peer_conn::{PeerConn, PeerConnId},
    peer_map::PeerMap,
    peer_ospf_route::PeerRoute,
    peer_rpc::PeerRpcManagerTransport,
    peer_session::PeerSessionStore,
    public_ipv6::{CorePublicIpv6Runtime, PublicIpv6Runtime},
    recv_packet_from_chan,
    relay_peer_map::RelayPeerMap,
    route_trait::{
        ArcRoute, DisabledRoute, ForeignNetworkRouteInfoMap, NextHopPolicy, Route, RouteInterface,
        RouteInterfaceBox,
    },
    traffic_metrics::{
        InstanceLabelKind, LogicalTrafficMetrics, TrafficKind, TrafficMetricRecorder,
        route_peer_info_instance_id, traffic_kind,
    },
    util::shrink_dashmap,
};
use crate::proto::peer_rpc::{
    ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, GetIpListResponse, PeerIdentityType,
    RouteForeignNetworkInfos, RouteForeignNetworkSummary,
};
use crate::stats_manager::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager};

#[derive(Debug, Clone)]
pub struct PeerSnapshot {
    pub peer_id: PeerId,
    pub default_conn_id: Option<PeerConnId>,
    pub directly_connected_conns: Vec<PeerConnId>,
    pub conns: Vec<PeerConnInfo>,
}

#[derive(Debug, Clone)]
pub struct NodeSnapshot {
    pub peer_id: PeerId,
    pub ipv4_addr: Option<cidr::Ipv4Inet>,
    pub proxy_networks: Vec<ProxyNetworkConfig>,
    pub hostname: String,
    pub stun_info: StunInfo,
    pub instance_id: uuid::Uuid,
    pub listeners: Vec<Url>,
    pub version: String,
    pub feature_flags: PeerFeatureFlag,
    pub ip_list: GetIpListResponse,
    pub public_ipv6_addr: Option<cidr::Ipv6Inet>,
    pub ipv6_public_addr_prefix: Option<cidr::Ipv6Inet>,
}

fn magic_dns_route_advertisement(route: CoreRoute) -> MagicDnsRouteAdvertisement {
    MagicDnsRouteAdvertisement {
        hostname: route.hostname,
        ipv4_addr: route.ipv4_addr,
    }
}

pub(crate) struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<dyn Encryptor>,
    is_secure_mode_enabled: bool,
}

impl RpcTransport {
    pub fn new(
        my_peer_id: PeerId,
        peers: Weak<PeerMap>,
        encryptor: Arc<dyn Encryptor>,
        is_secure_mode_enabled: bool,
    ) -> Arc<Self> {
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        Arc::new(Self {
            my_peer_id,
            peers,
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
            encryptor,
            is_secure_mode_enabled,
        })
    }

    pub fn packet_sender(&self) -> UnboundedSender<ZCPacket> {
        self.peer_rpc_tspt_sender.clone()
    }

    pub async fn set_foreign_peers(&self, foreign_peers: Option<Weak<ForeignNetworkClient>>) {
        *self.foreign_peers.lock().await = foreign_peers;
    }
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()> {
        let peers = self
            .peers
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer map is gone"))?;
        // NOTE: if route info is not exchanged, this will return None. treat it as public server.
        let is_dst_peer_public_server = peers
            .get_route_peer_info(dst_peer_id)
            .await
            .and_then(|x| x.feature_flag.map(|x| x.is_public_server))
            // if dst is directly connected, it's must not public server
            .unwrap_or(!peers.has_peer(dst_peer_id));
        if !is_dst_peer_public_server && !self.is_secure_mode_enabled {
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
        }
        // send to self and this packet will be forwarded in peer_recv loop
        peers.send_msg_directly(msg, self.my_peer_id).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<ZCPacket> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(anyhow::anyhow!("rpc transport is closed"))
        }
    }
}

pub(crate) fn get_next_hop_policy(is_latency_first: bool) -> NextHopPolicy {
    if is_latency_first {
        NextHopPolicy::LeastCost
    } else {
        NextHopPolicy::LeastHop
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RouteAlgoType {
    Ospf,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortablePeerManagerConfig {
    pub snapshot: PeerRuntimeSnapshot,
    pub route_algo: RouteAlgoType,
    pub exit_nodes: Vec<IpAddr>,
    /// Defaults inherited by peer contexts created for foreign networks.
    ///
    /// This is explicit because those contexts participate in the same
    /// handshake as the parent but do not inherit all parent policy flags.
    pub foreign_context_default_flags: FlagsInConfig,
}

impl PortablePeerManagerConfig {
    pub fn new(mut runtime: PeerRuntimeConfig) -> Self {
        let policy = &runtime.core.peer_policy;
        let traffic = &runtime.core.traffic;
        let mut flags = FlagsInConfig::default();
        flags.enable_encryption = policy.encryption_required;
        flags.disable_p2p = !policy.p2p_enabled;
        flags.relay_all_peer_rpc = policy.relay_peer_rpc;
        flags.disable_relay_data = !policy.relay_data;
        flags.latency_first = policy.latency_first;
        flags.data_compress_algo = crate::proto::common::CompressionAlgoPb::None.into();
        flags.mtu = traffic.mtu.map(u32::from).unwrap_or_default();
        flags.instance_recv_bps_limit = traffic.instance_recv_bps_limit.unwrap_or_default();
        flags.foreign_relay_bps_limit = traffic.foreign_relay_bps_limit.unwrap_or_default();
        runtime.feature_flags.disable_p2p = flags.disable_p2p;
        runtime.feature_flags.avoid_relay_data |= flags.disable_relay_data;
        let foreign_context_default_flags = flags.clone();
        Self {
            snapshot: PeerRuntimeSnapshot::new(runtime, flags),
            route_algo: RouteAlgoType::Ospf,
            exit_nodes: Vec::new(),
            foreign_context_default_flags,
        }
    }
}

/// Host capabilities used while composing the core-owned peer runtime.
///
/// Every field is a narrow projection or resource adapter. The peer graph and
/// all of its portable state remain constructed and owned by core.
pub struct PeerManagerHostAdapters {
    pub relay_state_sink: Arc<dyn PeerRelayStateSink>,
    pub event_sink: Arc<dyn PeerEventSink>,
    pub credential_storage: Option<Arc<dyn CredentialStorage>>,
    pub credential_event_sink: Arc<dyn PeerCredentialEventSink>,
}

impl Default for PeerManagerHostAdapters {
    fn default() -> Self {
        Self {
            relay_state_sink: Arc::new(()),
            event_sink: Arc::new(()),
            credential_storage: None,
            credential_event_sink: Arc::new(()),
        }
    }
}

fn validate_portable_routes(routes: &crate::config::RouteConfig) -> anyhow::Result<()> {
    if !routes.advertised_routes.is_empty() {
        anyhow::bail!("portable peer manager does not support advertised routes yet");
    }
    if !routes.foreign_networks.is_empty() {
        anyhow::bail!("portable peer manager does not support foreign networks yet");
    }
    if let Some(prefix) = &routes.ipv4 {
        if !matches!(prefix.address, IpAddr::V4(_)) || prefix.prefix_len > 32 {
            anyhow::bail!("routes.ipv4 must contain a valid IPv4 prefix");
        }
    }
    if let Some(prefix) = &routes.ipv6 {
        if !matches!(prefix.address, IpAddr::V6(_)) || prefix.prefix_len > 128 {
            anyhow::bail!("routes.ipv6 must contain a valid IPv6 prefix");
        }
    }
    for proxy in &routes.proxy_networks {
        for (field, prefix) in [
            ("real", Some(&proxy.real)),
            ("mapped", proxy.mapped.as_ref()),
        ] {
            let Some(prefix) = prefix else {
                continue;
            };
            let IpAddr::V4(address) = prefix.address else {
                anyhow::bail!("proxy network {field} prefix must be IPv4");
            };
            if cidr::Ipv4Cidr::new(address, prefix.prefix_len).is_err() {
                anyhow::bail!("proxy network {field} must be a valid IPv4 network prefix");
            }
        }
    }
    Ok(())
}

pub(crate) enum RouteAlgoInst {
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

impl RouteAlgoInst {
    pub fn new(
        route_algo: RouteAlgoType,
        my_peer_id: PeerId,
        context: ArcPeerContext,
        public_ipv6_runtime: Arc<dyn PublicIpv6Runtime>,
        peer_rpc_mgr: Arc<super::peer_rpc::PeerRpcManager>,
    ) -> Self {
        match route_algo {
            RouteAlgoType::Ospf => RouteAlgoInst::Ospf(PeerRoute::new(
                my_peer_id,
                context,
                public_ipv6_runtime,
                peer_rpc_mgr,
            )),
            RouteAlgoType::None => RouteAlgoInst::None,
        }
    }

    pub fn ospf_route(&self) -> Option<Arc<PeerRoute>> {
        match self {
            RouteAlgoInst::Ospf(route) => Some(route.clone()),
            RouteAlgoInst::None => None,
        }
    }

    pub fn route_arc(&self) -> ArcRoute {
        match self {
            RouteAlgoInst::Ospf(route) => route.clone(),
            RouteAlgoInst::None => Arc::new(DisabledRoute),
        }
    }
}

fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
    network
        .network_secret_digest
        .as_ref()
        .is_none_or(|d| d.iter().all(|b| *b == 0))
}

pub(crate) async fn add_new_peer_conn(
    peer_map: &PeerMap,
    local_identity: &NetworkIdentity,
    local_secure_mode: bool,
    peer_conn: PeerConn,
) -> Result<PeerId, Error> {
    let peer_identity = peer_conn.get_network_identity();
    let conn_info = peer_conn.get_conn_info();
    let peer_secure_mode = !conn_info.noise_remote_static_pubkey.is_empty();

    if local_secure_mode != peer_secure_mode {
        return Err(Error::SecretKeyError(
            "same-network peers must use the same secure mode".to_string(),
        ));
    }

    // For credential nodes, network_secret_digest is either None or all-zeros
    // (all-zeros when received over the wire via handshake).
    // In this case, only compare network_name.
    let my_digest_empty = network_secret_digest_is_empty(local_identity);
    let peer_digest_empty = network_secret_digest_is_empty(&peer_identity);

    let identity_ok = if my_digest_empty || peer_digest_empty {
        // Credential node: only check network_name
        local_identity.network_name == peer_identity.network_name
    } else {
        local_identity == &peer_identity
    };

    if !identity_ok {
        return Err(Error::SecretKeyError(
            "network identity not match".to_string(),
        ));
    }
    let peer_id = peer_conn.get_peer_id();
    peer_map.add_new_peer_conn(peer_conn).await?;
    Ok(peer_id)
}

pub(crate) async fn close_untrusted_credential_peers<F>(
    peer_map: &PeerMap,
    network_name: &str,
    mut is_pubkey_trusted: F,
) where
    F: FnMut(&[u8], &str) -> bool + Send,
{
    for peer_id in peer_map.list_peers() {
        if !matches!(
            peer_map.get_peer_identity_type(peer_id),
            Some(PeerIdentityType::Credential)
        ) {
            continue;
        }
        let Some(peer) = peer_map.get_peer_by_id(peer_id) else {
            continue;
        };
        let Some(pubkey) = peer.get_peer_public_key() else {
            continue;
        };

        if is_pubkey_trusted(&pubkey, network_name) {
            continue;
        }

        tracing::warn!(?peer_id, "closing untrusted credential peer");
        if let Err(e) = peer_map.close_peer(peer_id).await {
            tracing::warn!(?e, ?peer_id, "failed to close untrusted credential peer");
        }
    }
}

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
            let _ = self.nic_channel.send(packet).await;
            None
        } else {
            Some(packet)
        }
    }
}

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

pub(crate) struct PeerPipelineEntry {
    active: Arc<AtomicBool>,
    filter: Arc<SyncRwLock<Option<Arc<dyn PeerPacketFilter + Send + Sync>>>>,
}

pub(crate) struct NicPipelineEntry {
    active: Arc<AtomicBool>,
    filter: Arc<SyncRwLock<Option<Arc<dyn super::NicPacketFilter + Send + Sync>>>>,
}

#[derive(Clone)]
pub(crate) struct PipelineRegistrationGuard {
    active: Arc<AtomicBool>,
    release_filter: Arc<dyn Fn() + Send + Sync>,
}

impl PipelineRegistrationGuard {
    pub fn close(&self) {
        self.active.store(false, Ordering::Release);
        (self.release_filter)();
    }
}

impl Drop for PipelineRegistrationGuard {
    fn drop(&mut self) {
        self.close();
    }
}

fn permanent_peer_pipeline_entry(filter: BoxPeerPacketFilter) -> Arc<PeerPipelineEntry> {
    Arc::new(PeerPipelineEntry {
        active: Arc::new(AtomicBool::new(true)),
        filter: Arc::new(SyncRwLock::new(Some(Arc::from(filter)))),
    })
}

fn permanent_nic_pipeline_entry(filter: BoxNicPacketFilter) -> Arc<NicPipelineEntry> {
    Arc::new(NicPipelineEntry {
        active: Arc::new(AtomicBool::new(true)),
        filter: Arc::new(SyncRwLock::new(Some(Arc::from(filter)))),
    })
}

fn managed_peer_pipeline_entry(
    filter: BoxPeerPacketFilter,
) -> (Arc<PeerPipelineEntry>, PipelineRegistrationGuard) {
    let active = Arc::new(AtomicBool::new(true));
    let filter = Arc::new(SyncRwLock::new(Some(Arc::from(filter))));
    let release_filter = filter.clone();
    (
        Arc::new(PeerPipelineEntry {
            active: active.clone(),
            filter,
        }),
        PipelineRegistrationGuard {
            active,
            release_filter: Arc::new(move || {
                let filter = release_filter.write().take();
                drop(filter);
            }),
        },
    )
}

#[cfg(any(feature = "proxy-packet", test))]
fn managed_nic_pipeline_entry(
    filter: BoxNicPacketFilter,
) -> (Arc<NicPipelineEntry>, PipelineRegistrationGuard) {
    let active = Arc::new(AtomicBool::new(true));
    let filter = Arc::new(SyncRwLock::new(Some(Arc::from(filter))));
    let release_filter = filter.clone();
    (
        Arc::new(NicPipelineEntry {
            active: active.clone(),
            filter,
        }),
        PipelineRegistrationGuard {
            active,
            release_filter: Arc::new(move || {
                let filter = release_filter.write().take();
                drop(filter);
            }),
        },
    )
}

#[cfg(any(feature = "proxy-packet", test))]
async fn remove_managed_nic_pipeline_entry(
    pipeline: &RwLock<Vec<Arc<NicPipelineEntry>>>,
    registration: &PipelineRegistrationGuard,
) {
    registration.close();
    pipeline
        .write()
        .await
        .retain(|entry| !Arc::ptr_eq(&entry.active, &registration.active));
}

async fn init_packet_process_pipeline(
    peer_packet_process_pipeline: &RwLock<Vec<Arc<PeerPipelineEntry>>>,
    nic_channel: PacketRecvChan,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,
) {
    // for tun/tap ip/eth packet.
    peer_packet_process_pipeline
        .write()
        .await
        .push(permanent_peer_pipeline_entry(Box::new(
            NicPacketProcessor { nic_channel },
        )));

    // for peer rpc packet
    peer_packet_process_pipeline
        .write()
        .await
        .push(permanent_peer_pipeline_entry(Box::new(
            PeerRpcPacketProcessor {
                peer_rpc_tspt_sender,
            },
        )));
}

async fn add_route<T>(
    peer_packet_process_pipeline: &RwLock<Vec<Arc<PeerPipelineEntry>>>,
    peers: Arc<PeerMap>,
    foreign_network_client: Arc<ForeignNetworkClient>,
    foreign_network_provider: Arc<dyn ForeignNetworkRouteInfoProvider>,
    my_peer_id: PeerId,
    route: Arc<T>,
) where
    T: Route + PeerPacketFilter + Send + Sync + 'static,
{
    // for route
    peer_packet_process_pipeline
        .write()
        .await
        .push(permanent_peer_pipeline_entry(Box::new(route.clone())));

    let _route_id = route
        .open(peer_manager_route_interface(
            my_peer_id,
            Arc::downgrade(&peers),
            Arc::downgrade(&foreign_network_client),
            Arc::downgrade(&foreign_network_provider),
        ))
        .await
        .unwrap();

    let arc_route: ArcRoute = route;
    peers.add_route(arc_route).await;
}

pub(crate) struct PeerManagerTrafficCounters {
    pub self_tx_packets: CounterHandle,
    pub self_tx_bytes: CounterHandle,
    pub compress_tx_bytes_before: CounterHandle,
    pub compress_tx_bytes_after: CounterHandle,
}

pub struct PeerManagerCore {
    my_peer_id: PeerId,
    tasks: Mutex<JoinSet<()>>,
    packet_recv: Arc<Mutex<Option<PacketRecvChanReceiver>>>,
    peers: Arc<PeerMap>,
    peer_rpc_mgr: Arc<super::peer_rpc::PeerRpcManager>,
    peer_rpc_tspt: Arc<RpcTransport>,
    peer_packet_process_pipeline: Arc<RwLock<Vec<Arc<PeerPipelineEntry>>>>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<Arc<NicPipelineEntry>>>>,
    nic_channel: PacketRecvChan,
    route_algo_inst: RouteAlgoInst,
    foreign_network_client: Arc<ForeignNetworkClient>,
    foreign_network_handler: Arc<dyn ForeignNetworkPacketHandler>,
    foreign_network_provider: Arc<dyn ForeignNetworkRouteInfoProvider>,
    foreign_network_info_provider: Arc<dyn ForeignNetworkInfoProvider>,
    foreign_network_closer: Arc<dyn ForeignPeerConnectionCloser>,
    foreign_network_manager: Arc<ForeignNetworkManager>,
    relay_peer_map: Arc<RelayPeerMap>,
    peer_connection_admission: PeerConnectionAdmission,
    outbound_packet_router: PeerOutboundPacketRouter,
    recent_traffic: RecentTrafficTracker,
    peer_session_store: Arc<PeerSessionStore>,
    encryptor: Arc<dyn Encryptor + 'static>,
    data_compress_algo: CompressorAlgo,
    exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
    acl_filter: Arc<AclFilter>,
    credential_manager: Arc<CredentialManager>,
    context: Arc<CorePeerContext>,
    is_secure_mode_enabled: bool,
    route: ArcRoute,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    stats_manager: Arc<StatsManager>,
    network_name: String,
    counters: PeerManagerTrafficCounters,
    owns_maintenance_tasks: bool,
}

pub(crate) enum AddressResolution {
    IpAddrs(Vec<SocketAddr>),
    NotIpBased,
    Unavailable,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub(crate) trait AddressResolver: Send + Sync {
    async fn resolve_remote(
        &self,
        remote_addr: &Url,
        default_port: Option<u16>,
    ) -> AddressResolution;
}

pub(crate) struct DnsAddressResolver {
    dns: Arc<dyn DnsResolver>,
    context: SocketContext,
}

impl DnsAddressResolver {
    pub fn new(dns: Arc<dyn DnsResolver>) -> Self {
        Self {
            dns,
            context: SocketContext::default(),
        }
    }

    pub fn with_context(mut self, context: SocketContext) -> Self {
        self.context = context;
        self
    }
}

#[async_trait::async_trait]
impl AddressResolver for DnsAddressResolver {
    async fn resolve_remote(
        &self,
        remote_addr: &Url,
        default_port: Option<u16>,
    ) -> AddressResolution {
        if matches!(remote_addr.scheme(), "ring" | "unix") {
            return AddressResolution::NotIpBased;
        }
        let Some(host) = remote_addr.host() else {
            return AddressResolution::Unavailable;
        };
        let Some(port) = remote_addr.port().or(default_port) else {
            return AddressResolution::Unavailable;
        };
        match host {
            url::Host::Ipv4(ip) => {
                AddressResolution::IpAddrs(vec![SocketAddr::new(IpAddr::V4(ip), port)])
            }
            url::Host::Ipv6(ip) => {
                AddressResolution::IpAddrs(vec![SocketAddr::new(IpAddr::V6(ip), port)])
            }
            url::Host::Domain(host) => {
                if let Ok(ip) = host.parse::<IpAddr>() {
                    return AddressResolution::IpAddrs(vec![SocketAddr::new(ip, port)]);
                }
                match self
                    .dns
                    .resolve(DnsQuery::new(host, self.context.clone()))
                    .await
                {
                    Ok(ips) => AddressResolution::IpAddrs(
                        ips.into_iter()
                            .map(|ip| SocketAddr::new(ip, port))
                            .collect(),
                    ),
                    Err(error) => {
                        tracing::debug!(?error, ?remote_addr, "remote address resolution failed");
                        AddressResolution::Unavailable
                    }
                }
            }
        }
    }
}

async fn check_resolved_remote_addr_not_from_virtual_network(
    context: &ArcPeerContext,
    address_resolver: &dyn AddressResolver,
    src: Url,
) -> Result<(), Error> {
    let addrs = match address_resolver.resolve_remote(&src, Some(1)).await {
        AddressResolution::IpAddrs(addrs) => addrs,
        AddressResolution::NotIpBased | AddressResolution::Unavailable => return Ok(()),
    };

    // if no-tun is enabled, the src ip of packet in virtual network is converted to loopback address
    // we already filter out the connection in tcp/quic/kcp proxy so no need check here.
    let Some(addr) = addrs
        .into_iter()
        .find(|addr| !addr.ip().is_loopback() && context.is_ip_in_same_network(&addr.ip()))
    else {
        return Ok(());
    };

    Err(anyhow::anyhow!(
        "tunnel src {} is from the same network (ignore this error please)",
        addr
    )
    .into())
}

impl PeerManagerCore {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        config: PortablePeerManagerConfig,
        runtime_config: CoreRuntimeConfigStore,
        dns: Arc<dyn DnsResolver>,
        dns_context: SocketContext,
        stun_info_source: Arc<dyn PeerStunInfoSource>,
        nic_channel: PacketRecvChan,
        public_ipv6_runtime: Arc<CorePublicIpv6Runtime>,
        host_adapters: PeerManagerHostAdapters,
        foreign_rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
    ) -> anyhow::Result<Self> {
        Self::build(
            config,
            runtime_config,
            dns,
            dns_context,
            Some(stun_info_source),
            nic_channel,
            public_ipv6_runtime,
            host_adapters,
            foreign_rpc_registrar,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        mut config: PortablePeerManagerConfig,
        runtime_config: CoreRuntimeConfigStore,
        dns: Arc<dyn DnsResolver>,
        dns_context: SocketContext,
        stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
        nic_channel: PacketRecvChan,
        public_ipv6_runtime: Arc<CorePublicIpv6Runtime>,
        host_adapters: PeerManagerHostAdapters,
        foreign_rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
    ) -> anyhow::Result<Self> {
        let runtime = &mut config.snapshot.runtime;
        let flags = &config.snapshot.flags;
        let network_name = runtime.network_identity.network_name.clone();
        if network_name.is_empty() {
            anyhow::bail!("network identity name cannot be empty");
        }
        match runtime.core.node.network_name.as_str() {
            "" => runtime.core.node.network_name = network_name.clone(),
            configured if configured != network_name => anyhow::bail!(
                "core node network name {configured:?} does not match identity {network_name:?}"
            ),
            _ => {}
        }
        validate_portable_routes(&runtime.core.routes)?;

        if let (Some(_), Some(expected_digest)) = (
            runtime.network_identity.network_secret.as_ref(),
            runtime.network_identity.network_secret_digest.as_ref(),
        ) {
            let mut identity = runtime.network_identity.clone();
            identity.network_secret_digest = None;
            let derived_digest = identity
                .secret_digest()
                .expect("identity with a secret should derive a digest");
            if &derived_digest != expected_digest {
                anyhow::bail!("network secret does not match the configured digest");
            }
        }
        if runtime.network_identity.network_secret.is_none()
            && runtime
                .network_identity
                .network_secret_digest
                .as_ref()
                .is_some_and(|digest| digest.iter().any(|byte| *byte != 0))
        {
            anyhow::bail!("digest-only local identity requires credential key capabilities");
        }
        let is_secure_mode_enabled = runtime
            .secure_mode
            .as_ref()
            .is_some_and(|secure| secure.enabled);
        let is_credential_peer = runtime.network_identity.network_secret.is_none();
        if is_credential_peer && !is_secure_mode_enabled {
            anyhow::bail!("credential peer identity requires secure mode and a local keypair");
        }
        runtime.feature_flags.is_credential_peer = is_credential_peer;
        if let Some(secure) = runtime.secure_mode.as_ref().filter(|secure| secure.enabled) {
            let private_key = secure.private_key()?;
            let public_key = secure.public_key()?;
            let derived_public = x25519_dalek::PublicKey::from(&private_key);
            if derived_public.as_bytes() != public_key.as_bytes() {
                anyhow::bail!("secure mode public key does not match its private key");
            }
        }
        let data_compress_algo = CompressorAlgo::try_from(flags.data_compress_algo())?;
        if tokio::runtime::Handle::try_current().is_err() {
            anyhow::bail!("portable peer manager construction requires an entered Tokio runtime");
        }

        let my_peer_id = runtime.core.node.peer_id.unwrap_or_else(rand::random);
        runtime.core.node.peer_id = Some(my_peer_id);
        let instance_id = runtime
            .core
            .node
            .instance_id
            .map(uuid::Uuid::from_bytes)
            .unwrap_or_else(uuid::Uuid::new_v4);
        runtime.core.node.instance_id = Some(*instance_id.as_bytes());

        let secret = runtime
            .network_identity
            .network_secret
            .as_deref()
            .unwrap_or_default();
        let encryptor: Arc<dyn Encryptor> = if flags.enable_encryption {
            create_encryptor(
                &flags.encryption_algorithm,
                derive_key_128(secret),
                derive_key_256(secret),
            )
        } else {
            Arc::new(NullCipher)
        };
        runtime.feature_flags.disable_p2p = flags.disable_p2p;
        runtime.feature_flags.need_p2p = flags.need_p2p;
        runtime.feature_flags.avoid_relay_data |= flags.disable_relay_data;
        runtime_config.update_peer(Arc::new(config.snapshot.clone()));
        let PeerManagerHostAdapters {
            relay_state_sink,
            event_sink,
            credential_storage,
            credential_event_sink,
        } = host_adapters;
        let public_ipv6_state = public_ipv6_runtime.clone();
        let public_ipv6_runtime: Arc<dyn PublicIpv6Runtime> = public_ipv6_runtime;
        let context = Arc::new(CorePeerContext::new(
            runtime_config,
            public_ipv6_state,
            CorePeerContextAdapters {
                relay_state_sink,
                stun_info_source,
                event_sink,
                credential_storage,
                credential_event_sink,
            },
        ));
        let address_resolver = Arc::new(DnsAddressResolver::new(dns).with_context(dns_context));

        let mut core = Self::assemble(
            config.route_algo,
            my_peer_id,
            context,
            public_ipv6_runtime,
            nic_channel,
            encryptor,
            is_secure_mode_enabled,
            data_compress_algo,
            config.exit_nodes,
            address_resolver,
            config.foreign_context_default_flags,
            foreign_rpc_registrar,
        );
        core.owns_maintenance_tasks = true;
        Ok(core)
    }

    #[allow(clippy::too_many_arguments)]
    fn assemble(
        route_algo: RouteAlgoType,
        my_peer_id: PeerId,
        core_context: Arc<CorePeerContext>,
        public_ipv6_runtime: Arc<dyn PublicIpv6Runtime>,
        nic_channel: PacketRecvChan,
        encryptor: Arc<dyn Encryptor + 'static>,
        is_secure_mode_enabled: bool,
        data_compress_algo: CompressorAlgo,
        exit_nodes: Vec<IpAddr>,
        address_resolver: Arc<dyn AddressResolver>,
        foreign_context_default_flags: FlagsInConfig,
        foreign_rpc_registrar: Arc<dyn ForeignNetworkRpcRegistrar>,
    ) -> Self {
        let stats_manager = core_context.stats_manager();
        let credential_manager = core_context.credential_manager();
        let acl_filter = Arc::new(AclFilter::new());
        let context: ArcPeerContext = core_context.clone();
        let (packet_send, packet_recv) = super::create_packet_recv_chan();
        let peers = Arc::new(PeerMap::new(
            packet_send.clone(),
            context.clone(),
            my_peer_id,
        ));
        let peer_session_store = Arc::new(PeerSessionStore::new());

        let rpc_tspt = RpcTransport::new(
            my_peer_id,
            Arc::downgrade(&peers),
            encryptor.clone(),
            is_secure_mode_enabled,
        );
        let peer_rpc_mgr = Arc::new(super::peer_rpc::PeerRpcManager::new_with_stats_manager(
            rpc_tspt.clone(),
            stats_manager.clone(),
        ));

        let route_algo_inst = RouteAlgoInst::new(
            route_algo,
            my_peer_id,
            context.clone(),
            public_ipv6_runtime,
            peer_rpc_mgr.clone(),
        );

        let foreign_network_manager = Arc::new(ForeignNetworkManager::new(
            foreign_rpc_registrar,
            core_context.clone(),
            foreign_context_default_flags,
            stats_manager.clone(),
            peer_session_store.clone(),
            packet_send.clone(),
            peer_map_foreign_network_accessor(Arc::downgrade(&peers)),
        ));
        let foreign_network_client = Arc::new(ForeignNetworkClient::new(
            context.clone(),
            packet_send,
            peer_rpc_mgr.clone(),
            my_peer_id,
        ));

        let network_name = context.network_name();
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
        let self_tx_counters = PeerManagerTrafficCounters {
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
            network_name.clone(),
            MetricName::TrafficBytesRx,
            MetricName::TrafficPacketsRx,
            MetricName::TrafficBytesRxByInstance,
            MetricName::TrafficPacketsRxByInstance,
            InstanceLabelKind::From,
        ));
        let traffic_control_rx_metrics = Arc::new(LogicalTrafficMetrics::new(
            stats_manager.clone(),
            network_name.clone(),
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
                    match route_algo_inst.ospf_route() {
                        Some(route) => route
                            .get_peer_info(peer_id)
                            .await
                            .as_ref()
                            .and_then(route_peer_info_instance_id),
                        None => None,
                    }
                }
            },
        ));
        let peer_packet_process_pipeline = Arc::new(RwLock::new(Vec::new()));
        let nic_packet_process_pipeline = Arc::new(RwLock::new(Vec::new()));
        let exit_nodes = Arc::new(RwLock::new(exit_nodes));
        let relay_peer_map = super::relay_peer_map::new_relay_peer_map(
            peers.clone(),
            Some(foreign_network_client.clone()),
            context.clone(),
            my_peer_id,
            peer_session_store.clone(),
        );
        let recent_traffic = RecentTrafficTracker::new(my_peer_id);
        let peer_connection_admission = PeerConnectionAdmission::new(
            my_peer_id,
            context.clone(),
            peers.clone(),
            foreign_network_client.clone(),
            foreign_network_manager.clone(),
            peer_session_store.clone(),
            recent_traffic.clone(),
            address_resolver,
        );
        let route = route_algo_inst.route_arc();
        let outbound_packet_router = PeerOutboundPacketRouter::new(
            my_peer_id,
            context.clone(),
            peers.clone(),
            route.clone(),
            foreign_network_client.clone(),
            relay_peer_map.clone(),
            nic_packet_process_pipeline.clone(),
            encryptor.clone(),
            data_compress_algo,
            exit_nodes.clone(),
            recent_traffic.clone(),
            traffic_metrics.clone(),
            acl_filter.clone(),
            is_secure_mode_enabled,
            self_tx_counters.self_tx_packets.clone(),
            self_tx_counters.self_tx_bytes.clone(),
            self_tx_counters.compress_tx_bytes_before.clone(),
            self_tx_counters.compress_tx_bytes_after.clone(),
        );

        let foreign_network_handler: Arc<dyn ForeignNetworkPacketHandler> =
            foreign_network_manager.clone();
        let foreign_network_provider: Arc<dyn ForeignNetworkRouteInfoProvider> =
            foreign_network_manager.clone();
        let foreign_network_info_provider: Arc<dyn ForeignNetworkInfoProvider> =
            foreign_network_manager.clone();
        let foreign_network_closer: Arc<dyn ForeignPeerConnectionCloser> =
            foreign_network_manager.clone();

        Self {
            my_peer_id,
            tasks: Mutex::new(JoinSet::new()),
            packet_recv: Arc::new(Mutex::new(Some(packet_recv))),
            peers,
            peer_rpc_mgr,
            peer_rpc_tspt: rpc_tspt,
            peer_packet_process_pipeline,
            nic_packet_process_pipeline,
            nic_channel,
            route_algo_inst,
            foreign_network_client,
            foreign_network_handler,
            foreign_network_provider,
            foreign_network_info_provider,
            foreign_network_closer,
            foreign_network_manager: foreign_network_manager.clone(),
            relay_peer_map,
            peer_connection_admission,
            outbound_packet_router,
            recent_traffic,
            peer_session_store,
            encryptor,
            data_compress_algo,
            exit_nodes,
            acl_filter,
            credential_manager,
            context: core_context,
            is_secure_mode_enabled,
            route,
            traffic_metrics,
            stats_manager,
            network_name,
            counters: self_tx_counters,
            owns_maintenance_tasks: false,
        }
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    pub(crate) fn credential_manager(&self) -> Arc<CredentialManager> {
        self.credential_manager.clone()
    }

    pub fn stats_manager(&self) -> Arc<StatsManager> {
        self.stats_manager.clone()
    }

    pub fn can_manage_credentials(&self) -> bool {
        self.context.network_identity().network_secret.is_some()
    }

    pub(crate) fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) {
        self.context
            .set_avoid_relay_data_preference(avoid_relay_data);
    }

    pub fn notify_credential_changed(&self) {
        self.context.issue_credential_changed();
    }

    pub async fn list_peer_snapshots(&self) -> Vec<PeerSnapshot> {
        let foreign_peer_map = self.foreign_network_client.get_peer_map();
        let mut peers = self.peers.list_peers();
        peers.extend(foreign_peer_map.list_peers());

        let mut snapshots = Vec::with_capacity(peers.len());
        for peer_id in peers {
            let conns = if let Some(conns) = self.peers.list_peer_conns(peer_id).await {
                conns
            } else {
                foreign_peer_map
                    .list_peer_conns(peer_id)
                    .await
                    .unwrap_or_default()
            };
            snapshots.push(PeerSnapshot {
                peer_id,
                default_conn_id: self.peers.get_peer_default_conn_id(peer_id).await,
                directly_connected_conns: self
                    .peers
                    .get_directly_connections_by_peer_id(peer_id)
                    .into_iter()
                    .collect(),
                conns,
            });
        }
        snapshots
    }

    pub(crate) fn instance_id(&self) -> uuid::Uuid {
        self.context.instance_id()
    }

    pub(crate) async fn node_snapshot(&self, listeners: Vec<Url>) -> NodeSnapshot {
        NodeSnapshot {
            peer_id: self.my_peer_id,
            ipv4_addr: self.context.ipv4(),
            proxy_networks: self.context.proxy_networks(),
            hostname: self.context.hostname(),
            stun_info: self.context.stun_info(),
            instance_id: self.context.instance_id(),
            listeners,
            version: self.context.easytier_version(),
            feature_flags: self.context.feature_flags(),
            ip_list: GetIpListResponse::default(),
            public_ipv6_addr: self.get_route().get_my_public_ipv6_addr().await,
            ipv6_public_addr_prefix: self.context.advertised_ipv6_public_addr_prefix().map(
                |prefix| {
                    cidr::Ipv6Inet::new(prefix.first_address(), prefix.network_length()).unwrap()
                },
            ),
        }
    }

    pub async fn list_route_snapshots(&self) -> Vec<CoreRoute> {
        self.get_route().list_routes().await
    }

    pub async fn list_public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.get_route().list_public_ipv6_routes().await
    }

    pub async fn public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.get_route().get_my_public_ipv6_addr().await
    }

    pub async fn dump_route(&self) -> String {
        self.get_route().dump().await
    }

    pub async fn local_public_ipv6_info(&self) -> ListPublicIpv6InfoResponse {
        self.get_route().get_local_public_ipv6_info().await
    }

    pub async fn foreign_network_route_infos(&self) -> RouteForeignNetworkInfos {
        self.get_route().list_foreign_network_info().await
    }

    pub async fn list_foreign_network_infos(
        &self,
        include_trusted_keys: bool,
    ) -> std::collections::HashMap<String, ForeignNetworkEntryInfo> {
        self.foreign_network_info_provider
            .list_foreign_network_infos(include_trusted_keys)
            .await
    }

    pub async fn foreign_network_route_summary(&self) -> RouteForeignNetworkSummary {
        self.get_route().get_foreign_network_summary().await
    }

    pub fn acl_stats(&self) -> crate::proto::acl::AclStats {
        self.acl_filter.get_stats()
    }

    pub fn acl_filter(&self) -> Arc<AclFilter> {
        self.acl_filter.clone()
    }

    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    pub fn p2p_policy_flags(&self) -> P2pPolicyFlags {
        let flags = self.context.flags();
        P2pPolicyFlags {
            disable_udp_hole_punching: flags.disable_udp_hole_punching,
            disable_sym_hole_punching: flags.disable_sym_hole_punching,
            disable_upnp: flags.disable_upnp,
            lazy_p2p: flags.lazy_p2p,
            disable_p2p: flags.disable_p2p,
            need_p2p: flags.need_p2p,
        }
    }

    pub fn tcp_hole_punching_disabled(&self) -> bool {
        self.context.flags().disable_tcp_hole_punching
    }

    pub fn get_peer_map(&self) -> Arc<PeerMap> {
        self.peers.clone()
    }

    pub fn get_relay_peer_map(&self) -> Arc<RelayPeerMap> {
        self.relay_peer_map.clone()
    }

    pub fn get_peer_rpc_mgr(&self) -> Arc<super::peer_rpc::PeerRpcManager> {
        self.peer_rpc_mgr.clone()
    }

    pub fn get_peer_session_store(&self) -> Arc<PeerSessionStore> {
        self.peer_session_store.clone()
    }

    pub fn get_nic_channel(&self) -> PacketRecvChan {
        self.nic_channel.clone()
    }

    pub(crate) fn is_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.context.is_ip_local_virtual_ip(ip)
    }

    pub fn get_foreign_network_client(&self) -> Arc<ForeignNetworkClient> {
        self.foreign_network_client.clone()
    }

    pub async fn is_easytier_managed_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        if self.context.is_ip_local_ipv6(ip) {
            return true;
        }
        self.route
            .list_public_ipv6_routes()
            .await
            .iter()
            .any(|route| route.address() == *ip)
    }

    pub fn traffic_metrics(&self) -> Arc<TrafficMetricRecorder> {
        self.traffic_metrics.clone()
    }

    pub fn get_route(&self) -> ArcRoute {
        self.route.clone()
    }

    pub fn mark_recent_traffic(&self, dst_peer_id: PeerId) {
        let flags = self.context.flags();
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

    pub fn gc_recent_traffic(&self) {
        self.recent_traffic.gc(Instant::now(), |peer_id| {
            self.has_directly_connected_conn(peer_id)
        });
    }

    pub fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.peer_connection_admission
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
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
    }

    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        self.peer_connection_admission
            .add_tunnel_as_server(tunnel, is_directly_connected)
            .await
    }

    pub async fn add_packet_process_pipeline(&self, pipeline: BoxPeerPacketFilter) {
        // newest pipeline will be executed first
        self.peer_packet_process_pipeline
            .write()
            .await
            .push(permanent_peer_pipeline_entry(pipeline));
    }

    pub async fn add_nic_packet_process_pipeline(&self, pipeline: BoxNicPacketFilter) {
        // newest pipeline will be executed first
        self.nic_packet_process_pipeline
            .write()
            .await
            .push(permanent_nic_pipeline_entry(pipeline));
    }

    pub(crate) async fn add_managed_packet_process_pipeline(
        &self,
        pipeline: BoxPeerPacketFilter,
    ) -> PipelineRegistrationGuard {
        let (entry, guard) = managed_peer_pipeline_entry(pipeline);
        let mut pipelines = self.peer_packet_process_pipeline.write().await;
        pipelines.retain(|pipeline| pipeline.active.load(Ordering::Acquire));
        pipelines.push(entry);
        guard
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) async fn add_managed_nic_packet_process_pipeline(
        &self,
        pipeline: BoxNicPacketFilter,
    ) -> PipelineRegistrationGuard {
        let (entry, guard) = managed_nic_pipeline_entry(pipeline);
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        pipelines.retain(|pipeline| pipeline.active.load(Ordering::Acquire));
        pipelines.push(entry);
        guard
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) async fn remove_managed_nic_packet_process_pipeline(
        &self,
        registration: &PipelineRegistrationGuard,
    ) {
        remove_managed_nic_pipeline_entry(&self.nic_packet_process_pipeline, registration).await;
    }

    pub async fn add_route<T>(&self, route: Arc<T>)
    where
        T: Route + PeerPacketFilter + Send + Sync + 'static,
    {
        add_route(
            self.peer_packet_process_pipeline.as_ref(),
            self.peers.clone(),
            self.foreign_network_client.clone(),
            self.foreign_network_provider.clone(),
            self.my_peer_id,
            route,
        )
        .await;
    }

    pub async fn remove_nic_packet_process_pipeline(&self, id: String) -> Result<(), Error> {
        let mut pipelines = self.nic_packet_process_pipeline.write().await;
        if let Some(pos) = pipelines.iter().position(|pipeline| {
            let filter = pipeline.filter.read().clone();
            filter.is_some_and(|filter| filter.id() == id)
        }) {
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

    pub async fn update_exit_nodes(&self, exit_nodes: Vec<IpAddr>) {
        *self.exit_nodes.write().await = exit_nodes;
    }

    pub(crate) fn reload_acl(&self, acl: Option<&crate::proto::acl::Acl>) {
        // ACL rule effects are staged separately from configuration publication.
        // Keep the submitted group snapshot unchanged so CoreInstance can detect
        // the group change and refresh route trust state when the complete
        // runtime configuration is published.
        self.acl_filter.reload_rules(acl);
    }

    pub async fn wait(&self) {
        while !self.tasks.lock().await.is_empty() {
            crate::runtime_time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub(crate) async fn stop(&self) {
        let mut tasks = {
            let mut task_slot = self.tasks.lock().await;
            std::mem::replace(&mut *task_slot, JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        self.foreign_network_manager.stop().await;
        self.route.close().await;
        self.peer_rpc_mgr.stop().await;
        self.context.stop().await;
        if self.owns_maintenance_tasks {
            self.stats_manager.stop_cleanup_task().await;
            self.acl_filter.stop_cleanup_task().await;
        }
    }

    pub(crate) async fn clear_resources(&self) {
        self.stop().await;
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
        close_peer_conn(
            self.peers.as_ref(),
            &self.foreign_network_client,
            self.foreign_network_closer.as_ref(),
            peer_id,
            conn_id,
        )
        .await
    }

    async fn start_peer_recv(&self) {
        let packet_recv = self.packet_recv.lock().await.take().unwrap();
        let is_credential_node =
            self.context.network_identity().network_secret.is_none() && self.is_secure_mode_enabled;
        let router = PeerPacketRouter::new(
            packet_recv,
            self.my_peer_id,
            self.peers.clone(),
            self.peer_packet_process_pipeline.clone(),
            self.foreign_network_client.clone(),
            self.relay_peer_map.clone(),
            self.foreign_network_handler.clone(),
            self.encryptor.clone(),
            self.data_compress_algo,
            self.acl_filter.clone(),
            self.context.clone(),
            self.is_secure_mode_enabled,
            self.route.clone(),
            is_credential_node,
            self.traffic_metrics.clone(),
            self.stats_manager.clone(),
            self.network_name.clone(),
            self.counters.self_tx_packets.clone(),
            self.counters.self_tx_bytes.clone(),
            self.counters.compress_tx_bytes_before.clone(),
            self.counters.compress_tx_bytes_after.clone(),
        );

        self.tasks.lock().await.spawn(router.run());
    }

    async fn run_foreign_network(&self) {
        self.peer_rpc_tspt
            .set_foreign_peers(Some(Arc::downgrade(&self.foreign_network_client)))
            .await;

        self.foreign_network_client.run().await;
    }

    pub(crate) async fn run(&self) -> Result<(), Error> {
        self.stats_manager.start_cleanup_task();

        if let Some(route) = self.route_algo_inst.ospf_route() {
            self.add_route(route).await;
        }

        init_packet_process_pipeline(
            self.peer_packet_process_pipeline.as_ref(),
            self.nic_channel.clone(),
            self.peer_rpc_tspt.packet_sender(),
        )
        .await;
        self.peer_rpc_mgr.run();

        self.start_peer_recv().await;
        PeerMaintenanceTasks::new(
            self.peers.clone(),
            self.relay_peer_map.clone(),
            self.recent_traffic.clone(),
            self.foreign_network_client.clone(),
            self.peer_session_store.clone(),
            self.context.clone(),
            self.traffic_metrics.clone(),
        )
        .spawn_into(&self.tasks)
        .await;

        self.run_foreign_network().await;

        Ok(())
    }
}

#[async_trait::async_trait]
impl MagicDnsRouteSource for PeerManagerCore {
    async fn snapshot(&self) -> MagicDnsRouteSnapshot {
        let revision = self.get_route().get_peer_info_last_update_time().await;
        let mut routes = self
            .list_route_snapshots()
            .await
            .into_iter()
            .map(magic_dns_route_advertisement)
            .collect::<Vec<_>>();
        routes.push(MagicDnsRouteAdvertisement {
            hostname: self.context.hostname(),
            ipv4_addr: self.context.ipv4().map(Into::into),
        });
        MagicDnsRouteSnapshot {
            revision,
            routes,
            zone: self.context.flags().tld_dns_zone,
        }
    }

    async fn revision(&self) -> Instant {
        self.get_route().get_peer_info_last_update_time().await
    }
}

#[async_trait::async_trait]
impl crate::hole_punch::udp::UdpHolePunchTunnelSink for PeerManagerCore {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_client_tunnel(self, tunnel, false)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_tunnel_as_server(self, tunnel, false)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait::async_trait]
impl crate::hole_punch::tcp::TcpHolePunchTunnelSink for PeerManagerCore {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_client_tunnel(self, tunnel, false)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        PeerManagerCore::add_tunnel_as_server(self, tunnel, false)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub(crate) trait ForeignPeerConnectionCloser: Send + Sync {
    async fn close_peer_conn(&self, peer_id: PeerId, conn_id: &PeerConnId) -> Result<(), Error>;
}

pub(crate) async fn close_peer_conn(
    peers: &PeerMap,
    foreign_network_client: &ForeignNetworkClient,
    foreign_network_manager: &(dyn ForeignPeerConnectionCloser + Send + Sync),
    peer_id: PeerId,
    conn_id: &PeerConnId,
) -> Result<(), Error> {
    let ret = peers.close_peer_conn(peer_id, conn_id).await;
    tracing::info!("close_peer_conn in peer map: {:?}", ret);
    if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
        return ret;
    }

    let ret = foreign_network_client
        .get_peer_map()
        .close_peer_conn(peer_id, conn_id)
        .await;
    tracing::info!("close_peer_conn in foreign network client: {:?}", ret);
    if ret.is_ok() || !matches!(ret.as_ref().unwrap_err(), Error::NotFound) {
        return ret;
    }

    let ret = foreign_network_manager
        .close_peer_conn(peer_id, conn_id)
        .await;
    tracing::info!("close_peer_conn in foreign network manager done: {:?}", ret);
    ret
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub(crate) trait ForeignNetworkConnectionAdmission: Send + Sync {
    fn allow_client_foreign_network(&self) -> bool {
        true
    }

    fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId>;

    fn is_existing_credential_pubkey_trusted(
        &self,
        network_name: &str,
        remote_static_pubkey: &[u8],
    ) -> bool;

    async fn add_peer_conn(&self, peer_conn: PeerConn) -> Result<(), Error>;
}

pub(crate) struct PeerConnectionAdmission {
    my_peer_id: PeerId,
    context: ArcPeerContext,
    peers: Arc<PeerMap>,
    foreign_network_client: Arc<ForeignNetworkClient>,
    foreign_network_admission: Arc<dyn ForeignNetworkConnectionAdmission>,
    peer_session_store: Arc<PeerSessionStore>,
    recent_traffic: RecentTrafficTracker,
    reserved_my_peer_id_map: DashMap<String, PeerId>,
    address_resolver: Arc<dyn AddressResolver>,
}

impl PeerConnectionAdmission {
    pub fn new(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        peers: Arc<PeerMap>,
        foreign_network_client: Arc<ForeignNetworkClient>,
        foreign_network_admission: Arc<dyn ForeignNetworkConnectionAdmission>,
        peer_session_store: Arc<PeerSessionStore>,
        recent_traffic: RecentTrafficTracker,
        address_resolver: Arc<dyn AddressResolver>,
    ) -> Self {
        Self {
            my_peer_id,
            context,
            peers,
            foreign_network_client,
            foreign_network_admission,
            peer_session_store,
            recent_traffic,
            reserved_my_peer_id_map: DashMap::new(),
            address_resolver,
        }
    }

    pub async fn add_client_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(PeerId, PeerConnId), Error> {
        self.add_client_tunnel_with_peer_id_hint(tunnel, is_directly_connected, None)
            .await
    }

    pub async fn add_client_tunnel_with_peer_id_hint(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
        peer_id_hint: Option<PeerId>,
    ) -> Result<(PeerId, PeerConnId), Error> {
        let mut peer = PeerConn::new_with_peer_id_hint(
            self.my_peer_id,
            self.context.clone(),
            tunnel,
            peer_id_hint,
            self.peer_session_store.clone(),
        );
        peer.set_is_hole_punched(!is_directly_connected);
        peer.do_handshake_as_client().await?;
        let conn_id = peer.get_conn_id();
        let peer_id = peer.get_peer_id();
        let local_identity = self.context.network_identity();
        if peer.get_network_identity().network_name == local_identity.network_name {
            let local_secure_mode = self
                .context
                .secure_mode()
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            let peer_id = add_new_peer_conn(
                self.peers.as_ref(),
                &local_identity,
                local_secure_mode,
                peer,
            )
            .await?;
            self.recent_traffic.clear(peer_id);
        } else {
            if !self
                .foreign_network_admission
                .allow_client_foreign_network()
            {
                return Err(anyhow::anyhow!(
                    "foreign network client connections are disabled for this core instance"
                )
                .into());
            }
            self.foreign_network_client.add_new_peer_conn(peer).await?;
        }
        Ok((peer_id, conn_id))
    }

    fn remote_addr_from_tunnel(tunnel: &dyn Tunnel) -> Result<Url, Error> {
        let Some(tunnel_info) = tunnel.info() else {
            return Err(anyhow::anyhow!("tunnel info is not set").into());
        };
        let Some(src) = tunnel_info.remote_addr.map(Url::from) else {
            return Err(anyhow::anyhow!("tunnel info remote addr is not set").into());
        };
        Ok(src)
    }

    async fn check_remote_addr_not_from_virtual_network(&self, src: Url) -> Result<(), Error> {
        tracing::info!("check remote addr not from virtual network");
        check_resolved_remote_addr_not_from_virtual_network(
            &self.context,
            self.address_resolver.as_ref(),
            src,
        )
        .await
    }

    fn release_reserved_peer_id(&self, network_name: &str) {
        self.reserved_my_peer_id_map.remove(network_name);
        shrink_dashmap(&self.reserved_my_peer_id_map, None);
    }

    #[tracing::instrument(ret, skip(self, tunnel))]
    pub async fn add_tunnel_as_server(
        &self,
        tunnel: Box<dyn Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(), Error> {
        tracing::info!("add tunnel as server start");
        let remote_addr = Self::remote_addr_from_tunnel(&*tunnel)?;
        self.check_remote_addr_not_from_virtual_network(remote_addr)
            .await?;

        let mut conn = PeerConn::new(
            self.my_peer_id,
            self.context.clone(),
            tunnel,
            self.peer_session_store.clone(),
        );
        let mut reserved_peer_id_network_name = None;
        let handshake_ret = conn
            .do_handshake_as_server_ext(|peer, network_name: &str| {
                if network_name == self.context.network_identity().network_name {
                    return Ok(());
                }

                let mut peer_id = self
                    .foreign_network_admission
                    .get_network_peer_id(network_name);
                if peer_id.is_none() {
                    reserved_peer_id_network_name = Some(network_name.to_string());
                    peer_id = Some(
                        *self
                            .reserved_my_peer_id_map
                            .entry(network_name.to_string())
                            .or_insert_with(rand::random::<PeerId>)
                            .value(),
                    );
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
            return Err(err);
        }

        let peer_identity = conn.get_network_identity();
        let peer_network_name = peer_identity.network_name.clone();
        let local_identity = self.context.network_identity();
        let is_local_network = peer_network_name == local_identity.network_name;
        let trusted_foreign_credential =
            matches!(conn.get_peer_identity_type(), PeerIdentityType::Credential)
                && self
                    .foreign_network_admission
                    .is_existing_credential_pubkey_trusted(
                        &peer_network_name,
                        &conn.get_conn_info().noise_remote_static_pubkey,
                    );
        let foreign_network_allowed =
            conn.matches_local_network_secret() || trusted_foreign_credential;

        if !is_local_network && self.context.flags().private_mode && !foreign_network_allowed {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(Error::SecretKeyError(
                "private mode is turned on, foreign network secret mismatch".to_string(),
            ));
        }

        conn.set_is_hole_punched(!is_directly_connected);

        let add_peer_ret = if is_local_network {
            let local_secure_mode = self
                .context
                .secure_mode()
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false);
            match add_new_peer_conn(
                self.peers.as_ref(),
                &local_identity,
                local_secure_mode,
                conn,
            )
            .await
            {
                Ok(peer_id) => {
                    self.recent_traffic.clear(peer_id);
                    Ok(())
                }
                Err(err) => Err(err),
            }
        } else {
            self.foreign_network_admission.add_peer_conn(conn).await
        };

        if let Err(err) = add_peer_ret {
            self.release_reserved_peer_id(&peer_network_name);
            return Err(err);
        }

        self.release_reserved_peer_id(&peer_network_name);

        tracing::info!("add tunnel as server done");
        Ok(())
    }
}

// Keep lazy-p2p demand alive across the 5s task rescan interval and a full on-demand
// connect attempt, without retaining extra per-task state in the hot path.
pub(crate) const RECENT_HAVE_TRAFFIC_TTL: Duration = Duration::from_secs(30);

pub(crate) fn should_mark_recent_traffic_for_fanout(total_dst_peers: usize) -> bool {
    total_dst_peers <= 1
}

fn gc_recent_traffic_entries<F>(
    recent_have_traffic: &DashMap<PeerId, Instant>,
    now: Instant,
    mut has_directly_connected_conn: F,
) where
    F: FnMut(PeerId) -> bool,
{
    let mut to_remove = Vec::new();
    for entry in recent_have_traffic.iter() {
        let peer_id = *entry.key();
        let expired = now.saturating_duration_since(*entry.value()) > RECENT_HAVE_TRAFFIC_TTL;
        if expired || has_directly_connected_conn(peer_id) {
            to_remove.push(peer_id);
        }
    }

    if !to_remove.is_empty() {
        for peer_id in to_remove {
            recent_have_traffic.remove(&peer_id);
        }
        shrink_dashmap(recent_have_traffic, None);
    }
}

#[derive(Clone)]
pub(crate) struct RecentTrafficTracker {
    my_peer_id: PeerId,
    recent_have_traffic: Arc<DashMap<PeerId, Instant>>,
    p2p_demand_notify: Arc<ExternalTaskSignal>,
}

impl RecentTrafficTracker {
    pub fn new(my_peer_id: PeerId) -> Self {
        Self {
            my_peer_id,
            recent_have_traffic: Arc::new(DashMap::new()),
            p2p_demand_notify: Arc::new(ExternalTaskSignal::new()),
        }
    }

    pub fn mark<F>(
        &self,
        dst_peer_id: PeerId,
        disable_p2p: bool,
        lazy_p2p: bool,
        mut has_directly_connected_conn: F,
    ) where
        F: FnMut(PeerId) -> bool,
    {
        if dst_peer_id == self.my_peer_id {
            return;
        }

        if disable_p2p || !lazy_p2p || has_directly_connected_conn(dst_peer_id) {
            return;
        }

        let now = Instant::now();
        if let Some(mut last_seen) = self.recent_have_traffic.get_mut(&dst_peer_id) {
            let should_notify = now.saturating_duration_since(*last_seen) > RECENT_HAVE_TRAFFIC_TTL;
            *last_seen = now;
            if !should_notify {
                return;
            }
        } else {
            self.recent_have_traffic.insert(dst_peer_id, now);
        }
        self.p2p_demand_notify.notify();
    }

    pub fn has<F>(&self, peer_id: PeerId, now: Instant, mut has_directly_connected_conn: F) -> bool
    where
        F: FnMut(PeerId) -> bool,
    {
        if has_directly_connected_conn(peer_id) {
            return false;
        }

        self.recent_have_traffic
            .get(&peer_id)
            .map(|last_seen| now.saturating_duration_since(*last_seen) <= RECENT_HAVE_TRAFFIC_TTL)
            .unwrap_or(false)
    }

    pub fn clear(&self, peer_id: PeerId) {
        self.recent_have_traffic.remove(&peer_id);
    }

    pub fn gc<F>(&self, now: Instant, has_directly_connected_conn: F)
    where
        F: FnMut(PeerId) -> bool,
    {
        gc_recent_traffic_entries(
            self.recent_have_traffic.as_ref(),
            now,
            has_directly_connected_conn,
        );
    }

    pub fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        self.p2p_demand_notify.clone()
    }
}

pub(crate) struct PeerMaintenanceTasks {
    peer_map: Arc<PeerMap>,
    relay_peer_map: Arc<RelayPeerMap>,
    recent_traffic: RecentTrafficTracker,
    foreign_network_client: Arc<ForeignNetworkClient>,
    peer_session_store: Arc<PeerSessionStore>,
    context: ArcPeerContext,
    traffic_metrics: Arc<TrafficMetricRecorder>,
}

impl PeerMaintenanceTasks {
    pub fn new(
        peer_map: Arc<PeerMap>,
        relay_peer_map: Arc<RelayPeerMap>,
        recent_traffic: RecentTrafficTracker,
        foreign_network_client: Arc<ForeignNetworkClient>,
        peer_session_store: Arc<PeerSessionStore>,
        context: ArcPeerContext,
        traffic_metrics: Arc<TrafficMetricRecorder>,
    ) -> Self {
        Self {
            peer_map,
            relay_peer_map,
            recent_traffic,
            foreign_network_client,
            peer_session_store,
            context,
            traffic_metrics,
        }
    }

    pub async fn spawn_into(self, tasks: &Mutex<JoinSet<()>>) {
        self.spawn_clean_peer_without_conn_routine(tasks).await;
        self.spawn_relay_session_gc_routine(tasks).await;
        self.spawn_recent_traffic_gc_routine(tasks).await;
        self.spawn_peer_session_gc_routine(tasks).await;
        self.spawn_credential_gc_routine(tasks).await;
        self.spawn_traffic_metrics_gc_routine(tasks).await;
    }

    async fn spawn_clean_peer_without_conn_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let peer_map = self.peer_map.clone();
        tasks.lock().await.spawn(async move {
            loop {
                peer_map.clean_peer_without_conn().await;
                crate::runtime_time::sleep(std::time::Duration::from_secs(3)).await;
            }
        });
    }

    async fn spawn_relay_session_gc_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let relay_peer_map = self.relay_peer_map.clone();
        tasks.lock().await.spawn(async move {
            loop {
                relay_peer_map.evict_idle_sessions(std::time::Duration::from_secs(60));
                crate::runtime_time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn spawn_recent_traffic_gc_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let recent_traffic = self.recent_traffic.clone();
        let peers = self.peer_map.clone();
        let foreign_network_client = self.foreign_network_client.clone();
        tasks.lock().await.spawn(async move {
            loop {
                recent_traffic.gc(Instant::now(), |peer_id| {
                    if let Some(peer) = peers.get_peer_by_id(peer_id) {
                        peer.has_directly_connected_conn()
                    } else {
                        foreign_network_client.get_peer_map().has_peer(peer_id)
                    }
                });
                crate::runtime_time::sleep(std::time::Duration::from_secs(30)).await;
            }
        });
    }

    async fn spawn_peer_session_gc_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let peer_session_store = self.peer_session_store.clone();
        tasks.lock().await.spawn(async move {
            loop {
                crate::runtime_time::sleep(std::time::Duration::from_secs(60)).await;
                peer_session_store.evict_unused_sessions();
            }
        });
    }

    async fn spawn_credential_gc_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let context = self.context.clone();
        let peer_map = self.peer_map.clone();
        tasks.lock().await.spawn(async move {
            loop {
                if context.network_identity().network_secret.is_some() {
                    if context.remove_expired_credentials() {
                        context.issue_credential_changed();
                    }

                    let network_name = context.network_name();
                    close_untrusted_credential_peers(
                        peer_map.as_ref(),
                        &network_name,
                        |pubkey, network_name| context.is_pubkey_trusted(pubkey, network_name),
                    )
                    .await;
                }
                crate::runtime_time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    async fn spawn_traffic_metrics_gc_routine(&self, tasks: &Mutex<JoinSet<()>>) {
        let Some(mut event_receiver) = self.context.subscribe_peer_events() else {
            return;
        };
        let context = self.context.clone();
        let traffic_metrics = self.traffic_metrics.clone();
        tasks.lock().await.spawn(async move {
            loop {
                match event_receiver.recv().await {
                    Ok(super::context::PeerContextEvent::PeerRemoved(peer_id)) => {
                        traffic_metrics.remove_peer(peer_id);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                        tracing::warn!(
                            skipped,
                            "traffic metrics GC receiver lagged; clearing peer cache to avoid stale metric attribution"
                        );
                        traffic_metrics.clear_peer_cache();
                        let Some(new_receiver) = context.subscribe_peer_events() else {
                            break;
                        };
                        event_receiver = new_receiver;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

pub(crate) async fn try_compress_and_encrypt(
    compress_algo: CompressorAlgo,
    encryptor: &Arc<dyn Encryptor + 'static>,
    msg: &mut ZCPacket,
    secure_mode_enabled: bool,
) -> Result<(), Error> {
    let compressor = DefaultCompressor {};
    compressor
        .compress(msg, compress_algo)
        .await
        .with_context(|| "compress failed")?;
    if !secure_mode_enabled {
        encryptor.encrypt(msg).with_context(|| "encrypt failed")?;
    }
    Ok(())
}

struct PeerOutboundPacketRouterCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
}

pub(crate) struct PeerOutboundPacketRouter {
    my_peer_id: PeerId,
    context: ArcPeerContext,
    host_routing: HostRoutingPolicy,
    peers: Arc<PeerMap>,
    route: ArcRoute,
    foreign_network_client: Arc<ForeignNetworkClient>,
    relay_peer_map: Arc<RelayPeerMap>,
    nic_packet_process_pipeline: Arc<RwLock<Vec<Arc<NicPipelineEntry>>>>,
    encryptor: Arc<dyn Encryptor>,
    data_compress_algo: CompressorAlgo,
    exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
    recent_traffic: RecentTrafficTracker,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    acl_filter: Arc<AclFilter>,
    is_secure_mode_enabled: bool,
    counters: PeerOutboundPacketRouterCounters,
}

impl PeerOutboundPacketRouter {
    #[allow(clippy::too_many_arguments)]
    fn new(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        peers: Arc<PeerMap>,
        route: ArcRoute,
        foreign_network_client: Arc<ForeignNetworkClient>,
        relay_peer_map: Arc<RelayPeerMap>,
        nic_packet_process_pipeline: Arc<RwLock<Vec<Arc<NicPipelineEntry>>>>,
        encryptor: Arc<dyn Encryptor>,
        data_compress_algo: CompressorAlgo,
        exit_nodes: Arc<RwLock<Vec<IpAddr>>>,
        recent_traffic: RecentTrafficTracker,
        traffic_metrics: Arc<TrafficMetricRecorder>,
        acl_filter: Arc<AclFilter>,
        is_secure_mode_enabled: bool,
        self_tx_packets: CounterHandle,
        self_tx_bytes: CounterHandle,
        compress_tx_bytes_before: CounterHandle,
        compress_tx_bytes_after: CounterHandle,
    ) -> Self {
        let host_routing = context.host_routing_policy();
        Self {
            my_peer_id,
            context,
            host_routing,
            peers,
            route,
            foreign_network_client,
            relay_peer_map,
            nic_packet_process_pipeline,
            encryptor,
            data_compress_algo,
            exit_nodes,
            recent_traffic,
            traffic_metrics,
            acl_filter,
            is_secure_mode_enabled,
            counters: PeerOutboundPacketRouterCounters {
                self_tx_packets,
                self_tx_bytes,
                compress_tx_bytes_before,
                compress_tx_bytes_after,
            },
        }
    }

    fn has_directly_connected_conn(&self, peer_id: PeerId) -> bool {
        if let Some(peer) = self.peers.get_peer_by_id(peer_id) {
            peer.has_directly_connected_conn()
        } else {
            self.foreign_network_client.get_peer_map().has_peer(peer_id)
        }
    }

    fn mark_recent_traffic(&self, dst_peer_id: PeerId) {
        let flags = self.context.flags();
        self.recent_traffic
            .mark(dst_peer_id, flags.disable_p2p, flags.lazy_p2p, |peer_id| {
                self.has_directly_connected_conn(peer_id)
            });
    }

    async fn run_nic_packet_process_pipeline(&self, data: &mut ZCPacket) -> bool {
        // Enforce ACL for outbound (NIC-originated) packets. If ACL denies, stop processing.
        if !self.acl_filter.process_packet_with_acl(
            data,
            false,
            None,
            |_| false,
            self.route.as_ref(),
        ) {
            return false;
        }

        for pipeline in self.nic_packet_process_pipeline.read().await.iter().rev() {
            if !pipeline.active.load(Ordering::Acquire) {
                continue;
            }
            let filter = pipeline.filter.read().clone();
            if let Some(filter) = filter {
                let _ = filter.try_process_packet_from_nic(data).await;
            }
        }

        true
    }

    fn check_p2p_only_before_send(&self, dst_peer_id: PeerId) -> Result<(), Error> {
        if self.context.p2p_only() && !self.peers.has_peer(dst_peer_id) {
            return Err(Error::RouteError(None));
        }
        Ok(())
    }

    async fn check_allow_wrapped_proxy_to_dst(
        &self,
        dst_ip: &IpAddr,
        dst_allows_input: impl Fn(crate::proto::common::PeerFeatureFlag) -> bool,
        next_hop_disables_relay: impl Fn(crate::proto::common::PeerFeatureFlag) -> bool,
    ) -> bool {
        let Some(dst_peer_id) = self.route.get_peer_id_by_ip(dst_ip).await else {
            return false;
        };
        let Some(peer_info) = self.route.get_peer_info(dst_peer_id).await else {
            return false;
        };

        if !peer_info
            .feature_flag
            .map(dst_allows_input)
            .unwrap_or(false)
        {
            return false;
        }

        let next_hop_policy = get_next_hop_policy(self.context.flags().latency_first);
        let Some(next_hop_id) = self
            .route
            .get_next_hop_with_policy(dst_peer_id, next_hop_policy)
            .await
        else {
            return false;
        };

        if next_hop_id == dst_peer_id {
            return true;
        }

        let Some(next_hop_info) = self.route.get_peer_info(next_hop_id).await else {
            return false;
        };

        !next_hop_info
            .feature_flag
            .map(next_hop_disables_relay)
            .unwrap_or(false)
    }

    pub async fn check_allow_kcp_to_dst(&self, dst_ip: &IpAddr) -> bool {
        self.check_allow_wrapped_proxy_to_dst(
            dst_ip,
            |feature_flag| feature_flag.kcp_input,
            |feature_flag| feature_flag.no_relay_kcp,
        )
        .await
    }

    pub async fn check_allow_quic_to_dst(&self, dst_ip: &IpAddr) -> bool {
        self.check_allow_wrapped_proxy_to_dst(
            dst_ip,
            |feature_flag| feature_flag.quic_input,
            |feature_flag| feature_flag.no_relay_quic,
        )
        .await
    }

    pub async fn send_msg_for_proxy(
        &self,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
    ) -> Result<(), Error> {
        self.mark_recent_traffic(dst_peer_id);
        self.check_p2p_only_before_send(dst_peer_id)?;

        self.counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        try_compress_and_encrypt(
            self.data_compress_algo,
            &self.encryptor,
            &mut msg,
            self.is_secure_mode_enabled,
        )
        .await?;

        self.counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        let msg_len = msg.buf_len() as u64;
        let result = send_msg_internal(
            self.peers.as_ref(),
            &self.foreign_network_client,
            &self.relay_peer_map,
            Some(&self.traffic_metrics),
            msg,
            dst_peer_id,
        )
        .await;
        if result.is_ok() {
            self.counters.self_tx_bytes.add(msg_len);
            self.counters.self_tx_packets.inc();
        }
        result
    }

    pub async fn get_msg_dst_peer(&self, addr: &IpAddr) -> (Vec<PeerId>, bool) {
        match addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(ipv6_addr).await,
        }
    }

    fn is_all_peers_broadcast_ipv4(&self, ipv4_addr: &Ipv4Addr) -> bool {
        let network_length = self
            .context
            .ipv4()
            .map(|x| x.network_length())
            .unwrap_or(24);
        let ipv4_inet = cidr::Ipv4Inet::new(*ipv4_addr, network_length).unwrap();
        ipv4_addr.is_broadcast()
            || ipv4_addr.is_multicast()
            || *ipv4_addr == ipv4_inet.last_address()
    }

    fn is_all_peers_broadcast_ipv6(&self, ipv6_addr: &Ipv6Addr) -> bool {
        let network_length = self
            .context
            .ipv6()
            .map(|x| x.network_length())
            .unwrap_or(64);
        let ipv6_inet = cidr::Ipv6Inet::new(*ipv6_addr, network_length).unwrap();
        ipv6_addr.is_multicast() || *ipv6_addr == ipv6_inet.last_address()
    }

    fn select_ipv4_broadcast_peers<'a>(
        routes: impl IntoIterator<Item = &'a CoreRoute>,
        my_peer_id: PeerId,
    ) -> Vec<PeerId> {
        routes
            .into_iter()
            .filter_map(|route| {
                (route.peer_id != my_peer_id && route.ipv4_addr.is_some()).then_some(route.peer_id)
            })
            .collect()
    }

    pub async fn get_msg_dst_peer_ipv4(&self, ipv4_addr: &Ipv4Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv4(ipv4_addr) {
            dst_peers.extend(Self::select_ipv4_broadcast_peers(
                &self.peers.list_route_infos().await,
                self.my_peer_id,
            ));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(ipv4_addr).await {
            dst_peers.push(peer_id);
        } else if !self
            .context
            .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            for exit_node in self.exit_nodes.read().await.iter() {
                let IpAddr::V4(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv4(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }
        if self.host_routing.local_exit_node_fallback
            && dst_peers.is_empty()
            && !self
                .context
                .is_ip_in_same_network(&std::net::IpAddr::V4(*ipv4_addr))
        {
            tracing::trace!(
                %ipv4_addr,
                "no peer route for external IPv4; use local exit-node fallback"
            );
            dst_peers.push(self.my_peer_id);
            is_exit_node = true;
        }
        (dst_peers, is_exit_node)
    }

    pub async fn get_msg_dst_peer_ipv6(&self, ipv6_addr: &Ipv6Addr) -> (Vec<PeerId>, bool) {
        let mut is_exit_node = false;
        let mut dst_peers = vec![];
        if self.is_all_peers_broadcast_ipv6(ipv6_addr) {
            dst_peers.extend(self.peers.list_routes().await.iter().map(|x| *x.key()));
        } else if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(ipv6_addr).await {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local()
            && let Some(peer_id) = self.route.get_public_ipv6_gateway_peer_id().await
        {
            dst_peers.push(peer_id);
        } else if !ipv6_addr.is_unicast_link_local() {
            // NOTE: never route link local address to exit node.
            for exit_node in self.exit_nodes.read().await.iter() {
                let IpAddr::V6(exit_node) = exit_node else {
                    continue;
                };
                if let Some(peer_id) = self.peers.get_peer_id_by_ipv6(exit_node).await {
                    dst_peers.push(peer_id);
                    is_exit_node = true;
                    break;
                }
            }
        }

        (dst_peers, is_exit_node)
    }

    pub async fn send_msg_by_ip(
        &self,
        mut msg: ZCPacket,
        ip_addr: IpAddr,
        not_send_to_self: bool,
    ) -> Result<(), Error> {
        tracing::trace!(
            "do send_msg in peer manager, msg: {:?}, ip_addr: {}",
            msg,
            ip_addr
        );

        msg.fill_peer_manager_hdr(self.my_peer_id, 0, PacketType::Data as u8);
        if !self.run_nic_packet_process_pipeline(&mut msg).await {
            return Ok(());
        }
        let cur_to_peer_id = msg.peer_manager_header().unwrap().to_peer_id.into();
        if cur_to_peer_id != 0 {
            self.mark_recent_traffic(cur_to_peer_id);
            return send_msg_internal(
                self.peers.as_ref(),
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                cur_to_peer_id,
            )
            .await;
        }

        let (dst_peers, is_exit_node) = match ip_addr {
            IpAddr::V4(ipv4_addr) => self.get_msg_dst_peer_ipv4(&ipv4_addr).await,
            IpAddr::V6(ipv6_addr) => self.get_msg_dst_peer_ipv6(&ipv6_addr).await,
        };

        if dst_peers.is_empty() {
            tracing::info!("no peer id for ip: {}", ip_addr);
            return Ok(());
        }

        self.counters
            .compress_tx_bytes_before
            .add(msg.buf_len() as u64);

        try_compress_and_encrypt(
            self.data_compress_algo,
            &self.encryptor,
            &mut msg,
            self.is_secure_mode_enabled,
        )
        .await?;

        self.counters
            .compress_tx_bytes_after
            .add(msg.buf_len() as u64);

        let is_latency_first = self.context.latency_first();
        msg.mut_peer_manager_header()
            .unwrap()
            .set_latency_first(is_latency_first)
            .set_exit_node(is_exit_node);

        let mut errs: Vec<Error> = vec![];
        let mut msg = Some(msg);
        let total_dst_peers = dst_peers.len();
        let should_mark_recent_traffic = should_mark_recent_traffic_for_fanout(total_dst_peers);
        for (i, peer_id) in dst_peers.iter().enumerate() {
            if should_mark_recent_traffic {
                self.mark_recent_traffic(*peer_id);
            }
            if let Err(e) = self.check_p2p_only_before_send(*peer_id) {
                errs.push(e);
                continue;
            }

            let mut msg = if i == total_dst_peers - 1 {
                msg.take().unwrap()
            } else {
                msg.clone().unwrap()
            };

            let hdr = msg.mut_peer_manager_header().unwrap();
            hdr.to_peer_id.set(*peer_id);

            if !self.host_routing.local_exit_node_fallback
                && not_send_to_self
                && *peer_id == self.my_peer_id
                && !self.context.is_ip_local_virtual_ip(&ip_addr)
            {
                // Keep the loop-prevention flags for proxy-induced self-delivery where
                // the destination is not this node's own EasyTier-managed IP.
                hdr.set_not_send_to_tun(true);
                hdr.set_no_proxy(true);
            }

            self.counters.self_tx_bytes.add(msg.buf_len() as u64);
            self.counters.self_tx_packets.inc();

            if let Err(e) = send_msg_internal(
                self.peers.as_ref(),
                &self.foreign_network_client,
                &self.relay_peer_map,
                Some(&self.traffic_metrics),
                msg,
                *peer_id,
            )
            .await
            {
                errs.push(e);
            }
        }

        tracing::trace!(?dst_peers, "do send_msg in peer manager done");

        if errs.is_empty() {
            Ok(())
        } else {
            tracing::error!(?errs, "send_msg has error");
            Err(anyhow::anyhow!("send_msg has error: {:?}", errs).into())
        }
    }
}

struct PeerPacketRouterCounters {
    self_tx_packets: CounterHandle,
    self_tx_bytes: CounterHandle,
    self_rx_packets: CounterHandle,
    self_rx_bytes: CounterHandle,
    forward_data_tx_packets: CounterHandle,
    forward_data_tx_bytes: CounterHandle,
    forward_control_tx_packets: CounterHandle,
    forward_control_tx_bytes: CounterHandle,
    compress_tx_bytes_before: CounterHandle,
    compress_tx_bytes_after: CounterHandle,
    compress_rx_bytes_before: CounterHandle,
    compress_rx_bytes_after: CounterHandle,
}

pub(crate) struct PeerPacketRouter {
    packet_recv: PacketRecvChanReceiver,
    my_peer_id: PeerId,
    peers: Arc<PeerMap>,
    peer_packet_process_pipeline: Arc<RwLock<Vec<Arc<PeerPipelineEntry>>>>,
    foreign_client: Arc<ForeignNetworkClient>,
    relay_peer_map: Arc<RelayPeerMap>,
    foreign_network_handler: Arc<dyn ForeignNetworkPacketHandler>,
    encryptor: Arc<dyn Encryptor>,
    compress_algo: CompressorAlgo,
    acl_filter: Arc<AclFilter>,
    context: ArcPeerContext,
    secure_mode_enabled: bool,
    route: ArcRoute,
    is_credential_node: bool,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    stats_mgr: Arc<StatsManager>,
    counters: PeerPacketRouterCounters,
}

impl PeerPacketRouter {
    #[allow(clippy::too_many_arguments)]
    fn new(
        packet_recv: PacketRecvChanReceiver,
        my_peer_id: PeerId,
        peers: Arc<PeerMap>,
        peer_packet_process_pipeline: Arc<RwLock<Vec<Arc<PeerPipelineEntry>>>>,
        foreign_client: Arc<ForeignNetworkClient>,
        relay_peer_map: Arc<RelayPeerMap>,
        foreign_network_handler: Arc<dyn ForeignNetworkPacketHandler>,
        encryptor: Arc<dyn Encryptor>,
        compress_algo: CompressorAlgo,
        acl_filter: Arc<AclFilter>,
        context: ArcPeerContext,
        secure_mode_enabled: bool,
        route: ArcRoute,
        is_credential_node: bool,
        traffic_metrics: Arc<TrafficMetricRecorder>,
        stats_mgr: Arc<StatsManager>,
        network_name: String,
        self_tx_packets: CounterHandle,
        self_tx_bytes: CounterHandle,
        compress_tx_bytes_before: CounterHandle,
        compress_tx_bytes_after: CounterHandle,
    ) -> Self {
        let label_set = LabelSet::new().with_label_type(LabelType::NetworkName(network_name));
        Self {
            packet_recv,
            my_peer_id,
            peers,
            peer_packet_process_pipeline,
            foreign_client,
            relay_peer_map,
            foreign_network_handler,
            encryptor,
            compress_algo,
            acl_filter,
            context,
            secure_mode_enabled,
            route,
            is_credential_node,
            traffic_metrics,
            stats_mgr: stats_mgr.clone(),
            counters: PeerPacketRouterCounters {
                self_tx_packets,
                self_tx_bytes,
                self_rx_bytes: stats_mgr
                    .get_counter(MetricName::TrafficBytesSelfRx, label_set.clone()),
                self_rx_packets: stats_mgr
                    .get_counter(MetricName::TrafficPacketsSelfRx, label_set.clone()),
                forward_data_tx_bytes: stats_mgr
                    .get_counter(MetricName::TrafficBytesForwarded, label_set.clone()),
                forward_data_tx_packets: stats_mgr
                    .get_counter(MetricName::TrafficPacketsForwarded, label_set.clone()),
                forward_control_tx_bytes: stats_mgr
                    .get_counter(MetricName::TrafficControlBytesForwarded, label_set.clone()),
                forward_control_tx_packets: stats_mgr.get_counter(
                    MetricName::TrafficControlPacketsForwarded,
                    label_set.clone(),
                ),
                compress_tx_bytes_before,
                compress_tx_bytes_after,
                compress_rx_bytes_before: stats_mgr
                    .get_counter(MetricName::CompressionBytesRxBefore, label_set.clone()),
                compress_rx_bytes_after: stats_mgr
                    .get_counter(MetricName::CompressionBytesRxAfter, label_set),
            },
        }
    }

    pub async fn run(mut self) {
        tracing::trace!("start_peer_recv");
        while let Ok(ret) = recv_packet_from_chan(&mut self.packet_recv).await {
            let disable_relay_data = self.context.disable_relay_data();
            let Err(ret) = try_handle_foreign_network_packet(
                ret,
                self.my_peer_id,
                &self.peers,
                self.foreign_network_handler.as_ref(),
                self.stats_mgr.as_ref(),
                disable_relay_data,
            )
            .await
            else {
                continue;
            };

            self.handle_packet(ret, disable_relay_data).await;
        }
        panic!("done_peer_recv");
    }

    async fn handle_packet(&self, mut ret: ZCPacket, disable_relay_data: bool) {
        let buf_len = ret.buf_len();
        let is_relay_data_packet = is_relay_data_zc_packet(&ret);
        let Some(hdr) = ret.mut_peer_manager_header() else {
            tracing::warn!(?ret, "invalid packet, skip");
            return;
        };

        tracing::trace!(?hdr, "peer recv a packet...");
        let from_peer_id = hdr.from_peer_id.get();
        let to_peer_id = hdr.to_peer_id.get();
        let packet_type = hdr.packet_type;
        let is_encrypted = hdr.is_encrypted();
        if to_peer_id != self.my_peer_id {
            if disable_relay_data && is_relay_data_packet {
                tracing::debug!(
                    ?from_peer_id,
                    ?to_peer_id,
                    packet_type,
                    "drop forwarded relay data while relay data is disabled"
                );
                return;
            }

            if hdr.forward_counter > 7 {
                tracing::warn!(?hdr, "forward counter exceed, drop packet");
                return;
            }

            // Step 10b: credential nodes don't forward handshake packets
            if self.is_credential_node
                && (packet_type == PacketType::HandShake as u8
                    || packet_type == PacketType::NoiseHandshakeMsg1 as u8
                    || packet_type == PacketType::NoiseHandshakeMsg2 as u8
                    || packet_type == PacketType::NoiseHandshakeMsg3 as u8)
            {
                tracing::debug!("credential node dropping forwarded handshake packet");
                return;
            }

            if hdr.forward_counter > 2 && hdr.is_latency_first() {
                tracing::trace!(?hdr, "set_latency_first false because too many hop");
                hdr.set_latency_first(false);
            }

            hdr.forward_counter += 1;

            if from_peer_id == self.my_peer_id {
                self.counters.compress_tx_bytes_before.add(buf_len as u64);

                if packet_type == PacketType::Data as u8
                    || packet_type == PacketType::KcpSrc as u8
                    || packet_type == PacketType::KcpDst as u8
                {
                    let _ = try_compress_and_encrypt(
                        self.compress_algo,
                        &self.encryptor,
                        &mut ret,
                        self.secure_mode_enabled,
                    )
                    .await;
                }

                self.counters
                    .compress_tx_bytes_after
                    .add(ret.buf_len() as u64);
                self.counters.self_tx_bytes.add(ret.buf_len() as u64);
                self.counters.self_tx_packets.inc();
            } else {
                match traffic_kind(packet_type) {
                    TrafficKind::Data => {
                        self.counters.forward_data_tx_bytes.add(buf_len as u64);
                        self.counters.forward_data_tx_packets.inc();
                    }
                    TrafficKind::Control => {
                        self.counters.forward_control_tx_bytes.add(buf_len as u64);
                        self.counters.forward_control_tx_packets.inc();
                    }
                }
            }

            tracing::trace!(?to_peer_id, my_peer_id = ?self.my_peer_id, "need forward");
            let tx_metrics = if from_peer_id == self.my_peer_id {
                Some(&self.traffic_metrics)
            } else {
                None
            };
            let ret = send_msg_internal(
                self.peers.as_ref(),
                &self.foreign_client,
                &self.relay_peer_map,
                tx_metrics,
                ret,
                to_peer_id,
            )
            .await
            .map_err(Error::from);
            if ret.is_err() {
                tracing::error!(?ret, ?to_peer_id, ?from_peer_id, "forward packet error");
            }
        } else {
            if packet_type == PacketType::RelayHandshake as u8
                || packet_type == PacketType::RelayHandshakeAck as u8
            {
                let _ = self.relay_peer_map.handle_handshake_packet(ret).await;
                return;
            }
            if !self.secure_mode_enabled {
                if let Err(e) = self.encryptor.decrypt(&mut ret) {
                    tracing::error!(?e, "decrypt failed");
                    return;
                }
            } else if is_encrypted {
                match self.relay_peer_map.decrypt_if_needed(&mut ret).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::error!("secure session not found");
                        return;
                    }
                    Err(e) => {
                        tracing::error!(?e, "secure decrypt failed");
                        return;
                    }
                }
            }

            self.counters.self_rx_bytes.add(buf_len as u64);
            self.counters.self_rx_packets.inc();
            self.traffic_metrics
                .record_rx(from_peer_id, packet_type, buf_len as u64)
                .await;
            self.counters.compress_rx_bytes_before.add(buf_len as u64);

            let compressor = DefaultCompressor {};
            if let Err(e) = compressor.decompress(&mut ret).await {
                tracing::error!(?e, "decompress failed");
                return;
            }

            self.counters
                .compress_rx_bytes_after
                .add(ret.buf_len() as u64);

            if !self.acl_filter.process_packet_with_acl(
                &ret,
                true,
                self.context.ipv4().map(|x| x.address()),
                |dst| self.context.is_ip_local_ipv6(&dst),
                self.route.as_ref(),
            ) {
                return;
            }

            let mut processed = false;
            let mut zc_packet = Some(ret);
            tracing::trace!(?zc_packet, "try_process_packet_from_peer");
            for pipeline in self.peer_packet_process_pipeline.read().await.iter().rev() {
                if !pipeline.active.load(Ordering::Acquire) {
                    continue;
                }
                let filter = pipeline.filter.read().clone();
                if let Some(filter) = filter {
                    zc_packet = filter
                        .try_process_packet_from_peer(zc_packet.unwrap())
                        .await;
                }
                if zc_packet.is_none() {
                    processed = true;
                    break;
                }
            }
            if !processed {
                tracing::error!(?zc_packet, "unhandled packet");
            }
        }
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub(crate) trait ForeignNetworkPacketHandler: Send + Sync + 'static {
    fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId>;

    async fn forward_foreign_network_packet(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> anyhow::Result<()>;
}

pub(crate) fn is_relay_data_packet(packet_type: u8) -> bool {
    super::traffic_metrics::is_relay_data_packet_type(packet_type)
}

pub(crate) fn is_relay_data_zc_packet(packet: &ZCPacket) -> bool {
    let Some(hdr) = packet.peer_manager_header() else {
        return false;
    };

    if hdr.packet_type == PacketType::ForeignNetworkPacket as u8 {
        let inner_packet_type = packet.foreign_network_inner_packet_type();
        if inner_packet_type.is_none() {
            tracing::warn!(
                ?hdr,
                "foreign network packet has unparseable inner peer manager header"
            );
        }
        return inner_packet_type.is_none_or(is_relay_data_packet);
    }

    is_relay_data_packet(hdr.packet_type)
}

pub(crate) async fn try_handle_foreign_network_packet<H>(
    mut packet: ZCPacket,
    my_peer_id: PeerId,
    peer_map: &PeerMap,
    foreign_network_handler: &H,
    stats_manager: &StatsManager,
    disable_relay_data: bool,
) -> Result<(), ZCPacket>
where
    H: ForeignNetworkPacketHandler + ?Sized,
{
    let pm_header = packet.peer_manager_header().unwrap();
    if pm_header.packet_type != PacketType::ForeignNetworkPacket as u8 {
        return Err(packet);
    }

    let from_peer_id = pm_header.from_peer_id.get();
    let to_peer_id = pm_header.to_peer_id.get();

    if disable_relay_data && is_relay_data_zc_packet(&packet) {
        tracing::debug!(
            ?from_peer_id,
            ?to_peer_id,
            inner_packet_type = ?packet.foreign_network_inner_packet_type(),
            "drop foreign network relay data while relay data is disabled"
        );
        return Ok(());
    }

    let foreign_hdr = packet.foreign_network_hdr().unwrap();
    let foreign_network_name = foreign_hdr.get_network_name(packet.payload());
    let foreign_peer_id = foreign_hdr.get_dst_peer_id();

    let foreign_network_my_peer_id =
        foreign_network_handler.get_network_peer_id(&foreign_network_name);

    let buf_len = packet.buf_len();
    let label_set =
        LabelSet::new().with_label_type(LabelType::NetworkName(foreign_network_name.clone()));
    let add_counter = move |bytes_metric, packets_metric| {
        stats_manager
            .get_counter(bytes_metric, label_set.clone())
            .add(buf_len as u64);
        stats_manager.get_counter(packets_metric, label_set).inc();
    };

    // NOTICE: the to peer id is modified by the src from foreign network my peer id to the origin my peer id
    if to_peer_id == my_peer_id {
        // packet sent from other peer to me, extract the inner packet and forward it
        add_counter(
            MetricName::TrafficBytesForeignForwardRx,
            MetricName::TrafficPacketsForeignForwardRx,
        );
        if let Err(e) = foreign_network_handler
            .forward_foreign_network_packet(
                &foreign_network_name,
                foreign_peer_id,
                packet.foreign_network_packet(),
            )
            .await
        {
            tracing::debug!(
                ?e,
                ?foreign_network_name,
                ?foreign_peer_id,
                "foreign network mgr send_msg_to_peer failed"
            );
        }
        Ok(())
    } else if Some(from_peer_id) == foreign_network_my_peer_id {
        // to_peer_id is my peer id for the foreign network, need to convert to the origin my_peer_id of dst
        let Some(to_peer_id) = peer_map
            .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
            .await
        else {
            tracing::debug!(
                ?foreign_network_name,
                ?to_peer_id,
                "cannot find origin my peer id for foreign network."
            );
            return Err(packet);
        };

        add_counter(
            MetricName::TrafficBytesForeignForwardTx,
            MetricName::TrafficPacketsForeignForwardTx,
        );

        // modify the to_peer id from foreign network my peer id to the origin my peer id
        packet
            .mut_peer_manager_header()
            .unwrap()
            .to_peer_id
            .set(to_peer_id);

        // packet is generated from foreign network mgr and should be forward to other peer
        if let Err(e) = peer_map
            .send_msg(packet, to_peer_id, NextHopPolicy::LeastHop)
            .await
        {
            tracing::debug!(
                ?e,
                ?to_peer_id,
                "send_msg_directly failed when forward local generated foreign network packet"
            );
        }
        Ok(())
    } else {
        // target is not me, forward it. try get origin peer id
        add_counter(
            MetricName::TrafficBytesForeignForwardForwarded,
            MetricName::TrafficPacketsForeignForwardForwarded,
        );
        Err(packet)
    }
}

pub(crate) struct PeerManagerRouteInterface {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_network_client: Weak<ForeignNetworkClient>,
    foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
}

impl PeerManagerRouteInterface {
    pub fn new(
        my_peer_id: PeerId,
        peers: Weak<PeerMap>,
        foreign_network_client: Weak<ForeignNetworkClient>,
        foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
    ) -> Self {
        Self {
            my_peer_id,
            peers,
            foreign_network_client,
            foreign_network_provider,
        }
    }
}

#[async_trait::async_trait]
impl RouteInterface for PeerManagerRouteInterface {
    async fn list_peers(&self) -> Vec<PeerId> {
        let Some(foreign_client) = self.foreign_network_client.upgrade() else {
            return vec![];
        };

        let Some(peer_map) = self.peers.upgrade() else {
            return vec![];
        };

        let mut peers = foreign_client.list_public_peers().await;
        peers.extend(peer_map.list_peers_with_conn().await);
        peers
    }

    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn close_peer(&self, peer_id: PeerId) {
        if let Some(peer_map) = self.peers.upgrade() {
            let _ = peer_map.close_peer(peer_id).await;
        }

        if let Some(foreign_client) = self.foreign_network_client.upgrade() {
            let _ = foreign_client.get_peer_map().close_peer(peer_id).await;
        }
    }

    async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let peer_map = self.peers.upgrade()?;
        peer_map.get_peer_public_key(peer_id)
    }

    async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        let peer_map = self.peers.upgrade()?;
        peer_map.get_peer_identity_type(peer_id)
    }

    async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
        let ret = ForeignNetworkRouteInfoMap::new();
        let Some(provider) = self.foreign_network_provider.upgrade() else {
            return ret;
        };

        let networks = provider.list_foreign_network_route_infos().await;
        for info in networks {
            if info.peer_ids.is_empty() {
                continue;
            }

            let last_update = provider
                .get_foreign_network_last_update(&info.network_name)
                .unwrap_or(SystemTime::now());
            ret.insert(
                ForeignNetworkRouteInfoKey {
                    peer_id: self.my_peer_id,
                    network_name: info.network_name,
                },
                ForeignNetworkRouteInfoEntry {
                    foreign_peer_ids: info.peer_ids,
                    last_update: Some(last_update.into()),
                    version: 0,
                    network_secret_digest: info.network_secret_digest,
                    my_peer_id_for_this_network: info.my_peer_id_for_this_network,
                },
            );
        }
        ret
    }
}

pub(crate) fn peer_manager_route_interface(
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_network_client: Weak<ForeignNetworkClient>,
    foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
) -> RouteInterfaceBox {
    Box::new(PeerManagerRouteInterface::new(
        my_peer_id,
        peers,
        foreign_network_client,
        foreign_network_provider,
    ))
}

pub(crate) async fn send_msg_internal(
    peers: &PeerMap,
    foreign_network_client: &Arc<ForeignNetworkClient>,
    relay_peer_map: &Arc<RelayPeerMap>,
    direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
    msg: ZCPacket,
    dst_peer_id: PeerId,
) -> Result<(), Error> {
    let policy = get_next_hop_policy(msg.peer_manager_header().unwrap().is_latency_first());
    let is_latency_first = msg.peer_manager_header().unwrap().is_latency_first();
    let packet_type = msg.peer_manager_header().unwrap().packet_type;
    let msg_len = msg.buf_len() as u64;
    let latency_first_gateway = if is_latency_first {
        peers
            .get_gateway_peer_id(dst_peer_id, policy.clone())
            .await
            .filter(|gateway| *gateway != dst_peer_id)
    } else {
        None
    };
    let send_result = if let Some(gateway) = latency_first_gateway
        && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
    {
        relay_peer_map
            .send_msg(msg, dst_peer_id, policy)
            .await
            .map_err(Error::from)
    } else if peers.has_peer(dst_peer_id) {
        peers.send_msg_directly(msg, dst_peer_id).await
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy.clone()).await {
        if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
            relay_peer_map
                .send_msg(msg, dst_peer_id, policy)
                .await
                .map_err(Error::from)
        } else {
            tracing::warn!(
                ?gateway,
                ?dst_peer_id,
                "cannot send msg to peer through gateway"
            );
            Err(Error::RouteError(None))
        }
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        // check foreign network again. so in happy path we can avoid extra check
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else {
        tracing::debug!(?dst_peer_id, "no gateway for peer");
        Err(Error::RouteError(None))
    };

    if send_result.is_ok()
        && let Some(metrics) = direct_tx_metrics
    {
        metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
    }

    send_result
}

#[cfg(test)]
mod tests {
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use dashmap::DashMap;
    use quanta::Instant;
    use x25519_dalek::{PublicKey, StaticSecret};

    use super::*;
    use crate::{
        config::{CoreConfig, IpPrefix, NetworkIdentity, NodeConfig, ProxyNetworkConfig},
        peers::{
            context::{PeerContext, PeerEvent},
            create_packet_recv_chan,
        },
        proto::common::{PeerFeatureFlag, StunInfo},
        runtime_config::CoreRuntimeConfig,
    };

    impl PeerManagerCore {
        pub(crate) fn new_portable_for_test(
            config: PortablePeerManagerConfig,
            dns: Arc<dyn DnsResolver>,
            nic_channel: PacketRecvChan,
        ) -> anyhow::Result<Self> {
            let runtime_config = CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(config.snapshot.clone()),
            );
            let public_ipv6_runtime =
                CorePublicIpv6Runtime::new(runtime_config.clone(), Arc::new(()));
            Self::build(
                config,
                runtime_config,
                dns,
                SocketContext::default(),
                None,
                nic_channel,
                public_ipv6_runtime,
                PeerManagerHostAdapters::default(),
                Arc::new(()),
            )
        }
    }

    struct SameNetworkContext {
        contains_every_address: bool,
    }

    impl PeerContext for SameNetworkContext {
        fn network_identity(&self) -> NetworkIdentity {
            NetworkIdentity {
                network_name: "test".to_string(),
                network_secret: None,
                network_secret_digest: None,
            }
        }

        fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
            self.contains_every_address
                || matches!(ip, IpAddr::V4(ip) if ip.octets()[0..2] == [10, 144])
        }
    }

    struct StaticAddressResolver(AddressResolution);

    #[async_trait::async_trait]
    impl AddressResolver for StaticAddressResolver {
        async fn resolve_remote(
            &self,
            _remote_addr: &Url,
            _default_port: Option<u16>,
        ) -> AddressResolution {
            match &self.0 {
                AddressResolution::IpAddrs(addrs) => AddressResolution::IpAddrs(addrs.clone()),
                AddressResolution::NotIpBased => AddressResolution::NotIpBased,
                AddressResolution::Unavailable => AddressResolution::Unavailable,
            }
        }
    }

    struct StaticDnsResolver;

    #[async_trait::async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            assert_eq!(
                query,
                DnsQuery::new("example.test", SocketContext::default())
            );
            Ok(vec![
                IpAddr::from([192, 0, 2, 10]),
                "2001:db8::10".parse().unwrap(),
            ])
        }
    }

    struct PanicDnsResolver;

    #[async_trait::async_trait]
    impl DnsResolver for PanicDnsResolver {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            panic!("IP literals must not invoke DNS")
        }
    }

    #[derive(Default)]
    struct CountingPeerEventSink(AtomicUsize);

    impl super::super::context::PeerEventSink for CountingPeerEventSink {
        fn issue_event(&self, _event: super::super::context::PeerEvent) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct ContextDnsResolver(SocketContext);

    #[async_trait::async_trait]
    impl DnsResolver for ContextDnsResolver {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            assert_eq!(query.context, self.0);
            Ok(vec![IpAddr::from([192, 0, 2, 11])])
        }
    }

    struct DropCountingNicFilter(Arc<AtomicUsize>);

    impl Drop for DropCountingNicFilter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[async_trait::async_trait]
    impl super::super::NicPacketFilter for DropCountingNicFilter {
        async fn try_process_packet_from_nic(&self, _data: &mut ZCPacket) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn managed_nic_pipeline_removal_waits_for_readers_and_drops_filter() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (entry, registration) =
            managed_nic_pipeline_entry(Box::new(DropCountingNicFilter(drops.clone())));
        let pipeline = Arc::new(RwLock::new(vec![entry]));
        let reader = pipeline.read().await;
        let active_filter = reader[0].filter.read().clone().unwrap();
        let remove_pipeline = pipeline.clone();
        let remove_registration = registration.clone();
        let removal = tokio::spawn(async move {
            remove_managed_nic_pipeline_entry(&remove_pipeline, &remove_registration).await;
        });

        tokio::task::yield_now().await;
        assert!(!removal.is_finished());
        assert_eq!(drops.load(Ordering::Relaxed), 0);

        drop(reader);
        drop(active_filter);
        removal.await.unwrap();
        assert!(pipeline.read().await.is_empty());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn managed_pipeline_guard_releases_filter_without_a_runtime() {
        let drops = Arc::new(AtomicUsize::new(0));
        let (entry, registration) =
            managed_nic_pipeline_entry(Box::new(DropCountingNicFilter(drops.clone())));

        drop(registration);

        assert!(entry.filter.read().is_none());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn dns_address_resolver_uses_host_dns_and_default_port() {
        let resolver = DnsAddressResolver::new(Arc::new(StaticDnsResolver));

        let result = resolver
            .resolve_remote(&Url::parse("tcp://example.test").unwrap(), Some(11010))
            .await;

        let AddressResolution::IpAddrs(addrs) = result else {
            panic!("domain should resolve to socket addresses");
        };
        assert_eq!(
            addrs,
            vec![
                SocketAddr::from(([192, 0, 2, 10], 11010)),
                SocketAddr::new("2001:db8::10".parse().unwrap(), 11010),
            ]
        );
    }

    #[tokio::test]
    async fn dns_address_resolver_forwards_instance_socket_context() {
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(crate::socket::NetNamespace::new("instance-a")));
        let resolver = DnsAddressResolver::new(Arc::new(ContextDnsResolver(context.clone())))
            .with_context(context);

        let result = resolver
            .resolve_remote(&Url::parse("tcp://example.test").unwrap(), Some(11010))
            .await;

        assert!(matches!(result, AddressResolution::IpAddrs(_)));
    }

    #[tokio::test]
    async fn dns_address_resolver_keeps_ip_literals_below_dns_seam() {
        let resolver = DnsAddressResolver::new(Arc::new(PanicDnsResolver));

        let result = resolver
            .resolve_remote(&Url::parse("tcp://127.0.0.1:0").unwrap(), Some(11010))
            .await;

        let AddressResolution::IpAddrs(addrs) = result else {
            panic!("IP literal should produce a socket address");
        };
        assert_eq!(addrs, vec![SocketAddr::from(([127, 0, 0, 1], 0))]);
    }

    fn portable_runtime_config(network_name: &str, peer_id: PeerId) -> PeerRuntimeConfig {
        PeerRuntimeConfig {
            core: CoreConfig {
                node: NodeConfig {
                    peer_id: Some(peer_id),
                    network_name: network_name.to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            },
            network_identity: NetworkIdentity {
                network_name: network_name.to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            },
            stun_info: StunInfo::default(),
            feature_flags: PeerFeatureFlag::default(),
            secure_mode: None,
            host_routing: HostRoutingPolicy::default(),
        }
    }

    fn credential_secure_mode() -> crate::proto::common::SecureModeConfig {
        let private = StaticSecret::from([7; 32]);
        let public = PublicKey::from(&private);
        crate::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        }
    }

    fn build_portable_for_test(runtime: PeerRuntimeConfig) -> anyhow::Result<PeerManagerCore> {
        build_portable_config_for_test(PortablePeerManagerConfig::new(runtime))
    }

    fn build_portable_config_for_test(
        config: PortablePeerManagerConfig,
    ) -> anyhow::Result<PeerManagerCore> {
        let (packet_tx, _packet_rx) = create_packet_recv_chan();
        PeerManagerCore::new_portable_for_test(config, Arc::new(PanicDnsResolver), packet_tx)
    }

    #[tokio::test]
    async fn portable_peer_manager_builds_and_stops_from_normalized_config() {
        let runtime = portable_runtime_config("portable-net", 77);
        let core = build_portable_for_test(runtime).unwrap();

        assert_eq!(core.my_peer_id(), 77);
        assert_eq!(core.context.network_name(), "portable-net");
        assert_ne!(core.context.instance_id(), uuid::Uuid::nil());
        assert_eq!(core.data_compress_algo, CompressorAlgo::None);
        assert!(
            core.peer_connection_admission
                .foreign_network_admission
                .allow_client_foreign_network()
        );
        assert!(core.list_foreign_network_infos(false).await.is_empty());

        core.run().await.unwrap();
        let route = core.route_algo_inst.ospf_route().unwrap();
        assert!(route.task_count() > 0);
        assert!(!core.stats_manager.cleanup_task_is_stopped());
        assert!(!core.acl_filter.cleanup_task_is_stopped());
        core.clear_resources().await;
        assert_eq!(route.task_count(), 0);
        assert!(core.stats_manager.cleanup_task_is_stopped());
        assert!(core.acl_filter.cleanup_task_is_stopped());
        assert!(core.foreign_network_manager.is_stopped_for_test().await);
        assert!(
            !core
                .foreign_network_manager
                .admission_is_open_for_test()
                .await
        );
    }

    #[tokio::test]
    async fn unknown_ipv6_has_no_peer_destination() {
        let core = build_portable_for_test(portable_runtime_config("ipv6-net", 77)).unwrap();
        let unknown = "fd00::2".parse().unwrap();

        let (peers, is_self) = core.get_msg_dst_peer_ipv6(&unknown).await;

        assert!(peers.is_empty());
        assert!(!is_self);
    }

    #[tokio::test]
    async fn foreign_network_stop_waits_for_inflight_admission() {
        let core = build_portable_for_test(portable_runtime_config("portable-net", 92)).unwrap();
        let manager = core.foreign_network_manager.clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let admission_manager = manager.clone();
        let admission_entered = entered.clone();
        let admission_release = release.clone();
        let admission = tokio::spawn(async move {
            admission_manager
                .hold_admission_for_test(admission_entered, admission_release)
                .await
        });
        entered.notified().await;

        let stop_manager = manager.clone();
        let stop = tokio::spawn(async move { stop_manager.stop().await });
        tokio::task::yield_now().await;
        assert!(!stop.is_finished());

        release.notify_waiters();
        admission.await.unwrap().unwrap();
        stop.await.unwrap();
        assert!(manager.is_stopped_for_test().await);
        assert!(!manager.admission_is_open_for_test().await);

        core.clear_resources().await;
    }

    #[tokio::test]
    async fn portable_peer_manager_uses_host_context_adapters() {
        let config = PortablePeerManagerConfig::new(portable_runtime_config("portable-net", 78));
        let runtime_config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(config.snapshot.clone()),
        );
        let public_ipv6_runtime = CorePublicIpv6Runtime::new(runtime_config.clone(), Arc::new(()));
        let events = Arc::new(CountingPeerEventSink::default());
        let (packet_tx, _packet_rx) = create_packet_recv_chan();

        let core = PeerManagerCore::new(
            config,
            runtime_config,
            Arc::new(PanicDnsResolver),
            SocketContext::default(),
            Arc::new(()),
            packet_tx,
            public_ipv6_runtime,
            PeerManagerHostAdapters {
                event_sink: events.clone(),
                ..Default::default()
            },
            Arc::new(()),
        )
        .unwrap();

        core.context.issue_event(PeerEvent::PeerAdded(99));
        assert_eq!(events.0.load(Ordering::Relaxed), 1);
        core.clear_resources().await;
    }

    #[tokio::test]
    async fn portable_peer_assembly_preserves_submitted_acl_groups() {
        let mut config =
            PortablePeerManagerConfig::new(portable_runtime_config("portable-net", 86));
        let acl = crate::proto::acl::Acl {
            acl_v1: Some(crate::proto::acl::AclV1 {
                chains: Vec::new(),
                group: Some(crate::proto::acl::GroupInfo {
                    declares: vec![crate::proto::acl::GroupIdentity {
                        group_name: "ops".to_owned(),
                        group_secret: "ops-secret".to_owned(),
                    }],
                    members: vec!["ops".to_owned()],
                }),
            }),
        };
        config.snapshot.set_acl_groups(Some(&acl));
        let (packet_tx, _packet_rx) = create_packet_recv_chan();

        let core =
            PeerManagerCore::new_portable_for_test(config, Arc::new(PanicDnsResolver), packet_tx)
                .unwrap();

        let groups = core.context.peer_groups(86);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_name, "ops");
        assert!(groups[0].verify("ops-secret", 86));
        assert_eq!(core.context.acl_group_declarations()[0].group_name, "ops");
        core.clear_resources().await;
    }

    #[tokio::test]
    async fn node_snapshot_exposes_normalized_runtime_state() {
        let instance_id = uuid::Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let mut runtime = portable_runtime_config("portable-net", 91);
        runtime.core.node.instance_id = Some(*instance_id.as_bytes());
        runtime.core.node.hostname = Some("portable-node".to_owned());
        runtime.core.routes.ipv4 = Some(IpPrefix::new("10.20.0.91".parse().unwrap(), 16).unwrap());
        runtime.core.routes.proxy_networks = vec![ProxyNetworkConfig {
            real: IpPrefix::new("10.40.0.0".parse().unwrap(), 16).unwrap(),
            mapped: Some(IpPrefix::new("10.50.0.0".parse().unwrap(), 16).unwrap()),
        }];
        runtime.stun_info.public_ip = vec!["192.0.2.91".to_owned()];
        let core = build_portable_for_test(runtime).unwrap();
        let listener = Url::parse("tcp://0.0.0.0:11010").unwrap();

        let snapshot = core.node_snapshot(vec![listener.clone()]).await;

        assert_eq!(snapshot.peer_id, 91);
        assert_eq!(snapshot.instance_id, instance_id);
        assert_eq!(snapshot.hostname, "portable-node");
        assert_eq!(snapshot.ipv4_addr, Some("10.20.0.91/16".parse().unwrap()));
        assert_eq!(snapshot.proxy_networks.len(), 1);
        assert_eq!(snapshot.listeners, vec![listener]);
        assert_eq!(snapshot.stun_info.public_ip, vec!["192.0.2.91"]);
        assert_eq!(snapshot.version, env!("CARGO_PKG_VERSION"));
        assert!(snapshot.public_ipv6_addr.is_none());
        assert!(snapshot.ipv6_public_addr_prefix.is_none());

        let dns_snapshot = MagicDnsRouteSource::snapshot(&core).await;
        assert_eq!(
            dns_snapshot.routes.last(),
            Some(&MagicDnsRouteAdvertisement {
                hostname: "portable-node".to_owned(),
                ipv4_addr: Some("10.20.0.91/16".parse::<cidr::Ipv4Inet>().unwrap().into()),
            })
        );
    }

    #[test]
    fn magic_dns_advertisement_preserves_untrusted_prefix_without_parsing() {
        let ipv4_addr = crate::proto::common::Ipv4Inet {
            address: Some("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into()),
            network_length: 33,
        };

        let advertisement = magic_dns_route_advertisement(CoreRoute {
            hostname: "remote".to_owned(),
            ipv4_addr: Some(ipv4_addr.clone()),
            ..Default::default()
        });

        assert_eq!(advertisement.ipv4_addr, Some(ipv4_addr));
    }

    #[tokio::test]
    async fn portable_peer_manager_auth_uses_managed_credentials() {
        let admin_a = build_portable_for_test(portable_runtime_config("portable-net", 84)).unwrap();
        let admin_b = build_portable_for_test(portable_runtime_config("portable-net", 85)).unwrap();
        let generated = admin_a.credential_manager().generate_credential(
            vec!["guest".to_owned()],
            false,
            Vec::new(),
            Duration::from_secs(3600),
        );
        let private_bytes: [u8; 32] = BASE64_STANDARD
            .decode(generated.secret)
            .unwrap()
            .try_into()
            .unwrap();
        let public_key = PublicKey::from(&StaticSecret::from(private_bytes));

        assert!(
            admin_a
                .context
                .is_pubkey_trusted(public_key.as_bytes(), "portable-net")
        );
        assert!(
            !admin_a
                .context
                .is_pubkey_trusted(public_key.as_bytes(), "other")
        );
        let trusted = admin_a.context.trusted_credential_pubkeys("secret");
        assert_eq!(trusted.len(), 1);

        let propagated_key = trusted[0].credential.as_ref().unwrap().pubkey.clone();
        admin_b.context.update_trusted_keys(
            std::collections::HashMap::from([(
                propagated_key.clone(),
                crate::peers::context::TrustedKeyMetadata {
                    source: crate::peers::context::TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
            "portable-net",
        );
        assert!(
            admin_b
                .context
                .is_pubkey_trusted(&propagated_key, "portable-net")
        );
        assert!(admin_b.context.is_pubkey_trusted_with_source(
            &propagated_key,
            "portable-net",
            crate::peers::context::TrustedKeySource::OspfCredential,
        ));
        assert!(!admin_b.context.is_pubkey_trusted_with_source(
            &propagated_key,
            "portable-net",
            crate::peers::context::TrustedKeySource::OspfNode,
        ));

        assert!(
            admin_a
                .credential_manager()
                .revoke_credential(&generated.credential_id)
        );
        admin_b
            .context
            .update_trusted_keys(std::collections::HashMap::new(), "portable-net");
        assert!(
            !admin_b
                .context
                .is_pubkey_trusted(&propagated_key, "portable-net")
        );
    }

    #[tokio::test]
    async fn portable_host_policy_controls_local_exit_node_fallback() {
        let external_ipv4 = Ipv4Addr::new(203, 0, 113, 10);
        let default_core =
            build_portable_for_test(portable_runtime_config("portable-net", 78)).unwrap();
        assert_eq!(
            default_core.get_msg_dst_peer_ipv4(&external_ipv4).await,
            (Vec::new(), false)
        );

        let mut runtime = portable_runtime_config("portable-net", 79);
        runtime.host_routing.local_exit_node_fallback = true;
        let fallback_core = build_portable_for_test(runtime).unwrap();
        assert_eq!(
            fallback_core.get_msg_dst_peer_ipv4(&external_ipv4).await,
            (vec![79], true)
        );
    }

    #[tokio::test]
    async fn portable_peer_manager_rejects_inconsistent_network_names() {
        let mut runtime = portable_runtime_config("identity-net", 78);
        runtime.core.node.network_name = "node-net".to_owned();
        let (packet_tx, _packet_rx) = create_packet_recv_chan();

        let result = PeerManagerCore::new_portable_for_test(
            PortablePeerManagerConfig::new(runtime),
            Arc::new(PanicDnsResolver),
            packet_tx,
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn portable_peer_manager_rejects_unavailable_config_capabilities() {
        let mut digest_mismatch = portable_runtime_config("portable-net", 79);
        digest_mismatch.network_identity.network_secret_digest = Some([1; 32]);
        assert!(build_portable_for_test(digest_mismatch).is_err());

        let mut secure_without_keys = portable_runtime_config("portable-net", 83);
        secure_without_keys.secure_mode = Some(crate::proto::common::SecureModeConfig {
            enabled: true,
            ..Default::default()
        });
        assert!(build_portable_for_test(secure_without_keys).is_err());

        let mut mismatched_keys = portable_runtime_config("portable-net", 82);
        mismatched_keys.secure_mode = Some(credential_secure_mode());
        mismatched_keys
            .secure_mode
            .as_mut()
            .unwrap()
            .local_public_key = Some(BASE64_STANDARD.encode([9; 32]));
        assert!(build_portable_for_test(mismatched_keys).is_err());

        let mut credential_without_secure_mode = portable_runtime_config("portable-net", 84);
        credential_without_secure_mode
            .network_identity
            .network_secret = None;
        credential_without_secure_mode
            .network_identity
            .network_secret_digest = None;
        assert!(build_portable_for_test(credential_without_secure_mode).is_err());
    }

    #[tokio::test]
    async fn portable_peer_manager_accepts_credential_client_config() {
        let mut runtime = portable_runtime_config("portable-net", 81);
        runtime.network_identity.network_secret = None;
        runtime.network_identity.network_secret_digest = None;
        runtime.secure_mode = Some(credential_secure_mode());

        let core = build_portable_for_test(runtime).unwrap();
        assert!(core.context.feature_flags().is_credential_peer);
        assert!(core.context.network_identity().network_secret.is_none());
        assert!(core.is_secure_mode_enabled);
        core.clear_resources().await;
    }

    #[tokio::test]
    async fn portable_peer_manager_accepts_legacy_unlimited_limits() {
        let runtime = portable_runtime_config("portable-net", 84);
        let mut flags = PortablePeerManagerConfig::new(runtime.clone())
            .snapshot
            .flags;
        flags.instance_recv_bps_limit = u64::MAX;
        flags.foreign_relay_bps_limit = u64::MAX;
        let mut config = PortablePeerManagerConfig::new(runtime.clone());
        config.snapshot = PeerRuntimeSnapshot::new(runtime, flags);

        let core = build_portable_config_for_test(config).unwrap();
        assert!(core.context.recv_limiter("portable-net", false).is_none());
        assert!(core.context.recv_limiter("foreign-net", true).is_none());
        core.clear_resources().await;
    }

    #[tokio::test]
    async fn portable_peer_manager_builds_configured_recv_limiters() {
        let mut runtime = portable_runtime_config("portable-net", 80);
        runtime.core.traffic.instance_recv_bps_limit = Some(1024);
        runtime.core.traffic.foreign_relay_bps_limit = Some(2048);
        let core = build_portable_for_test(runtime).unwrap();

        let instance_a = core.context.recv_limiter("portable-net", false).unwrap();
        let instance_b = core.context.recv_limiter("other-net", false).unwrap();
        assert!(Arc::ptr_eq(&instance_a, &instance_b));

        let foreign_a = core.context.recv_limiter("foreign-a", true).unwrap();
        let foreign_a_again = core.context.recv_limiter("foreign-a", true).unwrap();
        let foreign_b = core.context.recv_limiter("foreign-b", true).unwrap();
        let foreign_named_instance = core.context.recv_limiter("instance", true).unwrap();
        assert!(Arc::ptr_eq(&foreign_a, &foreign_a_again));
        assert!(!Arc::ptr_eq(&foreign_a, &foreign_b));
        assert!(!Arc::ptr_eq(&instance_a, &foreign_a));
        assert!(!Arc::ptr_eq(&instance_a, &foreign_named_instance));

        core.clear_resources().await;
        assert!(core.context.recv_limiter("portable-net", false).is_none());
        assert!(core.context.recv_limiter("foreign-a", true).is_none());
    }

    #[tokio::test]
    async fn portable_peer_manager_rejects_invalid_identity_and_prefixes() {
        let mut digest_only = portable_runtime_config("portable-net", 85);
        digest_only.network_identity.network_secret = None;
        digest_only.network_identity.network_secret_digest = Some([1; 32]);
        assert!(build_portable_for_test(digest_only).is_err());

        let mut wrong_family = portable_runtime_config("portable-net", 86);
        wrong_family.core.routes.ipv4 = Some(IpPrefix {
            address: "2001:db8::1".parse().unwrap(),
            prefix_len: 64,
        });
        assert!(build_portable_for_test(wrong_family).is_err());

        let mut proxy_host_bits = portable_runtime_config("portable-net", 87);
        proxy_host_bits.core.routes.proxy_networks = vec![crate::config::ProxyNetworkConfig {
            real: IpPrefix::new("10.50.0.7".parse().unwrap(), 16).unwrap(),
            mapped: None,
        }];
        assert!(build_portable_for_test(proxy_host_bits).is_err());

        let mut wrong_proxy_family = portable_runtime_config("portable-net", 88);
        wrong_proxy_family.core.routes.proxy_networks = vec![crate::config::ProxyNetworkConfig {
            real: IpPrefix::new("10.50.0.0".parse().unwrap(), 16).unwrap(),
            mapped: Some(IpPrefix::new("2001:db8::".parse().unwrap(), 64).unwrap()),
        }];
        assert!(build_portable_for_test(wrong_proxy_family).is_err());

        let mut advertised = portable_runtime_config("portable-net", 89);
        advertised
            .core
            .routes
            .advertised_routes
            .push(IpPrefix::new("10.60.0.0".parse().unwrap(), 16).unwrap());
        assert!(build_portable_for_test(advertised).is_err());

        let mut foreign = portable_runtime_config("portable-net", 90);
        foreign
            .core
            .routes
            .foreign_networks
            .push(crate::config::ForeignNetworkConfig {
                name: "other-net".to_owned(),
                cidrs: Vec::new(),
            });
        assert!(build_portable_for_test(foreign).is_err());
    }

    #[test]
    fn portable_peer_manager_reports_missing_tokio_runtime() {
        let result = build_portable_for_test(portable_runtime_config("portable-net", 90));

        let Err(error) = result else {
            panic!("construction outside Tokio must fail");
        };
        assert!(error.to_string().contains("entered Tokio runtime"));
    }

    #[test]
    fn recent_traffic_fanout_policy_only_marks_single_peer() {
        assert!(should_mark_recent_traffic_for_fanout(0));
        assert!(should_mark_recent_traffic_for_fanout(1));
        assert!(!should_mark_recent_traffic_for_fanout(2));
    }

    #[tokio::test]
    async fn remote_addr_check_rejects_resolved_virtual_network_ip() {
        let context: ArcPeerContext = Arc::new(SameNetworkContext {
            contains_every_address: false,
        });
        let resolver = StaticAddressResolver(AddressResolution::IpAddrs(vec![
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            SocketAddr::from(([10, 144, 0, 2], 1234)),
        ]));
        let url = Url::parse("tcp://example.test:1234").unwrap();

        let err =
            check_resolved_remote_addr_not_from_virtual_network(&context, &resolver, url).await;

        assert!(matches!(err, Err(Error::Other(_))));
    }

    #[tokio::test]
    async fn remote_addr_check_allows_non_network_and_unresolved_sources() {
        let context: ArcPeerContext = Arc::new(SameNetworkContext {
            contains_every_address: false,
        });
        let url = Url::parse("tcp://example.test:1234").unwrap();

        for resolution in [
            AddressResolution::IpAddrs(vec![SocketAddr::from(([192, 0, 2, 10], 1234))]),
            AddressResolution::NotIpBased,
            AddressResolution::Unavailable,
        ] {
            let resolver = StaticAddressResolver(resolution);
            let ret = check_resolved_remote_addr_not_from_virtual_network(
                &context,
                &resolver,
                url.clone(),
            )
            .await;

            assert!(ret.is_ok());
        }
    }

    #[tokio::test]
    async fn remote_addr_check_allows_loopback_inside_virtual_network() {
        let context: ArcPeerContext = Arc::new(SameNetworkContext {
            contains_every_address: true,
        });
        let resolver = StaticAddressResolver(AddressResolution::IpAddrs(vec![
            SocketAddr::from(([127, 0, 0, 1], 1234)),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1234),
        ]));
        let url = Url::parse("tcp://localhost:1234").unwrap();

        let ret =
            check_resolved_remote_addr_not_from_virtual_network(&context, &resolver, url).await;

        assert!(ret.is_ok());
    }

    #[test]
    fn disable_relay_data_classifies_data_plane_packets_only() {
        for packet_type in [
            PacketType::Data,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
            PacketType::ForeignNetworkPacket,
        ] {
            assert!(is_relay_data_packet(packet_type as u8));
        }

        for packet_type in [
            PacketType::RpcReq,
            PacketType::RpcResp,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::HandShake,
            PacketType::NoiseHandshakeMsg1,
            PacketType::NoiseHandshakeMsg2,
            PacketType::NoiseHandshakeMsg3,
            PacketType::RelayHandshake,
            PacketType::RelayHandshakeAck,
        ] {
            assert!(!is_relay_data_packet(packet_type as u8));
        }
    }

    #[test]
    fn disable_relay_data_inspects_foreign_network_inner_packet_type() {
        let network_name = "net1".to_string();

        let mut rpc_packet = ZCPacket::new_with_payload(b"rpc");
        rpc_packet.fill_peer_manager_hdr(1, 2, PacketType::RpcReq as u8);
        let mut foreign_rpc_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &rpc_packet);
        foreign_rpc_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_rpc_packet.foreign_network_inner_packet_type(),
            Some(PacketType::RpcReq as u8)
        );
        assert!(!is_relay_data_zc_packet(&foreign_rpc_packet));

        let mut data_packet = ZCPacket::new_with_payload(b"data");
        data_packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut foreign_data_packet =
            ZCPacket::new_for_foreign_network(&network_name, 2, &data_packet);
        foreign_data_packet.fill_peer_manager_hdr(10, 20, PacketType::ForeignNetworkPacket as u8);

        assert_eq!(
            foreign_data_packet.foreign_network_inner_packet_type(),
            Some(PacketType::Data as u8)
        );
        assert!(is_relay_data_zc_packet(&foreign_data_packet));
    }

    fn route_with_ipv4(
        peer_id: u32,
        ipv4_addr: Option<std::net::Ipv4Addr>,
    ) -> crate::proto::core_peer::peer::Route {
        crate::proto::core_peer::peer::Route {
            peer_id,
            ipv4_addr: ipv4_addr.map(|addr| cidr::Ipv4Inet::new(addr, 24).unwrap().into()),
            ..Default::default()
        }
    }

    #[test]
    fn ipv4_broadcast_peer_selection_skips_peers_without_ipv4() {
        let routes = vec![
            route_with_ipv4(1, Some(std::net::Ipv4Addr::new(10, 126, 126, 1))),
            route_with_ipv4(2, None),
            route_with_ipv4(3, Some(std::net::Ipv4Addr::new(10, 126, 126, 3))),
            route_with_ipv4(4, None),
        ];

        assert_eq!(
            PeerOutboundPacketRouter::select_ipv4_broadcast_peers(&routes, 3),
            vec![1]
        );
    }

    #[test]
    fn gc_recent_traffic_removes_expired_and_connected_entries() {
        let stale_peer = 1;
        let direct_peer = 2;
        let active_peer = 3;
        let recent_have_traffic = DashMap::new();

        recent_have_traffic.insert(
            stale_peer,
            Instant::now() - RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1),
        );
        recent_have_traffic.insert(direct_peer, Instant::now());
        recent_have_traffic.insert(active_peer, Instant::now());

        let future_peer = 4;
        recent_have_traffic.insert(future_peer, Instant::now() + Duration::from_secs(1));

        gc_recent_traffic_entries(&recent_have_traffic, Instant::now(), |peer_id| {
            peer_id == direct_peer
        });

        assert!(!recent_have_traffic.contains_key(&stale_peer));
        assert!(!recent_have_traffic.contains_key(&direct_peer));
        assert!(recent_have_traffic.contains_key(&active_peer));
        assert!(recent_have_traffic.contains_key(&future_peer));
    }

    #[test]
    fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let tracker = RecentTrafficTracker::new(1);
        let peer_id = 2;
        let signal = tracker.p2p_demand_notify();

        let initial_version = signal.version();
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(signal.version(), initial_version + 1);

        let first_seen = *tracker.recent_have_traffic.get(&peer_id).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "fresh demand should not wake all p2p workers again"
        );
        let refreshed_seen = *tracker.recent_have_traffic.get(&peer_id).unwrap();
        assert!(refreshed_seen > first_seen);

        if let Some(mut last_seen) = tracker.recent_have_traffic.get_mut(&peer_id) {
            *last_seen = Instant::now() - RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1);
        }
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(signal.version(), initial_version + 2);
    }

    #[test]
    fn recent_traffic_tolerates_future_timestamps() {
        let tracker = RecentTrafficTracker::new(1);
        let peer_id = 2;
        tracker
            .recent_have_traffic
            .insert(peer_id, Instant::now() + Duration::from_secs(1));

        assert!(tracker.has(peer_id, Instant::now(), |_| false));
        tracker.mark(peer_id, false, true, |_| false);
    }
}

use std::{
    collections::{BTreeSet, HashSet},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use easytier_core::peers::context::{
    ArcByteLimiter, NetworkIdentity as CoreNetworkIdentity, PeerContext, PeerContextEvent,
    PeerContextEventSubscriber, PeerEvent, PeerGroupIdentity, TrustedKeyMapManager,
    secret_proof_from_secret,
};
pub use easytier_core::peers::context::{TrustedKeyMap, TrustedKeyMetadata, TrustedKeySource};
use easytier_core::peers::encrypt::{derive_key_128, derive_key_256};
use easytier_core::peers::public_ipv6::PublicIpv6Runtime;

use super::{
    PeerId,
    config::{ConfigLoader, Flags},
    constants::EASYTIER_VERSION,
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
};
use crate::{
    common::{
        config::ProxyNetworkConfig,
        credential_manager::CredentialManager,
        stats_manager::{self, StatsManager},
        token_bucket::TokenBucketManager,
    },
    peers::acl_filter::AclFilter,
    proto::{
        acl::GroupIdentity,
        api::{config::InstanceConfigPatch, instance::PeerConnInfo},
        common::{PeerFeatureFlag, PortForwardConfigPb},
        peer_rpc::PeerGroupInfo,
    },
    rpc_service::protected_port,
    tunnel::matches_protocol,
    use_global_var,
};
use crossbeam::atomic::AtomicCell;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use socket2::Protocol;

pub type NetworkIdentity = crate::common::config::NetworkIdentity;

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GlobalCtxEvent {
    TunDeviceReady(String),
    TunDeviceError(String),

    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(PeerConnInfo),
    PeerConnRemoved(PeerConnInfo),

    ListenerAdded(url::Url),
    ListenerAddFailed(url::Url, String), // (url, error message)
    ListenerAcceptFailed(url::Url, String), // (url, error message)
    ConnectionAccepted(String, String),  // (local url, remote url)
    ConnectionError(String, String, String), // (local url, remote url, error message)
    ListenerPortMappingEstablished {
        local_listener: url::Url,
        mapped_listener: url::Url,
        backend: String,
    },

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),
    PublicIpv6Changed(Option<cidr::Ipv6Inet>, Option<cidr::Ipv6Inet>), // (old, new)
    PublicIpv6RoutesUpdated(Vec<cidr::Ipv6Inet>, Vec<cidr::Ipv6Inet>), // (added, removed)

    PortForwardAdded(PortForwardConfigPb),

    ConfigPatched(InstanceConfigPatch),

    ProxyCidrsUpdated(Vec<cidr::Ipv4Cidr>, Vec<cidr::Ipv4Cidr>), // (added, removed)

    UdpBroadcastRelayStartResult {
        capture_backend: Option<String>,
        error: Option<String>,
    },

    CredentialChanged,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;
type PeerEventBus = tokio::sync::broadcast::Sender<PeerContextEvent>;

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,
    peer_event_bus: PeerEventBus,

    cached_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_lease: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_routes: Mutex<BTreeSet<std::net::Ipv6Addr>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<url::Url>>,
    advertised_ipv6_public_addr_prefix: Mutex<Option<cidr::Ipv6Cidr>>,
    tun_device_name: Mutex<Option<String>>,

    flags: ArcSwap<Flags>,

    // Runtime/base advertised feature flags before config-owned fields are
    // overlaid by set_flags. Keep this separate so config patches do not erase
    // runtime state such as public-server role, IPv6 provider status, or the
    // non-whitelist avoid-relay preference.
    base_feature_flags: AtomicCell<PeerFeatureFlag>,

    feature_flags: AtomicCell<PeerFeatureFlag>,

    token_bucket_manager: TokenBucketManager,

    stats_manager: Arc<StatsManager>,

    acl_filter: Arc<AclFilter>,

    credential_manager: Arc<CredentialManager>,

    /// OSPF propagated trusted keys (peer pubkeys and admin credentials)
    /// Stored in ArcSwap for lock-free reads and atomic batch updates
    trusted_keys: Arc<TrustedKeyMapManager>,
}

impl std::fmt::Debug for GlobalCtx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GlobalCtx")
            .field("inst_name", &self.inst_name)
            .field("id", &self.id)
            .field("net_ns", &self.net_ns.name())
            .field("event_bus", &"EventBus")
            .field("ipv4", &self.cached_ipv4)
            .finish()
    }
}

pub type ArcGlobalCtx = std::sync::Arc<GlobalCtx>;

impl PeerContext for GlobalCtx {
    fn network_identity(&self) -> CoreNetworkIdentity {
        let identity = self.get_network_identity();
        CoreNetworkIdentity {
            network_name: identity.network_name,
            network_secret: identity.network_secret,
            network_secret_digest: identity.network_secret_digest,
        }
    }

    fn flags(&self) -> crate::proto::common::FlagsInConfig {
        self.get_flags()
    }

    fn disable_relay_data(&self) -> bool {
        self.flags_arc().disable_relay_data
    }

    fn secure_mode(&self) -> Option<crate::proto::common::SecureModeConfig> {
        self.config.get_secure_mode()
    }

    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.get_stun_info_collector().get_stun_info()
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.get_id()
    }

    fn ipv4(&self) -> Option<cidr::Ipv4Inet> {
        self.get_ipv4()
    }

    fn ipv6(&self) -> Option<cidr::Ipv6Inet> {
        self.get_ipv6()
    }

    fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        GlobalCtx::is_ip_local_ipv6(self, ip)
    }

    fn proxy_cidrs(&self) -> Vec<cidr::Ipv4Cidr> {
        self.config
            .get_proxy_cidrs()
            .iter()
            .map(|x| x.mapped_cidr.unwrap_or(x.cidr))
            .collect()
    }

    fn vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.get_vpn_portal_cidr()
    }

    fn hostname(&self) -> String {
        self.get_hostname()
    }

    fn feature_flags(&self) -> crate::proto::common::PeerFeatureFlag {
        self.get_feature_flags()
    }

    fn easytier_version(&self) -> String {
        EASYTIER_VERSION.to_string()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        use_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC)
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        self.get_advertised_ipv6_public_addr_prefix()
    }

    fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        GlobalCtx::is_ip_in_same_network(self, ip)
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        GlobalCtx::is_ip_local_virtual_ip(self, ip)
    }

    fn p2p_only(&self) -> bool {
        GlobalCtx::p2p_only(self)
    }

    fn latency_first(&self) -> bool {
        GlobalCtx::latency_first(self)
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        self.get_acl_groups(peer_id)
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        self.get_acl_group_declarations()
            .into_iter()
            .map(|group| PeerGroupIdentity {
                group_name: group.group_name,
                group_secret: group.group_secret,
            })
            .collect()
    }

    fn pinned_remote_static_pubkey(
        &self,
        tunnel_info: Option<&crate::proto::common::TunnelInfo>,
    ) -> Option<String> {
        let remote_url_str = tunnel_info
            .and_then(|t| t.remote_addr.as_ref())
            .map(|u| u.url.as_str())?;
        let remote_url: url::Url = remote_url_str.parse().ok()?;

        self.config
            .get_peers()
            .into_iter()
            .find(|p| p.uri == remote_url)
            .and_then(|p| p.peer_public_key)
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<hmac::Hmac<sha2::Sha256>> {
        let secret = self.get_network_identity().network_secret?;
        secret_proof_from_secret(&secret, challenge)
    }

    fn secret_digest(&self, network_identity: &CoreNetworkIdentity) -> Vec<u8> {
        if use_global_var!(HMAC_SECRET_DIGEST) {
            self.get_secret_proof(b"digest")
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network_identity
                .secret_digest()
                .unwrap_or_default()
                .to_vec()
        }
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.is_pubkey_trusted(pubkey, network_name)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        GlobalCtx::is_pubkey_trusted_with_source(self, pubkey, network_name, source)
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<crate::proto::peer_rpc::TrustedCredentialPubkeyProof> {
        self.get_credential_manager()
            .get_trusted_pubkeys(network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        self.get_credential_manager().remove_expired_credentials()
    }

    fn issue_credential_changed(&self) {
        GlobalCtx::issue_event(self, GlobalCtxEvent::CredentialChanged);
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        GlobalCtx::update_trusted_keys(self, keys, network_name);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        GlobalCtx::remove_trusted_keys(self, network_name);
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.record_control_metric(
            network_name,
            bytes,
            stats_manager::MetricName::TrafficControlBytesTx,
            stats_manager::MetricName::TrafficControlPacketsTx,
        );
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.record_control_metric(
            network_name,
            bytes,
            stats_manager::MetricName::TrafficControlBytesRx,
            stats_manager::MetricName::TrafficControlPacketsRx,
        );
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        let flags = self.get_flags();
        if is_foreign_network && flags.foreign_relay_bps_limit != u64::MAX {
            let limiter_config = crate::proto::common::LimiterConfig {
                burst_rate: None,
                bps: Some(flags.foreign_relay_bps_limit),
                fill_duration_ms: None,
            };
            return Some(
                self.token_bucket_manager()
                    .get_or_create(&format!("{network_name}:recv"), limiter_config.into()),
            );
        }

        if flags.instance_recv_bps_limit != u64::MAX {
            let limiter_config = crate::proto::common::LimiterConfig {
                burst_rate: None,
                bps: Some(flags.instance_recv_bps_limit),
                fill_duration_ms: None,
            };
            return Some(
                self.token_bucket_manager()
                    .get_or_create("instance:recv", limiter_config.into()),
            );
        }

        None
    }

    fn issue_event(&self, event: PeerEvent) {
        match event {
            PeerEvent::PeerAdded(peer_id) => self.issue_event(GlobalCtxEvent::PeerAdded(peer_id)),
            PeerEvent::PeerRemoved(peer_id) => {
                self.issue_event(GlobalCtxEvent::PeerRemoved(peer_id))
            }
            PeerEvent::PeerConnAdded(info) => {
                self.issue_event(GlobalCtxEvent::PeerConnAdded(info.into()))
            }
            PeerEvent::PeerConnRemoved(info) => {
                self.issue_event(GlobalCtxEvent::PeerConnRemoved(info.into()))
            }
        }
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        Some(self.peer_event_bus.subscribe())
    }
}

#[async_trait]
impl PublicIpv6Runtime for GlobalCtx {
    fn ipv6_public_addr_auto(&self) -> bool {
        self.config.get_ipv6_public_addr_auto()
    }

    fn ipv6_public_addr_provider(&self) -> bool {
        self.config.get_ipv6_public_addr_provider()
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.get_id()
    }

    fn network_name(&self) -> String {
        self.get_network_name()
    }

    async fn collect_reserved_public_ipv6_addrs(
        &self,
        prefix: cidr::Ipv6Cidr,
    ) -> HashSet<Ipv6Addr> {
        let ip_list = self.get_ip_collector().collect_ip_addrs().await;
        let mut reserved = HashSet::new();
        reserved.extend(
            ip_list
                .interface_ipv6s
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved.extend(
            ip_list
                .public_ipv6
                .into_iter()
                .map(Ipv6Addr::from)
                .filter(|addr| prefix.contains(addr)),
        );
        reserved
    }

    fn public_ipv6_lease_changed(&self, old: Option<cidr::Ipv6Inet>, new: Option<cidr::Ipv6Inet>) {
        self.set_public_ipv6_lease(new);
        self.issue_event(GlobalCtxEvent::PublicIpv6Changed(old, new));
    }

    fn public_ipv6_routes_changed(
        &self,
        routes: BTreeSet<cidr::Ipv6Inet>,
        added: Vec<cidr::Ipv6Inet>,
        removed: Vec<cidr::Ipv6Inet>,
    ) {
        self.set_public_ipv6_routes(routes);
        self.issue_event(GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed));
    }
}

impl GlobalCtx {
    fn record_control_metric(
        &self,
        network_name: &str,
        bytes: u64,
        bytes_metric: stats_manager::MetricName,
        packets_metric: stats_manager::MetricName,
    ) {
        let label_set = stats_manager::LabelSet::new().with_label_type(
            stats_manager::LabelType::NetworkName(network_name.to_string()),
        );
        self.stats_manager()
            .get_counter(bytes_metric, label_set.clone())
            .add(bytes);
        self.stats_manager()
            .get_counter(packets_metric, label_set)
            .inc();
    }

    fn apply_disable_relay_data_flag(
        flags: &Flags,
        mut feature_flags: PeerFeatureFlag,
    ) -> PeerFeatureFlag {
        if flags.disable_relay_data {
            feature_flags.avoid_relay_data = true;
        }
        feature_flags
    }

    fn derive_feature_flags(flags: &Flags, mut feature_flags: PeerFeatureFlag) -> PeerFeatureFlag {
        feature_flags.kcp_input = !flags.disable_kcp_input;
        feature_flags.no_relay_kcp = flags.disable_relay_kcp;
        feature_flags.support_conn_list_sync = true;
        feature_flags.quic_input = !flags.disable_quic_input;
        feature_flags.no_relay_quic = flags.disable_relay_quic;
        feature_flags.need_p2p = flags.need_p2p;
        feature_flags.disable_p2p = flags.disable_p2p;
        Self::apply_disable_relay_data_flag(flags, feature_flags)
    }

    pub fn new(config_fs: impl ConfigLoader + 'static) -> Self {
        let id = config_fs.get_id();
        let network = config_fs.get_network_identity();
        let net_ns = NetNS::new(config_fs.get_netns());
        let hostname = config_fs.get_hostname();

        let (event_bus, _) = tokio::sync::broadcast::channel(16);
        let (peer_event_bus, _) = tokio::sync::broadcast::channel(16);

        let stun_info_collector = StunInfoCollector::new_with_default_servers();

        if let Some(stun_servers) = config_fs.get_stun_servers() {
            stun_info_collector.set_stun_servers(stun_servers);
        } else {
            stun_info_collector.set_stun_servers(StunInfoCollector::get_default_servers());
        }

        if let Some(stun_servers) = config_fs.get_stun_servers_v6() {
            stun_info_collector.set_stun_servers_v6(stun_servers);
        } else {
            stun_info_collector.set_stun_servers_v6(StunInfoCollector::get_default_servers_v6());
        }

        let stun_info_collector = Arc::new(stun_info_collector);

        let flags = config_fs.get_flags();

        let base_feature_flags = PeerFeatureFlag::default();
        let feature_flags = Self::derive_feature_flags(&flags, base_feature_flags);

        let credential_storage_path = config_fs.get_credential_file();
        let credential_manager = Arc::new(CredentialManager::new(credential_storage_path));

        GlobalCtx {
            inst_name: config_fs.get_inst_name(),
            id,
            config: Box::new(config_fs),
            net_ns: net_ns.clone(),
            network,

            event_bus,
            peer_event_bus,
            cached_ipv4: AtomicCell::new(None),
            cached_ipv6: AtomicCell::new(None),
            public_ipv6_lease: AtomicCell::new(None),
            public_ipv6_routes: Mutex::new(BTreeSet::new()),
            cached_proxy_cidrs: AtomicCell::new(None),

            ip_collector: Mutex::new(Some(Arc::new(IPCollector::new(
                net_ns,
                stun_info_collector.clone(),
            )))),

            hostname: Mutex::new(hostname),

            stun_info_collection: Mutex::new(stun_info_collector),

            running_listeners: Mutex::new(Vec::new()),
            advertised_ipv6_public_addr_prefix: Mutex::new(None),
            tun_device_name: Mutex::new(None),

            flags: ArcSwap::new(Arc::new(flags)),

            base_feature_flags: AtomicCell::new(base_feature_flags),

            feature_flags: AtomicCell::new(feature_flags),

            token_bucket_manager: TokenBucketManager::new(),

            stats_manager: Arc::new(StatsManager::new()),

            acl_filter: Arc::new(AclFilter::new()),

            credential_manager,

            trusted_keys: Arc::new(TrustedKeyMapManager::new()),
        }
    }

    pub fn subscribe(&self) -> EventBusSubscriber {
        self.event_bus.subscribe()
    }

    pub fn issue_event(&self, event: GlobalCtxEvent) {
        self.issue_peer_context_event(&event);
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
    }

    fn issue_peer_context_event(&self, event: &GlobalCtxEvent) {
        let event = match event {
            GlobalCtxEvent::PeerAdded(peer_id) => PeerContextEvent::PeerAdded(*peer_id),
            GlobalCtxEvent::PeerRemoved(peer_id) => PeerContextEvent::PeerRemoved(*peer_id),
            GlobalCtxEvent::PeerConnAdded(_) => PeerContextEvent::PeerConnAdded,
            GlobalCtxEvent::PeerConnRemoved(_) => PeerContextEvent::PeerConnRemoved,
            _ => return,
        };
        let _ = self.peer_event_bus.send(event);
    }

    fn set_tun_device_name(&self, name: Option<String>) {
        *self.tun_device_name.lock().unwrap() = name;
    }

    pub(crate) fn set_tun_device_ready(&self, name: String) {
        self.set_tun_device_name(Some(name.clone()));
        self.issue_event(GlobalCtxEvent::TunDeviceReady(name));
    }

    pub(crate) fn set_tun_device_error(&self, error: String) {
        self.set_tun_device_name(None);
        self.issue_event(GlobalCtxEvent::TunDeviceError(error));
    }

    pub fn get_tun_device_name(&self) -> Option<String> {
        self.tun_device_name.lock().unwrap().clone()
    }

    pub fn check_network_in_whitelist(&self, network_name: &str) -> Result<(), anyhow::Error> {
        if self
            .get_flags()
            .relay_network_whitelist
            .split(" ")
            .map(wildmatch::WildMatch::new)
            .any(|wl| wl.matches(network_name))
        {
            Ok(())
        } else {
            Err(anyhow::anyhow!("network {} not in whitelist", network_name))
        }
    }

    pub fn get_ipv4(&self) -> Option<cidr::Ipv4Inet> {
        if let Some(ret) = self.cached_ipv4.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv4();
        self.cached_ipv4.store(addr);
        addr
    }

    pub fn set_ipv4(&self, addr: Option<cidr::Ipv4Inet>) {
        self.config.set_ipv4(addr);
        self.cached_ipv4.store(None);
    }

    pub fn get_ipv6(&self) -> Option<cidr::Ipv6Inet> {
        if let Some(ret) = self.cached_ipv6.load() {
            return Some(ret);
        }
        let addr = self.config.get_ipv6();
        self.cached_ipv6.store(addr);
        addr
    }

    pub fn set_ipv6(&self, addr: Option<cidr::Ipv6Inet>) {
        self.config.set_ipv6(addr);
        self.cached_ipv6.store(None);
    }

    pub fn get_public_ipv6_lease(&self) -> Option<cidr::Ipv6Inet> {
        self.public_ipv6_lease.load()
    }

    pub fn set_public_ipv6_lease(&self, addr: Option<cidr::Ipv6Inet>) {
        self.public_ipv6_lease.store(addr);
    }

    pub fn set_public_ipv6_routes(&self, routes: BTreeSet<cidr::Ipv6Inet>) {
        *self.public_ipv6_routes.lock().unwrap() =
            routes.into_iter().map(|route| route.address()).collect();
    }

    pub fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_ipv6().map(|x| x.address() == *ip).unwrap_or(false)
            || self
                .get_public_ipv6_lease()
                .map(|x| x.address() == *ip)
                .unwrap_or(false)
    }

    pub fn is_ip_easytier_managed_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.is_ip_local_ipv6(ip) || self.public_ipv6_routes.lock().unwrap().contains(ip)
    }

    pub fn get_advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        *self.advertised_ipv6_public_addr_prefix.lock().unwrap()
    }

    pub fn set_advertised_ipv6_public_addr_prefix(&self, prefix: Option<cidr::Ipv6Cidr>) -> bool {
        let mut guard = self.advertised_ipv6_public_addr_prefix.lock().unwrap();
        if *guard == prefix {
            return false;
        }

        *guard = prefix;
        true
    }

    pub fn get_id(&self) -> uuid::Uuid {
        self.config.get_id()
    }

    pub fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.contains(v4)).unwrap_or(false),
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.contains(v6)).unwrap_or(false),
        }
    }

    pub fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.get_ipv4().map(|x| x.address() == *v4).unwrap_or(false),
            IpAddr::V6(v6) => self.is_ip_local_ipv6(v6),
        }
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        self.config.get_network_identity()
    }

    pub fn get_secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let network_secret = self.get_network_identity().network_secret?;
        let key = network_secret.as_bytes();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(b"easytier secret proof");
        mac.update(challenge);
        Some(mac)
    }

    pub fn get_network_name(&self) -> String {
        self.get_network_identity().network_name
    }

    pub fn get_ip_collector(&self) -> Arc<IPCollector> {
        self.ip_collector.lock().unwrap().as_ref().unwrap().clone()
    }

    pub fn get_hostname(&self) -> String {
        return self.hostname.lock().unwrap().clone();
    }

    pub fn set_hostname(&self, hostname: String) {
        *self.hostname.lock().unwrap() = hostname;
    }

    pub fn get_stun_info_collector(&self) -> Arc<dyn StunInfoCollectorTrait> {
        self.stun_info_collection.lock().unwrap().clone()
    }

    pub fn replace_stun_info_collector(&self, collector: Box<dyn StunInfoCollectorTrait>) {
        let arc_collector: Arc<dyn StunInfoCollectorTrait> = Arc::new(collector);
        *self.stun_info_collection.lock().unwrap() = arc_collector.clone();

        // rebuild the ip collector
        *self.ip_collector.lock().unwrap() = Some(Arc::new(IPCollector::new(
            self.net_ns.clone(),
            arc_collector,
        )));
    }

    pub fn get_running_listeners(&self) -> Vec<url::Url> {
        self.running_listeners.lock().unwrap().clone()
    }

    pub fn add_running_listener(&self, url: url::Url) {
        let mut l = self.running_listeners.lock().unwrap();
        if !l.contains(&url) {
            l.push(url);
        }
    }

    pub fn get_vpn_portal_cidr(&self) -> Option<cidr::Ipv4Cidr> {
        self.config.get_vpn_portal_config().map(|x| x.client_cidr)
    }

    pub fn get_flags(&self) -> Flags {
        self.flags.load().as_ref().clone()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.config.set_flags(flags.clone());
        self.feature_flags.store(Self::derive_feature_flags(
            &flags,
            self.base_feature_flags.load(),
        ));
        self.flags.store(Arc::new(flags));
    }

    pub fn flags_arc(&self) -> Arc<Flags> {
        self.flags.load_full()
    }

    pub fn get_128_key(&self) -> [u8; 16] {
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        derive_key_128(&secret)
    }

    pub fn get_256_key(&self) -> [u8; 32] {
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        derive_key_256(&secret)
    }

    pub fn enable_exit_node(&self) -> bool {
        self.flags.load().enable_exit_node || cfg!(target_env = "ohos")
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.flags.load().proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.flags.load().no_tun
    }

    pub fn get_feature_flags(&self) -> PeerFeatureFlag {
        self.feature_flags.load()
    }

    /// Replace the runtime/base advertised flags as a complete snapshot.
    ///
    /// This is intended for foreign scoped contexts that inherit an already
    /// computed feature-flag snapshot from their parent. Most callers should use
    /// a narrower setter so they do not accidentally overwrite unrelated runtime
    /// state.
    pub fn set_base_advertised_feature_flags(&self, feature_flags: PeerFeatureFlag) {
        self.base_feature_flags.store(feature_flags);
        let flags = self.flags.load();
        self.feature_flags
            .store(Self::apply_disable_relay_data_flag(
                flags.as_ref(),
                feature_flags,
            ));
    }

    /// Set the avoid-relay preference that is independent of disable_relay_data.
    ///
    /// disable_relay_data still forces the effective advertised flag to true,
    /// but this base preference is preserved when that config flag is toggled.
    pub fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        let mut base_feature_flags = self.base_feature_flags.load();
        base_feature_flags.avoid_relay_data = avoid_relay_data;
        self.base_feature_flags.store(base_feature_flags);

        let mut feature_flags = self.feature_flags.load();
        let previous = feature_flags.avoid_relay_data;
        feature_flags.avoid_relay_data = avoid_relay_data || self.flags.load().disable_relay_data;
        self.feature_flags.store(feature_flags);
        previous != feature_flags.avoid_relay_data
    }

    /// Set the runtime IPv6-provider advertised bit without touching
    /// config-derived feature flags.
    pub fn set_ipv6_public_addr_provider_feature_flag(&self, enabled: bool) -> bool {
        let mut base_feature_flags = self.base_feature_flags.load();
        base_feature_flags.ipv6_public_addr_provider = enabled;
        self.base_feature_flags.store(base_feature_flags);

        let mut feature_flags = self.feature_flags.load();
        if feature_flags.ipv6_public_addr_provider == enabled {
            return false;
        }

        feature_flags.ipv6_public_addr_provider = enabled;
        self.feature_flags.store(feature_flags);
        true
    }

    pub fn token_bucket_manager(&self) -> &TokenBucketManager {
        &self.token_bucket_manager
    }

    pub fn stats_manager(&self) -> &Arc<StatsManager> {
        &self.stats_manager
    }

    pub fn get_acl_filter(&self) -> &Arc<AclFilter> {
        &self.acl_filter
    }

    pub fn get_credential_manager(&self) -> &Arc<CredentialManager> {
        &self.credential_manager
    }

    /// Check if a public key is trusted using two-level lookup:
    /// 1. OSPF propagated trusted_keys (lock-free)
    /// 2. Local credential_manager
    pub fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        // First level: check OSPF propagated keys (lock-free)
        if self.trusted_keys.verify_trusted_key(pubkey, network_name) {
            return true;
        }

        // Second level: check local credential_manager if in the same network
        if network_name == self.get_network_name() {
            return self.credential_manager.is_pubkey_trusted(pubkey);
        }

        false
    }

    pub fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.trusted_keys
            .verify_trusted_key_with_source(pubkey, network_name, Some(source))
    }

    /// Atomically replace all OSPF trusted keys with a new set
    /// Called by OSPF route layer after each route update
    pub fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.trusted_keys.update_trusted_keys(network_name, keys);
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.trusted_keys.remove_trusted_keys(network_name);
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.trusted_keys.list_trusted_keys(network_name)
    }

    pub fn get_acl_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        use std::collections::HashSet;
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| {
                let memberships: HashSet<_> = group.members.iter().collect();
                group
                    .declares
                    .iter()
                    .filter(|g| memberships.contains(&g.group_name))
                    .map(|g| {
                        PeerGroupInfo::generate_with_proof(
                            g.group_name.clone(),
                            g.group_secret.clone(),
                            peer_id,
                        )
                    })
                    .collect()
            })
    }

    pub fn get_acl_group_declarations(&self) -> Vec<GroupIdentity> {
        self.config
            .get_acl()
            .and_then(|acl| acl.acl_v1)
            .and_then(|acl_v1| acl_v1.group)
            .map_or_else(Vec::new, |group| group.declares.to_vec())
    }

    pub fn p2p_only(&self) -> bool {
        self.flags.load().p2p_only
    }

    pub fn latency_first(&self) -> bool {
        // NOTICE: p2p only is conflict with latency first
        let flags = self.flags.load();
        flags.latency_first && !flags.p2p_only
    }

    fn is_port_in_running_listeners(&self, port: u16, is_udp: bool) -> bool {
        self.running_listeners
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.port() == Some(port) && matches_protocol!(x, Protocol::UDP) == is_udp)
    }

    pub fn is_local_ip(&self, ip: &IpAddr) -> bool {
        let _guard = self.net_ns.guard();
        self.is_ip_local_virtual_ip(ip) || std::net::UdpSocket::bind(format!("{ip}:0")).is_ok()
    }

    pub fn is_protected_tcp_port(&self, port: u16) -> bool {
        protected_port::is_protected_tcp_port(port)
    }

    #[tracing::instrument(ret, skip(self))]
    pub fn should_deny_proxy(&self, dst_addr: &SocketAddr, is_udp: bool) -> bool {
        let ip = dst_addr.ip();
        // this is an expensive operation, should be called sparingly
        // 1. tcp/kcp/quic call this only after proxy conn is established
        // 2. udp cache the result in nat entry
        if self.is_local_ip(&ip) {
            // if is local ip, make sure the port is not one of the listening ports
            self.is_port_in_running_listeners(dst_addr.port(), is_udp)
                || (!is_udp && self.is_protected_tcp_port(dst_addr.port()))
        } else {
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        common::{config::TomlConfigLoader, new_peer_id, stun::MockStunInfoCollector},
        proto::common::NatType,
    };

    use super::*;

    #[tokio::test]
    async fn test_global_ctx() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut subscriber = global_ctx.subscribe();
        let mut peer_subscriber = global_ctx.subscribe_peer_events().unwrap();
        let peer_id = new_peer_id();
        global_ctx.issue_event(GlobalCtxEvent::PeerAdded(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerRemoved(peer_id));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default()));
        global_ctx.issue_event(GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default()));

        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnAdded(PeerConnInfo::default())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::PeerConnRemoved(PeerConnInfo::default())
        );
        assert_eq!(
            peer_subscriber.recv().await.unwrap(),
            PeerContextEvent::PeerAdded(peer_id)
        );
        assert_eq!(
            peer_subscriber.recv().await.unwrap(),
            PeerContextEvent::PeerRemoved(peer_id)
        );
        assert_eq!(
            peer_subscriber.recv().await.unwrap(),
            PeerContextEvent::PeerConnAdded
        );
        assert_eq!(
            peer_subscriber.recv().await.unwrap(),
            PeerContextEvent::PeerConnRemoved
        );
    }

    #[tokio::test]
    async fn test_tun_device_name_tracks_explicit_runtime_state() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        assert_eq!(global_ctx.get_tun_device_name(), None);

        global_ctx.issue_event(GlobalCtxEvent::TunDeviceReady("ignored".to_string()));
        assert_eq!(global_ctx.get_tun_device_name(), None);

        let mut subscriber = global_ctx.subscribe();

        global_ctx.set_tun_device_ready("easytier0".to_string());
        assert_eq!(
            global_ctx.get_tun_device_name(),
            Some("easytier0".to_string())
        );
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceReady("easytier0".to_string())
        );

        global_ctx.set_tun_device_error("closed".to_string());
        assert_eq!(global_ctx.get_tun_device_name(), None);
        assert_eq!(
            subscriber.recv().await.unwrap(),
            GlobalCtxEvent::TunDeviceError("closed".to_string())
        );
    }

    #[tokio::test]
    async fn trusted_key_source_lookup_is_precise() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let network_name = "net1";
        let pubkey = vec![1; 32];

        global_ctx.update_trusted_keys(
            std::collections::HashMap::from([(
                pubkey.clone(),
                TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
            network_name,
        );

        assert!(global_ctx.is_pubkey_trusted(&pubkey, network_name));
        assert!(!global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfNode,
        ));
        assert!(global_ctx.is_pubkey_trusted_with_source(
            &pubkey,
            network_name,
            TrustedKeySource::OspfCredential,
        ));
    }

    #[tokio::test]
    async fn set_flags_keeps_derived_feature_flags_in_sync() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut feature_flags = global_ctx.get_feature_flags();
        feature_flags.avoid_relay_data = true;
        feature_flags.is_public_server = true;
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_kcp_input = true;
        flags.disable_relay_kcp = true;
        flags.disable_quic_input = true;
        flags.disable_relay_quic = true;
        flags.need_p2p = true;
        flags.disable_p2p = true;
        global_ctx.set_flags(flags);

        let feature_flags = global_ctx.get_feature_flags();
        assert!(!feature_flags.kcp_input);
        assert!(feature_flags.no_relay_kcp);
        assert!(!feature_flags.quic_input);
        assert!(feature_flags.no_relay_quic);
        assert!(feature_flags.need_p2p);
        assert!(feature_flags.disable_p2p);
        assert!(feature_flags.support_conn_list_sync);
        assert!(feature_flags.avoid_relay_data);
        assert!(feature_flags.is_public_server);
        assert!(!feature_flags.ipv6_public_addr_provider);
    }

    #[tokio::test]
    async fn set_base_advertised_feature_flags_applies_current_values() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let feature_flags = PeerFeatureFlag {
            kcp_input: false,
            no_relay_kcp: true,
            quic_input: false,
            no_relay_quic: true,
            is_public_server: true,
            ..Default::default()
        };
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        assert_eq!(global_ctx.get_feature_flags(), feature_flags);
    }

    #[tokio::test]
    async fn set_base_advertised_feature_flags_keeps_disable_relay_data_effective() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        let mut feature_flags = global_ctx.get_feature_flags();
        feature_flags.avoid_relay_data = false;
        feature_flags.is_public_server = true;
        global_ctx.set_base_advertised_feature_flags(feature_flags);

        let advertised_feature_flags = global_ctx.get_feature_flags();
        assert!(advertised_feature_flags.avoid_relay_data);
        assert!(advertised_feature_flags.is_public_server);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        let advertised_feature_flags = global_ctx.get_feature_flags();
        assert!(!advertised_feature_flags.avoid_relay_data);
        assert!(advertised_feature_flags.is_public_server);
    }

    #[tokio::test]
    async fn disable_relay_data_sets_avoid_relay_feature_flag() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(!global_ctx.get_feature_flags().avoid_relay_data);

        global_ctx.set_avoid_relay_data_preference(true);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags().clone();
        flags.disable_relay_data = false;
        global_ctx.set_flags(flags);

        assert!(global_ctx.get_feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn should_deny_proxy_for_process_wide_rpc_port() {
        protected_port::clear_protected_tcp_ports_for_test();
        protected_port::register_protected_tcp_port(15888);

        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let rpc_addr = SocketAddr::from(([127, 0, 0, 1], 15888));
        let other_tcp_addr = SocketAddr::from(([127, 0, 0, 1], 15889));

        assert!(global_ctx.should_deny_proxy(&rpc_addr, false));
        assert!(!global_ctx.should_deny_proxy(&rpc_addr, true));
        assert!(!global_ctx.should_deny_proxy(&other_tcp_addr, false));

        protected_port::clear_protected_tcp_ports_for_test();
    }

    #[tokio::test]
    async fn virtual_ipv6_and_public_ipv6_lease_are_stored_separately() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let virtual_ipv6 = "fd00::1/64".parse().unwrap();
        let public_ipv6 = "2001:db8::2/64".parse().unwrap();

        global_ctx.set_ipv6(Some(virtual_ipv6));
        global_ctx.set_public_ipv6_lease(Some(public_ipv6));

        assert_eq!(global_ctx.get_ipv6(), Some(virtual_ipv6));
        assert_eq!(global_ctx.get_public_ipv6_lease(), Some(public_ipv6));
    }

    #[tokio::test]
    async fn public_ipv6_lease_is_treated_as_local_ip() {
        protected_port::clear_protected_tcp_ports_for_test();

        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let public_ipv6 = "2001:db8::2/64".parse().unwrap();
        let listener: url::Url = "tcp://[2001:db8::2]:11010".parse().unwrap();
        global_ctx.set_public_ipv6_lease(Some(public_ipv6));
        global_ctx.add_running_listener(listener);

        let ip = std::net::IpAddr::V6(public_ipv6.address());
        let socket = SocketAddr::from((public_ipv6.address(), 11010));

        assert!(global_ctx.is_ip_local_virtual_ip(&ip));
        assert!(global_ctx.should_deny_proxy(&socket, false));

        protected_port::clear_protected_tcp_ports_for_test();
    }

    pub fn get_mock_global_ctx_with_network(
        network_identy: Option<NetworkIdentity>,
    ) -> ArcGlobalCtx {
        let config_fs = TomlConfigLoader::default();
        config_fs.set_inst_name(format!("test_{}", config_fs.get_id()));
        config_fs.set_network_identity(network_identy.unwrap_or_default());

        let ctx = Arc::new(GlobalCtx::new(config_fs));
        ctx.replace_stun_info_collector(Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
        }));
        ctx
    }

    pub fn get_mock_global_ctx() -> ArcGlobalCtx {
        get_mock_global_ctx_with_network(None)
    }
}

use std::{
    collections::{BTreeSet, HashMap, hash_map::DefaultHasher},
    hash::Hasher,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use super::{
    PeerId,
    config::{ConfigLoader, DEFAULT_CONNECTION_PRIORITY, Flags, ListenerConfig},
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
};
use crate::{
    common::{
        config::ProxyNetworkConfig, shrink_dashmap, stats_manager::StatsManager,
        token_bucket::TokenBucketManager,
    },
    peers::{acl_filter::AclFilter, credential_manager::CredentialManager},
    proto::{
        acl::GroupIdentity,
        api::{config::InstanceConfigPatch, instance::PeerConnInfo},
        common::{PeerFeatureFlag, PortForwardConfigPb},
        peer_rpc::PeerGroupInfo,
    },
    rpc_service::protected_port,
    tunnel::matches_protocol,
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

    CredentialChanged,
}

pub type EventBus = tokio::sync::broadcast::Sender<GlobalCtxEvent>;
pub type EventBusSubscriber = tokio::sync::broadcast::Receiver<GlobalCtxEvent>;

/// Source of a trusted public key from OSPF route propagation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeySource {
    /// Peer node's noise static pubkey
    OspfNode,
    /// Admin-declared trusted credential pubkey
    OspfCredential,
}

/// Metadata for a trusted public key
#[derive(Debug, Clone)]
pub struct TrustedKeyMetadata {
    pub source: TrustedKeySource,
    /// Expiry time in Unix seconds. None means never expires.
    pub expiry_unix: Option<i64>,
}

impl TrustedKeyMetadata {
    pub fn is_expired(&self) -> bool {
        if let Some(expiry) = self.expiry_unix {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            return now >= expiry;
        }
        false
    }
}

// key is (pubkey, network-name)
pub type TrustedKeyMap = HashMap<Vec<u8>, TrustedKeyMetadata>;

struct TrustedKeyMapManager {
    network_trusted_keys: DashMap<String, ArcSwap<TrustedKeyMap>>,
}

impl TrustedKeyMapManager {
    pub fn new() -> Self {
        Self {
            network_trusted_keys: DashMap::new(),
        }
    }

    pub fn update_trusted_keys(&self, network_name: &str, trusted_keys: TrustedKeyMap) {
        match self.network_trusted_keys.entry(network_name.to_string()) {
            dashmap::Entry::Vacant(entry) => {
                entry.insert(ArcSwap::new(Arc::new(trusted_keys)));
            }
            dashmap::Entry::Occupied(entry) => {
                entry.get().store(Arc::new(trusted_keys));
            }
        }
    }

    pub fn remove_trusted_keys(&self, network_name: &str) {
        self.network_trusted_keys.remove(network_name);
        shrink_dashmap(&self.network_trusted_keys, None);
    }

    pub fn verify_trusted_key(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.verify_trusted_key_with_source(pubkey, network_name, None)
    }

    pub fn verify_trusted_key_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: Option<TrustedKeySource>,
    ) -> bool {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return false;
        };

        let Some(metadata) = trusted_keys.get(&pubkey.to_vec()) else {
            return false;
        };

        if let Some(source) = source {
            metadata.source == source && !metadata.is_expired()
        } else {
            !metadata.is_expired()
        }
    }

    pub fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        let Some(trusted_keys) = self
            .network_trusted_keys
            .get(network_name)
            .map(|v| v.load_full())
        else {
            return Vec::new();
        };

        let mut items = trusted_keys
            .iter()
            .filter(|(_, metadata)| !metadata.is_expired())
            .map(|(pubkey, metadata)| (pubkey.clone(), metadata.clone()))
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.0.cmp(&right.0));
        items
    }
}

pub struct GlobalCtx {
    pub inst_name: String,
    pub id: uuid::Uuid,
    pub config: Box<dyn ConfigLoader>,
    pub net_ns: NetNS,
    pub network: NetworkIdentity,

    event_bus: EventBus,

    cached_ipv4: AtomicCell<Option<cidr::Ipv4Inet>>,
    cached_ipv6: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_lease: AtomicCell<Option<cidr::Ipv6Inet>>,
    public_ipv6_routes: Mutex<BTreeSet<std::net::Ipv6Addr>>,
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<ListenerConfig>>,
    advertised_ipv6_public_addr_prefix: Mutex<Option<cidr::Ipv6Cidr>>,

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

impl GlobalCtx {
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
        if let Err(e) = self.event_bus.send(event.clone()) {
            tracing::warn!(
                "Failed to send event: {:?}, error: {:?}, receiver count: {}",
                event,
                e,
                self.event_bus.receiver_count()
            );
        }
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
        self.running_listeners
            .lock()
            .unwrap()
            .iter()
            .map(|listener| listener.url.clone())
            .collect()
    }

    pub fn get_running_listener_configs(&self) -> Vec<ListenerConfig> {
        self.running_listeners.lock().unwrap().clone()
    }

    pub fn add_running_listener(&self, url: url::Url) {
        self.add_running_listener_with_priority(url, DEFAULT_CONNECTION_PRIORITY);
    }

    pub fn add_running_listener_with_priority(&self, url: url::Url, priority: u32) {
        let mut l = self.running_listeners.lock().unwrap();
        if let Some(listener) = l.iter_mut().find(|listener| listener.url == url) {
            listener.priority = priority;
        } else {
            l.push(ListenerConfig::new(url, priority));
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
        let mut key = [0u8; 16];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..8]);
        key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&key[0..16]);
        key
    }

    pub fn get_256_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        let secret = self
            .config
            .get_network_identity()
            .network_secret
            .unwrap_or_default();
        // fill key according to network secret
        let mut hasher = DefaultHasher::new();
        hasher.write(secret.as_bytes());
        hasher.write(b"easytier-256bit-key"); // 添加固定盐值以区分128位和256位密钥

        // 生成32字节密钥
        for i in 0..4 {
            let chunk_start = i * 8;
            let chunk_end = chunk_start + 8;
            hasher.write(&key[0..chunk_start]);
            hasher.write(&[i as u8]); // 添加索引以确保每个8字节块都不同
            key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
        }
        key
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
        self.running_listeners.lock().unwrap().iter().any(|x| {
            x.url.port() == Some(port) && matches_protocol!(&x.url, Protocol::UDP) == is_udp
        })
    }

    #[tracing::instrument(ret, skip(self))]
    pub fn should_deny_proxy(&self, dst_addr: &SocketAddr, is_udp: bool) -> bool {
        let _g = self.net_ns.guard();
        let ip = dst_addr.ip();
        // first check if ip is an EasyTier-managed local address
        // then try bind this ip, if succ means it is local ip
        let dst_is_local_et_ip = self.is_ip_local_virtual_ip(&ip);
        // this is an expensive operation, should be called sparingly
        // 1. tcp/kcp/quic call this only after proxy conn is established
        // 2. udp cache the result in nat entry
        let dst_is_local_phy_ip = std::net::UdpSocket::bind(format!("{}:0", ip)).is_ok();

        tracing::trace!(
            "check should_deny_proxy: dst_addr={}, dst_is_local_et_ip={}, dst_is_local_phy_ip={}, is_udp={}",
            dst_addr,
            dst_is_local_et_ip,
            dst_is_local_phy_ip,
            is_udp
        );

        if dst_is_local_et_ip || dst_is_local_phy_ip {
            // if is local ip, make sure the port is not one of the listening ports
            self.is_port_in_running_listeners(dst_addr.port(), is_udp)
                || (!is_udp && protected_port::is_protected_tcp_port(dst_addr.port()))
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
    }

    #[tokio::test]
    async fn trusted_key_source_lookup_is_precise() {
        let config = TomlConfigLoader::default();
        let global_ctx = GlobalCtx::new(config);
        let network_name = "net1";
        let pubkey = vec![1; 32];

        global_ctx.update_trusted_keys(
            HashMap::from([(
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

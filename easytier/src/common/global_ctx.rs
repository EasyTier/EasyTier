use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::{
    hash::Hasher,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use dashmap::DashMap;

use crate::common::config::ProxyNetworkConfig;
use crate::common::shrink_dashmap;
use crate::common::stats_manager::StatsManager;
use crate::common::token_bucket::TokenBucketManager;
use crate::peers::acl_filter::AclFilter;
use crate::peers::credential_manager::CredentialManager;
use crate::proto::acl::GroupIdentity;
use crate::proto::api::config::InstanceConfigPatch;
use crate::proto::api::instance::PeerConnInfo;
use crate::proto::common::{PeerFeatureFlag, PortForwardConfigPb};
use crate::proto::peer_rpc::PeerGroupInfo;
use crossbeam::atomic::AtomicCell;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::{
    config::{ConfigLoader, Flags},
    netns::NetNS,
    network::IPCollector,
    stun::{StunInfoCollector, StunInfoCollectorTrait},
    PeerId,
};

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

    Connecting(url::Url),
    ConnectError(String, String, String), // (dst, ip version, error message)

    VpnPortalStarted(String),                    // (portal)
    VpnPortalClientConnected(String, String),    // (portal, client ip)
    VpnPortalClientDisconnected(String, String), // (portal, client ip)

    DhcpIpv4Changed(Option<cidr::Ipv4Inet>, Option<cidr::Ipv4Inet>), // (old, new)
    DhcpIpv4Conflicted(Option<cidr::Ipv4Inet>),

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
    cached_proxy_cidrs: AtomicCell<Option<Vec<ProxyNetworkConfig>>>,

    ip_collector: Mutex<Option<Arc<IPCollector>>>,

    hostname: Mutex<String>,

    stun_info_collection: Mutex<Arc<dyn StunInfoCollectorTrait>>,

    running_listeners: Mutex<Vec<url::Url>>,

    enable_exit_node: bool,
    proxy_forward_by_system: bool,
    no_tun: bool,
    p2p_only: bool,

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

        let enable_exit_node = config_fs.get_flags().enable_exit_node || cfg!(target_env = "ohos");
        let proxy_forward_by_system = config_fs.get_flags().proxy_forward_by_system;
        let no_tun = config_fs.get_flags().no_tun;
        let p2p_only = config_fs.get_flags().p2p_only;

        let feature_flags = PeerFeatureFlag {
            kcp_input: !config_fs.get_flags().disable_kcp_input,
            no_relay_kcp: config_fs.get_flags().disable_relay_kcp,
            support_conn_list_sync: true, // Enable selective peer list sync by default
            quic_input: !config_fs.get_flags().disable_quic_input,
            no_relay_quic: config_fs.get_flags().disable_relay_quic,
            need_p2p: config_fs.get_flags().need_p2p,
            ..Default::default()
        };

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
            cached_proxy_cidrs: AtomicCell::new(None),

            ip_collector: Mutex::new(Some(Arc::new(IPCollector::new(
                net_ns,
                stun_info_collector.clone(),
            )))),

            hostname: Mutex::new(hostname),

            stun_info_collection: Mutex::new(stun_info_collector),

            running_listeners: Mutex::new(Vec::new()),

            enable_exit_node,
            proxy_forward_by_system,
            no_tun,
            p2p_only,

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
            IpAddr::V6(v6) => self.get_ipv6().map(|x| x.address() == *v6).unwrap_or(false),
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
        self.config.get_flags()
    }

    pub fn set_flags(&self, flags: Flags) {
        self.config.set_flags(flags);
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
        self.enable_exit_node
    }

    pub fn proxy_forward_by_system(&self) -> bool {
        self.proxy_forward_by_system
    }

    pub fn no_tun(&self) -> bool {
        self.no_tun
    }

    pub fn get_feature_flags(&self) -> PeerFeatureFlag {
        self.feature_flags.load()
    }

    pub fn set_feature_flags(&self, flags: PeerFeatureFlag) {
        self.feature_flags.store(flags);
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
        self.p2p_only
    }

    pub fn latency_first(&self) -> bool {
        // NOTICE: p2p only is conflict with latency first
        self.config.get_flags().latency_first && !self.p2p_only
    }

    fn is_port_in_running_listeners(&self, port: u16, is_udp: bool) -> bool {
        let check_proto = |listener_proto: &str| {
            let listener_is_udp = matches!(listener_proto, "udp" | "wg");
            listener_is_udp == is_udp
        };
        self.running_listeners
            .lock()
            .unwrap()
            .iter()
            .any(|x| x.port() == Some(port) && check_proto(x.scheme()))
    }

    #[tracing::instrument(ret, skip(self))]
    pub fn should_deny_proxy(&self, dst_addr: &SocketAddr, is_udp: bool) -> bool {
        let _g = self.net_ns.guard();
        let ip = dst_addr.ip();
        // first check if ip is virtual ip
        // then try bind this ip, if succ means it is local ip
        let dst_is_local_virtual_ip = self.is_ip_local_virtual_ip(&ip);
        // this is an expensive operation, should be called sparingly
        // 1. tcp/kcp/quic call this only after proxy conn is established
        // 2. udp cache the result in nat entry
        let dst_is_local_phy_ip = std::net::UdpSocket::bind(format!("{}:0", ip)).is_ok();

        tracing::trace!(
            "check should_deny_proxy: dst_addr={}, dst_is_local_virtual_ip={}, dst_is_local_phy_ip={}, is_udp={}",
            dst_addr,
            dst_is_local_virtual_ip,
            dst_is_local_phy_ip,
            is_udp
        );

        if dst_is_local_virtual_ip || dst_is_local_phy_ip {
            // if is local ip, make sure the port is not one of the listening ports
            self.is_port_in_running_listeners(dst_addr.port(), is_udp)
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

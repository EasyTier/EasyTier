use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use dashmap::DashMap;
use easytier_proto::{
    acl::Acl,
    common::{
        FlagsInConfig, LimiterConfig, PeerFeatureFlag, SecureModeConfig, StunInfo, TunnelInfo,
    },
    peer_rpc::{PeerGroupInfo, TrustedCredentialPubkeyProof},
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub use crate::config::{NetworkIdentity, NetworkSecretDigest};
use crate::{
    config::{
        CoreConfig, IpPrefix, NodeConfig, PeerId, PeerPolicyConfig, ProxyNetworkConfig,
        RouteConfig, TrafficConfig,
    },
    peers::{credential_manager::CredentialManager, util::shrink_dashmap},
    token_bucket::TokenBucketManager,
};

pub const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";

#[async_trait]
pub trait ByteLimiter: Send + Sync {
    async fn consume(&self, bytes: u64);

    fn try_consume(&self, bytes: u64) -> bool;
}

#[async_trait]
impl ByteLimiter for () {
    async fn consume(&self, _bytes: u64) {}

    fn try_consume(&self, _bytes: u64) -> bool {
        true
    }
}

pub type ArcByteLimiter = Arc<dyn ByteLimiter>;

#[derive(Debug, Clone)]
pub enum PeerEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(easytier_proto::core_peer::peer::PeerConnInfo),
    PeerConnRemoved(easytier_proto::core_peer::peer::PeerConnInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerContextEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded,
    PeerConnRemoved,
}

pub type PeerContextEventSubscriber = tokio::sync::broadcast::Receiver<PeerContextEvent>;

#[async_trait]
pub trait PeerRuntimeChangeSubscriber: Send {
    /// Wait for the next change. Returns false when the stream is closed.
    async fn changed(&mut self) -> bool;
}

pub type BoxPeerRuntimeChangeSubscriber = Box<dyn PeerRuntimeChangeSubscriber>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRuntimeConfig {
    pub core: CoreConfig,
    pub network_identity: NetworkIdentity,
    pub stun_info: StunInfo,
    pub feature_flags: PeerFeatureFlag,
    pub secure_mode: Option<SecureModeConfig>,
    pub host_routing: HostRoutingPolicy,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoutingPolicy {
    /// Route otherwise-unreachable external IPv4 traffic through this node and
    /// keep self-delivered packets eligible for the host TUN/proxy path.
    pub local_exit_node_fallback: bool,
}

/// One normalized peer configuration version submitted by a host.
#[derive(Debug, Clone)]
pub struct PeerRuntimeSnapshot {
    pub runtime: PeerRuntimeConfig,
    pub flags: FlagsInConfig,
    pub vpn_portal_cidr: Option<Ipv4Cidr>,
    pub pinned_peers: Vec<(url::Url, Option<String>)>,
    pub peer_group_memberships: Vec<PeerGroupIdentity>,
    pub acl_group_declarations: Vec<PeerGroupIdentity>,
    pub ospf_update_my_foreign_network_interval_sec: u64,
    pub max_direct_conns_per_peer_in_foreign_network: usize,
    pub hmac_secret_digest: bool,
}

impl PeerRuntimeSnapshot {
    pub fn new(runtime: PeerRuntimeConfig, flags: FlagsInConfig) -> Self {
        Self {
            runtime,
            flags,
            vpn_portal_cidr: None,
            pinned_peers: Vec::new(),
            peer_group_memberships: Vec::new(),
            acl_group_declarations: Vec::new(),
            ospf_update_my_foreign_network_interval_sec: 10,
            max_direct_conns_per_peer_in_foreign_network: 3,
            hmac_secret_digest: false,
        }
    }
}

impl Default for PeerRuntimeSnapshot {
    fn default() -> Self {
        Self::new(
            PeerRuntimeConfig {
                core: CoreConfig::default(),
                network_identity: NetworkIdentity::default(),
                stun_info: StunInfo::default(),
                feature_flags: PeerFeatureFlag::default(),
                secure_mode: None,
                host_routing: HostRoutingPolicy::default(),
            },
            FlagsInConfig::default(),
        )
    }
}

/// Supplies the current core-owned peer configuration version.
pub trait PeerRuntimeConfigSource: Send + Sync {
    fn peer_runtime_snapshot(&self) -> Arc<PeerRuntimeSnapshot>;
}

/// Live observations and side effects that cannot be represented as submitted
/// peer configuration.
pub trait PeerRuntimeSupport: Send + Sync {
    fn stun_info(&self) -> StunInfo {
        StunInfo::default()
    }

    fn public_ipv6_lease_contains(&self, _ip: &std::net::Ipv6Addr) -> bool {
        false
    }

    fn avoid_relay_data_preference(&self) -> bool {
        false
    }

    fn set_avoid_relay_data_preference(&self, _avoid_relay_data: bool) -> bool {
        false
    }

    fn subscribe_runtime_changes(&self) -> Option<BoxPeerRuntimeChangeSubscriber> {
        None
    }

    fn public_ipv6_provider_enabled(&self) -> bool {
        false
    }

    fn easytier_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        None
    }

    fn is_pubkey_trusted(&self, _pubkey: &[u8], _network_name: &str) -> bool {
        false
    }

    fn is_pubkey_trusted_with_source(
        &self,
        _pubkey: &[u8],
        _network_name: &str,
        _source: TrustedKeySource,
    ) -> bool {
        false
    }

    fn list_trusted_keys(&self, _network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        Vec::new()
    }

    fn trusted_credential_pubkeys(
        &self,
        _network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        Vec::new()
    }

    fn remove_expired_credentials(&self) -> bool {
        false
    }

    fn issue_credential_changed(&self) {}

    fn update_trusted_keys(&self, _keys: TrustedKeyMap, _network_name: &str) {}

    fn remove_trusted_keys(&self, _network_name: &str) {}

    fn record_control_tx(&self, _network_name: &str, _bytes: u64) {}

    fn record_control_rx(&self, _network_name: &str, _bytes: u64) {}

    fn recv_limiter(&self, _key: &str, _bps: u64) -> Option<ArcByteLimiter> {
        None
    }

    fn issue_event(&self, _event: PeerEvent) {}

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        None
    }
}

/// Peer context whose configuration comes exclusively from a core-owned
/// submitted snapshot while live effects stay behind a narrow support seam.
#[derive(Clone)]
pub struct SubmittedPeerContext {
    config: Arc<dyn PeerRuntimeConfigSource>,
    support: Arc<dyn PeerRuntimeSupport>,
}

impl SubmittedPeerContext {
    pub fn new(
        config: Arc<dyn PeerRuntimeConfigSource>,
        support: Arc<dyn PeerRuntimeSupport>,
    ) -> Self {
        Self { config, support }
    }

    fn snapshot(&self) -> Arc<PeerRuntimeSnapshot> {
        self.config.peer_runtime_snapshot()
    }
}

#[derive(Clone)]
pub(crate) struct ConfigPeerContext {
    runtime: PeerRuntimeConfig,
    flags: FlagsInConfig,
    peer_events: tokio::sync::broadcast::Sender<PeerContextEvent>,
    support: Arc<ConfigPeerContextSupport>,
}

#[derive(Default)]
struct ConfigLimiterState {
    manager: Option<TokenBucketManager>,
    stopped: bool,
}

#[derive(Default)]
pub(crate) struct ConfigPeerContextSupport {
    limiter_state: Mutex<ConfigLimiterState>,
    acl: ArcSwapOption<Acl>,
    credentials: Arc<CredentialManager>,
    trusted_keys: TrustedKeyMapManager,
}

impl ConfigPeerContextSupport {
    fn new(credentials: Arc<CredentialManager>) -> Self {
        Self {
            credentials,
            ..Default::default()
        }
    }

    pub(crate) fn set_acl(&self, acl: Option<Acl>) {
        self.acl.store(acl.map(Arc::new));
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        let Some(acl) = self.acl.load_full() else {
            return Vec::new();
        };
        let Some(group) = acl.acl_v1.as_ref().and_then(|acl| acl.group.as_ref()) else {
            return Vec::new();
        };
        let memberships: HashSet<_> = group.members.iter().collect();
        group
            .declares
            .iter()
            .filter(|identity| memberships.contains(&identity.group_name))
            .map(|identity| {
                PeerGroupInfo::generate_with_proof(
                    identity.group_name.clone(),
                    identity.group_secret.clone(),
                    peer_id,
                )
            })
            .collect()
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        let Some(acl) = self.acl.load_full() else {
            return Vec::new();
        };
        acl.acl_v1
            .as_ref()
            .and_then(|acl| acl.group.as_ref())
            .map_or_else(Vec::new, |group| {
                group
                    .declares
                    .iter()
                    .map(|identity| PeerGroupIdentity {
                        group_name: identity.group_name.clone(),
                        group_secret: identity.group_secret.clone(),
                    })
                    .collect()
            })
    }

    fn get_or_create_limiter(&self, key: &str, bps: u64) -> Option<ArcByteLimiter> {
        let mut state = self.limiter_state.lock().unwrap();
        if state.stopped {
            return None;
        }
        let manager = state.manager.get_or_insert_with(TokenBucketManager::new);
        Some(
            manager.get_or_create(
                key,
                LimiterConfig {
                    burst_rate: None,
                    bps: Some(bps),
                    fill_duration_ms: None,
                }
                .into(),
            ),
        )
    }

    pub(crate) async fn stop(&self) {
        let manager = {
            let mut state = self.limiter_state.lock().unwrap();
            state.stopped = true;
            state.manager.take()
        };
        if let Some(manager) = manager {
            manager.stop().await;
        }
    }
}

impl ConfigPeerContext {
    pub(crate) fn new(runtime: PeerRuntimeConfig, credentials: Arc<CredentialManager>) -> Self {
        Self {
            runtime,
            flags: FlagsInConfig::default(),
            peer_events: tokio::sync::broadcast::channel(100).0,
            support: Arc::new(ConfigPeerContextSupport::new(credentials)),
        }
    }

    pub(crate) fn with_flags(mut self, flags: FlagsInConfig) -> Self {
        self.flags = flags;
        self
    }

    pub(crate) fn support(&self) -> Arc<ConfigPeerContextSupport> {
        self.support.clone()
    }
}

fn config_ipv4(value: &IpPrefix) -> Option<Ipv4Inet> {
    let IpAddr::V4(address) = value.address else {
        return None;
    };
    Ipv4Inet::new(address, value.prefix_len).ok()
}

fn config_ipv4_cidr(value: &IpPrefix) -> Option<Ipv4Cidr> {
    let IpAddr::V4(address) = value.address else {
        return None;
    };
    Ipv4Cidr::new(address, value.prefix_len).ok()
}

fn config_ipv6(value: &IpPrefix) -> Option<Ipv6Inet> {
    let IpAddr::V6(address) = value.address else {
        return None;
    };
    Ipv6Inet::new(address, value.prefix_len).ok()
}

fn ipv4_inet_to_config(value: Ipv4Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(value.address()), value.network_length())
        .expect("Ipv4Inet should always have a valid IPv4 prefix length")
}

fn ipv6_inet_to_config(value: Ipv6Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V6(value.address()), value.network_length())
        .expect("Ipv6Inet should always have a valid IPv6 prefix length")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerGroupIdentity {
    pub group_name: String,
    pub group_secret: String,
}

/// Source of a trusted public key propagated by the OSPF route layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedKeySource {
    OspfNode,
    OspfCredential,
}

#[derive(Debug, Clone)]
pub struct TrustedKeyMetadata {
    pub source: TrustedKeySource,
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

pub type TrustedKeyMap = HashMap<Vec<u8>, TrustedKeyMetadata>;

pub struct TrustedKeyMapManager {
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

impl Default for TrustedKeyMapManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Runtime dependency interface for the peers module.
///
/// `PeerContext` is intentionally scoped to `easytier-core::peers`; other core
/// modules should depend on their own narrow DTOs or traits instead of treating
/// this as a core-wide global context.
pub trait PeerContext: Send + Sync {
    fn runtime_config(&self) -> PeerRuntimeConfig {
        let network_identity = self.network_identity();
        let hostname = self.hostname();
        PeerRuntimeConfig {
            core: CoreConfig {
                node: NodeConfig {
                    peer_id: None,
                    instance_id: Some(*self.instance_id().as_bytes()),
                    hostname: (!hostname.is_empty()).then_some(hostname),
                    network_name: network_identity.network_name.clone(),
                },
                routes: RouteConfig {
                    ipv4: self.ipv4().map(ipv4_inet_to_config),
                    ipv6: self.ipv6().map(ipv6_inet_to_config),
                    ..Default::default()
                },
                peer_policy: PeerPolicyConfig::default(),
                traffic: TrafficConfig::default(),
            },
            network_identity,
            stun_info: self.stun_info(),
            feature_flags: self.feature_flags(),
            secure_mode: self.secure_mode(),
            host_routing: self.host_routing_policy(),
        }
    }

    fn host_routing_policy(&self) -> HostRoutingPolicy {
        HostRoutingPolicy::default()
    }

    fn network_identity(&self) -> NetworkIdentity;

    fn network_name(&self) -> String {
        self.network_identity().network_name
    }

    fn flags(&self) -> FlagsInConfig {
        FlagsInConfig::default()
    }

    fn disable_relay_data(&self) -> bool {
        self.flags().disable_relay_data
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        None
    }

    fn stun_info(&self) -> StunInfo {
        StunInfo::default()
    }

    fn instance_id(&self) -> uuid::Uuid {
        uuid::Uuid::nil()
    }

    fn ipv4(&self) -> Option<Ipv4Inet> {
        None
    }

    fn ipv6(&self) -> Option<Ipv6Inet> {
        None
    }

    fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.ipv6()
            .map(|addr| addr.address() == *ip)
            .unwrap_or(false)
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self
                .ipv4()
                .map(|addr| addr.address() == *v4)
                .unwrap_or(false),
            IpAddr::V6(v6) => self.is_ip_local_ipv6(v6),
        }
    }

    fn p2p_only(&self) -> bool {
        self.flags().p2p_only
    }

    fn latency_first(&self) -> bool {
        let flags = self.flags();
        flags.latency_first && !flags.p2p_only
    }

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        Vec::new()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        Vec::new()
    }

    fn vpn_portal_cidr(&self) -> Option<Ipv4Cidr> {
        None
    }

    fn hostname(&self) -> String {
        String::new()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        PeerFeatureFlag::default()
    }

    fn set_avoid_relay_data_preference(&self, _avoid_relay_data: bool) -> bool {
        false
    }

    fn subscribe_runtime_changes(&self) -> Option<BoxPeerRuntimeChangeSubscriber> {
        None
    }

    fn easytier_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        10
    }

    fn max_direct_conns_per_peer_in_foreign_network(&self) -> usize {
        3
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        None
    }

    fn is_ip_in_same_network(&self, _ip: &IpAddr) -> bool {
        false
    }

    fn peer_groups(&self, _peer_id: PeerId) -> Vec<PeerGroupInfo> {
        Vec::new()
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        Vec::new()
    }

    fn pinned_remote_static_pubkey(&self, _tunnel_info: Option<&TunnelInfo>) -> Option<String> {
        None
    }

    fn secret_proof(&self, _challenge: &[u8]) -> Option<Hmac<Sha256>> {
        None
    }

    fn secret_digest(&self, network_identity: &NetworkIdentity) -> Vec<u8> {
        network_identity
            .secret_digest()
            .unwrap_or_default()
            .to_vec()
    }

    fn is_pubkey_trusted(&self, _pubkey: &[u8], _network_name: &str) -> bool {
        false
    }

    fn is_pubkey_trusted_with_source(
        &self,
        _pubkey: &[u8],
        _network_name: &str,
        _source: TrustedKeySource,
    ) -> bool {
        false
    }

    fn list_trusted_keys(&self, _network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        Vec::new()
    }

    fn trusted_credential_pubkeys(
        &self,
        _network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        Vec::new()
    }

    fn remove_expired_credentials(&self) -> bool {
        false
    }

    fn issue_credential_changed(&self) {}

    fn update_trusted_keys(&self, _keys: TrustedKeyMap, _network_name: &str) {}

    fn remove_trusted_keys(&self, _network_name: &str) {}

    fn record_control_tx(&self, _network_name: &str, _bytes: u64) {}

    fn record_control_rx(&self, _network_name: &str, _bytes: u64) {}

    fn recv_limiter(
        &self,
        _network_name: &str,
        _is_foreign_network: bool,
    ) -> Option<ArcByteLimiter> {
        None
    }

    fn foreign_forward_limiter(&self, _network_name: &str) -> Option<ArcByteLimiter> {
        None
    }

    fn issue_event(&self, _event: PeerEvent) {}

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        None
    }
}

pub type ArcPeerContext = Arc<dyn PeerContext>;

#[derive(Debug, Clone)]
pub struct NoopPeerContext {
    network_identity: NetworkIdentity,
    flags: FlagsInConfig,
    secure_mode: Option<SecureModeConfig>,
}

impl NoopPeerContext {
    pub fn new(network_identity: NetworkIdentity) -> Self {
        Self {
            network_identity,
            flags: FlagsInConfig::default(),
            secure_mode: None,
        }
    }

    pub fn with_flags(mut self, flags: FlagsInConfig) -> Self {
        self.flags = flags;
        self
    }

    pub fn with_secure_mode(mut self, secure_mode: Option<SecureModeConfig>) -> Self {
        self.secure_mode = secure_mode;
        self
    }
}

impl Default for NoopPeerContext {
    fn default() -> Self {
        Self::new(NetworkIdentity::default())
    }
}

pub fn secret_proof_from_secret(secret: &str, challenge: &[u8]) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(SECRET_PROOF_PREFIX);
    mac.update(challenge);
    Some(mac)
}

impl PeerContext for NoopPeerContext {
    fn network_identity(&self) -> NetworkIdentity {
        self.network_identity.clone()
    }

    fn flags(&self) -> FlagsInConfig {
        self.flags.clone()
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.secure_mode.clone()
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let secret = self.network_identity.network_secret.as_ref()?;
        secret_proof_from_secret(secret, challenge)
    }
}

impl PeerContext for ConfigPeerContext {
    fn runtime_config(&self) -> PeerRuntimeConfig {
        self.runtime.clone()
    }

    fn network_identity(&self) -> NetworkIdentity {
        self.runtime.network_identity.clone()
    }

    fn flags(&self) -> FlagsInConfig {
        self.flags.clone()
    }

    fn host_routing_policy(&self) -> HostRoutingPolicy {
        self.runtime.host_routing
    }

    fn issue_event(&self, event: PeerEvent) {
        let event = match event {
            PeerEvent::PeerAdded(peer_id) => PeerContextEvent::PeerAdded(peer_id),
            PeerEvent::PeerRemoved(peer_id) => PeerContextEvent::PeerRemoved(peer_id),
            PeerEvent::PeerConnAdded(_) => PeerContextEvent::PeerConnAdded,
            PeerEvent::PeerConnRemoved(_) => PeerContextEvent::PeerConnRemoved,
        };
        let _ = self.peer_events.send(event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        Some(self.peer_events.subscribe())
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.runtime.secure_mode.clone()
    }

    fn stun_info(&self) -> StunInfo {
        self.runtime.stun_info.clone()
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.runtime
            .core
            .node
            .instance_id
            .map(uuid::Uuid::from_bytes)
            .unwrap_or_else(uuid::Uuid::nil)
    }

    fn ipv4(&self) -> Option<Ipv4Inet> {
        self.runtime.core.routes.ipv4.as_ref().and_then(config_ipv4)
    }

    fn ipv6(&self) -> Option<Ipv6Inet> {
        self.runtime.core.routes.ipv6.as_ref().and_then(config_ipv6)
    }

    fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.ipv4().is_some_and(|network| network.contains(ip)),
            IpAddr::V6(ip) => self.ipv6().is_some_and(|network| network.contains(ip)),
        }
    }

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.runtime
            .core
            .routes
            .proxy_networks
            .iter()
            .filter_map(|proxy| config_ipv4_cidr(proxy.mapped.as_ref().unwrap_or(&proxy.real)))
            .collect()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        self.runtime.core.routes.proxy_networks.clone()
    }

    fn hostname(&self) -> String {
        self.runtime.core.node.hostname.clone().unwrap_or_default()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        self.runtime.feature_flags
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        self.support.peer_groups(peer_id)
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        self.support.acl_group_declarations()
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let secret = self.runtime.network_identity.network_secret.as_ref()?;
        secret_proof_from_secret(secret, challenge)
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        if self
            .support
            .trusted_keys
            .verify_trusted_key(pubkey, network_name)
        {
            return true;
        }
        network_name == self.runtime.network_identity.network_name
            && self.support.credentials.is_pubkey_trusted(pubkey)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.support
            .trusted_keys
            .verify_trusted_key_with_source(pubkey, network_name, Some(source))
    }

    fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.support.trusted_keys.list_trusted_keys(network_name)
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        self.support.credentials.get_trusted_pubkeys(network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        self.support.credentials.remove_expired_credentials()
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.support
            .trusted_keys
            .update_trusted_keys(network_name, keys);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        self.support.trusted_keys.remove_trusted_keys(network_name);
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        let traffic = &self.runtime.core.traffic;
        let foreign_limit = traffic
            .foreign_relay_bps_limit
            .or(Some(self.flags.foreign_relay_bps_limit))
            .filter(|limit| !matches!(*limit, 0 | u64::MAX));
        let instance_limit = traffic
            .instance_recv_bps_limit
            .or(Some(self.flags.instance_recv_bps_limit))
            .filter(|limit| !matches!(*limit, 0 | u64::MAX));
        let (key, bps) = if is_foreign_network && let Some(limit) = foreign_limit {
            (format!("portable:foreign:{network_name}:recv"), limit)
        } else {
            ("portable:instance:recv".to_owned(), instance_limit?)
        };
        self.support.get_or_create_limiter(&key, bps)
    }

    fn foreign_forward_limiter(&self, network_name: &str) -> Option<ArcByteLimiter> {
        let bps = self
            .runtime
            .core
            .traffic
            .foreign_relay_bps_limit
            .or(Some(self.flags.foreign_relay_bps_limit))
            .filter(|limit| !matches!(*limit, 0 | u64::MAX))?;
        self.support
            .get_or_create_limiter(&format!("portable:foreign:{network_name}:forward"), bps)
    }
}

impl PeerContext for SubmittedPeerContext {
    fn runtime_config(&self) -> PeerRuntimeConfig {
        self.snapshot().runtime.clone()
    }

    fn max_direct_conns_per_peer_in_foreign_network(&self) -> usize {
        self.snapshot().max_direct_conns_per_peer_in_foreign_network
    }

    fn network_identity(&self) -> NetworkIdentity {
        self.snapshot().runtime.network_identity.clone()
    }

    fn flags(&self) -> FlagsInConfig {
        self.snapshot().flags.clone()
    }

    fn host_routing_policy(&self) -> HostRoutingPolicy {
        self.snapshot().runtime.host_routing
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.snapshot().runtime.secure_mode.clone()
    }

    fn stun_info(&self) -> StunInfo {
        self.support.stun_info()
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.snapshot()
            .runtime
            .core
            .node
            .instance_id
            .map(uuid::Uuid::from_bytes)
            .unwrap_or_else(uuid::Uuid::nil)
    }

    fn ipv4(&self) -> Option<Ipv4Inet> {
        self.snapshot()
            .runtime
            .core
            .routes
            .ipv4
            .as_ref()
            .and_then(config_ipv4)
    }

    fn ipv6(&self) -> Option<Ipv6Inet> {
        self.snapshot()
            .runtime
            .core
            .routes
            .ipv6
            .as_ref()
            .and_then(config_ipv6)
    }

    fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.ipv6().is_some_and(|address| address.address() == *ip)
            || self.support.public_ipv6_lease_contains(ip)
    }

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.snapshot()
            .runtime
            .core
            .routes
            .proxy_networks
            .iter()
            .filter_map(|proxy| config_ipv4_cidr(proxy.mapped.as_ref().unwrap_or(&proxy.real)))
            .collect()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        self.snapshot().runtime.core.routes.proxy_networks.clone()
    }

    fn vpn_portal_cidr(&self) -> Option<Ipv4Cidr> {
        self.snapshot().vpn_portal_cidr
    }

    fn hostname(&self) -> String {
        self.snapshot()
            .runtime
            .core
            .node
            .hostname
            .clone()
            .unwrap_or_default()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        let snapshot = self.snapshot();
        let mut flags = snapshot.runtime.feature_flags;
        flags.avoid_relay_data =
            snapshot.flags.disable_relay_data || self.support.avoid_relay_data_preference();
        flags.ipv6_public_addr_provider = self.support.public_ipv6_provider_enabled();
        flags
    }

    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        self.support
            .set_avoid_relay_data_preference(avoid_relay_data)
    }

    fn subscribe_runtime_changes(&self) -> Option<BoxPeerRuntimeChangeSubscriber> {
        self.support.subscribe_runtime_changes()
    }

    fn easytier_version(&self) -> String {
        self.support.easytier_version()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        self.snapshot().ospf_update_my_foreign_network_interval_sec
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        self.support.advertised_ipv6_public_addr_prefix()
    }

    fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.ipv4().is_some_and(|network| network.contains(ip)),
            IpAddr::V6(ip) => self.ipv6().is_some_and(|network| network.contains(ip)),
        }
    }

    fn pinned_remote_static_pubkey(&self, tunnel_info: Option<&TunnelInfo>) -> Option<String> {
        let remote_url = tunnel_info
            .and_then(|info| info.remote_addr.as_ref())?
            .url
            .parse::<url::Url>()
            .ok()?;
        self.snapshot()
            .pinned_peers
            .iter()
            .find(|(uri, _)| *uri == remote_url)
            .and_then(|(_, public_key)| public_key.clone())
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let snapshot = self.snapshot();
        let secret = snapshot.runtime.network_identity.network_secret.as_ref()?;
        secret_proof_from_secret(secret, challenge)
    }

    fn secret_digest(&self, network_identity: &NetworkIdentity) -> Vec<u8> {
        let snapshot = self.snapshot();
        if snapshot.hmac_secret_digest {
            snapshot
                .runtime
                .network_identity
                .network_secret
                .as_deref()
                .and_then(|secret| secret_proof_from_secret(secret, b"digest"))
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network_identity
                .secret_digest()
                .unwrap_or_default()
                .to_vec()
        }
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        self.snapshot()
            .peer_group_memberships
            .iter()
            .map(|group| {
                PeerGroupInfo::generate_with_proof(
                    group.group_name.clone(),
                    group.group_secret.clone(),
                    peer_id,
                )
            })
            .collect()
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        self.snapshot().acl_group_declarations.clone()
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        self.support.is_pubkey_trusted(pubkey, network_name)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.support
            .is_pubkey_trusted_with_source(pubkey, network_name, source)
    }

    fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.support.list_trusted_keys(network_name)
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        self.support.trusted_credential_pubkeys(network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        self.support.remove_expired_credentials()
    }

    fn issue_credential_changed(&self) {
        self.support.issue_credential_changed();
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.support.update_trusted_keys(keys, network_name);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        self.support.remove_trusted_keys(network_name);
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.support.record_control_tx(network_name, bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.support.record_control_rx(network_name, bytes);
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        let flags = &self.snapshot().flags;
        if is_foreign_network && flags.foreign_relay_bps_limit != u64::MAX {
            return self.support.recv_limiter(
                &format!("{network_name}:recv"),
                flags.foreign_relay_bps_limit,
            );
        }
        if flags.instance_recv_bps_limit != u64::MAX {
            return self
                .support
                .recv_limiter("instance:recv", flags.instance_recv_bps_limit);
        }
        None
    }

    fn foreign_forward_limiter(&self, network_name: &str) -> Option<ArcByteLimiter> {
        let bps = self.snapshot().flags.foreign_relay_bps_limit;
        (bps != u64::MAX)
            .then(|| {
                self.support
                    .recv_limiter(&format!("{network_name}:forward"), bps)
            })
            .flatten()
    }

    fn issue_event(&self, event: PeerEvent) {
        self.support.issue_event(event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        self.support.subscribe_peer_events()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestSubmittedConfig {
        snapshot: ArcSwap<PeerRuntimeSnapshot>,
    }

    impl PeerRuntimeConfigSource for TestSubmittedConfig {
        fn peer_runtime_snapshot(&self) -> Arc<PeerRuntimeSnapshot> {
            self.snapshot.load_full()
        }
    }

    #[derive(Default)]
    struct TestSubmittedSupport {
        avoid_relay_data: AtomicBool,
        limiter_keys: Mutex<Vec<String>>,
    }

    impl PeerRuntimeSupport for TestSubmittedSupport {
        fn avoid_relay_data_preference(&self) -> bool {
            self.avoid_relay_data.load(Ordering::Acquire)
        }

        fn recv_limiter(&self, key: &str, _bps: u64) -> Option<ArcByteLimiter> {
            self.limiter_keys.lock().unwrap().push(key.to_owned());
            Some(Arc::new(()))
        }
    }

    fn submitted_snapshot(hostname: &str, disable_relay_data: bool) -> PeerRuntimeSnapshot {
        let mut flags = FlagsInConfig::default();
        flags.disable_relay_data = disable_relay_data;
        PeerRuntimeSnapshot::new(
            PeerRuntimeConfig {
                core: CoreConfig {
                    node: NodeConfig {
                        hostname: Some(hostname.to_owned()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                network_identity: NetworkIdentity::default(),
                stun_info: StunInfo::default(),
                feature_flags: PeerFeatureFlag::default(),
                secure_mode: None,
                host_routing: HostRoutingPolicy::default(),
            },
            flags,
        )
    }

    #[test]
    fn submitted_peer_context_separates_config_versions_from_live_support() {
        let config = Arc::new(TestSubmittedConfig {
            snapshot: ArcSwap::from_pointee(submitted_snapshot("before", false)),
        });
        let support = Arc::new(TestSubmittedSupport::default());
        let context = SubmittedPeerContext::new(config.clone(), support.clone());

        assert_eq!(context.hostname(), "before");
        assert!(!context.feature_flags().avoid_relay_data);

        support.avoid_relay_data.store(true, Ordering::Release);
        assert!(context.feature_flags().avoid_relay_data);

        config
            .snapshot
            .store(Arc::new(submitted_snapshot("after", true)));
        support.avoid_relay_data.store(false, Ordering::Release);
        assert_eq!(context.hostname(), "after");
        assert!(context.feature_flags().avoid_relay_data);

        config
            .snapshot
            .store(Arc::new(submitted_snapshot("after", false)));
        assert!(!context.feature_flags().avoid_relay_data);
    }

    #[test]
    fn foreign_forward_limiter_is_independent_from_peer_receive_limiter() {
        let mut snapshot = submitted_snapshot("limiter", false);
        snapshot.flags.foreign_relay_bps_limit = 1024;
        let config = Arc::new(TestSubmittedConfig {
            snapshot: ArcSwap::from_pointee(snapshot),
        });
        let support = Arc::new(TestSubmittedSupport::default());
        let context = SubmittedPeerContext::new(config, support.clone());

        assert!(context.recv_limiter("foreign", true).is_some());
        assert!(context.foreign_forward_limiter("foreign").is_some());
        assert_eq!(
            support.limiter_keys.lock().unwrap().as_slice(),
            ["foreign:recv", "foreign:forward"]
        );
    }

    #[test]
    fn foreign_forward_limiter_does_not_fall_back_to_instance_limit() {
        let mut snapshot = submitted_snapshot("limiter", false);
        snapshot.flags.foreign_relay_bps_limit = u64::MAX;
        snapshot.flags.instance_recv_bps_limit = 1024;
        let config = Arc::new(TestSubmittedConfig {
            snapshot: ArcSwap::from_pointee(snapshot),
        });
        let support = Arc::new(TestSubmittedSupport::default());
        let context = SubmittedPeerContext::new(config, support.clone());

        assert!(context.recv_limiter("foreign", true).is_some());
        assert!(context.foreign_forward_limiter("foreign").is_none());
        assert_eq!(
            support.limiter_keys.lock().unwrap().as_slice(),
            ["instance:recv"]
        );
    }

    #[test]
    fn noop_peer_context_uses_runtime_secret_proof_prefix() {
        let context = NoopPeerContext::new(NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        });

        let proof = context
            .secret_proof(b"challenge")
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();
        let expected = secret_proof_from_secret("secret", b"challenge")
            .unwrap()
            .finalize()
            .into_bytes()
            .to_vec();

        assert_eq!(proof, expected);
    }

    struct RuntimeConfigContext {
        instance_id: uuid::Uuid,
    }

    impl PeerContext for RuntimeConfigContext {
        fn network_identity(&self) -> NetworkIdentity {
            NetworkIdentity {
                network_name: "net".to_string(),
                network_secret: Some("secret".to_string()),
                network_secret_digest: None,
            }
        }

        fn instance_id(&self) -> uuid::Uuid {
            self.instance_id
        }

        fn ipv4(&self) -> Option<Ipv4Inet> {
            Some("10.1.0.1/24".parse().unwrap())
        }

        fn ipv6(&self) -> Option<Ipv6Inet> {
            Some("2001:db8::1/64".parse().unwrap())
        }

        fn hostname(&self) -> String {
            "node-a".to_string()
        }
    }

    #[test]
    fn runtime_config_preserves_peer_context_snapshot() {
        let instance_id = uuid::Uuid::from_u128(0x11223344556677889900aabbccddeeff);
        let context = RuntimeConfigContext { instance_id };

        let config = context.runtime_config();

        assert_eq!(config.network_identity.network_name, "net");
        assert_eq!(config.core.node.instance_id, Some(*instance_id.as_bytes()));
        assert_eq!(config.core.node.hostname.as_deref(), Some("node-a"));
        assert_eq!(config.core.node.network_name, "net");
        assert_eq!(
            config.core.routes.ipv4,
            Some(IpPrefix::new("10.1.0.1".parse().unwrap(), 24).unwrap())
        );
        assert_eq!(
            config.core.routes.ipv6,
            Some(IpPrefix::new("2001:db8::1".parse().unwrap(), 64).unwrap())
        );
    }

    #[test]
    fn config_peer_context_reads_normalized_snapshot() {
        let instance_id = uuid::Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let runtime = PeerRuntimeConfig {
            core: CoreConfig {
                node: NodeConfig {
                    peer_id: Some(7),
                    instance_id: Some(*instance_id.as_bytes()),
                    hostname: Some("config-node".to_owned()),
                    network_name: "config-net".to_owned(),
                },
                routes: RouteConfig {
                    ipv4: Some(IpPrefix::new("10.20.0.7".parse().unwrap(), 16).unwrap()),
                    ipv6: Some(IpPrefix::new("2001:db8::7".parse().unwrap(), 64).unwrap()),
                    proxy_networks: vec![
                        crate::config::ProxyNetworkConfig {
                            real: IpPrefix::new("10.40.0.0".parse().unwrap(), 16).unwrap(),
                            mapped: Some(IpPrefix::new("10.50.0.0".parse().unwrap(), 16).unwrap()),
                        },
                        crate::config::ProxyNetworkConfig {
                            real: IpPrefix::new("10.60.0.0".parse().unwrap(), 16).unwrap(),
                            mapped: None,
                        },
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
            network_identity: NetworkIdentity {
                network_name: "config-net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            },
            stun_info: StunInfo::default(),
            feature_flags: PeerFeatureFlag::default(),
            secure_mode: Some(SecureModeConfig {
                enabled: true,
                ..Default::default()
            }),
            host_routing: HostRoutingPolicy {
                local_exit_node_fallback: true,
            },
        };
        let mut flags = FlagsInConfig::default();
        flags.p2p_only = true;
        let context = ConfigPeerContext::new(runtime.clone(), Arc::new(CredentialManager::new()))
            .with_flags(flags.clone());

        assert_eq!(context.runtime_config().core, runtime.core);
        assert_eq!(context.network_identity(), runtime.network_identity);
        assert_eq!(context.flags(), flags);
        assert_eq!(context.instance_id(), instance_id);
        assert_eq!(context.hostname(), "config-node");
        assert_eq!(context.ipv4(), Some("10.20.0.7/16".parse().unwrap()));
        assert_eq!(context.ipv6(), Some("2001:db8::7/64".parse().unwrap()));
        assert!(context.is_ip_in_same_network(&"10.20.99.1".parse().unwrap()));
        assert!(context.is_ip_in_same_network(&"2001:db8::99".parse().unwrap()));
        assert!(!context.is_ip_in_same_network(&"10.21.0.1".parse().unwrap()));
        assert_eq!(
            context.proxy_cidrs(),
            vec![
                "10.50.0.0/16".parse().unwrap(),
                "10.60.0.0/16".parse().unwrap()
            ]
        );
        assert!(context.secure_mode().unwrap().enabled);
        assert!(context.host_routing_policy().local_exit_node_fallback);

        context.support.set_acl(Some(Acl {
            acl_v1: Some(easytier_proto::acl::AclV1 {
                chains: Vec::new(),
                group: Some(easytier_proto::acl::GroupInfo {
                    declares: vec![easytier_proto::acl::GroupIdentity {
                        group_name: "ops".to_string(),
                        group_secret: "group-secret".to_string(),
                    }],
                    members: vec!["ops".to_string()],
                }),
            }),
        }));
        let groups = context.peer_groups(7);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].group_name, "ops");
        assert!(groups[0].verify("group-secret", 7));
        assert_eq!(
            context.acl_group_declarations(),
            vec![PeerGroupIdentity {
                group_name: "ops".to_string(),
                group_secret: "group-secret".to_string(),
            }]
        );

        let proof = context
            .secret_proof(b"challenge")
            .unwrap()
            .finalize()
            .into_bytes();
        let expected = secret_proof_from_secret("secret", b"challenge")
            .unwrap()
            .finalize()
            .into_bytes();
        assert_eq!(proof, expected);
    }

    fn config_context_with_routes(
        ipv4: Option<IpPrefix>,
        ipv6: Option<IpPrefix>,
    ) -> ConfigPeerContext {
        ConfigPeerContext::new(
            PeerRuntimeConfig {
                core: CoreConfig {
                    routes: RouteConfig {
                        ipv4,
                        ipv6,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                network_identity: NetworkIdentity::default(),
                stun_info: StunInfo::default(),
                feature_flags: PeerFeatureFlag::default(),
                secure_mode: None,
                host_routing: HostRoutingPolicy::default(),
            },
            Arc::new(CredentialManager::new()),
        )
    }

    #[tokio::test]
    async fn config_peer_context_publishes_peer_events_per_instance() {
        let context = config_context_with_routes(None, None);
        let mut events = context.subscribe_peer_events().unwrap();

        context.issue_event(PeerEvent::PeerAdded(7));
        assert_eq!(events.recv().await.unwrap(), PeerContextEvent::PeerAdded(7));
        context.issue_event(PeerEvent::PeerConnAdded(Default::default()));
        assert_eq!(
            events.recv().await.unwrap(),
            PeerContextEvent::PeerConnAdded
        );
        context.issue_event(PeerEvent::PeerConnRemoved(Default::default()));
        assert_eq!(
            events.recv().await.unwrap(),
            PeerContextEvent::PeerConnRemoved
        );
        context.issue_event(PeerEvent::PeerRemoved(7));
        assert_eq!(
            events.recv().await.unwrap(),
            PeerContextEvent::PeerRemoved(7)
        );
    }

    #[test]
    fn config_peer_context_validates_route_family_and_prefix_edges() {
        let mismatched = config_context_with_routes(
            Some(IpPrefix {
                address: "2001:db8::1".parse().unwrap(),
                prefix_len: 64,
            }),
            Some(IpPrefix {
                address: "10.20.0.1".parse().unwrap(),
                prefix_len: 24,
            }),
        );
        assert_eq!(mismatched.ipv4(), None);
        assert_eq!(mismatched.ipv6(), None);
        assert!(!mismatched.is_ip_in_same_network(&"2001:db8::2".parse().unwrap()));
        assert!(!mismatched.is_ip_in_same_network(&"10.20.0.2".parse().unwrap()));

        let edges = config_context_with_routes(
            Some(IpPrefix::new("10.20.0.7".parse().unwrap(), 0).unwrap()),
            Some(IpPrefix::new("2001:db8::7".parse().unwrap(), 128).unwrap()),
        );
        assert!(edges.is_ip_in_same_network(&"203.0.113.1".parse().unwrap()));
        assert!(edges.is_ip_in_same_network(&"2001:db8::7".parse().unwrap()));
        assert!(!edges.is_ip_in_same_network(&"2001:db8::8".parse().unwrap()));

        let invalid = config_context_with_routes(
            Some(IpPrefix {
                address: "10.20.0.7".parse().unwrap(),
                prefix_len: 33,
            }),
            None,
        );
        assert_eq!(invalid.ipv4(), None);
        assert!(!invalid.is_ip_in_same_network(&"10.20.0.7".parse().unwrap()));
    }

    #[test]
    fn trusted_key_manager_respects_source_filter() {
        let manager = TrustedKeyMapManager::new();
        let network_name = "net";
        let pubkey = vec![1; 32];
        manager.update_trusted_keys(
            network_name,
            HashMap::from([(
                pubkey.clone(),
                TrustedKeyMetadata {
                    source: TrustedKeySource::OspfCredential,
                    expiry_unix: None,
                },
            )]),
        );

        assert!(manager.verify_trusted_key(&pubkey, network_name));
        assert!(manager.verify_trusted_key_with_source(
            &pubkey,
            network_name,
            Some(TrustedKeySource::OspfCredential),
        ));
        assert!(!manager.verify_trusted_key_with_source(
            &pubkey,
            network_name,
            Some(TrustedKeySource::OspfNode),
        ));
    }
}

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
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
    peers::{
        credential_manager::{CredentialManager, CredentialStorage},
        foreign_network_manager::check_network_in_relay_whitelist,
        util::shrink_dashmap,
    },
    runtime_config::CoreRuntimeConfigStore,
    stats_manager::{LabelSet, LabelType, MetricName, StatsManager},
    token_bucket::TokenBucketManager,
};

pub(crate) const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";
const PEER_EVENT_CAPACITY: usize = 100;

#[async_trait]
pub(crate) trait ByteLimiter: Send + Sync {
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

pub(crate) type ArcByteLimiter = Arc<dyn ByteLimiter>;

/// Projects credential-store changes without exposing the store itself.
pub trait PeerCredentialEventSink: Send + Sync {
    fn credential_changed(&self);
}

impl PeerCredentialEventSink for () {
    fn credential_changed(&self) {}
}

#[derive(Debug, Clone)]
pub enum PeerEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(easytier_proto::core_peer::peer::PeerConnInfo),
    PeerConnRemoved(easytier_proto::core_peer::peer::PeerConnInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerContextEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded,
    PeerConnRemoved,
}

pub(crate) type PeerContextEventSubscriber = tokio::sync::broadcast::Receiver<PeerContextEvent>;

/// Projects peer-domain events without exposing the peer event stream or any
/// other runtime capability to the receiver.
pub trait PeerEventSink: Send + Sync {
    fn issue_event(&self, event: PeerEvent);
}

impl PeerEventSink for () {
    fn issue_event(&self, _event: PeerEvent) {}
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRuntimeConfig {
    pub core: CoreConfig,
    pub network_identity: NetworkIdentity,
    pub stun_info: StunInfo,
    pub feature_flags: PeerFeatureFlag,
    pub secure_mode: Option<SecureModeConfig>,
    pub host_routing: HostRoutingPolicy,
}

/// Normalized product and host inputs used to derive one peer runtime version.
///
/// The host owns platform-specific normalization of node, route, identity, and
/// capability values. Peer policy remains derived in core from the submitted
/// flags and ACL.
#[derive(Debug, Clone)]
pub struct PeerRuntimeSnapshotInput {
    pub node: NodeConfig,
    pub routes: RouteConfig,
    pub network_identity: NetworkIdentity,
    pub stun_info: StunInfo,
    pub flags: FlagsInConfig,
    pub secure_mode: Option<SecureModeConfig>,
    pub host_routing: HostRoutingPolicy,
    pub acl: Option<Acl>,
    pub easytier_version: String,
    pub vpn_portal_cidr: Option<Ipv4Cidr>,
    pub pinned_peers: Vec<(url::Url, Option<String>)>,
    pub ospf_update_my_foreign_network_interval_sec: u64,
    pub max_direct_conns_per_peer_in_foreign_network: usize,
    pub hmac_secret_digest: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoutingPolicy {
    /// Route otherwise-unreachable external IPv4 traffic through this node and
    /// keep self-delivered packets eligible for the host TUN/proxy path.
    pub local_exit_node_fallback: bool,
}

/// One normalized peer configuration version submitted by a host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRuntimeSnapshot {
    pub runtime: PeerRuntimeConfig,
    pub easytier_version: String,
    pub avoid_relay_data_preference: bool,
    pub flags: FlagsInConfig,
    pub vpn_portal_cidr: Option<Ipv4Cidr>,
    pub pinned_peers: Vec<(url::Url, Option<String>)>,
    pub peer_group_memberships: Vec<PeerGroupIdentity>,
    pub acl_group_declarations: Vec<PeerGroupIdentity>,
    pub ospf_update_my_foreign_network_interval_sec: u64,
    pub max_direct_conns_per_peer_in_foreign_network: usize,
    pub hmac_secret_digest: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PeerTrafficLimits {
    instance_recv_bps: Option<u64>,
    foreign_relay_bps: Option<u64>,
}

impl PeerTrafficLimits {
    fn from_portable(runtime: &PeerRuntimeConfig, flags: &FlagsInConfig) -> Self {
        let traffic = &runtime.core.traffic;
        Self {
            instance_recv_bps: Self::normalize(
                traffic.instance_recv_bps_limit,
                flags.instance_recv_bps_limit,
            ),
            foreign_relay_bps: Self::normalize(
                traffic.foreign_relay_bps_limit,
                flags.foreign_relay_bps_limit,
            ),
        }
    }

    fn normalize(explicit: Option<u64>, legacy: u64) -> Option<u64> {
        match explicit {
            Some(u64::MAX) => None,
            Some(limit) => Some(limit),
            None if !matches!(legacy, 0 | u64::MAX) => Some(legacy),
            None => None,
        }
    }
}

impl PeerRuntimeSnapshot {
    pub fn from_host_input(input: PeerRuntimeSnapshotInput) -> Self {
        let PeerRuntimeSnapshotInput {
            node,
            routes,
            network_identity,
            stun_info,
            flags,
            secure_mode,
            host_routing,
            acl,
            easytier_version,
            vpn_portal_cidr,
            pinned_peers,
            ospf_update_my_foreign_network_interval_sec,
            max_direct_conns_per_peer_in_foreign_network,
            hmac_secret_digest,
        } = input;
        let feature_flags = PeerFeatureFlag {
            kcp_input: !flags.disable_kcp_input,
            no_relay_kcp: flags.disable_relay_kcp,
            support_conn_list_sync: true,
            quic_input: !flags.disable_quic_input,
            no_relay_quic: flags.disable_relay_quic,
            need_p2p: flags.need_p2p,
            disable_p2p: flags.disable_p2p,
            avoid_relay_data: flags.disable_relay_data,
            ..Default::default()
        };
        let peer_policy = PeerPolicyConfig {
            p2p_enabled: !flags.disable_p2p,
            relay_peer_rpc: flags.relay_all_peer_rpc,
            relay_data: !flags.disable_relay_data,
            latency_first: flags.latency_first,
            encryption_required: flags.enable_encryption,
        };
        let traffic = TrafficConfig {
            mtu: u16::try_from(flags.mtu)
                .ok()
                .filter(|configured| *configured != 0),
            instance_recv_bps_limit: (flags.instance_recv_bps_limit != u64::MAX)
                .then_some(flags.instance_recv_bps_limit),
            foreign_relay_bps_limit: (flags.foreign_relay_bps_limit != u64::MAX)
                .then_some(flags.foreign_relay_bps_limit),
        };
        let avoid_relay_data_preference = check_network_in_relay_whitelist(
            &flags.relay_network_whitelist,
            &network_identity.network_name,
        )
        .is_err();
        let (acl_group_declarations, peer_group_memberships) = peer_acl_groups(acl.as_ref());

        Self {
            runtime: PeerRuntimeConfig {
                core: CoreConfig {
                    node,
                    routes,
                    peer_policy,
                    traffic,
                },
                network_identity,
                stun_info,
                feature_flags,
                secure_mode,
                host_routing,
            },
            easytier_version,
            avoid_relay_data_preference,
            flags,
            vpn_portal_cidr,
            pinned_peers,
            peer_group_memberships,
            acl_group_declarations,
            ospf_update_my_foreign_network_interval_sec,
            max_direct_conns_per_peer_in_foreign_network,
            hmac_secret_digest,
        }
    }

    pub fn new(runtime: PeerRuntimeConfig, flags: FlagsInConfig) -> Self {
        let avoid_relay_data_preference = runtime.feature_flags.avoid_relay_data;
        Self {
            runtime,
            easytier_version: env!("CARGO_PKG_VERSION").to_owned(),
            avoid_relay_data_preference,
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

    fn traffic_limits(&self) -> PeerTrafficLimits {
        PeerTrafficLimits::from_portable(&self.runtime, &self.flags)
    }

    #[cfg(test)]
    pub(crate) fn set_acl_groups(&mut self, acl: Option<&Acl>) {
        (self.acl_group_declarations, self.peer_group_memberships) = peer_acl_groups(acl);
    }
}

fn peer_acl_groups(acl: Option<&Acl>) -> (Vec<PeerGroupIdentity>, Vec<PeerGroupIdentity>) {
    let group = acl
        .and_then(|acl| acl.acl_v1.as_ref())
        .and_then(|acl| acl.group.as_ref());
    let declarations = group.map_or_else(Vec::new, |group| {
        group
            .declares
            .iter()
            .map(|identity| PeerGroupIdentity {
                group_name: identity.group_name.clone(),
                group_secret: identity.group_secret.clone(),
            })
            .collect()
    });
    let memberships = group.map_or_else(Vec::new, |group| {
        group
            .declares
            .iter()
            .filter(|identity| group.members.contains(&identity.group_name))
            .map(|identity| PeerGroupIdentity {
                group_name: identity.group_name.clone(),
                group_secret: identity.group_secret.clone(),
            })
            .collect()
    });
    (declarations, memberships)
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

/// Projects core-owned relay preference to host-facing feature state.
pub trait PeerRelayStateSink: Send + Sync {
    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool);
}

impl PeerRelayStateSink for () {
    fn set_avoid_relay_data_preference(&self, _avoid_relay_data: bool) {}
}

/// Supplies the instance's current STUN observation.
pub(crate) trait PeerStunInfoSource: Send + Sync {
    fn stun_info(&self) -> StunInfo {
        StunInfo::default()
    }
}

impl PeerStunInfoSource for () {}

/// Supplies public-IPv6 state observed or leased by the host.
pub(crate) trait PeerPublicIpv6State: Send + Sync {
    fn public_ipv6_lease_contains(&self, _ip: &std::net::Ipv6Addr) -> bool {
        false
    }

    fn public_ipv6_provider_enabled(&self) -> bool {
        false
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        None
    }
}

impl PeerPublicIpv6State for () {}

/// Host adapters used to assemble the core-owned peer context. Each field stays
/// narrow so peer modules cannot reach unrelated host state after construction.
pub(crate) struct CorePeerContextAdapters {
    pub relay_state_sink: Arc<dyn PeerRelayStateSink>,
    pub stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
    pub event_sink: Arc<dyn PeerEventSink>,
    pub credential_storage: Option<Arc<dyn CredentialStorage>>,
    pub credential_event_sink: Arc<dyn PeerCredentialEventSink>,
}

impl Default for CorePeerContextAdapters {
    fn default() -> Self {
        Self {
            relay_state_sink: Arc::new(()),
            stun_info_source: None,
            event_sink: Arc::new(()),
            credential_storage: None,
            credential_event_sink: Arc::new(()),
        }
    }
}

/// Peer context backed by one core-owned submitted snapshot and its instance
/// runtime resources.
pub(crate) struct CorePeerContext {
    config: CoreRuntimeConfigStore,
    avoid_relay_data_preference: AtomicBool,
    relay_state_sink: Arc<dyn PeerRelayStateSink>,
    stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
    public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
    limiter_state: Mutex<CoreLimiterState>,
    stats_manager: Arc<StatsManager>,
    credentials: Arc<CredentialManager>,
    trusted_keys: Arc<TrustedKeyMapManager>,
    credential_event_sink: Arc<dyn PeerCredentialEventSink>,
    peer_events: tokio::sync::broadcast::Sender<PeerContextEvent>,
    event_sink: Arc<dyn PeerEventSink>,
}

impl CorePeerContext {
    pub(crate) fn new(
        config: CoreRuntimeConfigStore,
        public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
        adapters: CorePeerContextAdapters,
    ) -> Self {
        Self::new_with_stats_manager(
            config,
            public_ipv6_state,
            adapters,
            Arc::new(StatsManager::new()),
        )
    }

    /// Builds a foreign-network context that contributes to the same
    /// instance-level metrics registry while retaining independent identity,
    /// credential, trusted-key, event, and limiter state.
    pub fn new_foreign(
        config: CoreRuntimeConfigStore,
        adapters: CorePeerContextAdapters,
        parent: &CorePeerContext,
    ) -> Self {
        Self::new_with_stats_manager(config, Arc::new(()), adapters, parent.stats_manager())
    }

    fn new_with_stats_manager(
        config: CoreRuntimeConfigStore,
        public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
        adapters: CorePeerContextAdapters,
        stats_manager: Arc<StatsManager>,
    ) -> Self {
        let avoid_relay_data_preference =
            AtomicBool::new(config.snapshot().peer.avoid_relay_data_preference);
        let credentials = Arc::new(
            adapters
                .credential_storage
                .map_or_else(CredentialManager::new, CredentialManager::from_storage),
        );
        Self {
            config,
            avoid_relay_data_preference,
            relay_state_sink: adapters.relay_state_sink,
            stun_info_source: adapters.stun_info_source,
            public_ipv6_state,
            limiter_state: Mutex::new(CoreLimiterState::default()),
            stats_manager,
            credentials,
            trusted_keys: Arc::new(TrustedKeyMapManager::new()),
            credential_event_sink: adapters.credential_event_sink,
            peer_events: tokio::sync::broadcast::channel(PEER_EVENT_CAPACITY).0,
            event_sink: adapters.event_sink,
        }
    }

    fn snapshot(&self) -> Arc<PeerRuntimeSnapshot> {
        self.config.snapshot().peer.clone()
    }

    pub fn stats_manager(&self) -> Arc<StatsManager> {
        self.stats_manager.clone()
    }

    pub fn credential_manager(&self) -> Arc<CredentialManager> {
        self.credentials.clone()
    }

    #[cfg(test)]
    pub fn trusted_key_manager(&self) -> Arc<TrustedKeyMapManager> {
        self.trusted_keys.clone()
    }

    fn record_control_metric(
        &self,
        network_name: &str,
        bytes: u64,
        bytes_metric: MetricName,
        packets_metric: MetricName,
    ) {
        let labels =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_owned()));
        self.stats_manager
            .get_counter(bytes_metric, labels.clone())
            .add(bytes);
        self.stats_manager.get_counter(packets_metric, labels).inc();
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

#[derive(Default)]
struct CoreLimiterState {
    manager: Option<TokenBucketManager>,
    stopped: bool,
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

#[cfg(test)]
fn ipv4_inet_to_config(value: Ipv4Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(value.address()), value.network_length())
        .expect("Ipv4Inet should always have a valid IPv4 prefix length")
}

#[cfg(test)]
fn ipv6_inet_to_config(value: Ipv6Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V6(value.address()), value.network_length())
        .expect("Ipv6Inet should always have a valid IPv6 prefix length")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub(crate) struct TrustedKeyMetadata {
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

pub(crate) type TrustedKeyMap = HashMap<Vec<u8>, TrustedKeyMetadata>;

pub(crate) struct TrustedKeyMapManager {
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
pub(crate) trait PeerContext: Send + Sync {
    #[cfg(test)]
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

    fn subscribe_runtime_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
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

    fn hmac_secret_digest(&self) -> bool {
        false
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

pub(crate) type ArcPeerContext = Arc<dyn PeerContext>;

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct NoopPeerContext {
    network_identity: NetworkIdentity,
    flags: FlagsInConfig,
    secure_mode: Option<SecureModeConfig>,
}

#[cfg(test)]
impl NoopPeerContext {
    pub fn new(network_identity: NetworkIdentity) -> Self {
        Self {
            network_identity,
            flags: FlagsInConfig::default(),
            secure_mode: None,
        }
    }
}

#[cfg(test)]
impl Default for NoopPeerContext {
    fn default() -> Self {
        Self::new(NetworkIdentity::default())
    }
}

pub(crate) fn secret_proof_from_secret(secret: &str, challenge: &[u8]) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(SECRET_PROOF_PREFIX);
    mac.update(challenge);
    Some(mac)
}

#[cfg(test)]
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

impl PeerContext for CorePeerContext {
    #[cfg(test)]
    fn runtime_config(&self) -> PeerRuntimeConfig {
        let mut runtime = self.snapshot().runtime.clone();
        runtime.stun_info = self.stun_info();
        runtime
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
        self.stun_info_source
            .as_ref()
            .map(|source| source.stun_info())
            .unwrap_or_else(|| self.snapshot().runtime.stun_info.clone())
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
            || self.public_ipv6_state.public_ipv6_lease_contains(ip)
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
        flags.avoid_relay_data = snapshot.flags.disable_relay_data
            || self.avoid_relay_data_preference.load(Ordering::Acquire);
        flags.ipv6_public_addr_provider |= self.public_ipv6_state.public_ipv6_provider_enabled();
        flags
    }

    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        let before = self.feature_flags().avoid_relay_data;
        let previous = self
            .avoid_relay_data_preference
            .swap(avoid_relay_data, Ordering::AcqRel);
        if previous != avoid_relay_data {
            self.relay_state_sink
                .set_avoid_relay_data_preference(avoid_relay_data);
        }
        before != self.feature_flags().avoid_relay_data
    }

    fn subscribe_runtime_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.config.subscribe_peer_runtime_changes())
    }

    fn easytier_version(&self) -> String {
        self.snapshot().easytier_version.clone()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        self.snapshot().ospf_update_my_foreign_network_interval_sec
    }

    fn hmac_secret_digest(&self) -> bool {
        self.snapshot().hmac_secret_digest
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        self.public_ipv6_state.advertised_ipv6_public_addr_prefix()
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
        if self.trusted_keys.verify_trusted_key(pubkey, network_name) {
            return true;
        }
        network_name == self.snapshot().runtime.network_identity.network_name
            && self.credentials.is_pubkey_trusted(pubkey)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        self.trusted_keys
            .verify_trusted_key_with_source(pubkey, network_name, Some(source))
    }

    fn list_trusted_keys(&self, network_name: &str) -> Vec<(Vec<u8>, TrustedKeyMetadata)> {
        self.trusted_keys.list_trusted_keys(network_name)
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        self.credentials.get_trusted_pubkeys(network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        self.credentials.remove_expired_credentials()
    }

    fn issue_credential_changed(&self) {
        self.credential_event_sink.credential_changed();
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        self.trusted_keys.update_trusted_keys(network_name, keys);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        self.trusted_keys.remove_trusted_keys(network_name);
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.record_control_metric(
            network_name,
            bytes,
            MetricName::TrafficControlBytesTx,
            MetricName::TrafficControlPacketsTx,
        );
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.record_control_metric(
            network_name,
            bytes,
            MetricName::TrafficControlBytesRx,
            MetricName::TrafficControlPacketsRx,
        );
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        let limits = self.snapshot().traffic_limits();
        let (key, bps) = if is_foreign_network && let Some(limit) = limits.foreign_relay_bps {
            (format!("peer:foreign:{network_name}:recv"), limit)
        } else {
            ("peer:instance:recv".to_owned(), limits.instance_recv_bps?)
        };
        self.get_or_create_limiter(&key, bps)
    }

    fn foreign_forward_limiter(&self, network_name: &str) -> Option<ArcByteLimiter> {
        let bps = self.snapshot().traffic_limits().foreign_relay_bps?;
        self.get_or_create_limiter(&format!("peer:foreign:{network_name}:forward"), bps)
    }

    fn issue_event(&self, event: PeerEvent) {
        let context_event = match &event {
            PeerEvent::PeerAdded(peer_id) => PeerContextEvent::PeerAdded(*peer_id),
            PeerEvent::PeerRemoved(peer_id) => PeerContextEvent::PeerRemoved(*peer_id),
            PeerEvent::PeerConnAdded(_) => PeerContextEvent::PeerConnAdded,
            PeerEvent::PeerConnRemoved(_) => PeerContextEvent::PeerConnRemoved,
        };
        let _ = self.peer_events.send(context_event);
        self.event_sink.issue_event(event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        Some(self.peer_events.subscribe())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_config::{CoreRuntimeConfig, CoreRuntimeConfigStore};
    use std::sync::atomic::{AtomicBool, Ordering};

    #[derive(Default)]
    struct TestPeerEventSink {
        events: Mutex<Vec<PeerEvent>>,
    }

    impl PeerEventSink for TestPeerEventSink {
        fn issue_event(&self, event: PeerEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[derive(Default)]
    struct TestCredentialEventSink {
        changed: AtomicBool,
    }

    impl PeerCredentialEventSink for TestCredentialEventSink {
        fn credential_changed(&self) {
            self.changed.store(true, Ordering::Release);
        }
    }

    fn test_core_context_adapters(event_sink: Arc<dyn PeerEventSink>) -> CorePeerContextAdapters {
        CorePeerContextAdapters {
            relay_state_sink: Arc::new(()),
            stun_info_source: Some(Arc::new(())),
            event_sink,
            credential_storage: None,
            credential_event_sink: Arc::new(()),
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

    fn host_snapshot_input(flags: FlagsInConfig, acl: Option<Acl>) -> PeerRuntimeSnapshotInput {
        PeerRuntimeSnapshotInput {
            node: NodeConfig {
                peer_id: None,
                instance_id: Some([7; 16]),
                hostname: Some("host-node".to_owned()),
                network_name: "host-network".to_owned(),
            },
            routes: RouteConfig {
                ipv4: Some(IpPrefix::new("10.20.0.7".parse().unwrap(), 16).unwrap()),
                ..Default::default()
            },
            network_identity: NetworkIdentity::new("host-network".to_owned(), "secret".to_owned()),
            stun_info: StunInfo::default(),
            flags,
            secure_mode: None,
            host_routing: HostRoutingPolicy {
                local_exit_node_fallback: true,
            },
            acl,
            easytier_version: "host-version".to_owned(),
            vpn_portal_cidr: Some("10.30.0.0/24".parse().unwrap()),
            pinned_peers: vec![(
                "tcp://192.0.2.10:11010".parse().unwrap(),
                Some("peer-key".to_owned()),
            )],
            ospf_update_my_foreign_network_interval_sec: 17,
            max_direct_conns_per_peer_in_foreign_network: 5,
            hmac_secret_digest: true,
        }
    }

    #[test]
    fn host_input_derives_peer_policy_features_and_traffic() {
        let mut flags = FlagsInConfig::default();
        flags.disable_p2p = true;
        flags.need_p2p = true;
        flags.relay_all_peer_rpc = true;
        flags.disable_relay_data = true;
        flags.latency_first = true;
        flags.enable_encryption = false;
        flags.disable_kcp_input = true;
        flags.disable_relay_kcp = true;
        flags.disable_quic_input = true;
        flags.disable_relay_quic = true;
        flags.mtu = 1400;
        flags.instance_recv_bps_limit = 0;
        flags.foreign_relay_bps_limit = u64::MAX;
        flags.relay_network_whitelist = "host-network".to_owned();

        let snapshot =
            PeerRuntimeSnapshot::from_host_input(host_snapshot_input(flags.clone(), None));
        let runtime = &snapshot.runtime;

        assert_eq!(snapshot.flags, flags);
        assert!(!runtime.core.peer_policy.p2p_enabled);
        assert!(runtime.core.peer_policy.relay_peer_rpc);
        assert!(!runtime.core.peer_policy.relay_data);
        assert!(runtime.core.peer_policy.latency_first);
        assert!(!runtime.core.peer_policy.encryption_required);
        assert_eq!(runtime.core.traffic.mtu, Some(1400));
        assert_eq!(runtime.core.traffic.instance_recv_bps_limit, Some(0));
        assert_eq!(runtime.core.traffic.foreign_relay_bps_limit, None);
        assert!(!runtime.feature_flags.kcp_input);
        assert!(runtime.feature_flags.no_relay_kcp);
        assert!(runtime.feature_flags.support_conn_list_sync);
        assert!(!runtime.feature_flags.quic_input);
        assert!(runtime.feature_flags.no_relay_quic);
        assert!(runtime.feature_flags.need_p2p);
        assert!(runtime.feature_flags.disable_p2p);
        assert!(runtime.feature_flags.avoid_relay_data);
        assert!(!snapshot.avoid_relay_data_preference);
    }

    #[test]
    fn host_input_derives_acl_groups_and_preserves_explicit_inputs() {
        let acl = Acl {
            acl_v1: Some(easytier_proto::acl::AclV1 {
                chains: Vec::new(),
                group: Some(easytier_proto::acl::GroupInfo {
                    declares: vec![
                        easytier_proto::acl::GroupIdentity {
                            group_name: "ops".to_owned(),
                            group_secret: "ops-secret".to_owned(),
                        },
                        easytier_proto::acl::GroupIdentity {
                            group_name: "audit".to_owned(),
                            group_secret: "audit-secret".to_owned(),
                        },
                    ],
                    members: vec!["ops".to_owned(), "undeclared".to_owned()],
                }),
            }),
        };
        let mut flags = FlagsInConfig::default();
        flags.relay_network_whitelist = "other-network".to_owned();

        let snapshot = PeerRuntimeSnapshot::from_host_input(host_snapshot_input(flags, Some(acl)));

        assert!(snapshot.avoid_relay_data_preference);
        assert_eq!(snapshot.easytier_version, "host-version");
        assert_eq!(
            snapshot.vpn_portal_cidr,
            Some("10.30.0.0/24".parse().unwrap())
        );
        assert_eq!(
            snapshot.pinned_peers,
            vec![(
                "tcp://192.0.2.10:11010".parse().unwrap(),
                Some("peer-key".to_owned())
            )]
        );
        assert_eq!(snapshot.ospf_update_my_foreign_network_interval_sec, 17);
        assert_eq!(snapshot.max_direct_conns_per_peer_in_foreign_network, 5);
        assert!(snapshot.hmac_secret_digest);
        assert!(snapshot.runtime.host_routing.local_exit_node_fallback);
        assert_eq!(
            snapshot.acl_group_declarations,
            vec![
                PeerGroupIdentity {
                    group_name: "ops".to_owned(),
                    group_secret: "ops-secret".to_owned(),
                },
                PeerGroupIdentity {
                    group_name: "audit".to_owned(),
                    group_secret: "audit-secret".to_owned(),
                },
            ]
        );
        assert_eq!(
            snapshot.peer_group_memberships,
            vec![PeerGroupIdentity {
                group_name: "ops".to_owned(),
                group_secret: "ops-secret".to_owned(),
            }]
        );
    }

    #[test]
    fn records_control_traffic_in_core_owned_metrics() {
        let context = CorePeerContext::new(
            CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(PeerRuntimeSnapshot::default()),
            ),
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );
        let labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("metrics-network".to_owned()));

        PeerContext::record_control_tx(&context, "metrics-network", 128);

        assert_eq!(
            context
                .stats_manager()
                .get_metric(MetricName::TrafficControlBytesTx, &labels)
                .unwrap()
                .value,
            128
        );
        assert_eq!(
            context
                .stats_manager()
                .get_metric(MetricName::TrafficControlPacketsTx, &labels)
                .unwrap()
                .value,
            1
        );
    }

    #[test]
    fn explicit_traffic_limits_preserve_zero_and_override_flags() {
        let mut runtime = PeerRuntimeSnapshot::default().runtime;
        runtime.core.traffic.instance_recv_bps_limit = Some(0);
        runtime.core.traffic.foreign_relay_bps_limit = Some(2048);
        let mut flags = FlagsInConfig::default();
        flags.instance_recv_bps_limit = 1024;
        flags.foreign_relay_bps_limit = 4096;

        let snapshot = PeerRuntimeSnapshot::new(runtime, flags);

        assert_eq!(snapshot.traffic_limits().instance_recv_bps, Some(0));
        assert_eq!(snapshot.traffic_limits().foreign_relay_bps, Some(2048));
    }

    #[test]
    fn legacy_traffic_limits_ignore_unlimited_sentinels() {
        let runtime = PeerRuntimeSnapshot::default().runtime;
        let mut flags = FlagsInConfig::default();
        flags.instance_recv_bps_limit = 1024;
        flags.foreign_relay_bps_limit = u64::MAX;

        let snapshot = PeerRuntimeSnapshot::new(runtime, flags);

        assert_eq!(snapshot.traffic_limits().instance_recv_bps, Some(1024));
        assert_eq!(snapshot.traffic_limits().foreign_relay_bps, None);
    }

    #[test]
    fn explicit_unlimited_limits_override_legacy_values() {
        let mut runtime = PeerRuntimeSnapshot::default().runtime;
        runtime.core.traffic.instance_recv_bps_limit = Some(u64::MAX);
        runtime.core.traffic.foreign_relay_bps_limit = Some(u64::MAX);
        let mut flags = FlagsInConfig::default();
        flags.instance_recv_bps_limit = 1024;
        flags.foreign_relay_bps_limit = 2048;

        let snapshot = PeerRuntimeSnapshot::new(runtime, flags);

        assert_eq!(snapshot.traffic_limits(), PeerTrafficLimits::default());
    }

    #[test]
    fn portable_traffic_limits_default_to_unlimited() {
        let runtime = PeerRuntimeSnapshot::default().runtime;

        let snapshot = PeerRuntimeSnapshot::new(runtime, FlagsInConfig::default());

        assert_eq!(snapshot.traffic_limits(), PeerTrafficLimits::default());
    }

    fn submitted_config(snapshot: PeerRuntimeSnapshot) -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(snapshot))
    }

    #[test]
    fn core_peer_context_separates_config_versions_from_live_support() {
        let config = submitted_config(submitted_snapshot("before", false));
        let context = CorePeerContext::new(
            config.clone(),
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );

        assert_eq!(context.hostname(), "before");
        assert!(!context.feature_flags().avoid_relay_data);

        context.set_avoid_relay_data_preference(true);
        assert!(context.feature_flags().avoid_relay_data);

        config.update_peer(Arc::new(submitted_snapshot("after", true)));
        context.set_avoid_relay_data_preference(false);
        assert_eq!(context.hostname(), "after");
        assert!(context.feature_flags().avoid_relay_data);

        config.update_peer(Arc::new(submitted_snapshot("after", false)));
        assert!(!context.feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn core_peer_context_owns_events_and_projects_them_to_sink() {
        let config = submitted_config(submitted_snapshot("events", false));
        let sink = Arc::new(TestPeerEventSink::default());
        let context = CorePeerContext::new(
            config,
            Arc::new(()),
            test_core_context_adapters(sink.clone()),
        );
        let mut events = context.subscribe_peer_events().unwrap();

        context.issue_event(PeerEvent::PeerAdded(7));

        assert_eq!(events.recv().await.unwrap(), PeerContextEvent::PeerAdded(7));
        assert!(matches!(
            sink.events.lock().unwrap().as_slice(),
            [PeerEvent::PeerAdded(7)]
        ));
    }

    #[test]
    fn core_peer_context_owns_trusted_keys_and_projects_credential_changes() {
        let config = submitted_config(submitted_snapshot("trust", false));
        let credential_events = Arc::new(TestCredentialEventSink::default());
        let mut adapters = test_core_context_adapters(Arc::new(()));
        adapters.credential_event_sink = credential_events.clone();
        let context = CorePeerContext::new(config, Arc::new(()), adapters);
        let public_key = vec![7; 32];
        let mut keys = TrustedKeyMap::new();
        keys.insert(
            public_key.clone(),
            TrustedKeyMetadata {
                source: TrustedKeySource::OspfNode,
                expiry_unix: None,
            },
        );

        context.update_trusted_keys(keys, "foreign");
        context.issue_credential_changed();

        assert!(context.is_pubkey_trusted(&public_key, "foreign"));
        assert_eq!(context.list_trusted_keys("foreign").len(), 1);
        assert!(credential_events.changed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn foreign_forward_limiter_is_independent_from_peer_receive_limiter() {
        let mut snapshot = submitted_snapshot("limiter", false);
        snapshot.runtime.core.traffic.foreign_relay_bps_limit = Some(1024);
        let config = submitted_config(snapshot);
        let context = CorePeerContext::new(
            config,
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );

        let receive = context.recv_limiter("foreign", true).unwrap();
        let receive_again = context.recv_limiter("foreign", true).unwrap();
        let forward = context.foreign_forward_limiter("foreign").unwrap();
        assert!(Arc::ptr_eq(&receive, &receive_again));
        assert!(!Arc::ptr_eq(&receive, &forward));
        context.stop().await;
    }

    #[tokio::test]
    async fn foreign_forward_limiter_does_not_fall_back_to_instance_limit() {
        let mut snapshot = submitted_snapshot("limiter", false);
        snapshot.runtime.core.traffic.foreign_relay_bps_limit = None;
        snapshot.runtime.core.traffic.instance_recv_bps_limit = Some(1024);
        let config = submitted_config(snapshot);
        let context = CorePeerContext::new(
            config,
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );

        assert!(context.recv_limiter("foreign", true).is_some());
        assert!(context.foreign_forward_limiter("foreign").is_none());
        context.stop().await;
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
    fn core_owned_peer_context_reads_normalized_snapshot() {
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
        let acl = Acl {
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
        };
        let context = core_owned_context_with_acl(runtime.clone(), flags.clone(), None, Some(&acl));

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

    #[test]
    fn core_owned_peer_context_uses_live_stun_source_when_injected() {
        struct TestStunInfoSource(StunInfo);

        impl PeerStunInfoSource for TestStunInfoSource {
            fn stun_info(&self) -> StunInfo {
                self.0.clone()
            }
        }

        let mut runtime = PeerRuntimeSnapshot::default().runtime;
        runtime.stun_info.tcp_nat_type = 1;
        let mut live = StunInfo::default();
        live.tcp_nat_type = 4;
        let context = core_owned_context(
            runtime,
            FlagsInConfig::default(),
            Some(Arc::new(TestStunInfoSource(live.clone()))),
        );

        assert_eq!(context.stun_info(), live);
        assert_eq!(context.runtime_config().stun_info, live);
    }

    fn core_owned_context(
        runtime: PeerRuntimeConfig,
        flags: FlagsInConfig,
        stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
    ) -> CorePeerContext {
        core_owned_context_with_acl(runtime, flags, stun_info_source, None)
    }

    fn core_owned_context_with_acl(
        runtime: PeerRuntimeConfig,
        flags: FlagsInConfig,
        stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
        acl: Option<&Acl>,
    ) -> CorePeerContext {
        let mut snapshot = PeerRuntimeSnapshot::new(runtime, flags);
        snapshot.set_acl_groups(acl);
        let config = CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(snapshot));
        CorePeerContext::new(
            config,
            Arc::new(()),
            CorePeerContextAdapters {
                relay_state_sink: Arc::new(()),
                stun_info_source,
                event_sink: Arc::new(()),
                credential_storage: None,
                credential_event_sink: Arc::new(()),
            },
        )
    }

    fn core_context_with_routes(ipv4: Option<IpPrefix>, ipv6: Option<IpPrefix>) -> CorePeerContext {
        core_owned_context(
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
            FlagsInConfig::default(),
            None,
        )
    }

    #[tokio::test]
    async fn core_owned_peer_context_publishes_peer_events_per_instance() {
        let context = core_context_with_routes(None, None);
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
    fn core_owned_peer_context_validates_route_family_and_prefix_edges() {
        let mismatched = core_context_with_routes(
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

        let edges = core_context_with_routes(
            Some(IpPrefix::new("10.20.0.7".parse().unwrap(), 0).unwrap()),
            Some(IpPrefix::new("2001:db8::7".parse().unwrap(), 128).unwrap()),
        );
        assert!(edges.is_ip_in_same_network(&"203.0.113.1".parse().unwrap()));
        assert!(edges.is_ip_in_same_network(&"2001:db8::7".parse().unwrap()));
        assert!(!edges.is_ip_in_same_network(&"2001:db8::8".parse().unwrap()));

        let invalid = core_context_with_routes(
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

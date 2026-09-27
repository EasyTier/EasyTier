use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use dashmap::DashMap;
use easytier_proto::{
    acl::Acl,
    common::{Flags, PeerFeatureFlag, SecureModeConfig, StunInfo, TunnelInfo},
    peer_rpc::{PeerGroupInfo, TrustedCredentialPubkeyProof},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub use crate::config::{NetworkIdentity, NetworkSecretDigest};
use crate::{
    config::peers::{HostRoutingPolicy, PeerGroupIdentity},
    config::runtime::InstanceConfigStore,
    config::{PeerId, toml::ProxyNetworkConfig},
    events::{CoreEvent, CoreEventSink},
    foundation::stats::{LabelSet, LabelType, MetricName, StatsManager},
    foundation::token_bucket::{ArcByteLimiter, BucketConfig, TokenBucketManager},
    peers::{
        credential_manager::{CredentialManager, CredentialStorage},
        util::shrink_dashmap,
    },
};

pub(crate) const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";
const PEER_EVENT_CAPACITY: usize = 100;

#[derive(Debug, Clone)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum PeerEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(easytier_proto::core_peer::peer::PeerConnInfo),
    PeerConnRemoved(easytier_proto::core_peer::peer::PeerConnInfo),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum PeerContextEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded,
    PeerConnRemoved,
}

pub(crate) type PeerContextEventSubscriber = tokio::sync::broadcast::Receiver<PeerContextEvent>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PeerTrafficLimits {
    pub(crate) instance_recv_bps: Option<u64>,
    pub(crate) foreign_relay_bps: Option<u64>,
}

impl PeerTrafficLimits {
    pub(crate) fn from_flags(flags: &Flags) -> Self {
        Self {
            instance_recv_bps: (flags.instance_recv_bps_limit != u64::MAX)
                .then_some(flags.instance_recv_bps_limit),
            foreign_relay_bps: (flags.foreign_relay_bps_limit != u64::MAX)
                .then_some(flags.foreign_relay_bps_limit),
        }
    }
}

pub(crate) fn peer_acl_groups(
    acl: Option<&Acl>,
) -> (Vec<PeerGroupIdentity>, Vec<PeerGroupIdentity>) {
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
#[derive(Clone)]
pub(crate) struct CorePeerContextAdapters {
    pub stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
    pub events: Arc<dyn CoreEventSink>,
    pub credential_storage: Option<Arc<dyn CredentialStorage>>,
    pub host_routing: HostRoutingPolicy,
}

/// Peer context backed by one core-owned submitted snapshot and its instance
/// runtime resources.
pub(crate) struct CorePeerContext {
    is_foreign: bool,
    parent_feature_flags: Option<PeerFeatureFlag>,
    config: InstanceConfigStore,
    instance_id: uuid::Uuid,
    host_routing: HostRoutingPolicy,
    avoid_relay_data_preference: AtomicBool,
    stun_info_source: Option<Arc<dyn PeerStunInfoSource>>,
    fallback_stun_info: RwLock<StunInfo>,
    dhcp_ipv4: RwLock<Option<Ipv4Inet>>,
    public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
    limiter_state: Mutex<CoreLimiterState>,
    stats_manager: Arc<StatsManager>,
    credentials: Arc<CredentialManager>,
    trusted_keys: Arc<TrustedKeyMapManager>,
    peer_events: tokio::sync::broadcast::Sender<PeerContextEvent>,
    events: Arc<dyn CoreEventSink>,
}

impl CorePeerContext {
    pub(crate) fn new(
        config: InstanceConfigStore,
        public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
        adapters: CorePeerContextAdapters,
    ) -> Self {
        Self::new_with_stats_manager(
            config,
            public_ipv6_state,
            adapters,
            Arc::new(StatsManager::new()),
            false,
        )
    }

    /// Builds a foreign-network context that contributes to the same
    /// instance-level metrics registry while retaining independent identity,
    /// credential, trusted-key, event, and limiter state.
    pub fn new_foreign(
        config: InstanceConfigStore,
        mut adapters: CorePeerContextAdapters,
        parent: &CorePeerContext,
    ) -> Self {
        adapters.host_routing = parent.host_routing_policy();
        let mut foreign = Self::new_with_stats_manager(
            config,
            Arc::new(()),
            adapters,
            parent.stats_manager(),
            true,
        );
        foreign.parent_feature_flags = Some(parent.feature_flags());
        foreign
    }

    fn new_with_stats_manager(
        config: InstanceConfigStore,
        public_ipv6_state: Arc<dyn PeerPublicIpv6State>,
        adapters: CorePeerContextAdapters,
        stats_manager: Arc<StatsManager>,
        is_foreign: bool,
    ) -> Self {
        let snapshot = config.snapshot();
        let instance_id = snapshot.instance_id;
        let avoid_relay_data_preference = AtomicBool::new(false);
        let credentials = Arc::new(
            adapters
                .credential_storage
                .map_or_else(CredentialManager::new, CredentialManager::from_storage),
        );
        let fallback_stun_info = RwLock::new(StunInfo::default());
        Self {
            is_foreign,
            parent_feature_flags: None,
            config,
            instance_id,
            host_routing: adapters.host_routing,
            avoid_relay_data_preference,
            stun_info_source: adapters.stun_info_source,
            fallback_stun_info,
            dhcp_ipv4: RwLock::new(None),
            public_ipv6_state,
            limiter_state: Mutex::new(CoreLimiterState::default()),
            stats_manager,
            credentials,
            trusted_keys: Arc::new(TrustedKeyMapManager::new()),
            peer_events: tokio::sync::broadcast::channel(PEER_EVENT_CAPACITY).0,
            events: adapters.events,
        }
    }

    pub(crate) fn set_dhcp_ipv4(&self, actual: Option<Ipv4Inet>) {
        let changed = {
            let mut guard = self.dhcp_ipv4.write().unwrap();
            if *guard != actual {
                *guard = actual;
                true
            } else {
                false
            }
        };
        if changed {
            self.config.notify_peer_runtime_changes();
        }
    }

    #[cfg(test)]
    pub(crate) fn set_fallback_stun_info(&self, stun_info: StunInfo) {
        *self.fallback_stun_info.write().unwrap() = stun_info;
    }

    pub(crate) fn dhcp_enabled(&self) -> bool {
        self.config.snapshot().dhcp
    }

    pub(crate) fn runtime_config_store(&self) -> InstanceConfigStore {
        self.config.clone()
    }

    pub fn stats_manager(&self) -> Arc<StatsManager> {
        self.stats_manager.clone()
    }

    pub fn credential_manager(&self) -> Arc<CredentialManager> {
        self.credentials.clone()
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
        Some(manager.get_or_create(key, BucketConfig::with_default_capacity(bps)))
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct PeerPacketPolicy {
    pub(crate) disable_relay_data: bool,
    pub(crate) p2p_only: bool,
    pub(crate) latency_first: bool,
    pub(crate) disable_p2p: bool,
    pub(crate) lazy_p2p: bool,
}

impl PeerPacketPolicy {
    fn from_flags(flags: &Flags) -> Self {
        Self {
            disable_relay_data: flags.disable_relay_data,
            p2p_only: flags.p2p_only,
            latency_first: flags.latency_first && !flags.p2p_only,
            disable_p2p: flags.disable_p2p,
            lazy_p2p: flags.lazy_p2p,
        }
    }
}

pub(crate) trait PeerContext: Send + Sync {
    fn host_routing_policy(&self) -> HostRoutingPolicy {
        HostRoutingPolicy::default()
    }

    fn network_identity(&self) -> NetworkIdentity;

    fn network_name(&self) -> String {
        self.network_identity().network_name
    }

    fn flags(&self) -> Flags {
        Flags::default()
    }

    fn packet_policy(&self) -> PeerPacketPolicy {
        PeerPacketPolicy::from_flags(&self.flags())
    }

    fn disable_relay_data(&self) -> bool {
        self.packet_policy().disable_relay_data
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

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        Vec::new()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        Vec::new()
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

pub(crate) fn secret_proof_from_secret(secret: &str, challenge: &[u8]) -> Option<Hmac<Sha256>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(SECRET_PROOF_PREFIX);
    mac.update(challenge);
    Some(mac)
}

impl PeerContext for CorePeerContext {
    fn max_direct_conns_per_peer_in_foreign_network(&self) -> usize {
        3
    }

    fn network_identity(&self) -> NetworkIdentity {
        self.config.snapshot().network_identity.clone()
    }

    fn flags(&self) -> Flags {
        self.config.snapshot().flags.clone()
    }

    fn packet_policy(&self) -> PeerPacketPolicy {
        PeerPacketPolicy::from_flags(&self.config.snapshot().flags)
    }

    fn host_routing_policy(&self) -> HostRoutingPolicy {
        self.host_routing
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.config.snapshot().secure_mode.clone()
    }

    fn stun_info(&self) -> StunInfo {
        self.stun_info_source
            .as_ref()
            .map(|source| source.stun_info())
            .unwrap_or_else(|| self.fallback_stun_info.read().unwrap().clone())
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.instance_id
    }

    fn ipv4(&self) -> Option<Ipv4Inet> {
        if self.dhcp_enabled() {
            *self.dhcp_ipv4.read().unwrap()
        } else {
            self.config.snapshot().ipv4
        }
    }

    fn ipv6(&self) -> Option<Ipv6Inet> {
        self.config.snapshot().ipv6
    }

    fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.ipv6().is_some_and(|address| address.address() == *ip)
            || self.public_ipv6_state.public_ipv6_lease_contains(ip)
    }

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.config
            .snapshot()
            .proxy_network
            .iter()
            .map(|proxy| proxy.mapped_cidr.unwrap_or(proxy.cidr))
            .collect()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        self.config.snapshot().proxy_network.clone()
    }

    fn hostname(&self) -> String {
        self.config.snapshot().hostname.clone()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        let snapshot = self.config.snapshot();
        let (kcp_input, quic_input, no_relay_kcp, no_relay_quic, support_conn_list_sync) =
            if let Some(parent) = self.parent_feature_flags {
                (
                    parent.kcp_input,
                    parent.quic_input,
                    parent.no_relay_kcp,
                    parent.no_relay_quic,
                    false,
                )
            } else {
                (
                    !snapshot.flags.disable_kcp_input,
                    !snapshot.flags.disable_quic_input,
                    snapshot.flags.disable_relay_kcp,
                    snapshot.flags.disable_relay_quic,
                    true,
                )
            };
        PeerFeatureFlag {
            is_public_server: self.is_foreign,
            is_credential_peer: snapshot.network_identity.network_secret.is_none(),
            need_p2p: snapshot.flags.need_p2p,
            disable_p2p: snapshot.flags.disable_p2p,
            avoid_relay_data: snapshot.flags.disable_relay_data
                || self.avoid_relay_data_preference.load(Ordering::Acquire),
            ipv6_public_addr_provider: snapshot.ipv6_public_addr_provider
                || self.public_ipv6_state.public_ipv6_provider_enabled(),
            kcp_input,
            quic_input,
            no_relay_kcp,
            no_relay_quic,
            support_conn_list_sync,
        }
    }

    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        let before = self.feature_flags().avoid_relay_data;
        self.avoid_relay_data_preference
            .store(avoid_relay_data, Ordering::Release);
        let changed = before != self.feature_flags().avoid_relay_data;
        if changed {
            self.config.notify_peer_runtime_changes();
        }
        changed
    }

    fn subscribe_runtime_changes(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.config.subscribe_peer_runtime_changes())
    }

    fn easytier_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        10
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
        self.config
            .snapshot()
            .peer
            .iter()
            .find(|peer| peer.uri == remote_url)
            .and_then(|peer| peer.peer_public_key.clone())
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let snapshot = self.config.snapshot();
        let secret = snapshot.network_identity.network_secret.as_ref()?;
        secret_proof_from_secret(secret, challenge)
    }

    fn secret_digest(&self, network_identity: &NetworkIdentity) -> Vec<u8> {
        network_identity
            .secret_digest()
            .unwrap_or_default()
            .to_vec()
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        let snapshot = self.config.snapshot();
        let (_, memberships) = peer_acl_groups(snapshot.acl.as_ref());
        memberships
            .into_iter()
            .map(|group| {
                PeerGroupInfo::generate_with_proof(group.group_name, group.group_secret, peer_id)
            })
            .collect()
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        let snapshot = self.config.snapshot();
        let (declarations, _) = peer_acl_groups(snapshot.acl.as_ref());
        declarations
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        if self.trusted_keys.verify_trusted_key(pubkey, network_name) {
            return true;
        }
        network_name == self.config.snapshot().network_identity.network_name
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
        self.events.emit(CoreEvent::CredentialChanged);
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
        let limits = PeerTrafficLimits::from_flags(&self.config.snapshot().flags);
        let (key, bps) = if is_foreign_network && let Some(limit) = limits.foreign_relay_bps {
            (format!("peer:foreign:{network_name}:recv"), limit)
        } else {
            ("peer:instance:recv".to_owned(), limits.instance_recv_bps?)
        };
        self.get_or_create_limiter(&key, bps)
    }

    fn foreign_forward_limiter(&self, network_name: &str) -> Option<ArcByteLimiter> {
        let limits = PeerTrafficLimits::from_flags(&self.config.snapshot().flags);
        let bps = limits.foreign_relay_bps?;
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
        let event = match event {
            PeerEvent::PeerAdded(peer_id) => CoreEvent::PeerAdded(peer_id),
            PeerEvent::PeerRemoved(peer_id) => CoreEvent::PeerRemoved(peer_id),
            PeerEvent::PeerConnAdded(info) => CoreEvent::PeerConnAdded(info),
            PeerEvent::PeerConnRemoved(info) => CoreEvent::PeerConnRemoved(info),
        };
        self.events.emit(event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        Some(self.peer_events.subscribe())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(clippy::field_reassign_with_default)]

    use super::*;
    use crate::peers::test_support::NoopPeerContext;
    use std::sync::atomic::{AtomicBool, Ordering};

    impl CorePeerContext {
        pub(crate) fn trusted_key_manager(&self) -> Arc<TrustedKeyMapManager> {
            self.trusted_keys.clone()
        }
    }

    #[derive(Default)]
    struct TestPeerEventSink {
        events: Mutex<Vec<CoreEvent>>,
        credential_changed: AtomicBool,
    }

    impl CoreEventSink for TestPeerEventSink {
        fn emit(&self, event: CoreEvent) {
            if matches!(&event, CoreEvent::CredentialChanged) {
                self.credential_changed.store(true, Ordering::Release);
            }
            self.events.lock().unwrap().push(event);
        }
    }

    fn test_core_context_adapters(events: Arc<dyn CoreEventSink>) -> CorePeerContextAdapters {
        CorePeerContextAdapters {
            stun_info_source: None,
            events,
            credential_storage: None,
            host_routing: HostRoutingPolicy::default(),
        }
    }

    fn submitted_config(hostname: &str, disable_relay_data: bool) -> InstanceConfigStore {
        let mut flags = Flags::default();
        flags.disable_relay_data = disable_relay_data;
        let parsed = crate::config::InstanceConfigParsed {
            hostname: hostname.to_owned(),
            flags,
            ..Default::default()
        };
        InstanceConfigStore::from(parsed)
    }

    #[test]
    fn acl_group_derivation_works() {
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
        let (declarations, memberships) = peer_acl_groups(Some(&acl));
        assert_eq!(declarations.len(), 2);
        assert_eq!(memberships.len(), 1);
        assert_eq!(memberships[0].group_name, "ops");
    }

    #[test]
    fn traffic_limits_derivation_from_flags() {
        let mut flags = Flags::default();
        flags.instance_recv_bps_limit = 1024;
        flags.foreign_relay_bps_limit = 2048;
        let limits = PeerTrafficLimits::from_flags(&flags);
        assert_eq!(limits.instance_recv_bps, Some(1024));
        assert_eq!(limits.foreign_relay_bps, Some(2048));

        flags.instance_recv_bps_limit = u64::MAX;
        flags.foreign_relay_bps_limit = 0;
        let limits = PeerTrafficLimits::from_flags(&flags);
        assert_eq!(limits.instance_recv_bps, None);
        assert_eq!(limits.foreign_relay_bps, Some(0));
    }

    #[test]
    fn records_control_traffic_in_core_owned_metrics() {
        let context = CorePeerContext::new(
            submitted_config("metrics", false),
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
    fn core_peer_context_separates_config_versions_from_live_support() {
        let config = submitted_config("before", false);
        let context = CorePeerContext::new(
            config.clone(),
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );

        assert_eq!(context.hostname(), "before");
        assert!(!context.feature_flags().avoid_relay_data);

        context.set_avoid_relay_data_preference(true);
        assert!(context.feature_flags().avoid_relay_data);

        let mut next = (*config.snapshot()).clone();
        next.parsed_mut().hostname = "after".to_owned();
        next.parsed_mut().flags.disable_relay_data = true;
        config.replace(next);
        context.set_avoid_relay_data_preference(false);
        assert_eq!(context.hostname(), "after");
        assert!(context.feature_flags().avoid_relay_data);

        let mut next = (*config.snapshot()).clone();
        next.parsed_mut().flags.disable_relay_data = false;
        config.replace(next);
        assert!(!context.feature_flags().avoid_relay_data);
    }

    #[tokio::test]
    async fn core_peer_context_owns_events_and_projects_them_to_sink() {
        let config = submitted_config("events", false);
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
            [CoreEvent::PeerAdded(7)]
        ));
    }

    #[test]
    fn core_peer_context_owns_trusted_keys_and_projects_credential_changes() {
        let config = submitted_config("trust", false);
        let events = Arc::new(TestPeerEventSink::default());
        let context = CorePeerContext::new(
            config,
            Arc::new(()),
            test_core_context_adapters(events.clone()),
        );
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
        assert!(events.credential_changed.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn foreign_forward_limiter_is_independent_from_peer_receive_limiter() {
        let mut parsed = crate::config::InstanceConfigParsed {
            hostname: "limiter".to_owned(),
            ..Default::default()
        };
        parsed.flags.foreign_relay_bps_limit = 1024;
        let config = InstanceConfigStore::from(parsed);
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
        let mut parsed = crate::config::InstanceConfigParsed {
            hostname: "limiter".to_owned(),
            ..Default::default()
        };
        parsed.flags.foreign_relay_bps_limit = u64::MAX;
        parsed.flags.instance_recv_bps_limit = 1024;
        let config = InstanceConfigStore::from(parsed);
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

    #[test]
    fn core_owned_peer_context_reads_normalized_snapshot() {
        let instance_id = uuid::Uuid::from_u128(0x00112233445566778899aabbccddeeff);
        let mut flags = Flags::default();
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
        let parsed = crate::config::InstanceConfigParsed {
            instance_id,
            hostname: "config-node".to_owned(),
            ipv4: Some("10.20.0.7/16".parse().unwrap()),
            ipv6: Some("2001:db8::7/64".parse().unwrap()),
            proxy_network: vec![
                crate::config::toml::ProxyNetworkConfig {
                    cidr: "10.40.0.0/16".parse().unwrap(),
                    mapped_cidr: Some("10.50.0.0/16".parse().unwrap()),
                    allow: None,
                },
                crate::config::toml::ProxyNetworkConfig {
                    cidr: "10.60.0.0/16".parse().unwrap(),
                    mapped_cidr: None,
                    allow: None,
                },
            ],
            network_identity: NetworkIdentity {
                network_name: "config-net".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            },
            flags: flags.clone(),
            secure_mode: Some(SecureModeConfig {
                enabled: true,
                ..Default::default()
            }),
            acl: Some(acl),
            ..Default::default()
        };
        let mut adapters = test_core_context_adapters(Arc::new(()));
        adapters.host_routing = HostRoutingPolicy {
            local_exit_node_fallback: true,
        };
        let store = InstanceConfigStore::from(parsed);
        let context = CorePeerContext::new(store, Arc::new(()), adapters);

        assert_eq!(context.network_identity().network_name, "config-net");
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

        let mut live = StunInfo::default();
        live.tcp_nat_type = 4;
        let mut adapters = test_core_context_adapters(Arc::new(()));
        adapters.stun_info_source = Some(Arc::new(TestStunInfoSource(live.clone())));
        let store = InstanceConfigStore::new(crate::config::InstanceConfig::default());
        let context = CorePeerContext::new(store, Arc::new(()), adapters);

        assert_eq!(context.stun_info(), live);
    }

    #[tokio::test]
    async fn core_owned_peer_context_preserves_fallback_stun_and_notifies_dhcp() {
        let parsed = crate::config::InstanceConfigParsed {
            ipv4: Some("10.0.0.1/24".parse().unwrap()),
            ..Default::default()
        };
        let store = InstanceConfigStore::from(parsed);
        let context = CorePeerContext::new(
            store.clone(),
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );

        let mut live = StunInfo::default();
        live.tcp_nat_type = 5;
        context.set_fallback_stun_info(live.clone());
        assert_eq!(context.stun_info(), live);

        // When DHCP is false, ipv4() returns static configured IPv4
        assert_eq!(context.ipv4(), Some("10.0.0.1/24".parse().unwrap()));

        let mut changes = context.subscribe_runtime_changes().unwrap();
        assert_eq!(*changes.borrow(), 0);

        // Enable DHCP in runtime config
        let mut next = (*store.snapshot()).clone();
        next.parsed_mut().dhcp = true;
        store.replace(next);
        assert!(context.dhcp_enabled());
        // Since no DHCP lease has been applied, ipv4() returns None
        assert_eq!(context.ipv4(), None);
        assert!(changes.changed().await.is_ok());
        assert_eq!(*changes.borrow(), 1);

        let dhcp_lease: Ipv4Inet = "10.126.0.5/24".parse().unwrap();
        context.set_dhcp_ipv4(Some(dhcp_lease));
        assert_eq!(context.ipv4(), Some(dhcp_lease));
        assert!(changes.changed().await.is_ok());
        assert_eq!(*changes.borrow(), 2);

        // Same address set again does not notify
        context.set_dhcp_ipv4(Some(dhcp_lease));
        assert_eq!(*changes.borrow(), 2);
    }

    #[tokio::test]
    async fn core_owned_peer_context_publishes_peer_events_per_instance() {
        let store = InstanceConfigStore::new(crate::config::InstanceConfig::default());
        let context = CorePeerContext::new(
            store,
            Arc::new(()),
            test_core_context_adapters(Arc::new(())),
        );
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

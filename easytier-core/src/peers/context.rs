use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use dashmap::DashMap;
use easytier_proto::{
    common::{FlagsInConfig, PeerFeatureFlag, SecureModeConfig, StunInfo, TunnelInfo},
    peer_rpc::{PeerGroupInfo, TrustedCredentialPubkeyProof},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub use crate::config::{NetworkIdentity, NetworkSecretDigest};
use crate::{
    config::{
        CoreConfig, IpPrefix, NodeConfig, PeerId, PeerPolicyConfig, RouteConfig, TrafficConfig,
    },
    peers::util::shrink_dashmap,
};

pub const SECRET_PROOF_PREFIX: &[u8] = b"easytier secret proof";

#[async_trait]
pub trait ByteLimiter: Send + Sync {
    async fn consume(&self, bytes: u64);
}

#[async_trait]
impl ByteLimiter for () {
    async fn consume(&self, _bytes: u64) {}
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

#[derive(Debug, Clone)]
pub struct PeerRuntimeConfig {
    pub core: CoreConfig,
    pub network_identity: NetworkIdentity,
    pub stun_info: StunInfo,
    pub feature_flags: PeerFeatureFlag,
    pub secure_mode: Option<SecureModeConfig>,
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
        }
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

    fn vpn_portal_cidr(&self) -> Option<Ipv4Cidr> {
        None
    }

    fn hostname(&self) -> String {
        String::new()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        PeerFeatureFlag::default()
    }

    fn easytier_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        10
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

#[cfg(test)]
mod tests {
    use super::*;

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

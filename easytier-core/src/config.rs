use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::IpAddr,
};

use easytier_proto::{common as common_pb, core_config as pb};
use serde::{Deserialize, Serialize};

pub type PeerId = u32;

pub type NetworkSecretDigest = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIdentity {
    pub network_name: String,
    pub network_secret: Option<String>,
    pub network_secret_digest: Option<NetworkSecretDigest>,
}

impl NetworkIdentity {
    pub fn new(network_name: String, network_secret: String) -> Self {
        Self {
            network_secret_digest: Some(network_secret_digest(&network_name, &network_secret)),
            network_name,
            network_secret: Some(network_secret),
        }
    }

    pub fn new_credential(network_name: String) -> Self {
        Self {
            network_name,
            network_secret: None,
            network_secret_digest: None,
        }
    }

    pub fn secret_digest(&self) -> Option<NetworkSecretDigest> {
        if self.network_secret_digest.is_some() {
            self.network_secret_digest
        } else if let Some(network_secret) = &self.network_secret {
            let mut network_secret_digest = [0u8; 32];
            generate_digest_from_str(
                &self.network_name,
                network_secret,
                &mut network_secret_digest,
            );
            Some(network_secret_digest)
        } else {
            None
        }
    }

    pub fn with_secret_digest(mut self) -> Self {
        self.network_secret_digest = self.secret_digest();
        self
    }
}

#[derive(Eq, PartialEq, Hash)]
struct NetworkIdentityWithOnlyDigest {
    network_name: String,
    network_secret_digest: Option<NetworkSecretDigest>,
}

fn generate_digest_from_str(str1: &str, str2: &str, digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());

    assert_eq!(digest.len() % 8, 0, "digest length must be multiple of 8");

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

fn network_secret_digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
    let mut digest = [0u8; 32];
    generate_digest_from_str(network_name, network_secret, &mut digest);
    digest
}

impl From<NetworkIdentity> for NetworkIdentityWithOnlyDigest {
    fn from(identity: NetworkIdentity) -> Self {
        Self {
            network_secret_digest: identity.secret_digest(),
            network_name: identity.network_name,
        }
    }
}

impl PartialEq for NetworkIdentity {
    fn eq(&self, other: &Self) -> bool {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        let other_with_digest = NetworkIdentityWithOnlyDigest::from(other.clone());
        self_with_digest == other_with_digest
    }
}

impl Eq for NetworkIdentity {}

impl Hash for NetworkIdentity {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let self_with_digest = NetworkIdentityWithOnlyDigest::from(self.clone());
        self_with_digest.hash(state);
    }
}

impl Default for NetworkIdentity {
    fn default() -> Self {
        Self::new("default".to_string(), "".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoreConfig {
    pub node: NodeConfig,
    pub routes: RouteConfig,
    pub peer_policy: PeerPolicyConfig,
    pub traffic: TrafficConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct NodeConfig {
    pub peer_id: Option<PeerId>,
    pub instance_id: Option<[u8; 16]>,
    pub hostname: Option<String>,
    pub network_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RouteConfig {
    pub ipv4: Option<IpPrefix>,
    pub ipv6: Option<IpPrefix>,
    pub advertised_routes: Vec<IpPrefix>,
    pub proxy_networks: Vec<ProxyNetworkConfig>,
    pub foreign_networks: Vec<ForeignNetworkConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpPrefix {
    pub address: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyNetworkConfig {
    pub real: IpPrefix,
    pub mapped: Option<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForeignNetworkConfig {
    pub name: String,
    pub cidrs: Vec<IpPrefix>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerPolicyConfig {
    pub p2p_enabled: bool,
    pub relay_peer_rpc: bool,
    pub relay_data: bool,
    pub latency_first: bool,
    pub encryption_required: bool,
}

impl Default for PeerPolicyConfig {
    fn default() -> Self {
        Self {
            p2p_enabled: true,
            relay_peer_rpc: false,
            relay_data: true,
            latency_first: false,
            encryption_required: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub disable_upnp: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrafficConfig {
    pub mtu: Option<u16>,
    pub instance_recv_bps_limit: Option<u64>,
    pub foreign_relay_bps_limit: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required field: {0}")]
    MissingField(&'static str),
    #[error("invalid IPv4 prefix length: {0}")]
    InvalidIpv4Prefix(u8),
    #[error("invalid IPv6 prefix length: {0}")]
    InvalidIpv6Prefix(u8),
    #[error("invalid MTU: {0}")]
    InvalidMtu(u32),
}

impl IpPrefix {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, ConfigError> {
        match address {
            IpAddr::V4(_) if prefix_len <= 32 => Ok(Self {
                address,
                prefix_len,
            }),
            IpAddr::V4(_) => Err(ConfigError::InvalidIpv4Prefix(prefix_len)),
            IpAddr::V6(_) if prefix_len <= 128 => Ok(Self {
                address,
                prefix_len,
            }),
            IpAddr::V6(_) => Err(ConfigError::InvalidIpv6Prefix(prefix_len)),
        }
    }
}

impl TryFrom<pb::CoreConfig> for CoreConfig {
    type Error = ConfigError;

    fn try_from(value: pb::CoreConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            node: value
                .node
                .map(TryInto::try_into)
                .transpose()?
                .unwrap_or_default(),
            routes: value
                .routes
                .map(TryInto::try_into)
                .transpose()?
                .unwrap_or_default(),
            peer_policy: value.peer_policy.map(Into::into).unwrap_or_default(),
            traffic: value
                .traffic
                .map(TryInto::try_into)
                .transpose()?
                .unwrap_or_default(),
        })
    }
}

impl From<CoreConfig> for pb::CoreConfig {
    fn from(value: CoreConfig) -> Self {
        Self {
            node: Some(value.node.into()),
            routes: Some(value.routes.into()),
            peer_policy: Some(value.peer_policy.into()),
            traffic: Some(value.traffic.into()),
        }
    }
}

impl TryFrom<pb::NodeConfig> for NodeConfig {
    type Error = ConfigError;

    fn try_from(value: pb::NodeConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            peer_id: value.peer_id,
            instance_id: value.instance_id.map(uuid_to_bytes),
            hostname: value.hostname,
            network_name: value.network_name,
        })
    }
}

impl From<NodeConfig> for pb::NodeConfig {
    fn from(value: NodeConfig) -> Self {
        Self {
            peer_id: value.peer_id,
            instance_id: value.instance_id.map(uuid_from_bytes),
            hostname: value.hostname,
            network_name: value.network_name,
        }
    }
}

impl TryFrom<pb::RouteConfig> for RouteConfig {
    type Error = ConfigError;

    fn try_from(value: pb::RouteConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            ipv4: value.ipv4.map(TryInto::try_into).transpose()?,
            ipv6: value.ipv6.map(TryInto::try_into).transpose()?,
            advertised_routes: value
                .advertised_routes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            proxy_networks: value
                .proxy_networks
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            foreign_networks: value
                .foreign_networks
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<RouteConfig> for pb::RouteConfig {
    fn from(value: RouteConfig) -> Self {
        Self {
            ipv4: value.ipv4.map(Into::into),
            ipv6: value.ipv6.map(Into::into),
            advertised_routes: value
                .advertised_routes
                .into_iter()
                .map(Into::into)
                .collect(),
            proxy_networks: value.proxy_networks.into_iter().map(Into::into).collect(),
            foreign_networks: value.foreign_networks.into_iter().map(Into::into).collect(),
        }
    }
}

impl TryFrom<pb::IpPrefix> for IpPrefix {
    type Error = ConfigError;

    fn try_from(value: pb::IpPrefix) -> Result<Self, Self::Error> {
        let address = pb_ip_addr_to_std(
            value
                .address
                .ok_or(ConfigError::MissingField("IpPrefix.address"))?,
        )?;
        let prefix_len = u8::try_from(value.prefix_len)
            .map_err(|_| invalid_prefix_for_address(address, value.prefix_len))?;
        Self::new(address, prefix_len)
    }
}

impl From<IpPrefix> for pb::IpPrefix {
    fn from(value: IpPrefix) -> Self {
        Self {
            address: Some(value.address.into()),
            prefix_len: value.prefix_len.into(),
        }
    }
}

impl TryFrom<pb::ProxyNetworkConfig> for ProxyNetworkConfig {
    type Error = ConfigError;

    fn try_from(value: pb::ProxyNetworkConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            real: value
                .real
                .ok_or(ConfigError::MissingField("ProxyNetworkConfig.real"))?
                .try_into()?,
            mapped: value.mapped.map(TryInto::try_into).transpose()?,
        })
    }
}

impl From<ProxyNetworkConfig> for pb::ProxyNetworkConfig {
    fn from(value: ProxyNetworkConfig) -> Self {
        Self {
            real: Some(value.real.into()),
            mapped: value.mapped.map(Into::into),
        }
    }
}

impl TryFrom<pb::ForeignNetworkConfig> for ForeignNetworkConfig {
    type Error = ConfigError;

    fn try_from(value: pb::ForeignNetworkConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            cidrs: value
                .cidrs
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl From<ForeignNetworkConfig> for pb::ForeignNetworkConfig {
    fn from(value: ForeignNetworkConfig) -> Self {
        Self {
            name: value.name,
            cidrs: value.cidrs.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<pb::PeerPolicyConfig> for PeerPolicyConfig {
    fn from(value: pb::PeerPolicyConfig) -> Self {
        let default = Self::default();
        Self {
            p2p_enabled: value.p2p_enabled.unwrap_or(default.p2p_enabled),
            relay_peer_rpc: value.relay_peer_rpc.unwrap_or(default.relay_peer_rpc),
            relay_data: value.relay_data.unwrap_or(default.relay_data),
            latency_first: value.latency_first.unwrap_or(default.latency_first),
            encryption_required: value
                .encryption_required
                .unwrap_or(default.encryption_required),
        }
    }
}

impl From<PeerPolicyConfig> for pb::PeerPolicyConfig {
    fn from(value: PeerPolicyConfig) -> Self {
        Self {
            p2p_enabled: Some(value.p2p_enabled),
            relay_peer_rpc: Some(value.relay_peer_rpc),
            relay_data: Some(value.relay_data),
            latency_first: Some(value.latency_first),
            encryption_required: Some(value.encryption_required),
        }
    }
}

impl TryFrom<pb::TrafficConfig> for TrafficConfig {
    type Error = ConfigError;

    fn try_from(value: pb::TrafficConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            mtu: value
                .mtu
                .map(|mtu| u16::try_from(mtu).map_err(|_| ConfigError::InvalidMtu(mtu)))
                .transpose()?,
            instance_recv_bps_limit: value.instance_recv_bps_limit,
            foreign_relay_bps_limit: value.foreign_relay_bps_limit,
        })
    }
}

impl From<TrafficConfig> for pb::TrafficConfig {
    fn from(value: TrafficConfig) -> Self {
        Self {
            mtu: value.mtu.map(Into::into),
            instance_recv_bps_limit: value.instance_recv_bps_limit,
            foreign_relay_bps_limit: value.foreign_relay_bps_limit,
        }
    }
}

fn pb_ip_addr_to_std(value: common_pb::IpAddr) -> Result<IpAddr, ConfigError> {
    match value.ip.ok_or(ConfigError::MissingField("IpAddr.ip"))? {
        common_pb::ip_addr::Ip::Ipv4(addr) => Ok(IpAddr::V4(addr.into())),
        common_pb::ip_addr::Ip::Ipv6(addr) => Ok(IpAddr::V6(addr.into())),
    }
}

fn invalid_prefix_for_address(address: IpAddr, prefix_len: u32) -> ConfigError {
    let prefix_len = u8::try_from(prefix_len).unwrap_or(u8::MAX);
    match address {
        IpAddr::V4(_) => ConfigError::InvalidIpv4Prefix(prefix_len),
        IpAddr::V6(_) => ConfigError::InvalidIpv6Prefix(prefix_len),
    }
}

fn uuid_to_bytes(value: common_pb::Uuid) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[0..4].copy_from_slice(&value.part1.to_be_bytes());
    bytes[4..8].copy_from_slice(&value.part2.to_be_bytes());
    bytes[8..12].copy_from_slice(&value.part3.to_be_bytes());
    bytes[12..16].copy_from_slice(&value.part4.to_be_bytes());
    bytes
}

fn uuid_from_bytes(bytes: [u8; 16]) -> common_pb::Uuid {
    common_pb::Uuid {
        part1: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        part2: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        part3: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        part4: u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
        let mut digest = [0u8; 32];
        generate_digest_from_str(network_name, network_secret, &mut digest);
        digest
    }

    #[test]
    fn network_identity_matches_secret_to_digest_identity() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "secret")),
        };

        assert_eq!(local, remote);
    }

    #[test]
    fn network_identity_rejects_different_digest() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "other")),
        };

        assert_ne!(local, remote);
    }

    #[test]
    fn network_identity_equal_values_have_equal_hash() {
        let local = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };
        let remote = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: None,
            network_secret_digest: Some(digest("net", "secret")),
        };
        let mut local_hasher = DefaultHasher::new();
        let mut remote_hasher = DefaultHasher::new();

        local.hash(&mut local_hasher);
        remote.hash(&mut remote_hasher);

        assert_eq!(local_hasher.finish(), remote_hasher.finish());
    }

    #[test]
    fn network_identity_derives_digest_from_plaintext_secret() {
        let identity = NetworkIdentity {
            network_name: "net".to_string(),
            network_secret: Some("secret".to_string()),
            network_secret_digest: None,
        };

        assert_eq!(identity.secret_digest(), Some(digest("net", "secret")));
    }

    #[test]
    fn network_identity_default_matches_native_default_network() {
        assert_eq!(
            NetworkIdentity::default(),
            NetworkIdentity::new("default".to_string(), "".to_string())
        );
    }

    #[test]
    fn validates_ip_prefix_lengths() {
        assert!(IpPrefix::new("10.0.0.1".parse().unwrap(), 24).is_ok());
        assert_eq!(
            IpPrefix::new("10.0.0.1".parse().unwrap(), 33),
            Err(ConfigError::InvalidIpv4Prefix(33))
        );
        assert!(IpPrefix::new("2001:db8::1".parse().unwrap(), 64).is_ok());
        assert_eq!(
            IpPrefix::new("2001:db8::1".parse().unwrap(), 129),
            Err(ConfigError::InvalidIpv6Prefix(129))
        );
    }

    #[test]
    fn converts_core_config_from_proto_defaults() {
        let config = CoreConfig::try_from(pb::CoreConfig {
            node: Some(pb::NodeConfig {
                peer_id: Some(7),
                instance_id: None,
                hostname: Some("node-a".to_string()),
                network_name: "net".to_string(),
            }),
            routes: None,
            peer_policy: None,
            traffic: Some(pb::TrafficConfig {
                mtu: Some(1380),
                instance_recv_bps_limit: Some(100),
                foreign_relay_bps_limit: None,
            }),
        })
        .unwrap();

        assert_eq!(config.node.peer_id, Some(7));
        assert_eq!(config.node.hostname.as_deref(), Some("node-a"));
        assert!(config.peer_policy.p2p_enabled);
        assert_eq!(config.traffic.mtu, Some(1380));
    }

    #[test]
    fn converts_ip_prefix_round_trip() {
        let prefix = IpPrefix::new("10.1.0.1".parse().unwrap(), 16).unwrap();
        let pb: pb::IpPrefix = prefix.clone().into();
        assert_eq!(IpPrefix::try_from(pb).unwrap(), prefix);
    }
}

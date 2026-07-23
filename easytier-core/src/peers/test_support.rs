//! Test-only peer-context fakes shared by peer-domain unit tests
//! (`peers::tests`, `peers::route::peer_ospf_route::tests`, and
//! `context::tests`). Kept out of `context.rs` so the context unit tests and
//! their consumers share one definition.

use std::net::IpAddr;

use cidr::{Ipv4Inet, Ipv6Inet};
use easytier_proto::common::{FlagsInConfig, SecureModeConfig};
use hmac::Hmac;
use sha2::Sha256;

use crate::{
    config::peers::PeerRuntimeConfig,
    config::{CoreConfig, IpPrefix, NodeConfig, PeerPolicyConfig, RouteConfig, TrafficConfig},
    peers::context::{NetworkIdentity, PeerContext, secret_proof_from_secret},
};

pub(crate) trait PeerContextTestExt: PeerContext {
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
}

fn ipv4_inet_to_config(value: Ipv4Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V4(value.address()), value.network_length())
        .expect("Ipv4Inet should always have a valid IPv4 prefix length")
}

fn ipv6_inet_to_config(value: Ipv6Inet) -> IpPrefix {
    IpPrefix::new(IpAddr::V6(value.address()), value.network_length())
        .expect("Ipv6Inet should always have a valid IPv6 prefix length")
}

#[derive(Debug, Clone)]
pub(crate) struct NoopPeerContext {
    network_identity: NetworkIdentity,
    flags: FlagsInConfig,
    secure_mode: Option<SecureModeConfig>,
}

impl NoopPeerContext {
    pub(crate) fn new(network_identity: NetworkIdentity) -> Self {
        Self {
            network_identity,
            flags: FlagsInConfig::default(),
            secure_mode: None,
        }
    }
}

impl Default for NoopPeerContext {
    fn default() -> Self {
        Self::new(NetworkIdentity::default())
    }
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

impl PeerContextTestExt for NoopPeerContext {}

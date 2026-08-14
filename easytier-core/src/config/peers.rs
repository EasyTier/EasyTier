//! Peer-flavored configuration data owned by the config layer.
//!
//! These types are pure serializable configuration snapshots. Normalization
//! and derivation behavior that depends on peer-domain logic stays in
//! `crate::peers`.

use anyhow::Context as _;
use cidr::{Ipv4Cidr, Ipv6Cidr};
use easytier_proto::common::{FlagsInConfig, PeerFeatureFlag, SecureModeConfig, StunInfo};
use serde::{Deserialize, Serialize};

use crate::proto::acl::{Acl, AclV1, Action, Chain, ChainType, GroupInfo, Protocol, Rule};

use super::{CoreConfig, NetworkIdentity};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AclRuleConfig {
    pub acl: Option<Acl>,
    pub tcp_whitelist: Vec<String>,
    pub udp_whitelist: Vec<String>,
    pub whitelist_priority: Option<u32>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclWhitelistSnapshot {
    pub tcp_ports: Vec<String>,
    pub udp_ports: Vec<String>,
}

impl From<&AclRuleConfig> for AclWhitelistSnapshot {
    fn from(config: &AclRuleConfig) -> Self {
        Self {
            tcp_ports: config.tcp_whitelist.clone(),
            udp_ports: config.udp_whitelist.clone(),
        }
    }
}

impl AclRuleConfig {
    fn parse_port_list(port_list: &[String]) -> anyhow::Result<Vec<String>> {
        let mut ports = Vec::new();

        for port_spec in port_list {
            if port_spec.contains('-') {
                let parts: Vec<&str> = port_spec.split('-').collect();
                if parts.len() != 2 {
                    return Err(anyhow::anyhow!("Invalid port range format: {}", port_spec));
                }

                let start: u16 = parts[0]
                    .parse()
                    .with_context(|| format!("Invalid start port in range: {}", port_spec))?;
                let end: u16 = parts[1]
                    .parse()
                    .with_context(|| format!("Invalid end port in range: {}", port_spec))?;

                if start > end {
                    return Err(anyhow::anyhow!(
                        "Start port must be <= end port in range: {}",
                        port_spec
                    ));
                }
                ports.push(port_spec.clone());
            } else {
                let port: u16 = port_spec
                    .parse()
                    .with_context(|| format!("Invalid port number: {}", port_spec))?;
                ports.push(port.to_string());
            }
        }

        Ok(ports)
    }

    fn generate_acl_from_whitelists(&mut self) -> anyhow::Result<()> {
        if self.tcp_whitelist.is_empty() && self.udp_whitelist.is_empty() {
            return Ok(());
        }

        let mut inbound_chain = Chain {
            name: "inbound_whitelist".to_string(),
            chain_type: ChainType::Inbound as i32,
            description: "Auto-generated inbound whitelist from CLI".to_string(),
            enabled: true,
            rules: vec![],
            default_action: Action::Allow as i32,
        };

        let mut rule_priority = self.whitelist_priority.unwrap_or(1000u32);

        if !self.tcp_whitelist.is_empty() {
            let tcp_ports = Self::parse_port_list(&self.tcp_whitelist)?;
            inbound_chain.rules.push(Rule {
                name: "tcp_whitelist".to_string(),
                description: "Auto-generated TCP whitelist rule".to_string(),
                priority: rule_priority,
                enabled: true,
                protocol: Protocol::Tcp as i32,
                ports: tcp_ports,
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Allow as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: true,
                source_groups: vec![],
                destination_groups: vec![],
            });
            inbound_chain.rules.push(Rule {
                name: "tcp_whitelist_deny_other".to_string(),
                description: "Auto-generated TCP whitelist rule to deny other ports".to_string(),
                priority: 0,
                enabled: true,
                protocol: Protocol::Tcp as i32,
                ports: vec!["0-65535".to_string()],
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Drop as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: false,
                source_groups: vec![],
                destination_groups: vec![],
            });
            rule_priority -= 1;
        }

        if !self.udp_whitelist.is_empty() {
            let udp_ports = Self::parse_port_list(&self.udp_whitelist)?;
            inbound_chain.rules.push(Rule {
                name: "udp_whitelist".to_string(),
                description: "Auto-generated UDP whitelist rule".to_string(),
                priority: rule_priority,
                enabled: true,
                protocol: Protocol::Udp as i32,
                ports: udp_ports,
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Allow as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: false,
                source_groups: vec![],
                destination_groups: vec![],
            });
            inbound_chain.rules.push(Rule {
                name: "udp_whitelist_deny_other".to_string(),
                description: "Auto-generated UDP whitelist rule to deny other ports".to_string(),
                priority: 0,
                enabled: true,
                protocol: Protocol::Udp as i32,
                ports: vec!["0-65535".to_string()],
                source_ips: vec![],
                destination_ips: vec![],
                source_ports: vec![],
                action: Action::Drop as i32,
                rate_limit: 0,
                burst_limit: 0,
                stateful: false,
                source_groups: vec![],
                destination_groups: vec![],
            });
        }

        if self.acl.is_none() {
            self.acl = Some(Acl::default());
        }

        let acl = self.acl.as_mut().expect("ACL was initialized above");
        if let Some(acl_v1) = acl.acl_v1.as_mut() {
            acl_v1.chains.push(inbound_chain);
        } else {
            acl.acl_v1 = Some(AclV1 {
                chains: vec![inbound_chain],
                group: Some(GroupInfo {
                    declares: vec![],
                    members: vec![],
                }),
            });
        }

        Ok(())
    }

    pub fn build(&self) -> anyhow::Result<Option<Acl>> {
        let mut config = self.clone();
        config.generate_acl_from_whitelists()?;
        Ok(config.acl)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIpv6ProviderConfig {
    pub provider_enabled: bool,
    pub configured_prefix: Option<Ipv6Cidr>,
    pub provider_supported: bool,
}

impl PublicIpv6ProviderConfig {
    pub fn should_run_reconcile(self) -> bool {
        self.provider_enabled
    }
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

impl PeerRuntimeSnapshot {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerGroupIdentity {
    pub group_name: String,
    pub group_secret: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whitelist_rules_are_built_in_core() {
        let acl = AclRuleConfig {
            tcp_whitelist: vec!["80".to_string(), "8000-9000".to_string()],
            udp_whitelist: vec!["53".to_string()],
            ..Default::default()
        }
        .build()
        .unwrap()
        .unwrap();

        let chain = &acl.acl_v1.unwrap().chains[0];
        assert_eq!(chain.name, "inbound_whitelist");
        assert_eq!(chain.rules.len(), 4);
        assert_eq!(chain.rules[0].ports, ["80", "8000-9000"]);
        assert_eq!(chain.rules[2].ports, ["53"]);
    }

    #[test]
    fn invalid_whitelist_range_is_rejected() {
        let error = AclRuleConfig {
            tcp_whitelist: vec!["9000-8000".to_string()],
            ..Default::default()
        }
        .build()
        .unwrap_err();

        assert!(error.to_string().contains("Start port must be <= end port"));
    }
}

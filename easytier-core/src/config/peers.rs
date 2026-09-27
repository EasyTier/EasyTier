//! Peer-flavored configuration data owned by the config layer.
//!
//! These types are pure serializable configuration snapshots. Normalization
//! and derivation behavior that depends on peer-domain logic stays in
//! `crate::peers`.

use anyhow::Context as _;
use cidr::Ipv6Cidr;
use serde::{Deserialize, Serialize};

use crate::proto::acl::{Acl, AclV1, Action, Chain, ChainType, GroupInfo, Protocol, Rule};

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

impl From<&crate::config::InstanceConfigParsed> for AclRuleConfig {
    fn from(config: &crate::config::InstanceConfigParsed) -> Self {
        Self {
            acl: config.acl.clone(),
            tcp_whitelist: config.tcp_whitelist.clone(),
            udp_whitelist: config.udp_whitelist.clone(),
            whitelist_priority: None,
        }
    }
}

impl From<&crate::config::InstanceConfig> for AclRuleConfig {
    fn from(config: &crate::config::InstanceConfig) -> Self {
        Self::from(&**config)
    }
}

impl From<&AclRuleConfig> for AclWhitelistSnapshot {
    fn from(config: &AclRuleConfig) -> Self {
        Self {
            tcp_ports: config.tcp_whitelist.clone(),
            udp_ports: config.udp_whitelist.clone(),
        }
    }
}

impl From<&crate::config::InstanceConfigParsed> for AclWhitelistSnapshot {
    fn from(config: &crate::config::InstanceConfigParsed) -> Self {
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

    pub(crate) fn for_credential_peer(&self) -> Self {
        let mut config = self.clone();
        if let Some(acl) = config.acl.as_mut().and_then(|acl| acl.acl_v1.as_mut()) {
            acl.group = None;
        }
        config
    }

    pub fn strip_group_material_from_acl(acl: Option<&Acl>) -> Option<Acl> {
        strip_group_material_from_acl(acl)
    }

    pub fn build(&self) -> anyhow::Result<Option<Acl>> {
        let mut config = self.clone();
        config.generate_acl_from_whitelists()?;
        Ok(config.acl)
    }
}

pub fn strip_group_material_from_acl(acl: Option<&Acl>) -> Option<Acl> {
    let mut acl = acl.cloned()?;
    if let Some(acl_v1) = acl.acl_v1.as_mut() {
        acl_v1.group = None;
    }
    Some(acl)
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

impl From<&crate::config::InstanceConfigParsed> for PublicIpv6ProviderConfig {
    fn from(config: &crate::config::InstanceConfigParsed) -> Self {
        Self {
            provider_enabled: config.ipv6_public_addr_provider,
            configured_prefix: config.ipv6_public_addr_prefix,
            provider_supported: cfg!(target_os = "linux"),
        }
    }
}

impl From<&crate::config::InstanceConfig> for PublicIpv6ProviderConfig {
    fn from(config: &crate::config::InstanceConfig) -> Self {
        config.parsed().into()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostRoutingPolicy {
    /// Route otherwise-unreachable external IPv4 traffic through this node and
    /// keep self-delivered packets eligible for the host TUN/proxy path.
    pub local_exit_node_fallback: bool,
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

    #[test]
    fn credential_peer_acl_preserves_chains_without_group_secrets() {
        let config = AclRuleConfig {
            acl: Some(Acl {
                acl_v1: Some(AclV1 {
                    chains: vec![Chain {
                        name: "forward".to_owned(),
                        chain_type: ChainType::Forward as i32,
                        rules: vec![Rule {
                            action: Action::Drop as i32,
                            ..Default::default()
                        }],
                        ..Default::default()
                    }],
                    group: Some(GroupInfo {
                        declares: vec![crate::proto::acl::GroupIdentity {
                            group_name: "ops".to_owned(),
                            group_secret: "secret".to_owned(),
                        }],
                        members: vec!["ops".to_owned()],
                    }),
                }),
            }),
            tcp_whitelist: vec!["22".to_owned()],
            ..Default::default()
        };

        let sanitized = config.for_credential_peer();

        let acl = sanitized.acl.unwrap().acl_v1.unwrap();
        assert_eq!(acl.chains.len(), 1);
        assert_eq!(acl.chains[0].name, "forward");
        assert_eq!(acl.chains[0].rules[0].action, Action::Drop as i32);
        assert!(acl.group.is_none());
        assert_eq!(sanitized.tcp_whitelist, ["22"]);
        assert!(config.acl.unwrap().acl_v1.unwrap().group.is_some());
    }
}

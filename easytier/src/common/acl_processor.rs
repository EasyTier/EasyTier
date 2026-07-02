pub use easytier_core::peers::acl_processor::*;

use anyhow::Context as _;

use crate::{
    common::{config::ConfigLoader, global_ctx::ArcGlobalCtx},
    proto::acl::*,
};

pub struct AclRuleBuilder {
    pub acl: Option<Acl>,
    pub tcp_whitelist: Vec<String>,
    pub udp_whitelist: Vec<String>,
    pub whitelist_priority: Option<u32>,
}

impl AclRuleBuilder {
    fn parse_port_list(port_list: &[String]) -> anyhow::Result<Vec<String>> {
        let mut ports = Vec::new();

        for port_spec in port_list {
            if port_spec.contains('-') {
                // Handle port range like "8000-9000"
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

                // acl can handle port range
                ports.push(port_spec.clone());
            } else {
                // Handle single port
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

        // Create inbound chain for whitelist rules
        let mut inbound_chain = Chain {
            name: "inbound_whitelist".to_string(),
            chain_type: ChainType::Inbound as i32,
            description: "Auto-generated inbound whitelist from CLI".to_string(),
            enabled: true,
            rules: vec![],
            default_action: Action::Allow as i32,
        };

        let mut rule_priority = self.whitelist_priority.unwrap_or(1000u32);

        // Add TCP whitelist rules
        if !self.tcp_whitelist.is_empty() {
            let tcp_ports = Self::parse_port_list(&self.tcp_whitelist)?;
            let tcp_rule = Rule {
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
            };
            let tcp_rule_deny_other = Rule {
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
            };
            inbound_chain.rules.push(tcp_rule);
            inbound_chain.rules.push(tcp_rule_deny_other);
            rule_priority -= 1;
        }

        // Add UDP whitelist rules
        if !self.udp_whitelist.is_empty() {
            let udp_ports = Self::parse_port_list(&self.udp_whitelist)?;
            let udp_rule = Rule {
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
            };
            let udp_rule_deny_other = Rule {
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
            };
            inbound_chain.rules.push(udp_rule);
            inbound_chain.rules.push(udp_rule_deny_other);
        }

        if self.acl.is_none() {
            self.acl = Some(Acl::default());
        }

        let acl = self.acl.as_mut().unwrap();

        if let Some(ref mut acl_v1) = acl.acl_v1 {
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

    fn do_build(mut self) -> anyhow::Result<Option<Acl>> {
        self.generate_acl_from_whitelists()?;
        Ok(self.acl.clone())
    }

    pub fn build(global_ctx: &ArcGlobalCtx) -> anyhow::Result<Option<Acl>> {
        let builder = AclRuleBuilder {
            acl: global_ctx.config.get_acl(),
            tcp_whitelist: global_ctx.config.get_tcp_whitelist(),
            udp_whitelist: global_ctx.config.get_udp_whitelist(),
            whitelist_priority: None,
        };
        builder.do_build()
    }
}

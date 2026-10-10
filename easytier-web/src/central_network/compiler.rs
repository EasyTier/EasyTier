use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
};

use easytier::{
    common::config::{NetworkConfig, NetworkConfigExt, NetworkingMethod},
    proto::{
        acl::{Acl, AclV1, Action, Chain, ChainType, GroupInfo, Protocol, Rule},
        api::manage::ManagedCredentialConfig,
        common::SecureModeConfig,
    },
};
use easytier_core::{
    connectivity::manual::validate_manual_url,
    gateway::vpn_portal::{PortalRuntimeConfig, validate_clients},
    peers::credential_manager::validate_managed_credential_set,
};
use uuid::Uuid;

use super::model::{
    AclAction, AclDestination, AclPolicy, AclProtocol, AclProtocolTarget, AclSource,
    CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent, NetworkMemberIntent,
    NetworkMode, member_group_name,
};

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledNetwork {
    pub members: Vec<CompiledMember>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CompiledMember {
    pub member_id: Uuid,
    pub device_id: String,
    pub network_config: NetworkConfig,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CompileError {
    #[error("display name must not be empty")]
    EmptyDisplayName,
    #[error("network name must not be empty")]
    EmptyNetworkName,
    #[error("network secret must not be empty")]
    EmptyNetworkSecret,
    #[error("invalid network URL: {0}")]
    InvalidUrl(String),
    #[error("manual networking requires at least one peer URL")]
    EmptyPeerUrls,
    #[error("duplicate device in network intent: {0}")]
    DuplicateDevice(String),
    #[error("invalid CIDR: {0}")]
    InvalidCidr(String),
    #[error("invalid virtual subnet: {0}")]
    InvalidVirtualSubnet(String),
    #[error("invalid IPv4 address for member {member_id}: {address}")]
    InvalidMemberIp { member_id: Uuid, address: String },
    #[error("duplicate virtual IPv4 address: {0}")]
    DuplicateMemberIp(Ipv4Addr),
    #[error("virtual subnet has no free host address for member {0}")]
    SubnetExhausted(Uuid),
    #[error("invalid credential for member {member_id}: {reason}")]
    InvalidMemberCredential { member_id: Uuid, reason: String },
    #[error("invalid configuration for member {member_id}: {reason}")]
    InvalidMemberConfig { member_id: Uuid, reason: String },
    #[error("duplicate ACL rule id: {0}")]
    DuplicateAclRule(String),
    #[error("invalid ACL rule {rule_id}: {reason}")]
    InvalidAclRule { rule_id: String, reason: String },
    #[error("ACL references unknown member: {0}")]
    UnknownAclMember(Uuid),
    #[error("ACL references an ACL group not present in any credential grant: {0}")]
    UnknownAclGroup(String),
}

/// Compile a complete network intent without consulting external state.
///
/// Input order is deliberately normalized. Callers can therefore compare the
/// result directly when deciding whether materialized desired state changed.
pub fn compile(intent: &CentralNetworkIntent) -> Result<CompiledNetwork, CompileError> {
    validate_network(intent)?;

    let mut members: Vec<&NetworkMemberIntent> = intent.members.iter().collect();
    members.sort_by(|left, right| {
        left.device_id
            .cmp(&right.device_id)
            .then_with(|| left.id.cmp(&right.id))
    });
    let credentials = normalized_credentials(&intent.credentials)?;
    validate_members(intent, &members, &credentials)?;
    validate_acl(intent.acl_policy.as_ref(), &members, &credentials)?;

    let addresses = assign_addresses(intent.virtual_cidr.as_deref(), &members)?;
    let acl = compile_acl(intent.acl_policy.as_ref(), &members);
    let (networking_method, public_server_url, peer_urls) = compile_mode(&intent.mode)?;
    let managed_credentials: Vec<ManagedCredentialConfig> = credentials
        .iter()
        .map(|credential| compile_managed_credential(credential))
        .collect();

    let compiled_members = members
        .into_iter()
        .map(|member| {
            let credential = member
                .credential_id
                .as_deref()
                .map(|credential_id| credentials_by_id(&credentials)[credential_id]);
            let temporary = credential.is_some();
            let address = addresses.get(&member.id).copied().flatten();
            let network_length = intent
                .virtual_cidr
                .as_deref()
                .map(parse_ipv4_cidr)
                .transpose()?
                .map(|subnet| i32::from(subnet.prefix))
                .or(Some(24));

            let base_config = NetworkConfig {
                instance_id: Some(intent.id.to_string()),
                dhcp: Some(address.is_none()),
                virtual_ipv4: address.map(|address| address.to_string()),
                network_length,
                hostname: member.hostname.clone(),
                network_name: Some(intent.network_name.clone()),
                network_secret: (!temporary).then(|| intent.network_secret.clone()),
                networking_method: Some(networking_method as i32),
                public_server_url: public_server_url.clone(),
                peer_urls: peer_urls.clone(),
                secure_mode: if temporary {
                    Some(SecureModeConfig {
                        enabled: true,
                        local_private_key: credential.map(|item| item.secret.clone()),
                        ..Default::default()
                    })
                } else {
                    intent.secure_mode.then(|| SecureModeConfig {
                        enabled: true,
                        ..Default::default()
                    })
                },
                managed_credentials: if intent.secure_mode && !temporary {
                    managed_credentials.clone()
                } else {
                    Vec::new()
                },
                acl: acl.get(&member.id).cloned().flatten(),
                ..Default::default()
            };
            let network_config =
                apply_member_override(base_config, member.config_override.as_ref());
            validate_member_config(&network_config).map_err(|error| {
                CompileError::InvalidMemberConfig {
                    member_id: member.id,
                    reason: format!("{error:#}"),
                }
            })?;

            Ok(CompiledMember {
                member_id: member.id,
                device_id: member.device_id.clone(),
                network_config,
            })
        })
        .collect::<Result<Vec<_>, CompileError>>()?;

    Ok(CompiledNetwork {
        members: compiled_members,
    })
}

fn validate_member_config(config: &NetworkConfig) -> anyhow::Result<()> {
    let instance_config = config.gen_config()?;
    if let Some(portal) = instance_config.parsed().vpn_portal_config.as_ref() {
        let portal_runtime = PortalRuntimeConfig {
            clients: portal.clients.iter().cloned().map(Into::into).collect(),
        };
        validate_clients(&portal_runtime, instance_config.parsed())?;
    }
    Ok(())
}

fn apply_member_override(
    base: NetworkConfig,
    config_override: Option<&NetworkConfig>,
) -> NetworkConfig {
    let Some(config_override) = config_override else {
        return base;
    };
    let mut merged = config_override.clone();
    merged.instance_id = base.instance_id;
    merged.dhcp = base.dhcp;
    merged.virtual_ipv4 = base.virtual_ipv4;
    merged.network_length = base.network_length;
    merged.hostname = base.hostname;
    merged.network_name = base.network_name;
    merged.network_secret = base.network_secret;
    merged.networking_method = base.networking_method;
    merged.public_server_url = base.public_server_url;
    merged.peer_urls = base.peer_urls;
    merged.peers = base.peers;
    merged.secure_mode = base.secure_mode;
    merged.managed_credentials = base.managed_credentials;
    merged.acl = base.acl;
    merged.credential_file = None;
    merged
}

fn validate_network(intent: &CentralNetworkIntent) -> Result<(), CompileError> {
    if intent.display_name.trim().is_empty() {
        return Err(CompileError::EmptyDisplayName);
    }
    if intent.network_name.trim().is_empty() {
        return Err(CompileError::EmptyNetworkName);
    }
    if intent.network_secret.is_empty() {
        return Err(CompileError::EmptyNetworkSecret);
    }
    compile_mode(&intent.mode)?;
    Ok(())
}

fn compile_mode(
    mode: &NetworkMode,
) -> Result<(NetworkingMethod, Option<String>, Vec<String>), CompileError> {
    match mode {
        NetworkMode::PublicServer { url } => {
            validate_url(url)?;
            Ok((
                NetworkingMethod::PublicServer,
                Some(url.clone()),
                Vec::new(),
            ))
        }
        NetworkMode::Manual { peer_urls } => {
            if peer_urls.is_empty() {
                return Err(CompileError::EmptyPeerUrls);
            }
            for peer_url in peer_urls {
                validate_url(peer_url)?;
            }
            let mut peer_urls = peer_urls.clone();
            peer_urls.sort();
            peer_urls.dedup();
            Ok((NetworkingMethod::Manual, None, peer_urls))
        }
        NetworkMode::Standalone => Ok((NetworkingMethod::Standalone, None, Vec::new())),
        NetworkMode::Gateway { peer_url } => {
            validate_url(peer_url)?;
            Ok((NetworkingMethod::Manual, None, vec![peer_url.clone()]))
        }
    }
}

fn validate_url(value: &str) -> Result<(), CompileError> {
    let url = url::Url::parse(value).map_err(|_| CompileError::InvalidUrl(value.to_owned()))?;
    validate_manual_url(&url).map_err(|_| CompileError::InvalidUrl(value.to_owned()))
}

fn normalized_credentials(
    credentials: &[NetworkCredentialIntent],
) -> Result<Vec<&NetworkCredentialIntent>, CompileError> {
    let mut credentials: Vec<_> = credentials.iter().collect();
    credentials.sort_by(|left, right| left.id.cmp(&right.id));
    let mut secrets = HashSet::new();
    for credential in &credentials {
        if credential.id.trim().is_empty()
            || credential.id.trim() != credential.id
            || credential.secret.is_empty()
            || credential.secret.trim() != credential.secret
        {
            return Err(CompileError::InvalidMemberCredential {
                member_id: Uuid::nil(),
                reason: "credential id and secret must be non-empty canonical values".to_owned(),
            });
        }
        if !secrets.insert(credential.secret.as_str()) {
            return Err(CompileError::InvalidMemberCredential {
                member_id: Uuid::nil(),
                reason: format!(
                    "credential {} reuses another credential's key material",
                    credential.id
                ),
            });
        }
        for cidr in &credential.grant.allowed_proxy_cidrs {
            validate_cidr(cidr)?;
        }
        if credential
            .grant
            .acl_groups
            .iter()
            .any(|group| group.trim().is_empty())
        {
            return Err(CompileError::InvalidMemberCredential {
                member_id: Uuid::nil(),
                reason: format!("credential {} contains an empty ACL group", credential.id),
            });
        }
    }
    let runtime_credentials: Vec<_> = credentials
        .iter()
        .map(|credential| compile_managed_credential(credential))
        .collect();
    validate_managed_credential_set(&runtime_credentials).map_err(|reason| {
        CompileError::InvalidMemberCredential {
            member_id: Uuid::nil(),
            reason,
        }
    })?;
    Ok(credentials)
}

fn credentials_by_id<'a>(
    credentials: &'a [&NetworkCredentialIntent],
) -> HashMap<&'a str, &'a NetworkCredentialIntent> {
    credentials
        .iter()
        .map(|credential| (credential.id.as_str(), *credential))
        .collect()
}

fn validate_members(
    intent: &CentralNetworkIntent,
    members: &[&NetworkMemberIntent],
    credentials: &[&NetworkCredentialIntent],
) -> Result<(), CompileError> {
    let mut device_ids = HashSet::new();
    let credential_by_id = credentials_by_id(credentials);

    for member in members {
        if member.device_id.trim().is_empty() || !device_ids.insert(member.device_id.as_str()) {
            return Err(CompileError::DuplicateDevice(member.device_id.clone()));
        }
        let Some(credential_id) = member.credential_id.as_deref() else {
            if intent.acl_policy.is_some()
                && member.acl_group_secret.as_deref().is_none_or(str::is_empty)
            {
                return Err(CompileError::InvalidMemberCredential {
                    member_id: member.id,
                    reason: "a permanent ACL member requires an ACL group secret".to_owned(),
                });
            }
            continue;
        };
        if member.acl_group_secret.is_some() {
            return Err(CompileError::InvalidMemberCredential {
                member_id: member.id,
                reason: "a temporary member must not receive an ACL group secret".to_owned(),
            });
        }
        if !intent.secure_mode {
            return Err(CompileError::InvalidMemberCredential {
                member_id: member.id,
                reason: "temporary members require secure mode".to_owned(),
            });
        }
        let credential = credential_by_id.get(credential_id).copied().ok_or(
            CompileError::InvalidMemberCredential {
                member_id: member.id,
                reason: format!("credential {credential_id} does not exist"),
            },
        )?;
        if credential.grant.reusable {
            return Err(CompileError::InvalidMemberCredential {
                member_id: member.id,
                reason: "a member credential must be non-reusable".to_owned(),
            });
        }
        let required_group = member_group_name(member.id);
        if !credential.grant.acl_groups.contains(&required_group) {
            return Err(CompileError::InvalidMemberCredential {
                member_id: member.id,
                reason: format!("grant must contain dedicated ACL group {required_group}"),
            });
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Ipv4Subnet {
    network: u32,
    broadcast: u32,
    prefix: u8,
}

fn parse_ipv4_cidr(value: &str) -> Result<Ipv4Subnet, CompileError> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| CompileError::InvalidVirtualSubnet(value.to_owned()))?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| CompileError::InvalidVirtualSubnet(value.to_owned()))?;
    let prefix: u8 = prefix
        .parse()
        .ok()
        .filter(|prefix| *prefix <= 32)
        .ok_or_else(|| CompileError::InvalidVirtualSubnet(value.to_owned()))?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(address) & mask;
    Ok(Ipv4Subnet {
        network,
        broadcast: network | !mask,
        prefix,
    })
}

fn assign_addresses(
    virtual_cidr: Option<&str>,
    members: &[&NetworkMemberIntent],
) -> Result<HashMap<Uuid, Option<Ipv4Addr>>, CompileError> {
    let subnet = virtual_cidr.map(parse_ipv4_cidr).transpose()?;
    let mut used = HashSet::new();
    let mut result = HashMap::new();

    for member in members {
        let Some(value) = member.virtual_ipv4.as_deref() else {
            continue;
        };
        let address: Ipv4Addr = value.parse().map_err(|_| CompileError::InvalidMemberIp {
            member_id: member.id,
            address: value.to_owned(),
        })?;
        if let Some(subnet) = subnet {
            let raw = u32::from(address);
            if raw <= subnet.network || raw >= subnet.broadcast {
                return Err(CompileError::InvalidMemberIp {
                    member_id: member.id,
                    address: value.to_owned(),
                });
            }
        }
        if !used.insert(address) {
            return Err(CompileError::DuplicateMemberIp(address));
        }
        result.insert(member.id, Some(address));
    }

    // Explicit addresses take precedence over previous automatic allocations.
    // Reserve every reusable allocation before assigning any new address.
    if let Some(subnet) = subnet {
        for member in members {
            if result.contains_key(&member.id) {
                continue;
            }
            let Some(address) = member
                .allocated_ipv4
                .as_deref()
                .and_then(|value| value.parse::<Ipv4Addr>().ok())
            else {
                continue;
            };
            let raw = u32::from(address);
            if raw > subnet.network && raw < subnet.broadcast && used.insert(address) {
                result.insert(member.id, Some(address));
            }
        }
    }

    for member in members {
        if result.contains_key(&member.id) {
            continue;
        }
        let Some(subnet) = subnet else {
            result.insert(member.id, None);
            continue;
        };
        let address = (subnet.network.saturating_add(1)..subnet.broadcast)
            .map(Ipv4Addr::from)
            .find(|candidate| !used.contains(candidate))
            .ok_or(CompileError::SubnetExhausted(member.id))?;
        used.insert(address);
        result.insert(member.id, Some(address));
    }
    Ok(result)
}

fn validate_cidr(value: &str) -> Result<(), CompileError> {
    value
        .parse::<cidr::IpCidr>()
        .map(|_| ())
        .map_err(|_| CompileError::InvalidCidr(value.to_owned()))
}

fn normalized_grant(grant: &CredentialGrant) -> CredentialGrant {
    let mut grant = grant.clone();
    grant.acl_groups.sort();
    grant.acl_groups.dedup();
    grant.allowed_proxy_cidrs.sort();
    grant.allowed_proxy_cidrs.dedup();
    grant
}

fn compile_managed_credential(credential: &NetworkCredentialIntent) -> ManagedCredentialConfig {
    let grant = normalized_grant(&credential.grant);
    ManagedCredentialConfig {
        credential_id: credential.id.clone(),
        credential_secret: credential.secret.clone(),
        groups: grant.acl_groups,
        allow_relay: grant.allow_relay,
        allowed_proxy_cidrs: grant.allowed_proxy_cidrs,
        expiry_unix: credential.expiry_unix,
        reusable: Some(grant.reusable),
    }
}

fn validate_acl(
    policy: Option<&AclPolicy>,
    members: &[&NetworkMemberIntent],
    credentials: &[&NetworkCredentialIntent],
) -> Result<(), CompileError> {
    let Some(policy) = policy else {
        return Ok(());
    };
    let member_ids: HashSet<_> = members.iter().map(|member| member.id).collect();
    let granted_groups: HashSet<&str> = credentials
        .iter()
        .flat_map(|credential| credential.grant.acl_groups.iter().map(String::as_str))
        .collect();
    let mut rule_ids = HashSet::new();

    for rule in &policy.rules {
        if rule.id.trim().is_empty() || !rule_ids.insert(rule.id.as_str()) {
            return Err(CompileError::DuplicateAclRule(rule.id.clone()));
        }
        if rule.name.trim().is_empty()
            || rule.sources.is_empty()
            || rule.destinations.is_empty()
            || rule.protocols.is_empty()
        {
            return Err(CompileError::InvalidAclRule {
                rule_id: rule.id.clone(),
                reason: "name, sources, destinations and protocols must not be empty".to_owned(),
            });
        }
        for source in &rule.sources {
            match source {
                AclSource::All => {}
                AclSource::Member { member_id } if member_ids.contains(member_id) => {}
                AclSource::Member { member_id } => {
                    return Err(CompileError::UnknownAclMember(*member_id));
                }
                AclSource::Group { name } if granted_groups.contains(name.as_str()) => {}
                AclSource::Group { name } => {
                    return Err(CompileError::UnknownAclGroup(name.clone()));
                }
            }
        }
        for destination in &rule.destinations {
            let member_id = match destination {
                AclDestination::All => continue,
                AclDestination::Member { member_id } | AclDestination::Subnet { member_id, .. } => {
                    member_id
                }
            };
            if !member_ids.contains(member_id) {
                return Err(CompileError::UnknownAclMember(*member_id));
            }
            if let AclDestination::Subnet { cidrs, .. } = destination {
                if cidrs.is_empty() {
                    return Err(CompileError::InvalidAclRule {
                        rule_id: rule.id.clone(),
                        reason: "subnet destination must contain at least one CIDR".to_owned(),
                    });
                }
                for cidr in cidrs {
                    validate_cidr(cidr)?;
                }
            }
        }
        for target in &rule.protocols {
            validate_protocol_target(&rule.id, target)?;
        }
    }
    Ok(())
}

fn validate_protocol_target(rule_id: &str, target: &AclProtocolTarget) -> Result<(), CompileError> {
    if target.stateful && target.protocol != AclProtocol::Tcp {
        return Err(CompileError::InvalidAclRule {
            rule_id: rule_id.to_owned(),
            reason: "stateful is only supported for TCP".to_owned(),
        });
    }
    if matches!(target.protocol, AclProtocol::Icmp | AclProtocol::Icmpv6)
        && !target.ports.is_empty()
    {
        return Err(CompileError::InvalidAclRule {
            rule_id: rule_id.to_owned(),
            reason: "ICMP protocols do not accept ports".to_owned(),
        });
    }
    for port in &target.ports {
        let valid = match port.split_once('-') {
            Some((start, end)) => matches!(
                (start.parse::<u16>(), end.parse::<u16>()),
                (Ok(start), Ok(end)) if start > 0 && start <= end
            ),
            None => port.parse::<u16>().is_ok_and(|port| port > 0),
        };
        if !valid {
            return Err(CompileError::InvalidAclRule {
                rule_id: rule_id.to_owned(),
                reason: format!("invalid port {port}"),
            });
        }
    }
    Ok(())
}

fn compile_acl(
    policy: Option<&AclPolicy>,
    members: &[&NetworkMemberIntent],
) -> HashMap<Uuid, Option<Acl>> {
    let Some(policy) = policy else {
        return members.iter().map(|member| (member.id, None)).collect();
    };
    // Permanent members already hold the network admin secret and trust one
    // another. Shared group proofs express policy, not isolation from admins.
    // Untrusted devices must use credential identities instead.
    let permanent_groups: Vec<_> = members
        .iter()
        .filter(|member| member.credential_id.is_none())
        .map(|member| easytier::proto::acl::GroupIdentity {
            group_name: member_group_name(member.id),
            group_secret: member
                .acl_group_secret
                .clone()
                .expect("validated permanent ACL group secret"),
        })
        .collect();
    let mut inbound: HashMap<Uuid, Vec<Rule>> = members
        .iter()
        .map(|member| (member.id, Vec::new()))
        .collect();
    let mut forward: HashMap<Uuid, Vec<Rule>> = members
        .iter()
        .map(|member| (member.id, Vec::new()))
        .collect();

    let enabled: Vec<_> = policy.rules.iter().filter(|rule| rule.enabled).collect();
    for (position, policy_rule) in enabled.iter().enumerate() {
        let mut source_groups = if policy_rule
            .sources
            .iter()
            .any(|source| matches!(source, AclSource::All))
        {
            Vec::new()
        } else {
            let mut groups = Vec::new();
            for source in &policy_rule.sources {
                match source {
                    AclSource::All => unreachable!("handled above"),
                    AclSource::Member { member_id } => {
                        groups.push(member_group_name(*member_id));
                    }
                    AclSource::Group { name } => groups.push(name.clone()),
                }
            }
            groups
        };
        source_groups.sort();
        source_groups.dedup();
        let priority = ((enabled.len() - position) * 100) as u32;

        for destination in &policy_rule.destinations {
            let targets: Vec<(Uuid, bool, Vec<String>)> = match destination {
                AclDestination::All => members
                    .iter()
                    .map(|member| (member.id, false, Vec::new()))
                    .collect(),
                AclDestination::Member { member_id } => {
                    vec![(*member_id, false, Vec::new())]
                }
                AclDestination::Subnet { member_id, cidrs } => {
                    let mut cidrs = cidrs.clone();
                    cidrs.sort();
                    cidrs.dedup();
                    vec![(*member_id, true, cidrs)]
                }
            };
            for (member_id, is_forward, destination_ips) in targets {
                let accumulator = if is_forward {
                    forward.get_mut(&member_id).expect("validated ACL member")
                } else {
                    inbound.get_mut(&member_id).expect("validated ACL member")
                };
                for protocol in &policy_rule.protocols {
                    accumulator.push(Rule {
                        name: format!("{}:{}", policy_rule.id, protocol_name(protocol.protocol)),
                        description: policy_rule.name.clone(),
                        priority,
                        enabled: true,
                        protocol: core_protocol(protocol.protocol) as i32,
                        ports: protocol.ports.clone(),
                        source_ips: Vec::new(),
                        destination_ips: destination_ips.clone(),
                        source_ports: Vec::new(),
                        action: core_action(policy_rule.action) as i32,
                        rate_limit: 0,
                        burst_limit: 0,
                        stateful: protocol.stateful,
                        source_groups: source_groups.clone(),
                        destination_groups: Vec::new(),
                    });
                }
            }
        }
    }

    members
        .iter()
        .map(|member| {
            let chains = vec![
                Chain {
                    name: "inbound".to_owned(),
                    chain_type: ChainType::Inbound as i32,
                    description: "compiled from central network intent".to_owned(),
                    enabled: true,
                    rules: inbound.remove(&member.id).unwrap_or_default(),
                    default_action: core_action(policy.default_action) as i32,
                },
                Chain {
                    name: "forward".to_owned(),
                    chain_type: ChainType::Forward as i32,
                    description: "compiled from central network intent".to_owned(),
                    enabled: true,
                    rules: forward.remove(&member.id).unwrap_or_default(),
                    default_action: core_action(policy.default_action) as i32,
                },
            ];
            let own_groups = if member.credential_id.is_none() {
                vec![member_group_name(member.id)]
            } else {
                Vec::new()
            };
            (
                member.id,
                Some(Acl {
                    acl_v1: Some(AclV1 {
                        chains,
                        group: Some(GroupInfo {
                            declares: if member.credential_id.is_none() {
                                permanent_groups.clone()
                            } else {
                                Vec::new()
                            },
                            members: own_groups,
                        }),
                    }),
                }),
            )
        })
        .collect()
}

fn core_action(action: AclAction) -> Action {
    match action {
        AclAction::Allow => Action::Allow,
        AclAction::Deny => Action::Drop,
    }
}

fn core_protocol(protocol: AclProtocol) -> Protocol {
    match protocol {
        AclProtocol::Tcp => Protocol::Tcp,
        AclProtocol::Udp => Protocol::Udp,
        AclProtocol::Icmp => Protocol::Icmp,
        AclProtocol::Icmpv6 => Protocol::IcmPv6,
        AclProtocol::Any => Protocol::Any,
    }
}

fn protocol_name(protocol: AclProtocol) -> &'static str {
    match protocol {
        AclProtocol::Tcp => "tcp",
        AclProtocol::Udp => "udp",
        AclProtocol::Icmp => "icmp",
        AclProtocol::Icmpv6 => "icmpv6",
        AclProtocol::Any => "any",
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
    use easytier::proto::{acl::ChainType, api::manage::NetworkingMethod};
    use uuid::Uuid;

    use super::*;
    use crate::central_network::model::{
        AclAction, AclDestination, AclPolicy, AclProtocol, AclProtocolTarget, AclRule, AclSource,
        CentralNetworkIntent, CredentialGrant, NetworkCredentialIntent, NetworkMemberIntent,
        NetworkMode, member_group_name,
    };

    fn member(id: u128, device_id: &str, credential_id: Option<&str>) -> NetworkMemberIntent {
        NetworkMemberIntent {
            id: Uuid::from_u128(id),
            device_id: device_id.to_owned(),
            hostname: Some(device_id.to_owned()),
            virtual_ipv4: None,
            allocated_ipv4: None,
            config_override: None,
            credential_id: credential_id.map(str::to_owned),
            acl_group_secret: credential_id
                .is_none()
                .then(|| format!("group-secret-{device_id}")),
        }
    }

    fn credential(id: &str, member_id: Option<Uuid>) -> NetworkCredentialIntent {
        NetworkCredentialIntent {
            id: id.to_owned(),
            secret: credential_secret(id),
            expiry_unix: 2_000_000_000,
            grant: CredentialGrant {
                acl_groups: member_id.into_iter().map(member_group_name).collect(),
                allow_relay: true,
                allowed_proxy_cidrs: vec!["10.90.0.0/24".to_owned()],
                reusable: member_id.is_none(),
            },
        }
    }

    fn credential_secret(id: &str) -> String {
        let mut secret = [0u8; 32];
        for (index, byte) in id.bytes().enumerate() {
            secret[index % secret.len()] ^= byte;
        }
        BASE64_STANDARD.encode(secret)
    }

    fn intent() -> CentralNetworkIntent {
        let temporary = member(2, "device-b", Some("temporary"));
        CentralNetworkIntent {
            id: Uuid::from_u128(100),
            user_id: 7,
            display_name: "Engineering".to_owned(),
            network_name: "engineering".to_owned(),
            network_secret: "network-secret".to_owned(),
            mode: NetworkMode::Manual {
                peer_urls: vec!["tcp://gateway.example.com:11010".to_owned()],
            },
            virtual_cidr: Some("10.42.0.0/29".to_owned()),
            secure_mode: true,
            members: vec![temporary.clone(), member(1, "device-a", None)],
            credentials: vec![
                credential("temporary", Some(temporary.id)),
                credential("invite", None),
            ],
            acl_policy: Some(AclPolicy {
                default_action: AclAction::Deny,
                rules: vec![AclRule {
                    id: "allow-temporary".to_owned(),
                    name: "allow temporary member".to_owned(),
                    enabled: true,
                    action: AclAction::Allow,
                    sources: vec![AclSource::Member {
                        member_id: temporary.id,
                    }],
                    destinations: vec![AclDestination::Member {
                        member_id: Uuid::from_u128(1),
                    }],
                    protocols: vec![AclProtocolTarget {
                        protocol: AclProtocol::Tcp,
                        ports: vec!["443".to_owned()],
                        stateful: true,
                    }],
                }],
            }),
        }
    }

    #[test]
    fn compilation_is_deterministic_and_preserves_complete_grants() {
        let original = intent();
        let mut reordered = original.clone();
        reordered.members.reverse();
        reordered.credentials.reverse();

        let first = compile(&original).unwrap();
        let second = compile(&reordered).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.members[0].device_id, "device-a");
        assert_eq!(
            first.members[0].network_config.virtual_ipv4.as_deref(),
            Some("10.42.0.1")
        );

        let managed = &first.members[0].network_config.managed_credentials;
        assert_eq!(managed.len(), 2);
        let temporary = managed
            .iter()
            .find(|item| item.credential_id == "temporary")
            .unwrap();
        assert_eq!(
            temporary.groups,
            vec![member_group_name(Uuid::from_u128(2))]
        );
        assert!(temporary.allow_relay);
        assert_eq!(temporary.allowed_proxy_cidrs, vec!["10.90.0.0/24"]);
        assert_eq!(temporary.reusable, Some(false));
    }

    #[test]
    fn peer_schemes_are_validated_even_without_members() {
        for members in [Vec::new(), intent().members] {
            for url in [
                "tcp://gateway.example.com:11010",
                "http://discovery.example.com/peers",
                "https://discovery.example.com/peers",
                "txt://discovery.example.com",
                "srv://discovery.example.com",
                "bogus://gateway.example.com:11010",
            ] {
                let mut candidate = intent();
                candidate.members = members.clone();
                candidate.acl_policy = None;
                for mode in [
                    NetworkMode::Manual {
                        peer_urls: vec![url.to_owned()],
                    },
                    NetworkMode::PublicServer {
                        url: url.to_owned(),
                    },
                ] {
                    candidate.mode = mode;
                    let result = compile(&candidate);
                    if url.starts_with("bogus:") {
                        assert_eq!(result, Err(CompileError::InvalidUrl(url.to_owned())));
                    } else {
                        result.unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn member_proxy_networks_must_convert_to_core_config() {
        let mut candidate = intent();
        candidate.members[1].config_override = Some(NetworkConfig {
            proxy_cidrs: vec!["198.18.240.0/24".to_owned()],
            ..Default::default()
        });
        compile(&candidate).unwrap();
        candidate.members[1]
            .config_override
            .as_mut()
            .unwrap()
            .proxy_cidrs
            .push("2001:db8:240::/64".to_owned());
        assert!(matches!(
            compile(&candidate),
            Err(CompileError::InvalidMemberConfig { member_id, reason })
                if member_id == candidate.members[1].id && reason.contains("2001:db8:240::/64")
        ));
    }

    #[test]
    fn member_portal_clients_use_core_validation() {
        use easytier::proto::api::manage::{VpnPortalClientConfig, VpnPortalConfig};

        let mut candidate = intent();
        let client = VpnPortalClientConfig {
            name: "client-one".to_owned(),
            virtual_ip: "10.42.0.5/29".to_owned(),
            groups: vec![member_group_name(Uuid::from_u128(1))],
        };
        let mut portal = VpnPortalConfig {
            enabled: Some(true),
            wireguard_listen: "0.0.0.0:22020".to_owned(),
            wireguard_private_key: Some(credential_secret("portal")),
            clients: vec![client.clone()],
        };
        let mut overrides = NetworkConfig {
            vpn_portal_config: Some(portal.clone()),
            ..Default::default()
        };
        candidate.members[1].config_override = Some(overrides.clone());
        compile(&candidate).unwrap();

        for clients in [
            vec![
                client.clone(),
                VpnPortalClientConfig {
                    name: "client-two".to_owned(),
                    ..client.clone()
                },
            ],
            vec![
                client.clone(),
                VpnPortalClientConfig {
                    virtual_ip: "10.42.0.6/29".to_owned(),
                    ..client.clone()
                },
            ],
            vec![VpnPortalClientConfig {
                virtual_ip: "invalid-ip".to_owned(),
                ..client.clone()
            }],
            vec![VpnPortalClientConfig {
                virtual_ip: "10.42.0.0/29".to_owned(),
                ..client.clone()
            }],
            vec![VpnPortalClientConfig {
                virtual_ip: "10.42.0.7/29".to_owned(),
                ..client.clone()
            }],
            vec![VpnPortalClientConfig {
                virtual_ip: "10.42.0.1/29".to_owned(),
                ..client.clone()
            }],
            vec![VpnPortalClientConfig {
                groups: vec!["not-declared".to_owned()],
                ..client
            }],
        ] {
            portal.clients = clients;
            overrides.vpn_portal_config = Some(portal.clone());
            candidate.members[1].config_override = Some(overrides.clone());
            assert!(matches!(
                compile(&candidate),
                Err(CompileError::InvalidMemberConfig { .. })
            ));
        }
        portal.clients.clear();
        overrides.vpn_portal_config = Some(portal);
        candidate.members[1].config_override = Some(overrides);
        compile(&candidate).unwrap();
    }

    #[test]
    fn temporary_member_only_receives_its_credential_material() {
        let compiled = compile(&intent()).unwrap();
        let temporary = compiled
            .members
            .iter()
            .find(|member| member.device_id == "device-b")
            .unwrap();

        assert_eq!(temporary.network_config.network_secret, None);
        assert!(temporary.network_config.managed_credentials.is_empty());
        assert_eq!(
            temporary
                .network_config
                .secure_mode
                .as_ref()
                .unwrap()
                .local_private_key
                .as_deref(),
            Some(credential_secret("temporary").as_str())
        );

        let group = temporary
            .network_config
            .acl
            .as_ref()
            .unwrap()
            .acl_v1
            .as_ref()
            .unwrap()
            .group
            .as_ref()
            .unwrap();
        assert!(group.members.is_empty());
        assert!(group.declares.is_empty());
    }

    #[test]
    fn acl_member_references_compile_to_authenticated_groups() {
        let compiled = compile(&intent()).unwrap();
        let destination = &compiled.members[0].network_config;
        assert_eq!(
            destination.networking_method,
            Some(NetworkingMethod::Manual as i32)
        );
        let acl = destination.acl.as_ref().unwrap().acl_v1.as_ref().unwrap();
        let inbound = acl
            .chains
            .iter()
            .find(|chain| chain.chain_type == ChainType::Inbound as i32)
            .unwrap();
        assert_eq!(
            inbound.rules[0].source_groups,
            vec![member_group_name(Uuid::from_u128(2))]
        );
        assert!(
            acl.group
                .as_ref()
                .unwrap()
                .declares
                .iter()
                .all(|identity| identity.group_name != member_group_name(Uuid::from_u128(2)))
        );
    }

    #[test]
    fn acl_all_source_and_default_action_cover_unlisted_peers_and_forwarding() {
        let mut intent = intent();
        intent.acl_policy.as_mut().unwrap().rules[0].sources = vec![AclSource::All];

        let compiled = compile(&intent).unwrap();
        let acl = compiled.members[0]
            .network_config
            .acl
            .as_ref()
            .unwrap()
            .acl_v1
            .as_ref()
            .unwrap();
        let inbound = acl
            .chains
            .iter()
            .find(|chain| chain.chain_type == ChainType::Inbound as i32)
            .unwrap();
        assert!(inbound.rules[0].source_groups.is_empty());
        let forward = acl
            .chains
            .iter()
            .find(|chain| chain.chain_type == ChainType::Forward as i32)
            .unwrap();
        assert!(forward.rules.is_empty());
        assert_eq!(forward.default_action, Action::Drop as i32);
    }

    #[test]
    fn validation_rejects_duplicate_devices_and_inconsistent_credentials() {
        let mut duplicate_device = intent();
        duplicate_device.members[1].device_id = duplicate_device.members[0].device_id.clone();
        let error = compile(&duplicate_device).unwrap_err();
        assert!(matches!(error, CompileError::DuplicateDevice(_)));

        let mut reusable = intent();
        reusable.credentials[0].grant.reusable = true;
        let error = compile(&reusable).unwrap_err();
        assert!(matches!(
            error,
            CompileError::InvalidMemberCredential { .. }
        ));

        let mut missing_group = intent();
        missing_group.credentials[0].grant.acl_groups.clear();
        let error = compile(&missing_group).unwrap_err();
        assert!(matches!(
            error,
            CompileError::InvalidMemberCredential { .. }
        ));

        let mut duplicate_secret = intent();
        duplicate_secret.credentials[1].secret = duplicate_secret.credentials[0].secret.clone();
        assert!(matches!(
            compile(&duplicate_secret),
            Err(CompileError::InvalidMemberCredential { .. })
        ));
    }

    #[test]
    fn validation_rejects_bad_network_data_and_acl_references() {
        let mut bad_cidr = intent();
        bad_cidr.credentials[0].grant.allowed_proxy_cidrs = vec!["not-a-cidr".to_owned()];
        assert!(matches!(
            compile(&bad_cidr),
            Err(CompileError::InvalidCidr(_))
        ));

        let mut cidr_with_host_bits = intent();
        cidr_with_host_bits.credentials[0].grant.allowed_proxy_cidrs =
            vec!["10.90.0.1/24".to_owned()];
        assert!(matches!(
            compile(&cidr_with_host_bits),
            Err(CompileError::InvalidCidr(_))
        ));

        let mut bad_ip = intent();
        bad_ip.members[0].virtual_ipv4 = Some("192.168.1.1".to_owned());
        assert!(matches!(
            compile(&bad_ip),
            Err(CompileError::InvalidMemberIp { .. })
        ));

        let mut bad_acl = intent();
        bad_acl.acl_policy.as_mut().unwrap().rules[0].destinations = vec![AclDestination::Member {
            member_id: Uuid::from_u128(999),
        }];
        assert!(matches!(
            compile(&bad_acl),
            Err(CompileError::UnknownAclMember(_))
        ));

        let mut bad_group = intent();
        bad_group.acl_policy.as_mut().unwrap().rules[0].sources = vec![AclSource::Group {
            name: "ungranted".to_owned(),
        }];
        assert!(matches!(
            compile(&bad_group),
            Err(CompileError::UnknownAclGroup(_))
        ));
    }

    #[test]
    fn validation_uses_runtime_credential_identity_rules() {
        let mut invalid_secret = intent();
        invalid_secret.credentials[0].secret = "not-a-private-key".to_owned();
        assert!(matches!(
            compile(&invalid_secret),
            Err(CompileError::InvalidMemberCredential { .. })
        ));

        let mut noncanonical_id = intent();
        noncanonical_id.credentials[0].id = " temporary".to_owned();
        assert!(matches!(
            compile(&noncanonical_id),
            Err(CompileError::InvalidMemberCredential { .. })
        ));

        let mut noncanonical_secret = intent();
        noncanonical_secret.credentials[0].secret =
            format!(" {}", noncanonical_secret.credentials[0].secret);
        assert!(matches!(
            compile(&noncanonical_secret),
            Err(CompileError::InvalidMemberCredential { .. })
        ));

        let mut duplicate_public_key = intent();
        let original = base64::engine::general_purpose::STANDARD
            .decode(&duplicate_public_key.credentials[0].secret)
            .unwrap();
        let mut equivalent = original;
        equivalent[0] ^= 0b0000_0111;
        duplicate_public_key.credentials[1].secret = BASE64_STANDARD.encode(equivalent);
        assert!(matches!(
            compile(&duplicate_public_key),
            Err(CompileError::InvalidMemberCredential { .. })
        ));
    }

    #[test]
    fn member_override_cannot_replace_central_identity_or_authorization() {
        let mut intent = intent();
        intent.members[1].config_override = Some(NetworkConfig {
            enable_exit_node: Some(true),
            mtu: Some(1300),
            network_name: Some("tampered".to_owned()),
            network_secret: Some("tampered".to_owned()),
            hostname: Some("tampered".to_owned()),
            virtual_ipv4: Some("192.168.1.1".to_owned()),
            managed_credentials: Vec::new(),
            acl: None,
            ..Default::default()
        });

        let compiled = compile(&intent).unwrap();
        let permanent = compiled
            .members
            .iter()
            .find(|member| member.device_id == "device-a")
            .unwrap();
        assert_eq!(permanent.network_config.enable_exit_node, Some(true));
        assert_eq!(permanent.network_config.mtu, Some(1300));
        assert_eq!(
            permanent.network_config.network_name.as_deref(),
            Some("engineering")
        );
        assert_eq!(
            permanent.network_config.network_secret.as_deref(),
            Some("network-secret")
        );
        assert_eq!(
            permanent.network_config.hostname.as_deref(),
            Some("device-a")
        );
        assert_eq!(
            permanent.network_config.virtual_ipv4.as_deref(),
            Some("10.42.0.1")
        );
        assert_eq!(permanent.network_config.managed_credentials.len(), 2);
        assert!(permanent.network_config.acl.is_some());
    }
}

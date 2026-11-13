use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

use easytier::common::config::NetworkConfig;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CentralNetworkIntent {
    pub id: Uuid,
    pub user_id: i32,
    pub display_name: String,
    pub network_name: String,
    pub network_secret: String,
    pub mode: NetworkMode,
    pub virtual_cidr: Option<String>,
    pub secure_mode: bool,
    pub members: Vec<NetworkMemberIntent>,
    pub credentials: Vec<NetworkCredentialIntent>,
    pub acl_policy: Option<AclPolicy>,
}

impl CentralNetworkIntent {
    pub fn remove_device(&mut self, device_id: Uuid) -> bool {
        let removed_members: Vec<_> = self
            .members
            .iter()
            .filter(|member| member.device_id == device_id.to_string())
            .cloned()
            .collect();
        if removed_members.is_empty() {
            return false;
        }
        let removed_member_ids: HashSet<_> =
            removed_members.iter().map(|member| member.id).collect();
        let removed_credential_ids: HashSet<_> = removed_members
            .iter()
            .filter_map(|member| member.credential_id.as_deref())
            .collect();
        let removed_groups: HashSet<_> = self
            .credentials
            .iter()
            .filter(|credential| removed_credential_ids.contains(credential.id.as_str()))
            .flat_map(|credential| credential.grant.acl_groups.iter().cloned())
            .collect();

        self.members
            .retain(|member| !removed_member_ids.contains(&member.id));
        self.credentials
            .retain(|credential| !removed_credential_ids.contains(credential.id.as_str()));
        let remaining_groups: HashSet<_> = self
            .credentials
            .iter()
            .flat_map(|credential| credential.grant.acl_groups.iter().cloned())
            .collect();
        let removed_groups: HashSet<_> = removed_groups
            .difference(&remaining_groups)
            .cloned()
            .collect();

        if let Some(policy) = &mut self.acl_policy {
            policy.rules.retain_mut(|rule| {
                rule.sources.retain(|source| match source {
                    AclSource::Member { member_id } => !removed_member_ids.contains(member_id),
                    AclSource::Group { name } => !removed_groups.contains(name),
                    AclSource::All => true,
                });
                rule.destinations.retain(|destination| match destination {
                    AclDestination::Member { member_id }
                    | AclDestination::Subnet { member_id, .. } => {
                        !removed_member_ids.contains(member_id)
                    }
                    AclDestination::All => true,
                });
                !rule.sources.is_empty() && !rule.destinations.is_empty()
            });
        }
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NetworkMode {
    PublicServer { url: String },
    Manual { peer_urls: Vec<String> },
    Standalone,
    Gateway { peer_url: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NetworkMemberIntent {
    pub id: Uuid,
    pub device_id: String,
    pub hostname: Option<String>,
    pub virtual_ipv4: Option<String>,
    #[serde(default)]
    pub allocated_ipv4: Option<String>,
    #[serde(default)]
    pub config_override: Option<NetworkConfig>,
    pub credential_id: Option<String>,
    /// HMAC material for permanent administrator group proofs. Temporary
    /// members authenticate their groups through their credential grant and
    /// must leave this empty.
    pub acl_group_secret: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCredentialIntent {
    pub id: String,
    pub secret: String,
    pub expiry_unix: i64,
    pub grant: CredentialGrant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub acl_groups: Vec<String>,
    pub allow_relay: bool,
    pub allowed_proxy_cidrs: Vec<String>,
    pub reusable: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclPolicy {
    pub default_action: AclAction,
    pub rules: Vec<AclRule>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclAction {
    #[default]
    Allow,
    Deny,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub action: AclAction,
    pub sources: Vec<AclSource>,
    pub destinations: Vec<AclDestination>,
    pub protocols: Vec<AclProtocolTarget>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AclSource {
    All,
    Member { member_id: Uuid },
    Group { name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AclDestination {
    All,
    Member { member_id: Uuid },
    Subnet { member_id: Uuid, cidrs: Vec<String> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AclProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Any,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclProtocolTarget {
    pub protocol: AclProtocol,
    pub ports: Vec<String>,
    pub stateful: bool,
}

pub fn member_group_name(member_id: Uuid) -> String {
    format!("member:{member_id}")
}

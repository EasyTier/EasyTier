use crate::dns::utils::{sanitize, NameServerAddr};
use crate::proto::dns::{DnsConfigPb, ZoneConfigPb};
use derive_more::{Deref, DerefMut};
use gethostname::gethostname;
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;
use uuid::Uuid;

pub const DNS_DEFAULT_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53));
pub static DNS_DEFAULT_TLD: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    name: LowerName,
    pub domain: LowerName,
    pub addresses: Vec<SocketAddr>,
    pub listeners: Vec<NameServerAddr>,
}

impl DnsConfig {
    pub fn get_name(&self) -> String {
        if self.name.is_empty() {
            gethostname().to_string_lossy().to_string()
        } else {
            self.name.to_string()
        }
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = match LowerName::from_str(name) {
            Ok(name) => name,
            Err(_) => {
                let sanitized = sanitize(name);
                tracing::debug!("invalid hostname: {}, sanitized to: {}", name, sanitized);
                LowerName::from_str(&sanitized).unwrap_or_default()
            }
        };
    }

    pub fn export(&self) -> DnsConfigPb {
        DnsConfigPb {
            zones: self
                .zones
                .iter()
                .filter(|z| z.policy.export.is_some()) // TODO: check policies of parent zones
                .map(Into::into)
                .collect(),

            name: self.get_name(),
            domain: self.domain.to_string(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            zones: Vec::new(),
            policies: HashMap::new(),
            name: LowerName::default(),
            domain: DNS_DEFAULT_TLD.clone(),
            addresses: vec![DNS_DEFAULT_ADDRESS],
            listeners: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ZoneConfig {
    #[serde(default = "Uuid::new_v4")]
    #[serde(skip_serializing)]
    id: Uuid,
    pub origin: LowerName,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub records: Vec<String>,
    #[serde(default)]
    pub forwarders: Vec<NameServerAddr>,
    #[serde(flatten)]
    pub policy: ZonePolicyConfig,
}

impl From<&ZoneConfig> for ZoneConfigPb {
    fn from(value: &ZoneConfig) -> Self {
        Self {
            id: Some(value.id.into()),
            origin: value.origin.to_string(),
            ttl: value.ttl,
            records: value.records.clone(),
            forwarders: value.forwarders.iter().map(ToString::to_string).collect(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct AclPolicy {
    pub whitelist: Option<Vec<String>>,
    pub blacklist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default, Deref, DerefMut)]
#[serde(default)]
pub struct FunctionalityPolicy {
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    acl: AclPolicy, // TODO
    pub disabled: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default, Deref, DerefMut)]
#[serde(default)]
pub struct DnsPolicy<P = FunctionalityPolicy> {
    #[serde(flatten)]
    #[deref]
    #[deref_mut]
    policy: P,
    pub recursive: bool, // TODO
}

pub type ZoneExportPolicy = FunctionalityPolicy;
pub type DnsExportPolicy = DnsPolicy<ZoneExportPolicy>;
pub type DnsImportPolicy = DnsPolicy<FunctionalityPolicy>;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct DnsPolicyConfig {
    pub import: DnsImportPolicy,
    pub export: Option<DnsExportPolicy>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(default)]
pub struct ZonePolicyConfig {
    #[serde(default)]
    pub export: Option<DnsExportPolicy>,
}

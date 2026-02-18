use crate::common::config::ConfigLoader;
use crate::common::global_ctx::GlobalCtx;
use crate::dns::utils::{parse, NameServerAddr};
use crate::proto::dns::{DnsConfigPb, ZoneConfigPb};
use derive_more::{Deref, DerefMut};
use gethostname::gethostname;
use hickory_proto::rr::{LowerName, Name};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::iter;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;
use url::Url;
use uuid::Uuid;

pub const DNS_DEFAULT_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53));
pub static DNS_DEFAULT_TLD: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());
pub static DNS_SERVER_RPC_ADDR: LazyLock<Url> =
    LazyLock::new(|| Url::parse("tcp://127.0.0.1:49813").unwrap());

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
    pub fn get_name(&self) -> LowerName {
        if self.name.is_empty() {
            parse(gethostname().to_string_lossy().as_ref())
        } else {
            self.name.clone()
        }
    }

    pub fn set_name(&mut self, name: &str) {
        self.name = parse(name);
    }

    pub fn get_fqdn(&self) -> LowerName {
        Name::from(self.get_name())
            .append_domain(&self.domain)
            .unwrap()
            .into()
    }

    pub fn set_fqdn(&mut self, fqdn: &str) {
        let mut fqdn = Name::from(parse(fqdn));
        fqdn.set_fqdn(true);
        self.name = Name::from_labels(iter::once(fqdn.iter().next().unwrap_or_default()))
            .unwrap_or_default()
            .into();
        self.domain = fqdn.base_name().into();
    }
}

pub trait DnsGlobalCtxExt {
    fn dns_self_zone(&self) -> Option<ZoneConfig>;
    fn dns_export_config(&self) -> DnsConfigPb;
}

impl DnsGlobalCtxExt for GlobalCtx {
    fn dns_self_zone(&self) -> Option<ZoneConfig> {
        let fqdn = self.config.get_dns().get_fqdn();
        let ipv4 = self.get_ipv4().map(|ip| ip.address());
        let ipv6 = self.get_ipv6().map(|ip| ip.address());
        let ipv6 = ipv6.map(|a| vec![a]).unwrap_or_default();

        ZoneConfig::dedicated(Some(self.get_id()), fqdn.clone(), ipv4, ipv6)
    }

    fn dns_export_config(&self) -> DnsConfigPb {
        let config = self.config.get_dns();
        let zone = self.dns_self_zone();
        let zones = config.zones.iter().chain(zone.iter());

        DnsConfigPb {
            zones: zones
                .filter(|z| z.policy.export.is_some()) // TODO: check policies of parent zones
                .map(Into::into)
                .collect(),
            fqdn: config.get_fqdn().to_string(),
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

impl ZoneConfig {
    fn dedicated(
        id: Option<Uuid>,
        origin: LowerName,
        ipv4: Option<Ipv4Addr>,
        ipv6: Vec<Ipv6Addr>,
    ) -> Option<Self> {
        let mut records = Vec::new();

        if let Some(ipv4) = ipv4 {
            records.push(format!("@ IN A {}", ipv4));
        }
        for ipv6 in ipv6 {
            records.push(format!("@ IN AAAA {}", ipv6));
        }

        let policy = ZonePolicyConfig {
            export: Some(DnsExportPolicy::default()),
        };

        (!records.is_empty()).then_some(Self {
            id: id.unwrap_or(Uuid::new_v4()),
            origin,
            records,
            policy,

            ..Default::default()
        })
    }
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

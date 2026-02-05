use crate::dns::utils::{sanitize, NameServerAddr};
use crate::proto::dns::{DnsConfigKind, DnsConfigPb, ZoneConfigPb};
use gethostname::gethostname;
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;

pub const DNS_DEFAULT_ADDRESS: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53));
pub static DNS_DEFAULT_TLD: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
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

    pub fn to_pb(&self, kind: DnsConfigKind) -> DnsConfigPb {
        let pb = DnsConfigPb {
            kind: kind.into(),
            name: self.get_name(),
            domain: self.domain.to_string(),

            ..Default::default()
        };

        match kind {
            DnsConfigKind::Local => DnsConfigPb {
                zones: self.zones.iter().map(Into::into).collect(),
                addresses: self.addresses.clone().into_iter().map(Into::into).collect(),
                listeners: self.listeners.iter().map(ToString::to_string).collect(),

                ..pb
            },

            DnsConfigKind::Remote => DnsConfigPb {
                zones: self
                    .zones
                    .iter()
                    .filter(|z| z.broadcast)
                    .map(Into::into)
                    .collect(),

                ..pb
            },
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            name: LowerName::default(),
            domain: DNS_DEFAULT_TLD.clone(),
            addresses: vec![DNS_DEFAULT_ADDRESS],
            listeners: vec![],
            zones: vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub struct ZoneConfig {
    #[serde(default)]
    pub broadcast: bool,
    pub origin: LowerName,
    #[serde(default)]
    pub ttl: u32,
    #[serde(default)]
    pub records: Vec<String>,
    #[serde(default)]
    pub forwarders: Vec<NameServerAddr>,
}

impl From<&ZoneConfig> for ZoneConfigPb {
    fn from(value: &ZoneConfig) -> Self {
        Self {
            origin: value.origin.to_string(),
            ttl: value.ttl,
            records: value.records.clone(),
            forwarders: value.forwarders.iter().map(ToString::to_string).collect(),
        }
    }
}

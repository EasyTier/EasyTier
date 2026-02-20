use crate::common::global_ctx::GlobalCtx;
use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESS, DNS_DEFAULT_TLD};
use crate::dns::utils::{parse, NameServerAddrGroup};
use crate::proto::dns::GetExportConfigResponse;
use derivative::Derivative;
use gethostname::gethostname;
use hickory_proto::rr::{LowerName, Name};
use hickory_proto::xfer::Protocol;
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::iter;

#[derive(Derivative, Debug, Clone, Deserialize, Serialize, PartialEq)]
#[derivative(Default)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    name: LowerName,
    #[derivative(Default(value = "DNS_DEFAULT_TLD.clone()"))]
    pub domain: LowerName,
    #[derivative(Default(value = "vec![DNS_DEFAULT_ADDRESS].into()"))]
    #[serde(deserialize_with = "DnsConfig::validate_addresses")]
    pub addresses: NameServerAddrGroup,
    pub listeners: NameServerAddrGroup,
}

impl DnsConfig {
    pub fn validate_addresses<'de, D>(deserializer: D) -> Result<NameServerAddrGroup, D::Error>
    where
        D: Deserializer<'de>,
    {
        let addresses = NameServerAddrGroup::deserialize(deserializer)?;
        for address in &addresses {
            if address.protocol != Protocol::Udp {
                return Err(serde::de::Error::custom(format!(
                    "unsupported address protocol: {}, only udp is supported",
                    address.protocol
                )));
            }
        }
        Ok(addresses)
    }
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

pub type DnsExportConfig = GetExportConfigResponse;

pub trait DnsGlobalCtxExt {
    fn dns_self_zone(&self) -> Option<ZoneConfig>;
    fn dns_export_config(&self) -> DnsExportConfig;
}

impl DnsGlobalCtxExt for GlobalCtx {
    fn dns_self_zone(&self) -> Option<ZoneConfig> {
        let fqdn = self.config.get_dns().get_fqdn();
        let ipv4 = self.get_ipv4().map(|ip| ip.address());
        let ipv6 = self.get_ipv6().map(|ip| ip.address());
        let ipv6 = ipv6.map(|a| vec![a]).unwrap_or_default();

        ZoneConfig::dedicated(Some(self.get_id()), fqdn.clone(), ipv4, ipv6)
    }

    fn dns_export_config(&self) -> DnsExportConfig {
        let config = self.config.get_dns();
        let zone = self.dns_self_zone();
        let zones = config.zones.iter().chain(zone.iter());

        DnsExportConfig {
            zones: zones
                .filter(|z| z.policy.export.is_some()) // TODO: check policies of parent zones
                .cloned()
                .map_into()
                .collect(),
            fqdn: config.get_fqdn().to_string(),
        }
    }
}

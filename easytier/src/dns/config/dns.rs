use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESS, DNS_DEFAULT_DOMAIN};
use crate::dns::server::DnsServer;
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::dns::utils::parse;
use crate::proto::dns::GetExportConfigResponse;
use derivative::Derivative;
use hickory_net::xfer::Protocol;
use hickory_proto::rr::{LowerName, Name};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::iter;
use std::sync::Arc;

#[derive(Derivative, Debug, Clone, Deserialize, Serialize, PartialEq)]
#[derivative(Default)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    name: LowerName,
    #[derivative(Default(value = "DNS_DEFAULT_DOMAIN.clone()"))]
    pub domain: LowerName,
    #[derivative(Default(value = "vec![DNS_DEFAULT_ADDRESS].into()"))]
    #[serde(deserialize_with = "DnsConfig::deserialize_addresses")]
    pub addresses: NameServerAddrGroup,
    pub listeners: NameServerAddrGroup,
}

impl DnsConfig {
    pub fn deserialize_addresses<'de, D>(deserializer: D) -> Result<NameServerAddrGroup, D::Error>
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
            parse(
                hostname::get()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .as_ref(),
            )
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

#[auto_impl::auto_impl(Box, &)]
pub trait DnsConfigLoaderExt {
    fn get_dns(&self) -> DnsConfig;
    fn set_dns(&self, dns: Option<DnsConfig>);
}

pub type DnsExportConfig = GetExportConfigResponse;

pub trait DnsGlobalCtxExt {
    fn dns_server(&self) -> Option<Arc<DnsServer>>; // TODO: remove this
    fn set_dns_server(&self, dns: Option<Arc<DnsServer>>); // TODO: remove this
    fn dns_self_zone(&self) -> ZoneConfig;
    fn dns_export_config(&self) -> DnsExportConfig;
    fn dns_iter_zones(&self) -> impl Iterator<Item = ZoneConfig>;
}

use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESS, DNS_DEFAULT_DOMAIN};
use crate::dns::server::DnsServer;
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::proto::dns::GetExportConfigResponse;
use derivative::Derivative;
use hickory_net::xfer::Protocol;
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Derivative, Debug, Clone, Deserialize, Serialize, PartialEq)]
#[derivative(Default)]
#[serde(default)]
pub struct DnsConfig {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    pub name: LowerName,
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

use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESSES, DNS_DEFAULT_DOMAIN};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::proto::dns::GetExportConfigResponse;
use derivative::Derivative;
use hickory_proto::rr::LowerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    #[derivative(Default(value = "DNS_DEFAULT_ADDRESSES.clone()"))]
    pub addresses: NameServerAddrGroup,
    pub listeners: NameServerAddrGroup,
}

#[auto_impl::auto_impl(Box, &)]
pub trait DnsConfigLoaderExt {
    fn get_dns(&self) -> DnsConfig;
    fn set_dns(&self, dns: Option<DnsConfig>);
}

pub type DnsExportConfig = GetExportConfigResponse;

pub trait DnsGlobalCtxExt {
    fn dns_self_zone(&self) -> ZoneConfig;
    fn dns_export_config(&self) -> DnsExportConfig;
    fn dns_iter_zones(&self) -> impl Iterator<Item = ZoneConfig>;
}

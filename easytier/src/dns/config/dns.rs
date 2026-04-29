use crate::common::config::ConfigBase;
use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESSES, DNS_DEFAULT_DOMAIN};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::proto::dns::GetExportConfigResponse;
use hickory_proto::rr::LowerName;
use optional_struct::{Applicable, optional_struct};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[optional_struct(DnsConfigRaw)]
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct DnsConfigParsed {
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[optional_skip_wrap]
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    pub name: LowerName,
    pub domain: LowerName,
    pub addresses: NameServerAddrGroup,
    pub listeners: NameServerAddrGroup,
}

pub type DnsConfig = ConfigBase<DnsConfigRaw, DnsConfigParsed, ()>;

impl From<DnsConfigRaw> for DnsConfig {
    fn from(raw: DnsConfigRaw) -> Self {
        let default = DnsConfigParsed {
            domain: DNS_DEFAULT_DOMAIN.clone(),
            name: DNS_DEFAULT_DOMAIN.clone(),
            addresses: DNS_DEFAULT_ADDRESSES.clone(),
            ..Default::default()
        };

        let parsed = raw.clone().build(default);
        Self::new(raw, parsed, ())
    }
}

#[auto_impl::auto_impl(Box, &)]
pub trait DnsConfigLoaderExt {
    fn get_dns(&self) -> DnsConfig;
    fn set_dns(&self, dns: DnsConfig);
}

pub type DnsExportConfig = GetExportConfigResponse;

pub trait DnsGlobalCtxExt {
    fn dns_self_zone(&self) -> ZoneConfig;
    fn dns_export_config(&self) -> DnsExportConfig;
    fn dns_iter_zones(&self) -> impl Iterator<Item = ZoneConfig>;
}

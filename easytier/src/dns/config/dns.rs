use super::ConfigBase;
use crate::common::config::ConfigLoader;
use crate::dns::config::policy::DnsPolicyConfig;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{DNS_DEFAULT_ADDRESSES, DNS_DEFAULT_DOMAIN};
use crate::dns::utils::addr::NameServerAddrGroup;
use crate::proto::dns::GetExportConfigResponse;
use anyhow::Context;
use hickory_proto::rr::LowerName;
use optionize::{Optionizable, optionized};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[optionized]
#[optionize(name = "DnsConfigRaw")]
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
pub struct DnsConfigParsed {
    pub disabled: bool,
    #[serde(rename = "zone")]
    pub zones: Vec<ZoneConfig>,
    #[optionize(flatten)]
    #[serde(flatten)]
    pub policies: HashMap<LowerName, DnsPolicyConfig>,
    #[optionize(flatten)]
    pub name: Option<LowerName>,
    pub domain: LowerName,
    pub addresses: NameServerAddrGroup,
    pub listeners: NameServerAddrGroup,
}

pub type DnsConfig = ConfigBase<DnsConfigRaw, DnsConfigParsed, ()>;

impl From<DnsConfigRaw> for DnsConfig {
    fn from(raw: DnsConfigRaw) -> Self {
        let mut parsed = DnsConfigParsed {
            domain: DNS_DEFAULT_DOMAIN.clone(),
            addresses: DNS_DEFAULT_ADDRESSES.clone(),
            ..Default::default()
        };
        parsed.load(raw.clone());
        Self::new(parsed, raw, ())
    }
}

pub trait DnsConfigLoaderExt {
    fn try_get_dns(&self) -> anyhow::Result<DnsConfig>;
    fn set_dns(&self, dns: DnsConfig);
}

impl<T: ConfigLoader + ?Sized> DnsConfigLoaderExt for T {
    fn try_get_dns(&self) -> anyhow::Result<DnsConfig> {
        match self.get_dns_config() {
            Some(raw) => toml::Value::Table(raw)
                .try_into()
                .context("invalid [dns] configuration"),
            None => Ok(DnsConfig::default()),
        }
    }

    fn set_dns(&self, dns: DnsConfig) {
        let raw =
            toml::Table::try_from(dns.raw()).expect("DNS raw config serializes to a TOML table");
        self.set_dns_config(Some(raw));
    }
}

/// Validate the native DNS schema before configuration produces runtime effects.
pub fn validate_dns_config(config: &(impl ConfigLoader + ?Sized)) -> anyhow::Result<()> {
    config.try_get_dns().map(|_| ())
}

pub type DnsExportConfig = GetExportConfigResponse;

pub trait DnsGlobalCtxExt {
    fn try_dns_self_zone(&self) -> anyhow::Result<ZoneConfig>;
    fn try_dns_export_config(&self) -> anyhow::Result<DnsExportConfig>;
    fn try_dns_iter_zones(&self) -> anyhow::Result<Vec<ZoneConfig>>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::TomlConfig;

    #[test]
    fn invalid_zone_is_rejected_at_native_validation_boundary() {
        let config = TomlConfig::new_from_str(
            r#"
[[dns.zone]]
origin = "bad.example."
records = ["@ IN A definitely-not-an-address"]
"#,
        )
        .unwrap();
        assert!(validate_dns_config(&config).is_err());
        assert!(config.try_get_dns().is_err());
    }

    #[test]
    fn dns_raw_round_trip_keeps_defaults_unmaterialized() {
        let config = TomlConfig::new_from_str("[dns]\ndomain = 'mesh.example.'\n").unwrap();
        let dns = config.try_get_dns().unwrap();
        assert!(!dns.disabled);
        assert_eq!(dns.domain.to_string(), "mesh.example.");
        let before = config.get_dns_config();
        config.set_dns(dns);
        assert_eq!(config.get_dns_config(), before);
    }
}

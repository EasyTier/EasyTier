use crate::proto::utils::RepeatedMessageModel;
use anyhow::Context;
use easytier_core::config::dns::compile_dns;
pub(crate) use easytier_core::config::dns::parse_origin;
use easytier_core::config::toml::{ConfigLoader, DEFAULT_ET_DNS_ZONE, DnsConfig};
use hickory_proto::rr::{LowerName, Record, RecordSet, RrKey};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::collections::BTreeMap;

/// Resolves the default Magic DNS zone origin from `dns.domain`, falling back
/// to the deprecated `flags.tld_dns_zone` patch when `dns.domain` is unset, and
/// finally to [`DEFAULT_ET_DNS_ZONE`].
#[allow(deprecated)]
pub(crate) fn dns_domain(config: &impl ConfigLoader) -> anyhow::Result<LowerName> {
    let dns = config.get_dns();
    if let Some(domain) = dns.as_ref().and_then(|dns| dns.domain.as_deref()) {
        return parse_origin(domain).context("invalid dns.domain");
    }
    if let Some(legacy) = config.get_flags_patch().tld_dns_zone.as_deref()
        && !legacy.is_empty()
    {
        return parse_origin(legacy).context("invalid flags.tld_dns_zone");
    }
    parse_origin(DEFAULT_ET_DNS_ZONE)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Zone {
    records: BTreeMap<RrKey, RecordSet>,
}

impl Zone {
    pub fn iter_records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
    }
}

pub(crate) type ZoneGroup = RepeatedMessageModel<Zone>;

impl ZoneGroup {
    /// Merges records of every zone into one authority, since an in-memory
    /// authority answers authoritatively and never falls through to another.
    pub fn extend_authority(&self, authority: &mut InMemoryAuthority) {
        for record in self.iter().flat_map(Zone::iter_records) {
            authority.upsert_mut(record.clone(), 0);
        }
    }
}

/// Parses the local static records once, grouped by origin. Called before the
/// server election so an invalid local configuration cannot win the listener.
pub(crate) fn configured_zones(
    dns: Option<&DnsConfig>,
) -> anyhow::Result<BTreeMap<LowerName, ZoneGroup>> {
    let Some(dns) = dns else {
        return Ok(BTreeMap::new());
    };
    Ok(compile_dns(dns)?
        .into_iter()
        .map(|(origin, zone)| {
            (
                origin,
                std::iter::once(Zone {
                    records: zone.records,
                })
                .collect(),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::config::toml::TomlConfigLoader;
    #[test]
    fn dns_domain_prefers_dns_domain_and_falls_back_to_legacy_flag() {
        let loader = TomlConfigLoader::new_from_str("").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "et.net.");

        let loader = TomlConfigLoader::new_from_str("[dns]\ndomain = 'MESH.Example'\n").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "mesh.example.");

        let loader =
            TomlConfigLoader::new_from_str("[flags]\ntld_dns_zone = 'LEGACY.Example'\n").unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "legacy.example.");

        let loader = TomlConfigLoader::new_from_str(
            "[dns]\ndomain = 'mesh.example'\n[flags]\ntld_dns_zone = 'legacy.example'\n",
        )
        .unwrap();
        assert_eq!(dns_domain(&loader).unwrap().to_string(), "mesh.example.");

        assert!(
            TomlConfigLoader::new_from_str(
                "[dns]\ndomain = ''\n[flags]\ntld_dns_zone = 'legacy.example'\n",
            )
            .is_err()
        );

        assert!(
            TomlConfigLoader::new_from_str(
                "[dns]\ndomain = '.'\n[flags]\ntld_dns_zone = 'legacy.example'\n",
            )
            .is_err()
        );

        let loader = TomlConfigLoader::new_from_str("[flags]\ntld_dns_zone = '.'\n").unwrap();
        assert!(dns_domain(&loader).is_err());
    }
}

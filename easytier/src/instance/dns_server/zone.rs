use crate::proto::utils::RepeatedMessageModel;
use anyhow::{Context, ensure};
use easytier_core::config::toml::{ConfigLoader, DEFAULT_ET_DNS_ZONE, DnsConfig, DnsZoneConfig};
use hickory_proto::rr::{DNSClass, LowerName, Name, Record, RecordSet, RrKey};
use hickory_proto::serialize::txt::Parser;
use hickory_server::store::in_memory::InMemoryAuthority;
use std::collections::BTreeMap;

pub(crate) fn parse_origin(origin: &str) -> anyhow::Result<LowerName> {
    ensure!(
        !origin.trim().is_empty(),
        "DNS zone origin must not be empty"
    );
    let mut name: Name = origin.parse().context("invalid DNS zone origin")?;
    ensure!(!name.is_root(), "DNS zone origin must not be root");
    name.set_fqdn(true);
    Ok(LowerName::new(&name))
}

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
    origin: LowerName,
    records: BTreeMap<RrKey, RecordSet>,
}

impl Zone {
    #[cfg(test)]
    pub fn origin(&self) -> &LowerName {
        &self.origin
    }

    pub fn iter_records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
    }
}

impl TryFrom<&DnsZoneConfig> for Zone {
    type Error = anyhow::Error;

    fn try_from(value: &DnsZoneConfig) -> Result<Self, Self::Error> {
        let origin = parse_origin(&value.origin)?;
        let ttl = value.ttl.unwrap_or_default();
        let lines = value
            .records
            .as_ref()
            .map(|list| list.items.as_slice())
            .unwrap_or_default();
        ensure!(
            !lines
                .iter()
                .flat_map(|record| record.lines())
                .any(|line| line.trim_start().starts_with('$')),
            "zone file directives are not supported in DNS records"
        );
        let content = format!(
            "$ORIGIN {origin}\n$TTL {ttl}\n{}\n",
            // Hickory 0.25 carries an explicit record TTL into later records.
            lines.join(&format!("\n$TTL {ttl}\n"))
        );
        let name = Name::from(&origin);
        let (_, records) = Parser::new(content, None, Some(name.clone()))
            .parse()
            .with_context(|| format!("invalid DNS records for zone {origin}"))?;

        for record in records.values().flat_map(RecordSet::records_without_rrsigs) {
            ensure!(
                name.zone_of(record.name()),
                "DNS record {} is outside zone {origin}",
                record.name()
            );
            ensure!(
                record.dns_class() == DNSClass::IN,
                "DNS records must use class IN"
            );
        }

        Ok(Self { origin, records })
    }
}

impl From<Zone> for DnsZoneConfig {
    fn from(value: Zone) -> Self {
        let records = value
            .iter_records()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        Self {
            origin: value.origin.to_string(),
            ttl: None,
            records: Some(records.into()),
        }
    }
}

pub(crate) type ZoneGroup = RepeatedMessageModel<Zone>;

impl ZoneGroup {
    pub fn into_groups(self) -> BTreeMap<LowerName, ZoneGroup> {
        self.into_iter().fold(BTreeMap::new(), |mut map, zone| {
            map.entry(zone.origin.clone()).or_default().push(zone);
            map
        })
    }

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
    let items = dns
        .and_then(|dns| dns.zone.as_ref())
        .map(|zones| zones.items.as_slice())
        .unwrap_or_default();
    Ok(ZoneGroup::try_from(items)?.into_groups())
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::config::toml::{DnsConfig, TomlConfigLoader};
    use hickory_proto::rr::RecordType;

    fn zones(config: &DnsConfig) -> anyhow::Result<ZoneGroup> {
        let items = config
            .zone
            .as_ref()
            .map(|zones| zones.items.as_slice())
            .unwrap_or_default();
        ZoneGroup::try_from(items)
    }

    fn config(records: &[&str]) -> DnsConfig {
        DnsConfig {
            domain: None,
            zone: Some(
                vec![DnsZoneConfig {
                    origin: "EXAMPLE.test".to_owned(),
                    ttl: Some(60),
                    records: Some(
                        records
                            .iter()
                            .map(|record| (*record).to_owned())
                            .collect::<Vec<_>>()
                            .into(),
                    ),
                }]
                .into(),
            ),
        }
    }

    #[test]
    fn custom_records_parse_common_types_and_ttls() {
        let config = config(&[
            "nas IN A 10.0.0.8",
            "nas IN AAAA fd00::8",
            "alias 120 IN CNAME nas",
            "@ IN TXT \"local records\"",
        ]);
        let parsed = zones(&config).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].origin().to_string(), "example.test.");
        let records = parsed[0].iter_records().collect::<Vec<_>>();
        assert_eq!(records.len(), 4);
        for record in records {
            assert!(
                record.name().to_string().ends_with(".example.test.")
                    || record.name().to_string() == "example.test."
            );
            assert_eq!(
                record.ttl(),
                if record.record_type() == RecordType::CNAME {
                    120
                } else {
                    60
                }
            );
        }
        let mut config = config;
        config.zone.as_mut().unwrap().items[0].ttl = Some(0);
        let parsed = zones(&config).unwrap();
        assert_eq!(parsed[0].iter_records().next().unwrap().ttl(), 0);
    }

    #[test]
    fn custom_records_reject_invalid_records_and_directives() {
        for record in [
            "nas IN A not-an-address",
            "outside.invalid. IN A 10.0.0.8",
            "$INCLUDE /etc/hosts",
            "nas IN A 10.0.0.8\n$ORIGIN other.test.",
        ] {
            assert!(zones(&config(&[record])).is_err(), "accepted {record}");
        }
        for origin in ["", "."] {
            let mut config = config(&[]);
            config.zone.as_mut().unwrap().items[0].origin = origin.to_owned();
            assert!(zones(&config).is_err(), "accepted origin {origin}");
        }
        assert!(
            zones(&DnsConfig {
                domain: None,
                zone: None
            })
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn zone_group_into_groups_merges_same_origin() {
        let mut config = config(&["nas IN A 10.0.0.8"]);
        let mut second = config.zone.as_ref().unwrap().items[0].clone();
        second.origin = "example.test.".to_owned();
        config.zone.as_mut().unwrap().items.push(second);
        let groups = zones(&config).unwrap().into_groups();
        assert_eq!(groups.len(), 1);
        assert_eq!(
            groups[&"example.test.".parse::<LowerName>().unwrap()].len(),
            2
        );
    }

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

        let loader = TomlConfigLoader::new_from_str(
            "[dns]\ndomain = ''\n[flags]\ntld_dns_zone = 'legacy.example'\n",
        )
        .unwrap();
        assert!(dns_domain(&loader).is_err());

        let loader = TomlConfigLoader::new_from_str(
            "[dns]\ndomain = '.'\n[flags]\ntld_dns_zone = 'legacy.example'\n",
        )
        .unwrap();
        assert!(dns_domain(&loader).is_err());

        let loader = TomlConfigLoader::new_from_str("[flags]\ntld_dns_zone = '.'\n").unwrap();
        assert!(dns_domain(&loader).is_err());
    }
}

use crate::config::dns::compile_dns;
pub use crate::config::dns::{DnsZone as Zone, parse_origin};
use crate::config::toml::{ConfigLoader, DEFAULT_ET_DNS_ZONE, DnsConfig};
use anyhow::Context;
use hickory_proto::rr::LowerName;
use std::collections::BTreeMap;

/// Resolves the default Magic DNS zone origin from `dns.domain`, falling back
/// to the deprecated `flags.tld_dns_zone` patch when `dns.domain` is unset, and
/// finally to [`DEFAULT_ET_DNS_ZONE`].
#[allow(deprecated)]
pub fn dns_domain(config: &impl ConfigLoader) -> anyhow::Result<LowerName> {
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

/// Compiles the complete contribution using shared configuration validation.
pub fn configured_zones(dns: Option<&DnsConfig>) -> anyhow::Result<BTreeMap<LowerName, Vec<Zone>>> {
    let Some(dns) = dns else {
        return Ok(BTreeMap::new());
    };
    Ok(compile_dns(dns)?
        .into_iter()
        .map(|(origin, zone)| (origin, vec![zone]))
        .collect())
}

/// Resolves contribution metadata without rewriting structured record input.
pub fn normalized_dns(config: &impl ConfigLoader) -> anyhow::Result<DnsConfig> {
    let dns = config.get_dns();
    if let Some(dns) = &dns {
        compile_dns(dns)?;
    }
    let mut zones = dns.and_then(|dns| dns.zone).unwrap_or_default().items;
    for zone in &mut zones {
        zone.origin = parse_origin(&zone.origin)?.to_string();
    }
    zones.sort_by(|left, right| left.origin.cmp(&right.origin));
    Ok(DnsConfig {
        domain: Some(dns_domain(config)?.to_string()),
        zone: Some(zones.into()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::toml::TomlConfig;

    #[test]
    fn contribution_normalization_preserves_structured_record_input() {
        let config = TomlConfig::new_from_str(
            r#"
[dns]
domain = "MESH.test"
[[dns.zone]]
origin = "RECORDS.test"
ttl = 60
records = [
    { name = "info", type = "TXT", ttl = 0, txt = { segments = ["space quote\" slash\\ semicolon;", "tail"] } },
    { name = "alias", type = "CNAME", value = "info" },
]
"#,
        )
        .unwrap();
        let original = config.get_dns().unwrap();
        let normalized = normalized_dns(&config).unwrap();
        assert_eq!(normalized.domain.as_deref(), Some("mesh.test."));
        let zone = &normalized.zone.as_ref().unwrap().items[0];
        assert_eq!(zone.origin, "records.test.");
        assert_eq!(
            zone.records,
            original.zone.as_ref().unwrap().items[0].records
        );
        config.set_dns(Some(normalized.clone()));
        assert_eq!(normalized_dns(&config).unwrap(), normalized);
    }
}

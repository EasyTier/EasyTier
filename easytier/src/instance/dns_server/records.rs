use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use easytier_core::gateway::magic_dns::MagicDnsRecordSnapshot;
use hickory_proto::rr::{LowerName, Name, Record, RecordSet, RecordType, RrKey};
use hickory_server::{authority::ZoneType, store::in_memory::InMemoryAuthority};

use super::config::{RecordBuilder, RecordType as ConfigRecordType};

fn merge_configured_records(
    snapshot: &MagicDnsRecordSnapshot,
) -> anyhow::Result<BTreeMap<LowerName, BTreeMap<RrKey, RecordSet>>> {
    let mut configured = BTreeMap::<LowerName, BTreeMap<RrKey, RecordSet>>::new();
    for (origin, zones) in snapshot
        .clients
        .values()
        .flat_map(|client| &client.configured)
    {
        let records = configured.entry(origin.clone()).or_default();
        for (key, incoming) in zones.iter().flat_map(|zone| &zone.records) {
            let cname_conflict = if key.record_type == RecordType::CNAME {
                records.keys().any(|existing| {
                    existing.name == key.name && existing.record_type != RecordType::CNAME
                })
            } else {
                records.contains_key(&RrKey::new(key.name.clone(), RecordType::CNAME))
            };
            anyhow::ensure!(
                !cname_conflict,
                "DNS zone {origin}: CNAME cannot coexist with another record at {}",
                key.name
            );
            let Some(current) = records.get_mut(key) else {
                records.insert(key.clone(), incoming.clone());
                continue;
            };
            anyhow::ensure!(
                current.ttl() == incoming.ttl(),
                "DNS zone {origin}: RRset TTLs must match at {} {}",
                key.name,
                key.record_type
            );
            if matches!(
                key.record_type,
                RecordType::CNAME | RecordType::ANAME | RecordType::SOA
            ) {
                anyhow::ensure!(
                    current
                        .records_without_rrsigs()
                        .eq(incoming.records_without_rrsigs()),
                    "DNS zone {origin}: {} permits only one value at {}",
                    key.record_type,
                    key.name
                );
            } else {
                // Hickory deduplicates RDATA after the compatibility checks.
                for record in incoming.records_without_rrsigs() {
                    current.insert(record.clone(), 0);
                }
            }
        }
    }
    Ok(configured)
}

pub(super) fn build_authorities(
    snapshot: &MagicDnsRecordSnapshot,
    origins: BTreeSet<LowerName>,
) -> anyhow::Result<BTreeMap<LowerName, Arc<InMemoryAuthority>>> {
    let configured = merge_configured_records(snapshot)?;
    let mut authorities = BTreeMap::new();
    for origin in origins {
        let mut authority = InMemoryAuthority::empty(Name::from(&origin), ZoneType::Primary, false);
        for route in snapshot.zones.get(&origin).into_iter().flatten() {
            if route.hostname.is_empty() {
                continue;
            }
            let Some(address) = route.ipv4_addr else {
                continue;
            };
            let record = RecordBuilder::default()
                .rr_type(ConfigRecordType::A)
                .name(format!("{}.{}", route.hostname, origin))
                .value(address.to_string())
                .ttl(Duration::from_secs(1))
                .build()?;
            let mut record: Record = match (&record).try_into() {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(?error, "invalid DNS node name");
                    continue;
                }
            };
            if let Some(records) = configured.get(&origin) {
                let name = LowerName::new(record.name());
                anyhow::ensure!(
                    !records.contains_key(&RrKey::new(name.clone(), RecordType::CNAME)),
                    "automatic DNS record {} conflicts with configured records in {origin}",
                    record.name()
                );
                // Hickory's insert changes the set TTL without changing all
                // existing records, so normalize automatic values up front.
                if let Some(set) = records.get(&RrKey::new(name, RecordType::A)) {
                    record.set_ttl(set.ttl());
                }
            }
            // A route can be advertised by several local instances.
            authority.upsert_mut(record, 0);
        }
        let mut has_soa = false;
        if let Some(records) = configured.get(&origin) {
            for record in records
                .values()
                .flat_map(|set| set.records_without_rrsigs())
            {
                has_soa |= record.record_type() == RecordType::SOA;
                // Preserve configured TTLs when static and automatic A
                // records share an RRset, as at local-only startup.
                authority.upsert_mut(record.clone(), 0);
            }
        }
        if !has_soa {
            let soa = RecordBuilder::default()
                .rr_type(ConfigRecordType::SOA)
                .name(origin.to_string())
                .value(format!(
                    "ns.{origin} hostmaster.{origin} 2023101001 7200 3600 1209600 86400"
                ))
                .ttl(Duration::from_secs(60))
                .build()?;
            authority.upsert_mut((&soa).try_into()?, 0);
        }
        authorities.insert(origin, Arc::new(authority));
    }
    Ok(authorities)
}

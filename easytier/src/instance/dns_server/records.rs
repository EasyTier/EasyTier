use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use easytier_core::gateway::magic_dns::MagicDnsRecordSnapshot;
use hickory_proto::rr::{LowerName, Name, Record, RecordType, RrKey};
use hickory_server::{authority::ZoneType, store::in_memory::InMemoryAuthority};

use super::config::{RecordBuilder, RecordType as ConfigRecordType};

pub(super) fn build_authorities(
    snapshot: &MagicDnsRecordSnapshot,
    origins: BTreeSet<LowerName>,
) -> anyhow::Result<BTreeMap<LowerName, Arc<InMemoryAuthority>>> {
    let configured: BTreeMap<_, _> = snapshot
        .clients
        .values()
        .flat_map(|client| &client.configured)
        .collect();
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
            let record: Record = match (&record).try_into() {
                Ok(record) => record,
                Err(error) => {
                    tracing::warn!(?error, "invalid DNS node name");
                    continue;
                }
            };
            anyhow::ensure!(
                !configured
                    .get(&origin)
                    .into_iter()
                    .flat_map(|zones| zones.iter())
                    .any(|zone| {
                        zone.records.contains_key(&RrKey::new(
                            LowerName::new(record.name()),
                            RecordType::CNAME,
                        ))
                    }),
                "automatic DNS record {} conflicts with configured records in {origin}",
                record.name()
            );
            // A route can be advertised by several local instances.
            authority.upsert_mut(record, 0);
        }
        let mut has_soa = false;
        if let Some(zones) = configured.get(&origin) {
            for record in zones
                .iter()
                .flat_map(|zone| zone.records.values())
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

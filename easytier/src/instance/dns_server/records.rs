use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use easytier_core::gateway::magic_dns::MagicDnsRecordSnapshot;
use hickory_proto::{
    rr::{LowerName, Name, RData, Record, RecordType, RrKey},
    serialize::binary::{BinEncodable, BinEncoder, EncodeMode},
};
use hickory_server::{authority::ZoneType, store::in_memory::InMemoryAuthority};

use crate::proto::{
    api::config::{DnsRecordStatus, DnsRuntimeStatus, DnsZoneStatus},
    core_config::{DnsRecordRaw, DnsRecordType},
};

use super::config::{RecordBuilder, RecordType as ConfigRecordType};

struct Contribution {
    instance: String,
    zone: LowerName,
    automatic: bool,
    records: BTreeMap<Vec<u8>, Record>,
    notices: Vec<String>,
}

impl Contribution {
    fn first(&self) -> &Record {
        self.records.values().next().unwrap()
    }

    fn priority(&self) -> (bool, &str) {
        (self.automatic, &self.instance)
    }
}

pub(super) struct MergedRecords {
    pub authorities: BTreeMap<LowerName, Arc<InMemoryAuthority>>,
    pub status: BTreeMap<String, DnsRuntimeStatus>,
}

fn rdata_key(record: &Record) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut encoder = BinEncoder::with_mode(&mut bytes, EncodeMode::Signing);
    encoder.set_canonical_names(true);
    record.data().emit(&mut encoder)?;
    Ok(bytes)
}

fn raw_record(record: &Record) -> DnsRecordRaw {
    // Hickory's TXT Display concatenates segments, and HINFO/NAPTR Display
    // does not escape embedded quotes. Preserve their actual character-strings.
    let quoted = |value: &[u8]| {
        let mut result = String::from("\"");
        for &byte in value {
            match byte {
                b'"' | b'\\' => {
                    result.push('\\');
                    result.push(char::from(byte));
                }
                b' '..=b'~' => result.push(char::from(byte)),
                _ => {
                    use std::fmt::Write as _;
                    write!(result, "\\{byte:03}").unwrap();
                }
            }
        }
        result.push('"');
        result
    };
    let value = match record.data() {
        RData::TXT(txt) => txt
            .txt_data()
            .iter()
            .map(|segment| quoted(segment))
            .collect::<Vec<_>>()
            .join(" "),
        RData::HINFO(info) => format!("{} {}", quoted(info.cpu()), quoted(info.os())),
        RData::NAPTR(naptr) => format!(
            "{} {} {} {} {} {}",
            naptr.order(),
            naptr.preference(),
            quoted(naptr.flags()),
            quoted(naptr.services()),
            quoted(naptr.regexp()),
            naptr.replacement()
        ),
        RData::CAA(caa) => format!("{} {} {}", caa.flags(), caa.tag(), quoted(caa.raw_value())),
        data => data.to_string(),
    };
    DnsRecordRaw {
        name: record.name().to_string(),
        r#type: DnsRecordType::from_str_name(&record.record_type().to_string())
            .expect("all published record types have a configuration type") as i32,
        ttl: Some(record.ttl()),
        value: Some(value),
    }
}

impl MergedRecords {
    pub fn build(
        snapshot: &MagicDnsRecordSnapshot,
        origins: BTreeSet<LowerName>,
    ) -> anyhow::Result<Self> {
        let mut contributions = Vec::new();
        for (instance, client) in &snapshot.clients {
            for (zone, group) in &client.configured {
                for set in group.iter().flat_map(|zone| zone.records.values()) {
                    contributions.push(Contribution {
                        instance: instance.clone(),
                        zone: zone.clone(),
                        automatic: false,
                        records: set
                            .records_without_rrsigs()
                            .map(|record| Ok((rdata_key(record)?, record.clone())))
                            .collect::<anyhow::Result<_>>()?,
                        notices: Vec::new(),
                    });
                }
            }
            let mut nodes = BTreeMap::<LowerName, BTreeMap<Vec<u8>, Record>>::new();
            for route in &client.routes {
                if route.hostname.is_empty() {
                    continue;
                }
                let Some(address) = route.ipv4_addr else {
                    continue;
                };
                let record = RecordBuilder::default()
                    .rr_type(ConfigRecordType::A)
                    .name(format!("{}.{}", route.hostname, client.zone))
                    .value(address.to_string())
                    .ttl(std::time::Duration::from_secs(1))
                    .build()?;
                let record: Record = match (&record).try_into() {
                    Ok(record) => record,
                    Err(error) => {
                        tracing::warn!(?error, "invalid DNS node name");
                        continue;
                    }
                };
                nodes
                    .entry(LowerName::new(record.name()))
                    .or_default()
                    .insert(rdata_key(&record)?, record);
            }
            for records in nodes.into_values() {
                contributions.push(Contribution {
                    instance: instance.clone(),
                    zone: client.zone.clone(),
                    automatic: true,
                    records,
                    notices: Vec::new(),
                });
            }
        }

        let mut owners = BTreeMap::<(LowerName, LowerName), Vec<usize>>::new();
        for (index, contribution) in contributions.iter().enumerate() {
            owners
                .entry((
                    contribution.zone.clone(),
                    LowerName::new(contribution.first().name()),
                ))
                .or_default()
                .push(index);
        }
        let mut zones: BTreeMap<_, BTreeMap<RrKey, Vec<Record>>> = origins
            .into_iter()
            .map(|origin| (origin, BTreeMap::new()))
            .collect();
        for ((zone, owner), mut indices) in owners {
            indices.sort_by(|&a, &b| {
                contributions[a]
                    .priority()
                    .cmp(&contributions[b].priority())
                    .then_with(|| {
                        contributions[a]
                            .first()
                            .record_type()
                            .cmp(&contributions[b].first().record_type())
                    })
            });
            let preferred = &contributions[indices[0]];
            let cname = preferred.first().record_type() == RecordType::CNAME;
            let preferred_instance = preferred.instance.clone();
            let mut types = BTreeMap::<RecordType, Vec<usize>>::new();
            for index in indices {
                let candidate = &mut contributions[index];
                let kind = candidate.first().record_type();
                if (kind == RecordType::CNAME) != cname {
                    candidate.notices.push(format!(
                        "suppressed: incompatible name owned by instance {preferred_instance} \
                         (manual records precede automatic records, then instance UUID order)"
                    ));
                } else {
                    types.entry(kind).or_default().push(index);
                }
            }
            for (kind, indices) in types {
                let first = indices[0];
                let preferred_instance = contributions[first].instance.clone();
                let mut accepted = Vec::new();
                for index in indices {
                    // Other types encode application policy or singleton values.
                    // Preserve a source's complete RRset instead of inventing a
                    // combined SPF, service selection, or trust policy.
                    if matches!(kind, RecordType::A | RecordType::AAAA | RecordType::PTR)
                        || contributions[index]
                            .records
                            .keys()
                            .eq(contributions[first].records.keys())
                    {
                        accepted.push(index);
                    } else {
                        contributions[index].notices.push(format!(
                            "suppressed: different {kind} RRset; instance {preferred_instance} \
                             wins by instance UUID order"
                        ));
                    }
                }
                let ttl = accepted
                    .iter()
                    .map(|&index| contributions[index].first().ttl())
                    .min()
                    .unwrap();
                let mut records = BTreeMap::new();
                for &index in &accepted {
                    let candidate = &mut contributions[index];
                    if candidate.first().ttl() != ttl {
                        candidate.notices.push(format!(
                            "TTL reduced to {ttl}: minimum among compatible contributions"
                        ));
                    }
                    for (key, record) in &candidate.records {
                        let mut record = record.clone();
                        record.set_ttl(ttl);
                        records.insert(key.clone(), record);
                    }
                }
                if accepted.len() > 1 {
                    for index in accepted {
                        contributions[index]
                            .notices
                            .push("compatible contributions merged and deduplicated".to_owned());
                    }
                }
                zones.get_mut(&zone).unwrap().insert(
                    RrKey::new(owner.clone(), kind),
                    records.into_values().collect(),
                );
            }
        }

        let mut authorities = BTreeMap::new();
        for (origin, records) in &mut zones {
            let soa = RrKey::new(origin.clone(), RecordType::SOA);
            if let std::collections::btree_map::Entry::Vacant(entry) = records.entry(soa) {
                let record = RecordBuilder::default()
                    .rr_type(ConfigRecordType::SOA)
                    .name(origin.to_string())
                    .value(format!(
                        "ns.{origin} hostmaster.{origin} 2023101001 7200 3600 1209600 86400"
                    ))
                    .ttl(std::time::Duration::from_secs(60))
                    .build()?;
                entry.insert(vec![(&record).try_into()?]);
            }
            let mut authority =
                InMemoryAuthority::empty(Name::from(origin), ZoneType::Primary, false);
            for record in records.values().flatten() {
                anyhow::ensure!(
                    authority.upsert_mut(record.clone(), 0),
                    "failed to insert resolved DNS record {} {} in {origin}",
                    record.name(),
                    record.record_type()
                );
            }
            authorities.insert(origin.clone(), Arc::new(authority));
        }

        let mut status: BTreeMap<_, _> = snapshot
            .clients
            .iter()
            .map(|(id, client)| {
                let mut origins: BTreeSet<_> = client.configured.keys().cloned().collect();
                origins.insert(client.zone.clone());
                let zones = origins
                    .into_iter()
                    .map(|origin| DnsZoneStatus {
                        apex_records: zones
                            .get(&origin)
                            .into_iter()
                            .flat_map(|records| records.iter())
                            .filter(|(key, _)| key.name == origin)
                            .flat_map(|(_, records)| records.iter().map(raw_record))
                            .collect(),
                        origin: origin.to_string(),
                    })
                    .collect();
                (
                    id.clone(),
                    DnsRuntimeStatus {
                        published_dns: Some(client.dns.clone()),
                        records: Vec::new(),
                        zones,
                    },
                )
            })
            .collect();
        for mut candidate in contributions {
            let owner = LowerName::new(candidate.first().name());
            let authority = zones
                .keys()
                .filter(|zone| zone.zone_of(&owner))
                .max_by_key(|zone| zone.num_labels())
                .unwrap();
            if authority != &candidate.zone {
                candidate.notices.push(format!(
                    "shadowed by authoritative zone {authority}; no parent-zone fallback"
                ));
            }
            let effective = zones[authority]
                .iter()
                .filter(|(key, _)| key.name == owner)
                .flat_map(|(_, records)| records.iter().map(raw_record))
                .collect();
            status
                .get_mut(&candidate.instance)
                .unwrap()
                .records
                .push(DnsRecordStatus {
                    zone: candidate.zone.to_string(),
                    automatic: candidate.automatic,
                    requested: candidate.records.values().map(raw_record).collect(),
                    authority: authority.to_string(),
                    effective,
                    notices: candidate.notices,
                });
        }
        Ok(Self {
            authorities,
            status,
        })
    }
}

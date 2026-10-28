use anyhow::{Context, ensure};
use easytier_core::config::toml::DnsConfig;
use hickory_proto::rr;
use hickory_proto::rr::RData;
use hickory_proto::serialize::txt::Parser;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone, derive_builder::Builder)]
pub struct RunConfig {
    general: GeneralConfig,

    #[builder(default = HashMap::new())]
    zones: Zone,

    #[builder(default = Vec::new())]
    #[serde(default)]
    excluded_forward_nameservers: Vec<IpAddr>,
}

impl RunConfig {
    pub fn general(&self) -> &GeneralConfig {
        &self.general
    }

    pub fn zones(&self) -> &Zone {
        &self.zones
    }

    pub fn excluded_forward_nameservers(&self) -> &Vec<IpAddr> {
        &self.excluded_forward_nameservers
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, derive_builder::Builder)]
pub struct GeneralConfig {
    #[builder(setter(into, strip_option), default = None)]
    listen_tcp: Option<String>,

    #[builder(setter(into, strip_option), default = None)]
    listen_udp: Option<String>,
}

impl GeneralConfig {
    pub fn listen_tcp(&self) -> &Option<String> {
        &self.listen_tcp
    }

    pub fn listen_udp(&self) -> &Option<String> {
        &self.listen_udp
    }
}

pub type Zone = HashMap<String, Vec<Record>>; // domain -> records

pub type RecordType = rr::RecordType;

#[derive(Serialize, Deserialize, Debug, Clone, derive_builder::Builder)]
pub struct Record {
    #[serde(rename = "type")]
    rr_type: RecordType,

    name: String,
    value: String,

    #[serde(with = "humantime_serde")]
    ttl: Duration,
}

impl Record {
    pub fn name(&self) -> anyhow::Result<rr::Name> {
        let name = rr::Name::from_str(self.name.as_str())?;
        Ok(name)
    }

    fn rr_type(&self) -> rr::RecordType {
        self.rr_type
    }
}

impl TryFrom<Record> for rr::Record {
    type Error = anyhow::Error;

    fn try_from(value: Record) -> Result<Self, Self::Error> {
        let r: rr::Record = (&value).try_into()?;
        Ok(r)
    }
}

impl TryFrom<&Record> for rr::Record {
    type Error = anyhow::Error;

    fn try_from(value: &Record) -> Result<Self, Self::Error> {
        let name = value.name()?;
        let mut record = Self::update0(name, value.ttl.as_secs() as u32, value.rr_type());
        record.set_dns_class(rr::DNSClass::IN);
        match value.rr_type {
            RecordType::A => {
                let addr: Ipv4Addr = value.value.parse()?;
                record.set_data(RData::A(rr::rdata::a::A(addr)));
            }
            RecordType::SOA => {
                let soa = value.value.split_whitespace().collect::<Vec<_>>();
                if soa.len() != 7 {
                    return Err(anyhow::anyhow!("invalid SOA record"));
                }
                let mname = rr::Name::from_str(soa[0])?;
                let rname = rr::Name::from_str(soa[1])?;
                let serial: u32 = soa[2].parse()?;
                let refresh: u32 = soa[3].parse()?;
                let retry: u32 = soa[4].parse()?;
                let expire: u32 = soa[5].parse()?;
                let minimum: u32 = soa[6].parse()?;
                record.set_data(RData::SOA(rr::rdata::soa::SOA::new(
                    mname,
                    rname,
                    serial,
                    refresh.try_into().unwrap(),
                    retry.try_into().unwrap(),
                    expire.try_into().unwrap(),
                    minimum,
                )));
            }
            _ => todo!(),
        }
        Ok(record)
    }
}

pub(super) type ConfiguredZones = BTreeMap<String, Vec<rr::Record>>;

#[derive(Default)]
pub(super) struct ConfiguredRecordStore {
    pub clients: BTreeMap<String, ConfiguredZones>,
    // Route zones remain authoritative after their last route disappears.
    pub route_zones: BTreeSet<String>,
    pub applied_domains: BTreeSet<String>,
    pub system_closed: bool,
}

pub(super) fn dns_origin(name: &str) -> anyhow::Result<String> {
    ensure!(!name.is_empty(), "DNS zone origin must not be empty");
    let mut name: rr::Name = name.parse().context("invalid DNS zone origin")?;
    ensure!(
        !name.is_root()
            && name
                .iter()
                .flatten()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "DNS zone origin must be a domain name"
    );
    name.set_fqdn(true);
    Ok(rr::LowerName::new(&name).to_string())
}

pub(super) fn parse_records(config: Option<&DnsConfig>) -> anyhow::Result<ConfiguredZones> {
    let mut zones = ConfiguredZones::new();
    for zone in config.into_iter().flat_map(|config| &config.zone) {
        let origin = dns_origin(&zone.origin)?;
        let name: rr::Name = origin.parse()?;
        for record in &zone.records {
            ensure!(
                !record
                    .lines()
                    .any(|line| line.trim_start().starts_with('$')),
                "zone file directives are not supported in DNS records"
            );
        }
        let content = format!(
            "$ORIGIN {origin}\n$TTL {}\n{}\n",
            zone.ttl.unwrap_or_default(),
            // Hickory 0.25 carries an explicit record TTL into later records.
            zone.records
                .join(&format!("\n$TTL {}\n", zone.ttl.unwrap_or_default()))
        );
        let (_, records) = Parser::new(content, None, Some(name.clone()))
            .parse()
            .with_context(|| format!("invalid DNS records for zone {origin}"))?;
        let output = zones.entry(origin).or_default();
        for record in records
            .values()
            .flat_map(|set| set.records_without_rrsigs())
        {
            ensure!(
                name.zone_of(record.name()),
                "DNS record {} is outside zone {name}",
                record.name()
            );
            ensure!(
                record.dns_class() == rr::DNSClass::IN,
                "DNS records must use class IN"
            );
            output.push(record.clone());
        }
    }
    Ok(zones)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[tokio::test]
    async fn it_works() -> anyhow::Result<()> {
        let text = r#"
[general]
listen_tcp = "127.0.0.1:5300"
listen_udp = "127.0.0.1:5353"

[[zones."et.internal"]]
type = "A"
name = "www"
value = "123.123.123.123"
ttl = "60s"

[[zones."et.top"]]
type = "A"
name = "@"
value = "100.100.100.100"
ttl = "61s"

"#;

        let config = toml::from_str::<RunConfig>(text)?;
        assert_eq!(
            config.general.listen_tcp().clone().unwrap(),
            "127.0.0.1:5300"
        );
        assert_eq!(
            config.general.listen_udp().clone().unwrap(),
            "127.0.0.1:5353"
        );
        assert_eq!(config.zones.len(), 2);

        let (domain, records) = config
            .zones
            .get_key_value("et.internal")
            .ok_or(anyhow!("et.internal not found"))?;
        assert_eq!(domain, "et.internal");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.rr_type, RecordType::A);
        assert_eq!(record.name, "www");
        assert_eq!(record.value, "123.123.123.123");
        assert_eq!(record.ttl.as_secs(), 60);

        let (domain, records) = config
            .zones
            .get_key_value("et.top")
            .ok_or(anyhow!("et.top not found"))?;
        assert_eq!(domain, "et.top");
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record.rr_type, RecordType::A);
        assert_eq!(record.name, "@");
        assert_eq!(record.value, "100.100.100.100");
        assert_eq!(record.ttl.as_secs(), 61);

        Ok(())
    }
    use easytier_core::config::toml::DnsZoneConfig;

    fn config(records: &[&str]) -> DnsConfig {
        DnsConfig {
            zone: vec![DnsZoneConfig {
                origin: "EXAMPLE.test".to_owned(),
                ttl: Some(60),
                records: records.iter().map(|record| (*record).to_owned()).collect(),
            }],
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
        let zones = parse_records(Some(&config)).unwrap();
        let records = &zones["example.test."];
        assert_eq!(records.len(), 4);
        for record in records {
            assert!(
                record.name().to_string().ends_with(".example.test.")
                    || record.name().to_string() == "example.test."
            );
            assert_eq!(
                record.ttl(),
                if record.record_type() == rr::RecordType::CNAME {
                    120
                } else {
                    60
                }
            );
        }
        let mut config = config;
        config.zone[0].ttl = Some(0);
        let zones = parse_records(Some(&config)).unwrap();
        assert_eq!(zones["example.test."][0].ttl(), 0);
    }

    #[test]
    fn custom_records_reject_invalid_records_and_directives() {
        for record in [
            "nas IN A not-an-address",
            "outside.invalid. IN A 10.0.0.8",
            "$INCLUDE /etc/hosts",
            "nas IN A 10.0.0.8\n$ORIGIN other.test.",
        ] {
            assert!(
                parse_records(Some(&config(&[record]))).is_err(),
                "accepted {record}"
            );
        }
        for origin in ["", ".", "../escape", "/tmp/escape"] {
            let mut config = config(&[]);
            config.zone[0].origin = origin.to_owned();
            assert!(
                parse_records(Some(&config)).is_err(),
                "accepted origin {origin}"
            );
        }
        assert!(parse_records(None).unwrap().is_empty());
    }
}

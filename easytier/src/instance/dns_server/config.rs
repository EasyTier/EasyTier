use hickory_proto::rr;
use hickory_proto::rr::RData;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    fn name(&self) -> anyhow::Result<rr::Name> {
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
}

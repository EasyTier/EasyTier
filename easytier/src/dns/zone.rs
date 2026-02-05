use crate::dns::utils::NameServerAddr;
use crate::proto::dns::ZoneConfigPb;
use hickory_proto::rr::{LowerName, Record, RecordSet, RrKey, RrsetRecords};
use hickory_proto::serialize::txt::Parser;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_server::authority::{AuthorityObject, ZoneType};
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use hickory_server::store::in_memory::InMemoryAuthority;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use url::Url;

#[derive(Debug, Clone)]
pub struct Zone {
    pub(crate) origin: LowerName,
    pub(crate) records: BTreeMap<RrKey, RecordSet>,
    pub(crate) forward: Option<ForwardConfig>,
}

impl Zone {
    pub fn new(name: LowerName) -> Self {
        Self {
            origin: name,
            records: BTreeMap::new(),
            forward: None,
        }
    }

    pub fn create_authorities(&self) -> anyhow::Result<Vec<Arc<dyn AuthorityObject>>> {
        let mut authorities = Vec::<Arc<dyn AuthorityObject>>::with_capacity(2);

        let memory = InMemoryAuthority::new(
            self.origin.clone().into(),
            self.records.clone(),
            ZoneType::Primary,
            false,
        )
        .map_err(|e| anyhow::anyhow!("failed to create memory authority: {}", e))?;
        authorities.push(Arc::new(memory));

        if let Some(forward) = &self.forward {
            let forward = ForwardAuthority::builder_with_config(
                forward.clone(),
                TokioConnectionProvider::default(),
            )
            .build()
            .map_err(|e| anyhow::anyhow!("failed to create forward authority: {}", e))?;
            authorities.push(Arc::new(forward));
        }

        Ok(authorities)
    }

    fn parse_name_server<A>(addr: A) -> anyhow::Result<NameServerConfig>
    where
        A: AsRef<str>,
    {
        const SUPPORTED_PROTOCOLS: [Protocol; 2] = [
            Protocol::Udp,
            Protocol::Tcp,
            // Protocol::Tls,
            // Protocol::Https,
            // Protocol::Quic,
            // Protocol::H3,
        ];

        let addr = addr.as_ref();

        let url = if addr.parse::<IpAddr>().is_ok() || addr.parse::<SocketAddr>().is_ok() {
            Url::parse(&format!("udp://{addr}"))?
        } else {
            Url::parse(addr)?
        };

        let scheme = url.scheme();
        let protocol = *SUPPORTED_PROTOCOLS
            .iter()
            .find(|p| p.to_string().to_lowercase() == scheme)
            .ok_or(anyhow::anyhow!("unsupported scheme: {scheme}"))?;
        let addr = url.host_str().ok_or(anyhow::anyhow!("host not found"))?;
        let addr = addr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|e| anyhow::anyhow!("invalid ip address '{addr}': {e}"))?;
        let port = if let Some(port) = url.port() {
            port
        } else {
            match protocol {
                Protocol::Udp | Protocol::Tcp => 53,
                _ => return Err(anyhow::anyhow!("port not found")),
            }
        };
        let addr = SocketAddr::new(addr, port);
        Ok(NameServerConfig::new(addr, protocol))
    }

    pub fn set_forwarders<F, A>(
        &mut self,
        forwarders: F,
        options: Option<ResolverOpts>,
    ) -> anyhow::Result<()>
    where
        F: Iterator<Item = A>,
        A: AsRef<str>,
    {
        let name_servers = forwarders
            .into_iter()
            .map(|s| s.as_ref().parse::<NameServerAddr>().map(Into::into))
            .collect::<anyhow::Result<Vec<_>>>()?
            .into();
        self.forward = Some(ForwardConfig {
            name_servers,
            options,
        });
        Ok(())
    }

    pub fn iter_records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .filter(|set| !set.is_empty())
            .flat_map(|set| {
                let RrsetRecords::RecordsOnly(records) = set.records_without_rrsigs() else {
                    unreachable!()
                };
                records
            })
    }
}

impl FromStr for Zone {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (origin, records) = Parser::new(s, None, None)
            .parse()
            .map_err(|e| anyhow::anyhow!("failed to parse zone file: {e}"))?;

        let mut zone = Zone::new(origin.clone().into());
        zone.records = records;
        Ok(zone)
    }
}

impl TryFrom<&ZoneConfigPb> for Zone {
    type Error = anyhow::Error;

    fn try_from(value: &ZoneConfigPb) -> Result<Self, Self::Error> {
        let mut zone: Zone = value.to_string().parse()?;
        zone.set_forwarders(value.forwarders.iter(), None)?;

        Ok(zone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::DnsConfig;
    use hickory_proto::rr::{rdata, Name, RData, RecordType};

    #[tokio::test]
    async fn config() -> anyhow::Result<()> {
        let sep = "=".repeat(80);
        let text = r#"
    listeners = [
        "1.1.1.1",
    ]

    name = "et-test"
    domain = "测试.net"

    [[zone]]
    origin = "et.internal"

    broadcast = true

    ttl = 10

    records = [
        "www 0 IN A 123.123.123.123",
        "app IN CNAME www",
        "ftp IN AAAA ::",
        "mail IN MX 10 app",
    ]

    forwarders = [
        "1.1.1.1",
    ]

    [[zone]]
    origin = "et.top"

    records = [
        "@ 60 A 100.100.100.100",
    ]

    "#;

        let config = toml::from_str::<DnsConfig>(text)?;
        assert_eq!(config.domain.to_string(), "测试.net");
        let mut zones = config.zones;
        assert_eq!(zones.len(), 2);

        let zone = zones
            .extract_if(.., |z| z.origin.to_string() == "et.internal")
            .next()
            .unwrap();
        assert_eq!(zone.broadcast, true);
        let zone = ZoneConfigPb::from(&zone);
        println!("{}", sep);
        println!("{}", zone);
        println!("{}", sep);
        let zone = Zone::try_from(&zone)?;
        assert_eq!(zone.origin.to_string(), "et.internal.");
        let records = zone.iter_records().collect::<Vec<_>>();
        assert_eq!(records.len(), 4);

        let mut record = Record::update0(
            Name::from_str("www")?.append_domain(&*zone.origin)?,
            60,
            RecordType::A,
        );
        record.set_data(RData::A(rdata::a::A("123.123.123.123".parse()?)));
        assert_eq!(
            record,
            **records
                .iter()
                .find(|r| r.name().to_string().starts_with("www."))
                .unwrap()
        );

        let mut record = Record::update0(
            Name::from_str("app")?.append_domain(&*zone.origin)?,
            10,
            RecordType::CNAME,
        );
        record.set_data(RData::CNAME(rdata::name::CNAME(
            Name::from_str("www")?.append_domain(&*zone.origin)?,
        )));
        assert_eq!(
            record,
            **records
                .iter()
                .find(|r| r.name().to_string().starts_with("app."))
                .unwrap()
        );

        let zone = zones
            .extract_if(.., |c| c.origin.to_string() == "et.top")
            .next()
            .unwrap();
        let zone = ZoneConfigPb::from(&zone);
        let zone = Zone::try_from(&zone)?;
        assert_eq!(zone.origin.to_string(), "et.top.");
        let records = zone.iter_records().collect::<Vec<_>>();
        assert_eq!(records.len(), 1);

        let mut record = Record::update0(zone.origin.clone().into(), 60, RecordType::A);
        record.set_data(RData::A(rdata::a::A("100.100.100.100".parse()?)));
        assert_eq!(record, **records.iter().next().unwrap());

        Ok(())
    }
}

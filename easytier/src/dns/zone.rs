use crate::common::dns::get_default_resolver_config;
use crate::dns::utils::NameServerAddr;
use crate::proto;
use crate::proto::utils::RepeatedMessageModel;
use crate::utils::MapTryInto;
use derivative::Derivative;
use hickory_proto::rr::{LowerName, Record, RecordSet, RrKey, RrsetRecords};
use hickory_proto::serialize::txt::Parser;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::system_conf::read_system_conf;
use hickory_server::authority::{AuthorityObject, ZoneType};
use hickory_server::store::forwarder::{ForwardAuthority, ForwardConfig};
use hickory_server::store::in_memory::InMemoryAuthority;
use itertools::Itertools;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Derivative, Debug, Clone)]
#[derivative(PartialEq)]
pub struct Zone {
    pub(crate) id: Uuid,
    pub(crate) origin: LowerName,
    pub(crate) records: BTreeMap<RrKey, RecordSet>,
    #[derivative(PartialEq(compare_with = "Zone::compare_forward"))]
    pub(crate) forward: Option<ForwardConfig>,
}

impl Zone {
    pub fn system() -> Self {
        let (config, opts) =
            read_system_conf().unwrap_or((get_default_resolver_config(), ResolverOpts::default()));
        let forward = ForwardConfig {
            name_servers: config.name_servers().to_vec().into(),
            options: Some(opts),
        };
        let mut zone = Self::new(".".parse().unwrap());
        zone.forward = Some(forward);
        zone
    }

    pub fn compare_forward(l: &Option<ForwardConfig>, r: &Option<ForwardConfig>) -> bool {
        match (l, r) {
            (Some(l), Some(r)) => l
                .name_servers
                .iter()
                .cloned()
                .map_into::<NameServerAddr>()
                .eq(r.name_servers.iter().cloned().map_into()),
            (None, None) => true,
            _ => false,
        }
    }
}

impl Zone {
    pub fn new(name: LowerName) -> Self {
        Self {
            id: Uuid::new_v4(),
            origin: name,
            records: BTreeMap::new(),
            forward: None,
        }
    }

    pub fn create_memory_authority(&self) -> Option<Arc<dyn AuthorityObject>> {
        (!self.records.is_empty()).then(|| {
            let mut memory =
                InMemoryAuthority::empty(self.origin.clone().into(), ZoneType::External, false);

            memory.records_get_mut().extend(
                self.records
                    .clone()
                    .into_iter()
                    .map(|(k, v)| (k, Arc::new(v))),
            );

            Arc::new(memory) as Arc<dyn AuthorityObject>
        })
    }

    pub fn create_forward_authority(&self) -> Option<Arc<dyn AuthorityObject>> {
        self.forward.as_ref().and_then(|forward| {
            ForwardAuthority::builder_with_config(
                forward.clone(),
                TokioConnectionProvider::default(),
            )
            .build()
            .inspect_err(|e| tracing::error!("failed to create forward authority: {:?}", e))
            .ok()
            .map(|f| Arc::new(f) as Arc<dyn AuthorityObject>)
        })
    }

    // TODO: remove this
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

impl TryFrom<&proto::dns::ZoneData> for Zone {
    type Error = anyhow::Error;

    fn try_from(value: &proto::dns::ZoneData) -> Result<Self, Self::Error> {
        let id = value
            .id
            .ok_or(anyhow::anyhow!("missing id in zone data"))?
            .into();

        let (origin, records) = Parser::new(value.to_string(), None, None)
            .parse()
            .map_err(|e| anyhow::anyhow!("failed to parse zone data: {e}"))?;

        let name_servers = value
            .forwarders
            .iter()
            .map_try_into::<NameServerAddr>()
            .map_ok(Into::into)
            .try_collect::<_, Vec<_>, _>()?
            .into();
        let forward = Some(ForwardConfig {
            name_servers,
            options: None,
        });

        Ok(Self {
            id,
            origin: origin.into(),
            records,
            forward,
        })
    }
}

impl From<Zone> for proto::dns::ZoneData {
    fn from(value: Zone) -> Self {
        let records = value
            .records
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(ToString::to_string)
            .collect();

        let forwarders = value
            .forward
            .into_iter()
            .flat_map(|f| f.name_servers.into_inner().into_iter())
            .map_into::<NameServerAddr>()
            .map_into()
            .collect();

        Self {
            id: Some(value.id.into()),
            origin: value.origin.to_string(),
            records,
            forwarders,
        }
    }
}

pub type ZoneGroup = RepeatedMessageModel<Zone>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::config::DnsConfig;
    use hickory_client::client::{Client, ClientHandle};
    use hickory_proto::rr::{rdata, DNSClass, Name, RData, RecordType};
    use hickory_proto::runtime::TokioRuntimeProvider;
    use hickory_proto::udp::UdpClientStream;
    use hickory_server::authority::Catalog;
    use hickory_server::ServerFuture;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::spawn;
    use tokio::time::timeout;

    const CONFIG: &str = r#"
    listeners = [
        "127.0.0.1:5353",
    ]

    name = "et-test"
    domain = "测试.net"

    ["top".import]
    whitelist = ["*"]
    blacklist = []
    disabled = true
    recursive = true

    [[zone]]
    origin = "et.top"

    records = [
        "@ 60 A 100.100.100.100",
    ]

    [[zone]]
    origin = "google.com"

    ttl = 10

    records = [
        "www 0 IN A 123.123.123.123",
        "app IN CNAME www",
        "ftp IN AAAA ::",
        "mail IN MX 10 app",
    ]

    forwarders = [
        "10.175.160.10",
    ]

    [zone.export]

    "#;

    #[tokio::test]
    async fn test_config() -> anyhow::Result<()> {
        let sep = "=".repeat(80);
        let config = toml::from_str::<DnsConfig>(CONFIG)?;
        assert_eq!(config.domain.to_string(), "测试.net");
        let mut zones = config.zones;
        assert_eq!(zones.len(), 2);

        let zone = zones
            .extract_if(.., |c| c.origin.to_string() == "et.top")
            .next()
            .unwrap();
        let zone = proto::dns::ZoneData::from(zone);
        let zone = Zone::try_from(&zone)?;
        assert_eq!(zone.origin.to_string(), "et.top.");
        let records = zone.iter_records().collect_vec();
        assert_eq!(records.len(), 1);

        let mut record = Record::update0(zone.origin.clone().into(), 60, RecordType::A);
        record.set_data(RData::A(rdata::a::A("100.100.100.100".parse()?)));
        assert_eq!(record, **records.iter().next().unwrap());

        let zone = zones
            .extract_if(.., |z| z.origin.to_string() == "google.com")
            .next()
            .unwrap();
        assert_eq!(zone.policy.export.is_some(), true);
        let zone = proto::dns::ZoneData::from(zone);
        println!("{}", sep);
        println!("{}", zone);
        println!("{}", sep);

        let zone = Zone::try_from(&zone)?;

        for record in zone.iter_records() {
            println!("{}", record);
        }

        assert_eq!(zone.origin.to_string(), "google.com.");

        let records = zone.iter_records().collect_vec();
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

        assert_eq!(zone.forward.as_ref().unwrap().name_servers.len(), 1);

        let mut authorities = Vec::new();
        authorities.extend(zone.create_memory_authority().into_iter());
        authorities.extend(zone.create_forward_authority().into_iter());
        assert_eq!(authorities.len(), 2);
        let mut catalog = Catalog::new();
        catalog.upsert(zone.origin.clone().into(), authorities);

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        println!("listening on {}", addr);

        let mut server = ServerFuture::new(catalog);
        server.register_socket(socket);
        spawn(async move {
            if let Err(e) = server.block_until_done().await {
                eprintln!("server error: {}", e);
            }
        });

        let conn = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
        let (mut client, background) =
            timeout(Duration::from_secs(1), Client::connect(conn)).await??;
        spawn(async move {
            if let Err(e) = background.await {
                eprintln!("client error: {}", e);
            }
        });
        let value = timeout(
            Duration::from_secs(1),
            client.query("maps.google.com".parse()?, DNSClass::IN, RecordType::A),
        )
        .await??;
        value.answers().iter().for_each(|r| println!("{}", r));

        let value = timeout(
            Duration::from_secs(1),
            client.query("www.google.com".parse()?, DNSClass::IN, RecordType::A),
        )
        .await??;
        value.answers().iter().for_each(|r| println!("{}", r));

        let value = timeout(
            Duration::from_secs(1),
            client.query("google.com".parse()?, DNSClass::IN, RecordType::A),
        )
        .await??;
        value.answers().iter().for_each(|r| println!("{}", r));

        Ok(())
    }
}

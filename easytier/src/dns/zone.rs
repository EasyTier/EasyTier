use crate::utils::dns::get_default_resolver_config;
use crate::dns::utils::addr::{NameServerAddr, NameServerAddrGroup};
use crate::dns::utils::zone_handler::{ArcZoneHandler, ChainedZoneHandler};
use crate::proto;
use crate::proto::utils::RepeatedMessageModel;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{LowerName, RecordSet, RrKey};
use hickory_proto::serialize::txt::Parser;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::system_conf::read_system_conf;
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, ZoneType};
use indexmap::IndexMap;
use itertools::chain;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Zone {
    id: Uuid,
    origin: LowerName,
    records: BTreeMap<RrKey, RecordSet>,
    pub forward: Option<ForwardConfig>,
    fallthrough: bool,
}

impl Zone {
    pub fn system() -> Self {
        let (config, opts) =
            read_system_conf().unwrap_or((get_default_resolver_config(), ResolverOpts::default()));
        let forward = ForwardConfig {
            name_servers: config.name_servers().to_vec(),
            options: Some(opts),
        };
        let mut zone = Self::new(".".parse().unwrap());
        zone.forward = Some(forward);
        zone.fallthrough = false;
        zone
    }
}

impl Zone {
    pub fn new(name: LowerName) -> Self {
        Self {
            id: Uuid::new_v4(),
            origin: name,
            records: BTreeMap::new(),
            forward: None,
            fallthrough: true,
        }
    }

    pub fn create_memory_zone_handler(&self) -> Option<ArcZoneHandler> {
        (!self.records.is_empty()).then(|| {
            let mut memory = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
                self.origin.clone().into(),
                ZoneType::External,
                AxfrPolicy::default(),
            );

            memory.records_get_mut().extend(
                self.records
                    .clone()
                    .into_iter()
                    .map(|(k, v)| (k, Arc::new(v))),
            );

            if self.fallthrough {
                Arc::new(ChainedZoneHandler::from(memory)) as _
            } else {
                Arc::new(memory) as _
            }
        })
    }

    pub fn create_forward_zone_handler(&self) -> Option<ArcZoneHandler> {
        self.forward.as_ref().and_then(|forward| {
            ForwardZoneHandler::builder_with_config(
                forward.clone(),
                TokioRuntimeProvider::default(),
            )
            .build()
            .inspect_err(|e| tracing::error!("failed to create forward zone_handler: {:?}", e))
            .ok()
            .map(|f| {
                if self.fallthrough {
                    Arc::new(ChainedZoneHandler::from(f)) as _
                } else {
                    Arc::new(f) as _
                }
            })
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
            .map(TryInto::<NameServerAddr>::try_into)
            .map(|a| a.map(Into::into))
            .collect::<Result<Vec<_>, _>>()?;
        let forward = (!name_servers.is_empty()).then_some(ForwardConfig {
            name_servers,
            options: None,
        });

        Ok(Self {
            id,
            origin: origin.into(),
            records,
            forward,
            fallthrough: value.fallthrough,
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
            .flat_map(|f| f.name_servers.into_iter())
            .map(|ns| (&ns).into())
            .flat_map(NameServerAddrGroup::into_iter)
            .map(Into::into)
            .collect();

        Self {
            id: Some(value.id.into()),
            origin: value.origin.to_string(),
            ttl: 0,
            records,
            forwarders,
            fallthrough: value.fallthrough,
        }
    }
}

pub type ZoneGroup = RepeatedMessageModel<Zone>;

impl ZoneGroup {
    pub fn into_groups(self) -> IndexMap<LowerName, ZoneGroup> {
        self.into_iter().fold(IndexMap::new(), |mut map, zone| {
            map.entry(zone.origin.clone()).or_default().push(zone);
            map
        })
    }

    pub fn iter_zone_handlers(&self) -> impl Iterator<Item = ArcZoneHandler> + use<'_> {
        self.iter().flat_map(|zone| {
            chain(
                zone.create_memory_zone_handler(),
                zone.create_forward_zone_handler(),
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tests::new_request;
    use crate::dns::utils::response::ResponseHandle;
    use crate::proto::common::Url;
    use crate::proto::dns::ZoneData;
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{RData, Record, RecordType, RrsetRecords};
    use hickory_server::Server;
    use hickory_server::zone_handler::Catalog;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;
    use uuid::Uuid;

    impl Zone {
        // Test-only record iterator for precise assertions.
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

    fn zone_data_with_fallthrough(
        origin: &str,
        records: Vec<&str>,
        forwarders: Vec<&str>,
        fallthrough: bool,
    ) -> ZoneData {
        ZoneData {
            id: Some(Uuid::new_v4().into()),
            origin: origin.to_string(),
            ttl: 60,
            records: records.into_iter().map(ToString::to_string).collect(),
            forwarders: forwarders
                .into_iter()
                .map(|f| Url::from_str(f).expect("invalid forwarder"))
                .collect(),
            fallthrough,
        }
    }

    fn zone_data(origin: &str, records: Vec<&str>, forwarders: Vec<&str>) -> ZoneData {
        zone_data_with_fallthrough(origin, records, forwarders, true)
    }

    fn build_catalog(zones: ZoneGroup) -> Catalog {
        zones
            .into_groups()
            .into_iter()
            .fold(Catalog::new(), |mut catalog, (origin, group)| {
                catalog.upsert(origin, group.iter_zone_handlers().collect());
                catalog
            })
    }

    async fn lookup_message(
        catalog: &Catalog,
        name: &str,
        record_type: RecordType,
    ) -> anyhow::Result<(ResponseCode, Option<Message>)> {
        let request = new_request(name, record_type)?;
        let response = ResponseHandle::new(1024);
        let info = catalog.lookup(&request, None, 0, response.clone()).await;
        let message = response
            .into_inner()
            .map(|raw| Message::from_vec(&raw))
            .transpose()?;
        Ok((info.response_code, message))
    }

    fn has_a_answer(message: &Message, expected: Ipv4Addr) -> bool {
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(addr) if *addr == expected))
    }

    async fn start_upstream_server() -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
        let upstream = Zone::try_from(&zone_data(
            "upstream.test",
            vec!["from-forward 60 IN A 203.0.113.9"],
            vec![],
        ))?;

        let mut catalog = Catalog::new();
        catalog.upsert(
            upstream.origin.clone(),
            vec![upstream.create_memory_zone_handler().unwrap()],
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;

        let mut server = Server::new(catalog);
        server.register_socket(socket);
        let handle = tokio::spawn(async move {
            let _ = server.block_until_done().await;
        });

        Ok((addr, handle))
    }

    #[test]
    fn zone_try_from_rejects_missing_id() {
        let data = ZoneData {
            id: None,
            origin: "missing-id.test".to_string(),
            ttl: 60,
            records: vec!["@ IN A 10.0.0.1".to_string()],
            forwarders: vec![],
            fallthrough: false,
        };

        let err = Zone::try_from(&data).expect_err("missing id should fail");
        assert!(err.to_string().contains("missing id"));
    }

    #[test]
    fn zone_try_from_rejects_invalid_record() {
        let data = zone_data("invalid-record.test", vec!["this is not a record"], vec![]);

        let err = Zone::try_from(&data).expect_err("invalid record should fail");
        assert!(err.to_string().contains("failed to parse zone data"));
    }

    #[test]
    fn zone_try_from_rejects_invalid_forwarder_protocol() {
        let data = zone_data("invalid-forwarder.test", vec![], vec!["http://1.1.1.1:53"]);

        let err = Zone::try_from(&data).expect_err("unsupported forwarder should fail");
        assert!(err.to_string().contains("unsupported") || err.to_string().contains("protocol"));
    }

    #[test]
    fn empty_zone_creates_no_zone_handler() -> anyhow::Result<()> {
        let zone = Zone::try_from(&zone_data("empty.test", vec![], vec![]))?;

        assert!(zone.create_memory_zone_handler().is_none());
        assert!(zone.create_forward_zone_handler().is_none());

        Ok(())
    }

    #[test]
    fn zone_roundtrip_preserves_records_and_forwarders() -> anyhow::Result<()> {
        let zone = Zone::try_from(&zone_data(
            "roundtrip.test",
            vec!["www 0 IN A 123.123.123.123", "app IN CNAME www"],
            vec!["udp://1.1.1.1:53", "tcp://8.8.8.8:53"],
        ))?;

        assert_eq!(zone.iter_records().count(), 2);
        assert_eq!(zone.forward.as_ref().unwrap().name_servers.len(), 2);

        let serialized = ZoneData::from(zone.clone());
        assert!(serialized.id.is_some());
        assert_eq!(serialized.origin, "roundtrip.test.");
        assert_eq!(serialized.records.len(), 2);
        assert_eq!(serialized.forwarders.len(), 2);

        let reparsed = Zone::try_from(&serialized)?;
        assert_eq!(reparsed.origin.to_string(), "roundtrip.test.");
        assert_eq!(reparsed.iter_records().count(), 2);
        assert_eq!(reparsed.forward.as_ref().unwrap().name_servers.len(), 2);

        Ok(())
    }

    #[test]
    fn zone_group_into_groups_merges_same_origin() -> anyhow::Result<()> {
        let zones: ZoneGroup = vec![
            Zone::try_from(&zone_data("same.test", vec!["@ IN A 10.0.0.1"], vec![]))?,
            Zone::try_from(&zone_data("other.test", vec!["@ IN A 10.0.0.2"], vec![]))?,
            Zone::try_from(&zone_data("same.test", vec![], vec!["udp://1.1.1.1:53"]))?,
        ]
        .into();

        let groups = zones.into_groups();
        assert_eq!(groups.len(), 2);
        assert_eq!(
            groups
                .get(&LowerName::from_str("same.test.")?)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            groups
                .get(&LowerName::from_str("other.test.")?)
                .unwrap()
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn zone_group_iter_zone_handlers_returns_memory_and_forward() -> anyhow::Result<()> {
        let zones: ZoneGroup = vec![Zone::try_from(&zone_data(
            "zone-handler.test",
            vec!["@ IN A 10.0.0.10"],
            vec!["udp://1.1.1.1:53"],
        ))?]
        .into();

        let zone_handlers = zones.iter_zone_handlers().collect::<Vec<_>>();
        assert_eq!(zone_handlers.len(), 2);

        Ok(())
    }

    #[test]
    fn zone_system_builds_root_forwarder() {
        let zone = Zone::system();
        assert_eq!(zone.origin.to_string(), ".");
        assert!(zone.forward.is_some());
        assert!(zone.create_forward_zone_handler().is_some());
    }

    #[tokio::test]
    async fn catalog_lookup_returns_a_record_from_memory_zone_handler() -> anyhow::Result<()> {
        let zones: ZoneGroup = vec![Zone::try_from(&zone_data(
            "memory.test",
            vec!["@ IN A 10.20.30.40"],
            vec![],
        ))?]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, message) = lookup_message(&catalog, "memory.test.", RecordType::A).await?;
        assert_eq!(rcode, ResponseCode::NoError);
        let message = message.expect("response should exist");
        assert!(has_a_answer(&message, Ipv4Addr::new(10, 20, 30, 40)));

        Ok(())
    }

    #[tokio::test]
    async fn catalog_lookup_returns_refused_when_zone_is_missing() -> anyhow::Result<()> {
        let zones: ZoneGroup = vec![Zone::try_from(&zone_data(
            "present.test",
            vec!["@ IN A 10.20.30.41"],
            vec![],
        ))?]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, _message) = lookup_message(&catalog, "absent.test.", RecordType::A).await?;
        assert_eq!(rcode, ResponseCode::Refused);

        Ok(())
    }

    #[tokio::test]
    async fn catalog_lookup_falls_back_to_later_zone_handler_with_same_origin() -> anyhow::Result<()>
    {
        let zones: ZoneGroup = vec![
            // First matching zone exists but does not contain the queried name.
            Zone::try_from(&zone_data(
                "fallback.test",
                vec!["first IN A 10.20.30.1"],
                vec![],
            ))?,
            // Second matching zone should be queried as fallback and answer.
            Zone::try_from(&zone_data(
                "fallback.test",
                vec!["target IN A 10.20.30.2"],
                vec![],
            ))?,
        ]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, message) =
            lookup_message(&catalog, "target.fallback.test.", RecordType::A).await?;
        assert_eq!(rcode, ResponseCode::NoError);
        assert!(has_a_answer(
            &message.expect("response should exist"),
            Ipv4Addr::new(10, 20, 30, 2)
        ));

        Ok(())
    }

    #[tokio::test]
    async fn catalog_lookup_does_not_fall_back_when_fallthrough_disabled() -> anyhow::Result<()> {
        let zones: ZoneGroup = vec![
            Zone::try_from(&zone_data_with_fallthrough(
                "fallback-disabled.test",
                vec!["first IN A 10.20.31.1"],
                vec![],
                false,
            ))?,
            Zone::try_from(&zone_data_with_fallthrough(
                "fallback-disabled.test",
                vec!["target IN A 10.20.31.2"],
                vec![],
                false,
            ))?,
        ]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, message) =
            lookup_message(&catalog, "target.fallback-disabled.test.", RecordType::A).await?;

        assert_ne!(rcode, ResponseCode::NoError);
        if let Some(message) = message.as_ref() {
            assert!(!has_a_answer(message, Ipv4Addr::new(10, 20, 31, 2)));
        }

        Ok(())
    }

    #[tokio::test]
    async fn catalog_forward_only_zone_queries_upstream() -> anyhow::Result<()> {
        let (upstream_addr, upstream_handle) = start_upstream_server().await?;

        let forward_zone = Zone::try_from(&zone_data(
            "upstream.test",
            vec![],
            vec![&format!("udp://{}", upstream_addr)],
        ))?;
        let catalog = build_catalog(vec![forward_zone].into());

        let (rcode, message) =
            lookup_message(&catalog, "from-forward.upstream.test.", RecordType::A).await?;
        assert_eq!(rcode, ResponseCode::NoError);
        assert!(has_a_answer(
            &message.expect("response should exist"),
            Ipv4Addr::new(203, 0, 113, 9)
        ));

        upstream_handle.abort();
        let _ = upstream_handle.await;

        Ok(())
    }
}

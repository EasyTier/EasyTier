use crate::dns::config::zone::Fallthrough;
use crate::dns::utils::addr::{NameServerAddr, NameServerAddrGroup};
use crate::dns::utils::zone_handler::{ArcZoneHandler, ChainedZoneHandler};
use crate::proto::dns::ZoneData;
use crate::proto::utils::RepeatedMessageModel;
use crate::utils::dns::resolver_conf;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{LowerName, RecordSet, RrKey};
use hickory_proto::serialize::txt::Parser;
use hickory_server::store::forwarder::{ForwardConfig, ForwardZoneHandler};
use hickory_server::store::in_memory::InMemoryZoneHandler;
use hickory_server::zone_handler::{AxfrPolicy, ZoneType};
use indexmap::IndexMap;
use itertools::chain;
use maplit::hashset;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

#[derive(Debug, Clone, Default)]
pub struct Zone {
    origin: LowerName,
    records: BTreeMap<RrKey, RecordSet>,
    pub forward: Option<ForwardConfig>,
    fallthrough: HashSet<Fallthrough>,
}

impl Zone {
    pub fn system() -> Self {
        let (config, opts) = resolver_conf();
        let forward = ForwardConfig {
            name_servers: config.name_servers().to_vec(),
            options: Some(opts),
        };
        Self {
            origin: ".".parse().unwrap(),
            forward: Some(forward),
            fallthrough: hashset! {},
            ..Default::default()
        }
    }
}

impl Zone {
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

            Arc::new(ChainedZoneHandler::new(memory, self.fallthrough.clone())) as _
        })
    }

    pub fn create_forward_zone_handler(&self) -> Option<ArcZoneHandler> {
        self.forward.as_ref().and_then(|forward| {
            ForwardZoneHandler::builder_with_config(
                forward.clone(),
                TokioRuntimeProvider::default(),
            )
            .build()
            .inspect_err(|error| tracing::error!(?error, "failed to create forward zone_handler"))
            .ok()
            .map(|handler| {
                Arc::new(ChainedZoneHandler::new(handler, self.fallthrough.clone())) as _
            })
        })
    }
}

impl TryFrom<&ZoneData> for Zone {
    type Error = anyhow::Error;

    fn try_from(value: &ZoneData) -> Result<Self, Self::Error> {
        let (origin, records) = Parser::new(&value.content, None, None)
            .parse()
            .map_err(|e| anyhow::anyhow!("failed to parse zone data: {e}"))?;

        let name_servers = value
            .forwarders
            .iter()
            .map(NameServerAddr::try_from)
            .map(|a| a.map(Into::into))
            .collect::<Result<Vec<_>, _>>()?;
        let forward = (!name_servers.is_empty()).then_some(ForwardConfig {
            name_servers,
            options: None,
        });

        let fallthrough = value.fallthrough.iter().copied().map(Into::into).collect();

        Ok(Self {
            origin: origin.into(),
            records,
            forward,
            fallthrough,
        })
    }
}

impl From<Zone> for ZoneData {
    fn from(value: Zone) -> Self {
        let records = value
            .records
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
            .map(ToString::to_string);

        let forwarders = value
            .forward
            .into_iter()
            .flat_map(|f| f.name_servers.into_iter())
            .map(|ns| (&ns).into())
            .flat_map(NameServerAddrGroup::into_iter)
            .map(Into::into);

        Self::new(&value.origin, 0, records, forwarders, value.fallthrough)
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
    use maplit::hashset;
    use std::collections::HashSet;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::str::FromStr;
    use tokio::net::UdpSocket;
    use tokio::task::JoinHandle;

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
        fallthrough: HashSet<Fallthrough>,
    ) -> ZoneData {
        ZoneData::new(
            &origin.parse().unwrap(),
            60,
            records,
            forwarders
                .into_iter()
                .map(|url| Url::from_str(url).unwrap()),
            fallthrough,
        )
    }

    fn zone_data(origin: &str, records: Vec<&str>, forwarders: Vec<&str>) -> ZoneData {
        zone_data_with_fallthrough(origin, records, forwarders, hashset! {Fallthrough::Any})
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

    fn has_aaaa_answer(message: &Message, expected: Ipv6Addr) -> bool {
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::AAAA(addr) if *addr == expected))
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
    async fn catalog_lookup_forwards_on_nameexists() -> anyhow::Result<()> {
        let upstream = Zone::try_from(&zone_data(
            "forward-aaaa.test",
            vec!["host 60 IN AAAA 2001:db8::1"],
            vec![],
        ))?;

        let mut upstream_catalog = Catalog::new();
        upstream_catalog.upsert(
            upstream.origin.clone(),
            vec![upstream.create_memory_zone_handler().unwrap()],
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream_addr = socket.local_addr()?;

        let mut server = Server::new(upstream_catalog);
        server.register_socket(socket);
        let upstream_handle = tokio::spawn(async move {
            let _ = server.block_until_done().await;
        });

        let zones: ZoneGroup = vec![Zone::try_from(&zone_data(
            "forward-aaaa.test",
            vec!["host IN A 10.20.30.40"],
            vec![&format!("udp://{}", upstream_addr)],
        ))?]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, message) =
            lookup_message(&catalog, "host.forward-aaaa.test.", RecordType::AAAA).await?;
        assert_eq!(rcode, ResponseCode::NoError);

        let message = message.expect("response should exist");
        assert!(has_aaaa_answer(&message, "2001:db8::1".parse()?));

        upstream_handle.abort();
        let _ = upstream_handle.await;

        Ok(())
    }

    #[tokio::test]
    async fn catalog_lookup_forwards_on_nxdomain() -> anyhow::Result<()> {
        let upstream = Zone::try_from(&zone_data(
            "forward-nxdomain.test",
            vec!["missing 60 IN A 203.0.113.55"],
            vec![],
        ))?;

        let mut upstream_catalog = Catalog::new();
        upstream_catalog.upsert(
            upstream.origin.clone(),
            vec![upstream.create_memory_zone_handler().unwrap()],
        );

        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let upstream_addr = socket.local_addr()?;

        let mut server = Server::new(upstream_catalog);
        server.register_socket(socket);
        let upstream_handle = tokio::spawn(async move {
            let _ = server.block_until_done().await;
        });

        let zones: ZoneGroup = vec![Zone::try_from(&zone_data(
            "forward-nxdomain.test",
            vec!["present IN A 10.20.30.41"],
            vec![&format!("udp://{}", upstream_addr)],
        ))?]
        .into();
        let catalog = build_catalog(zones);

        let (rcode, message) =
            lookup_message(&catalog, "missing.forward-nxdomain.test.", RecordType::A).await?;
        assert_eq!(rcode, ResponseCode::NoError);

        let message = message.expect("response should exist");
        assert!(has_a_answer(&message, Ipv4Addr::new(203, 0, 113, 55)));

        upstream_handle.abort();
        let _ = upstream_handle.await;

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
                hashset! {},
            ))?,
            Zone::try_from(&zone_data_with_fallthrough(
                "fallback-disabled.test",
                vec!["target IN A 10.20.31.2"],
                vec![],
                hashset! {},
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

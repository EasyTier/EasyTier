use crate::dns::utils::addr::NameServerAddr;
use crate::dns::utils::dirty::DirtyFlag;
use crate::dns::zone::{Zone, ZoneGroup};
use crate::proto::dns::DnsNodeMgrRpc;
use crate::proto::dns::{DnsSnapshot, HeartbeatRequest, HeartbeatResponse};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::{DeterministicDigest, MapTryInto};
use anyhow::Error;
use hickory_server::authority::Catalog;
use itertools::Itertools;
use moka::future::Cache;
use std::collections::HashSet;
use std::time::Duration;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
struct DnsNodeInfo {
    digest: Vec<u8>,
    zones: ZoneGroup,
    addresses: HashSet<NameServerAddr>,
    listeners: HashSet<NameServerAddr>,
}

impl TryFrom<&DnsSnapshot> for DnsNodeInfo {
    type Error = Error;

    fn try_from(value: &DnsSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            digest: value.digest(),
            zones: (&value.zones).try_into()?,
            addresses: value.addresses.iter().map_try_into().try_collect()?,
            listeners: value.listeners.iter().map_try_into().try_collect()?,
        })
    }
}

const DNS_NODE_TTI: Duration = Duration::from_secs(5);

#[derive(Debug, Default)]
pub struct DnsNodeMgrDirtyFlags {
    pub catalog: DirtyFlag,
    pub addresses: DirtyFlag,
    pub listeners: DirtyFlag,
}

#[derive(Debug)]
pub struct DnsNodeMgr {
    nodes: Cache<Uuid, DnsNodeInfo>,
    pub dirty: DnsNodeMgrDirtyFlags,
}

impl DnsNodeMgr {
    pub fn new() -> Self {
        Self {
            nodes: Cache::builder().time_to_idle(DNS_NODE_TTI).build(),
            dirty: Default::default(),
        }
    }

    pub fn catalog(&self) -> Catalog {
        let groups = self.collect_zones().into_groups();

        tracing::trace!("building catalog with zones: {:?}", groups);

        groups
            .into_iter()
            .fold(Catalog::new(), |mut catalog, (origin, zones)| {
                catalog.upsert(origin.clone(), zones.iter_authorities().collect());
                catalog
            })
    }

    pub fn collect_zones(&self) -> ZoneGroup {
        let mut zones = Vec::new();
        let mut local = HashSet::new();

        for (_, info) in self.nodes.iter() {
            zones.extend(info.zones);
            local.extend(info.addresses);
            local.extend(info.listeners);
        }

        zones.push(Zone::system());

        for forward in zones.iter_mut().flat_map(|z| &mut z.forward) {
            forward
                .name_servers
                .retain(|ns| !local.contains(&ns.into()));
        }

        zones.into()
    }

    pub fn iter_addresses(&self) -> impl Iterator<Item = NameServerAddr> + use<'_> {
        self.nodes
            .iter()
            .flat_map(|(_, info)| info.addresses)
            .unique()
    }

    pub fn iter_listeners(&self) -> impl Iterator<Item = NameServerAddr> + use<'_> {
        self.nodes
            .iter()
            .flat_map(|(_, info)| info.listeners)
            .unique()
    }
}

#[async_trait::async_trait]
impl DnsNodeMgrRpc for DnsNodeMgr {
    type Controller = BaseController;

    #[instrument(
        level = "trace",
        skip_all,
        fields(from = ?input.id, snapshot = ?input.snapshot),
        err
    )]
    async fn heartbeat(
        &self,
        _: BaseController,
        input: HeartbeatRequest,
    ) -> rpc_types::error::Result<HeartbeatResponse> {
        let id = input
            .id
            .ok_or(anyhow::anyhow!(
                "missing id in heartbeat request: {:?}",
                input
            ))?
            .into();

        let resync = if let Some(snapshot) = input.snapshot.as_ref() {
            let new = DnsNodeInfo::try_from(snapshot)?;
            let old = self.nodes.get(&id).await.unwrap_or_default();
            if new.digest != old.digest {
                self.dirty.catalog.mark();
                if new.addresses != old.addresses {
                    self.dirty.addresses.mark();
                }
                if new.listeners != old.listeners {
                    self.dirty.listeners.mark();
                }

                self.nodes.insert(id, new).await;
            }
            false
        } else {
            self.nodes
                .get(&id)
                .await
                .is_none_or(|info| info.digest != input.digest)
        };

        Ok(HeartbeatResponse { resync })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::log;
    use crate::dns::utils::response::ResponseHandle;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{rdata, Name, RData, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
    use hickory_proto::xfer::Protocol;
    use hickory_server::authority::MessageRequest;
    use hickory_server::server::Request;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn test_force_insert_node_info_then_catalog_lookup() -> anyhow::Result<()> {
        log::tests::init();

        let mgr = DnsNodeMgr::new();

        let zone = Zone::try_from(&crate::proto::dns::ZoneData {
            id: Some(Uuid::new_v4().into()),
            origin: "catalog.test".to_string(),
            ttl: 60,
            records: vec!["@ IN A 10.20.30.40".to_string()],
            forwarders: vec![],
        })?;

        mgr.nodes
            .insert(
                Uuid::new_v4(),
                DnsNodeInfo {
                    digest: vec![],
                    zones: vec![zone].into(),
                    addresses: Default::default(),
                    listeners: Default::default(),
                },
            )
            .await;

        let mut query = Message::new();
        query.set_id(0x1234);
        query.set_message_type(MessageType::Query);
        query.set_op_code(OpCode::Query);
        query.set_recursion_desired(true);
        query.add_query(Query::query(
            Name::from_ascii("catalog.test.")?,
            RecordType::A,
        ));

        let mut request = Vec::new();
        let mut encoder = BinEncoder::new(&mut request);
        query.emit(&mut encoder)?;

        let request = Request::new(
            MessageRequest::from_bytes(&request)?,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0).into(),
            Protocol::Udp,
        );

        let response = ResponseHandle::new(512);
        let info = mgr.catalog().lookup(&request, None, response.clone()).await;

        assert_eq!(info.response_code(), ResponseCode::NoError);

        let response = response.into_inner().unwrap();
        let message = Message::from_vec(&response)?;
        assert!(message.answers().iter().any(|record| {
            matches!(
                record.data(),
                RData::A(addr) if *addr == rdata::a::A(Ipv4Addr::new(10, 20, 30, 40))
            )
        }));

        Ok(())
    }
}

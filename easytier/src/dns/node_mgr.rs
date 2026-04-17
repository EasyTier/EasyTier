use crate::dns::config::DNS_NODE_TTI;
use crate::dns::utils::addr::NameServerAddr;
use crate::utils::dirty::DirtyFlag;
use crate::dns::zone::{Zone, ZoneGroup};
use crate::proto::dns::DnsNodeMgrRpc;
use crate::proto::dns::{DnsSnapshot, HeartbeatRequest, HeartbeatResponse};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::proto::utils::TransientDigest;
use anyhow::Error;
use hickory_server::zone_handler::Catalog;
use itertools::Itertools;
use moka::future::Cache;
use std::collections::HashSet;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
struct DnsNodeInfo {
    digest: [u8; 32],
    zones: ZoneGroup,
    addresses: HashSet<NameServerAddr>,
    listeners: HashSet<NameServerAddr>,
}

impl TryFrom<&DnsSnapshot> for DnsNodeInfo {
    type Error = Error;

    fn try_from(value: &DnsSnapshot) -> Result<Self, Self::Error> {
        Ok(Self {
            digest: value.digest(),
            zones: value.zones.as_slice().try_into()?,
            addresses: value
                .addresses
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
            listeners: value
                .listeners
                .iter()
                .map(TryInto::try_into)
                .collect::<Result<_, _>>()?,
        })
    }
}

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
                catalog.upsert(origin.clone(), zones.iter_zone_handlers().collect());
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
                .is_none_or(|info| input.digest != info.digest)
        };

        Ok(HeartbeatResponse { resync })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tests::{
        dns_snapshot_with as snapshot_with, heartbeat_with_snapshot, new_request,
        zone_data_a_with_forwarders as valid_zone_data,
    };
    use crate::dns::utils::response::ResponseHandle;
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::{RData, RecordType};
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    fn heartbeat_digest_only(id: Uuid, digest: Vec<u8>) -> HeartbeatRequest {
        HeartbeatRequest {
            id: Some(id.into()),
            digest,
            snapshot: None,
        }
    }

    fn reset_all_dirty(mgr: &DnsNodeMgr) {
        let _ = mgr.dirty.catalog.reset();
        let _ = mgr.dirty.addresses.reset();
        let _ = mgr.dirty.listeners.reset();
    }

    async fn send_heartbeat(mgr: &DnsNodeMgr, input: HeartbeatRequest) -> HeartbeatResponse {
        DnsNodeMgrRpc::heartbeat(mgr, BaseController::default(), input)
            .await
            .expect("heartbeat should succeed")
    }

    fn ns(s: &str) -> NameServerAddr {
        s.parse().expect("invalid nameserver")
    }

    async fn lookup_a_record(mgr: &DnsNodeMgr, name: &str) -> anyhow::Result<Message> {
        let request = new_request(name, RecordType::A)?;
        let response = ResponseHandle::new(512);
        let info = mgr
            .catalog()
            .lookup(&request, None, 0, response.clone())
            .await;

        assert_eq!(info.response_code, ResponseCode::NoError);

        let response = response.into_inner().expect("response should exist");
        Message::from_vec(&response).map_err(Into::into)
    }

    #[tokio::test]
    async fn catalog_lookup_returns_record_after_snapshot_heartbeat() -> anyhow::Result<()> {
        let mgr = DnsNodeMgr::new();
        let id = Uuid::new_v4();
        let snapshot = snapshot_with(
            vec![valid_zone_data("catalog.test", "10.20.30.40", vec![])],
            vec![],
            vec![],
        );

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, snapshot)).await;

        let message = lookup_a_record(&mgr, "catalog.test.").await?;
        assert!(message.answers.iter().any(|record| {
            matches!(
                record.data,
                RData::A(addr) if *addr == Ipv4Addr::new(10, 20, 30, 40)
            )
        }));

        Ok(())
    }

    #[tokio::test]
    async fn catalog_lookup_aggregates_records_from_multiple_nodes() -> anyhow::Result<()> {
        let mgr = DnsNodeMgr::new();

        let snap_a = snapshot_with(
            vec![valid_zone_data("node-a.test", "10.11.12.13", vec![])],
            vec!["udp://10.0.1.1:53"],
            vec![],
        );
        let snap_b = snapshot_with(
            vec![valid_zone_data("node-b.test", "10.21.22.23", vec![])],
            vec!["udp://10.0.2.1:53"],
            vec![],
        );

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(Uuid::new_v4(), snap_a)).await;
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(Uuid::new_v4(), snap_b)).await;

        let message_a = lookup_a_record(&mgr, "node-a.test.").await?;
        let message_b = lookup_a_record(&mgr, "node-b.test.").await?;

        assert!(message_a.answers.iter().any(|record| {
            matches!(
                record.data,
                RData::A(addr) if *addr == Ipv4Addr::new(10, 11, 12, 13)
            )
        }));
        assert!(message_b.answers.iter().any(|record| {
            matches!(
                record.data,
                RData::A(addr) if *addr == Ipv4Addr::new(10, 21, 22, 23)
            )
        }));

        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_digest_only_resync_behavior() {
        let mgr = DnsNodeMgr::new();
        let id = Uuid::new_v4();

        let first = send_heartbeat(&mgr, heartbeat_digest_only(id, vec![1, 2, 3])).await;
        assert!(first.resync);

        let snapshot = snapshot_with(
            vec![valid_zone_data("resync.test", "10.0.0.10", vec![])],
            vec!["udp://10.0.0.1:53"],
            vec!["udp://10.0.0.2:53"],
        );
        let digest = snapshot.digest();
        let full = send_heartbeat(&mgr, heartbeat_with_snapshot(id, snapshot)).await;
        assert!(!full.resync);

        let same = send_heartbeat(&mgr, heartbeat_digest_only(id, digest.into())).await;
        assert!(!same.resync);

        let different = send_heartbeat(&mgr, heartbeat_digest_only(id, vec![9, 9, 9])).await;
        assert!(different.resync);
    }

    #[tokio::test]
    async fn heartbeat_with_snapshot_marks_dirty_flags_by_field_changes() {
        let mgr = DnsNodeMgr::new();
        let id = Uuid::new_v4();

        reset_all_dirty(&mgr);

        let first = snapshot_with(
            vec![valid_zone_data("dirty.test", "10.0.0.1", vec![])],
            vec!["udp://10.10.10.1:53"],
            vec!["udp://10.10.10.2:53"],
        );
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, first)).await;
        assert!(mgr.dirty.catalog.peek());
        assert!(mgr.dirty.addresses.peek());
        assert!(mgr.dirty.listeners.peek());

        reset_all_dirty(&mgr);

        let record_changed = snapshot_with(
            vec![valid_zone_data("dirty.test", "10.0.0.2", vec![])],
            vec!["udp://10.10.10.1:53"],
            vec!["udp://10.10.10.2:53"],
        );
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, record_changed)).await;
        assert!(mgr.dirty.catalog.peek());
        assert!(!mgr.dirty.addresses.peek());
        assert!(!mgr.dirty.listeners.peek());

        reset_all_dirty(&mgr);

        let addr_listener_changed = snapshot_with(
            vec![valid_zone_data("dirty.test", "10.0.0.2", vec![])],
            vec!["udp://10.10.10.10:53"],
            vec!["udp://10.10.10.20:53"],
        );
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, addr_listener_changed)).await;
        assert!(mgr.dirty.catalog.peek());
        assert!(mgr.dirty.addresses.peek());
        assert!(mgr.dirty.listeners.peek());
    }

    #[tokio::test]
    async fn heartbeat_with_same_snapshot_digest_is_noop_for_dirty() {
        let mgr = DnsNodeMgr::new();
        let id = Uuid::new_v4();

        let snapshot = snapshot_with(
            vec![valid_zone_data("stable.test", "10.30.40.50", vec![])],
            vec!["udp://10.3.0.1:53"],
            vec!["udp://10.3.0.2:53"],
        );
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, snapshot.clone())).await;

        reset_all_dirty(&mgr);

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, snapshot)).await;
        assert!(!mgr.dirty.catalog.peek());
        assert!(!mgr.dirty.addresses.peek());
        assert!(!mgr.dirty.listeners.peek());
    }

    #[tokio::test]
    async fn heartbeat_missing_id_returns_error() {
        let mgr = DnsNodeMgr::new();
        let err =
            DnsNodeMgrRpc::heartbeat(&mgr, BaseController::default(), HeartbeatRequest::default())
                .await
                .expect_err("missing id should error");
        assert!(err.to_string().contains("missing id"));
    }

    #[tokio::test]
    async fn iter_addresses_and_listeners_deduplicate_across_multiple_nodes() -> anyhow::Result<()>
    {
        let mgr = DnsNodeMgr::new();
        let zone_a = Zone::try_from(&valid_zone_data("iter-a.test", "10.1.1.1", vec![]))?;
        let zone_b = Zone::try_from(&valid_zone_data("iter-b.test", "10.1.1.2", vec![]))?;

        mgr.nodes
            .insert(
                Uuid::new_v4(),
                DnsNodeInfo {
                    digest: [1; 32],
                    zones: vec![zone_a].into(),
                    addresses: [ns("udp://10.100.0.1:53"), ns("udp://10.100.0.2:53")]
                        .into_iter()
                        .collect(),
                    listeners: [ns("udp://10.200.0.1:53")].into_iter().collect(),
                },
            )
            .await;
        mgr.nodes
            .insert(
                Uuid::new_v4(),
                DnsNodeInfo {
                    digest: [2; 32],
                    zones: vec![zone_b].into(),
                    addresses: [ns("udp://10.100.0.2:53"), ns("udp://10.100.0.3:53")]
                        .into_iter()
                        .collect(),
                    listeners: [ns("udp://10.200.0.1:53"), ns("udp://10.200.0.2:53")]
                        .into_iter()
                        .collect(),
                },
            )
            .await;

        let addresses: HashSet<_> = mgr.iter_addresses().collect();
        let listeners: HashSet<_> = mgr.iter_listeners().collect();

        assert_eq!(addresses.len(), 3);
        assert!(addresses.contains(&ns("udp://10.100.0.1:53")));
        assert!(addresses.contains(&ns("udp://10.100.0.2:53")));
        assert!(addresses.contains(&ns("udp://10.100.0.3:53")));

        assert_eq!(listeners.len(), 2);
        assert!(listeners.contains(&ns("udp://10.200.0.1:53")));
        assert!(listeners.contains(&ns("udp://10.200.0.2:53")));

        Ok(())
    }

    #[tokio::test]
    async fn collect_zones_filters_out_local_forwarders() -> anyhow::Result<()> {
        let mgr = DnsNodeMgr::new();
        let zone = Zone::try_from(&valid_zone_data(
            "filter-loop.test",
            "10.2.3.4",
            vec![
                "udp://10.0.0.10:53",
                "tcp://10.0.0.11:53",
                "udp://1.1.1.1:53",
            ],
        ))?;

        mgr.nodes
            .insert(
                Uuid::new_v4(),
                DnsNodeInfo {
                    digest: [1; 32],
                    zones: vec![zone].into(),
                    addresses: [ns("udp://10.0.0.10:53")].into_iter().collect(),
                    listeners: [ns("tcp://10.0.0.11:53")].into_iter().collect(),
                },
            )
            .await;

        let zones: Vec<_> = mgr.collect_zones().into_iter().map(Into::into).collect();
        let loop_zone = zones
            .into_iter()
            .find(|z: &crate::proto::dns::ZoneData| {
                z.origin.trim_end_matches('.') == "filter-loop.test"
            })
            .expect("test zone should exist");

        let forwarders: HashSet<NameServerAddr> = loop_zone
            .forwarders
            .iter()
            .map(|u| NameServerAddr::try_from(u).expect("forwarder should be valid"))
            .collect();

        assert_eq!(forwarders.len(), 1);
        assert!(forwarders.contains(&ns("udp://1.1.1.1:53")));

        Ok(())
    }

    #[tokio::test]
    async fn collect_zones_filters_cross_node_local_forwarders() -> anyhow::Result<()> {
        let mgr = DnsNodeMgr::new();

        let node_a = snapshot_with(
            vec![valid_zone_data(
                "cross-node-filter.test",
                "10.8.8.8",
                vec![
                    "udp://10.50.0.1:53",
                    "udp://10.50.0.2:53",
                    "udp://8.8.8.8:53",
                ],
            )],
            vec!["udp://10.50.0.1:53"],
            vec![],
        );
        let node_b = snapshot_with(
            vec![valid_zone_data(
                "cross-node-helper.test",
                "10.9.9.9",
                vec![],
            )],
            vec![],
            vec!["udp://10.50.0.2:53"],
        );

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(Uuid::new_v4(), node_a)).await;
        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(Uuid::new_v4(), node_b)).await;

        let zones: Vec<_> = mgr.collect_zones().into_iter().map(Into::into).collect();
        let zone = zones
            .into_iter()
            .find(|z: &crate::proto::dns::ZoneData| {
                z.origin.trim_end_matches('.') == "cross-node-filter.test"
            })
            .expect("test zone should exist");

        let forwarders: HashSet<NameServerAddr> = zone
            .forwarders
            .iter()
            .map(|u| NameServerAddr::try_from(u).expect("forwarder should be valid"))
            .collect();

        assert_eq!(forwarders.len(), 1);
        assert!(forwarders.contains(&ns("udp://8.8.8.8:53")));

        Ok(())
    }

    #[tokio::test]
    async fn heartbeat_digest_resync_is_node_scoped() {
        let mgr = DnsNodeMgr::new();
        let node_a = Uuid::new_v4();
        let node_b = Uuid::new_v4();

        let snap_a = snapshot_with(
            vec![valid_zone_data("scope-a.test", "10.60.0.1", vec![])],
            vec!["udp://10.60.0.2:53"],
            vec![],
        );
        let digest_a = snap_a.digest();

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(node_a, snap_a)).await;

        let a_same = send_heartbeat(&mgr, heartbeat_digest_only(node_a, digest_a.into())).await;
        assert!(!a_same.resync);

        let b_unknown = send_heartbeat(&mgr, heartbeat_digest_only(node_b, vec![1, 2, 3])).await;
        assert!(b_unknown.resync);
    }

    #[tokio::test]
    async fn heartbeat_resync_after_node_idle_ttl_expiry() {
        let mgr = DnsNodeMgr::new();
        let id = Uuid::new_v4();
        let snapshot = snapshot_with(
            vec![valid_zone_data("ttl.test", "10.9.9.9", vec![])],
            vec!["udp://10.9.0.1:53"],
            vec![],
        );
        let digest = snapshot.digest();

        let _ = send_heartbeat(&mgr, heartbeat_with_snapshot(id, snapshot)).await;
        let before_expiry = send_heartbeat(&mgr, heartbeat_digest_only(id, digest.to_vec())).await;
        assert!(!before_expiry.resync);

        sleep(DNS_NODE_TTI + Duration::from_millis(300)).await;

        let after_expiry = send_heartbeat(&mgr, heartbeat_digest_only(id, digest.into())).await;
        assert!(after_expiry.resync);
    }
}

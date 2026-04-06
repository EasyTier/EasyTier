use crate::common::global_ctx::ArcGlobalCtx;
use crate::common::PeerId;
use crate::dns::config::{DnsExportConfig, DnsGlobalCtxExt};
use crate::dns::utils::dirty::DirtyFlag;
use crate::dns::zone::ZoneGroup;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::peers::route_trait::Route;
use crate::proto::dns::{
    DnsPeerMgrRpc, DnsPeerMgrRpcClientFactory, DnsPeerMgrRpcServer, DnsSnapshot,
    GetExportConfigRequest, GetExportConfigResponse, ZoneData,
};
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::DeterministicDigest;
use anyhow::Context;
use itertools::Itertools;
use moka::future::Cache;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tracing::instrument;

#[derive(Debug, Clone)]
struct DnsPeerInfo {
    digest: Vec<u8>,
    zones: Vec<ZoneData>,
}

impl TryFrom<DnsExportConfig> for DnsPeerInfo {
    type Error = anyhow::Error;

    fn try_from(value: DnsExportConfig) -> Result<Self, Self::Error> {
        let _ = ZoneGroup::try_from(&value.zones)?;
        Ok(Self {
            digest: value.digest(),
            zones: value.zones,
        })
    }
}

const DNS_PEER_TTI: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub struct DnsPeerMgrInner {
    peers: Cache<PeerId, DnsPeerInfo>,
    pub dirty: DirtyFlag,

    peer_mgr: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,
}

impl DnsPeerMgrInner {
    pub fn snapshot(&self) -> DnsSnapshot {
        let global_ctx = &self.global_ctx;

        let zones = global_ctx
            .dns_iter_zones()
            .map_into()
            .chain(
                self.peers
                    .iter()
                    .flat_map(|(_, info)| info.zones.into_iter()),
            )
            .collect();

        let config = global_ctx.config.get_dns();
        DnsSnapshot {
            zones,
            addresses: config.addresses.into(),
            listeners: config.listeners.into(),
        }
    }

    pub async fn refresh(&self, peer_id: PeerId) {
        if peer_id == self.peer_mgr.my_peer_id() {
            self.dirty.mark();
            return;
        }

        let Some(route) = self.peer_mgr.get_route().get_peer_info(peer_id).await else {
            return;
        };
        if self
            .peers
            .get(&peer_id)
            .await
            .is_some_and(|info| info.digest == route.dns)
        {
            return;
        }

        let mut invalidate = route.dns.is_empty();

        if !invalidate {
            match self.fetch(peer_id).await {
                Ok(info) => self.peers.insert(peer_id, info).await,
                Err(error) => {
                    tracing::warn!(%peer_id, ?error, "failed to fetch dns export config from peer");
                    invalidate = true;
                }
            };
        }

        if invalidate {
            self.peers.invalidate(&peer_id).await;
        }

        self.dirty.mark();
    }

    #[instrument(skip(self), level = "trace", ret)]
    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<DnsPeerInfo> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DnsPeerMgrRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                peer_id,
                self.global_ctx.get_network_name(),
            )
            .get_export_config(BaseController::default(), GetExportConfigRequest {})
            .await
            .context("rpc call failed")?
            .try_into()
    }
}

#[async_trait::async_trait]
impl DnsPeerMgrRpc for DnsPeerMgrInner {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: Self::Controller,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.global_ctx.dns_export_config())
    }
}

#[derive(Debug)]
pub struct DnsPeerMgr(Arc<DnsPeerMgrInner>);

impl DnsPeerMgr {
    pub fn new(peer_mgr: Arc<PeerManager>, global_ctx: ArcGlobalCtx) -> Self {
        Self(Arc::new(DnsPeerMgrInner {
            peers: Cache::builder().time_to_idle(DNS_PEER_TTI).build(),
            dirty: Default::default(),
            peer_mgr,
            global_ctx,
        }))
    }

    pub fn register(&self) {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsPeerMgrRpcServer::new_arc(self.0.clone()),
                &self.global_ctx.get_network_name(),
            );
    }

    pub fn unregister(&self) -> Option<()> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                DnsPeerMgrRpcServer::new_arc(self.0.clone()),
                &self.global_ctx.get_network_name(),
            )
    }
}

impl Deref for DnsPeerMgr {
    type Target = DnsPeerMgrInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for DnsPeerMgr {
    fn drop(&mut self) {
        self.unregister();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::dns::config::zone::ZoneConfig;
    use crate::peers::create_packet_recv_chan;
    use crate::peers::peer_manager::RouteAlgoType;
    use crate::peers::tests::{connect_peer_manager, wait_route_appear};
    use crate::proto::dns::{GetExportConfigRequest, ZoneData};
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use tokio::time::{sleep, Duration};
    use uuid::Uuid;

    fn valid_zone_data(origin: &str, record: &str) -> ZoneData {
        ZoneData {
            id: Some(Uuid::new_v4().into()),
            origin: origin.to_string(),
            ttl: 60,
            records: vec![format!("@ IN A {record}")],
            forwarders: vec![],
        }
    }

    async fn create_peer_manager_with_zone(
        host: &str,
        origin: &str,
        record_ip: Ipv4Addr,
    ) -> Arc<PeerManager> {
        let ctx = get_mock_global_ctx();
        let mut dns = ctx.config.get_dns();
        dns.set_name(host);
        dns.zones.push(
            ZoneConfig::dedicated(
                Some(Uuid::new_v4()),
                origin.parse().expect("invalid zone origin"),
                Some(record_ip),
                vec![],
            )
            .expect("failed to build test zone"),
        );
        ctx.config.set_dns(Some(dns));

        let (s, _r) = create_packet_recv_chan();
        let peer_mgr = Arc::new(PeerManager::new(RouteAlgoType::Ospf, ctx, s));
        peer_mgr.run().await.unwrap();
        peer_mgr
    }

    #[test]
    fn dns_peer_info_try_from_valid_config() {
        let cfg = DnsExportConfig {
            zones: vec![valid_zone_data("valid.peer.test", "10.0.0.10")],
            fqdn: "valid.peer.test".to_string(),
        };

        let info = DnsPeerInfo::try_from(cfg).expect("valid export config should pass");
        assert_eq!(info.zones.len(), 1);
        assert!(!info.digest.is_empty());
    }

    #[test]
    fn dns_peer_info_try_from_invalid_zone_rejected() {
        let cfg = DnsExportConfig {
            zones: vec![ZoneData {
                id: None,
                origin: "invalid.peer.test".to_string(),
                ttl: 60,
                records: vec!["@ IN A 10.0.0.11".to_string()],
                forwarders: vec![],
            }],
            fqdn: "invalid.peer.test".to_string(),
        };

        assert!(DnsPeerInfo::try_from(cfg).is_err());
    }

    #[tokio::test]
    async fn snapshot_merges_local_and_cached_peer_zones() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-peer",
            "local-custom.test",
            Ipv4Addr::new(10, 10, 10, 10),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();
        let mgr = DnsPeerMgr::new(peer_mgr, global_ctx);

        mgr.peers
            .insert(
                999_999,
                DnsPeerInfo {
                    digest: vec![1, 2, 3],
                    zones: vec![valid_zone_data("peer-cache.test", "10.20.30.40")],
                },
            )
            .await;

        let snapshot = mgr.snapshot();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("peer-cache.test"))
        );
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("local-custom.test"))
        );
    }

    #[tokio::test]
    async fn snapshot_includes_local_addresses_and_listeners() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-addr-listener",
            "local-addr-zone.test",
            Ipv4Addr::new(10, 10, 11, 11),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();
        let expected = global_ctx.config.get_dns();
        let mgr = DnsPeerMgr::new(peer_mgr, global_ctx);

        let snapshot = mgr.snapshot();
        let mut expected_addresses = expected
            .addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();
        let mut expected_listeners = expected
            .listeners
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();
        let mut got_addresses = snapshot
            .addresses
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();
        let mut got_listeners = snapshot
            .listeners
            .into_iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>();

        expected_addresses.sort();
        expected_listeners.sort();
        got_addresses.sort();
        got_listeners.sort();

        assert_eq!(got_addresses, expected_addresses);
        assert_eq!(got_listeners, expected_listeners);
    }

    #[tokio::test]
    async fn snapshot_aggregates_zones_from_multiple_cached_peers() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-multi",
            "local-multi.test",
            Ipv4Addr::new(10, 10, 12, 1),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();
        let mgr = DnsPeerMgr::new(peer_mgr, global_ctx);

        mgr.peers
            .insert(
                11,
                DnsPeerInfo {
                    digest: vec![11],
                    zones: vec![valid_zone_data("peer-a.test", "10.20.30.41")],
                },
            )
            .await;
        mgr.peers
            .insert(
                12,
                DnsPeerInfo {
                    digest: vec![12],
                    zones: vec![valid_zone_data("peer-b.test", "10.20.30.42")],
                },
            )
            .await;

        let snapshot = mgr.snapshot();
        let origins: HashSet<_> = snapshot.zones.into_iter().map(|z| z.origin).collect();

        assert!(origins.iter().any(|z| z.contains("peer-a.test")));
        assert!(origins.iter().any(|z| z.contains("peer-b.test")));
        assert!(origins.iter().any(|z| z.contains("local-multi.test")));
    }

    #[tokio::test]
    async fn snapshot_with_peer_without_zones_keeps_local_snapshot() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-empty-peer-zone",
            "local-empty-zone.test",
            Ipv4Addr::new(10, 10, 13, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr, get_mock_global_ctx());

        let before = mgr.snapshot();

        mgr.peers
            .insert(
                13,
                DnsPeerInfo {
                    digest: vec![13],
                    zones: vec![],
                },
            )
            .await;

        let after = mgr.snapshot();
        assert_eq!(before.zones.len(), after.zones.len());
        assert_eq!(before.addresses, after.addresses);
        assert_eq!(before.listeners, after.listeners);
    }

    #[tokio::test]
    async fn get_export_config_returns_global_ctx_export() {
        let peer_mgr = create_peer_manager_with_zone(
            "export-peer",
            "exported-zone.test",
            Ipv4Addr::new(10, 10, 20, 20),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();
        let mgr = DnsPeerMgr::new(peer_mgr, global_ctx.clone());

        let got = DnsPeerMgrRpc::get_export_config(
            mgr.0.as_ref(),
            BaseController::default(),
            GetExportConfigRequest {},
        )
        .await
        .expect("get_export_config should succeed");

        assert_eq!(got, global_ctx.dns_export_config());
    }

    #[tokio::test]
    async fn refresh_self_peer_marks_dirty_only() {
        let peer_mgr = create_peer_manager_with_zone(
            "self-peer",
            "self-zone.test",
            Ipv4Addr::new(10, 0, 0, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr.clone(), peer_mgr.get_global_ctx());

        mgr.dirty.reset();
        mgr.refresh(peer_mgr.my_peer_id()).await;

        assert!(mgr.dirty.peek());
    }

    #[tokio::test]
    async fn refresh_missing_route_noop_and_not_dirty() {
        let peer_mgr = create_peer_manager_with_zone(
            "solo-peer",
            "solo-zone.test",
            Ipv4Addr::new(10, 0, 0, 2),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr, get_mock_global_ctx());

        mgr.dirty.reset();
        mgr.refresh(987_654).await;

        assert!(!mgr.dirty.peek());
    }

    #[tokio::test]
    async fn refresh_same_digest_skips_fetch_and_not_mark_dirty() {
        let local = create_peer_manager_with_zone(
            "local-same",
            "local-same.test",
            Ipv4Addr::new(10, 0, 1, 1),
        )
        .await;
        let remote = create_peer_manager_with_zone(
            "remote-same",
            "remote-same.test",
            Ipv4Addr::new(10, 0, 1, 2),
        )
        .await;

        connect_peer_manager(local.clone(), remote.clone()).await;
        wait_route_appear(local.clone(), remote.clone())
            .await
            .expect("route should appear");

        let remote_id = remote.my_peer_id();
        let remote_route_dns = local
            .get_route()
            .get_peer_info(remote_id)
            .await
            .expect("remote route should exist")
            .dns;

        let mgr = DnsPeerMgr::new(local, get_mock_global_ctx());
        mgr.peers
            .insert(
                remote_id,
                DnsPeerInfo {
                    digest: remote_route_dns,
                    zones: vec![valid_zone_data("cached-same.test", "10.0.1.9")],
                },
            )
            .await;

        mgr.dirty.reset();
        mgr.refresh(remote_id).await;
        sleep(Duration::from_millis(50)).await;

        assert!(!mgr.dirty.peek());
    }

    #[tokio::test]
    async fn refresh_remote_peer_fetches_and_updates_snapshot() {
        let local = create_peer_manager_with_zone(
            "local-refresh",
            "local-refresh.test",
            Ipv4Addr::new(10, 0, 2, 1),
        )
        .await;
        let remote = create_peer_manager_with_zone(
            "remote-refresh",
            "remote-export.test",
            Ipv4Addr::new(10, 0, 2, 2),
        )
        .await;

        let local_dns = DnsPeerMgr::new(local.clone(), local.get_global_ctx());
        let remote_dns = DnsPeerMgr::new(remote.clone(), remote.get_global_ctx());
        remote_dns.register();

        connect_peer_manager(local.clone(), remote.clone()).await;
        wait_route_appear(local.clone(), remote.clone())
            .await
            .expect("route should appear");

        local_dns.dirty.reset();
        local_dns.refresh(remote.my_peer_id()).await;

        assert!(local_dns.dirty.peek());
        let snapshot = local_dns.snapshot();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("remote-export.test"))
        );
    }

    #[tokio::test]
    async fn multi_peer_refresh_updates_only_target_peer_snapshot_data() {
        let local = create_peer_manager_with_zone(
            "local-multi-refresh",
            "local-multi-refresh.test",
            Ipv4Addr::new(10, 2, 0, 1),
        )
        .await;
        let peer_a = create_peer_manager_with_zone(
            "peer-a",
            "remote-a.test",
            Ipv4Addr::new(10, 2, 0, 2),
        )
        .await;
        let peer_b = create_peer_manager_with_zone(
            "peer-b",
            "remote-b.test",
            Ipv4Addr::new(10, 2, 0, 3),
        )
        .await;

        let local_dns = DnsPeerMgr::new(local.clone(), local.get_global_ctx());
        let peer_a_dns = DnsPeerMgr::new(peer_a.clone(), peer_a.get_global_ctx());
        peer_a_dns.register();

        connect_peer_manager(local.clone(), peer_a.clone()).await;
        connect_peer_manager(local.clone(), peer_b.clone()).await;
        wait_route_appear(local.clone(), peer_a.clone())
            .await
            .expect("route to peer_a should appear");
        wait_route_appear(local.clone(), peer_b.clone())
            .await
            .expect("route to peer_b should appear");

        local_dns.refresh(peer_a.my_peer_id()).await;

        let snapshot = local_dns.snapshot();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("remote-a.test"))
        );
        assert!(
            !snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("remote-b.test"))
        );
    }

    #[tokio::test]
    async fn multi_peer_refresh_failure_invalidates_only_target_peer_cache() {
        let local = create_peer_manager_with_zone(
            "local-invalidate",
            "local-invalidate.test",
            Ipv4Addr::new(10, 2, 1, 1),
        )
        .await;
        let fail_peer = create_peer_manager_with_zone(
            "peer-fail",
            "peer-fail.test",
            Ipv4Addr::new(10, 2, 1, 2),
        )
        .await;
        let keep_peer = create_peer_manager_with_zone(
            "peer-keep",
            "peer-keep.test",
            Ipv4Addr::new(10, 2, 1, 3),
        )
        .await;

        let local_dns = DnsPeerMgr::new(local.clone(), local.get_global_ctx());
        let keep_dns = DnsPeerMgr::new(keep_peer.clone(), keep_peer.get_global_ctx());
        keep_dns.register();

        let fail_id = fail_peer.my_peer_id();
        let keep_id = keep_peer.my_peer_id();

        local_dns
            .peers
            .insert(
                fail_id,
                DnsPeerInfo {
                    digest: vec![1],
                    zones: vec![valid_zone_data("cached-fail.test", "10.2.1.20")],
                },
            )
            .await;
        local_dns
            .peers
            .insert(
                keep_id,
                DnsPeerInfo {
                    digest: vec![2],
                    zones: vec![valid_zone_data("cached-keep.test", "10.2.1.21")],
                },
            )
            .await;

        connect_peer_manager(local.clone(), fail_peer.clone()).await;
        connect_peer_manager(local.clone(), keep_peer.clone()).await;
        wait_route_appear(local.clone(), fail_peer.clone())
            .await
            .expect("route to fail_peer should appear");
        wait_route_appear(local.clone(), keep_peer.clone())
            .await
            .expect("route to keep_peer should appear");

        local_dns.dirty.reset();
        local_dns.refresh(fail_id).await;

        assert!(local_dns.dirty.peek());
        assert!(local_dns.peers.get(&fail_id).await.is_none());
        assert!(local_dns.peers.get(&keep_id).await.is_some());
    }

    #[tokio::test]
    async fn multi_peer_mixed_digest_changes_only_mark_for_changed_peer() {
        let local = create_peer_manager_with_zone(
            "local-mixed",
            "local-mixed.test",
            Ipv4Addr::new(10, 2, 2, 1),
        )
        .await;
        let changed_peer = create_peer_manager_with_zone(
            "peer-changed",
            "peer-changed.test",
            Ipv4Addr::new(10, 2, 2, 2),
        )
        .await;
        let unchanged_peer = create_peer_manager_with_zone(
            "peer-unchanged",
            "peer-unchanged.test",
            Ipv4Addr::new(10, 2, 2, 3),
        )
        .await;

        let local_dns = DnsPeerMgr::new(local.clone(), local.get_global_ctx());
        let changed_dns = DnsPeerMgr::new(changed_peer.clone(), changed_peer.get_global_ctx());
        let unchanged_dns =
            DnsPeerMgr::new(unchanged_peer.clone(), unchanged_peer.get_global_ctx());
        changed_dns.register();
        unchanged_dns.register();

        connect_peer_manager(local.clone(), changed_peer.clone()).await;
        connect_peer_manager(local.clone(), unchanged_peer.clone()).await;
        wait_route_appear(local.clone(), changed_peer.clone())
            .await
            .expect("route to changed_peer should appear");
        wait_route_appear(local.clone(), unchanged_peer.clone())
            .await
            .expect("route to unchanged_peer should appear");

        let unchanged_id = unchanged_peer.my_peer_id();
        let unchanged_digest = local
            .get_route()
            .get_peer_info(unchanged_id)
            .await
            .expect("unchanged route should exist")
            .dns;

        local_dns
            .peers
            .insert(
                changed_peer.my_peer_id(),
                DnsPeerInfo {
                    digest: vec![0],
                    zones: vec![valid_zone_data("stale-changed.test", "10.2.2.20")],
                },
            )
            .await;
        local_dns
            .peers
            .insert(
                unchanged_id,
                DnsPeerInfo {
                    digest: unchanged_digest,
                    zones: vec![valid_zone_data("cached-unchanged.test", "10.2.2.21")],
                },
            )
            .await;

        local_dns.dirty.reset();
        local_dns.refresh(changed_peer.my_peer_id()).await;
        assert!(local_dns.dirty.peek());

        local_dns.dirty.reset();
        local_dns.refresh(unchanged_id).await;
        assert!(!local_dns.dirty.peek());

        let unchanged_cache = local_dns
            .peers
            .get(&unchanged_id)
            .await
            .expect("unchanged peer cache should stay");
        assert!(
            unchanged_cache
                .zones
                .iter()
                .any(|z| z.origin.contains("cached-unchanged.test"))
        );
    }

    #[tokio::test]
    async fn snapshot_removes_cached_peer_zone_after_tti_expire() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-tti",
            "local-tti.test",
            Ipv4Addr::new(10, 3, 0, 1),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();
        let mgr = DnsPeerMgr::new(peer_mgr, global_ctx);

        let cached_peer_id = 66_666;
        mgr.peers
            .insert(
                cached_peer_id,
                DnsPeerInfo {
                    digest: vec![6, 6, 6],
                    zones: vec![valid_zone_data("cached-expire.test", "10.3.0.2")],
                },
            )
            .await;

        let before = mgr.snapshot();
        assert!(
            before
                .zones
                .iter()
                .any(|z| z.origin.contains("cached-expire.test"))
        );
        assert!(
            before
                .zones
                .iter()
                .any(|z| z.origin.contains("local-tti.test"))
        );

        let deadline = tokio::time::Instant::now() + DNS_PEER_TTI + Duration::from_secs(3);
        loop {
            let now_snapshot = mgr.snapshot();
            let expired = !now_snapshot
                .zones
                .iter()
                .any(|z| z.origin.contains("cached-expire.test"));
            if expired {
                assert!(
                    now_snapshot
                        .zones
                        .iter()
                        .any(|z| z.origin.contains("local-tti.test"))
                );
                break;
            }

            assert!(
                tokio::time::Instant::now() < deadline,
                "cached peer zone did not expire within expected TTI window"
            );
            sleep(Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn register_then_unregister_returns_some() {
        let peer_mgr = create_peer_manager_with_zone(
            "register-peer",
            "register-zone.test",
            Ipv4Addr::new(10, 1, 0, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr.clone(), peer_mgr.get_global_ctx());

        mgr.register();
        assert!(mgr.unregister().is_some());
    }

    #[tokio::test]
    async fn unregister_without_register_returns_none() {
        let peer_mgr = create_peer_manager_with_zone(
            "unregister-peer",
            "unregister-zone.test",
            Ipv4Addr::new(10, 1, 0, 2),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr, get_mock_global_ctx());

        assert!(mgr.unregister().is_none());
    }

    #[tokio::test]
    async fn drop_triggers_unregister() {
        let peer_mgr = create_peer_manager_with_zone(
            "drop-peer",
            "drop-zone.test",
            Ipv4Addr::new(10, 1, 0, 3),
        )
        .await;
        let global_ctx = peer_mgr.get_global_ctx();

        let mgr = DnsPeerMgr::new(peer_mgr.clone(), global_ctx.clone());
        let inner = mgr.0.clone();
        mgr.register();

        drop(mgr);

        let res = peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                DnsPeerMgrRpcServer::new_arc(inner),
                &global_ctx.get_network_name(),
            );
        assert!(res.is_none());
    }
}


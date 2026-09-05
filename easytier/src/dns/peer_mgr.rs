use crate::common::global_ctx::ArcGlobalCtx;
use crate::dns::config::zone::ZoneConfig;
use crate::dns::config::{
    DNS_PEER_REFRESH_ATTEMPTS, DNS_PEER_REFRESH_BACKOFF, DnsConfigLoaderExt, DnsExportConfig,
    DnsGlobalCtxExt,
};
use crate::dns::zone::ZoneGroup;
use crate::proto::dns::{DnsSnapshot, ZoneData};
use crate::proto::utils::TransientDigest;
use crate::utils::dirty::DirtyFlag;
use anyhow::Context;
use easytier_core::config::PeerId;
use easytier_core::instance::{CoreDnsPeerAccess, DnsExportRegistration};
use futures::StreamExt;
use futures::stream;
use moka::future::Cache;
use std::ops::Deref;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::sleep;
use tracing::instrument;

#[derive(Debug, Clone)]
struct DnsPeerInfo {
    digest: [u8; 32],
    zones: Vec<ZoneData>,
}

impl TryFrom<DnsExportConfig> for DnsPeerInfo {
    type Error = anyhow::Error;

    fn try_from(value: DnsExportConfig) -> Result<Self, Self::Error> {
        let _ = ZoneGroup::try_from(value.zones.as_slice())?;
        Ok(Self {
            digest: value.digest(),
            zones: value.zones,
        })
    }
}

#[derive(Debug)]
pub struct DnsPeerMgrInner {
    peers: Cache<PeerId, DnsPeerInfo>,
    pub dirty: DirtyFlag,

    peer_mgr: Arc<CoreDnsPeerAccess>,
    registration: Mutex<Option<DnsExportRegistration>>,
    refresh_locks:
        Mutex<std::collections::HashMap<PeerId, std::sync::Weak<tokio::sync::Mutex<()>>>>,
    global_ctx: ArcGlobalCtx,
}

impl DnsPeerMgrInner {
    pub fn snapshot(&self) -> anyhow::Result<DnsSnapshot> {
        let global_ctx = &self.global_ctx;

        let zones = global_ctx
            .try_dns_iter_zones()?
            .into_iter()
            .map(ZoneConfig::into_data)
            .chain(
                self.peers
                    .iter()
                    .flat_map(|(_, info)| info.zones.into_iter()),
            )
            .collect();

        let config = global_ctx.config.try_get_dns()?.into_parsed();
        Ok(DnsSnapshot {
            zones,
            addresses: config.addresses.into(),
            listeners: config.listeners.into(),
        })
    }

    pub fn publish_local_export(&self) -> anyhow::Result<()> {
        if self.global_ctx.config.try_get_dns()?.disabled {
            self.peer_mgr.withdraw_export();
            return Ok(());
        }
        self.peer_mgr
            .publish_export(self.global_ctx.try_dns_export_config()?);
        Ok(())
    }

    #[instrument(skip(self), level = "trace", ret)]
    pub async fn refresh(
        &self,
        peer_id: PeerId,
        mut attempts: usize,
        mut backoff: Duration,
    ) -> anyhow::Result<bool> {
        // Events and periodic reconciliation can overlap. Serialize requests for
        // one peer so an older response cannot overwrite a newer cached export.
        let refresh_lock = {
            let mut locks = self.refresh_locks.lock().unwrap();
            locks.retain(|_, lock| lock.strong_count() != 0);
            let entry = locks.entry(peer_id).or_default();
            entry.upgrade().unwrap_or_else(|| {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                *entry = Arc::downgrade(&lock);
                lock
            })
        };
        let _refresh = refresh_lock.lock().await;
        loop {
            attempts = attempts.saturating_sub(1);
            let result = self.try_refresh(peer_id).await;
            match &result {
                Ok(_) => {
                    tracing::trace!(?peer_id, "peer info refreshed");
                    return result;
                }
                Err(_) if attempts == 0 => {
                    self.peers.invalidate(&peer_id).await;
                    self.dirty.mark();
                    tracing::error!(
                        ?peer_id,
                        "exhausted all attempts to refresh peer info, invalidating cache"
                    );
                    return result;
                }
                Err(error) => {
                    tracing::error!(
                        ?error,
                        ?peer_id,
                        "failed to refresh peer info, retrying in {:?}",
                        backoff
                    );
                    sleep(backoff).await;
                    backoff *= 2;
                }
            }
        }
    }

    async fn try_refresh(&self, peer_id: PeerId) -> anyhow::Result<bool> {
        if peer_id == self.peer_mgr.local_peer_id() {
            self.dirty.mark();
            return Ok(true);
        }

        let Some(digest) = self.peer_mgr.dns_advertisement(peer_id).await else {
            if self.peers.remove(&peer_id).await.is_some() {
                tracing::debug!(?peer_id, "peer route disappeared, removing from cache");
                self.dirty.mark();
            }
            return Ok(true);
        };

        if self
            .peers
            .get(&peer_id)
            .await
            .is_some_and(|info| digest == info.digest)
        {
            return Ok(false);
        }

        if !digest.is_empty() {
            let info = self.fetch(peer_id).await.with_context(|| {
                format!("failed to fetch dns export config from peer {}", peer_id)
            })?;
            // Routing and the RPC response travel independently. A concurrent
            // export change is retried instead of publishing data for a stale
            // advertisement (or resurrecting a peer that became unreachable).
            let current_digest = self.peer_mgr.dns_advertisement(peer_id).await;
            if current_digest.as_deref() != Some(info.digest.as_slice()) {
                anyhow::bail!("DNS advertisement changed while fetching peer {peer_id}");
            }
            self.peers.insert(peer_id, info).await;
        } else {
            self.peers.invalidate(&peer_id).await;
        }

        self.dirty.mark();
        Ok(true)
    }

    #[instrument(skip(self), level = "trace", ret)]
    async fn fetch(&self, peer_id: PeerId) -> anyhow::Result<DnsPeerInfo> {
        self.peer_mgr
            .fetch_export(peer_id)
            .await
            .context("rpc call failed")?
            .try_into()
    }
}

#[derive(Debug, Clone)]
pub struct DnsPeerMgr(Arc<DnsPeerMgrInner>);

impl DnsPeerMgr {
    pub fn new(peer_mgr: Arc<CoreDnsPeerAccess>, global_ctx: ArcGlobalCtx) -> Self {
        Self(Arc::new(DnsPeerMgrInner {
            // Peer exports remain valid until routing withdraws them, their
            // advertised digest changes, or an explicit refresh fails.
            peers: Cache::builder().build(),
            dirty: Default::default(),
            peer_mgr,
            registration: Mutex::new(None),
            refresh_locks: Mutex::new(std::collections::HashMap::new()),
            global_ctx,
        }))
    }

    pub fn register(&self) {
        let mut registration = self.registration.lock().unwrap();
        if registration.is_none() {
            *registration = Some(self.peer_mgr.register_export_service());
        }
    }

    pub fn unregister(&self) -> Option<()> {
        self.registration.lock().unwrap().take().map(drop)
    }

    #[instrument(skip(self), level = "trace")]
    pub async fn reconcile(&self) {
        if let Err(error) = self.publish_local_export() {
            tracing::error!(?error, "failed to compile local DNS export");
        }
        let peer_ids = self.peer_mgr.reachable_peer_ids().await;
        let reachable: std::collections::HashSet<_> = peer_ids.iter().copied().collect();
        for (peer_id, _) in self.peers.iter() {
            if !reachable.contains(peer_id.as_ref()) {
                self.peers.invalidate(peer_id.as_ref()).await;
                self.dirty.mark();
            }
        }
        stream::iter(peer_ids)
            .map(|peer_id| {
                let this = self.clone();
                async move {
                    if let Err(error) = this
                        .refresh(peer_id, DNS_PEER_REFRESH_ATTEMPTS, DNS_PEER_REFRESH_BACKOFF)
                        .await
                    {
                        tracing::error!(?error, ?peer_id, "failed to refresh peer info");
                    }
                }
            })
            .buffer_unordered(32)
            .collect::<Vec<_>>()
            .await;
    }
}

impl Deref for DnsPeerMgr {
    type Target = DnsPeerMgrInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::dns::config::zone::ZoneConfig;
    use crate::dns::tests::zone_data_a as valid_zone_data;
    use crate::instance::composition::{NativeCoreInstance, runtime_core_host_adapters};
    use crate::instance::config::test_core_instance_config;
    use crate::proto::dns::ZoneDataExt;
    use easytier_core::host::packet::{HostPacket, HostPacketChannelSink};
    use easytier_core::process_runtime::CoreProcessRuntime;
    use std::collections::HashSet;
    use std::net::Ipv4Addr;
    use tokio::time::{Duration, sleep};

    struct TestPeer {
        core: Arc<NativeCoreInstance>,
        ctx: ArcGlobalCtx,
    }

    impl TestPeer {
        fn get_global_ctx(&self) -> ArcGlobalCtx {
            self.ctx.clone()
        }
        fn my_peer_id(&self) -> PeerId {
            self.core.peer_id()
        }
        fn access(&self) -> Arc<CoreDnsPeerAccess> {
            self.core.packet_plane().dns_peer_access()
        }
    }

    async fn create_peer_manager_with_zone(
        host: &str,
        origin: &str,
        record_ip: Ipv4Addr,
    ) -> Arc<TestPeer> {
        let ctx = get_mock_global_ctx();
        let mut dns = ctx.config.try_get_dns().unwrap().into_raw();
        dns.name = Some(host.parse().unwrap());
        dns.zones
            .get_or_insert_default()
            .push(ZoneConfig::dedicated(
                origin.parse().expect("invalid zone origin"),
                Some(record_ip),
                vec![],
            ));
        ctx.config.set_dns(dns.into());
        ctx.config.set_listeners(vec![
            format!("ring://{}", uuid::Uuid::new_v4()).parse().unwrap(),
        ]);

        static PROCESS: std::sync::OnceLock<Arc<CoreProcessRuntime>> = std::sync::OnceLock::new();
        let (packet_tx, mut packet_rx) = tokio::sync::mpsc::channel::<HostPacket>(128);
        tokio::spawn(async move { while packet_rx.recv().await.is_some() {} });
        let adapters = runtime_core_host_adapters(
            ctx.clone(),
            PROCESS.get_or_init(CoreProcessRuntime::new).clone(),
            Arc::new(HostPacketChannelSink::new(packet_tx)),
        );
        let core = NativeCoreInstance::new(test_core_instance_config(&ctx), adapters).unwrap();
        core.start().await.unwrap();
        let peer = Arc::new(TestPeer { core, ctx });
        peer.access()
            .publish_export(peer.ctx.try_dns_export_config().unwrap());
        peer
    }

    async fn connect_peer_manager(local: Arc<TestPeer>, remote: Arc<TestPeer>) {
        let listener = remote
            .core
            .running_listeners()
            .into_iter()
            .find(|url| url.scheme() == "ring")
            .expect("ring listener");
        local.core.add_connector(listener).unwrap();
    }

    async fn wait_route_appear(local: Arc<TestPeer>, remote: Arc<TestPeer>) -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if local
                    .access()
                    .dns_advertisement(remote.my_peer_id())
                    .await
                    .is_some_and(|digest| !digest.is_empty())
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;
        Ok(())
    }

    #[test]
    fn dns_peer_info_try_from_valid_config() {
        let cfg = DnsExportConfig {
            zones: vec![valid_zone_data("valid.peer.test", "10.0.0.10")],
        };

        let info = DnsPeerInfo::try_from(cfg).expect("valid export config should pass");
        assert_eq!(info.zones.len(), 1);
        assert!(!info.digest.is_empty());
    }

    #[test]
    fn dns_peer_info_try_from_invalid_zone_rejected() {
        let cfg = DnsExportConfig {
            zones: vec![ZoneData::new(&".".parse().unwrap(), 60, ["?"], [], [])],
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
        let mgr = DnsPeerMgr::new(peer_mgr.access(), global_ctx);

        mgr.peers
            .insert(
                999_999,
                DnsPeerInfo {
                    digest: [9; 32],
                    zones: vec![valid_zone_data("peer-cache.test", "10.20.30.40")],
                },
            )
            .await;

        let snapshot = mgr.snapshot().unwrap();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.content.contains("$ORIGIN peer-cache.test"))
        );
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.content.contains("$ORIGIN local-custom.test"))
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
        let expected = global_ctx.config.try_get_dns().unwrap().into_parsed();
        let mgr = DnsPeerMgr::new(peer_mgr.access(), global_ctx);

        let snapshot = mgr.snapshot().unwrap();
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
        let mgr = DnsPeerMgr::new(peer_mgr.access(), global_ctx);

        mgr.peers
            .insert(
                11,
                DnsPeerInfo {
                    digest: [11; 32],
                    zones: vec![valid_zone_data("peer-a.test", "10.20.30.41")],
                },
            )
            .await;
        mgr.peers
            .insert(
                12,
                DnsPeerInfo {
                    digest: [12; 32],
                    zones: vec![valid_zone_data("peer-b.test", "10.20.30.42")],
                },
            )
            .await;

        let snapshot = mgr.snapshot().unwrap();
        let contents: HashSet<_> = snapshot.zones.into_iter().map(|z| z.content).collect();

        assert!(contents.iter().any(|z| z.contains("$ORIGIN peer-a.test")));
        assert!(contents.iter().any(|z| z.contains("$ORIGIN peer-b.test")));
        assert!(
            contents
                .iter()
                .any(|z| z.contains("$ORIGIN local-multi.test"))
        );
    }

    #[tokio::test]
    async fn snapshot_with_peer_without_zones_keeps_local_snapshot() {
        let peer_mgr = create_peer_manager_with_zone(
            "local-empty-peer-zone",
            "local-empty-zone.test",
            Ipv4Addr::new(10, 10, 13, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr.access(), get_mock_global_ctx());

        let before = mgr.snapshot().unwrap();

        mgr.peers
            .insert(
                13,
                DnsPeerInfo {
                    digest: [13; 32],
                    zones: vec![],
                },
            )
            .await;

        let after = mgr.snapshot().unwrap();
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
        let mgr = DnsPeerMgr::new(peer_mgr.access(), global_ctx.clone());

        mgr.publish_local_export().unwrap();
        let got = mgr.peer_mgr.local_export();

        assert_eq!(got, global_ctx.try_dns_export_config().unwrap());
    }

    #[tokio::test]
    async fn refresh_self_peer_marks_dirty_only() {
        let peer_mgr = create_peer_manager_with_zone(
            "self-peer",
            "self-zone.test",
            Ipv4Addr::new(10, 0, 0, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr.access(), peer_mgr.get_global_ctx());

        mgr.dirty.reset();
        mgr.try_refresh(peer_mgr.my_peer_id()).await.unwrap();

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
        let mgr = DnsPeerMgr::new(peer_mgr.access(), get_mock_global_ctx());

        mgr.dirty.reset();
        mgr.try_refresh(987_654).await.unwrap();

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
            .access()
            .dns_advertisement(remote_id)
            .await
            .expect("remote route should exist");

        let mgr = DnsPeerMgr::new(local.access(), get_mock_global_ctx());
        mgr.peers
            .insert(
                remote_id,
                DnsPeerInfo {
                    digest: remote_route_dns
                        .try_into()
                        .expect("route dns digest should be 32 bytes"),
                    zones: vec![valid_zone_data("cached-same.test", "10.0.1.9")],
                },
            )
            .await;

        mgr.dirty.reset();
        mgr.try_refresh(remote_id).await.unwrap();
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

        let local_dns = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        let remote_dns = DnsPeerMgr::new(remote.access(), remote.get_global_ctx());
        remote_dns.register();

        connect_peer_manager(local.clone(), remote.clone()).await;
        wait_route_appear(local.clone(), remote.clone())
            .await
            .expect("route should appear");

        local_dns.dirty.reset();
        local_dns.try_refresh(remote.my_peer_id()).await.unwrap();

        assert!(local_dns.dirty.peek());
        let snapshot = local_dns.snapshot().unwrap();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.content.contains("$ORIGIN remote-export.test"))
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
        let peer_a =
            create_peer_manager_with_zone("peer-a", "remote-a.test", Ipv4Addr::new(10, 2, 0, 2))
                .await;
        let peer_b =
            create_peer_manager_with_zone("peer-b", "remote-b.test", Ipv4Addr::new(10, 2, 0, 3))
                .await;

        let local_dns = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        let peer_a_dns = DnsPeerMgr::new(peer_a.access(), peer_a.get_global_ctx());
        peer_a_dns.register();

        connect_peer_manager(local.clone(), peer_a.clone()).await;
        connect_peer_manager(local.clone(), peer_b.clone()).await;
        wait_route_appear(local.clone(), peer_a.clone())
            .await
            .expect("route to peer_a should appear");
        wait_route_appear(local.clone(), peer_b.clone())
            .await
            .expect("route to peer_b should appear");

        local_dns.try_refresh(peer_a.my_peer_id()).await.unwrap();

        let snapshot = local_dns.snapshot().unwrap();
        assert!(
            snapshot
                .zones
                .iter()
                .any(|z| z.content.contains("$ORIGIN remote-a.test"))
        );
        assert!(
            !snapshot
                .zones
                .iter()
                .any(|z| z.content.contains("$ORIGIN remote-b.test"))
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

        let local_dns = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        local_dns.register();
        let keep_dns = DnsPeerMgr::new(keep_peer.access(), keep_peer.get_global_ctx());
        keep_dns.register();

        let fail_id = fail_peer.my_peer_id();
        let keep_id = keep_peer.my_peer_id();

        local_dns
            .peers
            .insert(
                fail_id,
                DnsPeerInfo {
                    digest: [1; 32],
                    zones: vec![valid_zone_data("cached-fail.test", "10.2.1.20")],
                },
            )
            .await;
        local_dns
            .peers
            .insert(
                keep_id,
                DnsPeerInfo {
                    digest: [2; 32],
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
        local_dns
            .refresh(fail_id, Default::default(), Default::default())
            .await
            .unwrap_err();

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

        let local_dns = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        let changed_dns = DnsPeerMgr::new(changed_peer.access(), changed_peer.get_global_ctx());
        let unchanged_dns =
            DnsPeerMgr::new(unchanged_peer.access(), unchanged_peer.get_global_ctx());
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
            .access()
            .dns_advertisement(unchanged_id)
            .await
            .expect("unchanged route should exist");

        local_dns
            .peers
            .insert(
                changed_peer.my_peer_id(),
                DnsPeerInfo {
                    digest: [0; 32],
                    zones: vec![valid_zone_data("stale-changed.test", "10.2.2.20")],
                },
            )
            .await;
        local_dns
            .peers
            .insert(
                unchanged_id,
                DnsPeerInfo {
                    digest: unchanged_digest
                        .try_into()
                        .expect("route dns digest should be 32 bytes"),
                    zones: vec![valid_zone_data("cached-unchanged.test", "10.2.2.21")],
                },
            )
            .await;

        local_dns.dirty.reset();
        local_dns
            .try_refresh(changed_peer.my_peer_id())
            .await
            .unwrap();
        assert!(local_dns.dirty.peek());

        local_dns.dirty.reset();
        local_dns.try_refresh(unchanged_id).await.unwrap();
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
                .any(|z| z.content.contains("$ORIGIN cached-unchanged.test"))
        );
    }

    #[tokio::test]
    async fn stable_peer_export_survives_without_refresh_past_old_idle_timeout() {
        let local = create_peer_manager_with_zone(
            "local-stable",
            "local-stable.test",
            Ipv4Addr::new(10, 3, 0, 1),
        )
        .await;
        let remote = create_peer_manager_with_zone(
            "remote-stable",
            "remote-stable.test",
            Ipv4Addr::new(10, 3, 0, 2),
        )
        .await;
        let mgr = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        let remote_dns = DnsPeerMgr::new(remote.access(), remote.get_global_ctx());
        remote_dns.register();
        connect_peer_manager(local.clone(), remote.clone()).await;
        wait_route_appear(local.clone(), remote.clone())
            .await
            .unwrap();
        mgr.try_refresh(remote.my_peer_id()).await.unwrap();

        // The former three-second TTI expired even healthy peers between the
        // ten-second reconciliation ticks. Merely rebuilding a snapshot must
        // not lose this export.
        sleep(Duration::from_millis(3200)).await;
        assert!(
            local
                .access()
                .dns_advertisement(remote.my_peer_id())
                .await
                .is_some()
        );
        assert!(
            mgr.snapshot()
                .unwrap()
                .zones
                .iter()
                .any(|zone| zone.content.contains("$ORIGIN remote-stable.test"))
        );
    }

    #[tokio::test]
    async fn reconcile_removes_export_after_its_peer_route_is_withdrawn() {
        let local = create_peer_manager_with_zone(
            "local-withdraw",
            "local-withdraw.test",
            Ipv4Addr::new(10, 3, 1, 1),
        )
        .await;
        let remote = create_peer_manager_with_zone(
            "remote-withdraw",
            "remote-withdraw.test",
            Ipv4Addr::new(10, 3, 1, 2),
        )
        .await;
        let mgr = DnsPeerMgr::new(local.access(), local.get_global_ctx());
        let remote_dns = DnsPeerMgr::new(remote.access(), remote.get_global_ctx());
        remote_dns.register();
        connect_peer_manager(local.clone(), remote.clone()).await;
        wait_route_appear(local.clone(), remote.clone())
            .await
            .unwrap();
        mgr.try_refresh(remote.my_peer_id()).await.unwrap();
        assert!(mgr.peers.get(&remote.my_peer_id()).await.is_some());

        remote.core.stop().await;
        tokio::time::timeout(Duration::from_secs(10), async {
            while local
                .access()
                .dns_advertisement(remote.my_peer_id())
                .await
                .is_some()
            {
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("peer route should be withdrawn");
        mgr.dirty.reset();
        mgr.reconcile().await;
        assert!(mgr.dirty.peek());
        assert!(mgr.peers.get(&remote.my_peer_id()).await.is_none());
        assert!(
            !mgr.snapshot()
                .unwrap()
                .zones
                .iter()
                .any(|zone| zone.content.contains("$ORIGIN remote-withdraw.test"))
        );
    }

    #[tokio::test]
    async fn register_then_unregister_returns_some() {
        let peer_mgr = create_peer_manager_with_zone(
            "register-peer",
            "register-zone.test",
            Ipv4Addr::new(10, 1, 0, 1),
        )
        .await;
        let mgr = DnsPeerMgr::new(peer_mgr.access(), peer_mgr.get_global_ctx());
        mgr.register();
        assert!(mgr.unregister().is_some());
    }

    #[tokio::test]
    async fn multiple_registration_guards_keep_export_until_the_last_drop() {
        let peer = create_peer_manager_with_zone(
            "registration-guards",
            "guards.test",
            Ipv4Addr::new(10, 1, 0, 2),
        )
        .await;
        let access = peer.access();
        let expected = access.local_export();
        assert!(!expected.zones.is_empty());
        let first = access.register_export_service();
        let second = access.register_export_service();
        drop(first);
        assert_eq!(access.local_export(), expected);
        drop(second);
        assert!(access.local_export().zones.is_empty());
    }
}

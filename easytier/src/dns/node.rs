use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::dns::config::{
    DNS_NODE_HEARTBEAT_INTERVAL, DNS_NODE_RECONCILE_INTERVAL, DNS_PEER_REFRESH_ATTEMPTS,
    DNS_PEER_REFRESH_BACKOFF, DNS_SERVER_ELECTION_INTERVAL, DNS_SERVER_RPC_ADDR,
};
use crate::dns::host::DnsHost;
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::dns::server::DnsServer;
use crate::proto::dns::{DnsNodeMgrRpcClientFactory, HeartbeatRequest};
use crate::proto::rpc::standalone::{
    RuntimeRpcClient, StandAloneServer, runtime_rpc_client, runtime_rpc_listener,
};
use crate::proto::rpc_types::controller::BaseController;
use crate::utils::task::CancellableTask;
use easytier_core::instance::CoreDnsPeerAccess;
use std::io;
use std::sync::Arc;
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinSet;
use tokio::time::{MissedTickBehavior, interval};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct DnsNodeRuntime {
    mgr: DnsPeerMgr,

    host: Arc<dyn DnsHost>,
    global_ctx: ArcGlobalCtx,

    elect: Arc<Notify>,
}

impl DnsNodeRuntime {
    fn id(&self) -> Uuid {
        self.global_ctx.get_id()
    }

    #[instrument(skip_all, name = "DnsNode election loop")]
    async fn run_election(&self, token: CancellationToken) {
        let mut election_interval = interval(DNS_SERVER_ELECTION_INTERVAL);
        election_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    tracing::info!("DnsNode received shutdown signal, exiting election loop");
                    break;
                }
                _ = self.elect.notified() => {}
                _ = election_interval.tick() => {}
            }

            tracing::info!("trying to become DNS server");

            let mut rpc = StandAloneServer::new(runtime_rpc_listener(
                DNS_SERVER_RPC_ADDR
                    .socket_addrs(|| None)
                    .expect("valid DNS RPC address")[0],
            ));

            if rpc.serve().await.is_err() {
                // Another node already owns the address — that's fine.
                tracing::info!(
                    "failed to bind RPC server, another node might have won the election"
                );
                continue;
            }

            tracing::info!("won DNS server election, starting DnsServer");

            let server = Arc::new(DnsServer::new(self.global_ctx.clone(), self.host.clone()));
            server.register(&rpc);
            server.run(token.child_token()).await;

            tracing::warn!("DnsServer exited, will retry election");
        }
    }

    #[instrument(skip_all, name = "DnsNode main loop")]
    async fn run(&self, token: CancellationToken) {
        let mut rpc = runtime_rpc_client(DNS_SERVER_RPC_ADDR.clone());

        let mut heartbeat = HeartbeatRequest {
            id: Some(self.id().into()),

            ..Default::default()
        };

        let mut heartbeat_interval = interval(DNS_NODE_HEARTBEAT_INTERVAL);
        heartbeat_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut reconcile_interval = interval(DNS_NODE_RECONCILE_INTERVAL);
        reconcile_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

        let mut subscriber = self.global_ctx.subscribe();
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                biased;

                _ = token.cancelled() => {
                    tracing::info!("DnsNode received shutdown signal, exiting main loop");
                    break;
                }

                _ = heartbeat_interval.tick() => {
                    let result = tokio::select! {
                        _ = token.cancelled() => break,
                        result = self.heartbeat(&mut rpc, &mut heartbeat) => result,
                    };
                    if let Err(error) = result {
                        tracing::error!(?error, "heartbeat failed");
                        self.elect.notify_one();
                    }
                }

                _ = reconcile_interval.tick() => {
                    let mgr = self.mgr.clone();
                    tasks.spawn(async move {
                        mgr.reconcile().await;
                    });
                }

                event = subscriber.recv() => {
                    match event {
                        Ok(GlobalCtxEvent::PeerInfoUpdated(peer_ids)) => {
                            for peer_id in peer_ids {
                                let mgr = self.mgr.clone();
                                tasks.spawn(async move {
                                    if let Err(error) = mgr.refresh(peer_id, DNS_PEER_REFRESH_ATTEMPTS, DNS_PEER_REFRESH_BACKOFF).await {
                                        tracing::error!(?error, ?peer_id, "failed to refresh peer");
                                    }
                                });
                            }
                            continue;
                        }
                        Ok(
                            GlobalCtxEvent::DhcpIpv4Changed(..)
                            | GlobalCtxEvent::DhcpIpv4Conflicted(..),
                        ) => {
                            tracing::info!(?event, "ip change detected, rebuilding snapshot");
                        }
                        #[cfg(feature = "management")]
                        Ok(GlobalCtxEvent::ConfigPatched(patch)) => {
                            // TODO: inspect patch
                            tracing::info!(?patch, "config change detected, rebuilding snapshot");
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            tracing::warn!("event listener lagged, skipped {n} events, rebuilding snapshot");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            tracing::info!("event bus closed");
                            break;
                        }
                        _ => continue,
                    }

                    if let Err(error) = self.mgr.publish_local_export() {
                        tracing::warn!(?error, "failed to publish local DNS configuration");
                    }
                    self.mgr.dirty.mark();
                }

                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result {
                        tracing::error!(?error, "refresh task panicked");
                    }
                }
            }
        }
    }

    async fn heartbeat(
        &self,
        rpc: &mut RuntimeRpcClient,
        heartbeat: &mut HeartbeatRequest,
    ) -> anyhow::Result<()> {
        let dirty = self.mgr.dirty.reset();
        let request = if heartbeat.snapshot.is_none() || dirty {
            heartbeat.update(self.mgr.snapshot()?);
            heartbeat.clone()
        } else {
            let snapshot = heartbeat.snapshot.take();
            let request = heartbeat.clone();
            heartbeat.snapshot = snapshot;
            request
        };

        let client = rpc
            .scoped_client::<DnsNodeMgrRpcClientFactory<BaseController>>("".to_string())
            .await?;

        let response = client.heartbeat(BaseController::default(), request).await?;
        if response.resync {
            tracing::trace!("resync requested by server, sending full snapshot");
            client
                .heartbeat(BaseController::default(), heartbeat.clone())
                .await?;
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct DnsNode {
    runtime: DnsNodeRuntime,
    task: Option<CancellableTask<()>>,
}

impl DnsNode {
    pub fn new(
        peer_mgr: Arc<CoreDnsPeerAccess>,
        global_ctx: ArcGlobalCtx,
        host: Arc<dyn DnsHost>,
    ) -> Self {
        let runtime = DnsNodeRuntime {
            mgr: DnsPeerMgr::new(peer_mgr.clone(), global_ctx.clone()),
            host,
            global_ctx,
            elect: Default::default(),
        };

        Self {
            runtime,
            task: None,
        }
    }

    pub fn start(&mut self) {
        self.start_with_token(CancellationToken::new());
    }

    pub(crate) fn start_with_token(&mut self, token: CancellationToken) {
        if let Err(error) = self.runtime.mgr.publish_local_export() {
            tracing::warn!(?error, "failed to publish local DNS configuration");
        }
        self.runtime.mgr.register();
        let runtime = self.runtime.clone();
        self.task
            .replace(CancellableTask::new(token.clone(), async move {
                runtime.elect.notify_one();
                tokio::join!(runtime.run_election(token.clone()), runtime.run(token));
            }));
    }

    pub async fn stop(&mut self) -> io::Result<()> {
        let Some(task) = self.task.take() else {
            self.runtime.mgr.unregister();
            return Ok(());
        };
        let result = task.stop(None).await;
        self.runtime.mgr.unregister();
        result
    }
}

impl Drop for DnsNode {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            self.runtime.mgr.unregister();
            return;
        };
        task.token().cancel();
        let mgr = self.runtime.mgr.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = task.stop(Some(std::time::Duration::from_secs(10))).await;
                mgr.unregister();
            });
        } else {
            mgr.unregister();
        }
    }
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    use crate::common::global_ctx::GlobalCtxEvent;
    #[cfg(feature = "management")]
    use crate::proto::api::config::InstanceConfigPatch;
    use crate::proto::dns::{DnsNodeMgrRpc, DnsNodeMgrRpcServer, HeartbeatResponse};
    use crate::proto::rpc::standalone::{RuntimeRpcListener, StandAloneServer};
    use crate::proto::rpc_types;
    use crate::tunnel::common::tests::wait_for_condition;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tokio::time::sleep;
    use url::Url;

    #[derive(Debug)]
    struct RecordingDnsNodeMgr {
        requests: Mutex<Vec<HeartbeatRequest>>,
        resync_on_first: AtomicBool,
    }

    impl RecordingDnsNodeMgr {
        fn new(resync_on_first: bool) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                resync_on_first: AtomicBool::new(resync_on_first),
            }
        }

        async fn recorded_requests(&self) -> Vec<HeartbeatRequest> {
            self.requests.lock().await.clone()
        }
    }

    #[async_trait::async_trait]
    impl DnsNodeMgrRpc for RecordingDnsNodeMgr {
        type Controller = BaseController;

        async fn heartbeat(
            &self,
            _: Self::Controller,
            input: HeartbeatRequest,
        ) -> rpc_types::error::Result<HeartbeatResponse> {
            let mut requests = self.requests.lock().await;
            requests.push(input);
            let is_first = requests.len() == 1;
            let resync = is_first && self.resync_on_first.load(Ordering::Relaxed);
            if is_first {
                self.resync_on_first.store(false, Ordering::Relaxed);
            }
            Ok(HeartbeatResponse { resync })
        }
    }

    async fn build_test_runtime() -> (DnsNodeRuntime, Arc<crate::dns::tests::DnsTestPeer>) {
        let peer = crate::dns::tests::prepare_env_from_config_str(
            "hostname = \"node-test\"\n[flags]\nno_tun = true\n[dns]\naddresses = []",
        )
        .await;
        let global_ctx = peer.get_global_ctx();
        let runtime = DnsNodeRuntime {
            mgr: DnsPeerMgr::new(peer.access(), global_ctx.clone()),
            host: Arc::new(crate::dns::host::NoDnsInterface),
            global_ctx,
            elect: Default::default(),
        };
        (runtime, peer)
    }

    async fn start_recording_rpc_server(
        rpc_addr: Url,
        resync_on_first: bool,
    ) -> anyhow::Result<(
        Arc<RecordingDnsNodeMgr>,
        StandAloneServer<RuntimeRpcListener>,
    )> {
        let mgr = Arc::new(RecordingDnsNodeMgr::new(resync_on_first));
        let mut server =
            StandAloneServer::new(runtime_rpc_listener(rpc_addr.socket_addrs(|| None)?[0]));
        server
            .registry()
            .register(DnsNodeMgrRpcServer::new_arc(mgr.clone()), "");
        server.serve().await?;
        sleep(Duration::from_millis(50)).await;
        Ok((mgr, server))
    }

    async fn occupy_dns_rpc_addr(rpc_addr: Url) -> StandAloneServer<RuntimeRpcListener> {
        let mut server = StandAloneServer::new(runtime_rpc_listener(
            rpc_addr.socket_addrs(|| None).unwrap()[0],
        ));
        server.serve().await.unwrap();
        server
    }

    #[tokio::test]
    async fn heartbeat_first_send_includes_snapshot() {
        let rpc_addr = Url::parse(&format!("tcp://127.0.0.1:{}", 49851)).unwrap();
        let (_mgr, server) = start_recording_rpc_server(rpc_addr.clone(), false)
            .await
            .unwrap();
        let (node, _peer) = build_test_runtime().await;

        let mut rpc = runtime_rpc_client(rpc_addr);
        let mut heartbeat = HeartbeatRequest {
            id: Some(node.id().into()),
            ..Default::default()
        };

        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();

        drop(server);
        sleep(Duration::from_millis(50)).await;

        assert!(heartbeat.snapshot.is_some());
        assert!(!heartbeat.digest.is_empty());
    }

    #[tokio::test]
    async fn heartbeat_clean_send_digest_only() {
        let rpc_addr = Url::parse(&format!("tcp://127.0.0.1:{}", 49852)).unwrap();
        let (mgr, server) = start_recording_rpc_server(rpc_addr.clone(), false)
            .await
            .unwrap();
        let (node, _peer) = build_test_runtime().await;

        let mut rpc = runtime_rpc_client(rpc_addr);
        let mut heartbeat = HeartbeatRequest {
            id: Some(node.id().into()),
            ..Default::default()
        };

        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();
        let _ = node.mgr.dirty.reset();
        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();

        let requests = mgr.recorded_requests().await;
        drop(server);
        sleep(Duration::from_millis(50)).await;

        assert_eq!(requests.len(), 2);
        assert!(requests[0].snapshot.is_some());
        assert!(requests[1].snapshot.is_none());
        assert_eq!(requests[0].digest, requests[1].digest);
    }

    #[tokio::test]
    async fn heartbeat_dirty_forces_full_snapshot() {
        let rpc_addr = Url::parse(&format!("tcp://127.0.0.1:{}", 49853)).unwrap();
        let (mgr, server) = start_recording_rpc_server(rpc_addr.clone(), false)
            .await
            .unwrap();
        let (node, _peer) = build_test_runtime().await;

        let mut rpc = runtime_rpc_client(rpc_addr);
        let mut heartbeat = HeartbeatRequest {
            id: Some(node.id().into()),
            ..Default::default()
        };

        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();
        node.mgr.dirty.mark();
        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();

        let requests = mgr.recorded_requests().await;
        drop(server);
        sleep(Duration::from_millis(50)).await;

        assert_eq!(requests.len(), 2);
        assert!(requests[0].snapshot.is_some());
        assert!(requests[1].snapshot.is_some());
    }

    #[tokio::test]
    async fn heartbeat_resync_triggers_second_send() {
        let rpc_addr = Url::parse(&format!("tcp://127.0.0.1:{}", 49854)).unwrap();
        let (mgr, server) = start_recording_rpc_server(rpc_addr.clone(), true)
            .await
            .unwrap();
        let (node, _peer) = build_test_runtime().await;

        let mut rpc = runtime_rpc_client(rpc_addr);
        let mut heartbeat = HeartbeatRequest {
            id: Some(node.id().into()),
            ..Default::default()
        };

        node.heartbeat(&mut rpc, &mut heartbeat).await.unwrap();

        let requests = mgr.recorded_requests().await;
        drop(server);
        sleep(Duration::from_millis(50)).await;

        assert_eq!(requests.len(), 2);
        assert!(requests[0].snapshot.is_some());
        assert!(requests[1].snapshot.is_some());
    }

    #[tokio::test]
    #[serial_test::serial(dns_integration_rpc)]
    async fn run_marks_dirty_on_dhcp_event() {
        let (node, _peer) = build_test_runtime().await;

        let _ = node.mgr.dirty.reset();
        assert!(!node.mgr.dirty.peek());

        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let node = node.clone();
            let token = token.clone();
            async move { node.run(token).await }
        });

        sleep(Duration::from_millis(50)).await;
        node.global_ctx
            .issue_event(GlobalCtxEvent::DhcpIpv4Changed(None, None));

        wait_for_condition(async || node.mgr.dirty.peek(), Duration::from_secs(2)).await;

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(feature = "management")]
    #[tokio::test]
    async fn run_marks_dirty_on_config_patched_event() {
        let (node, _peer) = build_test_runtime().await;

        let _ = node.mgr.dirty.reset();
        assert!(!node.mgr.dirty.peek());

        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let node = node.clone();
            let token = token.clone();
            async move { node.run(token).await }
        });

        sleep(Duration::from_millis(50)).await;
        node.global_ctx
            .issue_event(GlobalCtxEvent::ConfigPatched(InstanceConfigPatch::default()));

        wait_for_condition(async || node.mgr.dirty.peek(), Duration::from_secs(2)).await;

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_peer_info_updated_non_self_does_not_mark_dirty() {
        let (node, _peer) = build_test_runtime().await;

        let _ = node.mgr.dirty.reset();
        assert!(!node.mgr.dirty.peek());

        let token = CancellationToken::new();
        let handle = tokio::spawn({
            let node = node.clone();
            let token = token.clone();
            async move { node.run(token).await }
        });

        sleep(Duration::from_millis(50)).await;
        node.global_ctx
            .issue_event(GlobalCtxEvent::PeerInfoUpdated(vec![u32::MAX]));
        sleep(Duration::from_millis(200)).await;

        assert!(!node.mgr.dirty.peek());

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn run_heartbeat_error_notifies_election() {
        let (node, _peer) = build_test_runtime().await;

        let _ = node.mgr.dirty.reset();

        let token = CancellationToken::new();
        let notified = node.elect.notified();
        let handle = tokio::spawn({
            let node = node.clone();
            let token = token.clone();
            async move { node.run(token).await }
        });

        tokio::time::timeout(2 * DNS_NODE_HEARTBEAT_INTERVAL, notified)
            .await
            .expect("heartbeat failure should notify election");

        token.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .unwrap()
            .unwrap();
    }
}

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::dns::config::{
    DNS_NODE_RR_INTERVAL, DNS_SERVER_ELECTION_INTERVAL, DNS_SERVER_RPC_ADDR, DnsGlobalCtxExt,
};
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::dns::server::DnsServer;
#[cfg(feature = "tun")]
use crate::instance::instance::ArcNicCtx;
use crate::peers::NicPacketFilter;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{DnsNodeMgrRpcClientFactory, HeartbeatRequest};
use crate::proto::rpc_impl::standalone::{StandAloneClient, StandAloneServer};
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};
use crate::utils::task::CancellableTask;
use std::sync::Arc;
use tokio::sync::{Notify, broadcast};
use tokio::task::JoinSet;
use tokio::time::{Instant, sleep, sleep_until};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone)]
struct DnsNodeRuntime {
    mgr: Arc<DnsPeerMgr>,

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx, // TODO: REMOVE THIS

    peer_mgr: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,

    elect: Arc<Notify>,
}

impl DnsNodeRuntime {
    fn id(&self) -> Uuid {
        self.global_ctx.get_id()
    }

    #[instrument(skip_all, name = "DnsNode election loop")]
    async fn run_election(&self, token: CancellationToken) {
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => {
                    tracing::info!("DnsNode received shutdown signal, exiting election loop");
                    break;
                }
                _ = self.elect.notified() => {}
                _ = sleep(DNS_SERVER_ELECTION_INTERVAL) => {}
            }

            tracing::info!("trying to become DNS server");

            let mut rpc =
                StandAloneServer::new(TcpTunnelListener::new(DNS_SERVER_RPC_ADDR.clone()));

            if rpc.serve().await.is_err() {
                // Another node already owns the address — that's fine.
                tracing::info!(
                    "failed to bind RPC server, another node might have won the election"
                );
                continue;
            }

            tracing::info!("won DNS server election, starting DnsServer");

            let server = Arc::new(DnsServer::new(
                self.peer_mgr.clone(),
                self.global_ctx.clone(),
                #[cfg(feature = "tun")]
                self.nic_ctx.clone(),
            ));

            server.register(&rpc);

            self.global_ctx.set_dns_server(Some(server.clone()));
            tokio::join!(
                self.peer_mgr
                    .add_nic_packet_process_pipeline(Box::new(server.clone())),
                server.run(token.child_token())
            );

            self.global_ctx.set_dns_server(None);
            let _ = self
                .peer_mgr
                .remove_nic_packet_process_pipeline(server.id())
                .await;

            tracing::warn!("DnsServer exited, will retry election");
        }
    }

    #[instrument(skip_all, name = "DnsNode main loop")]
    async fn run(&self, token: CancellationToken) {
        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
        let mut heartbeat = HeartbeatRequest {
            id: Some(self.id().into()),

            ..Default::default()
        };
        let mut last_heartbeat = Instant::now();
        let sleep = sleep_until(last_heartbeat);
        tokio::pin!(sleep);

        let mut subscriber = self.global_ctx.subscribe();
        let mut tasks = JoinSet::new();

        loop {
            // Dynamic interval: slower if dirty (throttled), faster if clean (fast liveness check)
            let next_heartbeat = last_heartbeat
                + if self.mgr.dirty.peek() {
                    DNS_NODE_RR_INTERVAL
                } else {
                    DNS_NODE_RR_INTERVAL / 4
                };
            sleep.as_mut().reset(next_heartbeat);

            tokio::select! {
                biased;

                _ = token.cancelled() => {
                    tracing::info!("DnsNode received shutdown signal, exiting node loop");
                    break;
                }

                _ = &mut sleep => {
                    if let Err(error) = self.heartbeat(&mut rpc, &mut heartbeat).await {
                        tracing::error!(?error, "heartbeat failed");
                        self.elect.notify_one();
                    }

                    last_heartbeat = Instant::now();
                }

                _ = self.mgr.dirty.wait() => {}

                event = subscriber.recv() => {
                    match event {
                        Ok(GlobalCtxEvent::PeerInfoUpdated(peer_ids)) => {
                            for peer_id in peer_ids {
                                let mgr = self.mgr.clone();
                                tasks.spawn(async move {
                                    mgr.refresh(peer_id).await;
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
        rpc: &mut StandAloneClient<TcpTunnelConnector>,
        heartbeat: &mut HeartbeatRequest,
    ) -> anyhow::Result<()> {
        let request = if heartbeat.snapshot.is_none() || self.mgr.dirty.reset() {
            heartbeat.update(self.mgr.snapshot());
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

        tracing::trace!(?request, "sending heartbeat");
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
    task: CancellableTask,
}

impl DnsNode {
    pub fn new(
        peer_mgr: Arc<PeerManager>,
        global_ctx: ArcGlobalCtx,
        #[cfg(feature = "tun")] nic_ctx: ArcNicCtx, // TODO: REMOVE THIS
    ) -> Self {
        let runtime = DnsNodeRuntime {
            mgr: Arc::new(DnsPeerMgr::new(peer_mgr.clone(), global_ctx.clone())),
            #[cfg(feature = "tun")]
            nic_ctx,
            peer_mgr,
            global_ctx,
            elect: Default::default(),
        };

        let task = {
            let runtime = runtime.clone();
            CancellableTask::spawn(|token| async move {
                runtime.elect.notify_one();
                tokio::join!(runtime.run_election(token.clone()), runtime.run(token),);
            })
        };

        Self { runtime, task }
    }

    pub async fn stop(self) -> std::io::Result<()> {
        self.task.stop(None).await
    }
}

#[cfg(all(test, feature = "tun"))]
mod tests {
    use super::*;
    use crate::common::global_ctx::GlobalCtxEvent;
    use crate::peers::tests::create_mock_peer_manager;
    use crate::proto::api::config::InstanceConfigPatch;
    use crate::proto::dns::{DnsNodeMgrRpc, DnsNodeMgrRpcServer, HeartbeatResponse};
    use crate::proto::rpc_impl::standalone::StandAloneServer;
    use crate::proto::rpc_types;
    use crate::tunnel::common::tests::wait_for_condition;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;
    use tokio::sync::Mutex;

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

    async fn build_test_runtime() -> DnsNodeRuntime {
        let peer_mgr = create_mock_peer_manager().await;
        let global_ctx = peer_mgr.get_global_ctx();
        let nic_ctx: ArcNicCtx = Arc::new(Mutex::new(None));
        DnsNodeRuntime {
            mgr: Arc::new(DnsPeerMgr::new(peer_mgr.clone(), global_ctx.clone())),
            nic_ctx,
            peer_mgr,
            global_ctx,
            elect: Default::default(),
        }
    }

    async fn build_test_node() -> DnsNode {
        let runtime = build_test_runtime().await;
        DnsNode::new(
            runtime.peer_mgr.clone(),
            runtime.global_ctx.clone(),
            runtime.nic_ctx.clone(),
        )
    }

    async fn start_recording_rpc_server(
        resync_on_first: bool,
    ) -> anyhow::Result<(
        Arc<RecordingDnsNodeMgr>,
        StandAloneServer<TcpTunnelListener>,
    )> {
        let mgr = Arc::new(RecordingDnsNodeMgr::new(resync_on_first));
        let mut server = StandAloneServer::new(TcpTunnelListener::new(DNS_SERVER_RPC_ADDR.clone()));
        server
            .registry()
            .register(DnsNodeMgrRpcServer::new_arc(mgr.clone()), "");
        server.serve().await?;
        sleep(Duration::from_millis(50)).await;
        Ok((mgr, server))
    }

    async fn occupy_dns_rpc_addr() -> StandAloneServer<TcpTunnelListener> {
        let mut server = StandAloneServer::new(TcpTunnelListener::new(DNS_SERVER_RPC_ADDR.clone()));
        server.serve().await.unwrap();
        server
    }

    #[tokio::test]
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn heartbeat_first_send_includes_snapshot() {
        let (_mgr, server) = start_recording_rpc_server(false).await.unwrap();
        let node = build_test_runtime().await;

        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn heartbeat_clean_send_digest_only() {
        let (mgr, server) = start_recording_rpc_server(false).await.unwrap();
        let node = build_test_runtime().await;

        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn heartbeat_dirty_forces_full_snapshot() {
        let (mgr, server) = start_recording_rpc_server(false).await.unwrap();
        let node = build_test_runtime().await;

        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn heartbeat_resync_triggers_second_send() {
        let (mgr, server) = start_recording_rpc_server(true).await.unwrap();
        let node = build_test_runtime().await;

        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn run_marks_dirty_on_dhcp_event() {
        let node = build_test_runtime().await;

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

    #[tokio::test]
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn run_marks_dirty_on_config_patched_event() {
        let node = build_test_runtime().await;

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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn run_peer_info_updated_non_self_does_not_mark_dirty() {
        let node = build_test_runtime().await;

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
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn run_heartbeat_error_notifies_election() {
        let node = build_test_runtime().await;

        let _ = node.mgr.dirty.reset();

        let token = CancellationToken::new();
        let notified = node.elect.notified();
        let handle = tokio::spawn({
            let node = node.clone();
            let token = token.clone();
            async move { node.run(token).await }
        });

        tokio::time::timeout(Duration::from_secs(2), notified)
            .await
            .expect("heartbeat failure should notify election");

        token.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn id_matches_global_ctx_id() {
        let node = build_test_runtime().await;

        assert_eq!(node.id(), node.global_ctx.get_id());
    }

    #[tokio::test]
    async fn stop_without_start_is_ok() {
        let node = build_test_node().await;
        node.stop().await.unwrap();
    }

    #[tokio::test]
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn election_wins_and_sets_dns_server() {
        let node = build_test_node().await;
        let runtime = node.runtime.clone();

        wait_for_condition(
            async || runtime.global_ctx.dns_server().is_some(),
            Duration::from_secs(2),
        )
        .await;

        let global_ctx = runtime.global_ctx.clone();
        node.stop().await.unwrap();

        wait_for_condition(
            async || global_ctx.dns_server().is_none(),
            Duration::from_secs(2),
        )
        .await;
    }

    #[tokio::test]
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn election_loses_when_rpc_addr_is_occupied() {
        let holder = occupy_dns_rpc_addr().await;
        let node = build_test_node().await;
        let runtime = node.runtime.clone();

        sleep(Duration::from_millis(300)).await;
        assert!(runtime.global_ctx.dns_server().is_none());

        node.stop().await.unwrap();
        drop(holder);
    }

    #[tokio::test]
    #[serial_test::serial(dns_node_rpc_addr)]
    async fn election_retries_after_losing_then_wins() {
        let holder = occupy_dns_rpc_addr().await;
        let node = build_test_node().await;
        let runtime = node.runtime.clone();

        sleep(Duration::from_millis(300)).await;
        assert!(runtime.global_ctx.dns_server().is_none());

        drop(holder);
        sleep(DNS_NODE_RR_INTERVAL).await;
        wait_for_condition(
            async || runtime.global_ctx.dns_server().is_some(),
            Duration::from_secs(2),
        )
        .await;

        node.stop().await.unwrap();
    }
}

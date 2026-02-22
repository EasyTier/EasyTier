use crate::common::global_ctx::GlobalCtxEvent;
use crate::common::PeerId;
use crate::dns::config::DNS_SERVER_RPC_ADDR;
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::{DnsNodeMgrRpcClientFactory, DnsPeerMgrRpcServer, HeartbeatRequest};
use crate::proto::rpc_impl::standalone::StandAloneClient;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::TcpTunnelConnector;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time::{sleep_until, Instant};
use uuid::Uuid;

#[derive(Debug)]
pub struct DnsNode {
    mgr: Arc<DnsPeerMgr>,
}

impl DnsNode {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let mgr = Arc::new(DnsPeerMgr::new(peer_mgr.clone()));
        peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsPeerMgrRpcServer::new_arc(mgr.clone()),
                &peer_mgr.get_global_ctx_ref().get_network_name(),
            );

        Self { mgr }
    }

    pub fn id(&self) -> Uuid {
        self.mgr.get_global_ctx_ref().get_id()
    }

    pub async fn run(&self) {
        let mut rpc = StandAloneClient::new(TcpTunnelConnector::new(DNS_SERVER_RPC_ADDR.clone()));
        let mut heartbeat = HeartbeatRequest {
            id: Some(self.id().into()),

            ..Default::default()
        };
        let rr_interval = Duration::from_secs(1);
        let mut last_heartbeat = Instant::now();
        let sleep = sleep_until(last_heartbeat);
        tokio::pin!(sleep);

        let mut subscriber = self.mgr.get_global_ctx_ref().subscribe();
        let mut tasks = JoinSet::new();

        loop {
            let next_heartbeat = last_heartbeat
                + if self.mgr.dirty.peek() {
                    rr_interval
                } else {
                    rr_interval / 8
                };
            sleep.as_mut().reset(next_heartbeat);

            tokio::select! {
                biased;

                _ = &mut sleep => {
                    if let Err(e) = self.heartbeat(&mut rpc, &mut heartbeat).await {
                        // TODO: try to start server
                        tracing::error!("heartbeat failed: {:?}", e);
                    }

                    last_heartbeat = Instant::now();
                }

                _ = self.mgr.dirty.notify.notified() => {}

                event = subscriber.recv() => {
                    match event {
                        Ok(GlobalCtxEvent::PeerInfoUpdated(peer_ids)) => {
                            self.refresh(&mut tasks, peer_ids);
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

        let response = client.heartbeat(BaseController::default(), request).await?;
        if response.resync {
            client
                .heartbeat(BaseController::default(), heartbeat.clone())
                .await?;
        }

        Ok(())
    }

    fn refresh(&self, tasks: &mut JoinSet<()>, peer_ids: Vec<PeerId>) {
        let my_peer_id = self.mgr.my_peer_id();
        for peer_id in peer_ids {
            if peer_id == my_peer_id {
                continue;
            }
            let mgr = self.mgr.clone();
            let route = mgr.get_route();
            tasks.spawn(async move {
                if let Some(peer_info) = route.get_peer_info(peer_id).await {
                    mgr.refresh(peer_id, peer_info.dns).await;
                }
            });
        }
    }
}

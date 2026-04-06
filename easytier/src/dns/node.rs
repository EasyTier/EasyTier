use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::common::join_joinset_background;
use crate::dns::config::{DnsGlobalCtxExt, DNS_SERVER_ELECTION_INTERVAL, DNS_SERVER_RPC_ADDR};
use crate::dns::peer_mgr::DnsPeerMgr;
use crate::dns::server::DnsServer;
#[cfg(feature = "tun")]
use crate::instance::instance::ArcNicCtx;
use crate::peers::peer_manager::PeerManager;
use crate::peers::NicPacketFilter;
use crate::proto::dns::{DnsNodeMgrRpcClientFactory, HeartbeatRequest};
use crate::proto::rpc_impl::standalone::{StandAloneClient, StandAloneServer};
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::tcp::{TcpTunnelConnector, TcpTunnelListener};
use crate::utils::AsyncRuntime;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{broadcast, Notify};
use tokio::task::JoinSet;
use tokio::time::{sleep, sleep_until, Instant};
use tokio_util::sync::CancellationToken;
use tracing::instrument;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DnsNode {
    mgr: Arc<DnsPeerMgr>,

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx, // TODO: REMOVE THIS

    peer_mgr: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,

    elect: Arc<Notify>,
    runtime: AsyncRuntime,
}

impl DnsNode {
    pub fn new(
        peer_mgr: Arc<PeerManager>,
        global_ctx: ArcGlobalCtx,
        #[cfg(feature = "tun")] nic_ctx: ArcNicCtx, // TODO: REMOVE THIS
    ) -> Self {
        Self {
            mgr: Arc::new(DnsPeerMgr::new(peer_mgr.clone(), global_ctx.clone())),
            #[cfg(feature = "tun")]
            nic_ctx,
            peer_mgr,
            global_ctx,
            elect: Default::default(),
            runtime: Default::default(),
        }
    }

    pub fn id(&self) -> Uuid {
        self.global_ctx.get_id()
    }

    pub fn start(&self) {
        self.mgr.register();
        let this = self.clone();
        self.runtime.start(None, |token| async move {
            tracing::info!("starting DnsNode");
            this.elect.notify_one();
            tokio::join!(this.run_election(token.clone()), this.run(token));
        });
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        self.runtime.stop().await.unwrap_or(Ok(()))
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
        let rr_interval = Duration::from_secs(1);
        let mut last_heartbeat = Instant::now();
        let sleep = sleep_until(last_heartbeat);
        tokio::pin!(sleep);

        let mut subscriber = self.global_ctx.subscribe();
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "DnsNode".to_owned());

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
                                tasks.lock().unwrap().spawn(async move {
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

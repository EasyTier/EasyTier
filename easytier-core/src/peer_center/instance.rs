use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, SystemTime},
};

use futures::Future;
use tokio::{sync::Mutex, task::JoinSet};
use tracing::Instrument;

use crate::peers::{peer_manager::PeerManager, rpc_service::PeerManagerRpcService, PeerId};

use super::{
    server::PeerCenterServer,
    service::{PeerCenterService, PeerCenterServiceClient, PeerInfoForGlobalMap},
    Digest, Error,
};

pub struct PeerCenterClient {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

static SERVICE_ID: u32 = 5;

struct PeridicJobCtx<T> {
    peer_mgr: Arc<PeerManager>,
    job_ctx: T,
}

impl PeerCenterClient {
    pub async fn init(&self) -> Result<(), Error> {
        self.peer_mgr.get_peer_rpc_mgr().run_service(
            SERVICE_ID,
            PeerCenterServer::new(self.peer_mgr.my_node_id()).serve(),
        );

        Ok(())
    }

    async fn select_center_peer(peer_mgr: &Arc<PeerManager>) -> Option<PeerId> {
        let peers = peer_mgr.list_routes().await;
        if peers.is_empty() {
            return None;
        }
        // find peer with alphabetical smallest id.
        let mut min_peer = peer_mgr.my_node_id().to_string();
        for peer in peers.iter() {
            if peer.peer_id < min_peer {
                min_peer = peer.peer_id.clone();
            }
        }
        Some(min_peer.parse().unwrap())
    }

    async fn init_periodic_job<
        T: Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<u32, tarpc::client::RpcError>> + Send + 'static,
    >(
        &self,
        job_ctx: T,
        job_fn: (impl Fn(PeerCenterServiceClient, Arc<PeridicJobCtx<T>>) -> Fut + Send + Sync + 'static),
    ) -> () {
        let my_node_id = self.peer_mgr.my_node_id();
        let peer_mgr = self.peer_mgr.clone();
        self.tasks.lock().await.spawn(
            async move {
                let ctx = Arc::new(PeridicJobCtx {
                    peer_mgr: peer_mgr.clone(),
                    job_ctx,
                });
                tracing::warn!(?my_node_id, "before periodic job loop");
                loop {
                    let Some(center_peer) = Self::select_center_peer(&peer_mgr).await else {
                        tracing::warn!("no center peer found, sleep 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    tracing::warn!(?center_peer, "run periodic job");
                    let rpc_mgr = peer_mgr.get_peer_rpc_mgr();
                    let ret = rpc_mgr
                        .do_client_rpc_scoped(SERVICE_ID, center_peer, |c| async {
                            let client =
                                PeerCenterServiceClient::new(tarpc::client::Config::default(), c)
                                    .spawn();
                            job_fn(client, ctx.clone()).await
                        })
                        .await;

                    let Ok(sleep_time_ms) = ret else {
                        tracing::error!("periodic job to center server rpc failed: {:?}", ret);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    };

                    if sleep_time_ms > 0 {
                        tokio::time::sleep(Duration::from_millis(sleep_time_ms as u64)).await;
                    }
                }
            }
            .instrument(tracing::info_span!("periodic_job", ?my_node_id)),
        );
    }

    pub async fn new(peer_mgr: Arc<PeerManager>) -> Self {
        PeerCenterClient {
            peer_mgr,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }
}

struct PeerCenterInstance {
    peer_mgr: Arc<PeerManager>,
    client: Arc<PeerCenterClient>,
}

impl PeerCenterInstance {
    pub async fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let client = Arc::new(PeerCenterClient::new(peer_mgr.clone()).await);
        client.init().await.unwrap();

        PeerCenterInstance { peer_mgr, client }
    }

    async fn init_get_global_info_job(&self) {
        self.client
            .init_periodic_job({}, |client, _ctx| async move {
                let ret = client
                    .get_global_peer_map(tarpc::context::current(), 0)
                    .await?;

                let Ok(global_peer_map) = ret else {
                    tracing::error!(
                        "get global info from center server got error result: {:?}",
                        ret
                    );
                    return Ok(1000);
                };

                tracing::warn!("get global info from center server: {:?}", global_peer_map);

                Ok(5000)
            })
            .await;
    }

    async fn init_report_peers_job(&self) {
        struct Ctx {
            service: PeerManagerRpcService,
            need_send_peers: AtomicBool,
        }
        let ctx = Arc::new(Ctx {
            service: PeerManagerRpcService::new(self.peer_mgr.clone()),
            need_send_peers: AtomicBool::new(true),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                let my_node_id = ctx.peer_mgr.my_node_id();
                let peers: PeerInfoForGlobalMap = ctx.job_ctx.service.list_peers().await.into();
                let mut hasher = DefaultHasher::new();
                peers.hash(&mut hasher);

                let peers = if ctx.job_ctx.need_send_peers.load(Ordering::Relaxed) {
                    Some(peers)
                } else {
                    None
                };
                let mut rpc_ctx = tarpc::context::current();
                rpc_ctx.deadline = SystemTime::now() + Duration::from_secs(3);

                let ret = client
                    .report_peers(
                        rpc_ctx,
                        my_node_id.clone(),
                        peers,
                        hasher.finish() as Digest,
                    )
                    .await?;

                if matches!(ret.as_ref().err(), Some(Error::DigestMismatch)) {
                    ctx.job_ctx.need_send_peers.store(true, Ordering::Relaxed);
                    return Ok(0);
                } else if ret.is_err() {
                    tracing::error!("report peers to center server got error result: {:?}", ret);
                    return Ok(500);
                }

                ctx.job_ctx.need_send_peers.store(false, Ordering::Relaxed);
                Ok(1000)
            })
            .await;
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peer_center::server::get_global_data,
        peers::tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
    };

    use super::*;

    #[tokio::test]
    async fn test_peer_center_instance() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        let peer_mgr_c = create_mock_peer_manager().await;

        let peer_center_a = PeerCenterInstance::new(peer_mgr_a.clone()).await;
        let peer_center_b = PeerCenterInstance::new(peer_mgr_b.clone()).await;
        let peer_center_c = PeerCenterInstance::new(peer_mgr_c.clone()).await;

        peer_center_a.init_report_peers_job().await;
        peer_center_b.init_report_peers_job().await;
        peer_center_c.init_report_peers_job().await;

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.my_node_id())
            .await
            .unwrap();

        let center_peer = PeerCenterClient::select_center_peer(&peer_mgr_a)
            .await
            .unwrap();
        let center_data = get_global_data(center_peer);

        // wait center_data has 3 records for 10 seconds
        let now = std::time::Instant::now();
        loop {
            if center_data.read().await.global_peer_map.map.len() == 3 {
                println!(
                    "center data ready, {:#?}",
                    center_data.read().await.global_peer_map
                );
                break;
            }
            if now.elapsed().as_secs() > 60 {
                panic!("center data not ready");
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

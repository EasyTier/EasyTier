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
use tokio::{
    sync::{Mutex, RwLock},
    task::JoinSet,
};
use tracing::Instrument;

use crate::{
    peers::{peer_manager::PeerManager, rpc_service::PeerManagerRpcService, PeerId},
    rpc::{GetGlobalPeerMapRequest, GetGlobalPeerMapResponse},
};

use super::{
    server::PeerCenterServer,
    service::{GlobalPeerMap, PeerCenterService, PeerCenterServiceClient, PeerInfoForGlobalMap},
    Digest, Error,
};

struct PeerCenterBase {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<Mutex<JoinSet<()>>>,
    lock: Arc<Mutex<()>>,
}

static SERVICE_ID: u32 = 5;

struct PeridicJobCtx<T> {
    peer_mgr: Arc<PeerManager>,
    job_ctx: T,
}

impl PeerCenterBase {
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
        let lock = self.lock.clone();
        self.tasks.lock().await.spawn(
            async move {
                let ctx = Arc::new(PeridicJobCtx {
                    peer_mgr: peer_mgr.clone(),
                    job_ctx,
                });
                loop {
                    let Some(center_peer) = Self::select_center_peer(&peer_mgr).await else {
                        tracing::warn!("no center peer found, sleep 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    tracing::info!(?center_peer, "run periodic job");
                    let rpc_mgr = peer_mgr.get_peer_rpc_mgr();
                    let _g = lock.lock().await;
                    let ret = rpc_mgr
                        .do_client_rpc_scoped(SERVICE_ID, center_peer, |c| async {
                            let client =
                                PeerCenterServiceClient::new(tarpc::client::Config::default(), c)
                                    .spawn();
                            job_fn(client, ctx.clone()).await
                        })
                        .await;
                    drop(_g);

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

    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        PeerCenterBase {
            peer_mgr,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            lock: Arc::new(Mutex::new(())),
        }
    }
}

pub struct PeerCenterInstanceService {
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<RwLock<Digest>>,
}

#[tonic::async_trait]
impl crate::rpc::cli::peer_center_rpc_server::PeerCenterRpc for PeerCenterInstanceService {
    async fn get_global_peer_map(
        &self,
        _request: tonic::Request<GetGlobalPeerMapRequest>,
    ) -> Result<tonic::Response<GetGlobalPeerMapResponse>, tonic::Status> {
        let global_peer_map = self.global_peer_map.read().await.clone();
        Ok(tonic::Response::new(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map
                .map
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        }))
    }
}

pub struct PeerCenterInstance {
    peer_mgr: Arc<PeerManager>,

    client: Arc<PeerCenterBase>,
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<RwLock<Digest>>,
}

impl PeerCenterInstance {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        PeerCenterInstance {
            peer_mgr: peer_mgr.clone(),
            client: Arc::new(PeerCenterBase::new(peer_mgr.clone())),
            global_peer_map: Arc::new(RwLock::new(GlobalPeerMap::new())),
            global_peer_map_digest: Arc::new(RwLock::new(Digest::default())),
        }
    }

    pub async fn init(&self) {
        self.client.init().await.unwrap();
        self.init_get_global_info_job().await;
        self.init_report_peers_job().await;
    }

    async fn init_get_global_info_job(&self) {
        struct Ctx {
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,
            global_peer_map_digest: Arc<RwLock<Digest>>,
        }

        let ctx = Arc::new(Ctx {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                let mut rpc_ctx = tarpc::context::current();
                rpc_ctx.deadline = SystemTime::now() + Duration::from_secs(3);

                let ret = client
                    .get_global_peer_map(
                        rpc_ctx,
                        ctx.job_ctx.global_peer_map_digest.read().await.clone(),
                    )
                    .await?;

                let Ok(resp) = ret else {
                    tracing::error!(
                        "get global info from center server got error result: {:?}",
                        ret
                    );
                    return Ok(1000);
                };

                let Some(resp) = resp else {
                    return Ok(1000);
                };

                tracing::info!(
                    "get global info from center server: {:?}, digest: {:?}",
                    resp.global_peer_map,
                    resp.digest
                );

                *ctx.job_ctx.global_peer_map.write().await = resp.global_peer_map;
                *ctx.job_ctx.global_peer_map_digest.write().await = resp.digest;

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

    pub fn get_rpc_service(&self) -> PeerCenterInstanceService {
        PeerCenterInstanceService {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Deref;

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

        let peer_center_a = PeerCenterInstance::new(peer_mgr_a.clone());
        let peer_center_b = PeerCenterInstance::new(peer_mgr_b.clone());
        let peer_center_c = PeerCenterInstance::new(peer_mgr_c.clone());

        let peer_centers = vec![&peer_center_a, &peer_center_b, &peer_center_c];
        for pc in peer_centers.iter() {
            pc.init().await;
        }

        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.my_node_id())
            .await
            .unwrap();

        let center_peer = PeerCenterBase::select_center_peer(&peer_mgr_a)
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

        let mut digest = None;
        for pc in peer_centers.iter() {
            let rpc_service = pc.get_rpc_service();
            let now = std::time::Instant::now();
            while now.elapsed().as_secs() < 10 {
                if rpc_service.global_peer_map.read().await.map.len() == 3 {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            assert_eq!(rpc_service.global_peer_map.read().await.map.len(), 3);
            println!("rpc service ready, {:#?}", rpc_service.global_peer_map);

            if digest.is_none() {
                digest = Some(rpc_service.global_peer_map_digest.read().await.clone());
            } else {
                let v = rpc_service.global_peer_map_digest.read().await;
                assert_eq!(digest.as_ref().unwrap(), v.deref());
            }
        }

        let global_digest = get_global_data(center_peer).read().await.digest.clone();
        assert_eq!(digest.as_ref().unwrap(), &global_digest);
    }
}

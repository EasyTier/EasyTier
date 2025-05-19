use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, Instant},
};

use crossbeam::atomic::AtomicCell;
use futures::Future;
use std::sync::RwLock;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::Instrument;

use crate::{
    common::PeerId,
    peers::{
        peer_manager::PeerManager,
        route_trait::{RouteCostCalculator, RouteCostCalculatorInterface},
        rpc_service::PeerManagerRpcService,
    },
    proto::{
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, GlobalPeerMap, PeerCenterRpc,
            PeerCenterRpcClientFactory, PeerCenterRpcServer, PeerInfoForGlobalMap,
            ReportPeersRequest, ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::{server::PeerCenterServer, Digest, Error};

struct PeerCenterBase {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<Mutex<JoinSet<()>>>,
    lock: Arc<Mutex<()>>,
}

// static SERVICE_ID: u32 = 5; for compatibility with the original code
static SERVICE_ID: u32 = 50;

struct PeridicJobCtx<T> {
    peer_mgr: Arc<PeerManager>,
    center_peer: AtomicCell<PeerId>,
    job_ctx: T,
}

impl PeerCenterBase {
    pub async fn init(&self) -> Result<(), Error> {
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                PeerCenterRpcServer::new(PeerCenterServer::new(self.peer_mgr.my_peer_id())),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );
        Ok(())
    }

    async fn select_center_peer(peer_mgr: &Arc<PeerManager>) -> Option<PeerId> {
        let peers = peer_mgr.list_routes().await;
        if peers.is_empty() {
            return None;
        }
        // find peer with alphabetical smallest id.
        let mut min_peer = peer_mgr.my_peer_id();
        for peer in peers
            .iter()
            .filter(|r| r.feature_flag.map(|r| !r.is_public_server).unwrap_or(true))
        {
            let peer_id = peer.peer_id;
            if peer_id < min_peer {
                min_peer = peer_id;
            }
        }
        Some(min_peer)
    }

    async fn init_periodic_job<
        T: Send + Sync + 'static + Clone,
        Fut: Future<Output = Result<u32, rpc_types::error::Error>> + Send + 'static,
    >(
        &self,
        job_ctx: T,
        job_fn: (impl Fn(
            Box<dyn PeerCenterRpc<Controller = BaseController> + Send>,
            Arc<PeridicJobCtx<T>>,
        ) -> Fut
             + Send
             + Sync
             + 'static),
    ) -> () {
        let my_peer_id = self.peer_mgr.my_peer_id();
        let peer_mgr = self.peer_mgr.clone();
        let lock = self.lock.clone();
        self.tasks.lock().await.spawn(
            async move {
                let ctx = Arc::new(PeridicJobCtx {
                    peer_mgr: peer_mgr.clone(),
                    center_peer: AtomicCell::new(PeerId::default()),
                    job_ctx,
                });
                loop {
                    let Some(center_peer) = Self::select_center_peer(&peer_mgr).await else {
                        tracing::trace!("no center peer found, sleep 1 second");
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    };
                    ctx.center_peer.store(center_peer.clone());
                    tracing::trace!(?center_peer, "run periodic job");
                    let rpc_mgr = peer_mgr.get_peer_rpc_mgr();
                    let _g = lock.lock().await;
                    let stub = rpc_mgr
                        .rpc_client()
                        .scoped_client::<PeerCenterRpcClientFactory<BaseController>>(
                            my_peer_id,
                            center_peer,
                            peer_mgr.get_global_ctx().get_network_name(),
                        );
                    let ret = job_fn(stub, ctx.clone()).await;
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
            .instrument(tracing::info_span!("periodic_job", ?my_peer_id)),
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

#[derive(Clone)]
pub struct PeerCenterInstanceService {
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterInstanceService {
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        _: BaseController,
        _: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let global_peer_map = self.global_peer_map.read().unwrap();
        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map.clone(),
            digest: Some(self.global_peer_map_digest.load()),
        })
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        Err(anyhow::anyhow!("not implemented").into())
    }
}

pub struct PeerCenterInstance {
    peer_mgr: Arc<PeerManager>,

    client: Arc<PeerCenterBase>,
    global_peer_map: Arc<RwLock<GlobalPeerMap>>,
    global_peer_map_digest: Arc<AtomicCell<Digest>>,
    global_peer_map_update_time: Arc<AtomicCell<Instant>>,
}

impl PeerCenterInstance {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        PeerCenterInstance {
            peer_mgr: peer_mgr.clone(),
            client: Arc::new(PeerCenterBase::new(peer_mgr.clone())),
            global_peer_map: Arc::new(RwLock::new(GlobalPeerMap::default())),
            global_peer_map_digest: Arc::new(AtomicCell::new(Digest::default())),
            global_peer_map_update_time: Arc::new(AtomicCell::new(Instant::now())),
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
            global_peer_map_digest: Arc<AtomicCell<Digest>>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
        }

        let ctx = Arc::new(Ctx {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                if ctx
                    .job_ctx
                    .global_peer_map_update_time
                    .load()
                    .elapsed()
                    .as_secs()
                    > 120
                {
                    ctx.job_ctx.global_peer_map_digest.store(Digest::default());
                }

                let ret = client
                    .get_global_peer_map(
                        BaseController::default(),
                        GetGlobalPeerMapRequest {
                            digest: ctx.job_ctx.global_peer_map_digest.load(),
                        },
                    )
                    .await;

                let Ok(resp) = ret else {
                    tracing::error!(
                        "get global info from center server got error result: {:?}",
                        ret
                    );
                    return Ok(10000);
                };

                if resp == GetGlobalPeerMapResponse::default() {
                    // digest match, no need to update
                    return Ok(15000);
                }

                tracing::info!(
                    "get global info from center server: {:?}, digest: {:?}",
                    resp.global_peer_map,
                    resp.digest
                );

                *ctx.job_ctx.global_peer_map.write().unwrap() = GlobalPeerMap {
                    map: resp.global_peer_map,
                };
                ctx.job_ctx
                    .global_peer_map_digest
                    .store(resp.digest.unwrap_or_default());
                ctx.job_ctx
                    .global_peer_map_update_time
                    .store(Instant::now());

                Ok(15000)
            })
            .await;
    }

    async fn init_report_peers_job(&self) {
        struct Ctx {
            service: PeerManagerRpcService,

            last_report_peers: Mutex<BTreeSet<PeerId>>,

            last_center_peer: AtomicCell<PeerId>,
            last_report_time: AtomicCell<Instant>,
        }
        let ctx = Arc::new(Ctx {
            service: PeerManagerRpcService::new(self.peer_mgr.clone()),
            last_report_peers: Mutex::new(BTreeSet::new()),
            last_center_peer: AtomicCell::new(PeerId::default()),
            last_report_time: AtomicCell::new(Instant::now()),
        });

        self.client
            .init_periodic_job(ctx, |client, ctx| async move {
                let my_node_id = ctx.peer_mgr.my_peer_id();
                let peers: PeerInfoForGlobalMap = ctx.job_ctx.service.list_peers().await.into();
                let peer_list = peers.direct_peers.keys().map(|k| *k).collect();
                let job_ctx = &ctx.job_ctx;

                // only report when:
                // 1. center peer changed
                // 2. last report time is more than 60 seconds
                // 3. peers changed
                if ctx.center_peer.load() == ctx.job_ctx.last_center_peer.load()
                    && job_ctx.last_report_time.load().elapsed().as_secs() < 60
                    && *job_ctx.last_report_peers.lock().await == peer_list
                {
                    return Ok(5000);
                }

                let ret = client
                    .report_peers(
                        BaseController::default(),
                        ReportPeersRequest {
                            my_peer_id: my_node_id,
                            peer_infos: Some(peers),
                        },
                    )
                    .await;

                if ret.is_ok() {
                    ctx.job_ctx.last_center_peer.store(ctx.center_peer.load());
                    *ctx.job_ctx.last_report_peers.lock().await = peer_list;
                    ctx.job_ctx.last_report_time.store(Instant::now());
                } else {
                    tracing::error!("report peers to center server got error result: {:?}", ret);
                }

                Ok(5000)
            })
            .await;
    }

    pub fn get_rpc_service(&self) -> PeerCenterInstanceService {
        PeerCenterInstanceService {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_digest: self.global_peer_map_digest.clone(),
        }
    }

    pub fn get_cost_calculator(&self) -> RouteCostCalculator {
        struct RouteCostCalculatorImpl {
            global_peer_map: Arc<RwLock<GlobalPeerMap>>,

            global_peer_map_clone: GlobalPeerMap,

            last_update_time: AtomicCell<Instant>,
            global_peer_map_update_time: Arc<AtomicCell<Instant>>,
        }

        impl RouteCostCalculatorImpl {
            fn directed_cost(&self, src: PeerId, dst: PeerId) -> Option<i32> {
                self.global_peer_map_clone
                    .map
                    .get(&src)
                    .and_then(|src_peer_info| src_peer_info.direct_peers.get(&dst))
                    .and_then(|info| Some(info.latency_ms))
            }
        }

        impl RouteCostCalculatorInterface for RouteCostCalculatorImpl {
            fn calculate_cost(&self, src: PeerId, dst: PeerId) -> i32 {
                if let Some(cost) = self.directed_cost(src, dst) {
                    return cost;
                }
                self.directed_cost(dst, src).unwrap_or(100)
            }

            fn begin_update(&mut self) {
                let global_peer_map = self.global_peer_map.read().unwrap();
                self.global_peer_map_clone = global_peer_map.clone();
            }

            fn end_update(&mut self) {
                self.last_update_time
                    .store(self.global_peer_map_update_time.load());
            }

            fn need_update(&self) -> bool {
                self.last_update_time.load() < self.global_peer_map_update_time.load()
            }
        }

        Box::new(RouteCostCalculatorImpl {
            global_peer_map: self.global_peer_map.clone(),
            global_peer_map_clone: GlobalPeerMap::default(),
            last_update_time: AtomicCell::new(
                self.global_peer_map_update_time.load() - Duration::from_secs(1),
            ),
            global_peer_map_update_time: self.global_peer_map_update_time.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        peer_center::server::get_global_data,
        peers::tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        tunnel::common::tests::wait_for_condition,
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

        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        let center_peer = PeerCenterBase::select_center_peer(&peer_mgr_a)
            .await
            .unwrap();
        let center_data = get_global_data(center_peer);

        // wait center_data has 3 records for 10 seconds
        wait_for_condition(
            || async {
                if center_data.global_peer_map.len() == 4 {
                    println!("center data {:#?}", center_data.global_peer_map);
                    true
                } else {
                    false
                }
            },
            Duration::from_secs(20),
        )
        .await;

        let mut digest = None;
        for pc in peer_centers.iter() {
            let rpc_service = pc.get_rpc_service();
            wait_for_condition(
                || async { rpc_service.global_peer_map.read().unwrap().map.len() == 3 },
                Duration::from_secs(20),
            )
            .await;

            println!("rpc service ready, {:#?}", rpc_service.global_peer_map);

            if digest.is_none() {
                digest = Some(rpc_service.global_peer_map_digest.load());
            } else {
                let v = rpc_service.global_peer_map_digest.load();
                assert_eq!(digest.unwrap(), v);
            }

            let mut route_cost = pc.get_cost_calculator();
            assert!(route_cost.need_update());

            route_cost.begin_update();
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_a.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_b.my_peer_id(), peer_mgr_c.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_b.my_peer_id()) < 30
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_c.my_peer_id(), peer_mgr_a.my_peer_id()) > 50
            );
            assert!(
                route_cost.calculate_cost(peer_mgr_a.my_peer_id(), peer_mgr_c.my_peer_id()) > 50
            );
            route_cost.end_update();
            assert!(!route_cost.need_update());
        }

        let global_digest = get_global_data(center_peer).digest.load();
        assert_eq!(digest.as_ref().unwrap(), &global_digest);
    }
}

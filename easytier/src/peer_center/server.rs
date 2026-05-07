use std::{
    collections::BinaryHeap,
    hash::{Hash, Hasher},
    sync::Arc,
};

use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use tokio::task::JoinSet;

use crate::{
    common::PeerId,
    proto::{
        peer_rpc::{
            DirectConnectedPeerInfo, GetGlobalPeerMapRequest, GetGlobalPeerMapResponse,
            GlobalPeerMap, PeerCenterRpc, PeerInfoForGlobalMap, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::Digest;

#[derive(Debug, Clone, PartialEq, PartialOrd, Ord, Eq, Hash)]
pub(crate) struct SrcDstPeerPair {
    src: PeerId,
    dst: PeerId,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerCenterInfoEntry {
    info: DirectConnectedPeerInfo,
    update_time: std::time::Instant,
}

#[derive(Debug, Default)]
struct PeerCenterServerData {
    global_peer_map: DashMap<SrcDstPeerPair, PeerCenterInfoEntry>,
    peer_report_time: DashMap<PeerId, std::time::Instant>,
    digest: AtomicCell<Digest>,
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    data: Arc<PeerCenterServerData>,
    tasks: Arc<JoinSet<()>>,
}

impl PeerCenterServer {
    pub fn new() -> Self {
        let data = Arc::new(PeerCenterServerData::default());
        let weak_data = Arc::downgrade(&data);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                let Some(data) = weak_data.upgrade() else {
                    break;
                };
                PeerCenterServer::clean_outdated_peer_data(&data).await;
            }
        });

        PeerCenterServer {
            data,
            tasks: Arc::new(tasks),
        }
    }

    async fn clean_outdated_peer_data(data: &PeerCenterServerData) {
        data.peer_report_time.retain(|_, v| {
            std::time::Instant::now().duration_since(*v) < std::time::Duration::from_secs(180)
        });
        data.global_peer_map.retain(|_, v| {
            std::time::Instant::now().duration_since(v.update_time)
                < std::time::Duration::from_secs(180)
        });
    }

    fn calc_global_digest_data(data: &PeerCenterServerData) -> Digest {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        data.global_peer_map
            .iter()
            .map(|v| v.key().clone())
            .collect::<BinaryHeap<_>>()
            .into_sorted_vec()
            .into_iter()
            .for_each(|v| v.hash(&mut hasher));
        hasher.finish()
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterServer {
    type Controller = BaseController;

    #[tracing::instrument()]
    async fn report_peers(
        &self,
        _: BaseController,
        req: ReportPeersRequest,
    ) -> Result<ReportPeersResponse, rpc_types::error::Error> {
        let my_peer_id = req.my_peer_id;
        let peers = req.peer_infos.unwrap_or_default();

        tracing::debug!("receive report_peers");

        let data = &self.data;
        data.peer_report_time
            .insert(my_peer_id, std::time::Instant::now());

        for (peer_id, peer_info) in peers.direct_peers {
            let pair = SrcDstPeerPair {
                src: my_peer_id,
                dst: peer_id,
            };
            let entry = PeerCenterInfoEntry {
                info: peer_info,
                update_time: std::time::Instant::now(),
            };
            data.global_peer_map.insert(pair, entry);
        }

        data.digest
            .store(PeerCenterServer::calc_global_digest_data(data));

        Ok(ReportPeersResponse::default())
    }

    #[tracing::instrument()]
    async fn get_global_peer_map(
        &self,
        _: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let digest = req.digest;

        let data = &self.data;
        if digest == data.digest.load() && digest != 0 {
            return Ok(GetGlobalPeerMapResponse::default());
        }

        let mut global_peer_map = GlobalPeerMap::default();
        for item in data.global_peer_map.iter() {
            let (pair, entry) = item.pair();
            global_peer_map
                .map
                .entry(pair.src)
                .or_insert_with(|| PeerInfoForGlobalMap {
                    direct_peers: Default::default(),
                })
                .direct_peers
                .insert(pair.dst, entry.info);
        }

        Ok(GetGlobalPeerMapResponse {
            global_peer_map: global_peer_map.map,
            digest: Some(data.digest.load()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_clones_share_instance_data() {
        let server = PeerCenterServer::new();
        let server_clone = server.clone();

        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(100, DirectConnectedPeerInfo { latency_ms: 3 });

        server
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 99,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp = server_clone
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert_eq!(1, resp.global_peer_map.len());
        assert!(resp.global_peer_map[&99].direct_peers.contains_key(&100));
    }

    #[tokio::test]
    async fn independent_server_instances_do_not_share_data() {
        let server_a = PeerCenterServer::new();
        let server_b = PeerCenterServer::new();

        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(101, DirectConnectedPeerInfo { latency_ms: 5 });

        server_a
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 100,
                    peer_infos: Some(peers),
                },
            )
            .await
            .unwrap();

        let resp_a = server_a
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert_eq!(1, resp_a.global_peer_map.len());

        let resp_b = server_b
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        assert!(resp_b.global_peer_map.is_empty());
    }
}

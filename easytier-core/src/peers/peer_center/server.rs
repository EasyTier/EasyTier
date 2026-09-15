use std::{
    collections::BTreeMap,
    hash::{Hash, Hasher},
    sync::Arc,
};

use parking_lot::RwLock;
use tokio::task::JoinSet;

use crate::{
    config::PeerId,
    proto::{
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc, PeerInfoForGlobalMap,
            ReportPeersRequest, ReportPeersResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

use super::Digest;

#[derive(Debug, Clone)]
struct PeerCenterInfoEntry {
    peer_info: PeerInfoForGlobalMap,
    update_time: std::time::Instant,
}

#[derive(Debug, Default)]
struct PeerCenterServerState {
    peer_infos: BTreeMap<PeerId, PeerCenterInfoEntry>,
    digest: Digest,
}

#[derive(Debug, Default)]
struct PeerCenterServerData {
    state: RwLock<PeerCenterServerState>,
}

#[derive(Clone, Debug)]
pub struct PeerCenterServer {
    data: Arc<PeerCenterServerData>,
    _tasks: Arc<JoinSet<()>>,
}

impl PeerCenterServer {
    pub fn new() -> Self {
        let data = Arc::new(PeerCenterServerData::default());
        let weak_data = Arc::downgrade(&data);
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                crate::foundation::time::sleep(std::time::Duration::from_secs(10)).await;
                let Some(data) = weak_data.upgrade() else {
                    break;
                };
                PeerCenterServer::clean_outdated_peer_data(&data).await;
            }
        });

        PeerCenterServer {
            data,
            _tasks: Arc::new(tasks),
        }
    }

    async fn clean_outdated_peer_data(data: &PeerCenterServerData) {
        let mut state = data.state.write();
        let previous_len = state.peer_infos.len();
        state
            .peer_infos
            .retain(|_, entry| entry.update_time.elapsed() < std::time::Duration::from_secs(180));
        if state.peer_infos.len() != previous_len {
            state.digest = Self::calc_global_digest_data(&state.peer_infos);
        }
    }

    fn calc_global_digest_data(peer_infos: &BTreeMap<PeerId, PeerCenterInfoEntry>) -> Digest {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        peer_infos.len().hash(&mut hasher);
        for (src_peer_id, entry) in peer_infos {
            src_peer_id.hash(&mut hasher);
            entry.peer_info.direct_peers.len().hash(&mut hasher);
            for (dst_peer_id, peer_info) in &entry.peer_info.direct_peers {
                dst_peer_id.hash(&mut hasher);
                peer_info.latency_ms.hash(&mut hasher);
            }
        }
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
        let mut state = data.state.write();
        state.peer_infos.insert(
            my_peer_id,
            PeerCenterInfoEntry {
                peer_info: peers,
                update_time: std::time::Instant::now(),
            },
        );
        state.digest = PeerCenterServer::calc_global_digest_data(&state.peer_infos);

        Ok(ReportPeersResponse::default())
    }

    #[tracing::instrument()]
    async fn get_global_peer_map(
        &self,
        _: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> Result<GetGlobalPeerMapResponse, rpc_types::error::Error> {
        let digest = req.digest;

        let state = self.data.state.read();
        if digest == state.digest && digest != 0 {
            return Ok(GetGlobalPeerMapResponse::default());
        }

        let global_peer_map = state
            .peer_infos
            .iter()
            .map(|(peer_id, entry)| (*peer_id, entry.peer_info.clone()))
            .collect();

        Ok(GetGlobalPeerMapResponse {
            global_peer_map,
            digest: Some(state.digest),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::peer_rpc::DirectConnectedPeerInfo;

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

    #[tokio::test]
    async fn peer_report_replaces_removed_neighbors() {
        let server = PeerCenterServer::new();
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
        let initial = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();

        server
            .report_peers(
                BaseController::default(),
                ReportPeersRequest {
                    my_peer_id: 99,
                    peer_infos: Some(PeerInfoForGlobalMap::default()),
                },
            )
            .await
            .unwrap();
        let updated = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest {
                    digest: initial.digest.unwrap(),
                },
            )
            .await
            .unwrap();

        assert!(
            updated.digest.is_some(),
            "removed peer did not change digest"
        );
        assert!(
            updated
                .global_peer_map
                .get(&99)
                .is_none_or(|peers| peers.direct_peers.is_empty())
        );
    }

    #[tokio::test]
    async fn peer_latency_change_invalidates_digest() {
        let server = PeerCenterServer::new();
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
        let initial = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();

        let mut peers = PeerInfoForGlobalMap::default();
        peers
            .direct_peers
            .insert(100, DirectConnectedPeerInfo { latency_ms: 30 });
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
        let updated = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest {
                    digest: initial.digest.unwrap(),
                },
            )
            .await
            .unwrap();

        assert_eq!(
            updated.global_peer_map[&99].direct_peers[&100].latency_ms,
            30
        );
    }

    #[tokio::test]
    async fn expired_peer_report_invalidates_digest() {
        let server = PeerCenterServer::new();
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
        let initial = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest { digest: 0 },
            )
            .await
            .unwrap();
        {
            let mut state = server.data.state.write();
            state.peer_infos.get_mut(&99).unwrap().update_time =
                std::time::Instant::now() - std::time::Duration::from_secs(181);
        }

        PeerCenterServer::clean_outdated_peer_data(&server.data).await;
        let updated = server
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest {
                    digest: initial.digest.unwrap(),
                },
            )
            .await
            .unwrap();

        assert!(
            updated.digest.is_some(),
            "expired peer did not change digest"
        );
        assert!(!updated.global_peer_map.contains_key(&99));
    }
}

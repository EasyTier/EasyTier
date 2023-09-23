use std::sync::Arc;

use easytier_rpc::peer_manage_rpc_server::PeerManageRpc;
use easytier_rpc::{ListPeerRequest, ListPeerResponse, ListRouteRequest, ListRouteResponse};
use tonic::{Request, Response, Status};

use super::peer_manager::PeerManager;

pub struct PeerManagerRpcService {
    peer_manager: Arc<PeerManager>,
}

impl PeerManagerRpcService {
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        PeerManagerRpcService { peer_manager }
    }
}

#[tonic::async_trait]
impl PeerManageRpc for PeerManagerRpcService {
    async fn list_peer(
        &self,
        _request: Request<ListPeerRequest>, // Accept request of type HelloRequest
    ) -> Result<Response<ListPeerResponse>, Status> {
        let mut reply = ListPeerResponse::default();

        let peers = self.peer_manager.get_peer_map().list_peers().await;
        for peer in peers {
            let mut peer_info = easytier_rpc::PeerInfo::default();
            peer_info.peer_id = peer.to_string();

            if let Some(conns) = self
                .peer_manager
                .get_peer_map()
                .list_peer_conns(&peer)
                .await
            {
                peer_info.conns = conns;
            }

            reply.peer_infos.push(peer_info);
        }

        Ok(Response::new(reply))
    }

    async fn list_route(
        &self,
        _request: Request<ListRouteRequest>, // Accept request of type HelloRequest
    ) -> Result<Response<ListRouteResponse>, Status> {
        let mut reply = ListRouteResponse::default();
        reply.routes = self.peer_manager.list_routes().await;
        Ok(Response::new(reply))
    }
}

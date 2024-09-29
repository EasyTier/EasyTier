use std::sync::Arc;

use crate::proto::{
    cli::{
        DumpRouteRequest, DumpRouteResponse, ListForeignNetworkRequest, ListForeignNetworkResponse,
        ListGlobalForeignNetworkRequest, ListGlobalForeignNetworkResponse, ListPeerRequest,
        ListPeerResponse, ListRouteRequest, ListRouteResponse, PeerInfo, PeerManageRpc,
        ShowNodeInfoRequest, ShowNodeInfoResponse,
    },
    rpc_types::{self, controller::BaseController},
};

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    peer_manager: Arc<PeerManager>,
}

impl PeerManagerRpcService {
    pub fn new(peer_manager: Arc<PeerManager>) -> Self {
        PeerManagerRpcService { peer_manager }
    }

    pub async fn list_peers(&self) -> Vec<PeerInfo> {
        let mut peers = self.peer_manager.get_peer_map().list_peers().await;
        peers.extend(
            self.peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
                .iter(),
        );
        let mut peer_infos = Vec::new();
        for peer in peers {
            let mut peer_info = PeerInfo::default();
            peer_info.peer_id = peer;

            if let Some(conns) = self.peer_manager.get_peer_map().list_peer_conns(peer).await {
                peer_info.conns = conns;
            } else if let Some(conns) = self
                .peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peer_conns(peer)
                .await
            {
                peer_info.conns = conns;
            }

            peer_infos.push(peer_info);
        }

        peer_infos
    }
}

#[async_trait::async_trait]
impl PeerManageRpc for PeerManagerRpcService {
    type Controller = BaseController;
    async fn list_peer(
        &self,
        _: BaseController,
        _request: ListPeerRequest, // Accept request of type HelloRequest
    ) -> Result<ListPeerResponse, rpc_types::error::Error> {
        let mut reply = ListPeerResponse::default();

        let peers = self.list_peers().await;
        for peer in peers {
            reply.peer_infos.push(peer);
        }

        Ok(reply)
    }

    async fn list_route(
        &self,
        _: BaseController,
        _request: ListRouteRequest, // Accept request of type HelloRequest
    ) -> Result<ListRouteResponse, rpc_types::error::Error> {
        let mut reply = ListRouteResponse::default();
        reply.routes = self.peer_manager.list_routes().await;
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest, // Accept request of type HelloRequest
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let mut reply = DumpRouteResponse::default();
        reply.result = self.peer_manager.dump_route().await;
        Ok(reply)
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        _request: ListForeignNetworkRequest, // Accept request of type HelloRequest
    ) -> Result<ListForeignNetworkResponse, rpc_types::error::Error> {
        let reply = self
            .peer_manager
            .get_foreign_network_manager()
            .list_foreign_networks()
            .await;
        Ok(reply)
    }

    async fn list_global_foreign_network(
        &self,
        _: BaseController,
        _request: ListGlobalForeignNetworkRequest,
    ) -> Result<ListGlobalForeignNetworkResponse, rpc_types::error::Error> {
        Ok(self.peer_manager.list_global_foreign_network().await)
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        _request: ShowNodeInfoRequest, // Accept request of type HelloRequest
    ) -> Result<ShowNodeInfoResponse, rpc_types::error::Error> {
        Ok(ShowNodeInfoResponse {
            node_info: Some(self.peer_manager.get_my_info()),
        })
    }
}

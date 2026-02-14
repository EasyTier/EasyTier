use std::{
    ops::Deref,
    sync::{Arc, Weak},
};

use crate::{
    peer_center::instance::PeerCenterInstance,
    proto::{
        api::instance::{
            AclManageRpc, DumpRouteRequest, DumpRouteResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetForeignNetworkSummaryRequest, GetForeignNetworkSummaryResponse,
            GetWhitelistRequest, GetWhitelistResponse, ListForeignNetworkRequest,
            ListForeignNetworkResponse, ListGlobalForeignNetworkRequest,
            ListGlobalForeignNetworkResponse, ListPeerRequest, ListPeerResponse, ListRouteRequest,
            ListRouteResponse, PeerInfo, PeerManageRpc, ShowNodeInfoRequest, ShowNodeInfoResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
    utils::weak_upgrade,
};

use super::peer_manager::PeerManager;

#[derive(Clone)]
pub struct PeerManagerRpcService {
    peer_manager: Weak<PeerManager>,
    peer_center: Weak<PeerCenterInstance>,
}

impl PeerManagerRpcService {
    pub fn new(peer_manager: Arc<PeerManager>, peer_center: Arc<PeerCenterInstance>) -> Self {
        PeerManagerRpcService {
            peer_manager: Arc::downgrade(&peer_manager),
            peer_center: Arc::downgrade(&peer_center),
        }
    }

    pub async fn list_peers(
        peer_manager: &PeerManager,
        peer_center: Option<Arc<PeerCenterInstance>>,
    ) -> Vec<PeerInfo> {
        let my_peer_id = peer_manager.my_peer_id();
        let mut peers = peer_manager.get_peer_map().list_peers();
        peers.extend(
            peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .iter(),
        );
        let peer_map = peer_manager.get_peer_map();
        let mut peer_infos = Vec::new();
        for peer in peers {
            let mut peer_info = PeerInfo {
                peer_id: peer,
                default_conn_id: peer_map
                    .get_peer_default_conn_id(peer)
                    .await
                    .map(Into::into),
                directly_connected_conns: peer_map
                    .get_directly_connections_by_peer_id(peer)
                    .into_iter()
                    .map(Into::into)
                    .collect(),
                ..Default::default()
            };

            if let Some(conns) = peer_map.list_peer_conns(peer).await {
                peer_info.conns = conns;
            } else if let Some(conns) = peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peer_conns(peer)
                .await
            {
                peer_info.conns = conns;
            }

            // Distance calculation depends on the caller's context:
            // - Some(peer_center): CLI query - return outbound distance (self→peer),
            //   fetched from peer's reported GlobalPeerMap data
            // - None: GlobalPeerMap sync - return inbound distance (peer→self),
            //   calculated locally using this node's route_distance config
            peer_info.distance = match peer_center.as_ref() {
                Some(pc) => pc.get_outbound_distance(my_peer_id, peer).unwrap_or(0),
                None => peer_map.get_peer_distance(peer).await,
            };

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

        let peer_center = self.peer_center.upgrade();
        let peers = PeerManagerRpcService::list_peers(
            weak_upgrade(&self.peer_manager)?.deref(),
            peer_center,
        )
        .await;
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
        let reply = ListRouteResponse {
            routes: weak_upgrade(&self.peer_manager)?.list_routes().await,
        };
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest, // Accept request of type HelloRequest
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let reply = DumpRouteResponse {
            result: weak_upgrade(&self.peer_manager)?.dump_route().await,
        };
        Ok(reply)
    }

    async fn list_foreign_network(
        &self,
        _: BaseController,
        _request: ListForeignNetworkRequest, // Accept request of type HelloRequest
    ) -> Result<ListForeignNetworkResponse, rpc_types::error::Error> {
        let reply = weak_upgrade(&self.peer_manager)?
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
        Ok(weak_upgrade(&self.peer_manager)?
            .list_global_foreign_network()
            .await)
    }

    async fn get_foreign_network_summary(
        &self,
        _: BaseController,
        _request: GetForeignNetworkSummaryRequest,
    ) -> Result<GetForeignNetworkSummaryResponse, rpc_types::error::Error> {
        Ok(GetForeignNetworkSummaryResponse {
            summary: Some(
                weak_upgrade(&self.peer_manager)?
                    .get_foreign_network_summary()
                    .await,
            ),
        })
    }

    async fn show_node_info(
        &self,
        _: BaseController,
        _request: ShowNodeInfoRequest, // Accept request of type HelloRequest
    ) -> Result<ShowNodeInfoResponse, rpc_types::error::Error> {
        Ok(ShowNodeInfoResponse {
            node_info: Some(weak_upgrade(&self.peer_manager)?.get_my_info().await),
        })
    }
}

#[async_trait::async_trait]
impl AclManageRpc for PeerManagerRpcService {
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        _: BaseController,
        _request: GetAclStatsRequest,
    ) -> Result<GetAclStatsResponse, rpc_types::error::Error> {
        let acl_stats = weak_upgrade(&self.peer_manager)?
            .get_global_ctx()
            .get_acl_filter()
            .get_stats();
        Ok(GetAclStatsResponse {
            acl_stats: Some(acl_stats),
        })
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        _request: GetWhitelistRequest,
    ) -> Result<GetWhitelistResponse, rpc_types::error::Error> {
        let global_ctx = weak_upgrade(&self.peer_manager)?.get_global_ctx();
        let tcp_ports = global_ctx.config.get_tcp_whitelist();
        let udp_ports = global_ctx.config.get_udp_whitelist();
        tracing::info!(
            "Getting whitelist - TCP: {:?}, UDP: {:?}",
            tcp_ports,
            udp_ports
        );
        Ok(GetWhitelistResponse {
            tcp_ports,
            udp_ports,
        })
    }
}

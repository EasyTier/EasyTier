use std::sync::Arc;

use crate::{
    common::acl_processor::AclRuleBuilder,
    proto::{
        cli::{
            AclManageRpc, DumpRouteRequest, DumpRouteResponse, GetAclStatsRequest,
            GetAclStatsResponse, GetWhitelistRequest, GetWhitelistResponse,
            ListForeignNetworkRequest, ListForeignNetworkResponse, ListGlobalForeignNetworkRequest,
            ListGlobalForeignNetworkResponse, ListPeerRequest, ListPeerResponse, ListRouteRequest,
            ListRouteResponse, PeerInfo, PeerManageRpc, SetWhitelistRequest, SetWhitelistResponse,
            ShowNodeInfoRequest, ShowNodeInfoResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
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

    pub async fn list_peers(peer_manager: &PeerManager) -> Vec<PeerInfo> {
        let mut peers = peer_manager.get_peer_map().list_peers().await;
        peers.extend(
            peer_manager
                .get_foreign_network_client()
                .get_peer_map()
                .list_peers()
                .await
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

        let peers = PeerManagerRpcService::list_peers(&self.peer_manager).await;
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
            routes: self.peer_manager.list_routes().await,
        };
        Ok(reply)
    }

    async fn dump_route(
        &self,
        _: BaseController,
        _request: DumpRouteRequest, // Accept request of type HelloRequest
    ) -> Result<DumpRouteResponse, rpc_types::error::Error> {
        let reply = DumpRouteResponse {
            result: self.peer_manager.dump_route().await,
        };
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
            node_info: Some(self.peer_manager.get_my_info().await),
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
        let acl_stats = self
            .peer_manager
            .get_global_ctx()
            .get_acl_filter()
            .get_stats();
        Ok(GetAclStatsResponse {
            acl_stats: Some(acl_stats),
        })
    }

    async fn set_whitelist(
        &self,
        _: BaseController,
        request: SetWhitelistRequest,
    ) -> Result<SetWhitelistResponse, rpc_types::error::Error> {
        tracing::info!(
            "Setting whitelist - TCP: {:?}, UDP: {:?}",
            request.tcp_ports,
            request.udp_ports
        );

        let global_ctx = self.peer_manager.get_global_ctx();

        global_ctx.config.set_tcp_whitelist(request.tcp_ports);
        global_ctx.config.set_udp_whitelist(request.udp_ports);
        global_ctx
            .get_acl_filter()
            .reload_rules(AclRuleBuilder::build(&global_ctx)?.as_ref());

        Ok(SetWhitelistResponse {})
    }

    async fn get_whitelist(
        &self,
        _: BaseController,
        _request: GetWhitelistRequest,
    ) -> Result<GetWhitelistResponse, rpc_types::error::Error> {
        let global_ctx = self.peer_manager.get_global_ctx();
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

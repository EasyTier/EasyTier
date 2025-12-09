use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{self, ListPeerRequest, ListPeerResponse, PeerManageRpc},
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct PeerManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl PeerManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl PeerManageRpc for PeerManageRpcService {
    type Controller = BaseController;

    async fn list_peer(
        &self,
        ctrl: Self::Controller,
        req: ListPeerRequest,
    ) -> crate::proto::rpc_types::error::Result<ListPeerResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .list_peer(ctrl, req)
            .await
    }

    async fn list_route(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::ListRouteRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::ListRouteResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .list_route(ctrl, req)
            .await
    }

    async fn dump_route(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::DumpRouteRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::DumpRouteResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .dump_route(ctrl, req)
            .await
    }

    async fn list_foreign_network(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::ListForeignNetworkRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::ListForeignNetworkResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .list_foreign_network(ctrl, req)
            .await
    }

    async fn list_global_foreign_network(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::ListGlobalForeignNetworkRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::ListGlobalForeignNetworkResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .list_global_foreign_network(ctrl, req)
            .await
    }

    async fn get_foreign_network_summary(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::GetForeignNetworkSummaryRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::GetForeignNetworkSummaryResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .get_foreign_network_summary(ctrl, req)
            .await
    }

    async fn show_node_info(
        &self,
        ctrl: Self::Controller,
        req: crate::proto::api::instance::ShowNodeInfoRequest,
    ) -> crate::proto::rpc_types::error::Result<instance::ShowNodeInfoResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_peer_manage_service()
            .show_node_info(ctrl, req)
            .await
    }
}

use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{
            AclManageRpc, GetAclStatsRequest, GetAclStatsResponse, GetWhitelistRequest,
            GetWhitelistResponse,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct AclManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl AclManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl AclManageRpc for AclManageRpcService {
    type Controller = BaseController;

    async fn get_acl_stats(
        &self,
        ctrl: Self::Controller,
        req: GetAclStatsRequest,
    ) -> crate::proto::rpc_types::error::Result<GetAclStatsResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_acl_manage_service()
            .get_acl_stats(ctrl, req)
            .await
    }

    async fn get_whitelist(
        &self,
        ctrl: Self::Controller,
        req: GetWhitelistRequest,
    ) -> crate::proto::rpc_types::error::Result<GetWhitelistResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_acl_manage_service()
            .get_whitelist(ctrl, req)
            .await
    }
}

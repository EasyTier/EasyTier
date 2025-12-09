use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{GetVpnPortalInfoRequest, GetVpnPortalInfoResponse, VpnPortalRpc},
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct VpnPortalRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl VpnPortalRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl VpnPortalRpc for VpnPortalRpcService {
    type Controller = BaseController;

    async fn get_vpn_portal_info(
        &self,
        ctrl: Self::Controller,
        req: GetVpnPortalInfoRequest,
    ) -> crate::proto::rpc_types::error::Result<GetVpnPortalInfoResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_vpn_portal_service()
            .get_vpn_portal_info(ctrl, req)
            .await
    }
}

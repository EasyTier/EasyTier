use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{ListPortForwardRequest, ListPortForwardResponse, PortForwardManageRpc},
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct PortForwardManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl PortForwardManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl PortForwardManageRpc for PortForwardManageRpcService {
    type Controller = BaseController;

    async fn list_port_forward(
        &self,
        ctrl: Self::Controller,
        req: ListPortForwardRequest,
    ) -> crate::proto::rpc_types::error::Result<ListPortForwardResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_port_forward_manage_service()
            .list_port_forward(ctrl, req)
            .await
    }
}

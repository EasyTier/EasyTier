use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{ConnectorManageRpc, ListConnectorRequest, ListConnectorResponse},
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct ConnectorManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl ConnectorManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl ConnectorManageRpc for ConnectorManageRpcService {
    type Controller = BaseController;

    async fn list_connector(
        &self,
        ctrl: Self::Controller,
        req: ListConnectorRequest,
    ) -> crate::proto::rpc_types::error::Result<ListConnectorResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_connector_manage_service()
            .list_connector(ctrl, req)
            .await
    }
}

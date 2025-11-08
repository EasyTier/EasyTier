use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{
            ListMappedListenerRequest, ListMappedListenerResponse, MappedListenerManageRpc,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct MappedListenerManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl MappedListenerManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl MappedListenerManageRpc for MappedListenerManageRpcService {
    type Controller = BaseController;

    async fn list_mapped_listener(
        &self,
        ctrl: Self::Controller,
        req: ListMappedListenerRequest,
    ) -> crate::proto::rpc_types::error::Result<ListMappedListenerResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_mapped_listener_manage_service()
            .list_mapped_listener(ctrl, req)
            .await
    }
}

use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        file_transfer::{
            FileTransferManageRpc, StartTransferRequest, StartTransferResponse,
            ListTransfersRequest, ListTransfersResponse,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct FileTransferManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl FileTransferManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl FileTransferManageRpc for FileTransferManageRpcService {
    type Controller = BaseController;

    async fn list_transfers(
        &self,
        ctrl: Self::Controller,
        req: ListTransfersRequest,
    ) -> crate::proto::rpc_types::error::Result<ListTransfersResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_file_transfer_manage_service()
            .list_transfers(ctrl, req)
            .await
    }

    async fn start_transfer(
        &self,
        ctrl: Self::Controller,
        req: StartTransferRequest,
    ) -> crate::proto::rpc_types::error::Result<StartTransferResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_file_transfer_manage_service()
            .start_transfer(ctrl, req)
            .await
    }
}

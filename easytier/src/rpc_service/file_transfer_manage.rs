use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        file_transfer::{
            FileTransferRpc, StartTransferRequest, StartTransferResponse, TransferChunkRequest,
            TransferChunkResponse, TransferOfferRequest, TransferOfferResponse,
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
impl FileTransferRpc for FileTransferManageRpcService {
    type Controller = BaseController;

    async fn offer_file(
        &self,
        _ctrl: Self::Controller,
        _req: TransferOfferRequest,
    ) -> crate::proto::rpc_types::error::Result<TransferOfferResponse> {
         // Logic to delegate OfferFile based on instance identifier...
         // But OfferFile request doesn't have InstanceIdentifier!
         // This is a P2P RPC. Exposed via ApiRpcServer is primarily for Local Control.
         // If called here, we might fail or default to some instance?
         // For now, return error as this is not intended entry point for P2P RPC.
         Err(crate::proto::rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Not implemented for Manage API")))
    }

    async fn pull_chunk(
        &self,
        _ctrl: Self::Controller,
        _req: TransferChunkRequest,
    ) -> crate::proto::rpc_types::error::Result<TransferChunkResponse> {
        // Similarly, likely not used via Manage API
        Err(crate::proto::rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Not implemented for Manage API")))
    }

    async fn start_transfer(
        &self,
        ctrl: Self::Controller,
        req: StartTransferRequest,
    ) -> crate::proto::rpc_types::error::Result<StartTransferResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_file_transfer_service()
            .start_transfer(ctrl, req)
            .await
    }
}

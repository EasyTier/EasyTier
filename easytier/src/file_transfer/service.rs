use std::{path::PathBuf, sync::Arc};

use dashmap::DashMap;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    proto::{
        file_transfer::{
            FileTransferRpc, TransferChunkRequest, TransferChunkResponse, TransferOfferRequest,
            TransferOfferResponse, transfer_offer_response::Status as OfferStatus,
        },
        rpc_types::{self, controller::BaseController},
    },
};

pub struct FileTransferService {
    // Map transfer_id to context
    // This needs to hold state for files being sent (so we can serve PullChunk)
    // and maybe files being received (if we need to track status).
    // For now, let's focus on Serving files (Sender role handling PullChunk).
    sending_files: DashMap<String, PathBuf>, 
}

impl FileTransferService {
    pub fn new() -> Self {
        Self {
            sending_files: DashMap::new(),
        }
    }

    pub fn register_file_for_sending(&self, transfer_id: String, path: PathBuf) {
        self.sending_files.insert(transfer_id, path);
    }
}

#[async_trait::async_trait]
impl FileTransferRpc for FileTransferService {
    type Controller = BaseController;

    async fn offer_file(
        &self,
        _controller: BaseController,
        request: TransferOfferRequest,
    ) -> Result<TransferOfferResponse, rpc_types::error::Error> {
        tracing::info!("Received OfferFile request: {:?}", request);

        // TODO: Validate transfer_id and metadata.
        // TODO: Check if we are already receiving this transfer_id?
        
        // Resilience logic: Check for partial file (.et_part) to determine start_offset.
        // let temp_path = get_temp_path(&request.metadata.file_name);
        // let start_offset = if temp_path.exists() { temp_path.len() } else { 0 };

        // For now, auto-reject to prevent unauthorized transfers until we have a proper manager/UI.
        // To implement auto-accept, we would returning Accepted and spawn a background task to call PullChunk.
        
        Ok(TransferOfferResponse {
            status: OfferStatus::Rejected.into(), 
            start_offset: 0,
            message: "File transfer not yet enabled/implemented".to_string(),
        })
    }

    async fn pull_chunk(
        &self,
        _controller: BaseController,
        request: TransferChunkRequest,
    ) -> Result<TransferChunkResponse, rpc_types::error::Error> {
        let path = self.sending_files.get(&request.transfer_id)
            .ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Transfer ID not found")))?;
        
        // Security check: ensure path is valid/accessible? 
        // Assuming registered paths are safe.
        
        let mut file = File::open(path.as_path()).await
            .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("IO Error: {}", e)))?;
            
        file.seek(std::io::SeekFrom::Start(request.offset)).await
             .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Seek Error: {}", e)))?;
             
        let mut buf = vec![0u8; request.length as usize];
        let n = file.read(&mut buf).await
             .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Read Error: {}", e)))?;
             
        buf.truncate(n);
        
        Ok(TransferChunkResponse {
            data: buf,
        })
    }
}

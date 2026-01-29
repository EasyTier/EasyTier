use std::{path::PathBuf, sync::Arc};

use dashmap::DashMap;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    proto::{
        file_transfer::{
            FileTransferRpc, FileTransferRpcClientFactory, TransferChunkRequest, TransferChunkResponse,
            TransferOfferRequest, TransferOfferResponse,
            transfer_offer_response::Status as OfferStatus,
        },
        rpc_types::{self, controller::BaseController},
    },
    peers::peer_rpc::PeerRpcManager,
    common::PeerId,
};
use tokio::sync::OnceCell;
use tokio::io::AsyncWriteExt;

pub struct FileTransferService {
    sending_files: DashMap<String, PathBuf>,
    receiving_tasks: DashMap<String, tokio::task::JoinHandle<()>>, 
    
    // We need PeerRpcManager to create client for downloading.
    // Use OnceCell or Option to initialize later since PeerRpcManager might be created after Instance?
    // Or just pass it in constructor if possible. 
    // Actually PeerRpcManager is created in PeerManager which is in Instance. 
    // FileTransferService is also in Instance.
    // Let's use Weak or Arc<PeerRpcManager> initialized via a method.
    peer_rpc_mgr: OnceCell<Arc<PeerRpcManager>>,
    my_peer_id: PeerId,
}

impl FileTransferService {
    pub fn new(my_peer_id: PeerId) -> Self {
        Self {
            sending_files: DashMap::new(),
            receiving_tasks: DashMap::new(),
            peer_rpc_mgr: OnceCell::new(),
            my_peer_id,
        }
    }

    pub fn set_peer_rpc_mgr(&self, peer_rpc_mgr: Arc<PeerRpcManager>) {
        let _ = self.peer_rpc_mgr.set(peer_rpc_mgr);
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

        // Auto-accept logic
        let transfer_id = request.transfer_id.clone();
        let metadata = request.metadata.ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Missing metadata")))?;
        
        let start_offset = 0; // TODO: Implement resumability check

        // Spawn download task
        let rpc_mgr = self.peer_rpc_mgr.get().cloned().ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("PeerRpcManager not initialized")))?;
        let sender_peer_id = request.sender_peer_id;
        let my_peer_id = self.my_peer_id;
        
        let file_name = metadata.file_name.clone();
        let file_size = metadata.file_size;
        let transfer_id_clone = transfer_id.clone();

        let task = tokio::spawn(async move {
            tracing::info!("Starting download for {} from {}", file_name, sender_peer_id);
            if let Err(e) = Self::download_file(rpc_mgr, sender_peer_id, my_peer_id, transfer_id_clone, file_name, file_size, start_offset).await {
                tracing::error!("Download failed: {:?}", e);
            }
        });
        
        self.receiving_tasks.insert(transfer_id.clone(), task);

        Ok(TransferOfferResponse {
            status: OfferStatus::Accepted.into(), 
            start_offset,
            message: "Transfer accepted".to_string(),
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

impl FileTransferService {
    async fn download_file(
        rpc_mgr: Arc<PeerRpcManager>,
        sender_peer_id: PeerId,
        my_peer_id: PeerId,
        transfer_id: String,
        file_name: String,
        file_size: u64,
        start_offset: u64,
    ) -> anyhow::Result<()> {
        let client = rpc_mgr.rpc_client().scoped_client::<FileTransferRpcClientFactory<BaseController>>(
            my_peer_id,
            sender_peer_id,
            "file_transfer".to_string(),
        );

        // Save to current directory with .download extension
        let mut path = PathBuf::from(&file_name);
        path.set_extension("download");
        
        let mut file = File::options().create(true).write(true).open(&path).await?;
        file.seek(tokio::io::SeekFrom::Start(start_offset)).await?;

        let mut offset = start_offset;
        let chunk_size = 1024 * 1024; // 1MB chunks

        while offset < file_size {
            let len = std::cmp::min(chunk_size, file_size - offset);
            let req = TransferChunkRequest {
                transfer_id: transfer_id.clone(),
                offset,
                length: len as u32,
            };

            let resp = client.pull_chunk(BaseController::default(), req).await?;
            if resp.data.is_empty() {
                break; // EOF?
            }

            file.write_all(&resp.data).await?;
            offset += resp.data.len() as u64;
            
            // tracing::debug!("Downloaded {}/{} bytes", offset, file_size);
        }

        // Rename to final name
        let final_path = PathBuf::from(&file_name);
        tokio::fs::rename(&path, &final_path).await?;
        
        tracing::info!("Download completed: {:?}", final_path);
        Ok(())
    }
}


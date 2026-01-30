use std::{path::PathBuf, sync::Arc};

use dashmap::DashMap;
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    proto::{
        file_transfer::{
            FileTransferRpc, FileTransferRpcClientFactory, TransferChunkRequest, TransferChunkResponse,
            TransferOfferRequest, TransferOfferResponse, StartTransferRequest, StartTransferResponse, TransferFileMetadata,
            transfer_offer_response::Status as OfferStatus,
        },
        rpc_types::{self, controller::BaseController},
    },
    peers::{peer_rpc::PeerRpcManager, peer_manager::PeerManager, route_trait::NextHopPolicy},
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
    peer_manager: Arc<PeerManager>,
}

impl FileTransferService {
    pub fn new(peer_manager: Arc<PeerManager>, my_peer_id: PeerId) -> Self {
        Self {
            sending_files: DashMap::new(),
            receiving_tasks: DashMap::new(),
            peer_rpc_mgr: OnceCell::new(),
            my_peer_id,
            peer_manager,
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
        // 1. Check enable_file_transfer flag
        if !self.peer_manager.get_global_ctx().config.get_flags().enable_file_transfer {
            tracing::warn!("Rejecting file transfer from {}: file transfer disabled", request.sender_peer_id);
            return Ok(TransferOfferResponse {
                status: OfferStatus::Rejected.into(),
                start_offset: 0,
                message: "File transfer is disabled on this node. Enable with --enable-file-transfer".to_string(),
            });
        }

        // 2. Private-mode gate: only allow transfers on private-mode nodes.
        let sender_peer_id = request.sender_peer_id;
        let flags = self.peer_manager.get_global_ctx().get_flags();
        if !flags.private_mode {
            tracing::warn!(
                "Rejecting file transfer from {}: private mode is required",
                request.sender_peer_id
            );
            return Ok(TransferOfferResponse {
                status: OfferStatus::Rejected.into(),
                start_offset: 0,
                message: "File transfer is only allowed when private mode is enabled.".to_string(),
            });
        }

        // Determine whether this is a direct P2P connection (route to sender is the sender itself).
        let gateway_id = self
            .peer_manager
            .get_peer_map()
            .get_gateway_peer_id(sender_peer_id, NextHopPolicy::LeastHop)
            .await;
        let is_p2p = matches!(gateway_id, Some(id) if id == sender_peer_id);

        // 3. Relay Policy Verification
        if !is_p2p {
            if flags.disable_file_transfer_relay {
                return Ok(TransferOfferResponse {
                    status: OfferStatus::Rejected.into(),
                    start_offset: 0,
                    message: "Transfer rejected: File transfer via relay is disabled.".to_string(),
                });
            }

            let limit = flags.file_transfer_relay_size_limit;
            let file_size = request.metadata.as_ref().map(|m| m.file_size).unwrap_or(0);
            if limit > 0 && file_size > limit {
                return Ok(TransferOfferResponse {
                    status: OfferStatus::Rejected.into(),
                    start_offset: 0,
                    message: format!(
                        "Transfer rejected: File size {} exceeds relay limit {}",
                        file_size, limit
                    ),
                });
            }

            // Check if relay is foreign (Public/Shared)
            // If gateway peer ID != sender peer ID, it is a relay.
            // We need to check the identity of the gateway peer.
            if let Some(gateway_id) = gateway_id {
                if gateway_id != request.sender_peer_id {
                    let is_foreign_relay; 
                    
                    // A relay is foreign if it is managed by ForeignNetworkManager (implies different network identity)
                    // OR if it is in ForeignNetworkClient's peer map (Outgoing connection to foreign network/public relay).
                    if self.peer_manager.foreign_network_manager().is_foreign_peer(gateway_id) 
                       || self.peer_manager.foreign_network_client().get_peer_map().has_peer(gateway_id) {
                         is_foreign_relay = true;
                    } else {
                         // If it's not in either foreign manager, it's likely a private peer (PeerMap)
                         // or temporarily disconnected. We treat it as PRIVATE (not foreign).
                         is_foreign_relay = false;
                    }

                    if is_foreign_relay {
                        let limit = flags.file_transfer_foreign_network_relay_limit;
                        // effective limit is min(relay_limit, foreign_limit) if both set?
                        // The documentation says:
                        // 4) If both limits apply (foreign/public relay), smaller limit wins
                        // Check logic: we already checked generic limit above.
                        // So we just need to check if we exceed foreign limit here.
                        
                        if limit > 0 && file_size > limit {
                             return Ok(TransferOfferResponse {
                                status: OfferStatus::Rejected.into(),
                                start_offset: 0,
                                message: format!(
                                    "Transfer rejected: File size {} exceeds foreign relay limit {}. To transfer large files via public relay, increase --file-transfer-foreign-network-relay-limit",
                                    file_size, limit
                                ),
                            });
                        }
                    }
                }
            }
        }
        tracing::info!("Received OfferFile request: {:?}", request);

        // Auto-accept logic
        let transfer_id = request.transfer_id.clone();
        let metadata = request.metadata.ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Missing metadata")))?;
        
        let mut start_offset = 0;
        let partial_path = PathBuf::from(&metadata.file_name).with_extension("download");
        let meta_path = PathBuf::from(&metadata.file_name).with_extension("meta");

        // Check for resumable verified transfer
        let mut should_resume = false;
        if partial_path.exists() && meta_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&meta_path).await {
                // Meta format: "transfer_id|hash"
                let parts: Vec<&str> = content.split('|').collect();
                if parts.len() == 2 && parts[1] == metadata.file_hash {
                    if let Ok(m) = tokio::fs::metadata(&partial_path).await {
                        start_offset = m.len();
                        should_resume = true;
                        tracing::info!("Found valid partial file and matching hash, resuming from offset {}", start_offset);
                    }
                }
            }
        }

        if !should_resume {
            start_offset = 0;
            // Write new meta file
            let meta_content = format!("{}|{}", transfer_id, metadata.file_hash);
            if let Err(e) = tokio::fs::write(&meta_path, meta_content).await {
                 tracing::error!("Failed to write meta file: {:?}", e);
            }
        }

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

    async fn start_transfer(
        &self,
        _controller: BaseController,
        request: StartTransferRequest,
    ) -> Result<StartTransferResponse, rpc_types::error::Error> {
        let peer_id = request.peer_id;
        let file_path = PathBuf::from(request.file_path);
        
        if !file_path.exists() {
             return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("File not found")));
        }
        
        let metadata = tokio::fs::metadata(&file_path).await
            .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Metadata Error: {}", e)))?;
            
        if !metadata.is_file() {
             return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Not a file")));
        }

        let file_name = file_path.file_name().ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Invalid file name")))?
            .to_string_lossy().to_string();
        let file_size = metadata.len();
        
        let transfer_id = uuid::Uuid::new_v4().to_string();
        
        // Calculate hash
        let file_hash = Self::calculate_file_hash(&file_path).await
            .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Hash Error: {}", e)))?;

        // Register file
        self.register_file_for_sending(transfer_id.clone(), file_path.clone());
        
        // Initiate OfferFile to remote
        let rpc_mgr = self.peer_rpc_mgr.get().cloned().ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("PeerRpcManager not initialized")))?;
        
        let client = rpc_mgr.rpc_client().scoped_client::<FileTransferRpcClientFactory<BaseController>>(
            self.my_peer_id,
            peer_id,
            "file_transfer".to_string(),
        );

        let offer_req = TransferOfferRequest {
            transfer_id: transfer_id.clone(),
            sender_peer_id: self.my_peer_id,
            metadata: Some(TransferFileMetadata {
                file_name,
                file_size,
                file_hash, 
                is_dir: false,
            }),
        };

        let resp = client.offer_file(BaseController::default(), offer_req).await?;
        
        if resp.status != OfferStatus::Accepted as i32 {
             self.sending_files.remove(&transfer_id);
             return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Transfer rejected by peer: {}", resp.message)));
        }

        Ok(StartTransferResponse {
            transfer_id,
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
        
        // Open file in append mode if resuming, otherwise create new
        let mut file = if start_offset > 0 {
            File::options().write(true).open(&path).await?
        } else {
            File::options().create(true).write(true).truncate(true).open(&path).await?
        };

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
        
        // Clean up .meta file
        let mut meta_path = PathBuf::from(&file_name);
        meta_path.set_extension("meta");
        let _ = tokio::fs::remove_file(meta_path).await;

        tracing::info!("Download completed: {:?}", final_path);
        Ok(())
    }

    async fn calculate_file_hash(path: &PathBuf) -> anyhow::Result<String> {
        use sha2::{Sha256, Digest};
        let mut file = File::open(path).await?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 1024 * 1024]; // 1MB buffer on heap

        loop {
            let count = file.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}


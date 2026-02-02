use std::{path::PathBuf, sync::Arc};

use dashmap::DashMap;

use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{
    proto::{
        file_transfer::{
            FileTransferRpc, FileTransferRpcClientFactory, TransferChunkRequest, TransferChunkResponse,
            TransferOfferRequest, TransferOfferResponse, StartTransferRequest, StartTransferResponse, TransferFileMetadata,
            transfer_offer_response::Status as OfferStatus, ListTransfersRequest, ListTransfersResponse, TransferInfo, TransferState,
            FileTransferManageRpc, FileTransferManageRpcClientFactory,
        },
        rpc_types::{self, controller::BaseController},
    },
    peers::{peer_rpc::PeerRpcManager, peer_manager::PeerManager, route_trait::NextHopPolicy},
    common::PeerId,
};
use tokio::sync::OnceCell;
use tokio::io::AsyncWriteExt;
use std::time::SystemTime;

#[derive(Debug, Clone)]
struct ActiveTransfer {
    pub info: TransferInfo,
    pub last_updated: SystemTime,
}

pub struct FileTransferService {
    sending_files: DashMap<String, PathBuf>,
    receiving_tasks: DashMap<String, tokio::task::JoinHandle<()>>, 
    active_transfers: DashMap<String, ActiveTransfer>,
    
    // We need PeerRpcManager to create client for downloading.
    // Use OnceCell or Option to initialize later since PeerRpcManager might be created after Instance?
    // Or just pass it in constructor if possible. 
    // Actually PeerRpcManager is created in PeerManager which is in Instance. 
    // FileTransferService is also in Instance.
    // Let's use Weak or Arc<PeerRpcManager> initialized via a method.
    // We need PeerRpcManager to create client for downloading.
    // Use OnceCell or Option to initialize later since PeerRpcManager might be created after Instance?
    // Or just pass it in constructor if possible. 
    // Actually PeerRpcManager is created in PeerManager which is in Instance. 
    // FileTransferService is also in Instance.
    // Let's use Weak or Arc<PeerRpcManager> initialized via a method.
    peer_rpc_mgr: OnceCell<Arc<PeerRpcManager>>,
    me: OnceCell<std::sync::Weak<FileTransferService>>,
    my_peer_id: PeerId,
    peer_manager: Arc<PeerManager>,
}

impl FileTransferService {
    pub fn new(peer_manager: Arc<PeerManager>, my_peer_id: PeerId) -> Self {
        Self {
            sending_files: DashMap::new(),
            receiving_tasks: DashMap::new(),
            active_transfers: DashMap::new(),
            peer_rpc_mgr: OnceCell::new(),
            me: OnceCell::new(),
            my_peer_id,
            peer_manager,
        }
    }

    pub fn set_peer_rpc_mgr(&self, peer_rpc_mgr: Arc<PeerRpcManager>) {
        let _ = self.peer_rpc_mgr.set(peer_rpc_mgr);
    }

    pub fn set_self_ref(&self, me: std::sync::Weak<FileTransferService>) {
        let _ = self.me.set(me);
    }

    pub fn register_file_for_sending(&self, transfer_id: String, path: PathBuf) {
        self.sending_files.insert(transfer_id, path);
    }

    fn update_transfer_status(&self, transfer_id: &str, status: TransferState, msg: &str) {
        if let Some(mut entry) = self.active_transfers.get_mut(transfer_id) {
            entry.info.status = status as i32;
            if !msg.is_empty() {
                entry.info.error_message = msg.to_string();
            }
            entry.last_updated = SystemTime::now();
        }
    }
    
    fn update_transfer_progress(&self, transfer_id: &str, transferred: u64, speed: u64) {
        if let Some(mut entry) = self.active_transfers.get_mut(transfer_id) {
            entry.info.transferred_bytes = transferred;
            entry.info.speed = speed;
            entry.last_updated = SystemTime::now();
        }
    }

    fn update_sender_progress(&self, transfer_id: &str, transferred: u64) {
        if let Some(mut entry) = self.active_transfers.get_mut(transfer_id) {
            let now = SystemTime::now();
            let duration = now.duration_since(entry.last_updated).unwrap_or_default();
            let delta = transferred.saturating_sub(entry.info.transferred_bytes);
            if duration.as_secs_f64() > 0.0 && delta > 0 {
                entry.info.speed = (delta as f64 / duration.as_secs_f64()) as u64;
            }
            entry.info.transferred_bytes = transferred;
            entry.last_updated = now;
            if entry.info.transferred_bytes >= entry.info.file_size {
                entry.info.status = TransferState::Completed as i32;
            }
        }
    }

    /// Sanitize filename to prevent path traversal, absolute paths, and drive letter attacks
    fn sanitize_filename(filename: &str) -> Result<String, rpc_types::error::Error> {
        // Remove all path separators and normalize
        let cleaned = filename
            .replace('/', "")
            .replace('\\', "")
            .replace('\0', ""); // Null byte protection

        // Check for empty filename
        if cleaned.is_empty() {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Filename cannot be empty")
            ));
        }

        // Reject "." or ".."
        if cleaned == "." || cleaned == ".." {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Invalid filename")
            ));
        }

        // Reject overly long names
        if cleaned.len() > 255 {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Filename too long")
            ));
        }

        // Check for absolute path indicators
        if cleaned.starts_with('/') || cleaned.starts_with('\\') {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Absolute paths are not allowed")
            ));
        }

        // Check for Windows drive letters (e.g., "C:", "D:")
        if cleaned.len() >= 2 && cleaned.chars().nth(1) == Some(':') {
            let first_char = cleaned.chars().next().unwrap();
            if first_char.is_ascii_alphabetic() {
                return Err(rpc_types::error::Error::ExecutionError(
                    anyhow::anyhow!("Drive letter paths are not allowed")
                ));
            }
        }

        // Reject Windows reserved device names (case-insensitive), even with extensions.
        let upper = cleaned.to_ascii_uppercase();
        let base = upper.split('.').next().unwrap_or(&upper);
        const RESERVED: [&str; 22] = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        if RESERVED.contains(&base) {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Reserved filename is not allowed")
            ));
        }

        // Use Path::file_name() as final validation
        let path = std::path::Path::new(&cleaned);
        let final_name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Invalid filename after sanitization")
            ))?
            .to_string();

        // Final safety check: ensure result equals cleaned (no path components)
        if final_name != cleaned {
            return Err(rpc_types::error::Error::ExecutionError(
                anyhow::anyhow!("Filename contains invalid path components")
            ));
        }

        Ok(final_name)
    }

    /// Check if a path is a symbolic link
    async fn check_not_symlink(path: &std::path::Path) -> Result<(), rpc_types::error::Error> {
        if let Ok(metadata) = tokio::fs::symlink_metadata(path).await {
            if metadata.file_type().is_symlink() {
                return Err(rpc_types::error::Error::ExecutionError(
                    anyhow::anyhow!("Symbolic links are not allowed for file transfers")
                ));
            }
        }
        Ok(())
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
            // Receiver rejects transfers arriving via relay (not direct P2P).
            if flags.disable_file_from_relay {
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
                                    "Transfer rejected: File size {} exceeds foreign relay limit {}. To transfer large files via public relay, increase --file-foreign-limit",
                                    file_size, limit
                                ),
                            });
                        }
                    }
                }
            }
        }


        // 4. Resource Limits: Concurrent Transfers
        // Limit total active transfers (incoming + outgoing) to prevent resource exhaustion
        const MAX_CONCURRENT_TRANSFERS: usize = 10;
        let in_progress = self.active_transfers
            .iter()
            .filter(|kv| kv.value().info.status == TransferState::InProgress as i32)
            .count();
        if in_progress >= MAX_CONCURRENT_TRANSFERS {
            tracing::warn!("Rejecting file transfer: too many active transfers ({})", in_progress);
            return Ok(TransferOfferResponse {
                status: OfferStatus::Rejected.into(),
                start_offset: 0,
                message: "Transfer rejected: Too many active file transfers".to_string(),
            });
        }

        tracing::info!("Received OfferFile request: {:?}", request);

        let transfer_id = request.transfer_id.clone();
        let metadata = request.metadata.ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Missing metadata")))?;

        // Sanitize file name with comprehensive security checks
        let file_name = Self::sanitize_filename(&metadata.file_name)?;

        // 6. Configured Download Directory
        let flags = self.peer_manager.get_global_ctx().config.get_flags();
        let transfer_dir = if flags.file_transfer_dir.is_empty() {
            PathBuf::from("downloads")
        } else {
            PathBuf::from(&flags.file_transfer_dir)
        };

        // Ensure directory exists
        if let Err(e) = tokio::fs::create_dir_all(&transfer_dir).await {
            tracing::error!("Failed to create download directory {:?}: {:?}", transfer_dir, e);
             return Ok(TransferOfferResponse {
                status: OfferStatus::Rejected.into(),
                start_offset: 0,
                message: format!("Transfer rejected: Failed to prepare download directory: {}", e),
            });
        }
        if let Ok(abs_dir) = tokio::fs::canonicalize(&transfer_dir).await {
            tracing::info!("File transfer download dir: {:?}", abs_dir);
        }

        // 5. Overwrite Protection
        // Check if the final file already exists to prevent accidental overwrites
        // Resolve path relative to transfer_dir
        let final_target_path = transfer_dir.join(&file_name);
        if final_target_path.exists() {
             tracing::warn!("Rejecting file transfer: File {:?} already exists", final_target_path);
             return Ok(TransferOfferResponse {
                status: OfferStatus::Rejected.into(),
                start_offset: 0,
                message: format!("Transfer rejected: File '{}' already exists", file_name),
            });
        }
        
        // Canonicalize transfer_dir if possible, or just use as is. 
        // We trust the config to be reasonable or relative to CWD.

        // Register incoming transfer
        self.active_transfers.insert(transfer_id.clone(), ActiveTransfer {
            info: TransferInfo {
                transfer_id: transfer_id.clone(),
                file_name: file_name.clone(), // Use sanitized name
                file_size: metadata.file_size,
                transferred_bytes: 0,
                speed: 0,
                status: TransferState::InProgress as i32,
                error_message: "".to_string(),
                is_sender: false,
                peer_id: request.sender_peer_id.to_string(),
                start_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), 
            },
            last_updated: SystemTime::now(),
        });
        
        let mut start_offset = 0;
        let partial_path = transfer_dir.join(&transfer_id).with_extension("download");
        let meta_path = transfer_dir.join(&transfer_id).with_extension("meta");

        // Check for resumable verified transfer (with TOCTOU mitigation)
        let mut should_resume = false;
        
        // Atomic check: read meta file and verify both transfer_id and hash
        if let Ok(content) = tokio::fs::read_to_string(&meta_path).await {
            // Meta format: "transfer_id|hash"
            let parts: Vec<&str> = content.split('|').collect();
            
            // Verify BOTH transfer_id and hash to prevent replay attacks
            if parts.len() == 2 
                && parts[0] == transfer_id 
                && parts[1] == metadata.file_hash 
            {
                // Now check partial file metadata atomically
                if let Ok(m) = tokio::fs::metadata(&partial_path).await {
                    // Verify it's actually a file, not a symlink or directory
                    if m.is_file() {
                        start_offset = m.len();
                        should_resume = true;
                        tracing::info!(
                            "Resuming transfer {} from offset {} (verified transfer_id and hash)",
                            transfer_id, start_offset
                        );
                    } else {
                        tracing::warn!("Partial file exists but is not a regular file, starting fresh");
                    }
                }
            } else {
                tracing::warn!(
                    "Meta file exists but transfer_id or hash mismatch, starting fresh transfer"
                );
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
        
        let file_name = file_name.clone(); // Use sanitized name
        let file_size = metadata.file_size;
        let transfer_id_clone = transfer_id.clone();

        let self_clone = self.me.get().and_then(|w| w.upgrade());

        let expected_hash = metadata.file_hash.clone();
        let task = tokio::spawn(async move {
            tracing::info!("Starting download for {} from {}", file_name, sender_peer_id);
            let result = Self::download_file(
                rpc_mgr,
                sender_peer_id,
                my_peer_id,
                transfer_id_clone.clone(),
                file_name,
                file_size,
                expected_hash,
                start_offset,
                transfer_dir,
                self_clone.clone(),
            ).await;
            
            if let Some(s) = self_clone {
                match &result {
                    Ok(_) => s.update_transfer_status(&transfer_id_clone, TransferState::Completed, ""),
                    Err(e) => s.update_transfer_status(&transfer_id_clone, TransferState::Failed, &e.to_string()),
                }
            }

            if let Err(e) = result {
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
        const MAX_CHUNK_SIZE: u32 = 1024 * 1024; // 1MB
        let path = self.sending_files.get(&request.transfer_id)
            .ok_or_else(|| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Transfer ID not found")))?;
        let metadata = tokio::fs::metadata(path.as_path()).await
            .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Metadata Error: {}", e)))?;
        let file_size = metadata.len();

        if request.offset > file_size {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Invalid offset")));
        }
        if request.length == 0 {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Invalid length")));
        }
        let remaining = file_size - request.offset;
        let length = std::cmp::min(MAX_CHUNK_SIZE as u64, std::cmp::min(request.length as u64, remaining));
        if length == 0 {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Invalid length")));
        }

        let mut file = File::open(path.as_path()).await
            .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("IO Error: {}", e)))?;
            
        file.seek(std::io::SeekFrom::Start(request.offset)).await
             .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Seek Error: {}", e)))?;
             
        let mut buf = vec![0u8; length as usize];
        let n = file.read(&mut buf).await
             .map_err(|e| rpc_types::error::Error::ExecutionError(anyhow::anyhow!("Read Error: {}", e)))?;
             
        buf.truncate(n);

        let transferred = request.offset + n as u64;
        self.update_sender_progress(&request.transfer_id, transferred);
        
        Ok(TransferChunkResponse {
            data: buf,
        })
    }
}

#[async_trait::async_trait]
impl FileTransferManageRpc for FileTransferService {
    type Controller = BaseController;
    
    async fn list_transfers(
        &self,
        _controller: BaseController,
        _request: ListTransfersRequest,
    ) -> Result<ListTransfersResponse, rpc_types::error::Error> {
        let transfers = self.active_transfers.iter().map(|kv| kv.value().info.clone()).collect();
        Ok(ListTransfersResponse {
            transfers,
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
        
        // Check for symbolic links
        Self::check_not_symlink(&file_path).await?;
        
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
        
        // Register outgoing transfer
        self.active_transfers.insert(transfer_id.clone(), ActiveTransfer {
            info: TransferInfo {
                transfer_id: transfer_id.clone(),
                file_name: file_name.clone(),
                file_size,
                transferred_bytes: 0,
                speed: 0,
                status: TransferState::InProgress as i32,
                error_message: "".to_string(),
                is_sender: true,
                peer_id: peer_id.to_string(),
                start_time: SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs(), 
            },
            last_updated: SystemTime::now(),
        });

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
             self.update_transfer_status(
                 &transfer_id,
                 TransferState::Failed,
                 &format!("Transfer rejected by peer: {}", resp.message),
             );
             return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                 "Transfer rejected by peer: {}",
                 resp.message
             )));
        }

        if resp.start_offset > 0 {
            let transferred = resp.start_offset.min(file_size);
            self.update_sender_progress(&transfer_id, transferred);
        }

        if resp.start_offset >= file_size {
            self.update_transfer_status(&transfer_id, TransferState::Completed, "");
        }

        Ok(StartTransferResponse {
            transfer_id,
        })
    }
}

impl FileTransferService {
    #[allow(clippy::too_many_arguments)]
    async fn download_file(
        rpc_mgr: Arc<PeerRpcManager>,
        sender_peer_id: PeerId,
        my_peer_id: PeerId,
        transfer_id: String,
        file_name: String,
        file_size: u64,
        expected_hash: String,
        start_offset: u64,
        transfer_dir: PathBuf,
        service: Option<Arc<FileTransferService>>,
    ) -> anyhow::Result<()> {
        let client = rpc_mgr.rpc_client().scoped_client::<FileTransferRpcClientFactory<BaseController>>(
            my_peer_id,
            sender_peer_id,
            "file_transfer".to_string(),
        );

        // Re-sanitize filename for extra safety (defense in depth)
        // This should never fail since offer_file already validated it,
        // but we validate again to prevent any potential attack vector
        let safe_name = file_name.replace('/', "").replace('\\', "");
        if safe_name.is_empty() || safe_name != file_name {
            return Err(anyhow::anyhow!("Filename validation failed in download_file"));
        }

        // Use configured transfer directory
        let mut path = transfer_dir.join(&transfer_id);
        path.set_extension("download");
        
        // Verify the constructed path works (check for directory traversal relative to transfer_dir is hard without canonicalization)
        // usage of join() with safe_name (without separators) should be safe.
        // We trust transfer_dir from offer_file (which came from verified config).
        
        // Open file in append mode if resuming, otherwise create new
        let mut file = if start_offset > 0 {
            File::options().write(true).open(&path).await?
        } else {
            File::options().create(true).write(true).truncate(true).open(&path).await?
        };

        file.seek(tokio::io::SeekFrom::Start(start_offset)).await?;

        let mut offset = start_offset;
        let chunk_size = 1024 * 1024; // 1MB chunks
        
        let mut last_update_time = tokio::time::Instant::now();
        let mut bytes_since_last_update = 0;

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
            
            bytes_since_last_update += resp.data.len() as u64;
            let now = tokio::time::Instant::now();
            let duration = now.duration_since(last_update_time);
            if duration.as_secs_f64() >= 1.0 {
                let speed = (bytes_since_last_update as f64 / duration.as_secs_f64()) as u64;
                if let Some(s) = &service {
                    s.update_transfer_progress(&transfer_id, offset, speed);
                }
                last_update_time = now;
                bytes_since_last_update = 0;
            }
            
            // tracing::debug!("Downloaded {}/{} bytes", offset, file_size);
        }

        file.flush().await?;
        drop(file);

        // Verify file hash before finalizing
        let actual_hash = Self::calculate_file_hash(&path).await?;
        if actual_hash != expected_hash {
            let _ = tokio::fs::remove_file(&path).await;
            return Err(anyhow::anyhow!("Hash mismatch after download"));
        }

        // Rename to final name
        let final_path = transfer_dir.join(&safe_name);
        // Finalize via rename for wider filesystem compatibility.
        if final_path.exists() {
            return Err(anyhow::anyhow!("File {} already exists", safe_name));
        }
        if let Err(e) = tokio::fs::rename(&path, &final_path).await {
            return Err(anyhow::anyhow!("Finalization failed (rename): {}", e));
        }
        
        // Clean up .meta file
        let mut meta_path = transfer_dir.join(&transfer_id);
        meta_path.set_extension("meta");
        let _ = tokio::fs::remove_file(meta_path).await;

        if let Some(s) = &service {
            s.update_transfer_progress(&transfer_id, file_size, 0);
        }

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


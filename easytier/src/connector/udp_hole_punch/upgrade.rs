use std::sync::Arc;

use async_trait::async_trait;
use tokio::task::JoinHandle;

use crate::common::PeerId;
use crate::peers::{
    peer_manager::PeerManager,
    peer_task::PeerTaskLauncher,
};

#[derive(Clone)]
pub struct PeerUpgradeTaskLauncher {}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct UpgradeTaskInfo {
    pub peer_id: PeerId,
    pub remote_url: url::Url,
}

pub struct UpgradeConnectorData {
    peer_mgr: Arc<PeerManager>,
}

impl UpgradeConnectorData {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self { peer_mgr })
    }

    pub async fn get_peers_to_upgrade(&self) -> Vec<UpgradeTaskInfo> {
        let mut upgrades = Vec::new();
        
        let peers_config = self.peer_mgr.get_global_ctx().config.get_peers();
        
        let upgrade_uris: Vec<_> = peers_config
            .iter()
            .filter(|c| c.allow_p2p_upgrade.unwrap_or(false))
            .map(|c| c.uri.clone())
            .collect();
        
        if upgrade_uris.is_empty() {
            return upgrades;
        }
        
        let peer_map = self.peer_mgr.get_peer_map();
        let connected_peers = peer_map.list_peers_with_conn().await;
        
        for peer_id in connected_peers {
            if let Some(conns) = peer_map.list_peer_conns(peer_id).await {
                for conn in conns.iter() {
                    if let Some(tunnel) = &conn.tunnel {
                        if let Some(remote_addr) = &tunnel.remote_addr {
                            let conn_url = url::Url::parse(&remote_addr.url).ok();
                            
                            if let Some(ref conn_url) = conn_url {
                                if upgrade_uris.iter().any(|u| u == conn_url) {
                                    upgrades.push(UpgradeTaskInfo {
                                        peer_id,
                                        remote_url: conn_url.clone(),
                                    });
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        upgrades
    }
}

#[async_trait]
impl PeerTaskLauncher for PeerUpgradeTaskLauncher {
    type Data = Arc<UpgradeConnectorData>;
    type CollectPeerItem = UpgradeTaskInfo;
    type TaskRet = ();

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data {
        UpgradeConnectorData::new(peer_mgr)
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        data.get_peers_to_upgrade().await
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let peer_mgr = data.peer_mgr.clone();
        let remote_url = item.remote_url.clone();
        
        tokio::spawn(async move {
            tracing::info!(?remote_url, "P2P upgrade: triggering hole punch for peer");
            
            // Trigger UDP connection to the peer's UDP address
            // This will initiate NAT traversal
            // The existing UdpHolePunchPeerTaskLauncher will handle the actual punching
            // We just need to signal that we want to try upgrading
            
            // Get the global context to access configuration
            let global_ctx = peer_mgr.get_global_ctx();
            
            // Check if UDP hole punching is enabled
            if global_ctx.get_flags().disable_p2p {
                tracing::debug!("P2P upgrade skipped: P2P is disabled");
                return Ok(());
            }
            
            if global_ctx.get_flags().disable_udp_hole_punching {
                tracing::debug!("P2P upgrade skipped: UDP hole punching is disabled");
                return Ok(());
            }
            
            // The actual hole punch will be handled by the main UdpHolePunchPeerTaskLauncher
            // which now checks for allow_p2p_upgrade flag
            // This task just ensures the upgrade path is recognized
            
            tracing::info!(?remote_url, "P2P upgrade task completed, hole punch will be attempted");
            Ok(())
        })
    }

    fn loop_interval_ms(&self) -> u64 {
        30000
    }
}

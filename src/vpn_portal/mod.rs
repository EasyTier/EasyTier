// with vpn portal, user can use other vpn client to connect to easytier servers
// without installing easytier.
// these vpn client include:
// 1. wireguard
// 2. openvpn (TODO)
// 3. shadowsocks (TODO)

use std::sync::Arc;

use crate::{common::global_ctx::ArcGlobalCtx, peers::peer_manager::PeerManager};

pub mod wireguard;

#[async_trait::async_trait]
pub trait VpnPortal: Send + Sync {
    async fn start(
        &mut self,
        global_ctx: ArcGlobalCtx,
        peer_mgr: Arc<PeerManager>,
    ) -> anyhow::Result<()>;
    async fn dump_client_config(&self, peer_mgr: Arc<PeerManager>) -> String;
    fn name(&self) -> String;
    async fn list_clients(&self) -> Vec<String>;
}

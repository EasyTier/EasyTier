// with vpn portal, user can use other vpn client to connect to easytier servers
// without installing easytier.
// these vpn client include:
// 1. wireguard
// 2. openvpn (TODO)
// 3. shadowsocks (TODO)

use std::sync::Arc;

use crate::{common::global_ctx::ArcGlobalCtx, peers::peer_manager::PeerManager};

#[cfg(feature = "wireguard")]
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

pub struct NullVpnPortal;

#[async_trait::async_trait]
impl VpnPortal for NullVpnPortal {
    async fn start(
        &mut self,
        _global_ctx: ArcGlobalCtx,
        _peer_mgr: Arc<PeerManager>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    async fn dump_client_config(&self, _peer_mgr: Arc<PeerManager>) -> String {
        "".to_string()
    }

    fn name(&self) -> String {
        "null".to_string()
    }

    async fn list_clients(&self) -> Vec<String> {
        vec![]
    }
}

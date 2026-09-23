//! The DNS runtime's projection of peer routing and RPC capabilities.

use std::sync::Arc;

use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    config::PeerId,
    peers::{peer_manager::PeerManagerCore, peer_rpc::PeerRpcManager},
    proto::{
        dns::{
            DnsPeerMgrRpc, DnsPeerMgrRpcClientFactory, DnsPeerMgrRpcServer, GetExportConfigRequest,
            GetExportConfigResponse,
        },
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Debug, Default)]
pub(crate) struct DnsExportVersion {
    pub(crate) response: Option<GetExportConfigResponse>,
    pub(crate) digest: Vec<u8>,
}

/// Derived DNS data, published independently of whole runtime configuration replacements.
/// The route advertisement and RPC response always read the same immutable version.
#[derive(Debug)]
pub(crate) struct DnsExportState {
    version: tokio::sync::watch::Sender<Arc<DnsExportVersion>>,
    registrations: std::sync::Mutex<usize>,
}

impl Default for DnsExportState {
    fn default() -> Self {
        Self {
            version: tokio::sync::watch::channel(Arc::new(DnsExportVersion::default())).0,
            registrations: std::sync::Mutex::new(0),
        }
    }
}

impl DnsExportState {
    pub(crate) fn snapshot(&self) -> Arc<DnsExportVersion> {
        self.version.borrow().clone()
    }

    pub(crate) fn subscribe(&self) -> tokio::sync::watch::Receiver<Arc<DnsExportVersion>> {
        self.version.subscribe()
    }

    fn publish(&self, response: Option<GetExportConfigResponse>) {
        let digest = response
            .as_ref()
            .map(|response| Sha256::digest(response.encode_to_vec()).to_vec())
            .unwrap_or_default();
        self.version.send_if_modified(|current| {
            if current.response == response {
                return false;
            }
            *current = Arc::new(DnsExportVersion { response, digest });
            true
        });
    }
}

#[async_trait::async_trait]
impl DnsPeerMgrRpc for DnsExportState {
    type Controller = BaseController;

    async fn get_export_config(
        &self,
        _: BaseController,
        _: GetExportConfigRequest,
    ) -> rpc_types::error::Result<GetExportConfigResponse> {
        Ok(self.snapshot().response.clone().unwrap_or_default())
    }
}

/// DNS-specific access; callers never receive the underlying peer manager or route engine.
pub struct CoreDnsPeerAccess {
    peer_manager: Arc<PeerManagerCore>,
    export: Arc<DnsExportState>,
}

impl std::fmt::Debug for CoreDnsPeerAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreDnsPeerAccess")
            .field("peer_id", &self.local_peer_id())
            .finish()
    }
}

impl CoreDnsPeerAccess {
    pub(crate) fn new(peer_manager: Arc<PeerManagerCore>) -> Self {
        let export = peer_manager.dns_export_state();
        Self {
            peer_manager,
            export,
        }
    }

    pub fn local_peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }

    pub async fn dns_advertisement(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        self.peer_manager
            .get_route()
            .get_peer_info(peer_id)
            .await
            .map(|info| info.dns)
    }

    pub async fn reachable_peer_ids(&self) -> Vec<PeerId> {
        self.peer_manager
            .list_route_snapshots()
            .await
            .into_iter()
            .map(|route| route.peer_id)
            .collect()
    }

    pub async fn fetch_export(&self, peer_id: PeerId) -> anyhow::Result<GetExportConfigResponse> {
        Ok(self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DnsPeerMgrRpcClientFactory<BaseController>>(
                self.local_peer_id(),
                peer_id,
                self.peer_manager.network_name().to_owned(),
            )
            .get_export_config(BaseController::default(), GetExportConfigRequest {})
            .await?)
    }

    pub fn publish_export(&self, response: GetExportConfigResponse) {
        self.export.publish(Some(response));
    }

    pub fn withdraw_export(&self) {
        self.export.publish(None);
    }

    pub fn local_export(&self) -> GetExportConfigResponse {
        self.export.snapshot().response.clone().unwrap_or_default()
    }

    pub fn register_export_service(&self) -> DnsExportRegistration {
        let rpc = self.peer_manager.get_peer_rpc_mgr();
        let network_name = self.peer_manager.network_name().to_owned();
        let mut registrations = self.export.registrations.lock().unwrap();
        if *registrations == 0 {
            rpc.rpc_server().registry().register(
                DnsPeerMgrRpcServer::new_arc(self.export.clone()),
                &network_name,
            );
        }
        *registrations += 1;
        DnsExportRegistration {
            rpc,
            network_name,
            export: self.export.clone(),
        }
    }
}

pub struct DnsExportRegistration {
    rpc: Arc<PeerRpcManager>,
    network_name: String,
    export: Arc<DnsExportState>,
}

impl std::fmt::Debug for DnsExportRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsExportRegistration")
            .field("network_name", &self.network_name)
            .finish()
    }
}

impl Drop for DnsExportRegistration {
    fn drop(&mut self) {
        let mut registrations = self.export.registrations.lock().unwrap();
        *registrations -= 1;
        if *registrations != 0 {
            return;
        }
        self.export.publish(None);
        self.rpc.rpc_server().registry().unregister(
            DnsPeerMgrRpcServer::new_arc(self.export.clone()),
            &self.network_name,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_digest_and_rpc_payload_share_an_immutable_version() {
        let state = DnsExportState::default();
        let response = GetExportConfigResponse::default();
        state.publish(Some(response.clone()));
        let before = state.snapshot();
        assert_eq!(
            before.digest,
            Sha256::digest(response.encode_to_vec()).to_vec()
        );
        state.publish(None);
        assert!(state.snapshot().digest.is_empty());
        assert_eq!(before.response, Some(response));
        assert!(!before.digest.is_empty());
    }

    #[tokio::test]
    async fn unchanged_exports_do_not_wake_route_publication() {
        let state = DnsExportState::default();
        let mut changes = state.subscribe();
        state.publish(Some(GetExportConfigResponse::default()));
        changes.changed().await.unwrap();
        state.publish(Some(GetExportConfigResponse::default()));
        assert!(!changes.has_changed().unwrap());
        state.publish(None);
        assert!(changes.has_changed().unwrap());
    }
}

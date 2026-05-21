use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        peer_rpc::{
            GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc, ReportPeersRequest,
            ReportPeersResponse,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct PeerCenterManageRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl PeerCenterManageRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl PeerCenterRpc for PeerCenterManageRpcService {
    type Controller = BaseController;

    async fn get_global_peer_map(
        &self,
        ctrl: BaseController,
        req: GetGlobalPeerMapRequest,
    ) -> crate::proto::rpc_types::error::Result<GetGlobalPeerMapResponse> {
        let instance_service =
            super::get_instance_service(&self.instance_manager, &None).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("please specify the instance ID") {
                    anyhow::anyhow!(
                        "PeerCenter management RPC cannot select an instance automatically \
                         when multiple instances are running; please use an API that allows \
                         specifying an instance identifier."
                    )
                } else {
                    e
                }
            })?;

        instance_service
            .get_peer_center_service()
            .get_global_peer_map(ctrl, req)
            .await
    }

    async fn report_peers(
        &self,
        _: BaseController,
        _: ReportPeersRequest,
    ) -> crate::proto::rpc_types::error::Result<ReportPeersResponse> {
        Err(anyhow::anyhow!("not implemented for management API").into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        instance_manager::NetworkInstanceManager,
        proto::{
            peer_rpc::{GetGlobalPeerMapRequest, ReportPeersRequest},
            rpc_types::controller::BaseController,
        },
    };

    fn make_service() -> PeerCenterManageRpcService {
        PeerCenterManageRpcService::new(Arc::new(NetworkInstanceManager::new()))
    }

    #[tokio::test]
    async fn get_global_peer_map_errors_when_no_instance() {
        let svc = make_service();
        let result = svc
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest::default(),
            )
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("No instance matches the selector"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn report_peers_always_returns_error() {
        let svc = make_service();
        let result = svc
            .report_peers(BaseController::default(), ReportPeersRequest::default())
            .await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not implemented for management API"),
            "unexpected error: {msg}"
        );
    }
}

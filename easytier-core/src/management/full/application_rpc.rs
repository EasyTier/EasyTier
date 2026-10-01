//! Narrow mutation transport; it shares the application's existing RPC manager.
use crate::rpc::bidirect::BidirectRpcManager;
use async_trait::async_trait;
use easytier_proto::api::manage::{
    DeleteNetworkInstanceRequest, ListNetworkInstanceRequest, RunNetworkInstanceRequest,
    WebClientServiceClientFactory,
};
use easytier_proto::rpc_types::controller::BaseController;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub(super) trait InstanceControl: Send + Sync {
    async fn start(&self, request: RunNetworkInstanceRequest) -> anyhow::Result<Uuid>;
    async fn stop(&self, ids: &[Uuid]) -> anyhow::Result<()>;
    async fn running(&self) -> anyhow::Result<Vec<Uuid>>;
}

pub(super) struct RpcInstanceControl(pub Arc<BidirectRpcManager>);

#[async_trait]
impl InstanceControl for RpcInstanceControl {
    async fn start(&self, request: RunNetworkInstanceRequest) -> anyhow::Result<Uuid> {
        let client = self
            .0
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, String::new());
        let response = client
            .run_network_instance(BaseController::default(), request)
            .await?;
        Ok(response
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("Start RPC did not return an instance ID"))?
            .into())
    }
    async fn stop(&self, ids: &[Uuid]) -> anyhow::Result<()> {
        let client = self
            .0
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, String::new());
        client
            .delete_network_instance(
                BaseController::default(),
                DeleteNetworkInstanceRequest {
                    inst_ids: ids.iter().copied().map(Into::into).collect(),
                },
            )
            .await?;
        Ok(())
    }
    async fn running(&self) -> anyhow::Result<Vec<Uuid>> {
        let client = self
            .0
            .rpc_client()
            .scoped_client::<WebClientServiceClientFactory<BaseController>>(1, 1, String::new());
        Ok(client
            .list_network_instance(BaseController::default(), ListNetworkInstanceRequest {})
            .await?
            .inst_ids
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

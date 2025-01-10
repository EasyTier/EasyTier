use crate::{
    common::global_ctx::ArcGlobalCtx,
    proto::{
        peer_rpc::{DirectConnectorRpc, GetIpListRequest, GetIpListResponse},
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Clone)]
pub struct DirectConnectorManagerRpcServer {
    // TODO: this only cache for one src peer, should make it global
    global_ctx: ArcGlobalCtx,
}

#[async_trait::async_trait]
impl DirectConnectorRpc for DirectConnectorManagerRpcServer {
    type Controller = BaseController;

    async fn get_ip_list(
        &self,
        _: BaseController,
        _: GetIpListRequest,
    ) -> rpc_types::error::Result<GetIpListResponse> {
        let mut ret = self.global_ctx.get_ip_collector().collect_ip_addrs().await;
        ret.listeners = self
            .global_ctx
            .config
            .get_mapped_listeners()
            .into_iter()
            .chain(self.global_ctx.get_running_listeners().into_iter())
            .map(Into::into)
            .collect();
        Ok(ret)
    }
}

impl DirectConnectorManagerRpcServer {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

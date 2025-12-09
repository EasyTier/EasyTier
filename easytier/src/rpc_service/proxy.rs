use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyRpc},
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct TcpProxyRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
    client_type: &'static str,
}

impl TcpProxyRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>, client_type: &'static str) -> Self {
        Self {
            instance_manager,
            client_type,
        }
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for TcpProxyRpcService {
    type Controller = BaseController;

    async fn list_tcp_proxy_entry(
        &self,
        ctrl: Self::Controller,
        req: ListTcpProxyEntryRequest,
    ) -> crate::proto::rpc_types::error::Result<ListTcpProxyEntryResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_proxy_service(self.client_type)
            .ok_or_else(|| anyhow::anyhow!("TCP proxy service not found for {}", self.client_type))?
            .list_tcp_proxy_entry(ctrl, req)
            .await
    }
}

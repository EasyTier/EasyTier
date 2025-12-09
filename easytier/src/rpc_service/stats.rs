use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::instance::{
            GetPrometheusStatsRequest, GetPrometheusStatsResponse, GetStatsRequest,
            GetStatsResponse, StatsRpc,
        },
        rpc_types::controller::BaseController,
    },
};

#[derive(Clone)]
pub struct StatsRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl StatsRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl StatsRpc for StatsRpcService {
    type Controller = BaseController;

    async fn get_stats(
        &self,
        ctrl: Self::Controller,
        req: GetStatsRequest,
    ) -> crate::proto::rpc_types::error::Result<GetStatsResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_stats_service()
            .get_stats(ctrl, req)
            .await
    }

    async fn get_prometheus_stats(
        &self,
        ctrl: Self::Controller,
        req: GetPrometheusStatsRequest,
    ) -> crate::proto::rpc_types::error::Result<GetPrometheusStatsResponse> {
        super::get_instance_service(&self.instance_manager, &req.instance)?
            .get_stats_service()
            .get_prometheus_stats(ctrl, req)
            .await
    }
}

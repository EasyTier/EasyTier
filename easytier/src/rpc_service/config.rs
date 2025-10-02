use std::sync::Arc;

use crate::{
    instance_manager::NetworkInstanceManager,
    proto::{
        api::config::{ConfigRpc, PatchConfigRequest, PatchConfigResponse},
        rpc_types::{self, controller::BaseController},
    },
};

#[derive(Clone)]
pub struct ConfigRpcService {
    instance_manager: Arc<NetworkInstanceManager>,
}

impl ConfigRpcService {
    pub fn new(instance_manager: Arc<NetworkInstanceManager>) -> Self {
        Self { instance_manager }
    }
}

#[async_trait::async_trait]
impl ConfigRpc for ConfigRpcService {
    type Controller = BaseController;

    async fn patch_config(
        &self,
        ctrl: Self::Controller,
        input: PatchConfigRequest,
    ) -> Result<PatchConfigResponse, rpc_types::error::Error> {
        super::get_instance_service(&self.instance_manager, &input.instance)?
            .get_config_service()
            .patch_config(ctrl, input)
            .await
    }
}

use easytier_proto::{
    api::config::{
        ConfigRpc, GetConfigRequest, GetConfigResponse, PatchConfigRequest, PatchConfigResponse,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    config::api::network_config_from_toml,
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    management::apply_config_patch,
};

use super::InstanceManagementRpc;

#[async_trait::async_trait]
impl<F, H> ConfigRpc for InstanceManagementRpc<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>>,
    H: CoreInstanceHost,
{
    type Controller = BaseController;

    async fn patch_config(
        &self,
        _: BaseController,
        request: PatchConfigRequest,
    ) -> rpc_types::error::Result<PatchConfigResponse> {
        let instance = self.instance(request.instance.as_ref())?;
        if let Some(patch) = request.patch {
            apply_config_patch(&instance, patch).await?;
        }
        Ok(PatchConfigResponse::default())
    }

    async fn get_config(
        &self,
        _: BaseController,
        request: GetConfigRequest,
    ) -> rpc_types::error::Result<GetConfigResponse> {
        let config = self
            .instance(request.instance.as_ref())?
            .toml_config()
            .ok_or_else(|| anyhow::anyhow!("shared TOML configuration is not available"))?;
        Ok(GetConfigResponse {
            config: Some(network_config_from_toml(&config)),
        })
    }
}

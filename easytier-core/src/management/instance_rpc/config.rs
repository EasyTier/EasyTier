use easytier_proto::{
    api::config::{
        ConfigRpc, GetConfigRequest, GetConfigResponse, PatchConfigRequest, PatchConfigResponse,
    },
    rpc_types::{self, controller::BaseController},
};

use crate::{
    config::{api::network_config_from_raw, serialize_raw_to_toml},
    management::apply_config_patch,
};

use super::{ReadOnlyInstanceResolver, ResolvedInstanceManagementRpc};

#[async_trait::async_trait]
impl<R> ConfigRpc for ResolvedInstanceManagementRpc<R>
where
    R: ReadOnlyInstanceResolver,
{
    type Controller = BaseController;

    async fn patch_config(
        &self,
        _: BaseController,
        request: PatchConfigRequest,
    ) -> rpc_types::error::Result<PatchConfigResponse> {
        let instance = self.instance(request.instance.as_ref())?;
        if let Some(patch) = request.patch {
            apply_config_patch(&instance, patch, self.config_patch_persistence.as_deref()).await?;
        }
        Ok(PatchConfigResponse::default())
    }

    async fn get_config(
        &self,
        _: BaseController,
        request: GetConfigRequest,
    ) -> rpc_types::error::Result<GetConfigResponse> {
        let instance = self.instance(request.instance.as_ref())?;
        let snapshot = instance.config_store().snapshot();
        let config = network_config_from_raw(snapshot.raw());
        let toml_config = serialize_raw_to_toml(snapshot.raw()).map_err(|e| anyhow::anyhow!(e))?;
        Ok(GetConfigResponse {
            config: Some(config),
            toml_config,
        })
    }
}

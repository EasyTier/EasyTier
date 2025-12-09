use std::{collections::HashSet, sync::Arc};

use crate::{
    common::config::{ConfigFileControl, ConfigFilePermission, ConfigLoader},
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{config::GetConfigRequest, manage::*},
        rpc_types::{self, controller::BaseController},
    },
    web_client::WebClientHooks,
};

#[derive(Clone)]
pub struct InstanceManageRpcService {
    manager: Arc<NetworkInstanceManager>,
    hooks: Arc<dyn WebClientHooks>,
}

impl InstanceManageRpcService {
    pub fn new(manager: Arc<NetworkInstanceManager>, hooks: Arc<dyn WebClientHooks>) -> Self {
        Self { manager, hooks }
    }
}

#[async_trait::async_trait]
impl WebClientService for InstanceManageRpcService {
    type Controller = BaseController;

    async fn validate_config(
        &self,
        _: BaseController,
        req: ValidateConfigRequest,
    ) -> Result<ValidateConfigResponse, rpc_types::error::Error> {
        let toml_config = req.config.unwrap_or_default().gen_config()?.dump();
        Ok(ValidateConfigResponse { toml_config })
    }

    async fn run_network_instance(
        &self,
        _: BaseController,
        req: RunNetworkInstanceRequest,
    ) -> Result<RunNetworkInstanceResponse, rpc_types::error::Error> {
        if req.config.is_none() {
            return Err(anyhow::anyhow!("config is required").into());
        }
        let cfg = req.config.unwrap().gen_config()?;
        let id = cfg.get_id();
        if let Some(inst_id) = req.inst_id {
            cfg.set_id(inst_id.into());
        }
        let resp = RunNetworkInstanceResponse {
            inst_id: Some(id.into()),
        };

        let mut control = if let Some(control) = self.manager.get_instance_config_control(&id) {
            let error_msg = self
                .manager
                .get_network_info(&id)
                .await
                .and_then(|i| i.error_msg)
                .unwrap_or_default();

            if !req.overwrite && error_msg.is_empty() {
                return Ok(resp);
            }
            if control.is_read_only() {
                return Err(
                    anyhow::anyhow!("instance {} is read-only, cannot be overwritten", id).into(),
                );
            }

            if let Some(path) = control.path.as_ref() {
                let real_control = ConfigFileControl::from_path(path.clone()).await;
                if real_control.is_read_only() {
                    return Err(anyhow::anyhow!(
                        "config file {} is read-only, cannot be overwritten",
                        path.display()
                    )
                    .into());
                }
            }

            self.manager.delete_network_instance(vec![id])?;

            control.clone()
        } else if let Some(config_dir) = self.manager.get_config_dir() {
            ConfigFileControl::new(
                Some(config_dir.join(format!("{}.toml", id))),
                ConfigFilePermission::default(),
            )
        } else {
            ConfigFileControl::new(None, ConfigFilePermission::default())
        };

        if !control.is_read_only() {
            if let Some(config_file) = control.path.as_ref() {
                if let Err(e) = std::fs::write(config_file, cfg.dump()) {
                    tracing::warn!(
                        "failed to write config file {}: {}",
                        config_file.display(),
                        e
                    );
                    control.set_read_only(true);
                }
            }
        }

        if let Err(e) = self.hooks.pre_run_network_instance(&cfg).await {
            return Err(anyhow::anyhow!("pre-run hook failed: {}", e).into());
        }

        self.manager.run_network_instance(cfg, true, control)?;
        println!("instance {} started", id);

        if let Err(e) = self.hooks.post_run_network_instance(&id).await {
            tracing::warn!("post-run hook failed: {}", e);
        }

        Ok(resp)
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        req: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, rpc_types::error::Error> {
        let remain = self
            .manager
            .retain_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?;
        println!("instance {:?} retained", remain);
        Ok(RetainNetworkInstanceResponse {
            remain_inst_ids: remain.iter().map(|item| (*item).into()).collect(),
        })
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        req: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, rpc_types::error::Error> {
        let mut ret = NetworkInstanceRunningInfoMap {
            map: self
                .manager
                .collect_network_infos()
                .await?
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        };
        let include_inst_ids = req
            .inst_ids
            .iter()
            .cloned()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        if !include_inst_ids.is_empty() {
            let mut to_remove = Vec::new();
            for (k, _) in ret.map.iter() {
                if !include_inst_ids.contains(k) {
                    to_remove.push(k.clone());
                }
            }

            for k in to_remove {
                ret.map.remove(&k);
            }
        }
        Ok(CollectNetworkInfoResponse { info: Some(ret) })
    }

    //   rpc ListNetworkInstance(ListNetworkInstanceRequest) returns (ListNetworkInstanceResponse) {}
    async fn list_network_instance(
        &self,
        _: BaseController,
        _: ListNetworkInstanceRequest,
    ) -> Result<ListNetworkInstanceResponse, rpc_types::error::Error> {
        Ok(ListNetworkInstanceResponse {
            inst_ids: self
                .manager
                .list_network_instance_ids()
                .into_iter()
                .map(Into::into)
                .collect(),
        })
    }

    //   rpc DeleteNetworkInstance(DeleteNetworkInstanceRequest) returns (DeleteNetworkInstanceResponse) {}
    async fn delete_network_instance(
        &self,
        _: BaseController,
        req: DeleteNetworkInstanceRequest,
    ) -> Result<DeleteNetworkInstanceResponse, rpc_types::error::Error> {
        let inst_ids: HashSet<uuid::Uuid> = req.inst_ids.into_iter().map(Into::into).collect();

        let hook_ids: Vec<uuid::Uuid> = inst_ids.iter().cloned().collect();

        let inst_ids = self
            .manager
            .iter()
            .filter(|v| inst_ids.contains(v.key()))
            .filter(|v| v.get_config_file_control().is_deletable())
            .map(|v| *v.key())
            .collect::<Vec<_>>();
        let config_files = inst_ids
            .iter()
            .filter_map(|id| {
                self.manager
                    .get_instance_config_control(id)
                    .and_then(|control| control.path)
            })
            .collect::<Vec<_>>();
        let remain_inst_ids = self.manager.delete_network_instance(inst_ids)?;
        println!("instance {:?} retained", remain_inst_ids);

        if let Err(e) = self.hooks.post_remove_network_instances(&hook_ids).await {
            tracing::warn!("post-remove hook failed: {}", e);
        }

        for config_file in config_files {
            if let Err(e) = std::fs::remove_file(&config_file) {
                tracing::warn!(
                    "failed to remove config file {}: {}",
                    config_file.display(),
                    e
                );
            }
        }
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: remain_inst_ids.into_iter().map(Into::into).collect(),
        })
    }

    async fn get_network_instance_config(
        &self,
        _: BaseController,
        req: GetNetworkInstanceConfigRequest,
    ) -> Result<GetNetworkInstanceConfigResponse, rpc_types::error::Error> {
        let inst_id: uuid::Uuid = req
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("instance id is required"))?
            .into();

        let control = self
            .manager
            .get_instance_config_control(&inst_id)
            .ok_or_else(|| anyhow::anyhow!("instance config control not found"))?;

        if control.is_read_only() {
            return Err(anyhow::anyhow!(
                "Configuration for instance {} is read-only (uses environment variables) and cannot be retrieved via API. \
                 Please access the configuration file directly on the file system.",
                inst_id
            )
            .into());
        }

        let config = self
            .manager
            .get_instance_service(&inst_id)
            .ok_or_else(|| anyhow::anyhow!("instance service not found"))?
            .get_config_service()
            .get_config(BaseController::default(), GetConfigRequest::default())
            .await?
            .config;
        Ok(GetNetworkInstanceConfigResponse { config })
    }

    async fn list_network_instance_meta(
        &self,
        _: BaseController,
        req: ListNetworkInstanceMetaRequest,
    ) -> Result<ListNetworkInstanceMetaResponse, rpc_types::error::Error> {
        let mut metas = Vec::with_capacity(req.inst_ids.len());
        for inst_id in req.inst_ids {
            let inst_id: uuid::Uuid = (inst_id).into();
            let Some(control) = self.manager.get_instance_config_control(&inst_id) else {
                continue;
            };
            let Some(name) = self.manager.get_network_instance_name(&inst_id) else {
                continue;
            };
            let meta = NetworkMeta {
                inst_id: Some(inst_id.into()),
                network_name: name,
                config_permission: control.permission.into(),
            };
            metas.push(meta);
        }
        Ok(ListNetworkInstanceMetaResponse { metas })
    }
}

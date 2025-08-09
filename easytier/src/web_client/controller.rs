use crate::{
    common::config::ConfigLoader,
    instance_manager::NetworkInstanceManager,
    launcher::ConfigSource,
    proto::{
        rpc_types::{self, controller::BaseController},
        web::{
            CollectNetworkInfoRequest, CollectNetworkInfoResponse, DeleteNetworkInstanceRequest,
            DeleteNetworkInstanceResponse, ListNetworkInstanceRequest, ListNetworkInstanceResponse,
            NetworkInstanceRunningInfoMap, RetainNetworkInstanceRequest,
            RetainNetworkInstanceResponse, RunNetworkInstanceRequest, RunNetworkInstanceResponse,
            ValidateConfigRequest, ValidateConfigResponse, WebClientService,
        },
    },
};

pub struct Controller {
    token: String,
    hostname: String,
    manager: NetworkInstanceManager,
}

impl Controller {
    pub fn new(token: String, hostname: String) -> Self {
        Controller {
            token,
            hostname,
            manager: NetworkInstanceManager::new(),
        }
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.manager.list_network_instance_ids()
    }

    pub fn token(&self) -> String {
        self.token.clone()
    }

    pub fn hostname(&self) -> String {
        self.hostname.clone()
    }
}

#[async_trait::async_trait]
impl WebClientService for Controller {
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
        self.manager.run_network_instance(cfg, ConfigSource::Web)?;
        println!("instance {} started", id);
        Ok(RunNetworkInstanceResponse {
            inst_id: Some(id.into()),
        })
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
                .collect_network_infos()?
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
        let remain_inst_ids = self
            .manager
            .delete_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?;
        println!("instance {:?} retained", remain_inst_ids);
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: remain_inst_ids.into_iter().map(Into::into).collect(),
        })
    }
}

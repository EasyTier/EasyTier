use std::collections::BTreeMap;

use dashmap::DashMap;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    launcher::NetworkInstance,
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
    instance_map: DashMap<uuid::Uuid, NetworkInstance>,
}

impl Controller {
    pub fn new(token: String, hostname: String) -> Self {
        Controller {
            token,
            hostname,
            instance_map: DashMap::new(),
        }
    }

    pub fn run_network_instance(&self, cfg: TomlConfigLoader) -> Result<(), anyhow::Error> {
        let instance_id = cfg.get_id();
        if self.instance_map.contains_key(&instance_id) {
            anyhow::bail!("instance {} already exists", instance_id);
        }

        let mut instance = NetworkInstance::new(cfg);
        instance.start()?;

        println!("instance {} started", instance_id);
        self.instance_map.insert(instance_id, instance);
        Ok(())
    }

    pub fn retain_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<RetainNetworkInstanceResponse, anyhow::Error> {
        self.instance_map.retain(|k, _| instance_ids.contains(k));
        let remain = self
            .instance_map
            .iter()
            .map(|item| item.key().clone().into())
            .collect::<Vec<_>>();
        println!("instance {:?} retained", remain);
        Ok(RetainNetworkInstanceResponse {
            remain_inst_ids: remain,
        })
    }

    pub fn collect_network_infos(&self) -> Result<NetworkInstanceRunningInfoMap, anyhow::Error> {
        let mut map = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Some(info) = instance.get_running_info() {
                map.insert(instance.key().to_string(), info);
            }
        }
        Ok(NetworkInstanceRunningInfoMap { map })
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_map
            .iter()
            .map(|item| item.key().clone())
            .collect()
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
        self.run_network_instance(cfg)?;
        Ok(RunNetworkInstanceResponse {
            inst_id: Some(id.into()),
        })
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        req: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, rpc_types::error::Error> {
        Ok(self.retain_network_instance(req.inst_ids.into_iter().map(Into::into).collect())?)
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        req: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, rpc_types::error::Error> {
        let mut ret = self.collect_network_infos()?;
        let include_inst_ids = req
            .inst_ids
            .iter()
            .cloned()
            .map(|id| id.to_string())
            .collect::<Vec<_>>();
        if !include_inst_ids.is_empty() {
            let mut to_remove = Vec::new();
            for (k, _) in ret.map.iter() {
                if !include_inst_ids.contains(&k) {
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
        let mut inst_ids = self.list_network_instance_ids();
        inst_ids.retain(|id| !req.inst_ids.contains(&(id.clone().into())));
        self.retain_network_instance(inst_ids.clone())?;
        Ok(DeleteNetworkInstanceResponse {
            remain_inst_ids: inst_ids.into_iter().map(Into::into).collect(),
        })
    }
}

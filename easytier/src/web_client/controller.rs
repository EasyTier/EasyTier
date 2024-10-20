use std::collections::BTreeMap;

use anyhow::Context;
use dashmap::DashMap;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    launcher::{NetworkInstance, NetworkInstanceRunningInfo},
    proto::{
        rpc_types::{self, controller::BaseController},
        web::{
            CollectNetworkInfoRequest, CollectNetworkInfoResponse, NetworkInstanceRunningInfoMap,
            RetainNetworkInstanceRequest, RetainNetworkInstanceResponse, RunNetworkInstanceRequest,
            RunNetworkInstanceResponse, ValidateConfigRequest, ValidateConfigResponse,
            WebClientService,
        },
    },
};

pub struct Controller {
    instance_map: DashMap<uuid::Uuid, NetworkInstance>,
}

impl Controller {
    pub fn new() -> Self {
        Controller {
            instance_map: DashMap::new(),
        }
    }

    pub fn run_network_instance(&self, cfg: TomlConfigLoader) -> Result<(), String> {
        let instance_id = cfg.get_id();
        if self.instance_map.contains_key(&instance_id) {
            return Err("instance already exists".to_string());
        }

        let mut instance = NetworkInstance::new(cfg);
        instance.start().map_err(|e| e.to_string())?;

        println!("instance {} started", instance_id);
        self.instance_map.insert(instance_id, instance);
        Ok(())
    }

    pub fn retain_network_instance(&self, instance_ids: Vec<uuid::Uuid>) -> Result<(), String> {
        let _ = self.instance_map.retain(|k, _| instance_ids.contains(k));
        println!(
            "instance {:?} retained",
            self.instance_map
                .iter()
                .map(|item| item.key().clone())
                .collect::<Vec<_>>()
        );
        Ok(())
    }

    pub fn collect_network_infos(&self) -> Result<NetworkInstanceRunningInfoMap, String> {
        let mut map = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Some(info) = instance.get_running_info() {
                map.insert(instance.key().to_string(), info);
            }
        }
        Ok(NetworkInstanceRunningInfoMap { map })
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
        let error_msg = TomlConfigLoader::new_from_str(&req.config)
            .err()
            .map(|e| e.to_string());
        Ok(ValidateConfigResponse { error_msg })
    }

    async fn run_network_instance(
        &self,
        _: BaseController,
        req: RunNetworkInstanceRequest,
    ) -> Result<RunNetworkInstanceResponse, rpc_types::error::Error> {
        let cfg = TomlConfigLoader::new_from_str(&req.config);
        if let Err(e) = cfg {
            return Ok(RunNetworkInstanceResponse {
                error_msg: Some(e.to_string()),
            });
        }
        let ret = self.run_network_instance(cfg.unwrap()).err();
        Ok(RunNetworkInstanceResponse { error_msg: ret })
    }

    async fn retain_network_instance(
        &self,
        _: BaseController,
        req: RetainNetworkInstanceRequest,
    ) -> Result<RetainNetworkInstanceResponse, rpc_types::error::Error> {
        let error_msg = self
            .retain_network_instance(req.inst_ids.into_iter().map(Into::into).collect())
            .err();
        Ok(RetainNetworkInstanceResponse { error_msg })
    }

    async fn collect_network_info(
        &self,
        _: BaseController,
        _: CollectNetworkInfoRequest,
    ) -> Result<CollectNetworkInfoResponse, rpc_types::error::Error> {
        let ret = self.collect_network_infos();
        if let Err(e) = ret {
            Ok(CollectNetworkInfoResponse {
                error_msg: Some(e),
                info: None,
            })
        } else {
            Ok(CollectNetworkInfoResponse {
                error_msg: None,
                info: Some(ret.unwrap()),
            })
        }
    }
}

use std::collections::BTreeMap;

use dashmap::DashMap;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    launcher::{NetworkInstance, NetworkInstanceRunningInfo},
};

pub struct NetworkInstanceManager {
    instance_map: DashMap<uuid::Uuid, NetworkInstance>,
}

impl NetworkInstanceManager {
    pub fn new() -> Self {
        NetworkInstanceManager {
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

        self.instance_map.insert(instance_id, instance);
        Ok(())
    }

    pub fn retain_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| instance_ids.contains(k));
        Ok(self.list_network_instance_ids())
    }

    pub fn delete_network_instance(
        &self,
        instance_ids: Vec<uuid::Uuid>,
    ) -> Result<Vec<uuid::Uuid>, anyhow::Error> {
        self.instance_map.retain(|k, _| !instance_ids.contains(k));
        Ok(self.list_network_instance_ids())
    }

    pub fn collect_network_infos(
        &self,
    ) -> Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>, anyhow::Error> {
        let mut ret = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Some(info) = instance.get_running_info() {
                ret.insert(instance.key().clone(), info);
            }
        }
        Ok(ret)
    }

    pub fn list_network_instance_ids(&self) -> Vec<uuid::Uuid> {
        self.instance_map
            .iter()
            .map(|item| item.key().clone())
            .collect()
    }

    pub fn set_tun_fd(&self, instance_id: &uuid::Uuid, fd: i32) -> Result<(), anyhow::Error> {
        let mut instance = self.instance_map
            .get_mut(instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance not found"))?;
        instance.set_tun_fd(fd);
        Ok(())
    }
}

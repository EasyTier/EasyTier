use std::collections::BTreeMap;

use dashmap::DashMap;

use crate::{
    common::config::{ConfigLoader, TomlConfigLoader},
    launcher::{NetworkInstance, NetworkInstanceRunningInfo},
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

    pub fn collect_network_infos(
        &self,
    ) -> Result<BTreeMap<String, NetworkInstanceRunningInfo>, String> {
        let mut ret = BTreeMap::new();
        for instance in self.instance_map.iter() {
            if let Some(info) = instance.get_running_info() {
                ret.insert(instance.key().to_string(), info);
            }
        }
        Ok(ret)
    }
}

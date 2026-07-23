use std::collections::BTreeMap;

use easytier_proto::api::manage::NetworkInstanceRunningInfo;

use super::ManagedInstanceSet;
use crate::{
    config::toml::{ConfigLoader as _, ConfigSource, TomlConfig},
    instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory},
    management::network_instance_running_info,
};

impl<F, H> ManagedInstanceSet<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub fn config(&self, instance_id: uuid::Uuid) -> Option<TomlConfig> {
        self.manager
            .get(instance_id)
            .and_then(|instance| instance.toml_config())
    }

    pub fn get_instance_config(&self, instance_id: &uuid::Uuid) -> Option<TomlConfig> {
        self.config(*instance_id)
    }

    pub fn config_source(&self, instance_id: uuid::Uuid) -> Option<ConfigSource> {
        self.config(instance_id)
            .map(|config| config.get_network_config_source())
    }

    pub fn get_instance_network_config_source(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<ConfigSource> {
        self.config_source(*instance_id)
    }

    pub fn get_network_name(&self, instance_id: &uuid::Uuid) -> Option<String> {
        self.config(*instance_id)
            .map(|config| config.get_network_identity().network_name)
    }

    pub async fn network_info(
        &self,
        instance_id: uuid::Uuid,
    ) -> Option<NetworkInstanceRunningInfo> {
        let instance = self.manager.get(instance_id)?;
        network_instance_running_info(instance.as_ref()).await.ok()
    }

    pub async fn get_network_info(
        &self,
        instance_id: &uuid::Uuid,
    ) -> Option<NetworkInstanceRunningInfo> {
        self.network_info(*instance_id).await
    }

    pub async fn collect_network_infos(
        &self,
    ) -> anyhow::Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>> {
        let mut result = BTreeMap::new();
        for instance in self.manager.list() {
            result.insert(
                instance.instance_id(),
                network_instance_running_info(instance.as_ref()).await?,
            );
        }
        Ok(result)
    }

    pub fn collect_network_infos_sync(
        &self,
    ) -> anyhow::Result<BTreeMap<uuid::Uuid, NetworkInstanceRunningInfo>> {
        self.runtime_handle
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("managed Instance runtime handle is unavailable"))?
            .block_on(self.collect_network_infos())
    }
}

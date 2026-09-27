use super::{CoreInstance, CoreInstanceHost, CoreInstanceHostConfig};
use crate::config::{runtime::InstanceConfigStore, toml::TomlConfig};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub fn toml_config(&self) -> Option<TomlConfig> {
        self.management_toml.clone().or_else(|| {
            Some(TomlConfig::from_instance_config(
                (*self.runtime_config.snapshot()).clone(),
            ))
        })
    }

    pub(crate) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }

    pub fn config_store(&self) -> &InstanceConfigStore {
        &self.runtime_config
    }
}

use crate::config::toml::TomlConfig;

use crate::instance::CoreInstanceHostConfig;

pub(in crate::instance) struct ManagementState {
    toml_config: Option<TomlConfig>,
    host_config: CoreInstanceHostConfig,
}

impl ManagementState {
    pub(in crate::instance) fn new(
        toml_config: Option<TomlConfig>,
        host_config: CoreInstanceHostConfig,
    ) -> Self {
        Self {
            toml_config,
            host_config,
        }
    }

    pub(in crate::instance) fn toml_config(&self) -> Option<TomlConfig> {
        self.toml_config.clone()
    }

    pub(in crate::instance) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }
}

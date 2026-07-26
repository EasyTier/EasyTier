use crate::{config::toml::TomlConfig, instance::CoreInstanceHostConfig};

pub(super) struct ManagementState {
    #[cfg(feature = "management")]
    toml_config: Option<TomlConfig>,
    #[cfg(feature = "management")]
    host_config: CoreInstanceHostConfig,
}

impl ManagementState {
    pub(super) fn new(
        toml_config: Option<TomlConfig>,
        host_config: CoreInstanceHostConfig,
    ) -> Self {
        #[cfg(not(feature = "management"))]
        let _ = (toml_config, host_config);
        Self {
            #[cfg(feature = "management")]
            toml_config,
            #[cfg(feature = "management")]
            host_config,
        }
    }

    #[cfg(feature = "management")]
    pub(super) fn toml_config(&self) -> Option<TomlConfig> {
        self.toml_config.clone()
    }

    #[cfg(feature = "management")]
    pub(super) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }
}

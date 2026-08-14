use crate::{config::toml::TomlConfig, instance::CoreInstanceHostConfig};

pub(super) struct ManagementState {
    #[cfg(feature = "web-client")]
    toml_config: Option<TomlConfig>,
    #[cfg(feature = "web-client")]
    host_config: CoreInstanceHostConfig,
}

impl ManagementState {
    pub(super) fn new(
        toml_config: Option<TomlConfig>,
        host_config: CoreInstanceHostConfig,
    ) -> Self {
        #[cfg(not(feature = "web-client"))]
        let _ = (toml_config, host_config);
        Self {
            #[cfg(feature = "web-client")]
            toml_config,
            #[cfg(feature = "web-client")]
            host_config,
        }
    }

    #[cfg(feature = "web-client")]
    pub(super) fn toml_config(&self) -> Option<TomlConfig> {
        self.toml_config.clone()
    }

    #[cfg(feature = "web-client")]
    pub(super) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }
}

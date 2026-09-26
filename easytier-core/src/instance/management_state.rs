use crate::{config::toml::TomlConfig, instance::CoreInstanceHostConfig};

pub(super) struct ManagementState {
    #[cfg(any(feature = "web-client", test))]
    toml_config: Option<TomlConfig>,
    #[cfg(any(feature = "web-client", test))]
    host_config: CoreInstanceHostConfig,
}

impl ManagementState {
    pub(super) fn new(
        toml_config: Option<TomlConfig>,
        host_config: CoreInstanceHostConfig,
    ) -> Self {
        #[cfg(not(any(feature = "web-client", test)))]
        let _ = (toml_config, host_config);
        Self {
            #[cfg(any(feature = "web-client", test))]
            toml_config,
            #[cfg(any(feature = "web-client", test))]
            host_config,
        }
    }

    #[cfg(any(feature = "web-client", test))]
    pub(super) fn toml_config(&self) -> Option<TomlConfig> {
        self.toml_config.clone()
    }

    #[cfg(any(feature = "web-client", test))]
    pub(super) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }
}

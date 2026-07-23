use std::sync::Arc;

use crate::config::runtime::CoreInstanceRuntimeConfig;

use super::{CoreInstance, CoreInstanceHost, CoreInstanceHostConfig};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub fn toml_config(&self) -> Option<crate::config::toml::TomlConfig> {
        self.management.toml_config()
    }

    pub(crate) fn runtime_config_snapshot(&self) -> Arc<CoreInstanceRuntimeConfig> {
        self.runtime_config.snapshot()
    }

    pub(crate) fn host_config(&self) -> &CoreInstanceHostConfig {
        self.management.host_config()
    }
}

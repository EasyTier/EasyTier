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

    pub(crate) fn effective_toml_config(&self) -> Option<crate::config::toml::TomlConfig> {
        self.management.effective_config()
    }

    pub(crate) fn project_runtime_config(
        &self,
        authoritative: &crate::config::toml::TomlConfig,
    ) -> anyhow::Result<super::RuntimeConfigProjection> {
        self.management.project(authoritative)
    }

    pub(crate) fn project_connector(&self, connector: &url::Url) -> Option<url::Url> {
        self.management.project_connector(connector)
    }

    pub(crate) fn runtime_config_snapshot(&self) -> Arc<CoreInstanceRuntimeConfig> {
        self.runtime_config.snapshot()
    }

    pub(crate) fn host_config(&self) -> &CoreInstanceHostConfig {
        self.management.host_config()
    }
}

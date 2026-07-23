use crate::config::toml::TomlConfig;

use crate::instance::CoreInstanceHostConfig;

pub(in crate::instance) struct ManagementState;

impl ManagementState {
    pub(in crate::instance) fn new(
        _toml_config: Option<TomlConfig>,
        _host_config: CoreInstanceHostConfig,
    ) -> Self {
        Self
    }
}

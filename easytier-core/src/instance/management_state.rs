use std::sync::Arc;

#[cfg(feature = "web-client")]
use std::collections::BTreeSet;

use crate::{
    config::toml::TomlConfig,
    instance::{CoreInstanceHostConfig, RuntimeConfigProjection, RuntimeConfigProjector},
};

pub(super) struct ManagementState {
    #[cfg(feature = "web-client")]
    authoritative_config: Option<TomlConfig>,
    #[cfg(feature = "web-client")]
    effective_config: Option<TomlConfig>,
    #[cfg(feature = "web-client")]
    projector: Arc<dyn RuntimeConfigProjector>,
    #[cfg(feature = "web-client")]
    warned_capabilities: parking_lot::Mutex<BTreeSet<&'static str>>,
    #[cfg(feature = "web-client")]
    host_config: CoreInstanceHostConfig,
}

impl ManagementState {
    pub(super) fn new(
        authoritative_config: Option<TomlConfig>,
        effective_config: Option<TomlConfig>,
        projector: Arc<dyn RuntimeConfigProjector>,
        suppressed_capabilities: Vec<&'static str>,
        host_config: CoreInstanceHostConfig,
    ) -> Self {
        #[cfg(not(feature = "web-client"))]
        let _ = (
            authoritative_config,
            effective_config,
            projector,
            suppressed_capabilities,
            host_config,
        );
        #[cfg(feature = "web-client")]
        {
            let state = Self {
                authoritative_config,
                effective_config,
                projector,
                warned_capabilities: parking_lot::Mutex::new(BTreeSet::new()),
                host_config,
            };
            state.record_suppressions(&suppressed_capabilities);
            state
        }
        #[cfg(not(feature = "web-client"))]
        Self {}
    }

    #[cfg(feature = "web-client")]
    pub(super) fn toml_config(&self) -> Option<TomlConfig> {
        self.authoritative_config.clone()
    }

    #[cfg(feature = "web-client")]
    pub(super) fn effective_config(&self) -> Option<TomlConfig> {
        self.effective_config.clone()
    }

    #[cfg(feature = "web-client")]
    pub(super) fn project(
        &self,
        authoritative: &TomlConfig,
    ) -> anyhow::Result<RuntimeConfigProjection> {
        let projection = self.projector.project(authoritative)?;
        self.record_suppressions(&projection.suppressed_capabilities);
        Ok(projection)
    }

    #[cfg(feature = "web-client")]
    pub(super) fn project_connector(&self, connector: &url::Url) -> Option<url::Url> {
        self.projector.project_connector(connector)
    }

    #[cfg(feature = "web-client")]
    pub(super) fn host_config(&self) -> &CoreInstanceHostConfig {
        &self.host_config
    }

    #[cfg(feature = "web-client")]
    fn record_suppressions(&self, suppressions: &[&'static str]) {
        let mut warned = self.warned_capabilities.lock();
        for capability in suppressions {
            if warned.insert(capability) {
                tracing::warn!(
                    capability,
                    "configuration is preserved but this capability is disabled at runtime"
                );
            }
        }
    }
}

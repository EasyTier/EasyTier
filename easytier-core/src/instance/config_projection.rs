use std::sync::Arc;

use url::Url;

use crate::config::toml::TomlConfig;

/// An independent configuration snapshot used by the live runtime.
pub struct RuntimeConfigProjection {
    pub effective_config: TomlConfig,
    pub suppressed_capabilities: Vec<&'static str>,
}

impl RuntimeConfigProjection {
    pub fn identity(config: &TomlConfig) -> Self {
        Self {
            effective_config: config.detached_snapshot(),
            suppressed_capabilities: Vec::new(),
        }
    }
}

/// Projects an authoritative configuration onto the capabilities of one host.
///
/// Management APIs retain the authoritative model. Only the returned detached
/// snapshot may be normalized or changed for runtime use.
pub trait RuntimeConfigProjector: Send + Sync + 'static {
    fn project(&self, authoritative: &TomlConfig) -> anyhow::Result<RuntimeConfigProjection>;

    fn project_connector(&self, connector: &Url) -> Option<Url> {
        Some(connector.clone())
    }
}

#[derive(Default)]
pub struct IdentityRuntimeConfigProjector;

impl RuntimeConfigProjector for IdentityRuntimeConfigProjector {
    fn project(&self, authoritative: &TomlConfig) -> anyhow::Result<RuntimeConfigProjection> {
        Ok(RuntimeConfigProjection::identity(authoritative))
    }
}

pub(crate) fn identity_runtime_config_projector() -> Arc<dyn RuntimeConfigProjector> {
    Arc::new(IdentityRuntimeConfigProjector)
}

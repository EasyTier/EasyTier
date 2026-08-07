use std::sync::Arc;

use url::Url;

use crate::config::toml::TomlConfig;

/// The configuration used by the live runtime after host projection.
pub struct RuntimeConfigProjection {
    pub effective_config: TomlConfig,
    pub suppressed_capabilities: Vec<&'static str>,
}

impl RuntimeConfigProjection {
    pub fn identity(config: &TomlConfig) -> Self {
        Self {
            effective_config: config.clone(),
            suppressed_capabilities: Vec::new(),
        }
    }
}

/// Projects an authoritative configuration onto the capabilities of one host.
///
/// Projectors that suppress capabilities must return an independent runtime
/// snapshot so management can retain the authoritative model unchanged.
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

#[cfg(test)]
mod tests {
    use crate::config::toml::ConfigLoader as _;

    use super::*;

    #[test]
    fn identity_projection_preserves_shared_config_semantics() {
        let authoritative = TomlConfig::default();
        let projection = RuntimeConfigProjection::identity(&authoritative);

        projection
            .effective_config
            .set_ipv4(Some("10.144.144.7/24".parse().unwrap()));

        assert_eq!(
            authoritative.get_ipv4(),
            Some("10.144.144.7/24".parse().unwrap())
        );
    }
}

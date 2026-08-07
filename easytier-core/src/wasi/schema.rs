//! Versioned, serialized inputs accepted by the WASI instance lifecycle ABI.

use serde::{Deserialize, Serialize};

use crate::{
    config::toml::TomlConfig, connectivity::connector_host::HostConnectorEnvironmentSnapshot,
};

pub(crate) const WASI_CORE_INSTANCE_CONFIG_VERSION: u32 =
    crate::wasi::abi::CORE_INSTANCE_CONFIG_VERSION;
#[cfg(all(target_os = "wasi", feature = "management"))]
pub(crate) const WASI_WEB_CLIENT_CONFIG_VERSION: u32 = crate::wasi::abi::WEB_CLIENT_CONFIG_VERSION;

/// Versioned payload accepted by host-driven instance frontends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WasiCoreInstanceCreateConfig {
    pub version: u32,
    pub config: String,
    pub environment: HostConnectorEnvironmentSnapshot,
}

impl WasiCoreInstanceCreateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != WASI_CORE_INSTANCE_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported host core instance config version: {}",
                self.version
            );
        }
        Ok(())
    }

    pub fn parse_config(&self) -> anyhow::Result<TomlConfig> {
        TomlConfig::new_from_str_with_source("WASI create config", &self.config)
    }
}

#[cfg(all(target_os = "wasi", feature = "management"))]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WasiWebClientCreateConfig {
    pub version: u32,
    pub endpoint: String,
    pub machine_id: String,
    pub hostname: String,
    pub secure_mode: bool,
    pub os_type: String,
    pub environment: HostConnectorEnvironmentSnapshot,
}

#[cfg(all(target_os = "wasi", feature = "management"))]
impl WasiWebClientCreateConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != WASI_WEB_CLIENT_CONFIG_VERSION {
            anyhow::bail!(
                "unsupported host WebClient config version: {}",
                self.version
            );
        }
        uuid::Uuid::parse_str(&self.machine_id)?;
        Ok(())
    }
}

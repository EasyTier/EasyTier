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

#[cfg(feature = "wasm-host-tunnel")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WasiHostTunnelMetadata {
    pub version: u32,
    pub local_url: url::Url,
    pub remote_url: url::Url,
    #[serde(default)]
    pub resolved_remote_url: Option<url::Url>,
}

#[cfg(feature = "wasm-host-tunnel")]
impl WasiHostTunnelMetadata {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        if self.version != crate::wasi::abi::HOST_TUNNEL_ABI_VERSION {
            anyhow::bail!("unsupported host tunnel ABI version: {}", self.version);
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "wasm-host-tunnel"))]
mod tests {
    use super::*;

    #[test]
    fn host_tunnel_metadata_accepts_transport_neutral_urls() {
        let metadata = WasiHostTunnelMetadata {
            version: crate::wasi::abi::HOST_TUNNEL_ABI_VERSION,
            local_url: "test-tunnel://listener.example/".parse().unwrap(),
            remote_url: "test-tunnel://peer.example/".parse().unwrap(),
            resolved_remote_url: None,
        };

        metadata.validate().unwrap();
    }
}

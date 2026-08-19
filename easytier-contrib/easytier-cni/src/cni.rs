use std::{env, path::PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub(crate) const SUPPORTED_VERSIONS: &[&str] = &["1.0.0"];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PluginConfig {
    pub(crate) cni_version: String,
    pub(crate) name: String,
    #[serde(default = "default_rpc_portal")]
    pub(crate) rpc_portal: String,
    pub(crate) network_name: String,
    pub(crate) network_secret_file: PathBuf,
    #[serde(default)]
    pub(crate) peers: Vec<String>,
    #[serde(default = "default_mtu")]
    pub(crate) mtu: u16,
    #[serde(default = "default_timeout_seconds")]
    pub(crate) timeout_seconds: u64,
    pub(crate) ipam: IpamConfig,
    #[serde(default)]
    pub(crate) prev_result: Option<Value>,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IpamConfig {
    #[serde(rename = "type")]
    pub(crate) plugin_type: String,
    #[serde(flatten)]
    _extra: Map<String, Value>,
}

#[derive(Debug)]
pub(crate) struct CniArgs {
    pub(crate) command: String,
    pub(crate) container_id: Option<String>,
    pub(crate) netns: Option<String>,
    pub(crate) ifname: Option<String>,
    pub(crate) path: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CniResult {
    #[serde(rename = "cniVersion")]
    pub(crate) cni_version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) interfaces: Vec<CniInterface>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) ips: Vec<CniIp>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) routes: Vec<CniRoute>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns: Option<Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CniInterface {
    pub(crate) name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) sandbox: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CniIp {
    pub(crate) address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gateway: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) interface: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct CniRoute {
    dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    gw: Option<String>,
}

fn default_rpc_portal() -> String {
    "unix:///run/easytier-cni/rpc.sock".to_string()
}

fn default_mtu() -> u16 {
    1380
}

fn default_timeout_seconds() -> u64 {
    30
}

pub(crate) fn parse_args() -> CniArgs {
    CniArgs {
        command: env::var("CNI_COMMAND").unwrap_or_default(),
        container_id: env::var("CNI_CONTAINERID").ok(),
        netns: env::var("CNI_NETNS").ok().filter(|value| !value.is_empty()),
        ifname: env::var("CNI_IFNAME").ok(),
        path: env::var_os("CNI_PATH")
            .map(|value| env::split_paths(&value).collect())
            .unwrap_or_default(),
    }
}

pub(crate) fn validate_version(version: &str) -> Result<()> {
    ensure!(
        SUPPORTED_VERSIONS.contains(&version),
        "unsupported CNI version {version}"
    );
    Ok(())
}

pub(crate) fn required_attachment_args(args: &CniArgs) -> Result<(&str, &str)> {
    let container_id = args
        .container_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("CNI_CONTAINERID is required")?;
    let ifname = args
        .ifname
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("CNI_IFNAME is required")?;
    Ok((container_id, ifname))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_minimal_config() {
        let config: PluginConfig = serde_json::from_value(json!({
            "cniVersion": "1.0.0",
            "name": "overlay",
            "type": "easytier-cni",
            "networkName": "cluster",
            "networkSecretFile": "/etc/easytier/secret",
            "peers": ["tcp://192.0.2.1:11010"],
            "ipam": {"type": "whereabouts", "range": "10.200.0.0/24"}
        }))
        .unwrap();
        assert_eq!(config.rpc_portal, default_rpc_portal());
        assert_eq!(config.mtu, 1380);
        assert_eq!(config.ipam.plugin_type, "whereabouts");
    }
}

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use easytier_proto::common::{PortForwardConfigPb, SocketType};

/// Runtime configuration for the core-owned SOCKS and port-forward gateway.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayRuntimeConfig {
    pub socks5_bind: Option<SocketAddr>,
    pub port_forwards: Vec<PortForwardConfig>,
}

/// One TCP or UDP port-forward rule.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PortForwardConfig {
    pub bind_addr: SocketAddr,
    pub dst_addr: SocketAddr,
    pub proto: String,
}

impl From<PortForwardConfigPb> for PortForwardConfig {
    fn from(config: PortForwardConfigPb) -> Self {
        Self {
            bind_addr: config.bind_addr.unwrap_or_default().into(),
            dst_addr: config.dst_addr.unwrap_or_default().into(),
            proto: match SocketType::try_from(config.socket_type) {
                Ok(SocketType::Tcp) => "tcp".to_string(),
                Ok(SocketType::Udp) => "udp".to_string(),
                _ => "tcp".to_string(),
            },
        }
    }
}

impl From<PortForwardConfig> for PortForwardConfigPb {
    fn from(config: PortForwardConfig) -> Self {
        Self {
            bind_addr: Some(config.bind_addr.into()),
            dst_addr: Some(config.dst_addr.into()),
            socket_type: match config.proto.to_lowercase().as_str() {
                "tcp" => SocketType::Tcp as i32,
                "udp" => SocketType::Udp as i32,
                _ => SocketType::Tcp as i32,
            },
        }
    }
}

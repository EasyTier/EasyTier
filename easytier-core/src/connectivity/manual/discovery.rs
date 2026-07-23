use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::socket::{IpVersion, SocketContext, tcp::TcpBindOptions};

#[cfg(feature = "endpoint-discovery")]
#[path = "discovery/enabled.rs"]
mod selected;
#[cfg(not(feature = "endpoint-discovery"))]
#[path = "discovery/disabled.rs"]
mod selected;

pub(crate) use selected::CoreManualEndpointResolver;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualEndpointDiscoveryConfig {
    pub user_agent: String,
    pub network_name: String,
    pub http_timeout: Duration,
    pub http_ip_version: IpVersion,
    pub http_tcp_bind: TcpBindOptions,
    pub dns_record_context: SocketContext,
    pub srv_protocols: Vec<String>,
}

impl Default for ManualEndpointDiscoveryConfig {
    fn default() -> Self {
        Self {
            user_agent: "easytier-core".to_owned(),
            network_name: String::new(),
            http_timeout: Duration::from_secs(20),
            http_ip_version: IpVersion::Both,
            http_tcp_bind: TcpBindOptions::default(),
            dns_record_context: SocketContext::default(),
            srv_protocols: vec!["tcp".to_owned(), "udp".to_owned()],
        }
    }
}

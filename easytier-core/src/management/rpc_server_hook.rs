use std::{net::IpAddr, sync::Arc};

use cidr::IpCidr;
use easytier_proto::common::TunnelInfo;

use crate::rpc::standalone::RpcServerHook;

/// Restricts the process-level management endpoint to configured client CIDRs.
pub struct ManagementRpcServerHook {
    whitelist: Vec<IpCidr>,
}

impl ManagementRpcServerHook {
    pub fn new(whitelist: Option<Vec<IpCidr>>) -> Self {
        Self {
            whitelist: whitelist.unwrap_or_else(|| {
                vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()]
            }),
        }
    }
}

#[async_trait::async_trait]
impl RpcServerHook for ManagementRpcServerHook {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        let tunnel_info = tunnel_info.ok_or_else(|| anyhow::anyhow!("tunnel info is None"))?;
        let remote_url = tunnel_info
            .remote_addr
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("remote_addr is None"))?;
        let url = url::Url::parse(&remote_url.url)
            .map_err(|error| anyhow::anyhow!("failed to parse remote URL: {error}"))?;
        let host = url
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("remote URL has no host"))?;
        let ip_addr: IpAddr = host
            .parse()
            .map_err(|error| anyhow::anyhow!("failed to parse client IP {host}: {error}"))?;

        if self.whitelist.iter().any(|cidr| cidr.contains(&ip_addr)) {
            return Ok(Some(tunnel_info));
        }

        Err(anyhow::anyhow!(
            "RPC portal client IP {} is not in whitelist {:?}",
            ip_addr,
            self.whitelist
        ))
    }
}

impl From<ManagementRpcServerHook> for Arc<dyn RpcServerHook> {
    fn from(value: ManagementRpcServerHook) -> Self {
        Arc::new(value)
    }
}

pub use easytier_core::proxy::socks5_protocol::{AddrError, TargetAddr};

use anyhow::Context;
use tokio::net::lookup_host;

pub async fn resolve_dns(target_addr: TargetAddr) -> anyhow::Result<TargetAddr> {
    match target_addr {
        TargetAddr::Ip(ip) => Ok(TargetAddr::Ip(ip)),
        TargetAddr::Domain(domain, port) => {
            tracing::debug!("Attempt to DNS resolve the domain {}...", &domain);
            let socket_addr = lookup_host((&domain[..], port))
                .await
                .context(AddrError::DNSResolutionFailed)?
                .next()
                .ok_or_else(|| AddrError::Custom("Can't fetch DNS to the domain.".to_string()))?;
            tracing::debug!("domain name resolved to {}", socket_addr);
            Ok(TargetAddr::Ip(socket_addr))
        }
    }
}

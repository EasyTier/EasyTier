use std::net::SocketAddr;

use crate::{
    common::{dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx},
    tunnel::{IpScheme, IpVersion},
};

use super::{ConnectorResolver, ResolvedCandidate};

const DEFAULT_DNS_REFRESH_SECS: u64 = 300;

#[derive(Debug)]
pub struct DnsResolver {
    source_url: url::Url,
    scheme: IpScheme,
    ip_version: IpVersion,
    global_ctx: ArcGlobalCtx,
}

impl DnsResolver {
    pub fn new(
        source_url: url::Url,
        scheme: IpScheme,
        ip_version: IpVersion,
        global_ctx: ArcGlobalCtx,
    ) -> Self {
        Self {
            source_url,
            scheme,
            ip_version,
            global_ctx,
        }
    }

    fn default_port(&self) -> Option<u16> {
        Some(self.scheme.default_port())
    }

    fn addr_matches_ip_version(addr: &SocketAddr, ip_version: IpVersion) -> bool {
        match ip_version {
            IpVersion::V4 => addr.is_ipv4(),
            IpVersion::V6 => addr.is_ipv6(),
            IpVersion::Both => true,
        }
    }

    async fn is_ipv6_rejected(&self, addr: &SocketAddr) -> Result<bool, Error> {
        let SocketAddr::V6(v6_addr) = addr else {
            return Ok(false);
        };
        if self.global_ctx.is_ip_easytier_managed_ipv6(v6_addr.ip()) {
            return Ok(true);
        }
        Ok(false)
    }
}

#[async_trait::async_trait]
impl ConnectorResolver for DnsResolver {
    async fn resolve(&self) -> Result<Vec<ResolvedCandidate>, Error> {
        let protocol = self.scheme.to_string();

        let addrs = socket_addrs(&self.source_url, || self.default_port()).await?;

        let mut usable_addrs: Vec<SocketAddr> = Vec::new();
        for addr in addrs.into_iter().filter(|a| Self::addr_matches_ip_version(a, self.ip_version)) {
            if self.is_ipv6_rejected(&addr).await? {
                tracing::debug!("DnsResolver: skipping easytier-managed IPv6: {}", addr);
                continue;
            }
            usable_addrs.push(addr);
        }

        if usable_addrs.is_empty() {
            return Ok(vec![]);
        }

        let candidates: Vec<ResolvedCandidate> = usable_addrs
            .iter()
            .map(|addr| {
                let url_str = format!("{}://{}", protocol, addr);
                ResolvedCandidate {
                    url: url::Url::parse(&url_str).expect("valid url from socket addr"),
                }
            })
            .collect();

        Ok(candidates)
    }

    fn refresh_interval_secs(&self) -> u64 {
        DEFAULT_DNS_REFRESH_SECS
    }

    fn source_url(&self) -> &url::Url {
        &self.source_url
    }
}

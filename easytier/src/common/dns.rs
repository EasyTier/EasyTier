use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context;
use hickory_proto::runtime::TokioRuntimeProvider;
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::Lazy;
use tokio::net::lookup_host;

use super::error::Error;

pub fn get_default_resolver_config() -> ResolverConfig {
    let mut default_resolve_config = ResolverConfig::new();
    default_resolve_config.add_name_server(NameServerConfig::new(
        "223.5.5.5:53".parse().unwrap(),
        Protocol::Udp,
    ));
    default_resolve_config.add_name_server(NameServerConfig::new(
        "180.184.1.1:53".parse().unwrap(),
        Protocol::Udp,
    ));
    default_resolve_config
}

pub static ALLOW_USE_SYSTEM_DNS_RESOLVER: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(true));

pub static RESOLVER: Lazy<Arc<Resolver<GenericConnector<TokioRuntimeProvider>>>> =
    Lazy::new(|| {
        let system_cfg = read_system_conf();
        let mut cfg = get_default_resolver_config();
        let mut opt = ResolverOpts::default();
        if let Ok(s) = system_cfg {
            for ns in s.0.name_servers() {
                cfg.add_name_server(ns.clone());
            }
            opt = s.1;
        }
        opt.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        let builder = TokioResolver::builder_with_config(cfg, TokioConnectionProvider::default())
            .with_options(opt);
        Arc::new(builder.build())
    });

pub async fn resolve_txt_record(domain_name: &str) -> Result<String, Error> {
    let r = RESOLVER.clone();
    let response = r.txt_lookup(domain_name).await.with_context(|| {
        format!(
            "txt_lookup failed, domain_name: {}",
            domain_name.to_string()
        )
    })?;

    let txt_record = response.iter().next().with_context(|| {
        format!(
            "no txt record found, domain_name: {}",
            domain_name.to_string()
        )
    })?;

    let txt_data = String::from_utf8_lossy(&txt_record.txt_data()[0]);
    tracing::info!(?txt_data, ?domain_name, "get txt record");

    Ok(txt_data.to_string())
}

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    let host = url.host_str().ok_or(Error::InvalidUrl(url.to_string()))?;
    let port = url
        .port()
        .or_else(default_port_number)
        .ok_or(Error::InvalidUrl(url.to_string()))?;
    // See https://github.com/EasyTier/EasyTier/pull/947
    let port = match port {
        0 => match url.scheme() {
            "ws" => 80,
            "wss" => 443,
            _ => port,
        },
        _ => port,
    };

    // if host is an ip address, return it directly
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    if ALLOW_USE_SYSTEM_DNS_RESOLVER.load(std::sync::atomic::Ordering::Relaxed) {
        let socket_addr = format!("{}:{}", host, port);
        match lookup_host(socket_addr).await {
            Ok(a) => {
                let a = a.collect();
                tracing::debug!(?a, "system dns lookup done");
                return Ok(a);
            }
            Err(e) => {
                tracing::error!(?e, "system dns lookup failed");
            }
        }
    }

    // use hickory_resolver
    let ret = RESOLVER.lookup_ip(host).await.with_context(|| {
        format!(
            "hickory dns lookup_ip failed, host: {}, port: {}",
            host, port
        )
    })?;
    Ok(ret
        .iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use crate::defer;

    use super::*;

    #[tokio::test]
    async fn test_socket_addrs() {
        let url = url::Url::parse("tcp://public.easytier.cn:80").unwrap();
        let addrs = socket_addrs(&url, || Some(80)).await.unwrap();
        assert_eq!(2, addrs.len(), "addrs: {:?}", addrs);
        println!("addrs: {:?}", addrs);

        ALLOW_USE_SYSTEM_DNS_RESOLVER.store(false, std::sync::atomic::Ordering::Relaxed);
        defer!(
            ALLOW_USE_SYSTEM_DNS_RESOLVER.store(true, std::sync::atomic::Ordering::Relaxed);
        );
        let addrs = socket_addrs(&url, || Some(80)).await.unwrap();
        assert_eq!(2, addrs.len(), "addrs: {:?}", addrs);
        println!("addrs2: {:?}", addrs);
    }
}

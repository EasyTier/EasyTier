use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Context;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::{IntoName, RData};
use hickory_proto::rr::rdata::SRV;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::Lazy;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::net::lookup_host;

use crate::common::error::Error;

pub fn get_default_resolver_config() -> ResolverConfig {
    let mut config = ResolverConfig::default();
    for server in ["223.5.5.5", "180.184.1.1"] {
        config.add_name_server(NameServerConfig::new(
            server.parse().unwrap(),
            true,
            vec![ConnectionConfig::udp()],
        ));
    }
    config
}

pub static ALLOW_USE_SYSTEM_DNS_RESOLVER: AtomicBool = AtomicBool::new(true);

pub static RESOLVER: Lazy<Arc<Resolver<TokioRuntimeProvider>>> = Lazy::new(|| {
    let mut cfg = get_default_resolver_config();
    let mut opt = ResolverOpts::default();
    if let Ok((sys_cfg, sys_opt)) = read_system_conf() {
        for ns in sys_cfg.name_servers() {
            cfg.add_name_server(ns.clone());
        }
        opt = sys_opt;
    }
    opt.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    let builder =
        TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default()).with_options(opt);
    Arc::new(
        builder
            .build()
            .expect("failed to initialize global DNS resolver"),
    )
});

pub async fn txt_lookup(name: impl IntoName) -> Result<Vec<String>, Error> {
    let response = RESOLVER
        .txt_lookup(name)
        .await
        .context("failed to lookup txt record")?;

    let data = response
        .answers()
        .iter()
        .filter_map(|record| match record.data {
            RData::TXT(ref txt) => Some(txt.to_string()),
            _ => None,
        })
        .collect();

    tracing::info!(?data, "got txt record(s)");

    Ok(data)
}

pub async fn txt_resolve(name: impl IntoName) -> Result<Vec<String>, Error> {
    Ok(txt_lookup(name)
        .await?
        .iter()
        .flat_map(|s| s.split_whitespace())
        .map(String::from)
        .collect())
}

pub async fn srv_lookup(name: impl IntoName) -> Result<Vec<SRV>, Error> {
    let response = RESOLVER
        .srv_lookup(name)
        .await
        .context("failed to lookup srv record")?;

    let data = response
        .answers()
        .iter()
        .filter_map(|record| match record.data {
            RData::SRV(ref srv) => Some(srv.clone()),
            _ => None,
        })
        .collect();

    tracing::info!(?data, "got srv record(s)");

    Ok(data)
}

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    let host = url.host().ok_or(Error::InvalidUrl(url.to_string()))?;
    let port = url
        .port()
        .or_else(default_port_number)
        .ok_or(Error::InvalidUrl(url.to_string()))?;
    // See https://github.com/EasyTier/EasyTier/pull/947
    // here is for compatibility with old version
    let port = match port {
        0 => match url.scheme() {
            "ws" => 80,
            "wss" => 443,
            _ => port,
        },
        _ => port,
    };

    // if host is an ip address, return it directly
    match host {
        url::Host::Ipv4(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V4(ip), port)]),
        url::Host::Ipv6(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V6(ip), port)]),
        _ => {}
    }
    let host = host.to_string();

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
    let ret = RESOLVER.lookup_ip(&host).await.with_context(|| {
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
        let url = url::Url::parse("tcp://github-ci-test.easytier.cn:80").unwrap();
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

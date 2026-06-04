use crate::common::error::Error;
use anyhow::Context;
use hickory_net::runtime::TokioRuntimeProvider;
use hickory_proto::rr::rdata::SRV;
use hickory_proto::rr::{IntoName, LowerName, RData};
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use idna::AsciiDenyList;
use once_cell::sync::Lazy;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::RwLock;
use std::sync::atomic::AtomicBool;
use tokio::net::lookup_host;

const SYSTEM_DNS_RESOLVER: &str = "system";

#[derive(Clone)]
enum DnsResolver {
    System,
    Hickory {
        uri: String,
        resolver: Arc<Resolver<TokioRuntimeProvider>>,
    },
}

pub fn get_default_dns_resolvers() -> Vec<String> {
    vec![SYSTEM_DNS_RESOLVER.to_string()]
}

fn bootstrap_ips_for_doh_host(host: &str) -> Option<Vec<IpAddr>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(vec![ip]);
    }

    match host {
        "dns.alidns.com" => Some(vec![
            IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5)),
            IpAddr::V4(Ipv4Addr::new(223, 6, 6, 6)),
            IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2400, 0x3200, 0xbaba, 0, 0, 0, 0, 1)),
        ]),
        _ => None,
    }
}

fn build_hickory_resolver(
    config: ResolverConfig,
) -> Result<Arc<Resolver<TokioRuntimeProvider>>, Error> {
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    Ok(Arc::new(
        TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
            .with_options(opts)
            .build()
            .context("failed to build DNS resolver")?,
    ))
}

fn build_doh_resolver(raw: &str) -> Result<DnsResolver, Error> {
    let url = url::Url::parse(raw).map_err(|e| Error::InvalidUrl(e.to_string()))?;
    if url.scheme() != "https" {
        return Err(anyhow::anyhow!("unsupported dns resolver scheme: {}", url.scheme()).into());
    }

    let host = url
        .host_str()
        .with_context(|| format!("DoH resolver host is empty: {}", raw))?;
    let ips = bootstrap_ips_for_doh_host(host).with_context(|| {
        format!(
            "DoH resolver {} requires a known bootstrap IP; currently only dns.alidns.com or IP literals are supported",
            raw
        )
    })?;
    let port = url.port().unwrap_or(443);
    let server_name: Arc<str> = Arc::from(host.to_string());
    let http_endpoint: Option<Arc<str>> = match url.path() {
        "" | "/" | "/dns-query" => None,
        path => Some(Arc::from(path.to_string())),
    };

    let name_servers = ips
        .into_iter()
        .map(|ip| {
            let mut connection =
                ConnectionConfig::https(server_name.clone(), http_endpoint.clone());
            connection.port = port;

            NameServerConfig::new(ip, true, vec![connection])
        })
        .collect::<Vec<_>>();

    Ok(DnsResolver::Hickory {
        uri: raw.to_string(),
        resolver: build_hickory_resolver(ResolverConfig::from_parts(
            None,
            Vec::new(),
            name_servers,
        ))?,
    })
}

fn build_dns_resolver(raw: &str) -> Result<DnsResolver, Error> {
    if raw.eq_ignore_ascii_case(SYSTEM_DNS_RESOLVER) {
        return Ok(DnsResolver::System);
    }

    build_doh_resolver(raw)
}

fn build_dns_resolvers(raw_resolvers: &[String]) -> Result<Vec<DnsResolver>, Error> {
    let raw_resolvers = if raw_resolvers.is_empty() {
        get_default_dns_resolvers()
    } else {
        raw_resolvers.to_vec()
    };

    raw_resolvers
        .iter()
        .map(|raw| build_dns_resolver(raw))
        .collect()
}

pub fn validate_dns_resolvers(raw_resolvers: &[String]) -> Result<(), Error> {
    build_dns_resolvers(raw_resolvers).map(|_| ())
}

pub fn set_dns_resolvers(raw_resolvers: Vec<String>) -> Result<(), Error> {
    let resolvers = build_dns_resolvers(&raw_resolvers)?;
    *DNS_RESOLVERS.write().unwrap() = resolvers;
    Ok(())
}

static DNS_RESOLVERS: Lazy<RwLock<Vec<DnsResolver>>> =
    Lazy::new(|| RwLock::new(build_dns_resolvers(&get_default_dns_resolvers()).unwrap()));

fn configured_dns_resolvers() -> Vec<DnsResolver> {
    DNS_RESOLVERS.read().unwrap().clone()
}

pub fn sanitize(name: impl AsRef<str>) -> String {
    let name = name.as_ref();
    let dot = name.ends_with('.');
    let mut name = idna::domain_to_ascii_cow(name.as_ref(), AsciiDenyList::EMPTY)
        .unwrap_or_default()
        .into_owned()
        .to_lowercase()
        .split('.')
        .map(|label| {
            label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(63)
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    name.truncate(253);
    if dot {
        name.push('.');
    }
    name
}

pub fn parse(name: impl AsRef<str>) -> LowerName {
    let name = name.as_ref();
    if let Ok(name) = name.parse() {
        name
    } else {
        let sanitized = sanitize(name);
        tracing::debug!("invalid name: {}, sanitized to: {}", name, sanitized);
        sanitized.parse().unwrap_or_default()
    }
}

pub fn resolver_conf() -> (ResolverConfig, ResolverOpts) {
    let mut config = ResolverConfig::default();
    for server in ["223.5.5.5", "180.184.1.1"] {
        config.add_name_server(NameServerConfig::new(
            server.parse().unwrap(),
            true,
            vec![ConnectionConfig::udp()],
        ));
    }

    let mut opts = ResolverOpts::default();

    if let Ok((system_config, system_opts)) = read_system_conf() {
        for ns in system_config.name_servers() {
            config.add_name_server(ns.clone());
        }
        opts = system_opts;
    }

    opts.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;

    (config, opts)
}

static ALLOW_USE_SYSTEM_DNS_RESOLVER: AtomicBool = AtomicBool::new(true);

static RESOLVER: Lazy<Arc<Resolver<TokioRuntimeProvider>>> = Lazy::new(|| {
    let (config, opts) = resolver_conf();
    let builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts);
    Arc::new(
        builder
            .build()
            .expect("failed to initialize global DNS resolver"),
    )
});

pub async fn txt_lookup(name: impl IntoName) -> Result<Vec<String>, Error> {
    let name = name.into_name().context("invalid txt record name")?;
    let mut last_err = None;

    for resolver in configured_dns_resolvers() {
        let response = match resolver {
            DnsResolver::System => RESOLVER.txt_lookup(name.clone()).await,
            DnsResolver::Hickory { uri, resolver } => {
                let response = resolver.txt_lookup(name.clone()).await;
                if response.is_err() {
                    tracing::debug!(?uri, ?name, "txt lookup failed with resolver");
                }
                response
            }
        };

        let Ok(response) = response else {
            last_err = Some(anyhow::anyhow!("failed to lookup txt record").into());
            continue;
        };

        let data = response
            .answers()
            .iter()
            .filter_map(|record| match record.data {
                RData::TXT(ref txt) => Some(txt.to_string()),
                _ => None,
            })
            .collect::<Vec<_>>();

        if data.is_empty() {
            last_err = Some(Error::NotFound);
            continue;
        }

        tracing::info!(?data, "got txt record(s)");

        return Ok(data);
    }

    Err(last_err.unwrap_or(Error::NotFound))
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
    let name = name.into_name().context("invalid srv record name")?;
    let mut last_err = None;

    for resolver in configured_dns_resolvers() {
        let response = match resolver {
            DnsResolver::System => RESOLVER.srv_lookup(name.clone()).await,
            DnsResolver::Hickory { uri, resolver } => {
                let response = resolver.srv_lookup(name.clone()).await;
                if response.is_err() {
                    tracing::debug!(?uri, ?name, "srv lookup failed with resolver");
                }
                response
            }
        };

        let Ok(response) = response else {
            last_err = Some(anyhow::anyhow!("failed to lookup srv record").into());
            continue;
        };

        let data = response
            .answers()
            .iter()
            .filter_map(|record| match record.data {
                RData::SRV(ref srv) => Some(srv.clone()),
                _ => None,
            })
            .collect::<Vec<_>>();

        if data.is_empty() {
            last_err = Some(Error::NotFound);
            continue;
        }

        tracing::info!(?data, "got srv record(s)");

        return Ok(data);
    }

    Err(last_err.unwrap_or(Error::NotFound))
}

pub async fn resolve_host(host: &str, port: u16) -> Result<Vec<SocketAddr>, Error> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    let mut last_err = None;
    for resolver in configured_dns_resolvers() {
        match resolver {
            DnsResolver::System => {
                if !ALLOW_USE_SYSTEM_DNS_RESOLVER.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }

                match lookup_host(format!("{}:{}", host, port)).await {
                    Ok(addrs) => {
                        let addrs = addrs.collect::<Vec<_>>();
                        if !addrs.is_empty() {
                            tracing::debug!(?addrs, "system dns lookup done");
                            return Ok(addrs);
                        }
                    }
                    Err(error) => {
                        tracing::debug!(?error, "system dns lookup failed");
                        last_err = Some(Error::from(error));
                    }
                }
            }
            DnsResolver::Hickory { uri, resolver } => match resolver.lookup_ip(host).await {
                Ok(lookup) => {
                    let addrs = lookup
                        .iter()
                        .map(|ip| SocketAddr::new(ip, port))
                        .collect::<Vec<_>>();
                    if !addrs.is_empty() {
                        return Ok(addrs);
                    }
                }
                Err(error) => {
                    tracing::debug!(?uri, ?host, ?error, "hickory dns lookup failed");
                    last_err = Some(
                        anyhow::anyhow!(
                            "hickory dns lookup_ip failed, host: {}, port: {}",
                            host,
                            port
                        )
                        .into(),
                    );
                }
            },
        }
    }

    Err(last_err.unwrap_or(Error::NotFound))
}

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    let host = url.host().ok_or(Error::InvalidUrl(url.to_string()))?;

    // see https://github.com/EasyTier/EasyTier/pull/947, https://github.com/EasyTier/EasyTier/pull/1700
    let port = url
        .port()
        .or_else(default_port_number)
        .ok_or(Error::InvalidUrl(url.to_string()))?;

    // if host is an ip address, return it directly
    if let Some(ip) = match host {
        url::Host::Ipv4(ip) => Some(ip.into()),
        url::Host::Ipv6(ip) => Some(ip.into()),
        _ => None,
    } {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }

    resolve_host(&host.to_string(), port).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use guarden::defer;

    #[test]
    fn parse_matrix_cases() {
        let cases = [
            ["Example.COM.", "example.com."],
            ["a_b!.et.net.", "a-b.et.net."],
            ["foo..bar.com.", "foo.bar.com."],
            [
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com.",
            ],
            ["___", "___"],
            ["!", ""],
            ["", ""],
        ];

        for [input, expected] in cases {
            let parsed = parse(input);
            let expected: LowerName = expected.parse().unwrap();
            assert_eq!(
                parsed, expected,
                "parse({input:?}) should equal {expected:?}, got {parsed:?}"
            );
        }
    }

    #[test]
    fn default_dns_resolver_is_system() {
        assert_eq!(get_default_dns_resolvers(), vec!["system".to_string()]);
        assert!(matches!(
            build_dns_resolvers(&get_default_dns_resolvers()).unwrap()[0],
            DnsResolver::System
        ));
    }

    #[test]
    fn alidns_doh_resolver_is_supported() {
        validate_dns_resolvers(&["https://dns.alidns.com/dns-query".to_string()]).unwrap();
    }

    #[test]
    fn unknown_doh_resolver_requires_bootstrap_ip() {
        assert!(validate_dns_resolvers(&["https://example.com/dns-query".to_string()]).is_err());
    }

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

    #[tokio::test]
    async fn socket_addrs_preserves_explicit_zero_port() {
        let cases = [
            ("ws://127.0.0.1:0", 80, 0),
            ("wss://127.0.0.1:0", 443, 0),
            ("ws://127.0.0.1", 80, 80),
            ("wss://127.0.0.1", 443, 443),
        ];

        for (raw_url, default_port, expected_port) in cases {
            let url = url::Url::parse(raw_url).unwrap();
            let addrs = socket_addrs(&url, || Some(default_port)).await.unwrap();
            assert_eq!(
                addrs,
                vec![SocketAddr::from(([127, 0, 0, 1], expected_port))]
            );
        }
    }
}

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use async_trait::async_trait;
use easytier_core::host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};
use easytier_core::socket::SocketContext;
use hickory_proto::runtime::{RuntimeProvider, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
use hickory_resolver::system_conf::read_system_conf;
use hickory_resolver::{Resolver, TokioResolver};
use once_cell::sync::Lazy;
use tokio::net::{TcpSocket, TcpStream, UdpSocket, lookup_host};

use super::error::Error;
use super::netns::NetNS;
use crate::tunnel::common::apply_socket_mark;

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

fn resolver_config() -> (ResolverConfig, ResolverOpts) {
    let system_cfg = read_system_conf();
    let mut config = get_default_resolver_config();
    let mut options = ResolverOpts::default();
    if let Ok(system) = system_cfg {
        for name_server in system.0.name_servers() {
            config.add_name_server(name_server.clone());
        }
        options = system.1;
    }
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    (config, options)
}

static RESOLVER: Lazy<Arc<Resolver<GenericConnector<TokioRuntimeProvider>>>> = Lazy::new(|| {
    let (config, options) = resolver_config();
    let builder = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(options);
    Arc::new(builder.build())
});

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct RuntimeDnsIoContext {
    netns: Option<String>,
    socket_mark: Option<u32>,
}

impl RuntimeDnsIoContext {
    fn from_socket_context(context: &SocketContext) -> Self {
        Self {
            netns: context
                .netns
                .as_ref()
                .map(|namespace| namespace.token().to_owned()),
            socket_mark: context.socket_mark,
        }
    }

    fn netns(&self) -> NetNS {
        NetNS::new(self.netns.clone())
    }

    fn is_process_default(&self) -> bool {
        self.netns.is_none() && self.socket_mark.is_none()
    }
}

#[derive(Clone)]
struct RuntimeDnsIoProvider {
    inner: TokioRuntimeProvider,
    context: RuntimeDnsIoContext,
}

impl RuntimeDnsIoProvider {
    fn new(context: RuntimeDnsIoContext) -> Self {
        Self {
            inner: TokioRuntimeProvider::new(),
            context,
        }
    }
}

fn create_dns_tcp_socket(
    context: &RuntimeDnsIoContext,
    server_addr: SocketAddr,
    bind_addr: Option<SocketAddr>,
) -> io::Result<TcpSocket> {
    context.netns().run(|| {
        let socket = if server_addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        apply_socket_mark(&socket2::SockRef::from(&socket), context.socket_mark)
            .map_err(io::Error::other)?;
        if let Some(bind_addr) = bind_addr {
            socket.bind(bind_addr)?;
        }
        socket.set_nodelay(true)?;
        Ok(socket)
    })
}

fn create_dns_udp_socket(
    context: &RuntimeDnsIoContext,
    local_addr: SocketAddr,
) -> io::Result<UdpSocket> {
    context.netns().run(|| {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(local_addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.set_nonblocking(true)?;
        apply_socket_mark(&socket, context.socket_mark).map_err(io::Error::other)?;
        socket.bind(&socket2::SockAddr::from(local_addr))?;
        let socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(socket)
    })
}

impl RuntimeProvider for RuntimeDnsIoProvider {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = UdpSocket;
    type Tcp = AsyncIoTokioAsStd<TcpStream>;

    fn create_handle(&self) -> Self::Handle {
        self.inner.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        wait_for: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Tcp>>>> {
        // setns is thread-local. Create the socket synchronously while the
        // guard is active, then perform only descriptor I/O after it is gone.
        let socket = create_dns_tcp_socket(&self.context, server_addr, bind_addr);
        Box::pin(async move {
            let socket = socket?;
            let wait_for = wait_for.unwrap_or(Duration::from_secs(5));
            match tokio::time::timeout(wait_for, socket.connect(server_addr)).await {
                Ok(Ok(stream)) => Ok(AsyncIoTokioAsStd(stream)),
                Ok(Err(error)) => Err(error),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connection to {server_addr:?} timed out after {wait_for:?}"),
                )),
            }
        })
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        _server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = io::Result<Self::Udp>>>> {
        // Keep namespace switching out of the returned future for the same
        // reason as TCP above.
        let socket = create_dns_udp_socket(&self.context, local_addr);
        Box::pin(async move { socket })
    }
}

type ContextualResolver = Resolver<GenericConnector<RuntimeDnsIoProvider>>;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RuntimeDnsResolver;

impl RuntimeDnsResolver {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // A netns token can be deleted and recreated. Keep contextual resolvers
    // request-scoped so pooled DNS sockets cannot outlive that namespace.
    fn contextual_resolver(context: RuntimeDnsIoContext) -> ContextualResolver {
        let (config, options) = resolver_config();
        let provider = GenericConnector::new(RuntimeDnsIoProvider::new(context));
        Resolver::builder_with_config(config, provider)
            .with_options(options)
            .build()
    }

    async fn resolve_contextual_ips(
        &self,
        context: RuntimeDnsIoContext,
        host: String,
    ) -> anyhow::Result<Vec<IpAddr>> {
        if context.socket_mark.is_none() {
            // libc DNS cannot attach SO_MARK. It remains usable for a
            // namespace-only context when confined to one blocking thread.
            let lookup_host = host.clone();
            let netns = context.netns();
            match tokio::task::spawn_blocking(move || {
                netns.run(|| {
                    (lookup_host.as_str(), 0)
                        .to_socket_addrs()
                        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                })
            })
            .await
            .context("contextual system DNS task failed")?
            {
                Ok(addresses) => return Ok(addresses),
                Err(error) => tracing::error!(?error, "contextual system dns lookup failed"),
            }
        }

        let resolver = Self::contextual_resolver(context);
        let response = resolver
            .lookup_ip(&host)
            .await
            .with_context(|| format!("contextual hickory lookup_ip failed, host: {host}"))?;
        Ok(response.iter().collect())
    }
}

#[async_trait]
impl DnsResolver for RuntimeDnsResolver {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        let context = RuntimeDnsIoContext::from_socket_context(&query.context);
        if context.is_process_default() {
            return Ok(resolve_ips(&query.host).await?);
        }
        self.resolve_contextual_ips(context, query.host).await
    }
}

#[async_trait]
impl DnsRecordResolver for RuntimeDnsResolver {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        let context = RuntimeDnsIoContext::from_socket_context(&query.context);
        if context.is_process_default() {
            return Ok(resolve_txt_record(&query.host).await?);
        }

        let resolver = Self::contextual_resolver(context);
        let response = resolver
            .txt_lookup(&query.host)
            .await
            .with_context(|| format!("txt_lookup failed, domain_name: {}", query.host))?;
        let record = response
            .iter()
            .next()
            .with_context(|| format!("no txt record found, domain_name: {}", query.host))?;
        let data = record
            .txt_data()
            .first()
            .with_context(|| format!("empty txt record, domain_name: {}", query.host))?;
        Ok(String::from_utf8_lossy(data).into_owned())
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        let context = RuntimeDnsIoContext::from_socket_context(&query.context);
        let response = if context.is_process_default() {
            RESOLVER.srv_lookup(&query.host).await?
        } else {
            Self::contextual_resolver(context)
                .srv_lookup(&query.host)
                .await?
        };
        Ok(response
            .iter()
            .map(|record| DnsSrvRecord {
                priority: record.priority(),
                weight: record.weight(),
                port: record.port(),
                target: record.target().to_utf8(),
            })
            .collect())
    }
}

async fn resolve_txt_record(domain_name: &str) -> Result<String, Error> {
    let r = RESOLVER.clone();
    let response = r
        .txt_lookup(domain_name)
        .await
        .with_context(|| format!("txt_lookup failed, domain_name: {}", domain_name))?;

    let txt_record = response
        .iter()
        .next()
        .with_context(|| format!("no txt record found, domain_name: {}", domain_name))?;

    let txt_data = String::from_utf8_lossy(&txt_record.txt_data()[0]);
    tracing::info!(?txt_data, ?domain_name, "get txt record");

    Ok(txt_data.to_string())
}

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    socket_addrs_with_system_resolver(url, default_port_number, true).await
}

async fn socket_addrs_with_system_resolver(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
    allow_system_resolver: bool,
) -> Result<Vec<SocketAddr>, Error> {
    let host = url.host().ok_or(Error::InvalidUrl(url.to_string()))?;
    let port = url
        .port()
        .or_else(default_port_number)
        .ok_or(Error::InvalidUrl(url.to_string()))?;

    // if host is an ip address, return it directly
    match host {
        url::Host::Ipv4(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V4(ip), port)]),
        url::Host::Ipv6(ip) => return Ok(vec![SocketAddr::new(std::net::IpAddr::V6(ip), port)]),
        _ => {}
    }
    let host = host.to_string();

    if allow_system_resolver {
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

async fn resolve_ips(host: &str) -> Result<Vec<IpAddr>, Error> {
    match lookup_host((host, 0)).await {
        Ok(a) => {
            let a = a.map(|addr| addr.ip()).collect();
            tracing::debug!(?a, "system dns lookup done");
            return Ok(a);
        }
        Err(e) => {
            tracing::error!(?e, "system dns lookup failed");
        }
    }

    let ret = RESOLVER
        .lookup_ip(host)
        .await
        .with_context(|| format!("hickory dns lookup_ip failed, host: {}", host))?;
    Ok(ret.iter().collect::<Vec<_>>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_dns_context_preserves_process_routing_inputs() {
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(easytier_core::socket::NetNamespace::new("instance-a")));

        assert_eq!(
            RuntimeDnsIoContext::from_socket_context(&context),
            RuntimeDnsIoContext {
                netns: Some("instance-a".to_owned()),
                socket_mark: Some(0),
            }
        );
    }

    #[tokio::test]
    async fn test_socket_addrs() {
        let url = url::Url::parse("tcp://github-ci-test.easytier.cn:80").unwrap();
        let addrs = socket_addrs(&url, || Some(80)).await.unwrap();
        assert_eq!(2, addrs.len(), "addrs: {:?}", addrs);
        println!("addrs: {:?}", addrs);

        let addrs = socket_addrs_with_system_resolver(&url, || Some(80), false)
            .await
            .unwrap();
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

use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
#[cfg(feature = "dns-resolver")]
use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use easytier_core::host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};
use easytier_core::socket::SocketContext;
#[cfg(feature = "dns-resolver")]
use hickory_net::runtime::{RuntimeProvider, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd};
#[cfg(feature = "dns-resolver")]
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts,
};
#[cfg(feature = "dns-resolver")]
use hickory_resolver::system_conf::read_system_conf;
#[cfg(feature = "dns-resolver")]
use hickory_resolver::{Resolver, TokioResolver};
#[cfg(feature = "dns-resolver")]
use once_cell::sync::Lazy;
use tokio::net::lookup_host;
#[cfg(feature = "dns-resolver")]
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
#[cfg(feature = "dns-resolver")]
use tokio::sync::Semaphore;

use super::error::Error;
use super::netns::NetNS;
#[cfg(feature = "dns-resolver")]
use crate::tunnel::common::apply_socket_mark;

#[cfg(feature = "dns-resolver")]
pub fn get_default_resolver_config() -> ResolverConfig {
    let mut default_resolve_config = ResolverConfig::default();
    default_resolve_config.add_name_server(NameServerConfig::new(
        "223.5.5.5".parse().unwrap(),
        true,
        vec![ConnectionConfig::udp()],
    ));
    default_resolve_config.add_name_server(NameServerConfig::new(
        "180.184.1.1".parse().unwrap(),
        true,
        vec![ConnectionConfig::udp()],
    ));
    default_resolve_config
}

#[cfg(feature = "dns-resolver")]
pub(crate) fn resolver_config() -> (ResolverConfig, ResolverOpts) {
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

#[cfg(feature = "dns-resolver")]
pub(crate) static RESOLVER: Lazy<Arc<Resolver<TokioRuntimeProvider>>> = Lazy::new(|| {
    let (config, options) = resolver_config();
    let builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(options);
    Arc::new(
        builder
            .build()
            .expect("failed to initialize global DNS resolver"),
    )
});

#[cfg(feature = "dns-resolver")]
const SYSTEM_DNS_LOOKUP_TIMEOUT: Duration = Duration::from_millis(800);

#[cfg(feature = "dns-resolver")]
#[derive(Debug)]
struct SystemDnsResolver {
    lookup_slot: Arc<Semaphore>,
    timeout: Duration,
}

#[cfg(feature = "dns-resolver")]
impl Default for SystemDnsResolver {
    fn default() -> Self {
        Self::new(SYSTEM_DNS_LOOKUP_TIMEOUT)
    }
}

#[cfg(feature = "dns-resolver")]
impl SystemDnsResolver {
    fn new(timeout: Duration) -> Self {
        Self {
            lookup_slot: Arc::new(Semaphore::new(1)),
            timeout,
        }
    }

    async fn resolve<SystemFuture, FallbackFuture>(
        &self,
        system_lookup: SystemFuture,
        fallback_lookup: FallbackFuture,
    ) -> anyhow::Result<Vec<IpAddr>>
    where
        SystemFuture: Future<Output = anyhow::Result<Vec<IpAddr>>> + Send + 'static,
        FallbackFuture: Future<Output = anyhow::Result<Vec<IpAddr>>> + Send,
    {
        // Tokio runs getaddrinfo on its blocking pool and cannot cancel it.
        // Keep the permit in a detached task after a timeout so reconnects do
        // not accumulate blocked system lookups. Once it finishes, later
        // requests can use the system resolver again.
        let lookup_slot = self.lookup_slot.clone();
        let system_attempt = async move {
            let permit = lookup_slot
                .acquire_owned()
                .await
                .context("system DNS lookup slot closed")?;
            tokio::spawn(async move {
                let _permit = permit;
                system_lookup.await
            })
            .await
            .context("system DNS lookup task failed")?
        };

        match tokio::time::timeout(self.timeout, system_attempt).await {
            Ok(Ok(addresses)) => {
                tracing::debug!(?addresses, "system dns lookup done");
                return Ok(addresses);
            }
            Ok(Err(error)) => {
                tracing::warn!(?error, "system dns lookup failed, fallback to hickory");
            }
            Err(_) => {
                tracing::warn!(
                    timeout = ?self.timeout,
                    "system dns lookup timed out, fallback to hickory"
                );
            }
        }

        fallback_lookup.await
    }
}

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

    #[cfg(feature = "dns-resolver")]
    fn is_process_default(&self) -> bool {
        self.netns.is_none() && self.socket_mark.is_none()
    }
}

#[cfg(feature = "dns-resolver")]
#[derive(Clone)]
struct RuntimeDnsIoProvider {
    inner: TokioRuntimeProvider,
    context: RuntimeDnsIoContext,
}

#[cfg(feature = "dns-resolver")]
impl RuntimeDnsIoProvider {
    fn new(context: RuntimeDnsIoContext) -> Self {
        Self {
            inner: TokioRuntimeProvider::new(),
            context,
        }
    }
}

#[cfg(feature = "dns-resolver")]
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

#[cfg(feature = "dns-resolver")]
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

#[cfg(feature = "dns-resolver")]
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

#[cfg(feature = "dns-resolver")]
type ContextualResolver = Resolver<RuntimeDnsIoProvider>;

#[derive(Debug, Default)]
pub(crate) struct RuntimeDnsResolver {
    #[cfg(feature = "dns-resolver")]
    system_dns: SystemDnsResolver,
}

impl RuntimeDnsResolver {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    // A netns token can be deleted and recreated. Keep contextual resolvers
    // request-scoped so pooled DNS sockets cannot outlive that namespace.
    #[cfg(feature = "dns-resolver")]
    fn contextual_resolver(context: RuntimeDnsIoContext) -> ContextualResolver {
        let (config, options) = resolver_config();
        let provider = RuntimeDnsIoProvider::new(context);
        Resolver::builder_with_config(config, provider)
            .with_options(options)
            .build()
            .expect("failed to initialize contextual DNS resolver")
    }

    #[cfg(feature = "dns-resolver")]
    async fn resolve_contextual_with_hickory(
        context: RuntimeDnsIoContext,
        host: String,
    ) -> anyhow::Result<Vec<IpAddr>> {
        let resolver = Self::contextual_resolver(context);
        let response = resolver
            .lookup_ip(&host)
            .await
            .with_context(|| format!("contextual hickory lookup_ip failed, host: {host}"))?;
        Ok(response.iter().collect())
    }

    #[cfg(feature = "dns-resolver")]
    async fn resolve_process_ips(&self, host: &str) -> anyhow::Result<Vec<IpAddr>> {
        let system_host = host.to_owned();
        self.system_dns
            .resolve(
                async move {
                    let addresses = lookup_host((system_host.as_str(), 0))
                        .await?
                        .map(|address| address.ip())
                        .collect();
                    Ok(addresses)
                },
                async {
                    let response = RESOLVER
                        .lookup_ip(host)
                        .await
                        .with_context(|| format!("hickory dns lookup_ip failed, host: {host}"))?;
                    Ok(response.iter().collect())
                },
            )
            .await
    }

    #[cfg(feature = "dns-resolver")]
    async fn resolve_contextual_ips(
        &self,
        context: RuntimeDnsIoContext,
        host: String,
    ) -> anyhow::Result<Vec<IpAddr>> {
        if context.socket_mark.is_some() {
            return Self::resolve_contextual_with_hickory(context, host).await;
        }

        // libc DNS cannot attach SO_MARK. It remains usable for a
        // namespace-only context when confined to one blocking thread.
        let system_context = context.clone();
        let system_host = host.clone();
        self.system_dns
            .resolve(
                async move {
                    let netns = system_context.netns();
                    let addresses = tokio::task::spawn_blocking(move || {
                        netns.run(|| {
                            (system_host.as_str(), 0)
                                .to_socket_addrs()
                                .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                        })
                    })
                    .await
                    .context("contextual system DNS task failed")??;
                    Ok(addresses)
                },
                Self::resolve_contextual_with_hickory(context, host),
            )
            .await
    }
}

#[async_trait]
impl DnsResolver for RuntimeDnsResolver {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        let context = RuntimeDnsIoContext::from_socket_context(&query.context);
        #[cfg(feature = "dns-resolver")]
        {
            if context.is_process_default() {
                return self.resolve_process_ips(&query.host).await;
            }
            return self.resolve_contextual_ips(context, query.host).await;
        }
        #[cfg(not(feature = "dns-resolver"))]
        {
            if context.socket_mark.is_some() {
                anyhow::bail!("socket-marked DNS requires DNS resolver support");
            }
            if context.netns.is_none() {
                return Ok(resolve_ips(&query.host).await?);
            }
            let host = query.host;
            let netns = context.netns();
            return tokio::task::spawn_blocking(move || {
                netns.run(|| {
                    (host.as_str(), 0)
                        .to_socket_addrs()
                        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                })
            })
            .await
            .context("contextual system DNS task failed")?
            .map_err(Into::into);
        }
    }
}

#[cfg(feature = "dns-resolver")]
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
        txt_records(&response)
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
            .answers()
            .iter()
            .filter_map(|record| match &record.data {
                hickory_proto::rr::RData::SRV(record) => Some(DnsSrvRecord {
                    priority: record.priority,
                    weight: record.weight,
                    port: record.port,
                    target: record.target.to_utf8(),
                }),
                _ => None,
            })
            .collect())
    }
}

#[cfg(not(feature = "dns-resolver"))]
#[async_trait]
impl DnsRecordResolver for RuntimeDnsResolver {
    async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
        anyhow::bail!("this build does not include TXT DNS resolution")
    }

    async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        anyhow::bail!("this build does not include SRV DNS resolution")
    }
}

#[cfg(feature = "dns-resolver")]
fn txt_records(response: &hickory_resolver::lookup::Lookup) -> anyhow::Result<String> {
    // A TXT RR may contain several wire strings. Concatenate within each RR,
    // then separate distinct records for endpoint-discovery consumers.
    let records: Vec<_> = response
        .answers()
        .iter()
        .filter_map(|record| match &record.data {
            hickory_proto::rr::RData::TXT(txt) => Some(
                txt.txt_data
                    .iter()
                    .map(|part| String::from_utf8_lossy(part))
                    .collect::<String>(),
            ),
            _ => None,
        })
        .collect();
    anyhow::ensure!(!records.is_empty(), "no TXT record found");
    Ok(records.join(" "))
}

#[cfg(feature = "dns-resolver")]
async fn resolve_txt_record(domain_name: &str) -> Result<String, Error> {
    let r = RESOLVER.clone();
    let response = r
        .txt_lookup(domain_name)
        .await
        .with_context(|| format!("txt_lookup failed, domain_name: {}", domain_name))?;

    Ok(txt_records(&response)?)
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
                #[cfg(not(feature = "dns-resolver"))]
                return Err(e.into());
            }
        }
    }

    // use hickory_resolver
    #[cfg(feature = "dns-resolver")]
    {
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
    #[cfg(not(feature = "dns-resolver"))]
    unreachable!("the system resolver error returns above")
}

#[cfg(not(feature = "dns-resolver"))]
async fn resolve_ips(host: &str) -> Result<Vec<IpAddr>, Error> {
    Ok(lookup_host((host, 0))
        .await?
        .map(|addr| addr.ip())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "dns-resolver")]
    #[test]
    fn txt_resolution_preserves_all_wire_strings_and_records() {
        use hickory_proto::{
            op::Query,
            rr::{Name, RData, Record, RecordType, rdata::TXT},
        };
        let name: Name = "discovery.example.".parse().unwrap();
        let lookup = hickory_resolver::lookup::Lookup::new_with_max_ttl(
            Query::query(name.clone(), RecordType::TXT),
            [
                Record::from_rdata(
                    name.clone(),
                    60,
                    RData::TXT(TXT::new(vec!["tcp://one.".into(), "example:11010".into()])),
                ),
                Record::from_rdata(
                    name,
                    60,
                    RData::TXT(TXT::new(vec!["udp://two.example:11010".into()])),
                ),
            ],
        );
        assert_eq!(
            txt_records(&lookup).unwrap(),
            "tcp://one.example:11010 udp://two.example:11010",
        );
    }

    #[cfg(feature = "dns-resolver")]
    #[tokio::test]
    async fn timed_out_system_lookup_is_not_retried() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let resolver = SystemDnsResolver::new(Duration::from_millis(10));
        let system_calls = Arc::new(AtomicUsize::new(0));
        let fallback_calls = AtomicUsize::new(0);
        let expected = vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];

        let first_system_calls = system_calls.clone();
        let first = resolver
            .resolve(
                async move {
                    first_system_calls.fetch_add(1, Ordering::Relaxed);
                    std::future::pending::<anyhow::Result<Vec<IpAddr>>>().await
                },
                async {
                    fallback_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(expected.clone())
                },
            )
            .await;
        let second_system_calls = system_calls.clone();
        let second = resolver
            .resolve(
                async move {
                    second_system_calls.fetch_add(1, Ordering::Relaxed);
                    std::future::pending::<anyhow::Result<Vec<IpAddr>>>().await
                },
                async {
                    fallback_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(expected.clone())
                },
            )
            .await;

        assert_eq!(first.unwrap(), expected);
        assert_eq!(second.unwrap(), expected);
        assert_eq!(system_calls.load(Ordering::Relaxed), 1);
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 2);
    }

    #[cfg(feature = "dns-resolver")]
    #[tokio::test]
    async fn successful_system_lookup_skips_hickory() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let resolver = SystemDnsResolver::new(Duration::from_millis(10));
        let fallback_calls = AtomicUsize::new(0);
        let expected = vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)];
        let system_result = expected.clone();

        let addresses = resolver
            .resolve(async move { Ok(system_result) }, async {
                fallback_calls.fetch_add(1, Ordering::Relaxed);
                Ok(Vec::new())
            })
            .await
            .unwrap();

        assert_eq!(addresses, expected);
        assert_eq!(fallback_calls.load(Ordering::Relaxed), 0);
    }

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

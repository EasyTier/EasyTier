use std::net::{IpAddr, SocketAddr, ToSocketAddrs as _};
#[cfg(feature = "dns-resolver")]
use std::{future::Future, io, pin::Pin, sync::Arc, time::Duration};

use anyhow::Context;
use async_trait::async_trait;
use easytier_core::host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};
use easytier_core::socket::SocketContext;
#[cfg(feature = "dns-resolver")]
use hickory_proto::runtime::{RuntimeProvider, TokioRuntimeProvider, iocompat::AsyncIoTokioAsStd};
#[cfg(feature = "dns-resolver")]
use hickory_proto::xfer::Protocol;
#[cfg(feature = "dns-resolver")]
use hickory_resolver::config::{LookupIpStrategy, NameServerConfig, ResolverConfig, ResolverOpts};
#[cfg(feature = "dns-resolver")]
use hickory_resolver::name_server::{GenericConnector, TokioConnectionProvider};
#[cfg(feature = "dns-resolver")]
use hickory_resolver::system_conf::read_system_conf;
#[cfg(feature = "dns-resolver")]
use hickory_resolver::{Resolver, TokioResolver};
use tokio::net::lookup_host;
#[cfg(feature = "dns-resolver")]
use tokio::net::{TcpStream, UdpSocket};
#[cfg(feature = "dns-resolver")]
use tokio::sync::Semaphore;

use super::error::Error;
use super::netns::PlatformNamespace;
#[cfg(feature = "dns-resolver")]
use crate::socket::{tcp::create_tcp_socket_in_namespace, udp::create_udp_socket_in_namespace};
#[cfg(feature = "dns-resolver")]
use easytier_core::socket::{NetNamespace, tcp::TcpBindOptions, udp::UdpBindOptions};

#[cfg(feature = "dns-resolver")]
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

#[cfg(feature = "dns-resolver")]
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

#[cfg(feature = "dns-resolver")]
fn process_resolver() -> Resolver<GenericConnector<TokioRuntimeProvider>> {
    // A pooled socket must not survive the caller's runtime. Only configuration
    // may be process-shared; standalone requests own their resolver resources.
    let (config, options) = resolver_config();
    TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(options)
        .build()
}

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
            crate::host_runtime::native_host_runtime()
                .shared_executor()?
                .spawn(async move {
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

#[derive(Clone, Debug)]
struct RuntimeDnsIoContext {
    namespace: PlatformNamespace,
    socket_mark: Option<u32>,
}

impl RuntimeDnsIoContext {
    fn from_socket_context(
        context: &SocketContext,
        namespace: &PlatformNamespace,
    ) -> std::io::Result<Self> {
        namespace.validate_context(context)?;
        Ok(Self {
            namespace: namespace.clone(),
            socket_mark: context.socket_mark,
        })
    }

    #[cfg(feature = "dns-resolver")]
    fn socket_context(&self) -> SocketContext {
        SocketContext::default()
            .with_netns(Some(NetNamespace::new(self.namespace.id().to_string())))
            .with_socket_mark(self.socket_mark)
    }
}

#[cfg(feature = "dns-resolver")]
#[derive(Clone)]
pub(crate) struct RuntimeDnsIoProvider {
    inner: TokioRuntimeProvider,
    context: RuntimeDnsIoContext,
}

#[cfg(feature = "dns-resolver")]
impl RuntimeDnsIoProvider {
    pub(crate) fn in_namespace(namespace: PlatformNamespace, socket_mark: Option<u32>) -> Self {
        Self::new(RuntimeDnsIoContext {
            namespace,
            socket_mark,
        })
    }

    fn new(context: RuntimeDnsIoContext) -> Self {
        Self {
            inner: TokioRuntimeProvider::new(),
            context,
        }
    }
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
        let options = TcpBindOptions::default()
            .with_context(self.context.socket_context())
            .with_local_addr(bind_addr)
            .with_bind_device(Some(String::new()))
            .with_reuse_addr(false);
        let namespace = self.context.namespace.clone();
        Box::pin(async move {
            let wait_for = wait_for.unwrap_or(Duration::from_secs(5));
            let connect = async {
                let socket = create_tcp_socket_in_namespace(server_addr, &options, &namespace)
                    .await
                    .map_err(io::Error::other)?;
                socket.set_nodelay(true)?;
                socket.connect(server_addr).await
            };
            match tokio::time::timeout(wait_for, connect).await {
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
        let options = UdpBindOptions::default()
            .with_context(self.context.socket_context())
            .with_local_addr(Some(local_addr));
        let namespace = self.context.namespace.clone();
        Box::pin(async move {
            create_udp_socket_in_namespace(&options, &namespace)
                .await
                .map_err(io::Error::other)
        })
    }
}

#[cfg(feature = "dns-resolver")]
type ContextualResolver = Resolver<GenericConnector<RuntimeDnsIoProvider>>;

#[derive(Debug)]
pub(crate) struct RuntimeDnsResolver {
    namespace: PlatformNamespace,
    #[cfg(feature = "dns-resolver")]
    system_dns: SystemDnsResolver,
}

impl RuntimeDnsResolver {
    fn requires_socket_dns(context: &RuntimeDnsIoContext) -> std::io::Result<bool> {
        Ok(context.socket_mark.is_some()
            || crate::socket_protector::native_socket_protection_available()
            || !crate::host_runtime::native_host_runtime()
                .is_process_default(&context.namespace)?)
    }
    pub(crate) fn in_namespace(namespace: PlatformNamespace) -> Self {
        Self {
            namespace,
            #[cfg(feature = "dns-resolver")]
            system_dns: SystemDnsResolver::default(),
        }
    }

    // Keep the resolver request-scoped: connection pools must not retain
    // sockets registered on a caller's short-lived instance Reactor.
    #[cfg(feature = "dns-resolver")]
    fn contextual_resolver(context: RuntimeDnsIoContext) -> ContextualResolver {
        let (config, options) = resolver_config();
        let provider = GenericConnector::new(RuntimeDnsIoProvider::new(context));
        Resolver::builder_with_config(config, provider)
            .with_options(options)
            .build()
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
    async fn resolve_contextual_ips(
        &self,
        context: RuntimeDnsIoContext,
        host: String,
    ) -> anyhow::Result<Vec<IpAddr>> {
        if Self::requires_socket_dns(&context)? {
            return Self::resolve_contextual_with_hickory(context, host).await;
        }

        // Restrict libc/NSS to the process default domain. A scoped setns
        // cannot confine plugins that delegate to a host-wide Unix daemon.
        let system_context = context.clone();
        let system_host = host.clone();
        self.system_dns
            .resolve(
                async move {
                    let netns = system_context.namespace;
                    let addresses = tokio::task::spawn_blocking(move || {
                        netns.run(|| {
                            (system_host.as_str(), 0)
                                .to_socket_addrs()
                                .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                        })
                    })
                    .await
                    .context("contextual system DNS task failed")???;
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
        let context = RuntimeDnsIoContext::from_socket_context(&query.context, &self.namespace)?;
        if let Ok(address) = query.host.parse::<IpAddr>() {
            return Ok(vec![address]);
        }
        #[cfg(feature = "dns-resolver")]
        {
            return self.resolve_contextual_ips(context, query.host).await;
        }
        #[cfg(not(feature = "dns-resolver"))]
        {
            if Self::requires_socket_dns(&context)? {
                return Err(std::io::Error::new(std::io::ErrorKind::Unsupported,
                    "DNS in a non-default namespace, with a socket mark or VPN protection requires DNS resolver support").into());
            }
            let host = query.host;
            let netns = context.namespace;
            return tokio::task::spawn_blocking(move || {
                netns.run(|| {
                    (host.as_str(), 0)
                        .to_socket_addrs()
                        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
                })
            })
            .await
            .context("contextual system DNS task failed")??
            .map_err(Into::into);
        }
    }
}

#[cfg(feature = "dns-resolver")]
#[async_trait]
impl DnsRecordResolver for RuntimeDnsResolver {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        let context = RuntimeDnsIoContext::from_socket_context(&query.context, &self.namespace)?;
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
        let context = RuntimeDnsIoContext::from_socket_context(&query.context, &self.namespace)?;
        let response = Self::contextual_resolver(context)
            .srv_lookup(&query.host)
            .await?;
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

pub async fn socket_addrs(
    url: &url::Url,
    default_port_number: impl Fn() -> Option<u16>,
) -> Result<Vec<SocketAddr>, Error> {
    socket_addrs_with_system_resolver(url, default_port_number, true).await
}

#[cfg(any(feature = "faketcp", feature = "wireguard"))]
pub(crate) async fn socket_addrs_in_namespace(
    url: &url::Url,
    default_port: u16,
    namespace: PlatformNamespace,
    context: SocketContext,
) -> Result<Vec<SocketAddr>, Error> {
    namespace.validate_context(&context)?;
    let port = url.port().unwrap_or(default_port);
    let addresses = match url
        .host()
        .ok_or_else(|| Error::InvalidUrl(url.to_string()))?
    {
        url::Host::Ipv4(ip) => vec![IpAddr::V4(ip)],
        url::Host::Ipv6(ip) => vec![IpAddr::V6(ip)],
        url::Host::Domain(host) => {
            RuntimeDnsResolver::in_namespace(namespace)
                .resolve(DnsQuery::new(host, context))
                .await?
        }
    };
    Ok(addresses
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
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
        let ret = process_resolver().lookup_ip(&host).await.with_context(|| {
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn runtime_dns_context_preserves_bound_domain_and_zero_mark() {
        let namespace = PlatformNamespace::current().unwrap();
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(easytier_core::socket::NetNamespace::new(
                namespace.id().to_string(),
            )));
        let actual = RuntimeDnsIoContext::from_socket_context(&context, &namespace).unwrap();
        assert_eq!(actual.namespace.id(), namespace.id());
        assert_eq!(actual.socket_mark, Some(0));
        let named = SocketContext::default()
            .with_netns(Some(easytier_core::socket::NetNamespace::new("instance-a")));
        assert!(RuntimeDnsIoContext::from_socket_context(&named, &namespace).is_err());
    }

    #[tokio::test]
    async fn dns_literal_needs_no_resolver_socket_or_mark_capability() {
        let namespace = PlatformNamespace::current().unwrap();
        let resolver = RuntimeDnsResolver::in_namespace(namespace);
        for address in ["127.0.0.1", "::1"] {
            let context = SocketContext::default().with_socket_mark(Some(0));
            assert_eq!(
                resolver
                    .resolve(DnsQuery::new(address, context))
                    .await
                    .unwrap(),
                vec![address.parse::<IpAddr>().unwrap()]
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "run inside an isolated user+network namespace"]
    fn non_default_domains_cannot_use_process_wide_nss() {
        let host = crate::host_runtime::native_host_runtime();
        let original = host.capture_default_namespace().unwrap();
        let other = crate::common::netns::isolated_namespace_for_test().unwrap();
        assert!(host.is_process_default(original.platform()).unwrap());
        assert!(!host.is_process_default(other.platform()).unwrap());
        let context =
            RuntimeDnsIoContext::from_socket_context(&SocketContext::default(), other.platform())
                .unwrap();
        assert!(RuntimeDnsResolver::requires_socket_dns(&context).unwrap());
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

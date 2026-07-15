use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use easytier_core::{
    connectivity::{composite::ConnectorRuntime, transport::ConnectedByteStream},
    socket::{
        SocketContext,
        dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        tcp::{
            TcpConnectOptions, TcpListenOptions, TcpSocketPurpose, VirtualTcpListenerFactory,
            VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory,
        },
    },
};

use crate::{
    common::{
        dns::RuntimeDnsResolver, netns::NetNS, network::CACHED_IP_LIST_TIMEOUT_SEC,
        network::IPCollector,
    },
    proto::peer_rpc::GetIpListResponse,
    socket::{
        tcp::{RuntimeTcpListener, RuntimeTcpSocket},
        udp::{RuntimeUdpSocket, RuntimeUdpSocketFactory},
    },
};

/// Process-wide native implementation of the host capabilities consumed by core.
///
/// Instance-specific policy is carried by each request's socket context. Keeping
/// this object stateless prevents a socket operation from capturing one
/// instance's namespace or mark.
#[derive(Debug)]
pub struct NativeHostRuntime {
    udp_sockets: RuntimeUdpSocketFactory,
    dns: RuntimeDnsResolver,
    foreign_interface_cache: tokio::sync::Mutex<HashMap<Option<String>, CachedInterfaceAddrs>>,
}

#[derive(Debug, Clone)]
struct CachedInterfaceAddrs {
    collected_at: Instant,
    response: GetIpListResponse,
}

impl CachedInterfaceAddrs {
    fn is_fresh(&self) -> bool {
        self.collected_at.elapsed() < Duration::from_secs(CACHED_IP_LIST_TIMEOUT_SEC)
    }
}

fn foreign_interface_cache_key(context: &SocketContext) -> Option<String> {
    context.netns.as_ref().map(|netns| netns.token().to_owned())
}

static NATIVE_HOST_RUNTIME: OnceLock<Arc<NativeHostRuntime>> = OnceLock::new();

pub(crate) fn native_host_runtime() -> Arc<NativeHostRuntime> {
    NATIVE_HOST_RUNTIME
        .get_or_init(|| {
            Arc::new(NativeHostRuntime {
                udp_sockets: RuntimeUdpSocketFactory::new(),
                dns: RuntimeDnsResolver::new(),
                foreign_interface_cache: tokio::sync::Mutex::new(HashMap::new()),
            })
        })
        .clone()
}

#[async_trait]
impl VirtualTcpSocketFactory for NativeHostRuntime {
    type Socket = RuntimeTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        #[cfg(feature = "faketcp")]
        if options.purpose == TcpSocketPurpose::FakeTcp {
            let remote_addr = options.remote_addr;
            let socket_mark = options.bind.context.socket_mark;
            let net_ns = NetNS::from_socket_context(&options.bind.context);
            let socket =
                crate::tunnel::fake_tcp::connect_socket(remote_addr, socket_mark, net_ns).await?;
            return Ok(RuntimeTcpSocket::from_fake_tcp(socket));
        }

        #[cfg(not(feature = "faketcp"))]
        if options.purpose == TcpSocketPurpose::FakeTcp {
            anyhow::bail!("FakeTCP socket support is disabled")
        }

        crate::socket::tcp::connect_tcp(options)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[async_trait]
impl ConnectorRuntime for NativeHostRuntime {
    async fn connect_byte_stream(
        &self,
        url: &url::Url,
    ) -> anyhow::Result<ConnectedByteStream<RuntimeTcpSocket>> {
        #[cfg(unix)]
        if url.scheme() == "unix" {
            let stream = tokio::net::UnixStream::connect(url.path()).await?;
            let local_url = stream
                .local_addr()
                .ok()
                .and_then(crate::tunnel::unix::url_from_unix_socket_addr);
            return Ok(ConnectedByteStream::new(
                RuntimeTcpSocket::from_unix(stream),
                local_url,
                url.clone(),
                Some(url.clone()),
            ));
        }

        anyhow::bail!("unsupported runtime byte stream: {url}")
    }

    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        let socket = NetNS::from_socket_context(&context).run(|| -> anyhow::Result<_> {
            let (domain, bind_addr) = match remote_addr {
                SocketAddr::V4(_) => (
                    socket2::Domain::IPV4,
                    SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)),
                ),
                SocketAddr::V6(_) => (
                    socket2::Domain::IPV6,
                    SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0)),
                ),
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            crate::tunnel::common::apply_socket_mark(&socket, context.socket_mark)?;
            socket.set_nonblocking(true)?;
            socket.bind(&socket2::SockAddr::from(bind_addr))?;
            Ok(std::net::UdpSocket::from(socket))
        })?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
        socket.connect(remote_addr).await?;
        Ok(socket.local_addr()?)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: std::net::Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        IPCollector::collect_interfaces(NetNS::from_socket_context(&context), false)
            .await
            .into_iter()
            .find(|interface| {
                interface
                    .ips
                    .iter()
                    .any(|local| matches!(local.ip(), IpAddr::V6(local_ip) if local_ip == ip))
            })
            .map(|interface| PreferredIpv6Source {
                ip,
                ifindex: interface.index,
            })
    }

    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        let cache_key = foreign_interface_cache_key(context);
        if let Some(response) = self
            .foreign_interface_cache
            .lock()
            .await
            .get(&cache_key)
            .filter(|cached| cached.is_fresh())
            .map(|cached| cached.response.clone())
        {
            return response;
        }

        let response =
            IPCollector::collect_local_ip_addrs(NetNS::from_socket_context(context)).await;
        self.foreign_interface_cache.lock().await.insert(
            cache_key,
            CachedInterfaceAddrs {
                collected_at: Instant::now(),
                response: response.clone(),
            },
        );
        response
    }
}

impl NativeHostRuntime {
    pub(crate) fn bind_udp_with_explicit_options(
        &self,
        options: UdpBindOptions,
    ) -> anyhow::Result<Arc<RuntimeUdpSocket>> {
        // UDP hole punching historically used the request fields verbatim.
        // Keep that policy while centralizing the actual OS socket creation.
        let socket = self.udp_sockets.bind_udp_with_explicit_options(options)?;
        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;
        Ok(socket)
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for NativeHostRuntime {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        Ok(Arc::new(crate::socket::tcp::bind_tcp_listener(options)?))
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for NativeHostRuntime {
    type Socket = RuntimeUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let socket = self.udp_sockets.bind_udp(options).await?;
        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;
        Ok(socket)
    }
}

#[async_trait]
impl UdpSessionControlHandler<RuntimeUdpSocket> for NativeHostRuntime {
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        self.udp_sockets.send_v4_hole_punch(socket, dst_addr).await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<RuntimeUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        self.udp_sockets
            .send_v6_hole_punch(socket, dst_addr, preferred_src)
            .await
    }
}

#[async_trait]
impl DnsResolver for NativeHostRuntime {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        self.dns.resolve(query).await
    }
}

#[async_trait]
impl DnsRecordResolver for NativeHostRuntime {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        self.dns.resolve_txt(query).await
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        self.dns.resolve_srv(query).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::socket::NetNamespace;

    #[test]
    fn native_host_runtime_is_process_wide() {
        assert!(Arc::ptr_eq(&native_host_runtime(), &native_host_runtime()));
    }

    #[test]
    fn foreign_interface_cache_is_keyed_by_netns_and_ttl() {
        let context = SocketContext::default().with_netns(Some(NetNamespace::new("foreign-a")));
        assert_ne!(
            foreign_interface_cache_key(&context),
            foreign_interface_cache_key(
                &SocketContext::default().with_netns(Some(NetNamespace::new("foreign-b")))
            )
        );

        let cached = CachedInterfaceAddrs {
            collected_at: Instant::now(),
            response: GetIpListResponse::default(),
        };
        assert!(cached.is_fresh());

        let expired = CachedInterfaceAddrs {
            collected_at: Instant::now() - Duration::from_secs(CACHED_IP_LIST_TIMEOUT_SEC + 1),
            ..cached
        };
        assert!(!expired.is_fresh());
    }

    #[tokio::test]
    async fn native_route_probe_uses_remote_address_family() {
        let local_addr = native_host_runtime()
            .local_addr_for_remote(
                SocketAddr::from(([127, 0, 0, 1], 9)),
                SocketContext::default(),
            )
            .await
            .unwrap();

        assert!(local_addr.is_ipv4());
    }
}

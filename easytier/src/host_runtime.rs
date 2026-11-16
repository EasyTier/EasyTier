use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use cidr::{Ipv4Cidr, Ipv4Inet};
use easytier_core::{
    connectivity::{composite::ConnectorRuntime, transport::ConnectedByteStream},
    host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
    socket::{
        SocketContext,
        tcp::{
            TcpConnectOptions, TcpListenOptions, TcpSocketPurpose, VirtualTcpListenerFactory,
            VirtualTcpSocketFactory,
        },
        udp::{PreferredIpv6Source, UdpBindOptions, VirtualUdpSocketFactory},
    },
};

use crate::{
    common::{
        dns::RuntimeDnsResolver,
        netns::NetNS,
        network::{collect_interfaces, collect_local_ip_addrs, ip_mask_to_prefix},
    },
    proto::peer_rpc::GetIpListResponse,
    socket::{
        tcp::{RuntimeTcpListener, RuntimeTcpSocket},
        udp::{RuntimeUdpSocket, RuntimeUdpSocketFactory},
    },
};

/// Process-wide native implementation of the host capabilities consumed by core.
///
/// Instance-specific policy is carried by each request's socket context so a
/// process-wide service never captures one instance's namespace or mark.
#[derive(Debug)]
pub struct NativeHostRuntime {
    udp_sockets: RuntimeUdpSocketFactory,
    dns: RuntimeDnsResolver,
}

static NATIVE_HOST_RUNTIME: OnceLock<Arc<NativeHostRuntime>> = OnceLock::new();

pub(crate) fn native_host_runtime() -> Arc<NativeHostRuntime> {
    NATIVE_HOST_RUNTIME
        .get_or_init(|| {
            Arc::new(NativeHostRuntime {
                udp_sockets: RuntimeUdpSocketFactory::new(),
                dns: RuntimeDnsResolver::new(),
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
                crate::socket::fake_tcp::connect_socket(remote_addr, socket_mark, net_ns).await?;
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
                .and_then(crate::socket::tcp::url_from_unix_socket_addr);
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
        let bind_addr = match remote_addr {
            SocketAddr::V4(_) => {
                SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
            }
            SocketAddr::V6(_) => {
                SocketAddr::V6(SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
            }
        };
        let options = UdpBindOptions::default()
            .with_context(context)
            .with_local_addr(Some(bind_addr));
        let socket = crate::socket::udp::create_udp_socket(&options).await?;
        socket.connect(remote_addr).await?;
        Ok(socket.local_addr()?)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: std::net::Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        collect_interfaces(NetNS::from_socket_context(&context), false)
            .await
            .into_iter()
            .find(|interface| {
                interface
                    .addr
                    .iter()
                    .any(|local| matches!(local.ip(), IpAddr::V6(local_ip) if local_ip == ip))
            })
            .map(|interface| PreferredIpv6Source {
                ip,
                ifindex: interface.index,
            })
    }

    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        collect_local_ip_addrs(NetNS::from_socket_context(context)).await
    }

    async fn interface_ipv4_networks(&self, context: &SocketContext) -> Vec<Ipv4Cidr> {
        collect_interfaces(NetNS::from_socket_context(context), true)
            .await
            .into_iter()
            .flat_map(|interface| interface.addr)
            .filter_map(ipv4_interface_network)
            .collect()
    }
}

fn ipv4_interface_network(addr: network_interface::Addr) -> Option<Ipv4Cidr> {
    let network_interface::Addr::V4(addr) = addr else {
        return None;
    };
    if addr.ip.is_unspecified()
        || addr.ip.is_loopback()
        || addr.ip.is_multicast()
        || addr.ip.is_broadcast()
    {
        return None;
    }

    let prefix = ip_mask_to_prefix(addr.netmask?.into()).ok()?;
    // A default route does not establish a directly connected network.
    if prefix == 0 {
        return None;
    }
    Some(Ipv4Inet::new(addr.ip, prefix).ok()?.network())
}

impl NativeHostRuntime {
    pub(crate) fn is_local_ip(&self, ip: &IpAddr, context: &SocketContext) -> bool {
        NetNS::from_socket_context(context)
            .run(|| std::net::UdpSocket::bind(format!("{ip}:0")).is_ok())
    }
}

#[async_trait]
impl VirtualTcpListenerFactory for NativeHostRuntime {
    type Listener = RuntimeTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        Ok(Arc::new(
            crate::socket::tcp::bind_tcp_listener(options).await?,
        ))
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

    #[test]
    fn direct_ipv4_networks_use_valid_interface_masks() {
        let interface_addr = |ip: &str, netmask: Option<&str>| {
            network_interface::Addr::V4(network_interface::V4IfAddr {
                ip: ip.parse().unwrap(),
                broadcast: None,
                netmask: netmask.map(|mask| mask.parse().unwrap()),
            })
        };
        for (ip, mask, expected) in [
            (
                "192.168.23.7",
                Some("255.255.240.0"),
                Some("192.168.16.0/20"),
            ),
            (
                "198.51.100.7",
                Some("255.255.255.192"),
                Some("198.51.100.0/26"),
            ),
            ("192.168.10.7", None, None),
            ("192.168.10.7", Some("255.0.255.0"), None),
            ("192.168.10.7", Some("0.0.0.0"), None),
            ("127.0.0.1", Some("255.0.0.0"), None),
            ("0.0.0.0", Some("255.255.255.0"), None),
            ("224.0.0.1", Some("255.255.255.0"), None),
        ] {
            assert_eq!(
                ipv4_interface_network(interface_addr(ip, mask)),
                expected.map(|network| network.parse().unwrap()),
                "{ip} {mask:?}",
            );
        }
    }

    #[test]
    fn native_host_runtime_is_process_wide() {
        assert!(Arc::ptr_eq(&native_host_runtime(), &native_host_runtime()));
    }

    #[test]
    fn native_local_ip_probe_uses_process_runtime() {
        assert!(native_host_runtime().is_local_ip(
            &IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            &SocketContext::default(),
        ));
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

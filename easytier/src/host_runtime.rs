use std::{
    net::{IpAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, OnceLock},
};

use async_trait::async_trait;
use easytier_core::socket::{
    dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
    tcp::{
        TcpConnectOptions, TcpListenOptions, TcpSocketPurpose, VirtualTcpListenerFactory,
        VirtualTcpSocketFactory,
    },
    udp::{PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory},
};

use crate::{
    common::{dns::RuntimeDnsResolver, netns::NetNS},
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
            let socket = net_ns
                .run_async(|| async move {
                    crate::tunnel::fake_tcp::connect_socket(remote_addr, socket_mark).await
                })
                .await?;
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

    #[test]
    fn native_host_runtime_is_process_wide() {
        assert!(Arc::ptr_eq(&native_host_runtime(), &native_host_runtime()));
    }
}

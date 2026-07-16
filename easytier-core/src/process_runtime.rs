//! Host-domain portable resources shared by core instances.

use std::sync::Arc;

use crate::{
    connectivity::{
        manual::{
            ManualConnectorHost, ManualConnectorOptions, ManualTunnelConnector,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::ClientProtocolUpgrader,
    },
    listener::SocketListener,
    socket::{
        dns::{DnsRecordResolver, DnsResolver},
        ring::RingSocketId,
        tcp::VirtualTcpSocketFactory,
    },
    tunnel::{Tunnel, ring::RingTunnelRegistry},
};

/// Owns portable resources whose identity is shared across core instances in
/// one native process or one instantiated WASI module.
///
/// Native composition roots pass this handle around. The WASI lifecycle keeps
/// it module-local and never exposes it through the Go ABI. Neither host can
/// receive the internal managers it owns.
#[derive(Default)]
pub struct CoreProcessRuntime {
    ring_registry: Arc<RingTunnelRegistry>,
}

impl CoreProcessRuntime {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub(crate) fn ring_registry(&self) -> Arc<RingTunnelRegistry> {
        self.ring_registry.clone()
    }

    /// Binds an application-level Ring listener without exposing the registry
    /// that owns its process namespace.
    pub fn bind_ring_tunnel(
        &self,
        local_id: RingSocketId,
    ) -> anyhow::Result<Box<dyn SocketListener<Accepted = Box<dyn Tunnel>>>> {
        Ok(Box::new(self.ring_registry.bind(local_id)?))
    }

    /// Connects an application-level Ring tunnel in this runtime's namespace.
    pub fn connect_ring_tunnel(&self, remote_id: RingSocketId) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(self.ring_registry.connect(remote_id)?.into_tunnel())
    }

    pub fn manual_connector<H>(
        &self,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        dns_records: Arc<dyn DnsRecordResolver>,
        protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
        endpoint_discovery: ManualEndpointDiscoveryConfig,
        options: ManualConnectorOptions,
    ) -> ManualTunnelConnector<H>
    where
        H: ManualConnectorHost,
    {
        let endpoint_resolver = Arc::new(CoreManualEndpointResolver::new(
            host.clone(),
            dns.clone(),
            dns_records,
            endpoint_discovery,
        ));
        ManualTunnelConnector::new(host, dns, endpoint_resolver, protocol, options)
            .with_ring_registry(self.ring_registry())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use async_trait::async_trait;
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use crate::{
        connectivity::{
            manual::ManualInterfaceAddrs,
            protocol::{CoreClientProtocolConfig, CoreClientProtocolUpgrader},
        },
        packet::ZCPacket,
        socket::{
            IpVersion, SocketContext,
            dns::{DnsQuery, DnsRecordResolver, DnsSrvRecord},
            tcp::{TcpConnectOptions, VirtualTcpSocket},
            udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
        },
    };

    struct TestTcpSocket;

    impl AsyncRead for TestTcpSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TestTcpSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl VirtualTcpSocket for TestTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }
    }

    struct TestUdpSocket;

    #[async_trait]
    impl VirtualUdpSocket for TestUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            unreachable!("Ring connector must not use UDP")
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            unreachable!("Ring connector must not use UDP")
        }
    }

    struct TestHost;

    #[async_trait]
    impl VirtualTcpSocketFactory for TestHost {
        type Socket = TestTcpSocket;

        async fn connect_tcp(&self, _options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
            anyhow::bail!("Ring connector must not use TCP")
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for TestHost {
        type Socket = TestUdpSocket;

        async fn bind_udp(&self, _options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            anyhow::bail!("Ring connector must not use UDP")
        }
    }

    #[async_trait]
    impl ManualConnectorHost for TestHost {
        async fn local_addr_for_remote(
            &self,
            _remote_addr: SocketAddr,
            _context: SocketContext,
        ) -> anyhow::Result<SocketAddr> {
            anyhow::bail!("Ring connector must not probe routes")
        }

        async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
            anyhow::bail!("Ring connector must not collect interfaces")
        }
    }

    struct TestDns;

    #[async_trait]
    impl DnsResolver for TestDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<std::net::IpAddr>> {
            anyhow::bail!("Ring connector must not resolve DNS")
        }
    }

    #[async_trait]
    impl DnsRecordResolver for TestDns {
        async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
            anyhow::bail!("Ring connector must not resolve TXT records")
        }

        async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            anyhow::bail!("Ring connector must not resolve SRV records")
        }
    }

    fn manual_connector(runtime: &Arc<CoreProcessRuntime>) -> ManualTunnelConnector<TestHost> {
        runtime.manual_connector(
            Arc::new(TestHost),
            Arc::new(TestDns),
            Arc::new(TestDns),
            Arc::new(CoreClientProtocolUpgrader::<TestTcpSocket>::new(
                CoreClientProtocolConfig::default(),
            )),
            ManualEndpointDiscoveryConfig::default(),
            ManualConnectorOptions::default(),
        )
    }

    #[test]
    fn instances_share_ring_state_only_through_the_process_runtime() {
        let runtime = CoreProcessRuntime::new();

        assert!(Arc::ptr_eq(
            &runtime.ring_registry(),
            &runtime.ring_registry()
        ));
        assert!(!Arc::ptr_eq(
            &runtime.ring_registry(),
            &CoreProcessRuntime::new().ring_registry()
        ));
    }

    #[tokio::test]
    async fn one_shot_ring_connector_uses_its_process_runtime_namespace() {
        let runtime = CoreProcessRuntime::new();
        let isolated = CoreProcessRuntime::new();
        let listener_id = uuid::Uuid::new_v4();
        let mut listener = runtime.bind_ring_tunnel(listener_id).unwrap();
        let url: url::Url = format!("ring://{listener_id}").parse().unwrap();

        assert!(
            manual_connector(&isolated)
                .connect(url.clone(), IpVersion::Both)
                .await
                .is_err()
        );

        let client = manual_connector(&runtime)
            .connect(url, IpVersion::Both)
            .await
            .unwrap();
        let server = listener.accept().await.unwrap();
        let (_client_stream, mut client_sink) = client.split();
        let (mut server_stream, _server_sink) = server.split();
        client_sink
            .send(ZCPacket::new_with_payload(b"process-runtime"))
            .await
            .unwrap();

        assert_eq!(
            server_stream.next().await.unwrap().unwrap().payload(),
            b"process-runtime"
        );
    }
}

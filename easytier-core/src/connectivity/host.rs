//! Composition adapter for connector logic driven by host-owned sockets.

pub mod environment;

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use url::Url;

use crate::{
    connectivity::{
        direct::DirectConnectorHost,
        host::environment::{HostConnectorEnvironmentServices, HostConnectorEnvironmentSnapshot},
        manual::{ManualConnectorHost, ManualInterfaceAddrs},
    },
    hole_punch::udp::new_hole_punch_packet,
    proto::peer_rpc::GetIpListResponse,
    socket::{
        SocketContext,
        host::{
            HostSocketRuntime, HostTcpStream,
            factory::{HostSocketBackend, HostSocketFactory},
            listener::{HostTcpListener, HostTcpListenerBackend, HostTcpListenerFactory},
            udp::HostUdpSocket,
        },
        tcp::{
            TcpConnectOptions, TcpListenOptions, VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionControlHandler, UdpSocketSendMeta,
            VirtualUdpSocket, VirtualUdpSocketFactory,
        },
    },
};

/// One host handle domain capable of creating and operating connector sockets.
pub trait HostConnectorSocketBackend: HostSocketBackend + HostTcpListenerBackend {}

impl<T> HostConnectorSocketBackend for T where T: HostSocketBackend + HostTcpListenerBackend {}

/// Recombines mechanical host sockets with injected connector environment state.
///
/// This keeps the existing connector manager interfaces stable while ensuring
/// TCP connect, UDP bind, TCP listen, and accepted streams use one host backend.
pub struct HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    sockets: HostSocketFactory<B>,
    listeners: HostTcpListenerFactory<B>,
    environment: Arc<HostConnectorEnvironmentSnapshot>,
    environment_services: Arc<E>,
}

impl<B, E> HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    pub fn new(
        runtime: HostSocketRuntime,
        backend: Arc<B>,
        environment: HostConnectorEnvironmentSnapshot,
        environment_services: Arc<E>,
    ) -> Self {
        Self {
            sockets: HostSocketFactory::new(runtime.clone(), backend.clone()),
            listeners: HostTcpListenerFactory::new(runtime, backend),
            environment: Arc::new(environment),
            environment_services,
        }
    }
}

#[async_trait]
impl<B, E> VirtualTcpSocketFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    type Socket = HostTcpStream;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.sockets.connect_tcp(options).await
    }
}

#[async_trait]
impl<B, E> VirtualUdpSocketFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    type Socket = HostUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.sockets.bind_udp(options).await
    }
}

#[async_trait]
impl<B, E> VirtualTcpListenerFactory for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    type Listener = HostTcpListener<B>;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.listeners.bind_tcp(options).await
    }
}

#[async_trait]
impl<B, E> UdpSessionControlHandler<HostUdpSocket> for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    async fn send_v4_hole_punch(
        &self,
        socket: Arc<HostUdpSocket>,
        dst_addr: SocketAddrV4,
    ) -> std::io::Result<usize> {
        let packet = new_hole_punch_packet(1, 32).into_bytes();
        socket.send_to(&packet, SocketAddr::V4(dst_addr)).await
    }

    async fn send_v6_hole_punch(
        &self,
        socket: Arc<HostUdpSocket>,
        dst_addr: SocketAddrV6,
        preferred_src: Option<PreferredIpv6Source>,
    ) -> std::io::Result<usize> {
        let packet = new_hole_punch_packet(1, 32).into_bytes();
        if let Some(source) = preferred_src {
            let result = socket
                .send_to_with_meta(
                    &packet,
                    SocketAddr::V6(dst_addr),
                    UdpSocketSendMeta {
                        src_ip: Some(IpAddr::V6(source.ip)),
                        src_ifindex: Some(source.ifindex),
                    },
                )
                .await;
            match result {
                Ok(sent) => return Ok(sent),
                Err(error) => {
                    tracing::debug!(
                        ?source,
                        ?dst_addr,
                        ?error,
                        "UDP preferred IPv6 source failed, falling back"
                    );
                }
            }
        }
        socket.send_to(&packet, SocketAddr::V6(dst_addr)).await
    }
}

#[async_trait]
impl<B, E> ManualConnectorHost for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        self.environment_services
            .local_addr_for_remote(remote_addr, context)
            .await
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        Ok(self.environment.manual_interface_addrs())
    }
}

#[async_trait]
impl<B, E> DirectConnectorHost for HostConnectorAdapter<B, E>
where
    B: HostConnectorSocketBackend,
    E: HostConnectorEnvironmentServices,
{
    async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
        self.environment.ip_list()
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        self.environment.mapped_listeners.clone()
    }

    fn running_listeners(&self) -> Vec<Url> {
        self.environment.running_listeners.clone()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.environment.local_ips.contains(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.environment.protected_tcp_ports.contains(&port)
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.environment.managed_ipv6s.contains(ip)
    }

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        _context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.environment.preferred_ipv6_source(ip)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::Poll,
    };

    use crate::{
        connectivity::direct::DirectConnectorRpcHandler,
        hole_punch::tcp::TcpHolePunchHost,
        proto::{
            common::StunInfo,
            peer_rpc::{DirectConnectorRpc as _, GetIpListRequest},
            rpc_types::controller::BaseController,
        },
        socket::{
            host::{
                HostOperationId, HostSocketHandle, HostSocketIo, HostTcpIo,
                factory::{HostSocketFactoryIo, HostTcpConnectResult, HostUdpBindResult},
                listener::{HostTcpBindResult, HostTcpListenerIo},
                udp::{HostUdpDatagram, HostUdpIo},
            },
            udp::UdpSocketSendMeta,
        },
        stun::StunInfoProvider,
    };

    use super::*;

    #[derive(Default)]
    struct UnsupportedBackend {
        udp_send_attempts: Mutex<Vec<(Vec<u8>, SocketAddr, UdpSocketSendMeta)>>,
        reject_preferred_source: AtomicBool,
    }

    struct FixedStunProvider;

    #[async_trait]
    impl StunInfoProvider for FixedStunProvider {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                public_ip: vec!["198.51.100.7".to_owned(), "2001:db8::1".to_owned()],
                ..Default::default()
            }
        }

        async fn get_udp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            anyhow::bail!("unused by direct RPC projection test")
        }

        async fn get_tcp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            anyhow::bail!("unused by direct RPC projection test")
        }

        fn update_stun_info(&self) {}
    }

    fn unsupported<T>() -> io::Result<T> {
        Err(io::ErrorKind::Unsupported.into())
    }

    impl HostSocketIo for UnsupportedBackend {
        fn cancel_operation(&self, _operation: HostOperationId) -> io::Result<()> {
            Ok(())
        }

        fn close(&self, _handle: HostSocketHandle) -> io::Result<()> {
            Ok(())
        }
    }

    impl HostTcpIo for UnsupportedBackend {
        fn submit_read(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_read(&self, _operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
            Poll::Ready(unsupported())
        }

        fn submit_write(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _source: &[u8],
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_write(&self, _operation: HostOperationId) -> Poll<io::Result<()>> {
            Poll::Ready(unsupported())
        }
    }

    impl HostUdpIo for UnsupportedBackend {
        fn submit_recv(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_recv(&self, _operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>> {
            Poll::Ready(unsupported())
        }

        fn try_send(
            &self,
            _handle: HostSocketHandle,
            source: &[u8],
            peer_addr: SocketAddr,
            meta: UdpSocketSendMeta,
        ) -> io::Result<()> {
            self.udp_send_attempts
                .lock()
                .unwrap()
                .push((source.to_vec(), peer_addr, meta));
            if self.reject_preferred_source.load(Ordering::Relaxed) && meta.src_ip.is_some() {
                return Err(io::ErrorKind::AddrNotAvailable.into());
            }
            Ok(())
        }

        fn submit_send_ready(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_send_ready(&self, _operation: HostOperationId) -> Poll<io::Result<()>> {
            Poll::Ready(unsupported())
        }
    }

    impl HostSocketFactoryIo for UnsupportedBackend {
        fn submit_tcp_connect(
            &self,
            _operation: HostOperationId,
            _options: &TcpConnectOptions,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_tcp_connect(
            &self,
            _operation: HostOperationId,
        ) -> Poll<io::Result<HostTcpConnectResult>> {
            Poll::Ready(unsupported())
        }

        fn submit_udp_bind(
            &self,
            _operation: HostOperationId,
            _options: &UdpBindOptions,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_udp_bind(
            &self,
            _operation: HostOperationId,
        ) -> Poll<io::Result<HostUdpBindResult>> {
            Poll::Ready(unsupported())
        }
    }

    impl HostTcpListenerIo for UnsupportedBackend {
        fn submit_tcp_bind(
            &self,
            _operation: HostOperationId,
            _options: &TcpListenOptions,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_tcp_bind(
            &self,
            _operation: HostOperationId,
        ) -> Poll<io::Result<HostTcpBindResult>> {
            Poll::Ready(unsupported())
        }

        fn submit_tcp_accept(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
        ) -> io::Result<()> {
            unsupported()
        }

        fn take_tcp_accept(
            &self,
            _operation: HostOperationId,
        ) -> Poll<io::Result<HostTcpConnectResult>> {
            Poll::Ready(unsupported())
        }
    }

    #[derive(Default)]
    struct TestEnvironmentServices {
        local_requests: Mutex<Vec<(SocketAddr, SocketContext)>>,
    }

    #[async_trait]
    impl HostConnectorEnvironmentServices for TestEnvironmentServices {
        async fn local_addr_for_remote(
            &self,
            remote_addr: SocketAddr,
            context: SocketContext,
        ) -> anyhow::Result<SocketAddr> {
            self.local_requests
                .lock()
                .unwrap()
                .push((remote_addr, context));
            Ok("192.0.2.1:40100".parse().unwrap())
        }
    }

    fn test_environment_snapshot() -> HostConnectorEnvironmentSnapshot {
        HostConnectorEnvironmentSnapshot {
            interface_ipv4s: vec!["192.0.2.1".parse().unwrap()],
            public_ipv6: Some("2001:db8::1".parse().unwrap()),
            interface_ipv6s: vec!["2001:db8::1".parse().unwrap()],
            mapped_listeners: vec!["tcp://192.0.2.1:11010".parse().unwrap()],
            running_listeners: vec!["udp://192.0.2.1:11010".parse().unwrap()],
            local_ips: vec!["192.0.2.1".parse().unwrap()],
            protected_tcp_ports: vec![11010],
            managed_ipv6s: vec!["2001:db8::1".parse().unwrap()],
            preferred_ipv6_sources: vec![PreferredIpv6Source {
                ip: "2001:db8::1".parse().unwrap(),
                ifindex: 7,
            }],
            ..Default::default()
        }
    }

    fn assert_core_host<H>()
    where
        H: DirectConnectorHost + TcpHolePunchHost,
    {
    }

    #[tokio::test]
    async fn delegates_connector_environment_without_owning_policy() {
        type TestHost = HostConnectorAdapter<UnsupportedBackend, TestEnvironmentServices>;
        assert_core_host::<TestHost>();

        let services = Arc::new(TestEnvironmentServices::default());
        let host = TestHost::new(
            HostSocketRuntime::new(),
            Arc::new(UnsupportedBackend::default()),
            test_environment_snapshot(),
            services.clone(),
        );
        let remote = "203.0.113.1:11010".parse().unwrap();
        let context = SocketContext::default().with_socket_mark(Some(7));
        let local = ManualConnectorHost::local_addr_for_remote(&host, remote, context.clone())
            .await
            .unwrap();
        assert_eq!(local, "192.0.2.1:40100".parse().unwrap());
        assert_eq!(
            *services.local_requests.lock().unwrap(),
            vec![(remote, context)]
        );
        assert_eq!(
            ManualConnectorHost::interface_addrs(&host)
                .await
                .unwrap()
                .public_ipv6,
            Some("2001:db8::1".parse().unwrap())
        );
        let byte_stream_error =
            match ManualConnectorHost::connect_byte_stream(&host, &"ring://42".parse().unwrap())
                .await
            {
                Ok(_) => panic!("test environment should reject byte streams"),
                Err(error) => error,
            };
        assert_eq!(
            byte_stream_error.to_string(),
            "host does not support external byte stream: ring://42"
        );
        assert_eq!(
            DirectConnectorHost::mapped_listeners(&host),
            vec!["tcp://192.0.2.1:11010".parse::<Url>().unwrap()]
        );
        assert!(DirectConnectorHost::is_protected_tcp_port(&host, 11010));
    }

    #[tokio::test]
    async fn direct_rpc_projects_listeners_and_filters_managed_ipv6() {
        let host = Arc::new(HostConnectorAdapter::new(
            HostSocketRuntime::new(),
            Arc::new(UnsupportedBackend::default()),
            test_environment_snapshot(),
            Arc::new(TestEnvironmentServices::default()),
        ));
        let handler = DirectConnectorRpcHandler::new_with_stun(
            host,
            SocketContext::default().with_socket_mark(Some(7)),
            Some(Arc::new(FixedStunProvider)),
        );

        let response = handler
            .get_ip_list(BaseController::default(), GetIpListRequest {})
            .await
            .unwrap();

        assert_eq!(
            response.interface_ipv4s,
            vec![std::net::Ipv4Addr::new(192, 0, 2, 1).into()]
        );
        assert!(response.interface_ipv6s.is_empty());
        assert_eq!(
            response.public_ipv4,
            Some("198.51.100.7".parse::<std::net::Ipv4Addr>().unwrap().into())
        );
        assert!(response.public_ipv6.is_none());
        assert_eq!(
            response
                .listeners
                .into_iter()
                .map(Url::from)
                .collect::<Vec<_>>(),
            vec![
                "tcp://192.0.2.1:11010".parse::<Url>().unwrap(),
                "udp://192.0.2.1:11010".parse::<Url>().unwrap(),
            ]
        );
    }

    #[tokio::test]
    async fn foreign_direct_rpc_preserves_parent_managed_ipv6_addresses() {
        let host = Arc::new(HostConnectorAdapter::new(
            HostSocketRuntime::new(),
            Arc::new(UnsupportedBackend::default()),
            test_environment_snapshot(),
            Arc::new(TestEnvironmentServices::default()),
        ));
        let handler = DirectConnectorRpcHandler::new_for_foreign_network_with_stun(
            host,
            SocketContext::default().with_socket_mark(Some(7)),
            Some(Arc::new(FixedStunProvider)),
        );

        let response = handler
            .get_ip_list(BaseController::default(), GetIpListRequest {})
            .await
            .unwrap();

        assert_eq!(
            response.interface_ipv6s,
            vec!["2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().into()]
        );
        assert_eq!(
            response.public_ipv6,
            Some("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().into())
        );
        assert_eq!(
            response.public_ipv4,
            Some("198.51.100.7".parse::<std::net::Ipv4Addr>().unwrap().into())
        );
    }

    #[tokio::test]
    async fn core_builds_udp_hole_punch_packets_and_falls_back_without_source() {
        let runtime = HostSocketRuntime::new();
        let backend = Arc::new(UnsupportedBackend::default());
        let host = HostConnectorAdapter::new(
            runtime.clone(),
            backend.clone(),
            test_environment_snapshot(),
            Arc::new(TestEnvironmentServices::default()),
        );
        let socket = Arc::new(runtime.udp_socket(
            backend.clone(),
            HostSocketHandle(7),
            "[::]:40100".parse().unwrap(),
        ));
        let destination = "[2001:db8::2]:41000".parse().unwrap();
        let preferred = PreferredIpv6Source {
            ip: "2001:db8::1".parse().unwrap(),
            ifindex: 9,
        };

        let v4_destination = "192.0.2.2:41000".parse().unwrap();
        let v4_sent = host
            .send_v4_hole_punch(socket.clone(), v4_destination)
            .await
            .unwrap();
        {
            let mut attempts = backend.udp_send_attempts.lock().unwrap();
            assert_eq!(attempts.len(), 1);
            assert_eq!(v4_sent, attempts[0].0.len());
            assert_eq!(attempts[0].1, SocketAddr::V4(v4_destination));
            assert_eq!(attempts[0].2, UdpSocketSendMeta::default());
            attempts.clear();
        }

        backend
            .reject_preferred_source
            .store(true, Ordering::Relaxed);
        let sent = host
            .send_v6_hole_punch(socket, destination, Some(preferred))
            .await
            .unwrap();

        let attempts = backend.udp_send_attempts.lock().unwrap();
        assert_eq!(attempts.len(), 2);
        assert_eq!(sent, attempts[1].0.len());
        assert!(!attempts[0].0.is_empty());
        assert_eq!(attempts[0].0, attempts[1].0);
        assert_eq!(attempts[0].1, SocketAddr::V6(destination));
        assert_eq!(
            attempts[0].2,
            UdpSocketSendMeta {
                src_ip: Some(IpAddr::V6(preferred.ip)),
                src_ifindex: Some(preferred.ifindex),
            }
        );
        assert_eq!(attempts[1].2, UdpSocketSendMeta::default());
    }
}

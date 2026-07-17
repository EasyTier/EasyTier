use std::sync::Arc;

use async_trait::async_trait;

use super::*;
use crate::{
    listener::{SocketListener, transport::TransportListenerConfig},
    socket::{
        SocketContext,
        udp::{UdpSessionAcceptKind, UdpSessionProtocol},
    },
};

struct TestServerProtocol;

#[async_trait]
impl ServerProtocolUpgrader<()> for TestServerProtocol {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "ws" | "wss" | "wg" | "quic" | "faketcp" | "unix")
    }

    async fn upgrade_tcp(
        &self,
        _socket: (),
        _local_url: Url,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }

    async fn upgrade_udp(
        &self,
        _session: crate::socket::udp::UdpSession,
        _local_url: Url,
        _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }

    async fn upgrade_byte_stream(
        &self,
        _socket: (),
        _local_url: Url,
        _remote_url: Option<Url>,
    ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
        unreachable!()
    }
}

struct TestExternalListenerFactory;

impl ExternalListenerFactory<()> for TestExternalListenerFactory {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "faketcp" | "unix")
    }

    fn create(&self, _request: ExternalListenerRequest) -> Box<dyn SocketListener<Accepted = ()>> {
        unreachable!()
    }
}

#[test]
fn runtime_updates_retain_core_owned_peer_identity() {
    let mut snapshot = Arc::new(PeerRuntimeSnapshot::default());
    Arc::make_mut(&mut snapshot).runtime.core.node.peer_id = Some(17);
    Arc::make_mut(&mut snapshot).runtime.core.node.instance_id = Some([1; 16]);
    let submitted = snapshot.clone();

    retain_core_peer_identity(&mut snapshot, 23, Some([2; 16]));

    assert_eq!(snapshot.runtime.core.node.peer_id, Some(23));
    assert_eq!(snapshot.runtime.core.node.instance_id, Some([2; 16]));
    assert_eq!(submitted.runtime.core.node.peer_id, Some(17));
    assert_eq!(submitted.runtime.core.node.instance_id, Some([1; 16]));
}

#[test]
fn core_plans_transport_and_external_listener_capabilities() {
    let self_id = uuid::Uuid::new_v4();
    let config = ListenerRuntimeConfig::new(
        [
            "tcp://127.0.0.1:1",
            "udp://127.0.0.1:2",
            "ws://127.0.0.1:3",
            "wg://127.0.0.1:4",
            "quic://127.0.0.1:5",
            "faketcp://127.0.0.1:6",
            "unix:///tmp/easytier-test",
            "http://127.0.0.1:7",
        ]
        .into_iter()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .unwrap(),
        false,
        SocketContext::default().with_socket_mark(Some(7)),
    );

    let plan = prepare_listener_plan::<(), ()>(
        Some(&config),
        self_id,
        Some(&TestServerProtocol),
        Some(&TestExternalListenerFactory),
    )
    .unwrap();

    assert_eq!(plan.transports.len(), 6);
    assert_eq!(plan.external.len(), 2);
    assert_eq!(plan.failures.len(), 1);
    assert_eq!(
        plan.transports[0].url(),
        &crate::listener::plan::ring_listener_url(self_id)
    );
    assert!(matches!(
        &plan.transports[4],
        TransportListenerConfig::Udp {
            accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
            ..
        }
    ));
    assert!(matches!(
        &plan.transports[5],
        TransportListenerConfig::Udp {
            accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
            ..
        }
    ));
    assert_eq!(plan.external[0].0.url.scheme(), "faketcp");
    assert_eq!(plan.external[0].1.socket_mark, Some(7));
}

#[test]
fn unsupported_protocol_listener_becomes_a_plan_failure() {
    let config = ListenerRuntimeConfig::new(
        vec!["wg://127.0.0.1:11011".parse().unwrap()],
        false,
        SocketContext::default(),
    );

    let plan =
        prepare_listener_plan::<(), ()>(Some(&config), uuid::Uuid::new_v4(), None, None).unwrap();

    assert_eq!(plan.transports.len(), 1);
    assert!(plan.external.is_empty());
    assert_eq!(plan.failures.len(), 1);
}

#[test]
fn raw_unix_listener_does_not_require_a_server_protocol() {
    let config = ListenerRuntimeConfig::new(
        vec!["unix:///tmp/easytier-test".parse().unwrap()],
        false,
        SocketContext::default(),
    );

    let plan = prepare_listener_plan::<(), ()>(
        Some(&config),
        uuid::Uuid::new_v4(),
        None,
        Some(&TestExternalListenerFactory),
    )
    .unwrap();

    assert_eq!(plan.transports.len(), 1);
    assert_eq!(plan.external.len(), 1);
    assert!(plan.failures.is_empty());
    assert_eq!(plan.external[0].0.url.scheme(), "unix");
}

#[test]
fn core_instance_config_round_trips_as_normalized_json() {
    let mut core = crate::config::CoreConfig::default();
    core.peer_policy.encryption_required = false;
    core.peer_policy.p2p_enabled = false;
    let peer = crate::peers::peer_manager::PortablePeerManagerConfig::new(
        crate::peers::context::PeerRuntimeConfig {
            core,
            network_identity: crate::config::NetworkIdentity {
                network_name: "default".to_owned(),
                network_secret: Some("test".to_owned()),
                network_secret_digest: None,
            },
            stun_info: crate::proto::common::StunInfo::default(),
            feature_flags: crate::proto::common::PeerFeatureFlag::default(),
            secure_mode: None,
            host_routing: crate::peers::context::HostRoutingPolicy::default(),
        },
    );
    let config = CoreInstanceConfig {
        peer,
        connectivity: CoreConnectivityConfig::default(),
    };

    let mut config = config;
    config.connectivity.direct.disable_p2p = true;
    config.connectivity.direct.testing = true;
    let encoded = serde_json::to_value(&config).unwrap();
    assert!(encoded["connectivity"]["direct"].get("testing").is_none());
    let decoded: CoreInstanceConfig = serde_json::from_value(encoded.clone()).unwrap();

    assert!(!decoded.connectivity.direct.testing);
    assert!(decoded.connectivity.startup_plan.gateway);
    assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);

    let mut create = crate::instance::wasi::WasiCoreInstanceCreateConfig {
        version: crate::instance::wasi::WASI_CORE_INSTANCE_CONFIG_VERSION,
        instance: decoded,
        environment:
            crate::connectivity::host::environment::HostConnectorEnvironmentSnapshot::default(),
    };
    create.validate().unwrap();
    let fixture = include_bytes!("../../../easytier-go-host/testdata/minimal_core_instance.json");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(fixture).unwrap(),
        serde_json::to_value(&create).unwrap()
    );
    let create_json = serde_json::to_vec(&create).unwrap();
    serde_json::from_slice::<crate::instance::wasi::WasiCoreInstanceCreateConfig>(&create_json)
        .unwrap()
        .validate()
        .unwrap();
    create.version += 1;
    assert!(create.validate().is_err());
}

#[test]
fn core_instance_config_validation_rejects_invalid_acl_whitelist() {
    let peer = crate::peers::peer_manager::PortablePeerManagerConfig::new(
        crate::peers::context::PeerRuntimeConfig {
            core: crate::config::CoreConfig::default(),
            network_identity: crate::config::NetworkIdentity {
                network_name: "default".to_owned(),
                network_secret: Some("test".to_owned()),
                network_secret_digest: None,
            },
            stun_info: crate::proto::common::StunInfo::default(),
            feature_flags: crate::proto::common::PeerFeatureFlag::default(),
            secure_mode: None,
            host_routing: crate::peers::context::HostRoutingPolicy::default(),
        },
    );
    let mut config = CoreInstanceConfig {
        peer,
        connectivity: CoreConnectivityConfig::default(),
    };
    config.connectivity.direct.lazy_p2p = config.peer.snapshot.flags.lazy_p2p;
    config.connectivity.direct.disable_p2p = config.peer.snapshot.flags.disable_p2p;
    config.connectivity.direct.need_p2p = config.peer.snapshot.flags.need_p2p;
    config.connectivity.runtime.acl.tcp_whitelist = vec!["9000-8000".to_owned()];

    let error = validate_core_instance_config(&config).unwrap_err();

    assert!(error.to_string().contains("Start port must be <= end port"));
}

mod portable_runtime {
    use std::{
        io,
        net::{IpAddr, Ipv6Addr, SocketAddr},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    use tokio::{
        io::{AsyncRead, AsyncWrite, ReadBuf},
        sync::Notify,
    };
    use tokio_util::task::AbortOnDropHandle;

    #[cfg(feature = "proxy-packet")]
    use std::sync::Mutex as StdMutex;

    use super::*;
    use crate::{
        config::runtime::CoreInstanceRuntimeConfig,
        config::{CoreConfig, IpPrefix, NetworkIdentity, ProxyNetworkConfig},
        connectivity::manual::{ManualConnectorHost, ManualInterfaceAddrs},
        gateway::proxy::wrapped_transport::{
            WrappedTransportEngine, WrappedTransportEngineStart, WrappedTransportEngines,
            WrappedTransportRole,
        },
        host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        listener::transport::AcceptedTransport,
        peers::{
            context::{HostRoutingPolicy, PeerRuntimeConfig},
            peer_manager::PortablePeerManagerConfig,
        },
        proto::{common::StunInfo, peer_rpc::GetIpListResponse},
        socket::{
            SocketContext,
            tcp::{
                TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose,
                VirtualTcpListener, VirtualTcpListenerFactory, VirtualTcpSocket,
                VirtualTcpSocketFactory,
            },
            udp::{PreferredIpv6Source, UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
        },
    };

    #[cfg(feature = "proxy-packet")]
    use crate::gateway::proxy::wrapped_transport::WrappedTransportKind;

    struct TestTcpSocket(tokio::io::DuplexStream);

    impl AsyncRead for TestTcpSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(_cx, buf)
        }
    }

    impl AsyncWrite for TestTcpSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(_cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for TestTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:20000".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:20001".parse().unwrap())
        }
    }

    struct TestTcpListener(SocketAddr);

    #[async_trait]
    impl VirtualTcpListener for TestTcpListener {
        type Socket = TestTcpSocket;

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }

        async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
            std::future::pending().await
        }
    }

    struct TestUdpSocket(SocketAddr);

    #[async_trait]
    impl VirtualUdpSocket for TestUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.0)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct TestHost {
        proxy_nat_connections:
            Option<tokio::sync::mpsc::UnboundedSender<(SocketAddr, tokio::io::DuplexStream)>>,
        reject_socks5_listener: bool,
    }

    #[async_trait]
    impl VirtualTcpSocketFactory for TestHost {
        type Socket = TestTcpSocket;

        async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
            if options.purpose != TcpSocketPurpose::ProxyNat {
                anyhow::bail!("test host does not connect non-proxy TCP sockets");
            }
            let connections = self
                .proxy_nat_connections
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("test host proxy NAT is disabled"))?;
            let (socket, peer) = tokio::io::duplex(1024);
            connections
                .send((options.remote_addr, peer))
                .map_err(|_| anyhow::anyhow!("test host proxy NAT receiver is closed"))?;
            Ok(TestTcpSocket(socket))
        }
    }

    #[async_trait]
    impl VirtualTcpListenerFactory for TestHost {
        type Listener = TestTcpListener;

        async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
            if self.reject_socks5_listener && options.purpose == TcpListenPurpose::Socks5 {
                anyhow::bail!("test host rejected SOCKS5 listener");
            }
            let address = options
                .bind
                .local_addr
                .unwrap_or_else(|| "127.0.0.1:20000".parse().unwrap());
            Ok(Arc::new(TestTcpListener(address)))
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for TestHost {
        type Socket = TestUdpSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            let address = options
                .local_addr
                .unwrap_or_else(|| "127.0.0.1:20002".parse().unwrap());
            Ok(Arc::new(TestUdpSocket(address)))
        }
    }

    #[async_trait]
    impl ManualConnectorHost for TestHost {
        async fn local_addr_for_remote(
            &self,
            remote_addr: SocketAddr,
            _context: SocketContext,
        ) -> anyhow::Result<SocketAddr> {
            Ok(match remote_addr {
                SocketAddr::V4(_) => "127.0.0.1:0".parse().unwrap(),
                SocketAddr::V6(_) => "[::1]:0".parse().unwrap(),
            })
        }

        async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
            Ok(ManualInterfaceAddrs {
                interface_ipv4s: vec![],
                interface_ipv6s: vec![],
                public_ipv6: None,
            })
        }
    }

    #[async_trait]
    impl DirectConnectorHost for TestHost {
        async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
            GetIpListResponse::default()
        }

        fn mapped_listeners(&self) -> Vec<Url> {
            Vec::new()
        }

        fn is_local_ip(&self, _ip: &IpAddr) -> bool {
            false
        }

        fn is_protected_tcp_port(&self, _port: u16) -> bool {
            false
        }

        async fn preferred_ipv6_source(
            &self,
            _ip: Ipv6Addr,
            _context: SocketContext,
        ) -> Option<PreferredIpv6Source> {
            None
        }
    }

    struct TestDns;

    #[async_trait]
    impl DnsResolver for TestDns {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(query.host.parse().into_iter().collect())
        }
    }

    #[async_trait]
    impl DnsRecordResolver for TestDns {
        async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
            anyhow::bail!("test DNS has no TXT records")
        }

        async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            Ok(Vec::new())
        }
    }

    fn test_config(network_name: &str) -> CoreInstanceConfig {
        let mut core = CoreConfig::default();
        core.node.network_name = network_name.to_owned();
        core.peer_policy.encryption_required = false;
        let peer = PortablePeerManagerConfig::new(PeerRuntimeConfig {
            core,
            network_identity: NetworkIdentity {
                network_name: network_name.to_owned(),
                network_secret: Some(String::new()),
                network_secret_digest: None,
            },
            stun_info: StunInfo::default(),
            feature_flags: Default::default(),
            secure_mode: None,
            host_routing: HostRoutingPolicy::default(),
        });
        let mut connectivity = CoreConnectivityConfig::default();
        connectivity.direct.network_name = network_name.to_owned();
        connectivity.direct.lazy_p2p = peer.snapshot.flags.lazy_p2p;
        connectivity.direct.disable_p2p = peer.snapshot.flags.disable_p2p;
        connectivity.direct.need_p2p = peer.snapshot.flags.need_p2p;
        CoreInstanceConfig { peer, connectivity }
    }

    fn runtime_snapshot(config: &CoreInstanceConfig) -> CoreInstanceRuntimeConfig {
        CoreInstanceRuntimeConfig {
            services: config.connectivity.runtime.clone(),
            peer: Arc::new(config.peer.snapshot.clone()),
        }
    }

    fn proxy_network(real: &str, mapped: Option<&str>) -> ProxyNetworkConfig {
        fn prefix(value: &str) -> IpPrefix {
            let (address, prefix_len) = value.split_once('/').unwrap();
            IpPrefix {
                address: address.parse().unwrap(),
                prefix_len: prefix_len.parse().unwrap(),
            }
        }

        ProxyNetworkConfig {
            real: prefix(real),
            mapped: mapped.map(prefix),
        }
    }

    fn adapters(
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
    ) -> CoreHostAdapters<TestHost> {
        adapters_with_host(
            Arc::new(TestHost::default()),
            external_listener_factory,
            packet_sink,
        )
    }

    fn adapters_with_host(
        host: Arc<TestHost>,
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
        packet_sink: Arc<dyn PacketSink>,
    ) -> CoreHostAdapters<TestHost> {
        let dns = Arc::new(TestDns);
        let mut adapters = CoreHostAdapters::new(host, dns, packet_sink, CoreProcessRuntime::new());
        adapters.external_listener_factory = external_listener_factory;
        adapters
    }

    fn build_with_engines(
        config: CoreInstanceConfig,
        engines: WrappedTransportEngines,
    ) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        build_with_engines_and_listener(config, engines, None)
    }

    fn build_with_engines_and_listener(
        config: CoreInstanceConfig,
        engines: WrappedTransportEngines,
        external_listener_factory: Option<
            Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
        >,
    ) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters(external_listener_factory, Arc::new(packet_sink));
        adapters.wrapped_transports = engines;
        CoreInstance::new(config, adapters)
    }

    fn build_instance(config: CoreInstanceConfig) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
        build_with_engines(config, WrappedTransportEngines::default())
    }

    #[tokio::test]
    async fn packet_plane_does_not_retain_core_instance() {
        let instance = build_instance(test_config("packet-plane-ownership")).unwrap();
        let weak = Arc::downgrade(&instance);
        let packet_plane = instance.packet_plane();

        drop(instance);

        assert!(weak.upgrade().is_none());
        drop(packet_plane);
    }

    #[derive(Default)]
    struct RecordingProxyService {
        start_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        start_gate: Option<Arc<ProxyStartGate>>,
        #[cfg(feature = "proxy-packet")]
        destination_ingress: StdMutex<
            Option<crate::gateway::proxy::wrapped_transport::WrappedTransportDestinationIngress>,
        >,
    }

    #[derive(Default)]
    struct ProxyStartGate {
        entered: Notify,
        release: Notify,
    }

    impl RecordingProxyService {
        fn blocking() -> (Arc<Self>, Arc<ProxyStartGate>) {
            let gate = Arc::new(ProxyStartGate::default());
            (
                Arc::new(Self {
                    start_gate: Some(gate.clone()),
                    ..Default::default()
                }),
                gate,
            )
        }

        #[cfg(feature = "proxy-packet")]
        fn destination_ingress(
            &self,
        ) -> Option<crate::gateway::proxy::wrapped_transport::WrappedTransportDestinationIngress>
        {
            self.destination_ingress.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingProxyService {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            #[cfg(feature = "proxy-packet")]
            {
                *self.destination_ingress.lock().unwrap() = options.destination_ingress;
            }
            #[cfg(not(feature = "proxy-packet"))]
            let _ = options;
            if let Some(gate) = &self.start_gate {
                gate.entered.notify_one();
                gate.release.notified().await;
            }
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: bytes::Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: crate::gateway::proxy::wrapped_transport::WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn crate::gateway::proxy::runtime::TcpProxyStream>> {
            anyhow::bail!("recording engine does not open streams")
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Default)]
    struct BlockingListenerState {
        start_entered: Notify,
        drop_calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct BlockingSocketListener {
        url: Url,
        state: Arc<BlockingListenerState>,
    }

    #[async_trait]
    impl SocketListener for BlockingSocketListener {
        type Accepted = AcceptedTransport<TestTcpSocket>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.state.start_entered.notify_one();
            std::future::pending().await
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            self.url.clone()
        }
    }

    impl Drop for BlockingSocketListener {
        fn drop(&mut self) {
            self.state.drop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct BlockingExternalListenerFactory {
        state: Arc<BlockingListenerState>,
    }

    impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for BlockingExternalListenerFactory {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "unix"
        }

        fn create(
            &self,
            request: ExternalListenerRequest,
        ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
            Box::new(BlockingSocketListener {
                url: request.url,
                state: self.state.clone(),
            })
        }
    }

    #[derive(Debug)]
    struct ReadySocketListener(Url);

    #[async_trait]
    impl SocketListener for ReadySocketListener {
        type Accepted = AcceptedTransport<TestTcpSocket>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            self.0.clone()
        }
    }

    struct ReadyExternalListenerFactory;

    impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for ReadyExternalListenerFactory {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "unix"
        }

        fn create(
            &self,
            request: ExternalListenerRequest,
        ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
            Box::new(ReadySocketListener(request.url))
        }
    }

    #[tokio::test]
    async fn runtime_updates_refresh_avoid_relay_preference() {
        let config = test_config("portable-runtime-update");
        let instance = build_instance(config.clone()).unwrap();

        assert!(
            !instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut enabled = runtime_snapshot(&config);
        Arc::make_mut(&mut enabled.peer).avoid_relay_data_preference = true;
        instance.update_runtime_config(enabled).await.unwrap();
        assert!(
            instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut disabled = runtime_snapshot(&config);
        Arc::make_mut(&mut disabled.peer).avoid_relay_data_preference = false;
        instance.update_runtime_config(disabled).await.unwrap();
        assert!(
            !instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );
    }

    #[cfg(feature = "test-utils")]
    #[cfg_attr(
        not(target_os = "wasi"),
        tokio::test(flavor = "multi_thread", worker_threads = 2)
    )]
    #[cfg_attr(target_os = "wasi", tokio::test)]
    async fn concurrent_runtime_updates_keep_snapshot_and_derived_state_coherent() {
        let config = test_config("concurrent-runtime-update");
        let instance = build_instance(config.clone()).unwrap();
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();

        let original = instance.node_snapshot().await;
        let mut full = runtime_snapshot(&config);
        full.services.dhcp_ipv4 = true;
        full.services.acl.tcp_whitelist = vec!["80".to_owned()];
        {
            let peer = Arc::make_mut(&mut full.peer);
            peer.runtime.core.node.hostname = Some("full".to_owned());
            peer.runtime.core.routes.proxy_networks =
                vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
        }
        let mut peer_update = full.clone();
        {
            let peer = Arc::make_mut(&mut peer_update.peer);
            peer.runtime.core.node.hostname = Some("peer".to_owned());
            peer.runtime.core.routes.proxy_networks =
                vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];
        }

        let start = Arc::new(tokio::sync::Barrier::new(3));
        let full_update = tokio::spawn({
            let instance = instance.clone();
            let start = start.clone();
            async move {
                start.wait().await;
                instance.update_runtime_config(full).await
            }
        });
        let peer_update = tokio::spawn({
            let instance = instance.clone();
            let start = start.clone();
            async move {
                start.wait().await;
                instance.update_runtime_config(peer_update).await
            }
        });
        start.wait().await;
        full_update.await.unwrap().unwrap();
        peer_update.await.unwrap().unwrap();

        let final_config = instance.runtime_config.snapshot();
        assert!(final_config.services.dhcp_ipv4);
        assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["80"]);
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 1);
        let node = instance.node_snapshot().await;
        assert_eq!(node.peer_id, original.peer_id);
        assert_eq!(node.instance_id, original.instance_id);
        assert_eq!(
            final_config.peer.runtime.core.node.hostname.as_deref(),
            Some(node.hostname.as_str())
        );
        match node.hostname.as_str() {
            "full" => assert_eq!(
                instance
                    .proxy_cidr_table
                    .lookup_v4("198.51.100.42".parse().unwrap()),
                Some("192.0.2.42".parse().unwrap())
            ),
            "peer" => assert_eq!(
                instance
                    .proxy_cidr_table
                    .lookup_v4("10.20.30.42".parse().unwrap()),
                Some("203.0.113.42".parse().unwrap())
            ),
            hostname => panic!("unexpected final hostname: {hostname:?}"),
        }

        instance.stop().await;
    }

    #[cfg(feature = "test-utils")]
    #[tokio::test]
    async fn active_runtime_update_skips_unchanged_and_rejects_invalid_acl() {
        let config = test_config("invalid-active-acl-update");
        let instance = build_instance(config.clone()).unwrap();
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();

        let mut unrelated = runtime_snapshot(&config);
        Arc::make_mut(&mut unrelated.peer)
            .runtime
            .core
            .node
            .hostname = Some("accepted".to_owned());
        instance.update_runtime_config(unrelated).await.unwrap();
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 0);
        let before = instance.node_snapshot().await;

        let mut rejected = runtime_snapshot(&config);
        rejected.services.dhcp_ipv4 = true;
        rejected.services.acl.tcp_whitelist = vec!["invalid".to_owned()];
        Arc::make_mut(&mut rejected.peer).runtime.core.node.hostname = Some("rejected".to_owned());

        let error = instance.update_runtime_config(rejected).await.unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert!(!instance.runtime_config.snapshot().services.dhcp_ipv4);
        assert!(instance.acl_whitelist_snapshot().tcp_ports.is_empty());
        assert_eq!(instance.acl_reload_count.load(Ordering::Relaxed), 0);
        assert_eq!(instance.node_snapshot().await.hostname, before.hostname);
        instance.stop().await;
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_connectivity_lifecycle() {
        let mut config = test_config("connectivity-lifecycle");
        config.peer.snapshot.runtime.core.routes.proxy_networks =
            vec![proxy_network("10.1.2.0/24", None)];
        let initial_peer: Url = "tcp://127.0.0.1:29999".parse().unwrap();
        config.connectivity.initial_peers = vec![initial_peer.clone()];
        let proxy = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        assert_eq!(instance.state(), CoreInstanceState::Created);
        assert!(instance.list_connectors().is_empty());
        assert!(instance.start_transport_proxy().await.is_err());
        assert!(instance.start_network_services(None).await.is_err());
        assert!(instance.start_proxy().await.is_err());
        assert!(instance.start_peer_center().await.is_err());
        instance.start().await.unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Running);
        assert!(instance.list_connectors().is_empty());
        assert!(instance.start_initial_peers().await.is_err());
        assert!(instance.start().await.is_err());
        instance.start_after_host_ready(None).await.unwrap();
        instance.start_after_host_ready(None).await.unwrap();
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(instance.list_connectors().len(), 1);
        assert_eq!(instance.list_connectors()[0].url, initial_peer);
        assert!(instance.proxy_started.load(Ordering::Acquire));

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
        assert!(!instance.proxy_started.load(Ordering::Acquire));
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    #[tokio::test]
    async fn startup_plan_controls_gateway_for_initial_and_updated_config() {
        fn build(config: CoreInstanceConfig) -> Arc<CoreInstance<TestHost>> {
            let host = Arc::new(TestHost {
                reject_socks5_listener: true,
                ..Default::default()
            });
            let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
            let adapters = adapters_with_host(host, None, Arc::new(packet_sink));
            CoreInstance::new(config, adapters).unwrap()
        }

        let mut enabled_config = test_config("gateway-enabled-by-default");
        enabled_config.connectivity.runtime.gateway.socks5_bind =
            Some("127.0.0.1:1080".parse().unwrap());
        let enabled = build(enabled_config);
        enabled.start().await.unwrap();
        let error = enabled.start_after_host_ready(None).await.unwrap_err();
        assert!(error.to_string().contains("rejected SOCKS5 listener"));
        assert_eq!(enabled.state(), CoreInstanceState::Stopped);

        let mut disabled_config = test_config("gateway-disabled-by-plan");
        disabled_config.connectivity.startup_plan.gateway = false;
        let disabled = build(disabled_config.clone());
        let mut updated = runtime_snapshot(&disabled_config);
        updated.services.gateway.socks5_bind = Some("127.0.0.1:1080".parse().unwrap());
        disabled.update_runtime_config(updated).await.unwrap();
        disabled.start().await.unwrap();
        disabled.start_after_host_ready(None).await.unwrap();
        assert_eq!(disabled.state(), CoreInstanceState::Running);
        disabled.stop().await;
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_wrapped_transport_source_nat() {
        let mut config = test_config("wrapped-source");
        config.peer.snapshot.flags.enable_kcp_proxy = true;
        config.peer.snapshot.flags.disable_kcp_input = true;
        let engine = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(engine.clone()),
                quic: None,
            },
        )
        .unwrap();

        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert!(
            instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            )
        );
        assert!(
            instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Source,
                )
                .is_empty()
        );

        instance.stop().await;
        assert!(
            !instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            )
        );
        assert_eq!(engine.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn runtime_core_instance_owns_wrapped_transport_destination_sessions() {
        let mut config = test_config("wrapped-destination");
        config.peer.snapshot.flags.enable_kcp_proxy = false;
        config.peer.snapshot.flags.disable_kcp_input = false;
        let engine = Arc::new(RecordingProxyService::default());
        let (connections, mut connection_receiver) = tokio::sync::mpsc::unbounded_channel();
        let host = Arc::new(TestHost {
            proxy_nat_connections: Some(connections),
            ..Default::default()
        });
        let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
        let mut adapters = adapters_with_host(host, None, Arc::new(packet_sink));
        adapters.wrapped_transports = WrappedTransportEngines {
            kcp: Some(engine.clone()),
            quic: None,
        };
        let instance = CoreInstance::new(config, adapters).unwrap();

        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert!(instance.wrapped_transport_is_started(
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Destination,
        ));

        let destination: SocketAddr = "127.0.0.1:20100".parse().unwrap();
        let ingress = engine
            .destination_ingress()
            .expect("core should inject a destination ingress");
        let (core_stream, peer_stream) = tokio::io::duplex(1024);
        ingress
            .submit(
                crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                    src: "10.0.0.2:40000".parse().unwrap(),
                    dst: destination,
                    initial_acl_packet_size: 16,
                    stream: Box::new(core_stream),
                },
            )
            .await
            .unwrap();
        let (connected_destination, destination_stream) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection_receiver.recv(),
        )
        .await
        .expect("core should request the destination socket")
        .unwrap();
        assert_eq!(connected_destination, destination);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                let entries = instance.wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                );
                if entries.iter().any(|entry| {
                    entry.state
                        == crate::gateway::proxy::tcp_proxy_engine::TcpNatEntryState::Connected
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("core should own the connected destination entry");

        drop(peer_stream);
        drop(destination_stream);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completed destination entry should be removed");

        let (core_stream, _blocked_peer_stream) = tokio::io::duplex(1024);
        ingress
            .submit(
                crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                    src: "10.0.0.2:40001".parse().unwrap(),
                    dst: destination,
                    initial_acl_packet_size: 16,
                    stream: Box::new(core_stream),
                },
            )
            .await
            .unwrap();
        let (connected_destination, _blocked_destination_stream) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection_receiver.recv(),
        )
        .await
        .expect("second destination session should request a socket")
        .unwrap();
        assert_eq!(connected_destination, destination);
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("blocked destination session should be visible");

        tokio::time::timeout(std::time::Duration::from_secs(2), instance.stop())
            .await
            .expect("stop should cancel core-owned destination sessions");
        assert!(
            instance
                .wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                )
                .is_empty()
        );
        assert!(
            ingress
                .submit(
                    crate::gateway::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                        src: "10.0.0.2:40002".parse().unwrap(),
                        dst: destination,
                        initial_acl_packet_size: 16,
                        stream: Box::new(tokio::io::duplex(64).0),
                    },
                )
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_the_transport_proxy_cidr_table() {
        let mut config = test_config("transport-proxy-cidr");
        config.peer.snapshot.runtime.core.routes.proxy_networks =
            vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
        let mut updated = runtime_snapshot(&config);
        let proxy = Arc::new(RecordingProxyService::default());
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();

        assert!(instance.start_network_services(None).await.is_err());
        assert_eq!(instance.node_snapshot().await.proxy_networks.len(), 1);
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

        Arc::make_mut(&mut updated.peer)
            .runtime
            .core
            .routes
            .proxy_networks = vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];
        instance.update_runtime_config(updated).await.unwrap();
        let proxy_networks = instance.node_snapshot().await.proxy_networks;
        assert_eq!(proxy_networks.len(), 1);
        assert_eq!(
            proxy_networks[0].real.address,
            "203.0.113.0".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            proxy_networks[0].mapped.as_ref().unwrap().address,
            "10.20.30.0".parse::<IpAddr>().unwrap()
        );

        instance.stop().await;
        assert!(instance.start_network_services(None).await.is_err());
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_acl_runtime_snapshot() {
        let config = test_config("explicit-acl");
        let instance = build_instance(config.clone()).unwrap();
        assert_eq!(instance.acl_whitelist_snapshot(), Default::default());

        let mut updated = runtime_snapshot(&config);
        updated.services.acl.tcp_whitelist = vec!["invalid".to_owned()];
        instance.update_runtime_config(updated).await.unwrap();
        instance.start().await.unwrap();
        let error = instance.start_network_services(None).await.unwrap_err();
        assert!(error.to_string().contains("Invalid port number"));
        assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["invalid"]);
        instance.stop().await;
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_dhcp_runtime_snapshot() {
        let config = test_config("explicit-dhcp");
        let instance = build_instance(config.clone()).unwrap();
        let mut updated = runtime_snapshot(&config);
        updated.services.dhcp_ipv4 = true;
        instance.update_runtime_config(updated).await.unwrap();
        instance.start().await.unwrap();
        let error = instance.start_after_host_ready(None).await.unwrap_err();
        assert!(error.to_string().contains("no host adapter was provided"));
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_public_ipv6_runtime_snapshot() {
        let config = test_config("explicit-public-ipv6");
        let instance = build_instance(config.clone()).unwrap();
        let mut updated = runtime_snapshot(&config);
        updated.services.public_ipv6_provider.provider_enabled = true;
        updated.services.public_ipv6_provider.provider_supported = true;
        updated.services.public_ipv6_provider.configured_prefix =
            Some("fd00::/64".parse().unwrap());
        instance.update_runtime_config(updated).await.unwrap();

        let error = instance.start().await.unwrap_err();
        assert!(error.to_string().contains("not a valid global unicast"));
        assert_eq!(instance.state(), CoreInstanceState::Created);
    }

    #[tokio::test]
    async fn stopping_while_transport_proxy_starts_rolls_back_once() {
        let mut config = test_config("blocking-transport-proxy");
        config.peer.snapshot.runtime.core.routes.proxy_networks =
            vec![proxy_network("10.1.2.0/24", None)];
        config.connectivity.initial_peers = vec!["tcp://127.0.0.1:29998".parse().unwrap()];
        let (proxy, start_gate) = RecordingProxyService::blocking();
        let instance = build_with_engines(
            config,
            WrappedTransportEngines {
                kcp: Some(proxy.clone()),
                quic: None,
            },
        )
        .unwrap();
        instance.start().await.unwrap();
        instance.start_peer_center().await.unwrap();

        let start_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start_transport_proxy().await }
        });
        start_gate.entered.notified().await;
        let initial_peer_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start_initial_peers().await }
        });
        tokio::task::yield_now().await;
        let stop_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.stop().await }
        });
        tokio::task::yield_now().await;
        start_gate.release.notify_one();

        assert!(start_task.await.unwrap().is_err());
        assert!(initial_peer_task.await.unwrap().is_err());
        stop_task.await.unwrap();
        assert!(instance.list_connectors().is_empty());
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalid_initial_peer_fails_during_activation() {
        let mut config = test_config("invalid-initial-peer");
        config.connectivity.initial_peers =
            vec!["unsupported://peer.example:1234".parse().unwrap()];
        let instance = build_instance(config).unwrap();

        instance.start().await.unwrap();
        instance.start_peer_center().await.unwrap();
        let error = instance.start_initial_peers().await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsupported core manual connector URL")
        );
        instance.stop().await;
    }

    #[test]
    fn core_instance_rejects_conflicting_p2p_policy() {
        let mut config = test_config("conflicting-p2p");
        config.connectivity.direct.disable_p2p = !config.peer.snapshot.flags.disable_p2p;

        let error = build_instance(config)
            .err()
            .expect("conflicting P2P policy should be rejected");
        assert!(error.to_string().contains("P2P policy"));
    }

    #[test]
    fn core_instance_rejects_mismatched_connectivity_identity() {
        let mut config = test_config("peer-network");
        config.connectivity.direct.network_name = "connector-network".to_owned();

        let error = build_instance(config)
            .err()
            .expect("mismatched network identity should be rejected");
        assert!(error.to_string().contains("does not match peer identity"));
    }

    #[tokio::test]
    async fn runtime_core_instances_keep_lifecycle_and_connectors_isolated() {
        let instance_a = build_instance(test_config("instance-a")).unwrap();
        let instance_b = build_instance(test_config("instance-b")).unwrap();
        let connector_a: Url = "tcp://127.0.0.1:21001".parse().unwrap();
        let connector_b: Url = "udp://127.0.0.1:21002".parse().unwrap();

        instance_a.add_connector(connector_a.clone()).unwrap();
        instance_b.add_connector(connector_b.clone()).unwrap();
        assert_eq!(instance_a.list_connectors()[0].url, connector_a);
        assert_eq!(instance_b.list_connectors()[0].url, connector_b);
        instance_a.clear_connectors();
        instance_b.clear_connectors();

        let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
        start_a.unwrap();
        start_b.unwrap();
        let (udp_a, udp_b) = tokio::join!(
            instance_a.start_udp_hole_punch(),
            instance_b.start_udp_hole_punch()
        );
        udp_a.unwrap();
        udp_b.unwrap();
        assert_eq!(instance_a.state(), CoreInstanceState::Running);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);

        instance_a.stop().await;
        assert_eq!(instance_a.state(), CoreInstanceState::Stopped);
        assert_eq!(instance_b.state(), CoreInstanceState::Running);
        instance_b.stop().await;
        assert_eq!(instance_b.state(), CoreInstanceState::Stopped);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stop_cancels_pending_listener_start() {
        let state = Arc::new(BlockingListenerState::default());
        let mut config = test_config("pending-listener");
        config.connectivity.listeners = Some(ListenerRuntimeConfig::new(
            vec!["unix:///tmp/easytier-pending-listener".parse().unwrap()],
            false,
            SocketContext::default(),
        ));
        let instance = build_with_engines_and_listener(
            config,
            WrappedTransportEngines::default(),
            Some(Arc::new(BlockingExternalListenerFactory {
                state: state.clone(),
            })),
        )
        .unwrap();
        let start_instance = instance.clone();
        let start_task =
            AbortOnDropHandle::new(tokio::spawn(async move { start_instance.start().await }));
        let start_result = tokio::time::timeout(Duration::from_secs(1), async {
            state.start_entered.notified().await;
            instance.stop().await;
            start_task.await.unwrap()
        })
        .await
        .expect("listener cancellation should complete promptly");

        assert!(start_result.is_err());
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(state.drop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn external_listener_uses_core_running_listener_registry() {
        let external_url: Url = "unix:///tmp/easytier-external-listener-test"
            .parse()
            .unwrap();
        let mut config = test_config("external-listener-registry");
        config.connectivity.listeners = Some(ListenerRuntimeConfig::new(
            vec![external_url.clone()],
            false,
            SocketContext::default(),
        ));
        let instance = build_with_engines_and_listener(
            config,
            WrappedTransportEngines::default(),
            Some(Arc::new(ReadyExternalListenerFactory)),
        )
        .unwrap();

        instance.start().await.unwrap();
        let running = instance.running_listeners();
        assert_eq!(running.len(), 2);
        assert!(running.iter().any(|url| url.scheme() == "ring"));
        assert!(running.contains(&external_url));
        assert_eq!(instance.node_snapshot().await.listeners, running);

        instance.stop().await;
        assert!(instance.running_listeners().is_empty());
    }
}

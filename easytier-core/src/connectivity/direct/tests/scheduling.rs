use std::{
    collections::HashMap,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use super::super::*;
use crate::{
    config::peers::PeerRuntimeSnapshot,
    connectivity::{NoLocalListeners, manual::ManualInterfaceAddrs, stun::StunInfoCollector},
    host::{
        packet::host_packet_channel,
        testkit::{TestDns, TestHost, TestTcpSocket, TestUdpSocket},
    },
    peers::peer_manager::PortablePeerManagerConfig,
    socket::tcp::{TcpConnectOptions, VirtualTcpSocketFactory},
    tunnel::ring::create_ring_tunnel_pair,
};

const INTERFACE_IP: Ipv4Addr = Ipv4Addr::new(192, 168, 20, 2);
const PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 2);
const FALLBACK_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 2);

#[derive(Clone, Copy)]
enum DialResult {
    Success,
    Failure,
    Pending,
}

struct DialHost {
    results: HashMap<IpAddr, DialResult>,
    attempts: tokio::sync::mpsc::UnboundedSender<(SocketAddr, tokio::time::Instant)>,
    active: Arc<AtomicUsize>,
}

struct ActiveDial(Arc<AtomicUsize>);

impl Drop for ActiveDial {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

#[async_trait]
impl VirtualTcpSocketFactory for DialHost {
    type Socket = TestTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        self.active.fetch_add(1, Ordering::Relaxed);
        let _active = ActiveDial(self.active.clone());
        self.attempts
            .send((options.remote_addr, tokio::time::Instant::now()))
            .unwrap();
        match self.results[&options.remote_addr.ip()] {
            DialResult::Success => Ok(TestTcpSocket(tokio::io::duplex(1024).0)),
            DialResult::Failure => anyhow::bail!("unreachable test address"),
            DialResult::Pending => std::future::pending().await,
        }
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for DialHost {
    type Socket = TestUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        TestHost::default().bind_udp(options).await
    }
}

#[async_trait]
impl ManualConnectorHost for DialHost {
    async fn local_addr_for_remote(
        &self,
        _remote_addr: SocketAddr,
        _context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        Ok("192.168.10.1:0".parse().unwrap())
    }

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
        Ok(ManualInterfaceAddrs {
            interface_ipv4s: Vec::new(),
            interface_ipv6s: Vec::new(),
            public_ipv6: None,
        })
    }
}

#[async_trait]
impl DirectConnectorHost for DialHost {
    async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
        GetIpListResponse::default()
    }

    fn mapped_listeners(&self) -> Vec<Url> {
        Vec::new()
    }

    fn is_local_ip(&self, _ip: &IpAddr) -> bool {
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

struct PeerProtocol {
    remote: Arc<PeerManagerCore>,
    tasks: Mutex<JoinSet<()>>,
}

#[async_trait]
impl ClientProtocolUpgrader<TestTcpSocket> for PeerProtocol {
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "tcp" | "ws")
    }

    async fn upgrade_client(
        &self,
        _connected: ConnectedTransport<TestTcpSocket>,
        _requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        let (client, server) = create_ring_tunnel_pair();
        let remote = self.remote.clone();
        self.tasks.lock().unwrap().spawn(async move {
            remote.add_tunnel_as_server(server).await.unwrap();
        });
        Ok(client)
    }
}

fn peer_manager() -> Arc<PeerManagerCore> {
    let mut runtime = PeerRuntimeSnapshot::default().runtime;
    runtime.core.peer_policy.encryption_required = false;
    let (sender, _receiver) = host_packet_channel();
    Arc::new(
        PeerManagerCore::new_portable_for_test(PortablePeerManagerConfig::new(runtime), sender)
            .unwrap(),
    )
}

type Attempts = tokio::sync::mpsc::UnboundedReceiver<(SocketAddr, tokio::time::Instant)>;

fn connector(
    interface_result: DialResult,
    public_result: DialResult,
) -> (
    Arc<DirectConnectorData<DialHost>>,
    Arc<PeerProtocol>,
    Attempts,
) {
    let (attempts, receiver) = tokio::sync::mpsc::unbounded_channel();
    let host = Arc::new(DialHost {
        results: [
            (INTERFACE_IP.into(), interface_result),
            (PUBLIC_IP.into(), public_result),
            (FALLBACK_IP.into(), DialResult::Success),
        ]
        .into_iter()
        .collect(),
        attempts,
        active: Arc::new(AtomicUsize::new(0)),
    });
    let dns = Arc::new(TestDns);
    let stun = Arc::new(StunInfoCollector::new(
        host.clone(),
        dns.clone(),
        SocketContext::default(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    let protocol = Arc::new(PeerProtocol {
        remote: peer_manager(),
        tasks: Mutex::new(JoinSet::new()),
    });
    let data = Arc::new(DirectConnectorData {
        peer_manager: peer_manager(),
        host,
        protected_tcp_ports: Arc::new(ProtectedTcpPortRegistry::default()),
        stun,
        running_listeners: Arc::new(NoLocalListeners),
        dns,
        protocol: protocol.clone(),
        options: DirectConnectorOptions::default(),
        listener_blacklist: ExpiringSet::default(),
        peer_blacklist: ExpiringSet::default(),
    });
    (data, protocol, receiver)
}

fn ip_list() -> GetIpListResponse {
    GetIpListResponse {
        interface_ipv4s: vec![INTERFACE_IP.into()],
        public_ipv4: Some(PUBLIC_IP.into()),
        listeners: vec![Url::parse("tcp://0.0.0.0:11010").unwrap().into()],
        ..Default::default()
    }
}

fn start(
    data: Arc<DirectConnectorData<DialHost>>,
    peer_id: PeerId,
) -> tokio::task::JoinHandle<anyhow::Result<()>> {
    tokio::spawn(async move {
        data.try_direct_connect_with_ip_list(peer_id, ip_list())
            .await
    })
}

async fn stop(data: &DirectConnectorData<DialHost>, protocol: &PeerProtocol) {
    data.peer_manager.clear_resources().await;
    protocol.remote.clear_resources().await;
}

#[tokio::test(start_paused = true)]
async fn interface_authentication_stops_deferred_dialing() {
    for expected in [INTERFACE_IP, PUBLIC_IP] {
        for wildcard_listener in [true, false] {
            let (data, protocol, mut attempts) =
                connector(DialResult::Success, DialResult::Success);
            let peer_id = protocol.remote.my_peer_id();
            let mut list = ip_list();
            list.interface_ipv4s = vec![expected.into()];
            list.public_ipv4 = Some(
                if expected == INTERFACE_IP {
                    PUBLIC_IP
                } else {
                    INTERFACE_IP
                }
                .into(),
            );
            if !wildcard_listener {
                list.listeners = [INTERFACE_IP, PUBLIC_IP]
                    .into_iter()
                    .map(|ip| Url::parse(&format!("tcp://{ip}:11010")).unwrap().into())
                    .collect();
            }
            data.try_direct_connect_with_ip_list(peer_id, list)
                .await
                .unwrap();

            assert!(data.peer_manager.has_directly_connected_conn(peer_id));
            assert_eq!(attempts.try_recv().unwrap().0.ip(), IpAddr::V4(expected));
            assert!(attempts.try_recv().is_err());
            stop(&data, &protocol).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cancelling_the_attempt_cancels_deferred_and_active_dials() {
    let (data, protocol, mut attempts) = connector(DialResult::Pending, DialResult::Pending);
    let task = start(data.clone(), protocol.remote.my_peer_id());
    assert_eq!(
        attempts.recv().await.unwrap().0.ip(),
        IpAddr::V4(INTERFACE_IP)
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    tokio::time::advance(DIRECT_CONNECT_FALLBACK_DELAY).await;
    tokio::task::yield_now().await;
    assert!(attempts.try_recv().is_err());
    assert_eq!(data.host.active.load(Ordering::Relaxed), 0);
    stop(&data, &protocol).await;
}

#[tokio::test(start_paused = true)]
async fn slow_dns_does_not_hold_numeric_dials_or_their_fallback() {
    #[derive(Default)]
    struct PendingDns {
        queries: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl DnsResolver for PendingDns {
        async fn resolve(&self, query: crate::host::dns::DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            self.queries.lock().unwrap().push(query.host);
            std::future::pending().await
        }
    }

    for advertise_interface in [true, false] {
        for wildcard_listener in [true, false] {
            let (mut data, protocol, mut attempts) =
                connector(DialResult::Pending, DialResult::Pending);
            let dns = Arc::new(PendingDns::default());
            Arc::get_mut(&mut data).unwrap().dns = dns.clone();
            let mut list = ip_list();
            if !wildcard_listener {
                list.listeners = [INTERFACE_IP, PUBLIC_IP]
                    .into_iter()
                    .map(|ip| Url::parse(&format!("tcp://{ip}:11010")).unwrap().into())
                    .collect();
            }
            if !advertise_interface {
                list.interface_ipv4s.clear();
                if wildcard_listener {
                    list.listeners.push(
                        Url::parse(&format!("tcp://{INTERFACE_IP}:11010"))
                            .unwrap()
                            .into(),
                    );
                }
            }
            list.listeners
                .push(Url::parse("tcp://pending.example:11010").unwrap().into());
            let peer_id = protocol.remote.my_peer_id();
            let started = tokio::time::Instant::now();
            let attempt_data = data.clone();
            let task = tokio::spawn(async move {
                attempt_data
                    .try_direct_connect_with_ip_list(peer_id, list)
                    .await
            });
            let (first, at) = tokio::time::timeout(Duration::from_millis(100), attempts.recv())
                .await
                .expect("literal listener must not wait for unrelated DNS")
                .unwrap();
            assert_eq!(at, started);
            let first = (first.ip(), at);
            let (second, at) = tokio::time::timeout(Duration::from_secs(1), attempts.recv())
                .await
                .expect("numeric fallback must not wait for DNS")
                .unwrap();
            let expected_delay = if advertise_interface {
                DIRECT_CONNECT_FALLBACK_DELAY
            } else {
                Duration::ZERO
            };
            let observed = [first, (second.ip(), at)];
            assert!(observed.contains(&(IpAddr::V4(INTERFACE_IP), started)));
            assert!(observed.contains(&(IpAddr::V4(PUBLIC_IP), started + expected_delay)));
            assert_eq!(dns.queries.lock().unwrap().as_slice(), ["pending.example"]);
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            stop(&data, &protocol).await;
        }
    }
}

#[tokio::test(start_paused = true)]
async fn failed_or_pending_interface_dial_does_not_hold_back_fallback() {
    for interface_result in [DialResult::Failure, DialResult::Pending] {
        let (data, protocol, mut attempts) = connector(interface_result, DialResult::Success);
        let started = tokio::time::Instant::now();
        let task = start(data.clone(), protocol.remote.my_peer_id());
        assert_eq!(
            attempts.recv().await.unwrap().0.ip(),
            IpAddr::V4(INTERFACE_IP)
        );
        let (fallback, at) = attempts.recv().await.unwrap();
        assert_eq!(fallback.ip(), IpAddr::V4(PUBLIC_IP));
        assert_eq!(at - started, DIRECT_CONNECT_FALLBACK_DELAY);
        task.await.unwrap().unwrap();
        assert!(
            data.peer_manager
                .has_directly_connected_conn(protocol.remote.my_peer_id())
        );
        stop(&data, &protocol).await;
    }
}

#[tokio::test(start_paused = true)]
async fn interface_candidates_start_concurrently_before_fallback() {
    let (data, protocol, mut attempts) = connector(DialResult::Pending, DialResult::Pending);
    let mut list = ip_list();
    list.interface_ipv4s.push(PUBLIC_IP.into());
    list.public_ipv4 = Some(FALLBACK_IP.into());
    let peer_id = protocol.remote.my_peer_id();
    let attempt_data = data.clone();
    let started = tokio::time::Instant::now();
    let task = tokio::spawn(async move {
        attempt_data
            .try_direct_connect_with_ip_list(peer_id, list)
            .await
    });
    let first = attempts.recv().await.unwrap();
    let second = attempts.recv().await.unwrap();
    assert_ne!(first.0.ip(), second.0.ip());
    assert_eq!(first.1, started);
    assert_eq!(second.1, started);
    let (fallback, at) = attempts.recv().await.unwrap();
    assert_eq!(fallback.ip(), IpAddr::V4(FALLBACK_IP));
    assert_eq!(at - started, DIRECT_CONNECT_FALLBACK_DELAY);
    task.await.unwrap().unwrap();
    stop(&data, &protocol).await;
}

#[tokio::test(start_paused = true)]
async fn no_interface_candidate_keeps_concurrent_dialing() {
    for advertise_interface in [true, false] {
        let (data, protocol, mut attempts) = connector(DialResult::Pending, DialResult::Pending);
        let mut list = ip_list();
        list.listeners = if advertise_interface {
            // An explicit listener must not expand to other interface addresses.
            [11010, 11011]
                .into_iter()
                .map(|port| {
                    Url::parse(&format!("tcp://{PUBLIC_IP}:{port}"))
                        .unwrap()
                        .into()
                })
                .collect()
        } else {
            list.interface_ipv4s.clear();
            [INTERFACE_IP, PUBLIC_IP]
                .into_iter()
                .map(|ip| Url::parse(&format!("tcp://{ip}:11010")).unwrap().into())
                .collect()
        };
        let started = tokio::time::Instant::now();
        let peer_id = protocol.remote.my_peer_id();
        let attempt_data = data.clone();
        let task = tokio::spawn(async move {
            attempt_data
                .try_direct_connect_with_ip_list(peer_id, list)
                .await
        });
        let first = attempts.recv().await.unwrap();
        let second = attempts.recv().await.unwrap();
        assert_ne!(first.0, second.0);
        if advertise_interface {
            assert_eq!(first.0.ip(), IpAddr::V4(PUBLIC_IP));
            assert_eq!(second.0.ip(), IpAddr::V4(PUBLIC_IP));
        }
        assert_eq!(first.1, started);
        assert_eq!(second.1, started);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        tokio::task::yield_now().await;
        assert_eq!(data.host.active.load(Ordering::Relaxed), 0);
        stop(&data, &protocol).await;
    }
}

#[tokio::test(start_paused = true)]
async fn blacklisted_interface_candidate_does_not_delay_fallback() {
    let (data, protocol, mut attempts) = connector(DialResult::Pending, DialResult::Success);
    data.listener_blacklist.insert(
        ListenerBlacklistKey(
            protocol.remote.my_peer_id(),
            format!("tcp://{INTERFACE_IP}:11010"),
        ),
        DIRECT_CONNECTOR_BLACKLIST_TIMEOUT,
    );
    let started = tokio::time::Instant::now();
    start(data.clone(), protocol.remote.my_peer_id())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        attempts.try_recv().unwrap(),
        (SocketAddr::new(PUBLIC_IP.into(), 11010), started)
    );
    assert!(attempts.try_recv().is_err());
    stop(&data, &protocol).await;
}

#[tokio::test(start_paused = true)]
async fn existing_or_new_ordinary_connection_prevents_fallback() {
    for connect_before_attempt in [true, false] {
        let (data, protocol, mut attempts) = connector(DialResult::Pending, DialResult::Pending);
        let peer_id = protocol.remote.my_peer_id();
        let task = if connect_before_attempt {
            None
        } else {
            let task = start(data.clone(), peer_id);
            assert_eq!(
                attempts.recv().await.unwrap().0.ip(),
                IpAddr::V4(INTERFACE_IP)
            );
            Some(task)
        };
        let (client, server) = create_ring_tunnel_pair();
        let (client_result, server_result) = tokio::join!(
            data.peer_manager.add_client_tunnel(client),
            protocol.remote.add_tunnel_as_server(server),
        );
        client_result.unwrap();
        server_result.unwrap();
        assert!(data.peer_manager.has_directly_connected_conn(peer_id));
        if let Some(task) = task {
            tokio::time::advance(DIRECT_CONNECT_FALLBACK_DELAY).await;
            tokio::task::yield_now().await;
            assert!(attempts.try_recv().is_err());
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
            tokio::task::yield_now().await;
            assert_eq!(data.host.active.load(Ordering::Relaxed), 0);
        } else {
            start(data.clone(), peer_id).await.unwrap().unwrap();
            assert!(attempts.try_recv().is_err());
        }
        stop(&data, &protocol).await;
    }
}

#[tokio::test(start_paused = true)]
async fn interface_priority_stays_within_the_default_protocol_group() {
    for default_protocol in ["tcp", "ws"] {
        let (mut data, protocol, mut attempts) =
            connector(DialResult::Success, DialResult::Success);
        Arc::get_mut(&mut data).unwrap().options.default_protocol = default_protocol.to_owned();
        let mut list = ip_list();
        list.listeners = [
            format!("tcp://{PUBLIC_IP}:11010"),
            "ws://0.0.0.0:11011".to_owned(),
        ]
        .into_iter()
        .map(|url| Url::parse(&url).unwrap().into())
        .collect();
        data.try_direct_connect_with_ip_list(protocol.remote.my_peer_id(), list)
            .await
            .unwrap();
        let expected = if default_protocol == "tcp" {
            PUBLIC_IP
        } else {
            INTERFACE_IP
        };
        assert_eq!(attempts.try_recv().unwrap().0.ip(), IpAddr::V4(expected));
        assert!(attempts.try_recv().is_err());
        stop(&data, &protocol).await;
    }
}

//! Core-owned UDP hole-punch socket/session runtime.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Weak},
};

use anyhow::Context as _;
use async_trait::async_trait;
use quanta::Instant;

use crate::{
    connectivity::{
        direct::DirectConnectorHost,
        hole_punch::port_mapping::{
            UdpPortMappingEventSink, UdpPortMappingPlatform, start_udp_port_mapping,
        },
        protocol::ClientProtocolUpgrader,
        stun::{StunInfoProvider, StunSocketMapper},
    },
    peers::peer_manager::PeerManagerCore,
    proto::peer_rpc::UdpHolePunchRpcServer,
    socket::{
        IpVersion, SocketContext,
        tcp::VirtualTcpSocketFactory,
        udp::{
            UdpBindOptions, UdpSessionLayer, UdpSessionSocket, UdpSessionStunResponder,
            VirtualUdpSocket, VirtualUdpSocketFactory,
        },
    },
};

use super::{
    ProtocolUdpHolePunchTransportSink, UdpHolePunchConnector, UdpHolePunchPeerSource,
    UdpHolePunchRuntime, UdpPunchAcceptor, UdpPunchCandidate, UdpPunchConnCounter,
    UdpPunchListener, UdpPunchSocket, UdpResolvedPublicAddr, UdpSymPunchLock,
    rpc::{PeerRpcUdpHolePunchSignaling, UdpHolePunchRpcEndpoint},
};

#[async_trait]
impl UdpHolePunchPeerSource for PeerManagerCore {
    fn local_peer_id(&self) -> crate::config::PeerId {
        PeerManagerCore::my_peer_id(self)
    }

    fn network_name(&self) -> &str {
        PeerManagerCore::network_name(self)
    }

    fn p2p_policy_flags(&self) -> crate::config::P2pPolicyFlags {
        PeerManagerCore::p2p_policy_flags(self)
    }

    async fn candidates(&self) -> Vec<UdpPunchCandidate> {
        let now = Instant::now();
        let peer_map = self.get_peer_map();
        self.list_route_snapshots()
            .await
            .into_iter()
            .filter_map(|route| {
                let udp_nat_type = route
                    .stun_info
                    .as_ref()
                    .map(|info| info.udp_nat_type)
                    .unwrap_or_default();
                let Ok(udp_nat_type) = crate::proto::common::NatType::try_from(udp_nat_type) else {
                    return None;
                };
                Some(UdpPunchCandidate {
                    peer_id: route.peer_id,
                    udp_nat_type,
                    feature_flag: route.feature_flag,
                    has_direct_connection: peer_map.has_peer(route.peer_id),
                    has_recent_traffic: self.has_recent_traffic(route.peer_id, now),
                })
            })
            .collect()
    }
}

async fn resolve_public_addr_with_policy<S>(
    stun: &dyn StunSocketMapper<S>,
    platform: Option<Arc<dyn UdpPortMappingPlatform>>,
    events: Arc<dyn UdpPortMappingEventSink>,
    socket: Arc<S>,
    local_listener: &url::Url,
    disable_upnp: bool,
) -> anyhow::Result<UdpResolvedPublicAddr>
where
    S: VirtualUdpSocket + 'static,
{
    let port_mapping_lease = if disable_upnp {
        None
    } else if let Some(platform) = platform {
        match start_udp_port_mapping(platform, events, local_listener).await {
            Ok(lease) => lease,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    %local_listener,
                    "failed to establish udp port mapping, fallback to stun-only public addr resolution"
                );
                None
            }
        }
    } else {
        None
    };

    let mapped_addr = stun
        .get_udp_port_mapping_with_socket(socket)
        .await
        .map_err(anyhow::Error::from)
        .with_context(|| format!("resolve udp public addr for {local_listener}"))?;
    if let Some(lease) = &port_mapping_lease {
        lease.public_addr_resolved(mapped_addr);
    } else {
        tracing::debug!(
            %local_listener,
            stun_mapped_addr = %mapped_addr,
            "udp public addr resolved without port mapping"
        );
    }

    Ok(UdpResolvedPublicAddr {
        mapped_addr,
        port_mapping_lease,
    })
}

fn managed_local_addr_error(
    local_addr: SocketAddr,
    is_local_virtual_ipv4: bool,
    is_easytier_managed_ipv6: bool,
) -> Option<&'static str> {
    match local_addr.ip() {
        IpAddr::V4(_) if is_local_virtual_ipv4 => Some("local address is virtual ipv4"),
        IpAddr::V6(_) if is_easytier_managed_ipv6 => Some("local address is easytier-managed ipv6"),
        _ => None,
    }
}

type HostUdpSocket<H> = <H as VirtualUdpSocketFactory>::Socket;
type HostTcpSocket<H> = <H as VirtualTcpSocketFactory>::Socket;
type CoreUdpSessionLayer<H> = UdpSessionLayer<HostUdpSocket<H>, H>;
type CoreUdpHolePunchTransportSink<H> =
    ProtocolUdpHolePunchTransportSink<HostTcpSocket<H>, PeerManagerCore>;
type CoreUdpHolePunchConnector<H> = UdpHolePunchConnector<
    PeerManagerCore,
    PeerRpcUdpHolePunchSignaling,
    CoreUdpHolePunchTransportSink<H>,
    CoreUdpHolePunchRuntime<H>,
>;
type CoreUdpHolePunchEndpoint<H> =
    UdpHolePunchRpcEndpoint<CoreUdpHolePunchRuntime<H>, CoreUdpHolePunchTransportSink<H>>;

pub(crate) struct CoreUdpHolePunchService<H>
where
    H: DirectConnectorHost,
{
    server: Arc<CoreUdpHolePunchEndpoint<H>>,
    client: CoreUdpHolePunchConnector<H>,
    peer_manager: Arc<PeerManagerCore>,
}

impl<H> CoreUdpHolePunchService<H>
where
    H: DirectConnectorHost + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        stun: Arc<dyn StunSocketMapper<HostUdpSocket<H>>>,
        platform: Option<Arc<dyn UdpPortMappingPlatform>>,
        events: Arc<dyn UdpPortMappingEventSink>,
        socket_context: SocketContext,
        protocol: Arc<dyn ClientProtocolUpgrader<HostTcpSocket<H>>>,
    ) -> Self {
        let stun_mapper = stun.clone();
        let stun_info: Arc<dyn StunInfoProvider> = stun;
        let transport_sink = Arc::new(ProtocolUdpHolePunchTransportSink::new(
            protocol,
            peer_manager.clone(),
        ));
        let runtime = Arc::new(CoreUdpHolePunchRuntime::new(
            host,
            peer_manager.clone(),
            stun_mapper,
            platform,
            events,
            socket_context,
        ));
        let sym_punch_lock = UdpSymPunchLock::default();
        let client = UdpHolePunchConnector::new(
            peer_manager.clone(),
            Arc::new(PeerRpcUdpHolePunchSignaling::new(peer_manager.clone())),
            transport_sink.clone(),
            runtime.clone(),
            stun_info.clone(),
            sym_punch_lock.clone(),
            Some(peer_manager.p2p_demand_notify()),
        );

        Self {
            server: UdpHolePunchRpcEndpoint::new(
                stun_info,
                transport_sink,
                sym_punch_lock,
                runtime,
            ),
            client,
            peer_manager,
        }
    }

    pub(crate) async fn start(&self) -> anyhow::Result<()> {
        if self
            .peer_manager
            .p2p_policy_flags()
            .disable_udp_hole_punching
        {
            return Ok(());
        }

        self.server.start().await;
        self.peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                UdpHolePunchRpcServer::new(Arc::downgrade(&self.server)),
                self.peer_manager.network_name(),
            );
        self.client.run_as_client();
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        self.client.stop().await;
        self.server.begin_stop();
        self.peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                UdpHolePunchRpcServer::new(Arc::downgrade(&self.server)),
                self.peer_manager.network_name(),
            );
        self.server.stop().await;
    }
}

struct CoreUdpPunchAcceptor<H>
where
    H: VirtualUdpSocketFactory,
    HostUdpSocket<H>: VirtualUdpSocket,
{
    layer: Arc<CoreUdpSessionLayer<H>>,
}

#[async_trait]
impl<H> UdpPunchAcceptor for CoreUdpPunchAcceptor<H>
where
    H: VirtualUdpSocketFactory + UdpSessionStunResponder<HostUdpSocket<H>> + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    async fn accept(&mut self) -> anyhow::Result<UdpPunchSocket> {
        let session = self.layer.accept().await?;
        let remote_addr = session.peer_addr()?;
        Ok(UdpPunchSocket::new(
            session,
            remote_addr,
            self.layer.clone(),
        ))
    }
}

struct CoreUdpPunchConnCounter<H>
where
    H: VirtualUdpSocketFactory,
    HostUdpSocket<H>: VirtualUdpSocket,
{
    layer: Weak<CoreUdpSessionLayer<H>>,
}

impl<H> UdpPunchConnCounter for CoreUdpPunchConnCounter<H>
where
    H: VirtualUdpSocketFactory + UdpSessionStunResponder<HostUdpSocket<H>> + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    fn get(&self) -> Option<u32> {
        Some(
            self.layer
                .upgrade()
                .map(|layer| layer.active_session_count() as u32)
                .unwrap_or(0),
        )
    }
}

pub struct CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost,
{
    host: Arc<H>,
    peer_manager: Arc<PeerManagerCore>,
    stun: Arc<dyn StunSocketMapper<HostUdpSocket<H>>>,
    platform: Option<Arc<dyn UdpPortMappingPlatform>>,
    events: Arc<dyn UdpPortMappingEventSink>,
    socket_context: SocketContext,
}

impl<H> CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    pub fn new(
        host: Arc<H>,
        peer_manager: Arc<PeerManagerCore>,
        stun: Arc<dyn StunSocketMapper<HostUdpSocket<H>>>,
        platform: Option<Arc<dyn UdpPortMappingPlatform>>,
        events: Arc<dyn UdpPortMappingEventSink>,
        socket_context: SocketContext,
    ) -> Self {
        Self {
            host,
            peer_manager,
            stun,
            platform,
            events,
            socket_context,
        }
    }

    fn session_layer(&self, socket: Arc<HostUdpSocket<H>>) -> Arc<CoreUdpSessionLayer<H>> {
        Arc::new(UdpSessionLayer::new_with_stun_responder(
            socket,
            self.host.clone(),
        ))
    }

    async fn create_listener_with_mapping(
        &self,
        resolve_public_addr: bool,
        port: Option<u16>,
    ) -> anyhow::Result<UdpPunchListener<HostUdpSocket<H>>> {
        let bind = match port {
            Some(port) => UdpBindOptions::hole_punch_candidate().with_local_addr(Some(
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port)),
            )),
            None => UdpBindOptions::hole_punch_control(),
        }
        .with_context(self.socket_context.clone().with_ip_version(IpVersion::V4));
        let socket = self.host.bind_udp(bind).await?;
        let local_port = socket.local_addr()?.port();
        let resolved = if resolve_public_addr {
            self.resolve_public_addr(socket.clone()).await?
        } else {
            UdpResolvedPublicAddr {
                mapped_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port)),
                port_mapping_lease: None,
            }
        };

        let layer = self.session_layer(socket.clone());
        let conn_counter = Arc::new(CoreUdpPunchConnCounter {
            layer: Arc::downgrade(&layer),
        });
        let acceptor = Box::new(CoreUdpPunchAcceptor { layer });

        Ok(UdpPunchListener {
            socket,
            mapped_addr: resolved.mapped_addr,
            conn_counter,
            acceptor,
            port_mapping_lease: resolved.port_mapping_lease,
        })
    }

    async fn resolve_public_addr(
        &self,
        socket: Arc<HostUdpSocket<H>>,
    ) -> anyhow::Result<UdpResolvedPublicAddr> {
        let local_port = socket.local_addr()?.port();
        let local_listener: url::Url = format!("udp://0.0.0.0:{local_port}").parse()?;
        resolve_public_addr_with_policy(
            self.stun.as_ref(),
            self.platform.clone(),
            self.events.clone(),
            socket,
            &local_listener,
            self.peer_manager.p2p_policy_flags().disable_upnp,
        )
        .await
    }

    async fn validate_socket_route(
        &self,
        context: SocketContext,
        remote_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        let local_addr = self
            .host
            .local_addr_for_remote(remote_addr, context)
            .await?;
        let is_local_virtual_ipv4 = match local_addr.ip() {
            IpAddr::V4(ip) => self.peer_manager.is_local_virtual_ip(&IpAddr::V4(ip)),
            IpAddr::V6(_) => false,
        };
        let is_easytier_managed_ipv6 = match local_addr.ip() {
            IpAddr::V4(_) => false,
            IpAddr::V6(ip) => self.peer_manager.is_easytier_managed_ipv6(&ip).await,
        };
        if let Some(error) =
            managed_local_addr_error(local_addr, is_local_virtual_ipv4, is_easytier_managed_ipv6)
        {
            anyhow::bail!(error);
        }
        Ok(())
    }
}

#[async_trait]
impl<H> UdpHolePunchRuntime for CoreUdpHolePunchRuntime<H>
where
    H: DirectConnectorHost + Send + Sync + 'static,
    HostUdpSocket<H>: VirtualUdpSocket + 'static,
{
    type Socket = HostUdpSocket<H>;

    fn socket_context(&self) -> SocketContext {
        self.socket_context.clone()
    }

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.host.bind_udp(options).await
    }

    async fn bind_direct_connect_udp(&self) -> anyhow::Result<Arc<Self::Socket>> {
        self.host
            .bind_udp(
                UdpBindOptions::hole_punch_candidate()
                    .with_context(self.socket_context.clone().with_ip_version(IpVersion::V4)),
            )
            .await
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<UdpResolvedPublicAddr> {
        self.resolve_public_addr(socket).await
    }

    async fn create_listener(
        &self,
        _prefer_port_mapping: bool,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
        self.create_listener_with_mapping(true, None).await
    }

    async fn create_port_bound_listener(
        &self,
        port: u16,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
        self.create_listener_with_mapping(false, Some(port)).await
    }

    async fn connect_with_socket(
        &self,
        socket: Arc<Self::Socket>,
        remote: SocketAddr,
    ) -> anyhow::Result<UdpPunchSocket> {
        self.validate_socket_route(socket.socket_context(), remote)
            .await?;
        let layer = self.session_layer(socket);
        let session = layer.connect(remote).await?;
        if session.peer_addr()? != remote {
            tracing::debug!(
                recv_addr = ?session.peer_addr()?,
                ?remote,
                "udp connect addr not match"
            );
        }
        Ok(UdpPunchSocket::new(session, remote, layer))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{Ipv6Addr, SocketAddrV6},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use crate::{connectivity::stun::StunInfoProvider, proto::common::StunInfo};

    use super::*;

    #[derive(Debug)]
    struct MockSocket {
        local_addr: SocketAddr,
    }

    #[async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    struct MockStun {
        mapped_addr: SocketAddr,
        fail: bool,
        calls: AtomicUsize,
    }

    impl MockStun {
        fn succeeds_with(mapped_addr: SocketAddr) -> Self {
            Self {
                mapped_addr,
                fail: false,
                calls: AtomicUsize::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                mapped_addr: "0.0.0.0:0".parse().unwrap(),
                fail: true,
                calls: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl StunInfoProvider for MockStun {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo::default()
        }

        async fn get_udp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            Ok(self.mapped_addr)
        }

        async fn get_tcp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            Ok(self.mapped_addr)
        }

        fn update_stun_info(&self) {}
    }

    #[async_trait]
    impl StunSocketMapper<MockSocket> for MockStun {
        async fn get_udp_port_mapping_with_socket(
            &self,
            _socket: Arc<MockSocket>,
        ) -> anyhow::Result<SocketAddr> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("mock STUN failure");
            }
            Ok(self.mapped_addr)
        }
    }

    #[derive(Debug, Default)]
    struct LeaseState {
        drops: AtomicUsize,
    }

    #[derive(Default)]
    struct MockEvents {
        established: Mutex<Vec<crate::connectivity::hole_punch::port_mapping::UdpPortMappingEstablished>>,
    }

    impl UdpPortMappingEventSink for MockEvents {
        fn publish_udp_port_mapping_established(
            &self,
            event: crate::connectivity::hole_punch::port_mapping::UdpPortMappingEstablished,
        ) {
            self.established.lock().unwrap().push(event);
        }
    }

    #[derive(Debug)]
    struct MockMapping {
        state: Arc<LeaseState>,
        backend: crate::connectivity::hole_punch::port_mapping::UdpPortMappingBackend,
    }

    #[async_trait]
    impl crate::connectivity::hole_punch::port_mapping::ActiveUdpPortMapping for MockMapping {
        fn backend(&self) -> crate::connectivity::hole_punch::port_mapping::UdpPortMappingBackend {
            self.backend
        }

        fn local_addr(&self) -> SocketAddr {
            "192.168.1.5:30123".parse().unwrap()
        }

        fn gateway_external_port(&self) -> u16 {
            40123
        }

        async fn renew(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn remove(&self) -> anyhow::Result<()> {
            self.state.drops.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct MockPlatform {
        calls: AtomicUsize,
        fail: bool,
        lease_state: Arc<LeaseState>,
    }

    impl MockPlatform {
        fn failing() -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: true,
                lease_state: Arc::default(),
            }
        }

        fn with_lease(lease_state: Arc<LeaseState>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                fail: false,
                lease_state,
            }
        }
    }

    #[async_trait]
    impl UdpPortMappingPlatform for MockPlatform {
        async fn establish_udp_port_mapping(
            &self,
            backend: crate::connectivity::hole_punch::port_mapping::UdpPortMappingBackend,
            _local_listener: &url::Url,
        ) -> Result<
            Box<dyn crate::connectivity::hole_punch::port_mapping::ActiveUdpPortMapping>,
            crate::connectivity::hole_punch::port_mapping::UdpPortMappingAttemptError,
        > {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail {
                return Err(
                    crate::connectivity::hole_punch::port_mapping::UdpPortMappingAttemptError::establishment(
                        anyhow::anyhow!("mock port-mapping failure"),
                    ),
                );
            }
            Ok(Box::new(MockMapping {
                state: self.lease_state.clone(),
                backend,
            }))
        }
    }

    fn socket() -> Arc<MockSocket> {
        Arc::new(MockSocket {
            local_addr: "0.0.0.0:30123".parse().unwrap(),
        })
    }

    fn listener_url() -> url::Url {
        "udp://0.0.0.0:30123".parse().unwrap()
    }

    #[tokio::test]
    async fn port_mapping_failure_falls_back_to_stun() {
        let mapped_addr = "198.51.100.8:40123".parse().unwrap();
        let stun = MockStun::succeeds_with(mapped_addr);
        let platform = Arc::new(MockPlatform::failing());

        let resolved = resolve_public_addr_with_policy(
            &stun,
            Some(platform.clone()),
            Arc::new(()),
            socket(),
            &listener_url(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(resolved.mapped_addr, mapped_addr);
        assert!(resolved.port_mapping_lease.is_none());
        assert_eq!(platform.calls.load(Ordering::SeqCst), 2);
        assert_eq!(stun.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn stun_failure_releases_mapping_without_notification() {
        let lease_state = Arc::new(LeaseState::default());
        let platform = Arc::new(MockPlatform::with_lease(lease_state.clone()));
        let events = Arc::new(MockEvents::default());

        let result = resolve_public_addr_with_policy(
            &MockStun::failing(),
            Some(platform),
            events.clone(),
            socket(),
            &listener_url(),
            false,
        )
        .await;

        assert!(result.is_err());
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while lease_state.drops.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(lease_state.drops.load(Ordering::SeqCst), 1);
        assert!(events.established.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn disable_upnp_is_applied_per_resolution() {
        let mapped_addr = "198.51.100.9:40124".parse().unwrap();
        let stun = MockStun::succeeds_with(mapped_addr);
        let lease_state = Arc::new(LeaseState::default());
        let platform = Arc::new(MockPlatform::with_lease(lease_state));

        let disabled = resolve_public_addr_with_policy(
            &stun,
            Some(platform.clone()),
            Arc::new(()),
            socket(),
            &listener_url(),
            true,
        )
        .await
        .unwrap();
        assert!(disabled.port_mapping_lease.is_none());
        assert_eq!(platform.calls.load(Ordering::SeqCst), 0);

        let enabled = resolve_public_addr_with_policy(
            &stun,
            Some(platform.clone()),
            Arc::new(()),
            socket(),
            &listener_url(),
            false,
        )
        .await
        .unwrap();
        assert!(enabled.port_mapping_lease.is_some());
        assert_eq!(platform.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn successful_mapping_is_notified_and_held_with_result() {
        let mapped_addr = "198.51.100.10:40125".parse().unwrap();
        let lease_state = Arc::new(LeaseState::default());
        let platform = Arc::new(MockPlatform::with_lease(lease_state.clone()));
        let events = Arc::new(MockEvents::default());

        let resolved = resolve_public_addr_with_policy(
            &MockStun::succeeds_with(mapped_addr),
            Some(platform),
            events.clone(),
            socket(),
            &listener_url(),
            false,
        )
        .await
        .unwrap();

        assert_eq!(
            *events.established.lock().unwrap(),
            vec![
                crate::connectivity::hole_punch::port_mapping::UdpPortMappingEstablished {
                    local_listener: listener_url(),
                    mapped_listener: "udp://198.51.100.10:40125".parse().unwrap(),
                    backend: crate::connectivity::hole_punch::port_mapping::UdpPortMappingBackend::Igd,
                }
            ]
        );
        assert_eq!(lease_state.drops.load(Ordering::SeqCst), 0);
        drop(resolved);
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while lease_state.drops.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(lease_state.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn managed_local_addresses_are_rejected() {
        let virtual_ipv4 = "10.144.0.2:1234".parse().unwrap();
        assert_eq!(
            managed_local_addr_error(virtual_ipv4, true, false),
            Some("local address is virtual ipv4")
        );
        assert_eq!(managed_local_addr_error(virtual_ipv4, false, false), None);

        let managed_ipv6 = SocketAddr::V6(SocketAddrV6::new(
            "fd00::1".parse::<Ipv6Addr>().unwrap(),
            1234,
            0,
            0,
        ));
        assert_eq!(
            managed_local_addr_error(managed_ipv6, false, true),
            Some("local address is easytier-managed ipv6")
        );
        assert_eq!(managed_local_addr_error(managed_ipv6, false, false), None);
    }
}

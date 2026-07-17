use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;

use super::super::port_mapping::UdpPortMappingLease;

use crate::{
    config::P2pPolicyFlags,
    connectivity::{
        protocol::ClientProtocolUpgrader,
        transport::{ConnectedTransport, ConnectedUdpSession},
    },
    socket::{
        SocketContext,
        udp::{UdpBindOptions, UdpSession, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
    tunnel::Tunnel,
};

#[async_trait]
pub trait UdpPunchAcceptor: Send {
    async fn accept(&mut self) -> anyhow::Result<UdpPunchSocket>;
}

pub struct UdpPunchSocket {
    session: UdpSession,
    requested_remote_addr: SocketAddr,
    lifetime_guard: Box<dyn Send + Sync>,
}

impl UdpPunchSocket {
    pub fn new<G>(session: UdpSession, requested_remote_addr: SocketAddr, lifetime_guard: G) -> Self
    where
        G: Send + Sync + 'static,
    {
        Self {
            session,
            requested_remote_addr,
            lifetime_guard: Box::new(lifetime_guard),
        }
    }

    pub(crate) fn into_connected(self) -> (ConnectedUdpSession, url::Url) {
        (
            ConnectedUdpSession::new(self.session, self.lifetime_guard),
            udp_url(self.requested_remote_addr),
        )
    }
}

impl std::fmt::Debug for UdpPunchSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpPunchSocket")
            .field("session", &self.session)
            .field("requested_remote_addr", &self.requested_remote_addr)
            .finish_non_exhaustive()
    }
}

fn udp_url(addr: SocketAddr) -> url::Url {
    let mut url = url::Url::parse("udp://0.0.0.0").expect("static UDP URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("UDP URL should accept a port");
    url
}

pub trait UdpPunchConnCounter: Send + Sync {
    fn get(&self) -> Option<u32>;
}

pub struct UdpPunchListener<S> {
    pub socket: Arc<S>,
    pub mapped_addr: SocketAddr,
    pub conn_counter: Arc<dyn UdpPunchConnCounter>,
    pub acceptor: Box<dyn UdpPunchAcceptor>,
    pub port_mapping_lease: Option<Box<dyn UdpPortMappingLease>>,
}

pub struct UdpResolvedPublicAddr {
    pub mapped_addr: SocketAddr,
    pub port_mapping_lease: Option<Box<dyn UdpPortMappingLease>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectPunchListener {
    pub force_new: bool,
    pub prefer_port_mapping: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectPunchListenerResponse {
    pub listener_mapped_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketCone {
    pub listener_mapped_addr: SocketAddr,
    pub dest_addr: SocketAddr,
    pub transaction_id: u32,
    pub packet_count_per_batch: u32,
    pub packet_batch_count: u32,
    pub packet_interval_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketHardSym {
    pub listener_mapped_addr: SocketAddr,
    pub public_ips: Vec<Ipv4Addr>,
    pub transaction_id: u32,
    pub port_index: u32,
    pub round: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketHardSymResponse {
    pub next_port_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketEasySym {
    pub listener_mapped_addr: SocketAddr,
    pub public_ips: Vec<Ipv4Addr>,
    pub transaction_id: u32,
    pub base_port_num: u32,
    pub max_port_num: u32,
    pub is_incremental: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketBothEasySym {
    pub udp_socket_count: u32,
    pub public_ip: Ipv4Addr,
    pub transaction_id: u32,
    pub dst_port_num: u32,
    pub wait_time_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendPunchPacketBothEasySymResponse {
    pub is_busy: bool,
    pub base_mapped_addr: Option<SocketAddr>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UdpHolePunchSignalError {
    #[error("invalid service key")]
    InvalidServiceKey,
    #[error("timeout")]
    Timeout,
    #[error("remote rejected: {0}")]
    RemoteRejected(String),
    #[error("transport: {0}")]
    Transport(String),
}

pub fn should_blacklist_signal_error(error: &UdpHolePunchSignalError) -> bool {
    matches!(error, UdpHolePunchSignalError::InvalidServiceKey)
}

#[async_trait]
pub trait UdpHolePunchSignaling: Send + Sync {
    async fn select_punch_listener(
        &self,
        dst_peer_id: crate::config::PeerId,
        request: SelectPunchListener,
    ) -> Result<SelectPunchListenerResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_cone(
        &self,
        dst_peer_id: crate::config::PeerId,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_hard_sym(
        &self,
        dst_peer_id: crate::config::PeerId,
        request: SendPunchPacketHardSym,
    ) -> Result<SendPunchPacketHardSymResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_easy_sym(
        &self,
        dst_peer_id: crate::config::PeerId,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_both_easy_sym(
        &self,
        dst_peer_id: crate::config::PeerId,
        request: SendPunchPacketBothEasySym,
    ) -> Result<SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>;
}

#[async_trait]
pub trait UdpHolePunchInbound: Send + Sync {
    async fn select_punch_listener(
        &self,
        request: SelectPunchListener,
    ) -> Result<SelectPunchListenerResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_cone(
        &self,
        request: SendPunchPacketCone,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_hard_sym(
        &self,
        request: SendPunchPacketHardSym,
    ) -> Result<SendPunchPacketHardSymResponse, UdpHolePunchSignalError>;

    async fn send_punch_packet_easy_sym(
        &self,
        request: SendPunchPacketEasySym,
    ) -> Result<(), UdpHolePunchSignalError>;

    async fn send_punch_packet_both_easy_sym(
        &self,
        request: SendPunchPacketBothEasySym,
    ) -> Result<SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>;
}

#[async_trait]
pub trait UdpHolePunchTunnelSink: Send + Sync {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()>;
}

#[async_trait]
pub trait UdpHolePunchTransportSink: Send + Sync {
    async fn add_client_transport(
        &self,
        connected: ConnectedUdpSession,
        requested_url: url::Url,
    ) -> anyhow::Result<()>;

    async fn add_server_transport(
        &self,
        connected: ConnectedUdpSession,
        requested_url: url::Url,
    ) -> anyhow::Result<()>;
}

pub struct ProtocolUdpHolePunchTransportSink<TcpSocket, T> {
    protocol: Arc<dyn ClientProtocolUpgrader<TcpSocket>>,
    tunnel_sink: Arc<T>,
}

impl<TcpSocket: 'static, T> ProtocolUdpHolePunchTransportSink<TcpSocket, T> {
    pub fn new(protocol: Arc<dyn ClientProtocolUpgrader<TcpSocket>>, tunnel_sink: Arc<T>) -> Self {
        Self {
            protocol,
            tunnel_sink,
        }
    }

    async fn upgrade(
        &self,
        connected: ConnectedUdpSession,
        requested_url: url::Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        self.protocol
            .upgrade_client(ConnectedTransport::Udp(connected), requested_url)
            .await
    }
}

#[async_trait]
impl<TcpSocket, T> UdpHolePunchTransportSink for ProtocolUdpHolePunchTransportSink<TcpSocket, T>
where
    TcpSocket: 'static,
    T: UdpHolePunchTunnelSink + 'static,
{
    async fn add_client_transport(
        &self,
        connected: ConnectedUdpSession,
        requested_url: url::Url,
    ) -> anyhow::Result<()> {
        let tunnel = self.upgrade(connected, requested_url).await?;
        self.tunnel_sink.add_client_tunnel(tunnel).await
    }

    async fn add_server_transport(
        &self,
        connected: ConnectedUdpSession,
        requested_url: url::Url,
    ) -> anyhow::Result<()> {
        let tunnel = self.upgrade(connected, requested_url).await?;
        self.tunnel_sink.add_server_tunnel(tunnel).await
    }
}

#[async_trait]
pub trait UdpHolePunchPeerSource: Send + Sync {
    fn local_peer_id(&self) -> crate::config::PeerId;
    // Part of the peer-source contract implemented outside this module; no
    // in-crate caller remains after the connector surface converged.
    #[allow(dead_code)]
    fn network_name(&self) -> &str;
    fn p2p_policy_flags(&self) -> P2pPolicyFlags;

    async fn candidates(&self) -> Vec<super::UdpPunchCandidate>;
}

#[async_trait]
pub trait UdpHolePunchRuntime: Send + Sync + 'static {
    type Socket: VirtualUdpSocket + 'static;

    fn socket_context(&self) -> SocketContext {
        SocketContext::default()
    }

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>>;

    async fn bind_direct_connect_udp(&self) -> anyhow::Result<Arc<Self::Socket>> {
        UdpHolePunchRuntime::bind_udp(
            self,
            UdpBindOptions::direct_connect().with_context(
                self.socket_context()
                    .with_ip_version(crate::socket::IpVersion::V4),
            ),
        )
        .await
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<UdpResolvedPublicAddr>;

    async fn create_listener(
        &self,
        prefer_port_mapping: bool,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>>;

    async fn create_port_bound_listener(
        &self,
        port: u16,
    ) -> anyhow::Result<UdpPunchListener<Self::Socket>>;

    async fn connect_with_socket(
        &self,
        socket: Arc<Self::Socket>,
        remote: SocketAddr,
    ) -> anyhow::Result<UdpPunchSocket>;
}

#[async_trait]
impl<T> VirtualUdpSocketFactory for T
where
    T: UdpHolePunchRuntime + Send + Sync + 'static,
{
    type Socket = T::Socket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        UdpHolePunchRuntime::bind_udp(self, options).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::socket::udp::UdpSessionKind;

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

    struct DropSignal(Arc<AtomicBool>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }

    #[derive(Default)]
    struct MockProtocol {
        upgrades: AtomicUsize,
    }

    #[async_trait]
    impl ClientProtocolUpgrader<()> for MockProtocol {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "udp"
        }

        async fn upgrade_client(
            &self,
            connected: ConnectedTransport<()>,
            requested_url: url::Url,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            self.upgrades.fetch_add(1, Ordering::Relaxed);
            let ConnectedTransport::Udp(connected) = connected else {
                anyhow::bail!("expected UDP transport");
            };
            Ok(crate::connectivity::protocol::raw::upgrade_connected_udp(
                connected,
                requested_url,
            )?)
        }
    }

    #[derive(Default)]
    struct MockTunnelSink {
        clients: AtomicUsize,
        servers: AtomicUsize,
    }

    #[async_trait]
    impl UdpHolePunchTunnelSink for MockTunnelSink {
        async fn add_client_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.clients.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn add_server_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.servers.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn punched_socket(local_port: u16, remote_port: u16) -> UdpPunchSocket {
        let remote_addr = SocketAddr::from(([203, 0, 113, 1], remote_port));
        let session = UdpSession::identity_standalone(
            Arc::new(MockSocket {
                local_addr: SocketAddr::from(([127, 0, 0, 1], local_port)),
            }),
            remote_addr,
            UdpSessionKind::EasyTierMux,
        )
        .unwrap();
        UdpPunchSocket::new(session, remote_addr, ())
    }

    #[tokio::test]
    async fn protocol_sink_upgrades_before_role_specific_admission() {
        let protocol = Arc::new(MockProtocol::default());
        let tunnel_sink = Arc::new(MockTunnelSink::default());
        let sink =
            ProtocolUdpHolePunchTransportSink::<(), _>::new(protocol.clone(), tunnel_sink.clone());

        let (client, client_url) = punched_socket(1000, 2000).into_connected();
        sink.add_client_transport(client, client_url).await.unwrap();
        let (server, server_url) = punched_socket(1001, 2001).into_connected();
        sink.add_server_transport(server, server_url).await.unwrap();

        assert_eq!(protocol.upgrades.load(Ordering::Relaxed), 2);
        assert_eq!(tunnel_sink.clients.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_sink.servers.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn punched_socket_preserves_requested_and_resolved_addresses() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 1000));
        let requested_remote_addr = SocketAddr::from(([198, 51, 100, 1], 2000));
        let resolved_remote_addr = SocketAddr::from(([203, 0, 113, 1], 3000));
        let session = UdpSession::identity_standalone(
            Arc::new(MockSocket { local_addr }),
            resolved_remote_addr,
            UdpSessionKind::EasyTierMux,
        )
        .unwrap();
        let guard_dropped = Arc::new(AtomicBool::new(false));
        let socket = UdpPunchSocket::new(
            session,
            requested_remote_addr,
            DropSignal(guard_dropped.clone()),
        );

        let (connected, requested_url) = socket.into_connected();
        let tunnel =
            crate::connectivity::protocol::raw::upgrade_connected_udp(connected, requested_url)
                .unwrap();
        let info = tunnel.info().unwrap();
        let local_url: url::Url = info.local_addr.unwrap().into();
        let remote_url: url::Url = info.remote_addr.unwrap().into();
        let resolved_url: url::Url = info.resolved_remote_addr.unwrap().into();

        assert_eq!(local_url.host_str(), Some("127.0.0.1"));
        assert_eq!(local_url.port(), Some(local_addr.port()));
        assert_eq!(remote_url.host_str(), Some("198.51.100.1"));
        assert_eq!(remote_url.port(), Some(requested_remote_addr.port()));
        assert_eq!(resolved_url.host_str(), Some("203.0.113.1"));
        assert_eq!(resolved_url.port(), Some(resolved_remote_addr.port()));
        assert!(!guard_dropped.load(Ordering::Relaxed));
        drop(tunnel);
        assert!(guard_dropped.load(Ordering::Relaxed));
    }
}

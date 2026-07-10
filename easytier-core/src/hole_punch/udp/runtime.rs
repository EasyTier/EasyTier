use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;

use crate::{
    proto::common::{StunInfo, TunnelInfo},
    socket::udp::{
        UdpBindOptions, UdpSession, UdpSessionSocket, VirtualUdpSocket, VirtualUdpSocketFactory,
    },
    tunnel::{Tunnel, TunnelError, udp::UdpTunnelUpgrader},
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

    pub(crate) fn into_tunnel(self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let local_addr = self.session.local_addr()?;
        let resolved_remote_addr = self.session.peer_addr()?;
        let tunnel_info = TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: Some(udp_url(local_addr).into()),
            remote_addr: Some(udp_url(self.requested_remote_addr).into()),
            resolved_remote_addr: Some(udp_url(resolved_remote_addr).into()),
        };
        UdpTunnelUpgrader::with_keep_alive(tunnel_info, self.lifetime_guard).upgrade(self.session)
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

pub trait UdpPortMappingLease: Send + Sync + std::fmt::Debug {}

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
pub trait UdpHolePunchPeerSource: Send + Sync {
    fn local_peer_id(&self) -> crate::config::PeerId;
    fn network_name(&self) -> &str;
    fn p2p_policy_flags(&self) -> super::P2pPolicyFlags;

    async fn candidates(&self) -> Vec<super::UdpPunchCandidate>;
}

#[async_trait]
pub trait UdpHolePunchRuntime: Send + Sync + 'static {
    type Socket: VirtualUdpSocket + 'static;

    fn stun_info(&self) -> StunInfo;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>>;

    async fn bind_direct_connect_udp(&self) -> anyhow::Result<Arc<Self::Socket>> {
        UdpHolePunchRuntime::bind_udp(self, UdpBindOptions::direct_connect()).await
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<UdpResolvedPublicAddr>;

    async fn get_udp_port_mapping(&self, port: u16) -> anyhow::Result<SocketAddr>;

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
            atomic::{AtomicBool, Ordering},
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

        let tunnel = socket.into_tunnel().unwrap();
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

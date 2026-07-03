use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;

use crate::{proto::common::StunInfo, tunnel::Tunnel};

#[async_trait]
pub trait UdpPunchSocket: Send + Sync {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[async_trait]
pub trait UdpPunchAcceptor: Send {
    async fn accept(&mut self) -> anyhow::Result<Box<dyn Tunnel>>;
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

#[derive(Debug, thiserror::Error)]
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
pub trait UdpPunchSocketFactory: Send + Sync + 'static {
    type Socket: UdpPunchSocket + 'static;

    async fn bind_udp(&self, port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>>;
}

#[async_trait]
impl<T> UdpPunchSocketFactory for T
where
    T: UdpHolePunchRuntime + Send + Sync + 'static,
{
    type Socket = T::Socket;

    async fn bind_udp(&self, port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>> {
        UdpHolePunchRuntime::bind_udp(self, port).await
    }
}

#[async_trait]
pub trait UdpHolePunchRuntime: Send + Sync + 'static {
    type Socket: UdpPunchSocket + 'static;

    fn stun_info(&self) -> StunInfo;

    async fn bind_udp(&self, port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>>;

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<SocketAddr>;

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
    ) -> anyhow::Result<Box<dyn Tunnel>>;
}

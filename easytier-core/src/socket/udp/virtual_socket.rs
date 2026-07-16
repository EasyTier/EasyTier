use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::socket::{IpVersion, SocketContext};

use super::packet::{new_v4_hole_punch_packet, new_v6_hole_punch_packet};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketRecvMeta {
    pub dst_ip: Option<IpAddr>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketSendMeta {
    pub src_ip: Option<IpAddr>,
    pub src_ifindex: Option<u32>,
}

#[async_trait]
pub trait VirtualUdpSocket: Send + Sync + 'static {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    fn socket_context(&self) -> SocketContext {
        SocketContext::default()
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;

    async fn send_to_with_meta(
        &self,
        data: &[u8],
        addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> std::io::Result<usize> {
        let _ = meta;
        self.send_to(data, addr).await
    }

    async fn recv_from_with_meta(
        &self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, SocketAddr, UdpSocketRecvMeta)> {
        let (len, addr) = self.recv_from(buf).await?;
        Ok((len, addr, UdpSocketRecvMeta::default()))
    }
}

#[async_trait]
pub trait UdpSessionStunResponder<S>: Send + Sync + 'static
where
    S: VirtualUdpSocket,
{
    async fn respond_stun(
        &self,
        _socket: Arc<S>,
        _datagram: &[u8],
        _remote_addr: SocketAddr,
    ) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NoopUdpSessionStunResponder;

#[async_trait]
impl<S> UdpSessionStunResponder<S> for NoopUdpSessionStunResponder where S: VirtualUdpSocket {}

#[async_trait]
impl<S, F> UdpSessionStunResponder<S> for F
where
    S: VirtualUdpSocket,
    F: VirtualUdpSocketFactory<Socket = S>,
{
    async fn respond_stun(
        &self,
        socket: Arc<S>,
        datagram: &[u8],
        remote_addr: SocketAddr,
    ) -> io::Result<()> {
        crate::stun::respond_stun_packet(socket, self, remote_addr, datagram)
            .await
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))
    }
}

pub async fn send_v4_hole_punch_control_packet<F>(
    factory: &F,
    context: SocketContext,
    listener_port: u16,
    dst_addr: SocketAddrV4,
) -> anyhow::Result<()>
where
    F: VirtualUdpSocketFactory,
{
    let socket = factory
        .bind_udp(
            UdpBindOptions::hole_punch_control()
                .with_context(context.with_ip_version(IpVersion::V4))
                .with_local_addr(Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    0,
                )))),
        )
        .await?;
    let packet = new_v4_hole_punch_packet(&dst_addr).into_bytes();
    let listener_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener_port));
    socket.send_to(&packet, listener_addr).await?;
    Ok(())
}

pub async fn send_v6_hole_punch_control_packet<F>(
    factory: &F,
    context: SocketContext,
    listener_port: u16,
    dst_addr: SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> anyhow::Result<()>
where
    F: VirtualUdpSocketFactory,
{
    let socket = factory
        .bind_udp(
            UdpBindOptions::hole_punch_control()
                .with_context(context.with_ip_version(IpVersion::V6))
                .with_local_addr(Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    0,
                    0,
                    0,
                )))),
        )
        .await?;
    let packet = new_v6_hole_punch_packet(&dst_addr, preferred_src).into_bytes();
    let listener_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, listener_port, 0, 0));
    socket.send_to(&packet, listener_addr).await?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UdpSocketPurpose {
    HolePunchControl,
    HolePunchCandidate,
    DirectConnect,
    PortBoundListener,
    ProxyNat,
    StunProbe,
    Socks5,
    PortForward,
    PortLease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpBindOptions {
    #[serde(default)]
    pub context: SocketContext,
    pub local_addr: Option<SocketAddr>,
    pub bind_device: Option<String>,
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub only_v6: bool,
    pub purpose: UdpSocketPurpose,
}

impl UdpBindOptions {
    fn for_purpose(purpose: UdpSocketPurpose) -> Self {
        Self {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose,
        }
    }

    pub fn hole_punch_control() -> Self {
        Self::for_purpose(UdpSocketPurpose::HolePunchControl)
    }

    pub fn hole_punch_candidate() -> Self {
        Self::for_purpose(UdpSocketPurpose::HolePunchCandidate)
    }

    pub fn direct_connect() -> Self {
        Self::for_purpose(UdpSocketPurpose::DirectConnect)
    }

    pub fn port_bound_listener(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            ..Self::for_purpose(UdpSocketPurpose::PortBoundListener)
        }
    }

    pub fn proxy_nat() -> Self {
        Self::for_purpose(UdpSocketPurpose::ProxyNat)
    }

    pub fn stun_probe() -> Self {
        Self::for_purpose(UdpSocketPurpose::StunProbe)
    }

    pub fn socks5() -> Self {
        Self::for_purpose(UdpSocketPurpose::Socks5)
    }

    pub fn port_forward(local_addr: SocketAddr) -> Self {
        Self::for_purpose(UdpSocketPurpose::PortForward).with_local_addr(Some(local_addr))
    }

    pub fn port_lease(local_addr: SocketAddr) -> Self {
        Self::for_purpose(UdpSocketPurpose::PortLease).with_local_addr(Some(local_addr))
    }

    pub fn with_local_addr(mut self, local_addr: Option<SocketAddr>) -> Self {
        self.local_addr = local_addr;
        self
    }

    pub fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.context.socket_mark = socket_mark;
        self
    }

    pub fn with_context(mut self, context: SocketContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.context.ip_version = ip_version;
        self
    }

    pub fn with_bind_device(mut self, bind_device: Option<String>) -> Self {
        self.bind_device = bind_device;
        self
    }

    pub fn with_reuse_addr(mut self, reuse_addr: bool) -> Self {
        self.reuse_addr = reuse_addr;
        self
    }

    pub fn with_reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = only_v6;
        self
    }
}

impl Default for UdpBindOptions {
    fn default() -> Self {
        Self::hole_punch_control()
    }
}

#[async_trait]
pub trait VirtualUdpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferredIpv6Source {
    pub ip: Ipv6Addr,
    pub ifindex: u32,
}

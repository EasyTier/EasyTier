use crate::socket::BindConfig;
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use serde::{Deserialize, Serialize};

use super::packet::{new_v4_hole_punch_packet, new_v6_hole_punch_packet};
use crate::socket::IpVersion;
use crate::socket::SocketContext;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketRecvMeta {
    pub dst_ip: Option<IpAddr>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UdpSocketSendMeta {
    pub src_ip: Option<IpAddr>,
    pub src_ifindex: Option<u32>,
}

/// Largest UDP datagram that portable socket implementations must receive.
pub const MAX_UDP_DATAGRAM_SIZE: usize = u16::MAX as usize;

/// Largest datagram accepted by the UDP session/multiplexer data plane.
///
/// EasyTier, WireGuard, and QUIC datagrams are bounded by their transport MTU.
/// Keeping this capacity explicit avoids allocating the theoretical UDP maximum
/// for every packet on native hosts that can detect truncation.
pub const MAX_UDP_SESSION_DATAGRAM_SIZE: usize = 8 * 1024;

#[derive(Debug)]
pub struct UdpSocketDatagram {
    pub payload: BytesMut,
    pub remote_addr: SocketAddr,
    pub meta: UdpSocketRecvMeta,
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

    /// Receives one datagram into an owned buffer.
    ///
    /// Portable hosts can use this default implementation. Native hosts should
    /// override it when their socket API can write directly into owned storage,
    /// avoiding a second allocation and copy at the Host boundary.
    async fn recv_datagram(&self) -> std::io::Result<UdpSocketDatagram> {
        recv_portable_datagram(self, MAX_UDP_DATAGRAM_SIZE).await
    }

    /// Receives one datagram for the UDP session/multiplexer data plane.
    ///
    /// Portable hosts receive one byte past the session limit so a truncated
    /// oversized datagram remains distinguishable from a valid maximum-sized
    /// datagram. Native hosts may override this when they can detect truncation
    /// without the extra byte.
    async fn recv_session_datagram(&self) -> std::io::Result<UdpSocketDatagram> {
        recv_portable_datagram(self, MAX_UDP_SESSION_DATAGRAM_SIZE + 1).await
    }
}

async fn recv_portable_datagram<S>(
    socket: &S,
    capacity: usize,
) -> std::io::Result<UdpSocketDatagram>
where
    S: VirtualUdpSocket + ?Sized,
{
    let mut payload = BytesMut::new();
    payload.resize(capacity, 0);
    let (len, remote_addr, meta) = socket.recv_from_with_meta(&mut payload).await?;
    payload.truncate(len);
    Ok(UdpSocketDatagram {
        payload,
        remote_addr,
        meta,
    })
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
        .bind_udp(BindConfig {
            bind_device: Some("".into()),
            reuse_addr: Some(false),
            need_protect: false,
            context: SocketContext {
                ip_version: IpVersion::V4,
                ..context
            },
            local_addr: Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            ..BindConfig::default()
        })
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
        .bind_udp(BindConfig {
            bind_device: Some("".into()),
            reuse_addr: Some(false),
            need_protect: false,
            context: SocketContext {
                ip_version: IpVersion::V6,
                ..context
            },
            local_addr: Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::LOCALHOST,
                0,
                0,
                0,
            ))),
            ..BindConfig::default()
        })
        .await?;
    let packet = new_v6_hole_punch_packet(&dst_addr, preferred_src).into_bytes();
    let listener_addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, listener_port, 0, 0));
    socket.send_to(&packet, listener_addr).await?;
    Ok(())
}

#[async_trait]
pub trait VirtualUdpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualUdpSocket;

    async fn bind_udp(&self, options: BindConfig) -> anyhow::Result<Arc<Self::Socket>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreferredIpv6Source {
    pub ip: Ipv6Addr,
    pub ifindex: u32,
}
#[cfg(test)]
mod option_tests {
    use super::*;

    #[test]
    fn udp_constructor_protection_defaults_match_endpoint_role() {
        let local = SocketAddr::from(([0, 0, 0, 0], 11010));

        assert!(UdpBindOptions::default().need_protect);
        assert!(UdpBindOptions::hole_punch_control().need_protect);
        assert!(UdpBindOptions::hole_punch_candidate().need_protect);
        assert!(UdpBindOptions::direct_connect().need_protect);
        assert!(UdpBindOptions::port_bound_listener(local).need_protect);
        assert!(UdpBindOptions::proxy_nat().need_protect);
        assert!(UdpBindOptions::stun_probe().need_protect);
        assert!(UdpBindOptions::socks5().need_protect);
        assert!(!UdpBindOptions::port_forward(local).need_protect);
        assert!(!UdpBindOptions::port_lease(local).need_protect);
    }

    #[test]
    fn udp_bind_serde_defaults_to_protected_and_preserves_opt_out() {
        let options: UdpBindOptions = serde_json::from_str(
            r#"{"local_addr":null,"bind_device":null,"reuse_addr":false,"reuse_port":false,"only_v6":false,"purpose":"DirectConnect"}"#,
        )
        .unwrap();
        assert!(options.need_protect);
        let local = UdpBindOptions::port_forward("0.0.0.0:15555".parse().unwrap());
        let restored: UdpBindOptions =
            serde_json::from_str(&serde_json::to_string(&local).unwrap()).unwrap();
        assert_eq!(restored, local);
        assert!(!restored.need_protect);
    }
}
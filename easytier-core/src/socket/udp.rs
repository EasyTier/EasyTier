use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::BytesMut;
use zerocopy::{AsBytes, FromBytes};

use crate::packet::{
    UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, UdpPacketType, V4HolePunchPacket, V6HolePunchPacket,
    ZCPacket, ZCPacketType,
};

#[async_trait]
pub trait VirtualUdpSocket: Send + Sync + 'static {
    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize>;

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSocketPurpose {
    HolePunchControl,
    HolePunchCandidate,
    DirectConnect,
    PortBoundListener,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpBindOptions {
    pub local_addr: Option<SocketAddr>,
    pub purpose: UdpSocketPurpose,
}

impl UdpBindOptions {
    pub fn hole_punch_control() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchControl,
        }
    }

    pub fn hole_punch_candidate() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::HolePunchCandidate,
        }
    }

    pub fn direct_connect() -> Self {
        Self {
            local_addr: None,
            purpose: UdpSocketPurpose::DirectConnect,
        }
    }

    pub fn port_bound_listener(local_addr: SocketAddr) -> Self {
        Self {
            local_addr: Some(local_addr),
            purpose: UdpSocketPurpose::PortBoundListener,
        }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PreferredIpv6Source {
    pub ip: Ipv6Addr,
    pub ifindex: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum UdpSessionPacketError {
    #[error("udp packet size too small: {datagram_size:?}, packet: {packet:?}")]
    TooSmall {
        datagram_size: usize,
        packet: BytesMut,
    },
    #[error(
        "udp packet payload len not match: header len: {header_len:?}, real len: {datagram_size:?}"
    )]
    PayloadLenMismatch {
        header_len: usize,
        datagram_size: usize,
    },
}

fn new_udp_packet<F>(f: F, udp_body: &[u8]) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(UDP_TUNNEL_HEADER_SIZE + udp_body.len(), 0);
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body);

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

pub fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

pub fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

pub fn new_v6_hole_punch_packet(
    dst: &SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> ZCPacket {
    let mut body = V6HolePunchPacket::default();
    body.dst_ipv6.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    if let Some(src) = preferred_src {
        body.preferred_src_ipv6.copy_from_slice(&src.ip.octets());
        body.preferred_src_ifindex.set(src.ifindex);
    }
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V6HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V6HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn new_v4_hole_punch_packet(dst: &SocketAddrV4) -> ZCPacket {
    let mut body = V4HolePunchPacket::default();
    body.dst_ipv4.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V4HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V4HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn extract_dst_addr_from_v4_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV4> {
    let body = V4HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv4Addr::from(body.dst_ipv4);
    Some(SocketAddrV4::new(ip, body.dst_port.get()))
}

pub fn extract_v6_hole_punch_packet(
    buf: &[u8],
) -> Option<(SocketAddrV6, Option<PreferredIpv6Source>)> {
    let body = V6HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv6Addr::from(body.dst_ipv6);
    let preferred_src_ipv6 = Ipv6Addr::from(body.preferred_src_ipv6);
    let preferred_src = (!preferred_src_ipv6.is_unspecified()).then_some(PreferredIpv6Source {
        ip: preferred_src_ipv6,
        ifindex: body.preferred_src_ifindex.get(),
    });
    Some((
        SocketAddrV6::new(ip, body.dst_port.get(), 0, 0),
        preferred_src,
    ))
}

pub fn is_stun_packet(data: &[u8]) -> bool {
    data.len() >= UDP_TUNNEL_HEADER_SIZE
        && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
        && data[0] & 0xC0 == 0
}

pub fn parse_udp_session_datagram(
    buf: BytesMut,
    allow_stun: bool,
) -> Result<ZCPacket, UdpSessionPacketError> {
    let datagram_size = buf.len();
    if datagram_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(UdpSessionPacketError::TooSmall {
            datagram_size,
            packet: buf,
        });
    }

    if allow_stun && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]) {
        return Ok(ZCPacket::new_from_buf(buf, ZCPacketType::UDP));
    }

    let zc_packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = zc_packet.udp_tunnel_header().unwrap();
    let header_len = header.len.get() as usize;
    let real_len = datagram_size - UDP_TUNNEL_HEADER_SIZE;
    if header_len != real_len {
        return Err(UdpSessionPacketError::PayloadLenMismatch {
            header_len,
            datagram_size,
        });
    }

    Ok(zc_packet)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpSessionKind {
    Direct,
    EasyTierMux,
}

#[async_trait]
pub trait UdpSessionSocket: Send + Sync + 'static {
    fn kind(&self) -> UdpSessionKind;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    fn peer_addr(&self) -> std::io::Result<SocketAddr>;

    async fn send(&self, data: &[u8]) -> std::io::Result<usize>;

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionConnectRequest {
    pub remote_addr: SocketAddr,
    pub bind: UdpBindOptions,
}

impl UdpSessionConnectRequest {
    pub fn direct(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: UdpBindOptions::direct_connect(),
        }
    }

    pub fn with_bind(mut self, bind: UdpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSessionListenRequest {
    pub bind: UdpBindOptions,
}

impl UdpSessionListenRequest {
    pub fn new(bind: UdpBindOptions) -> Self {
        Self { bind }
    }
}

#[async_trait]
pub trait UdpSessionConnector: Send {
    type Session: UdpSessionSocket;

    async fn connect(&mut self, request: UdpSessionConnectRequest)
    -> anyhow::Result<Self::Session>;
}

#[async_trait]
pub trait UdpSessionListener: Send {
    type Session: UdpSessionSocket;

    async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()>;

    fn local_addr(&self) -> std::io::Result<SocketAddr>;

    async fn accept(&mut self) -> anyhow::Result<Self::Session>;
}

#[derive(Debug)]
pub struct UdpSession<S> {
    socket: Arc<S>,
    peer_addr: SocketAddr,
    kind: UdpSessionKind,
}

impl<S> UdpSession<S>
where
    S: VirtualUdpSocket,
{
    pub fn direct(socket: Arc<S>, peer_addr: SocketAddr) -> Self {
        Self {
            socket,
            peer_addr,
            kind: UdpSessionKind::Direct,
        }
    }
}

#[async_trait]
impl<S> UdpSessionSocket for UdpSession<S>
where
    S: VirtualUdpSocket,
{
    fn kind(&self) -> UdpSessionKind {
        self.kind
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
        self.socket.send_to(data, self.peer_addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let (len, remote_addr) = self.socket.recv_from(buf).await?;
            if remote_addr == self.peer_addr {
                return Ok(len);
            }
        }
    }
}

#[derive(Debug)]
pub struct UdpSessionDialer<F> {
    factory: Arc<F>,
}

impl<F> UdpSessionDialer<F>
where
    F: VirtualUdpSocketFactory,
{
    pub fn new(factory: Arc<F>) -> Self {
        Self { factory }
    }
}

#[async_trait]
impl<F> UdpSessionConnector for UdpSessionDialer<F>
where
    F: VirtualUdpSocketFactory,
{
    type Session = UdpSession<F::Socket>;

    async fn connect(
        &mut self,
        request: UdpSessionConnectRequest,
    ) -> anyhow::Result<Self::Session> {
        let socket = self.factory.bind_udp(request.bind).await?;
        Ok(UdpSession::direct(socket, request.remote_addr))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Mutex,
            atomic::{AtomicU16, Ordering},
        },
    };

    use super::*;

    #[test]
    fn bind_options_constructors_describe_socket_purpose() {
        let listener_addr = SocketAddr::from(([0, 0, 0, 0], 12345));

        assert_eq!(
            UdpBindOptions::hole_punch_control(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchControl,
            }
        );
        assert_eq!(
            UdpBindOptions::hole_punch_candidate(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::HolePunchCandidate,
            }
        );
        assert_eq!(
            UdpBindOptions::direct_connect(),
            UdpBindOptions {
                local_addr: None,
                purpose: UdpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            UdpBindOptions::port_bound_listener(listener_addr),
            UdpBindOptions {
                local_addr: Some(listener_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
        assert_eq!(
            UdpBindOptions::default(),
            UdpBindOptions::hole_punch_control()
        );
    }

    #[test]
    fn session_connect_request_keeps_peer_scoped_udp_shape() {
        let remote_addr = SocketAddr::from(([192, 0, 2, 1], 11010));
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 22020));

        let request = UdpSessionConnectRequest::direct(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        assert_eq!(request.remote_addr, remote_addr);
        assert_eq!(
            request.bind,
            UdpBindOptions {
                local_addr: Some(bind_addr),
                purpose: UdpSocketPurpose::PortBoundListener,
            }
        );
    }

    #[test]
    fn session_listen_request_keeps_bind_options() {
        let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
        let bind = UdpBindOptions::port_bound_listener(bind_addr);

        assert_eq!(UdpSessionListenRequest::new(bind).bind, bind);
    }

    struct MockUdpSessionSocket {
        kind: UdpSessionKind,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        incoming: Mutex<Vec<u8>>,
        sent: Mutex<Vec<u8>>,
    }

    #[async_trait]
    impl UdpSessionSocket for MockUdpSessionSocket {
        fn kind(&self) -> UdpSessionKind {
            self.kind
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }

        async fn send(&self, data: &[u8]) -> std::io::Result<usize> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let incoming = self.incoming.lock().unwrap();
            let len = incoming.len().min(buf.len());
            buf[..len].copy_from_slice(&incoming[..len]);
            Ok(len)
        }
    }

    #[tokio::test]
    async fn udp_session_socket_is_peer_scoped() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let socket = MockUdpSessionSocket {
            kind: UdpSessionKind::Direct,
            local_addr,
            peer_addr,
            incoming: Mutex::new(b"pong".to_vec()),
            sent: Mutex::new(Vec::new()),
        };

        assert_eq!(socket.kind(), UdpSessionKind::Direct);
        assert_eq!(socket.local_addr().unwrap(), local_addr);
        assert_eq!(socket.peer_addr().unwrap(), peer_addr);
        assert_eq!(socket.send(b"ping").await.unwrap(), 4);

        let mut buf = [0; 8];
        let len = socket.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"pong");
        assert_eq!(&*socket.sent.lock().unwrap(), b"ping");
    }

    struct MockUdpSessionListener {
        local_addr: SocketAddr,
        accepted: Option<MockUdpSessionSocket>,
    }

    #[async_trait]
    impl UdpSessionListener for MockUdpSessionListener {
        type Session = MockUdpSessionSocket;

        async fn listen(&mut self, request: UdpSessionListenRequest) -> anyhow::Result<()> {
            if let Some(local_addr) = request.bind.local_addr {
                self.local_addr = local_addr;
            }
            Ok(())
        }

        fn local_addr(&self) -> std::io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Session> {
            self.accepted
                .take()
                .ok_or_else(|| anyhow::anyhow!("no accepted session"))
        }
    }

    #[tokio::test]
    async fn udp_session_listener_reports_bound_local_addr_before_accept() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 10000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 10001));
        let mut listener = MockUdpSessionListener {
            local_addr: SocketAddr::from(([0, 0, 0, 0], 0)),
            accepted: Some(MockUdpSessionSocket {
                kind: UdpSessionKind::EasyTierMux,
                local_addr,
                peer_addr,
                incoming: Mutex::new(Vec::new()),
                sent: Mutex::new(Vec::new()),
            }),
        };

        listener
            .listen(UdpSessionListenRequest::new(
                UdpBindOptions::port_bound_listener(local_addr),
            ))
            .await
            .unwrap();

        assert_eq!(listener.local_addr().unwrap(), local_addr);
        assert_eq!(
            listener.accept().await.unwrap().peer_addr().unwrap(),
            peer_addr
        );
    }

    struct MockVirtualUdpSocket {
        local_addr: SocketAddr,
        incoming: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockVirtualUdpSocket {
        fn new(local_addr: SocketAddr, incoming: Vec<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                local_addr,
                incoming: Mutex::new(incoming.into()),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockVirtualUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let (data, remote_addr) =
                self.incoming.lock().unwrap().pop_front().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "no incoming datagram")
                })?;
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, remote_addr))
        }
    }

    #[tokio::test]
    async fn direct_udp_session_sends_to_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
        let session = UdpSession::direct(socket.clone(), peer_addr);

        assert_eq!(session.kind(), UdpSessionKind::Direct);
        assert_eq!(session.local_addr().unwrap(), local_addr);
        assert_eq!(session.peer_addr().unwrap(), peer_addr);
        assert_eq!(session.send(b"hello").await.unwrap(), 5);

        assert_eq!(socket.sent(), vec![(b"hello".to_vec(), peer_addr)]);
    }

    #[tokio::test]
    async fn direct_udp_session_receives_only_from_peer_addr() {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
        let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
        let socket = Arc::new(MockVirtualUdpSocket::new(
            local_addr,
            vec![
                (b"noise".to_vec(), unexpected_addr),
                (b"payload".to_vec(), peer_addr),
            ],
        ));
        let session = UdpSession::direct(socket, peer_addr);

        let mut buf = [0; 16];
        let len = session.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..len], b"payload");
    }

    struct MockVirtualUdpSocketFactory {
        next_port: AtomicU16,
        bind_options: Mutex<Vec<UdpBindOptions>>,
    }

    impl MockVirtualUdpSocketFactory {
        fn new(next_port: u16) -> Self {
            Self {
                next_port: AtomicU16::new(next_port),
                bind_options: Mutex::new(Vec::new()),
            }
        }

        fn bind_options(&self) -> Vec<UdpBindOptions> {
            self.bind_options.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockVirtualUdpSocketFactory {
        type Socket = MockVirtualUdpSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_options.lock().unwrap().push(options);
            let local_addr = options.local_addr.unwrap_or_else(|| {
                SocketAddr::from((
                    [127, 0, 0, 1],
                    self.next_port.fetch_add(1, Ordering::Relaxed),
                ))
            });
            Ok(Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new())))
        }
    }

    #[tokio::test]
    async fn udp_session_dialer_binds_socket_and_returns_direct_session() {
        let factory = Arc::new(MockVirtualUdpSocketFactory::new(13000));
        let mut dialer = UdpSessionDialer::new(factory.clone());
        let remote_addr = SocketAddr::from(([192, 0, 2, 10], 11010));
        let bind_addr = SocketAddr::from(([127, 0, 0, 1], 14000));
        let request = UdpSessionConnectRequest::direct(remote_addr)
            .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

        let session = dialer.connect(request).await.unwrap();

        assert_eq!(factory.bind_options(), vec![request.bind]);
        assert_eq!(session.kind(), UdpSessionKind::Direct);
        assert_eq!(session.local_addr().unwrap(), bind_addr);
        assert_eq!(session.peer_addr().unwrap(), remote_addr);
    }

    #[test]
    fn builds_syn_and_sack_packets_without_changing_wire_shape() {
        let conn_id = 0x1234_5678;
        let magic = 0x0102_0304_0506_0708;

        for (packet, msg_type) in [
            (new_syn_packet(conn_id, magic), UdpPacketType::Syn as u8),
            (new_sack_packet(conn_id, magic), UdpPacketType::Sack as u8),
        ] {
            let header = packet.udp_tunnel_header().unwrap();
            assert_eq!(header.conn_id.get(), conn_id);
            assert_eq!(header.msg_type, msg_type);
            assert_eq!(header.len.get(), 8);
            assert_eq!(packet.udp_payload(), magic.to_le_bytes());
        }
    }

    #[test]
    fn v6_hole_punch_packet_preserves_preferred_source() {
        let dst_addr = "[2001:db8::1]:10001".parse::<SocketAddrV6>().unwrap();
        let preferred_src = PreferredIpv6Source {
            ip: "2001:db8::2".parse().unwrap(),
            ifindex: 42,
        };

        let packet = new_v6_hole_punch_packet(&dst_addr, Some(preferred_src));
        let (parsed_dst_addr, parsed_preferred_src) =
            extract_v6_hole_punch_packet(packet.udp_payload()).unwrap();

        assert_eq!(parsed_dst_addr, dst_addr);
        assert_eq!(parsed_preferred_src, Some(preferred_src));
    }

    #[test]
    fn parses_udp_session_datagram_and_rejects_bad_payload_len() {
        let packet = new_syn_packet(7, 42).into_bytes();
        let parsed = parse_udp_session_datagram(packet.clone().into(), false).unwrap();
        assert_eq!(parsed.udp_tunnel_header().unwrap().conn_id.get(), 7);

        let mut bad_packet = packet.to_vec();
        bad_packet.pop();

        assert!(matches!(
            parse_udp_session_datagram(BytesMut::from(bad_packet.as_slice()), false),
            Err(UdpSessionPacketError::PayloadLenMismatch { .. })
        ));
    }

    #[test]
    fn stun_classifier_requires_cookie_and_stun_bits() {
        let mut stun = [0; UDP_TUNNEL_HEADER_SIZE];
        stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

        assert!(is_stun_packet(&stun));

        stun[0] = 0xC0;
        assert!(!is_stun_packet(&stun));
        assert!(!is_stun_packet(&stun[..UDP_TUNNEL_HEADER_SIZE - 1]));
    }
}

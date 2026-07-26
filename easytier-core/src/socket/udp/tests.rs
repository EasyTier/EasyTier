use std::{
    collections::VecDeque,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, Mutex, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU16, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytecodec::EncodeExt as _;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::StreamExt;
use stun_codec::{Message, MessageClass, MessageEncoder, rfc5389::methods::BINDING};
use tokio::sync::{Semaphore, mpsc, watch};

use crate::{
    packet::stun::{Attribute, ChangeRequest, u32_to_tid},
    packet::{UDP_TUNNEL_HEADER_SIZE, UdpPacketType, hole_punch_packet_tid},
    socket::{IpVersion, NetNamespace, SocketContext, SocketListener},
};

use super::{layer::*, packet::*, session::*, virtual_socket::*, *};

#[test]
fn bind_options_constructors_describe_socket_purpose() {
    let listener_addr = SocketAddr::from(([0, 0, 0, 0], 12345));

    assert_eq!(
        UdpBindOptions::hole_punch_control(),
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::HolePunchControl,
        }
    );
    assert_eq!(
        UdpBindOptions::hole_punch_candidate(),
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::HolePunchCandidate,
        }
    );
    assert_eq!(
        UdpBindOptions::direct_connect(),
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::DirectConnect,
        }
    );
    assert_eq!(
        UdpBindOptions::port_bound_listener(listener_addr),
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: Some(listener_addr),
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::PortBoundListener,
        }
    );
    assert_eq!(
        UdpBindOptions::socks5(),
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: None,
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::Socks5,
        }
    );
    assert_eq!(
        UdpBindOptions::port_forward(listener_addr).purpose,
        UdpSocketPurpose::PortForward
    );
    assert_eq!(
        UdpBindOptions::port_lease(listener_addr).purpose,
        UdpSocketPurpose::PortLease
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

    let request = UdpSessionConnectRequest::wireguard(remote_addr)
        .with_bind(UdpBindOptions::port_bound_listener(bind_addr));

    assert_eq!(request.remote_addr, remote_addr);
    assert_eq!(request.protocol, UdpSessionProtocol::WireGuard);
    assert_eq!(
        request.bind,
        UdpBindOptions {
            context: SocketContext::default(),
            local_addr: Some(bind_addr),
            bind_device: None,
            reuse_addr: false,
            reuse_port: false,
            only_v6: false,
            purpose: UdpSocketPurpose::PortBoundListener,
        }
    );
}

#[test]
fn session_listen_request_keeps_bind_options() {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
    let bind = UdpBindOptions::port_bound_listener(bind_addr);

    assert_eq!(UdpSessionListenRequest::new(bind.clone()).bind, bind);
}

async fn drain_session_payloads(mut rings: UdpSessionRingParts) -> usize {
    let mut count = 0;
    while let Ok(Some(Ok(_))) =
        tokio::time::timeout(Duration::from_millis(10), rings.session_recv_rx.next()).await
    {
        count += 1;
    }
    count
}

#[tokio::test]
async fn lossy_udp_session_enqueue_preserves_reserved_capacity() {
    const RING_RESERVED_CAPACITY: usize = 4;

    let rings = create_udp_session_rings();
    for _ in 0..UDP_SESSION_QUEUE_CAPACITY {
        assert!(dispatch_payload_to_session(
            &rings.session_recv_tx,
            BytesMut::from("lossy"),
            UdpSessionEnqueuePolicy::Lossy,
        ));
    }
    assert_eq!(
        drain_session_payloads(rings).await,
        UDP_SESSION_QUEUE_CAPACITY - RING_RESERVED_CAPACITY
    );

    let rings = create_udp_session_rings();
    for _ in 0..UDP_SESSION_QUEUE_CAPACITY {
        assert!(dispatch_payload_to_session(
            &rings.session_recv_tx,
            BytesMut::from("lossy"),
            UdpSessionEnqueuePolicy::Lossy,
        ));
    }
    for _ in 0..RING_RESERVED_CAPACITY {
        assert!(dispatch_payload_to_session(
            &rings.session_recv_tx,
            BytesMut::from("reliable"),
            UdpSessionEnqueuePolicy::Reliable,
        ));
    }
    assert_eq!(
        drain_session_payloads(rings).await,
        UDP_SESSION_QUEUE_CAPACITY
    );
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
        kind: UdpSessionKind::WireGuard,
        local_addr,
        peer_addr,
        incoming: Mutex::new(b"pong".to_vec()),
        sent: Mutex::new(Vec::new()),
    };

    assert_eq!(socket.kind(), UdpSessionKind::WireGuard);
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
    send_attempts: Mutex<Vec<(Vec<u8>, SocketAddr, UdpSocketSendMeta)>>,
    reject_preferred_source: AtomicBool,
}

impl MockVirtualUdpSocket {
    fn new(local_addr: SocketAddr, incoming: Vec<(Vec<u8>, SocketAddr)>) -> Self {
        Self {
            local_addr,
            incoming: Mutex::new(incoming.into()),
            sent: Mutex::new(Vec::new()),
            send_attempts: Mutex::new(Vec::new()),
            reject_preferred_source: AtomicBool::new(false),
        }
    }

    fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.sent.lock().unwrap().clone()
    }

    fn send_attempts(&self) -> Vec<(Vec<u8>, SocketAddr, UdpSocketSendMeta)> {
        self.send_attempts.lock().unwrap().clone()
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

    async fn send_to_with_meta(
        &self,
        data: &[u8],
        addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<usize> {
        self.send_attempts
            .lock()
            .unwrap()
            .push((data.to_vec(), addr, meta));
        if meta.src_ip.is_some() && self.reject_preferred_source.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "injected preferred source failure",
            ));
        }
        self.send_to(data, addr).await
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

fn easytier_stun_request(change_ip: bool, change_port: bool) -> Vec<u8> {
    let mut request = Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(7));
    if change_ip || change_port {
        request.add_attribute(Attribute::ChangeRequest(ChangeRequest::new(
            change_ip,
            change_port,
        )));
    }
    MessageEncoder::new().encode_into_bytes(request).unwrap()
}

struct FailingSendVirtualUdpSocket {
    local_addr: SocketAddr,
}

#[async_trait]
impl VirtualUdpSocket for FailingSendVirtualUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "injected send failure",
        ))
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[derive(Debug, Default)]
struct BlockingUdpSessionStunResponder {
    started: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl UdpSessionStunResponder<MockVirtualUdpSocket> for BlockingUdpSessionStunResponder {
    async fn respond_stun(
        &self,
        _socket: Arc<MockVirtualUdpSocket>,
        _datagram: &[u8],
        _remote_addr: SocketAddr,
    ) -> io::Result<()> {
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(())
    }
}

struct AutoSackVirtualUdpSocket {
    local_addr: SocketAddr,
    incoming: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    incoming_notify: tokio::sync::Notify,
}

impl AutoSackVirtualUdpSocket {
    fn new(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            incoming: Mutex::new(VecDeque::new()),
            sent: Mutex::new(Vec::new()),
            incoming_notify: tokio::sync::Notify::new(),
        }
    }

    fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
        self.sent.lock().unwrap().clone()
    }
}

#[async_trait]
impl VirtualUdpSocket for AutoSackVirtualUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.sent.lock().unwrap().push((data.to_vec(), addr));
        if let Ok(packet) = parse_udp_session_datagram(BytesMut::from(data), false) {
            let header = packet.udp_tunnel_header().unwrap();
            if header.msg_type == UdpPacketType::Syn as u8 && packet.udp_payload().len() == 8 {
                let conn_id = header.conn_id.get();
                let magic = u64::from_le_bytes(packet.udp_payload()[..8].try_into().unwrap());
                self.incoming
                    .lock()
                    .unwrap()
                    .push_back((new_sack_packet(conn_id, magic).into_bytes().to_vec(), addr));
                self.incoming_notify.notify_one();
            }
        }
        Ok(data.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            if let Some((data, remote_addr)) = self.incoming.lock().unwrap().pop_front() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                return Ok((len, remote_addr));
            }
            self.incoming_notify.notified().await;
        }
    }
}

#[async_trait]
impl UdpSessionStunResponder<AutoSackVirtualUdpSocket> for BlockingUdpSessionStunResponder {
    async fn respond_stun(
        &self,
        _socket: Arc<AutoSackVirtualUdpSocket>,
        _datagram: &[u8],
        _remote_addr: SocketAddr,
    ) -> io::Result<()> {
        self.started.notify_waiters();
        self.release.notified().await;
        Ok(())
    }
}

fn create_test_easy_tier_mux_session<S>(
    socket: Arc<S>,
    key: UdpSessionKey,
    sessions: Arc<UdpSessionRegistry>,
) -> (UdpSession, watch::Sender<bool>)
where
    S: VirtualUdpSocket,
{
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    (
        create_test_easy_tier_mux_session_with_shutdown(socket, key, sessions, shutdown_rx),
        shutdown_tx,
    )
}

fn create_test_easy_tier_mux_session_with_shutdown<S>(
    socket: Arc<S>,
    key: UdpSessionKey,
    sessions: Arc<UdpSessionRegistry>,
    shutdown: watch::Receiver<bool>,
) -> UdpSession
where
    S: VirtualUdpSocket,
{
    let local_addr = socket.local_addr().unwrap();
    let rings = create_udp_session_rings();
    sessions.insert(key, udp_session_registry_entry(&rings));
    let close = UdpSessionClose::easy_tier(key, rings.close_tx.clone(), sessions);
    UdpSession::new(
        socket,
        local_addr,
        key.peer_addr,
        UdpSessionKind::EasyTierMux,
        UdpSessionCodec::EasyTierData {
            conn_id: key.conn_id,
        },
        rings,
        close,
        shutdown,
    )
}

async fn wait_for_sent<F>(mut sent: F, min_len: usize) -> Vec<(Vec<u8>, SocketAddr)>
where
    F: FnMut() -> Vec<(Vec<u8>, SocketAddr)>,
{
    tokio::time::timeout(Duration::from_secs(1), async move {
        loop {
            let packets = sent();
            if packets.len() >= min_len {
                return packets;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap()
}

fn wireguard_transport_packet(payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 32.max(4 + payload.len())];
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    packet[4..4 + payload.len()].copy_from_slice(payload);
    packet
}

fn wireguard_packet_with_easy_tier_data_header(payload: &[u8]) -> Vec<u8> {
    let payload_len = 24.max(payload.len());
    let mut packet = vec![0; UDP_TUNNEL_HEADER_SIZE + payload_len];
    packet[..4].copy_from_slice(&4u32.to_le_bytes());
    packet[4] = UdpPacketType::Data as u8;
    packet[6..8].copy_from_slice(&(payload_len as u16).to_le_bytes());
    packet[UDP_TUNNEL_HEADER_SIZE..UDP_TUNNEL_HEADER_SIZE + payload.len()].copy_from_slice(payload);
    packet
}

#[tokio::test]
async fn wireguard_udp_session_sends_to_peer_addr() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let session =
        UdpSession::identity_standalone(socket.clone(), peer_addr, UdpSessionKind::WireGuard)
            .unwrap();

    assert_eq!(session.kind(), UdpSessionKind::WireGuard);
    assert_eq!(session.local_addr().unwrap(), local_addr);
    assert_eq!(session.peer_addr().unwrap(), peer_addr);
    assert_eq!(session.send(b"hello").await.unwrap(), 5);

    let sent = wait_for_sent(|| socket.sent(), 1).await;
    assert_eq!(sent, vec![(b"hello".to_vec(), peer_addr)]);
}

#[tokio::test]
async fn wireguard_udp_session_receives_only_from_peer_addr() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    socket.incoming.lock().unwrap().extend([
        (b"noise".to_vec(), unexpected_addr),
        (b"payload".to_vec(), peer_addr),
    ]);
    socket.incoming_notify.notify_one();
    let session =
        UdpSession::identity_standalone(socket, peer_addr, UdpSessionKind::WireGuard).unwrap();

    let mut buf = [0; 16];
    let len = session.recv(&mut buf).await.unwrap();

    assert_eq!(&buf[..len], b"payload");
}

#[tokio::test]
async fn wireguard_udp_session_send_failure_closes_recv() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
    let session =
        UdpSession::identity_standalone(socket, peer_addr, UdpSessionKind::WireGuard).unwrap();

    let err = tokio::time::timeout(Duration::from_secs(1), session.send(b"payload"))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

    let mut buf = [0; 16];
    let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn udp_layer_routes_wireguard_packets_to_registered_wireguard_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let session = layer
        .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
        .unwrap();

    assert_eq!(session.kind(), UdpSessionKind::WireGuard);
    assert_eq!(session.send(b"outbound").await.unwrap(), 8);
    let sent = wait_for_sent(|| socket.sent(), 1).await;
    assert_eq!(sent, vec![(b"outbound".to_vec(), peer_addr)]);

    let inbound = wireguard_transport_packet(b"inbound");
    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((inbound.clone(), peer_addr));
    socket.incoming_notify.notify_one();

    let mut buf = [0; 64];
    let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf[..len], inbound.as_slice());
}

#[tokio::test]
async fn udp_layer_routes_unclaimed_easy_tier_shaped_wireguard_packet_to_wireguard_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let session = layer
        .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
        .unwrap();
    let packet = wireguard_packet_with_easy_tier_data_header(b"wireguard-collision");

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((packet.clone(), peer_addr));
    socket.incoming_notify.notify_one();

    let mut buf = [0; 64];
    let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf[..len], packet.as_slice());
    assert_eq!(layer.active_session_count(), 0);
}

#[tokio::test]
async fn udp_layer_routes_claimed_easy_tier_data_to_mux_before_wireguard_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let wireguard_session = layer
        .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
        .unwrap();
    let key = UdpSessionKey::new(peer_addr, 4);
    let (mux_session, _shutdown_tx) =
        create_test_easy_tier_mux_session(socket.clone(), key, layer.sessions.clone());
    let packet = wireguard_packet_with_easy_tier_data_header(b"mux-payload");
    let mux_payload = packet[UDP_TUNNEL_HEADER_SIZE..].to_vec();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((packet, peer_addr));
    socket.incoming_notify.notify_one();

    let mut mux_buf = [0; 32];
    let len = tokio::time::timeout(Duration::from_secs(1), mux_session.recv(&mut mux_buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&mux_buf[..len], mux_payload.as_slice());

    let mut wireguard_buf = [0; 64];
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            wireguard_session.recv(&mut wireguard_buf)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn udp_layer_drops_unknown_datagram_instead_of_creating_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = Arc::new(UdpSessionLayer::new(socket.clone()));
    let mut accept_task = tokio::spawn({
        let layer = layer.clone();
        async move {
            layer
                .accept_classified_session(UdpSessionProtocol::WireGuard)
                .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !layer
            .classified_accepts
            .get(&UdpSessionProtocol::WireGuard)
            .unwrap()
            .accept_enabled
            .load(Ordering::Relaxed)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((b"first".to_vec(), peer_addr));
    socket.incoming_notify.notify_one();

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut accept_task)
            .await
            .is_err()
    );
    accept_task.abort();
    assert_eq!(layer.active_classified_session_count(), 0);
}

#[tokio::test]
async fn udp_layer_drops_malformed_quic_like_datagrams_instead_of_creating_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = Arc::new(UdpSessionLayer::new(socket.clone()));
    let mut accept_task = tokio::spawn({
        let layer = layer.clone();
        async move {
            layer
                .accept_classified_session(UdpSessionProtocol::Quic)
                .await
        }
    });

    tokio::time::timeout(Duration::from_secs(1), async {
        while !layer
            .classified_accepts
            .get(&UdpSessionProtocol::Quic)
            .unwrap()
            .accept_enabled
            .load(Ordering::Relaxed)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((vec![0xc0; 32], peer_addr));
    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((vec![0xc0; 1200], peer_addr));
    socket.incoming_notify.notify_one();

    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut accept_task)
            .await
            .is_err()
    );
    accept_task.abort();
    assert_eq!(layer.active_classified_session_count(), 0);
}

#[tokio::test]
async fn udp_layer_accepts_unclaimed_easy_tier_shaped_wireguard_packet_when_enabled() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = Arc::new(UdpSessionLayer::new(socket.clone()));
    let accept_task = tokio::spawn({
        let layer = layer.clone();
        async move {
            layer
                .accept_classified_session(UdpSessionProtocol::WireGuard)
                .await
        }
    });
    let packet = wireguard_packet_with_easy_tier_data_header(b"accepted-wireguard");

    tokio::time::timeout(Duration::from_secs(1), async {
        while !layer
            .classified_accepts
            .get(&UdpSessionProtocol::WireGuard)
            .unwrap()
            .accept_enabled
            .load(Ordering::Relaxed)
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((packet.clone(), peer_addr));
    socket.incoming_notify.notify_one();

    let accepted = tokio::time::timeout(Duration::from_secs(1), accept_task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let mut buf = [0; 192];
    let len = accepted.recv(&mut buf).await.unwrap();

    assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
    assert_eq!(&buf[..len], packet.as_slice());
    assert_eq!(layer.active_session_count(), 0);
    assert_eq!(layer.active_classified_session_count(), 1);
}

#[tokio::test]
async fn udp_layer_pre_enabled_classified_accept_queues_first_packet() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let packet = wireguard_packet_with_easy_tier_data_header(b"pre-enabled-wireguard");

    layer
        .enable_classified_accept(UdpSessionProtocol::WireGuard)
        .unwrap();
    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((packet.clone(), peer_addr));
    socket.incoming_notify.notify_one();

    let accepted = tokio::time::timeout(
        Duration::from_secs(1),
        layer.accept_classified_session(UdpSessionProtocol::WireGuard),
    )
    .await
    .unwrap()
    .unwrap();
    let mut buf = [0; 192];
    let len = accepted.recv(&mut buf).await.unwrap();

    assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
    assert_eq!(&buf[..len], packet.as_slice());
    assert_eq!(layer.active_session_count(), 0);
    assert_eq!(layer.active_classified_session_count(), 1);
}

#[tokio::test]
async fn udp_layer_routes_quic_like_easytier_packet_to_existing_quic_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let session = layer
        .open_classified_session(UdpSessionProtocol::Quic, peer_addr)
        .unwrap();
    let packet = new_udp_packet(
        |header| {
            header.conn_id.set(0x40);
            header.msg_type = UdpPacketType::Syn as u8;
            header.len.set(8);
        },
        b"12345678",
    )
    .into_bytes()
    .to_vec();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((packet.clone(), peer_addr));
    socket.incoming_notify.notify_one();

    let mut buf = [0; 64];
    let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf[..len], packet.as_slice());
    assert_eq!(layer.active_session_count(), 0);
    assert_eq!(layer.active_classified_session_count(), 1);
}

#[tokio::test]
async fn udp_layer_keeps_easy_tier_syn_out_of_wireguard_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let session = layer
        .open_classified_session(UdpSessionProtocol::WireGuard, peer_addr)
        .unwrap();
    let syn = new_syn_packet(0x1122_3344, 0x5566_7788).into_bytes();

    socket
        .incoming
        .lock()
        .unwrap()
        .push_back((syn.to_vec(), peer_addr));
    socket.incoming_notify.notify_one();

    tokio::time::timeout(Duration::from_secs(1), async {
        while layer.active_session_count() == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut buf = [0; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(50), session.recv(&mut buf))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn easy_tier_mux_udp_session_wraps_sent_payloads() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
        socket.clone(),
        UdpSessionKey::new(peer_addr, conn_id),
        sessions,
    );

    assert_eq!(session.kind(), UdpSessionKind::EasyTierMux);
    assert_eq!(session.send(b"payload").await.unwrap(), 7);

    let sent = wait_for_sent(|| socket.sent(), 1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, peer_addr);

    let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
        .expect("sent datagram should keep EasyTier UDP packet shape");
    let header = packet.udp_tunnel_header().unwrap();
    assert_eq!(header.conn_id.get(), conn_id);
    assert_eq!(header.msg_type, UdpPacketType::Data as u8);
    assert_eq!(header.len.get(), 7);
    assert_eq!(packet.udp_payload(), b"payload");
}

#[tokio::test]
async fn easy_tier_mux_udp_session_rejects_oversized_payload_before_enqueue() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
        socket.clone(),
        UdpSessionKey::new(peer_addr, conn_id),
        sessions,
    );

    let payload = vec![0; u16::MAX as usize + 1];
    let err = session.send(&payload).await.unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    assert!(socket.sent().is_empty());
}

#[tokio::test]
async fn easy_tier_mux_udp_session_send_failure_closes_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let key = UdpSessionKey::new(peer_addr, conn_id);
    let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) = create_test_easy_tier_mux_session(socket, key, sessions.clone());

    let err = tokio::time::timeout(Duration::from_secs(1), session.send(b"payload"))
        .await
        .unwrap()
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
    tokio::time::timeout(Duration::from_secs(1), async {
        while sessions.contains_key(&key) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();

    let mut buf = [0; 16];
    let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn easy_tier_mux_udp_session_receives_only_peer_data_payloads() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let unexpected_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let conn_id = 0x1122_3344;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
        socket,
        UdpSessionKey::new(peer_addr, conn_id),
        sessions.clone(),
    );

    dispatch_data_packet(
        &sessions,
        unexpected_addr,
        conn_id,
        &new_data_packet(conn_id, b"wrong-peer").unwrap(),
        Default::default(),
    );
    dispatch_data_packet(
        &sessions,
        peer_addr,
        conn_id + 1,
        &new_data_packet(conn_id + 1, b"wrong-conn").unwrap(),
        Default::default(),
    );
    dispatch_data_packet(
        &sessions,
        peer_addr,
        conn_id,
        &new_data_packet(conn_id, b"payload").unwrap(),
        Default::default(),
    );

    let mut buf = [0; 16];
    let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(&buf[..len], b"payload");
}

#[tokio::test]
async fn udp_session_layer_connects_with_shared_recv_loop() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());

    let session = tokio::time::timeout(Duration::from_secs(1), layer.connect(peer_addr))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(layer.local_addr().unwrap(), local_addr);
    assert_eq!(session.kind(), UdpSessionKind::EasyTierMux);
    assert_eq!(session.peer_addr().unwrap(), peer_addr);

    let sent = socket.sent();
    assert!(!sent.is_empty());
    let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
        .expect("first sent datagram should be syn");
    assert_eq!(
        packet.udp_tunnel_header().unwrap().msg_type,
        UdpPacketType::Syn as u8
    );
}

#[tokio::test]
async fn cancelled_udp_session_connect_cleans_registered_state() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let layer = UdpSessionLayer::new(socket);

    let result = tokio::time::timeout(Duration::from_millis(50), layer.connect(peer_addr)).await;

    assert!(result.is_err());
    assert!(layer.pending_connects.is_empty());
    assert!(layer.sessions.is_empty());
}

#[tokio::test]
async fn dropping_udp_session_layer_closes_session_recv() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    let layer = UdpSessionLayer::new(socket.clone());
    let session = layer.connect(peer_addr).await.unwrap();
    drop(layer);

    let mut buf = [0; 16];
    let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap_err();

    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn udp_session_recv_loop_error_closes_registered_sessions() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let (session_shutdown_tx, session_shutdown_rx) = watch::channel(false);
    let session = create_test_easy_tier_mux_session_with_shutdown(
        socket.clone(),
        UdpSessionKey::new(peer_addr, conn_id),
        sessions.clone(),
        session_shutdown_rx,
    );
    let pending_connects = Arc::new(DashMap::new());
    let classified_sessions = Arc::new(DashMap::new());
    let classified_accepts = create_classified_udp_session_accepts();
    let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);

    udp_session_layer_recv_task(
        socket,
        sessions.clone(),
        classified_sessions.clone(),
        classified_accepts,
        pending_connects.clone(),
        mux_accepted_tx,
        control_tx,
        Arc::new(NoopUdpSessionStunResponder),
        session_shutdown_tx,
    )
    .await;

    assert!(sessions.is_empty());
    assert!(classified_sessions.is_empty());
    assert!(pending_connects.is_empty());

    let mut buf = [0; 16];
    let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

    let err = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Err(err) = session.send(b"payload").await {
                return err;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn udp_session_layer_accepts_syn_and_sends_sack() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let (mux_accepted_tx, mut mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    handle_new_easy_tier_mux_connect(
        socket.clone(),
        sessions.clone(),
        mux_accepted_tx,
        peer_addr,
        conn_id,
        &new_syn_packet(conn_id, magic),
        shutdown_rx,
    );

    let accepted = tokio::time::timeout(Duration::from_secs(1), mux_accepted_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepted.kind(), UdpSessionKind::EasyTierMux);
    assert_eq!(accepted.peer_addr().unwrap(), peer_addr);
    assert!(sessions.contains_key(&UdpSessionKey::new(peer_addr, conn_id)));

    let sent = wait_for_sent(|| socket.sent(), 1).await;
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].1, peer_addr);
    let packet = parse_udp_session_datagram(BytesMut::from(sent[0].0.as_slice()), false)
        .expect("sent datagram should be sack");
    let header = packet.udp_tunnel_header().unwrap();
    assert_eq!(header.conn_id.get(), conn_id);
    assert_eq!(header.msg_type, UdpPacketType::Sack as u8);
    assert_eq!(packet.udp_payload(), magic.to_le_bytes());
}

#[tokio::test]
async fn duplicate_syn_sack_send_failure_closes_existing_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let key = UdpSessionKey::new(peer_addr, conn_id);
    let socket = Arc::new(FailingSendVirtualUdpSocket { local_addr });
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) =
        create_test_easy_tier_mux_session(socket.clone(), key, sessions.clone());
    let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (_session_shutdown_tx, session_shutdown_rx) = watch::channel(false);

    handle_new_easy_tier_mux_connect(
        socket,
        sessions.clone(),
        mux_accepted_tx,
        peer_addr,
        conn_id,
        &new_syn_packet(conn_id, magic),
        session_shutdown_rx,
    );

    let mut buf = [0; 16];
    let err = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!sessions.contains_key(&key));
}

#[tokio::test]
async fn full_accept_queue_does_not_block_udp_session_recv_loop() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, Vec::new()));
    let sessions = Arc::new(DashMap::new());
    let full_sessions = Arc::new(DashMap::new());
    let (mux_accepted_tx, mut mux_accepted_rx) = mpsc::channel(1);
    let (queued_session, _queued_shutdown_tx) = create_test_easy_tier_mux_session(
        socket.clone(),
        UdpSessionKey::new(SocketAddr::from(([127, 0, 0, 1], 12002)), 7),
        full_sessions,
    );
    mux_accepted_tx.try_send(queued_session).unwrap();
    let (_shutdown_tx, shutdown_rx) = watch::channel(false);

    handle_new_easy_tier_mux_connect(
        socket.clone(),
        sessions.clone(),
        mux_accepted_tx,
        peer_addr,
        conn_id,
        &new_syn_packet(conn_id, magic),
        shutdown_rx,
    );

    assert!(mux_accepted_rx.try_recv().is_ok());
    assert!(!sessions.contains_key(&UdpSessionKey::new(peer_addr, conn_id)));
    assert!(socket.sent().is_empty());
}

#[tokio::test]
async fn udp_session_layer_routes_stun_and_hole_punch_control_packets() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let change_stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12004));
    let rejected_remote_addr = SocketAddr::from(([192, 0, 2, 1], 12001));
    let v4_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let v6_remote_addr = "[::1]:12003".parse::<SocketAddr>().unwrap();
    let dst_v4 = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 1234);
    let dst_v6 = "[2001:db8::1]:2345".parse::<SocketAddrV6>().unwrap();
    let preferred_src = PreferredIpv6Source {
        ip: "2001:db8::2".parse().unwrap(),
        ifindex: 42,
    };
    let stun = easytier_stun_request(false, false);
    let change_stun = easytier_stun_request(true, false);
    let socket = Arc::new(MockVirtualUdpSocket::new(
        local_addr,
        vec![
            (stun.clone(), stun_remote_addr),
            (change_stun.clone(), change_stun_remote_addr),
            (
                new_v4_hole_punch_packet(&dst_v4).into_bytes().to_vec(),
                rejected_remote_addr,
            ),
            (
                new_v4_hole_punch_packet(&dst_v4).into_bytes().to_vec(),
                v4_remote_addr,
            ),
            (
                new_v6_hole_punch_packet(&dst_v6, Some(preferred_src))
                    .into_bytes()
                    .to_vec(),
                v6_remote_addr,
            ),
        ],
    ));
    socket
        .reject_preferred_source
        .store(true, Ordering::Relaxed);
    let stun_responder = Arc::new(MockVirtualUdpSocketFactory::new(13000));
    let layer = UdpSessionLayer::new_with_stun_responder(socket.clone(), stun_responder.clone());

    let mut events = Vec::new();
    for _ in 0..4 {
        events.push(
            tokio::time::timeout(Duration::from_secs(1), layer.recv_control())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(events.contains(&UdpSessionLayerControl::Stun {
        remote_addr: stun_remote_addr,
        datagram: BytesMut::from(stun.as_slice()),
    }));
    assert!(events.contains(&UdpSessionLayerControl::Stun {
        remote_addr: change_stun_remote_addr,
        datagram: BytesMut::from(change_stun.as_slice()),
    }));
    assert!(events.contains(&UdpSessionLayerControl::V4HolePunch {
        remote_addr: v4_remote_addr,
        dst_addr: dst_v4,
    }));
    assert!(events.contains(&UdpSessionLayerControl::V6HolePunch {
        remote_addr: v6_remote_addr,
        dst_addr: dst_v6,
        preferred_src: Some(preferred_src),
    }));
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let responder_sockets = stun_responder.sockets();
            let send_attempts = socket.send_attempts();
            let hole_punch_attempts = send_attempts
                .iter()
                .filter(|attempt| {
                    matches!(attempt.1, SocketAddr::V4(addr) if addr == dst_v4)
                        || matches!(attempt.1, SocketAddr::V6(addr) if addr == dst_v6)
                })
                .count();
            if responder_sockets
                .first()
                .is_some_and(|socket| !socket.sent().is_empty())
                && hole_punch_attempts == 3
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        stun_responder.bind_options(),
        vec![
            UdpBindOptions::hole_punch_control().with_local_addr(Some(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
            )))
        ]
    );
    let responder_sockets = stun_responder.sockets();
    assert_eq!(responder_sockets.len(), 1);
    assert_eq!(
        responder_sockets[0].sent()[0].1,
        change_stun_remote_addr,
        "ChangeRequest STUN responses should be sent through a fresh socket"
    );
    let attempts = socket
        .send_attempts()
        .into_iter()
        .filter(|attempt| {
            matches!(attempt.1, SocketAddr::V4(addr) if addr == dst_v4)
                || matches!(attempt.1, SocketAddr::V6(addr) if addr == dst_v6)
        })
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 3);
    assert!(attempts.iter().all(|attempt| {
        hole_punch_packet_tid(&attempt.0, UDP_SESSION_HOLE_PUNCH_PACKET_BODY_LEN) == Some(1)
    }));
    assert!(attempts.iter().any(|attempt| {
        attempt.1 == SocketAddr::V4(dst_v4) && attempt.2 == UdpSocketSendMeta::default()
    }));
    let preferred_meta = UdpSocketSendMeta {
        src_ip: Some(preferred_src.ip.into()),
        src_ifindex: Some(preferred_src.ifindex),
    };
    let preferred_index = attempts
        .iter()
        .position(|attempt| attempt.1 == SocketAddr::V6(dst_v6) && attempt.2 == preferred_meta)
        .unwrap();
    let fallback_index = attempts
        .iter()
        .position(|attempt| {
            attempt.1 == SocketAddr::V6(dst_v6) && attempt.2 == UdpSocketSendMeta::default()
        })
        .unwrap();
    assert!(preferred_index < fallback_index);
    assert_eq!(attempts[preferred_index].0, attempts[fallback_index].0);
    assert!(
        socket
            .sent()
            .iter()
            .any(|(_, destination)| *destination == stun_remote_addr),
        "normal STUN responses should use the listener socket"
    );
}

#[tokio::test]
async fn udp_session_recv_loop_does_not_wait_for_stun_responder() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 12000));
    let stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let conn_id = 0x1122_3344;
    let mut stun = vec![0; UDP_TUNNEL_HEADER_SIZE];
    stun[4..8].copy_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
    let socket = Arc::new(AutoSackVirtualUdpSocket::new(local_addr));
    socket.incoming.lock().unwrap().extend([
        (stun, stun_remote_addr),
        (
            new_data_packet(conn_id, b"payload")
                .unwrap()
                .into_bytes()
                .to_vec(),
            peer_addr,
        ),
    ]);
    socket.incoming_notify.notify_one();
    let sessions = Arc::new(DashMap::new());
    let (session, _shutdown_tx) = create_test_easy_tier_mux_session(
        socket.clone(),
        UdpSessionKey::new(peer_addr, conn_id),
        sessions.clone(),
    );
    let pending_connects = Arc::new(DashMap::new());
    let classified_sessions = Arc::new(DashMap::new());
    let classified_accepts = create_classified_udp_session_accepts();
    let (mux_accepted_tx, _mux_accepted_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let stun_responder = Arc::new(BlockingUdpSessionStunResponder::default());
    let (session_shutdown_tx, _) = watch::channel(false);
    let recv_task = tokio::spawn(udp_session_layer_recv_task(
        socket,
        sessions,
        classified_sessions,
        classified_accepts,
        pending_connects,
        mux_accepted_tx,
        control_tx,
        stun_responder.clone(),
        session_shutdown_tx,
    ));

    tokio::time::timeout(Duration::from_secs(1), stun_responder.started.notified())
        .await
        .unwrap();

    let mut buf = [0; 16];
    let len = tokio::time::timeout(Duration::from_secs(1), session.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..len], b"payload");

    stun_responder.release.notify_waiters();
    recv_task.abort();
    let _ = recv_task.await;
}

#[tokio::test]
async fn local_hole_punch_control_is_dispatched_to_control_queue() {
    let remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let dst_addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 10), 1234);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    let socket = Arc::new(MockVirtualUdpSocket::new(remote_addr, vec![]));

    dispatch_v4_hole_punch_control(
        socket,
        Arc::new(Semaphore::new(UDP_SESSION_QUEUE_CAPACITY)),
        &control_tx,
        remote_addr,
        &new_v4_hole_punch_packet(&dst_addr),
    );

    assert_eq!(
        control_rx.recv().await.unwrap(),
        UdpSessionLayerControl::V4HolePunch {
            remote_addr,
            dst_addr,
        }
    );
}

#[tokio::test]
async fn sack_from_actual_remote_rekeys_pending_session_before_data_dispatch() {
    let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let sessions = DashMap::new();
    let pending_connects = DashMap::new();
    let expected_key = UdpSessionKey::new(expected_addr, conn_id);
    let actual_key = UdpSessionKey::new(actual_addr, conn_id);
    let session_key = Arc::new(StdMutex::new(None));
    let rings = create_udp_session_rings();
    let entry = udp_session_registry_entry(&rings);
    let mut incoming_rx = rings.session_recv_rx;
    let (control_tx, _control_rx) = mpsc::channel(1);
    let (sack_tx, mut sack_rx) = watch::channel(None);
    control_tx
        .try_send(UdpConnectControl::HolePunch {
            recv_addr: expected_addr,
        })
        .unwrap();
    pending_connects.insert(
        conn_id,
        PendingUdpSessionConnect {
            expected_addr,
            magic,
            session_key: session_key.clone(),
            entry,
            control: control_tx,
            sack: sack_tx,
        },
    );

    dispatch_data_packet(
        &sessions,
        expected_addr,
        conn_id,
        &new_data_packet(conn_id, b"pre-sack").unwrap(),
        Default::default(),
    );
    dispatch_sack_packet(
        &sessions,
        &pending_connects,
        actual_addr,
        conn_id,
        &new_sack_packet(conn_id, magic),
    );
    dispatch_data_packet(
        &sessions,
        actual_addr,
        conn_id,
        &new_data_packet(conn_id, b"payload").unwrap(),
        Default::default(),
    );

    assert!(sessions.contains_key(&actual_key));
    assert!(!sessions.contains_key(&expected_key));
    assert!(pending_connects.is_empty());
    assert_eq!(*session_key.lock().unwrap(), Some(actual_key));
    sack_rx.changed().await.unwrap();
    assert_eq!(*sack_rx.borrow_and_update(), Some(actual_addr));

    let payload = futures::StreamExt::next(&mut incoming_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(payload.payload, BytesMut::from(&b"payload"[..]));
}

#[tokio::test]
async fn replayed_sack_cannot_rekey_pending_session_after_first_success() {
    let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let first_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let replay_addr = SocketAddr::from(([127, 0, 0, 1], 12003));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let sessions = DashMap::new();
    let pending_connects = DashMap::new();
    let expected_key = UdpSessionKey::new(expected_addr, conn_id);
    let first_key = UdpSessionKey::new(first_addr, conn_id);
    let replay_key = UdpSessionKey::new(replay_addr, conn_id);
    let session_key = Arc::new(StdMutex::new(None));
    let rings = create_udp_session_rings();
    let entry = udp_session_registry_entry(&rings);
    let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (sack_tx, mut sack_rx) = watch::channel(None);
    pending_connects.insert(
        conn_id,
        PendingUdpSessionConnect {
            expected_addr,
            magic,
            session_key: session_key.clone(),
            entry,
            control: control_tx,
            sack: sack_tx,
        },
    );

    dispatch_sack_packet(
        &sessions,
        &pending_connects,
        first_addr,
        conn_id,
        &new_sack_packet(conn_id, magic),
    );
    dispatch_sack_packet(
        &sessions,
        &pending_connects,
        replay_addr,
        conn_id,
        &new_sack_packet(conn_id, magic),
    );

    assert!(sessions.contains_key(&first_key));
    assert!(!sessions.contains_key(&expected_key));
    assert!(!sessions.contains_key(&replay_key));
    assert_eq!(*session_key.lock().unwrap(), Some(first_key));
    sack_rx.changed().await.unwrap();
    assert_eq!(*sack_rx.borrow_and_update(), Some(first_addr));
}

#[tokio::test]
async fn stale_sack_after_pending_removal_does_not_register_session() {
    let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let sessions = DashMap::new();
    let pending_connects = DashMap::new();
    let rings = create_udp_session_rings();
    let entry = udp_session_registry_entry(&rings);
    let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (sack_tx, sack_rx) = watch::channel(None);
    pending_connects.insert(
        conn_id,
        PendingUdpSessionConnect {
            expected_addr,
            magic,
            session_key: Arc::new(StdMutex::new(None)),
            entry,
            control: control_tx,
            sack: sack_tx,
        },
    );
    pending_connects.remove(&conn_id);

    dispatch_sack_packet(
        &sessions,
        &pending_connects,
        actual_addr,
        conn_id,
        &new_sack_packet(conn_id, magic),
    );

    assert!(sessions.is_empty());
    assert_eq!(*sack_rx.borrow(), None);
}

#[tokio::test]
async fn sack_after_connect_receiver_drop_removes_registered_session() {
    let expected_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let actual_addr = SocketAddr::from(([127, 0, 0, 1], 12002));
    let conn_id = 0x1122_3344;
    let magic = 0x0102_0304_0506_0708;
    let sessions = DashMap::new();
    let pending_connects = DashMap::new();
    let rings = create_udp_session_rings();
    let entry = udp_session_registry_entry(&rings);
    let (control_tx, _control_rx) = mpsc::channel(UDP_SESSION_QUEUE_CAPACITY);
    let (sack_tx, sack_rx) = watch::channel(None);
    drop(sack_rx);
    pending_connects.insert(
        conn_id,
        PendingUdpSessionConnect {
            expected_addr,
            magic,
            session_key: Arc::new(StdMutex::new(None)),
            entry,
            control: control_tx,
            sack: sack_tx,
        },
    );

    dispatch_sack_packet(
        &sessions,
        &pending_connects,
        actual_addr,
        conn_id,
        &new_sack_packet(conn_id, magic),
    );

    assert!(sessions.is_empty());
}

type MockIncomingDatagrams = VecDeque<Vec<(Vec<u8>, SocketAddr)>>;

struct MockVirtualUdpSocketFactory {
    next_port: AtomicU16,
    bind_options: Mutex<Vec<UdpBindOptions>>,
    sockets: Mutex<Vec<Arc<MockVirtualUdpSocket>>>,
    incoming: Mutex<MockIncomingDatagrams>,
}

impl MockVirtualUdpSocketFactory {
    fn new(next_port: u16) -> Self {
        Self {
            next_port: AtomicU16::new(next_port),
            bind_options: Mutex::new(Vec::new()),
            sockets: Mutex::new(Vec::new()),
            incoming: Mutex::new(VecDeque::new()),
        }
    }

    fn with_socket_incoming(next_port: u16, incoming: Vec<(Vec<u8>, SocketAddr)>) -> Self {
        let factory = Self::new(next_port);
        factory.incoming.lock().unwrap().push_back(incoming);
        factory
    }

    fn bind_options(&self) -> Vec<UdpBindOptions> {
        self.bind_options.lock().unwrap().clone()
    }

    fn sockets(&self) -> Vec<Arc<MockVirtualUdpSocket>> {
        self.sockets.lock().unwrap().clone()
    }
}

#[async_trait]
impl VirtualUdpSocketFactory for MockVirtualUdpSocketFactory {
    type Socket = MockVirtualUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        self.bind_options.lock().unwrap().push(options.clone());
        let local_addr = options.local_addr.unwrap_or_else(|| {
            SocketAddr::from((
                [127, 0, 0, 1],
                self.next_port.fetch_add(1, Ordering::Relaxed),
            ))
        });
        let incoming = self
            .incoming
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_default();
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, incoming));
        self.sockets.lock().unwrap().push(socket.clone());
        Ok(socket)
    }
}

#[tokio::test]
async fn udp_session_dialer_binds_socket_and_returns_wireguard_session() {
    let factory = Arc::new(MockVirtualUdpSocketFactory::new(13000));
    let mut dialer = UdpSessionDialer::new(factory.clone());
    let remote_addr = SocketAddr::from(([192, 0, 2, 10], 11010));
    let bind_addr = SocketAddr::from(([127, 0, 0, 1], 14000));
    let request = UdpSessionConnectRequest::wireguard(remote_addr)
        .with_bind(UdpBindOptions::port_bound_listener(bind_addr));
    let expected_bind = request.bind.clone();

    let session = dialer.connect(request).await.unwrap();

    assert_eq!(factory.bind_options(), vec![expected_bind]);
    assert_eq!(session.kind(), UdpSessionKind::WireGuard);
    assert_eq!(session.local_addr().unwrap(), bind_addr);
    assert_eq!(session.peer_addr().unwrap(), remote_addr);
}

#[tokio::test]
async fn udp_session_socket_listener_builds_port_bound_bind_options() {
    let factory = Arc::new(MockVirtualUdpSocketFactory::new(13000));
    let local_addr = SocketAddr::from(([0, 0, 0, 0], 11010));
    let mut listener = UdpSessionSocketListener::new(
        "udp://0.0.0.0:0".parse().unwrap(),
        local_addr,
        factory.clone(),
    );

    listener.listen().await.unwrap();

    assert_eq!(
        factory.bind_options(),
        vec![UdpBindOptions::port_bound_listener(local_addr).with_only_v6(true)]
    );
    assert_eq!(listener.local_url().port(), Some(11010));
    assert_eq!(listener.connection_counter().get(), Some(0));
    assert!(Arc::ptr_eq(
        &listener.bound_socket().unwrap(),
        &factory.sockets()[0]
    ));
}

#[tokio::test]
async fn udp_session_socket_listener_accepts_easy_tier_mux_session() {
    let local_addr = SocketAddr::from(([127, 0, 0, 1], 11010));
    let peer_addr = SocketAddr::from(([127, 0, 0, 1], 12010));
    let factory = Arc::new(MockVirtualUdpSocketFactory::with_socket_incoming(
        13000,
        vec![(
            new_syn_packet(0x1122_3344, 0x5566_7788)
                .into_bytes()
                .to_vec(),
            peer_addr,
        )],
    ));
    let mut listener =
        UdpSessionSocketListener::new("udp://127.0.0.1:0".parse().unwrap(), local_addr, factory);

    listener.listen().await.unwrap();
    let session = tokio::time::timeout(Duration::from_secs(1), listener.accept_session())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(session.kind(), UdpSessionKind::EasyTierMux);
    assert_eq!(session.local_addr().unwrap(), local_addr);
    assert_eq!(session.peer_addr().unwrap(), peer_addr);
}

#[tokio::test]
async fn udp_session_dialer_uses_factory_as_stun_responder() {
    let remote_addr = SocketAddr::from(([192, 0, 2, 10], 11010));
    let stun_remote_addr = SocketAddr::from(([127, 0, 0, 1], 12001));
    let request = UdpSessionConnectRequest::wireguard(remote_addr);
    let expected_session_bind = request.bind.clone();
    let factory = Arc::new(MockVirtualUdpSocketFactory::with_socket_incoming(
        13000,
        vec![(easytier_stun_request(true, false), stun_remote_addr)],
    ));
    let mut dialer = UdpSessionDialer::new(factory.clone());

    let _session = dialer.connect(request).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let sockets = factory.sockets();
            if sockets.len() == 2 && !sockets[1].sent().is_empty() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        factory.bind_options(),
        vec![
            expected_session_bind,
            UdpBindOptions::hole_punch_control().with_local_addr(Some(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)
            )))
        ]
    );
    let sockets = factory.sockets();
    assert_eq!(sockets[1].sent()[0].1, stun_remote_addr);
}

#[tokio::test]
async fn v4_hole_punch_control_sender_uses_factory_socket() {
    let factory = MockVirtualUdpSocketFactory::new(13000);
    let dst_addr = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 11010);
    let context = SocketContext::default()
        .with_socket_mark(Some(0))
        .with_netns(Some(NetNamespace::new("instance-a")));

    send_v4_hole_punch_control_packet(&factory, context.clone(), 22020, dst_addr)
        .await
        .unwrap();

    assert_eq!(
        factory.bind_options(),
        vec![
            UdpBindOptions::hole_punch_control()
                .with_context(context.with_ip_version(IpVersion::V4))
                .with_local_addr(Some(SocketAddr::V4(SocketAddrV4::new(
                    Ipv4Addr::LOCALHOST,
                    0
                ))))
        ]
    );
    let sockets = factory.sockets();
    assert_eq!(sockets.len(), 1);
    assert_eq!(
        sockets[0].sent(),
        vec![(
            new_v4_hole_punch_packet(&dst_addr).into_bytes().to_vec(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 22020))
        )]
    );
}

#[tokio::test]
async fn v6_hole_punch_control_sender_uses_factory_socket() {
    let factory = MockVirtualUdpSocketFactory::new(13000);
    let dst_addr = "[2001:db8::1]:11010".parse::<SocketAddrV6>().unwrap();
    let preferred_src = PreferredIpv6Source {
        ip: "2001:db8::2".parse().unwrap(),
        ifindex: 42,
    };
    let context = SocketContext::default()
        .with_socket_mark(Some(0))
        .with_netns(Some(NetNamespace::new("instance-a")));

    send_v6_hole_punch_control_packet(
        &factory,
        context.clone(),
        22020,
        dst_addr,
        Some(preferred_src),
    )
    .await
    .unwrap();

    assert_eq!(
        factory.bind_options(),
        vec![
            UdpBindOptions::hole_punch_control()
                .with_context(context.with_ip_version(IpVersion::V6))
                .with_local_addr(Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    0,
                    0,
                    0
                ))))
        ]
    );
    let sockets = factory.sockets();
    assert_eq!(sockets.len(), 1);
    assert_eq!(
        sockets[0].sent(),
        vec![(
            new_v6_hole_punch_packet(&dst_addr, Some(preferred_src))
                .into_bytes()
                .to_vec(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 22020, 0, 0))
        )]
    );
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
fn inspects_easytier_udp_datagram_without_owning_buffer() {
    let packet = new_syn_packet(7, 42).into_bytes();
    let info = inspect_easytier_udp_datagram(&packet).unwrap().unwrap();

    assert_eq!(info.kind, EasyTierUdpPacketKind::Syn);
    assert_eq!(info.conn_id, 7);

    let unknown_packet = new_udp_packet(
        |header| {
            header.conn_id.set(9);
            header.msg_type = 0xff;
            header.len.set(0);
        },
        &[],
    )
    .into_bytes();
    assert_eq!(
        inspect_easytier_udp_datagram(&unknown_packet).unwrap(),
        None
    );

    let mut bad_packet = packet.to_vec();
    bad_packet.pop();

    assert!(matches!(
        inspect_easytier_udp_datagram(&bad_packet),
        Err(EasyTierUdpDatagramInspectError::PayloadLenMismatch { .. })
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

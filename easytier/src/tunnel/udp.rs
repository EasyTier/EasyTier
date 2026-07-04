use std::{
    fmt::Debug,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use easytier_core::socket::udp::{
    EasyTierUdpSessionLayer, UdpSessionConnectError, UdpSessionSocket, VirtualUdpSocket,
    extract_dst_addr_from_v4_hole_punch_packet, extract_v6_hole_punch_packet, is_stun_packet,
    new_sack_packet, parse_udp_session_datagram,
};
pub use easytier_core::{
    hole_punch::udp::new_hole_punch_packet,
    socket::udp::{PreferredIpv6Source, new_v4_hole_punch_packet, new_v6_hole_punch_packet},
};
use futures::{StreamExt, stream::FuturesUnordered};
use zerocopy::AsBytes;

use tokio::{
    net::UdpSocket,
    sync::mpsc::{
        Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
    },
    task::JoinSet,
};
use tokio_util::task::AbortOnDropHandle;
use tracing::{Instrument, instrument};

use super::{
    FromUrl, IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelInfo, TunnelListener,
    TunnelUrl,
    common::wait_for_connect_futures,
    ring::{RingSink, RingSinkSendError, RingStream, create_ring_socket_pair, split_ring_socket},
};
use crate::tunnel::common::bind;
use crate::{
    common::{join_joinset_background, shrink_dashmap},
    tunnel::{
        build_url_from_socket_addr,
        common::{TunnelWrapper, reserve_buf},
        packet_def::{UDP_TUNNEL_HEADER_SIZE, UdpPacketType, ZCPacket, ZCPacketType},
        udp_src,
    },
};

pub const UDP_DATA_MTU: usize = 2000;

type UdpCloseEventSender = UnboundedSender<(SocketAddr, Option<TunnelError>)>;
type UdpCloseEventReceiver = UnboundedReceiver<(SocketAddr, Option<TunnelError>)>;

pub(crate) struct RuntimeUdpSocket {
    socket: Arc<UdpSocket>,
}

impl RuntimeUdpSocket {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

#[async_trait]
impl VirtualUdpSocket for RuntimeUdpSocket {
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        self.socket.send_to(data, addr).await
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        self.socket.recv_from(buf).await
    }
}

pub async fn send_v6_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("[::1]:0").await?;
    let udp_packet = new_v6_hole_punch_packet(&dst_addr, preferred_src);
    let remote_addr = format!("[::1]:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

pub async fn send_v4_hole_punch_packet(
    listener_port: u16,
    dst_addr: SocketAddrV4,
) -> Result<(), TunnelError> {
    let local_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let udp_packet = new_v4_hole_punch_packet(&dst_addr);
    let remote_addr = format!("127.0.0.1:{}", listener_port)
        .parse::<SocketAddr>()
        .unwrap();
    local_socket
        .send_to(&udp_packet.into_bytes(), remote_addr)
        .await?;
    Ok(())
}

async fn respond_stun_packet(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    req_buf: Vec<u8>,
) -> Result<(), anyhow::Error> {
    use crate::common::stun_codec_ext::*;
    use bytecodec::{DecodeExt as _, EncodeExt as _};
    use stun_codec::{
        Message, MessageClass, MessageDecoder, MessageEncoder,
        rfc5389::{attributes::XorMappedAddress, methods::BINDING},
    };

    let mut decoder = MessageDecoder::<Attribute>::new();
    let req_msg = decoder
        .decode_from_bytes(&req_buf)
        .map_err(|e| anyhow::anyhow!("stun decode error: {:?}", e))?
        .map_err(|e| anyhow::anyhow!("stun decode broken message error: {:?}", e))?;

    let tid = req_msg.transaction_id();
    // we only respond easytier stun req, whose tid has 0xdeadbeef prefix
    if tid.as_bytes()[0..4] != [0xde, 0xad, 0xbe, 0xef] {
        anyhow::bail!("stun req tid not from easytier");
    }

    let mut resp_msg = Message::<Attribute>::new(
        MessageClass::SuccessResponse,
        BINDING,
        // we discard the prefix, make sure our implementation is not compatible with other stun client
        u32_to_tid(tid_to_u32(&tid)),
    );
    resp_msg.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

    let mut encoder = MessageEncoder::new();
    let rsp_buf = encoder
        .encode_into_bytes(resp_msg.clone())
        .map_err(|e| anyhow::anyhow!("stun encode error: {:?}", e))?;

    let change_req = req_msg
        .get_attribute::<ChangeRequest>()
        .map(|r| r.ip() || r.port())
        .unwrap_or(false);

    if !change_req {
        socket
            .send_to(&rsp_buf, addr)
            .await
            .with_context(|| "send stun response error")?;
    } else {
        // send from a new udp socket
        let socket = if addr.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0").await?
        } else {
            UdpSocket::bind("[::]:0").await?
        };
        socket.send_to(&rsp_buf, addr).await?;
    }

    tracing::debug!(?addr, ?req_msg, ?change_req, "udp respond stun packet done");
    Ok(())
}

fn get_zcpacket_from_buf(buf: BytesMut, allow_stun: bool) -> Result<ZCPacket, TunnelError> {
    parse_udp_session_datagram(buf, allow_stun)
        .map_err(|err| TunnelError::InvalidPacket(err.to_string()))
}

#[instrument]
async fn forward_from_ring_to_udp(
    mut ring_recv: RingStream,
    socket: &Arc<UdpSocket>,
    addr: &SocketAddr,
    conn_id: u32,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from ring to udp");
    loop {
        let buf = ring_recv.next().await?;
        let packet = match buf {
            Ok(v) => v,
            Err(e) => {
                return Some(e);
            }
        };

        let mut packet = packet.convert_type(ZCPacketType::UDP);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.len.set(udp_payload_len as u16);
        header.msg_type = UdpPacketType::Data as u8;

        let buf = packet.into_bytes();
        tracing::trace!(?udp_payload_len, ?buf, "udp forward from ring to udp");
        let ret = socket.send_to(&buf, &addr).await;
        if ret.is_err() {
            return Some(TunnelError::IOError(ret.unwrap_err()));
        } else if ret.unwrap() == 0 {
            return None;
        }
    }
}

async fn forward_from_ring_to_udp_session(
    mut ring_recv: RingStream,
    session: Arc<dyn UdpSessionSocket>,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from ring to udp session");
    loop {
        let buf = ring_recv.next().await?;
        let packet = match buf {
            Ok(v) => v,
            Err(e) => return Some(e),
        };

        let packet = packet.convert_type(ZCPacketType::UDP);
        let payload = BytesMut::from(packet.udp_payload());
        match session.send(&payload).await {
            Ok(0) => return None,
            Ok(_) => {}
            Err(err) => return Some(TunnelError::IOError(err)),
        }
    }
}

async fn forward_from_udp_session_to_ring(
    session: Arc<dyn UdpSessionSocket>,
    mut ring_sender: RingSink,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from udp session to ring");
    let mut buf = vec![0u8; u16::MAX as usize];
    loop {
        let len = match session.recv(&mut buf).await {
            Ok(0) => return None,
            Ok(len) => len,
            Err(err) => return Some(TunnelError::IOError(err)),
        };

        let zc_packet = match zcpacket_from_udp_session_payload(&buf[..len]) {
            Ok(packet) => packet,
            Err(err) => return Some(err),
        };
        if let Some(err) = send_zcpacket_to_ring(&mut ring_sender, zc_packet) {
            if matches!(err, TunnelError::BufferFull) {
                tracing::trace!(?err, "udp session bridge ring send failed");
                continue;
            }
            return Some(err);
        }
    }
}

fn zcpacket_from_udp_session_payload(payload: &[u8]) -> Result<ZCPacket, TunnelError> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| TunnelError::ExceedMaxPacketSize(u16::MAX as usize, payload.len()))?;
    let mut buf = BytesMut::new();
    buf.resize(UDP_TUNNEL_HEADER_SIZE + payload.len(), 0);
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(payload);

    let mut packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = packet.mut_udp_tunnel_header().unwrap();
    header.msg_type = UdpPacketType::Data as u8;
    header.len.set(payload_len);
    Ok(packet)
}

fn send_zcpacket_to_ring(ring_sender: &mut RingSink, zc_packet: ZCPacket) -> Option<TunnelError> {
    if zc_packet.is_lossy() {
        if let Err(err) = ring_sender.try_send(zc_packet) {
            match err {
                RingSinkSendError::Full(packet) => {
                    tracing::trace!(?packet, "ring sender full, drop lossy packet");
                }
                RingSinkSendError::Closed(_) => return Some(TunnelError::Shutdown),
            }
        }
    } else if let Err(err) = ring_sender.force_send(zc_packet) {
        return match err {
            RingSinkSendError::Full(_) => {
                tracing::trace!("ring sender full, reject non-lossy packet");
                Some(TunnelError::BufferFull)
            }
            RingSinkSendError::Closed(_) => Some(TunnelError::Shutdown),
        };
    }

    None
}

fn map_udp_session_connect_error(error: UdpSessionConnectError) -> TunnelError {
    match error {
        UdpSessionConnectError::Io(error) => TunnelError::IOError(error),
        UdpSessionConnectError::Timeout => TunnelError::InvalidPacket("udp connect timeout".into()),
        UdpSessionConnectError::InvalidPacket(error) => TunnelError::InvalidPacket(error),
    }
}

async fn udp_recv_from_socket_forward_task(
    socket: &UdpSocket,
    buf: &mut BytesMut,
    allow_stun: bool,
) -> Result<(ZCPacket, SocketAddr), TunnelError> {
    loop {
        reserve_buf(buf, UDP_DATA_MTU, UDP_DATA_MTU * 4);
        let (dg_size, addr) = match socket.recv_buf_from(buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(?e, "udp recv from socket error");
                return Err(e.into());
            }
        };
        tracing::trace!(
            "udp recv packet: {:?}, buf: {:?}, size: {}",
            addr,
            buf,
            dg_size
        );

        let zc_packet = match get_zcpacket_from_buf(buf.split(), allow_stun) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(?e, "udp get zc packet from buf error");
                continue;
            }
        };

        return Ok((zc_packet, addr));
    }
}

struct UdpConnection {
    socket: Arc<UdpSocket>,
    conn_id: u32,
    dst_addr: SocketAddr,

    ring_sender: RingSink,
    forward_task: AbortOnDropHandle<()>,
}

impl UdpConnection {
    pub fn new(
        socket: Arc<UdpSocket>,
        conn_id: u32,
        dst_addr: SocketAddr,
        ring_sender: RingSink,
        ring_recv: RingStream,
        close_event_sender: UdpCloseEventSender,
    ) -> Self {
        let s = socket.clone();
        let forward_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let close_event_sender = close_event_sender;
            let err = forward_from_ring_to_udp(ring_recv, &s, &dst_addr, conn_id).await;
            if let Err(e) = close_event_sender.send((dst_addr, err)) {
                tracing::error!(?e, "udp send close event error");
            }
        }));
        Self {
            socket,
            conn_id,
            dst_addr,
            ring_sender,
            forward_task,
        }
    }

    pub fn handle_packet_from_remote(&mut self, zc_packet: ZCPacket) -> Result<(), TunnelError> {
        let header = zc_packet.udp_tunnel_header().unwrap();
        let conn_id = header.conn_id.get();

        if header.msg_type != UdpPacketType::Data as u8 {
            return Err(TunnelError::InvalidPacket("not data packet".to_owned()));
        }

        if self.conn_id != conn_id {
            return Err(TunnelError::ConnIdNotMatch(self.conn_id, conn_id));
        }

        if let Some(err) = send_zcpacket_to_ring(&mut self.ring_sender, zc_packet) {
            return Err(err);
        }

        Ok(())
    }
}

#[derive(Clone)]
struct UdpTunnelListenerData {
    local_url: url::Url,
    socket: Option<Arc<UdpSocket>>,
    sock_map: Arc<DashMap<SocketAddr, UdpConnection>>,
    conn_send: Sender<Box<dyn Tunnel>>,
    close_event_sender: UdpCloseEventSender,
}

impl UdpTunnelListenerData {
    pub fn new(
        local_url: url::Url,
        conn_send: Sender<Box<dyn Tunnel>>,
        close_event_sender: UdpCloseEventSender,
    ) -> Self {
        Self {
            local_url,
            socket: None,
            sock_map: Arc::new(DashMap::new()),
            conn_send,
            close_event_sender,
        }
    }

    async fn handle_new_connect(self, remote_addr: SocketAddr, zc_packet: ZCPacket) {
        let udp_payload = zc_packet.udp_payload();
        if udp_payload.len() != 8 {
            tracing::warn!(
                "udp syn packet payload len not match: {:?}, packet: {:?}",
                udp_payload.len(),
                zc_packet,
            );
            return;
        }
        let magic = u64::from_le_bytes(udp_payload[..8].try_into().unwrap());
        let conn_id = zc_packet.udp_tunnel_header().unwrap().conn_id.get();

        tracing::info!(?conn_id, ?remote_addr, "udp connection accept handling",);
        let socket = self.socket.as_ref().unwrap().clone();

        let sack_buf = new_sack_packet(conn_id, magic).into_bytes();
        if self
            .sock_map
            .get(&remote_addr)
            .is_some_and(|conn| conn.conn_id == conn_id)
        {
            if let Err(e) = socket.send_to(&sack_buf, remote_addr).await {
                tracing::error!(?e, "udp resend sack packet error");
            }
            tracing::debug!(?conn_id, ?remote_addr, "udp duplicate syn, resent sack");
            return;
        }

        let (tunnel_ring, udp_ring) = create_ring_socket_pair(128);
        tracing::debug!(?tunnel_ring, ?udp_ring, "udp build tunnel for listener");

        let (udp_recv, udp_sender) = split_ring_socket(udp_ring);
        let mut new_internal_conn = Some(UdpConnection::new(
            socket.clone(),
            conn_id,
            remote_addr,
            udp_sender,
            udp_recv,
            self.close_event_sender.clone(),
        ));
        let duplicate_syn = match self.sock_map.entry(remote_addr) {
            dashmap::mapref::entry::Entry::Occupied(entry) if entry.get().conn_id == conn_id => {
                true
            }
            dashmap::mapref::entry::Entry::Occupied(mut entry) => {
                entry.insert(new_internal_conn.take().unwrap());
                false
            }
            dashmap::mapref::entry::Entry::Vacant(entry) => {
                entry.insert(new_internal_conn.take().unwrap());
                false
            }
        };
        if duplicate_syn {
            if let Err(e) = socket.send_to(&sack_buf, remote_addr).await {
                tracing::error!(?e, "udp resend sack packet error");
            }
            tracing::debug!(?conn_id, ?remote_addr, "udp duplicate syn, resent sack");
            return;
        }

        if let Err(e) = socket.send_to(&sack_buf, remote_addr).await {
            self.sock_map
                .remove_if(&remote_addr, |_, conn| conn.conn_id == conn_id);
            tracing::error!(?e, "udp send sack packet error");
            return;
        }

        let (tunnel_recv, tunnel_sender) = split_ring_socket(tunnel_ring);
        let conn = Box::new(TunnelWrapper::new(
            Box::new(tunnel_recv),
            Box::new(tunnel_sender),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(self.local_url.clone().into()),
                remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
                ),
            }),
        ));

        tracing::info!(info = ?conn.info().unwrap().remote_addr, "udp connection accept done");

        if let Err(e) = self.conn_send.send(conn).await {
            tracing::warn!(?e, "udp send conn to accept channel error");
        }
    }

    fn do_forward_one_packet_to_conn(&self, zc_packet: ZCPacket, addr: SocketAddr) {
        let header = zc_packet.udp_tunnel_header().unwrap();
        if header.msg_type == UdpPacketType::Syn as u8 {
            tokio::spawn(Self::handle_new_connect(self.clone(), addr, zc_packet));
        } else if is_stun_packet(header.as_bytes()) {
            // ignore stun packet
            tracing::debug!("udp forward packet ignore stun packet");
            let socket = self.socket.as_ref().unwrap().clone();
            tokio::spawn(async move {
                let ret = respond_stun_packet(socket, addr, zc_packet.inner().to_vec()).await;
                if let Err(e) = ret {
                    tracing::error!(?e, "udp respond stun packet error");
                }
            });
        } else if header.msg_type == UdpPacketType::V4HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v4 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv4() {
                tracing::warn!(?addr, "v4 hole punch packet should be sent from ipv4");
                return;
            }
            let Some(dst_addr) =
                extract_dst_addr_from_v4_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v4 hole punch packet");
                return;
            };
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            if let Err(e) = socket.try_send_to(&udp_packet.into_bytes(), SocketAddr::V4(dst_addr)) {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(?dst_addr, "udp forward packet send hole punch packet");
        } else if header.msg_type == UdpPacketType::V6HolePunch as u8 {
            if !addr.ip().is_loopback() {
                tracing::warn!(?addr, "v6 hole punch packet should be from loopback");
                return;
            }
            if !addr.ip().is_ipv6() {
                tracing::warn!(?addr, "v6 hole punch packet should be sent from ipv6");
                return;
            }
            let Some((dst_addr, preferred_src)) =
                extract_v6_hole_punch_packet(zc_packet.udp_payload())
            else {
                tracing::warn!("invalid v6 hole punch packet");
                return;
            };
            let socket = self.socket.as_ref().unwrap().clone();
            let udp_packet = new_hole_punch_packet(1, 32);
            let udp_packet = udp_packet.into_bytes();
            let sent_with_src = if let Some(src) = preferred_src {
                match udp_src::send_to_with_src_ipv6(
                    &socket,
                    src.ip,
                    src.ifindex,
                    dst_addr,
                    &udp_packet,
                ) {
                    Ok(ret) => {
                        tracing::debug!(
                            ?src,
                            ?dst_addr,
                            ?ret,
                            "udp forward packet send hole punch packet with preferred ipv6 source"
                        );
                        true
                    }
                    Err(e) => {
                        tracing::debug!(
                            ?src,
                            ?dst_addr,
                            ?e,
                            "udp forward packet preferred ipv6 source failed, falling back"
                        );
                        false
                    }
                }
            } else {
                false
            };
            if !sent_with_src
                && let Err(e) = socket.try_send_to(&udp_packet, SocketAddr::V6(dst_addr))
            {
                tracing::error!(?e, "udp send hole punch packet error");
            }
            tracing::debug!(
                ?dst_addr,
                ?preferred_src,
                "udp forward packet send hole punch packet"
            );
        } else if header.msg_type != UdpPacketType::HolePunch as u8 {
            let Some(mut conn) = self.sock_map.get_mut(&addr) else {
                tracing::trace!(?header, "udp forward packet error, connection not found");
                return;
            };
            if let Err(e) = conn.handle_packet_from_remote(zc_packet) {
                tracing::trace!(?e, "udp forward packet error");
            }
        } else {
            tracing::trace!(?header, "udp forward packet ignore hole punch packet");
        }
    }

    async fn do_forward_task(self) {
        let socket = self.socket.as_ref().unwrap().clone();
        let mut buf = BytesMut::new();
        loop {
            match udp_recv_from_socket_forward_task(&socket, &mut buf, true).await {
                Ok((zc_packet, addr)) => self.do_forward_one_packet_to_conn(zc_packet, addr),
                Err(e) => {
                    tracing::error!(?e, "udp recv packet error");
                    break;
                }
            }
        }
    }
}

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,

    conn_recv: Receiver<Box<dyn Tunnel>>,
    data: UdpTunnelListenerData,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    close_event_recv: Option<UdpCloseEventReceiver>,
    socket_mark: Option<u32>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (close_event_send, close_event_recv) = unbounded_channel();
        let (conn_send, conn_recv) = channel(100);
        Self {
            addr: addr.clone(),
            socket: None,
            conn_recv,
            data: UdpTunnelListenerData::new(addr, conn_send, close_event_send),
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            close_event_recv: Some(close_event_recv),
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let mut listener = Self::new(addr);
        listener.socket = Some(socket);
        listener
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        if self.socket.is_none() {
            let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
            let tunnel_url: TunnelUrl = self.addr.clone().into();
            self.socket = Some(Arc::new(
                bind()
                    .addr(addr)
                    .only_v6(true)
                    .maybe_dev(tunnel_url.bind_dev())
                    .maybe_socket_mark(self.socket_mark)
                    .call()?,
            ));
        }
        self.data.socket = self.socket.clone();

        self.addr
            .set_port(Some(self.socket.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        self.forward_tasks
            .lock()
            .unwrap()
            .spawn(self.data.clone().do_forward_task());

        let sock_map = Arc::downgrade(&self.data.sock_map.clone());
        let mut close_recv = self.close_event_recv.take().unwrap();
        self.forward_tasks.lock().unwrap().spawn(async move {
            while let Some((dst_addr, err)) = close_recv.recv().await {
                if let Some(err) = err {
                    tracing::error!(?err, "udp close event error");
                }
                if let Some(sock_map) = sock_map.upgrade() {
                    sock_map.remove(&dst_addr);
                    shrink_dashmap(&sock_map, None);
                }
            }
        });

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::info!("start udp accept: {:?}", self.addr);
        if let Some(conn) = self.conn_recv.recv().await {
            return Ok(conn);
        }
        return Err(super::TunnelError::InternalError(
            "udp accept error".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        struct UdpTunnelConnCounter {
            sock_map: Weak<DashMap<SocketAddr, UdpConnection>>,
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                self.sock_map.upgrade().map(|x| x.len() as u32)
            }
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("sock_map_len", &self.get())
                    .finish()
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            sock_map: Arc::downgrade(&self.data.sock_map.clone()),
        }))
    }
}

#[derive(Debug)]
pub struct UdpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,
    socket_mark: Option<u32>,
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
            resolved_addr: None,
            socket_mark: None,
        }
    }

    async fn build_tunnel(
        &self,
        socket: Arc<UdpSocket>,
        layer: Arc<EasyTierUdpSessionLayer<RuntimeUdpSocket>>,
        session: Arc<dyn UdpSessionSocket>,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let (tunnel_ring, udp_ring) = create_ring_socket_pair(128);
        tracing::debug!(?tunnel_ring, ?udp_ring, "udp build tunnel for connector");

        let (ring_recv, ring_sender) = split_ring_socket(udp_ring);
        let send_session = session.clone();
        let recv_session = session.clone();
        let dst_addr = session.peer_addr()?;
        tokio::spawn(
            async move {
                let _layer = layer;
                tokio::select! {
                    err = forward_from_ring_to_udp_session(ring_recv, send_session) => {
                        tracing::debug!(?err, "connector udp ring-to-session task done");
                    }
                    err = forward_from_udp_session_to_ring(recv_session, ring_sender) => {
                        tracing::debug!(?err, "connector udp session-to-ring task done");
                    }
                }
            }
            .instrument(tracing::info_span!(
                "udp forward between session and ring",
                ?dst_addr,
            )),
        );

        let (tunnel_recv, tunnel_sender) = split_ring_socket(tunnel_ring);
        Ok(Box::new(TunnelWrapper::new(
            Box::new(tunnel_recv),
            Box::new(tunnel_sender),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(
                    build_url_from_socket_addr(&socket.local_addr()?.to_string(), "udp").into(),
                ),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&dst_addr.to_string(), "udp").into(),
                ),
            }),
        )))
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("udp connect: {:?}", self.addr);

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.as_ref())?;

        let layer = Arc::new(EasyTierUdpSessionLayer::new(Arc::new(
            RuntimeUdpSocket::new(socket.clone()),
        )));
        let session = layer
            .connect(addr)
            .await
            .map_err(map_udp_session_connect_error)?;
        if session.peer_addr()? != addr {
            tracing::debug!(
                recv_addr = ?session.peer_addr()?,
                ?addr,
                "udp connect addr not match"
            );
        }

        self.build_tunnel(socket, layer, Arc::new(session)).await
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // Route through bind() so socket_mark is applied consistently for
        // both the None (no-op) and Some(_) paths.
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = bind::<UdpSocket>()
            .addr(bind_addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        return self.try_connect_with_socket(Arc::new(socket), addr).await;
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(self.try_connect_with_socket(Arc::new(socket), addr)),
                Err(error) => {
                    tracing::error!(?error, ?bind_addr, ?addr, "bind addr fail");
                    continue;
                }
            }
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }
}

#[cfg(test)]
mod tests {
    use std::{io, net::IpAddr, time::Duration};

    use async_trait::async_trait;
    use easytier_core::socket::udp::UdpSessionKind;
    use futures::SinkExt;
    use rand::Rng;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{
            TunnelConnector,
            common::{
                get_interface_name_by_ip,
                tests::{_tunnel_bench, _tunnel_echo_server, _tunnel_pingpong, wait_for_condition},
            },
            packet_def::PacketType,
        },
    };

    fn new_udp_data_packet(conn_id: u32, packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"udp-data").convert_type(ZCPacketType::UDP);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.msg_type = UdpPacketType::Data as u8;
        header.len.set(udp_payload_len as u16);
        packet
    }

    struct MockUdpSessionSocket {
        recv: tokio::sync::Mutex<Receiver<Vec<u8>>>,
    }

    impl MockUdpSessionSocket {
        fn new(recv: Receiver<Vec<u8>>) -> Self {
            Self {
                recv: tokio::sync::Mutex::new(recv),
            }
        }
    }

    #[async_trait]
    impl UdpSessionSocket for MockUdpSessionSocket {
        fn kind(&self) -> UdpSessionKind {
            UdpSessionKind::EasyTierMux
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }

        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut recv = self.recv.lock().await;
            let Some(data) = recv.recv().await else {
                return Ok(0);
            };
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
        }
    }

    fn assert_sync_packet_handler(_: fn(&mut UdpConnection, ZCPacket) -> Result<(), TunnelError>) {}

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn udp_connection_handler_uses_sync_nonblocking_ring_delivery() {
        assert_sync_packet_handler(UdpConnection::handle_packet_from_remote);

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let dst_addr = "127.0.0.1:1".parse().unwrap();
        let (_tunnel_ring, udp_ring) = create_ring_socket_pair(8);
        let (udp_recv, udp_sender) = split_ring_socket(udp_ring);
        let (close_event_sender, _close_event_recv) = tokio::sync::mpsc::unbounded_channel();
        let mut conn = UdpConnection::new(
            socket,
            7,
            dst_addr,
            udp_sender,
            udp_recv,
            close_event_sender,
        );

        for _ in 0..16 {
            conn.handle_packet_from_remote(new_udp_data_packet(7, PacketType::Data))
                .unwrap();
        }

        let mut got_buffer_full = false;
        for _ in 0..16 {
            match conn.handle_packet_from_remote(new_udp_data_packet(7, PacketType::Ping)) {
                Ok(()) => {}
                Err(TunnelError::BufferFull) => {
                    got_buffer_full = true;
                    break;
                }
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert!(got_buffer_full);
    }

    #[test]
    fn udp_session_bridge_keeps_lossy_ring_delivery_policy() {
        let (_tunnel_ring, udp_ring) = create_ring_socket_pair(8);
        let (_udp_recv, mut udp_sender) = split_ring_socket(udp_ring);

        for _ in 0..16 {
            assert!(
                send_zcpacket_to_ring(&mut udp_sender, new_udp_data_packet(0, PacketType::Data))
                    .is_none()
            );
        }

        let mut got_buffer_full = false;
        for _ in 0..16 {
            match send_zcpacket_to_ring(&mut udp_sender, new_udp_data_packet(0, PacketType::Ping)) {
                None => {}
                Some(TunnelError::BufferFull) => {
                    got_buffer_full = true;
                    break;
                }
                Some(err) => panic!("unexpected error: {err:?}"),
            }
        }
        assert!(got_buffer_full);
    }

    #[tokio::test]
    async fn udp_session_bridge_keeps_running_after_non_lossy_ring_full() {
        let (payload_sender, payload_recv) = channel(32);
        let session = Arc::new(MockUdpSessionSocket::new(payload_recv));
        let (tunnel_ring, udp_ring) = create_ring_socket_pair(8);
        let (_tunnel_recv, _tunnel_sender) = split_ring_socket(tunnel_ring);
        let (_udp_recv, udp_sender) = split_ring_socket(udp_ring);
        let payload = new_udp_data_packet(0, PacketType::Ping)
            .udp_payload()
            .to_vec();

        let mut bridge_task = tokio::spawn(forward_from_udp_session_to_ring(session, udp_sender));
        for _ in 0..16 {
            payload_sender.send(payload.clone()).await.unwrap();
        }

        assert!(
            timeout(Duration::from_millis(100), &mut bridge_task)
                .await
                .is_err(),
            "bridge task must keep running after transient non-lossy BufferFull"
        );
        bridge_task.abort();
    }

    #[tokio::test]
    async fn udp_bench() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5555".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5555".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench_with_bind() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5554".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5554".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn udp_bench_with_bind_fail() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5553".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5553".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    async fn send_random_data_to_socket(remote_url: url::Url) {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket
            .connect(format!(
                "{}:{}",
                remote_url.host().unwrap(),
                remote_url.port().unwrap()
            ))
            .await
            .unwrap();

        // get a random 100-len buf
        loop {
            let mut buf = vec![0u8; 100];
            rand::thread_rng().fill(&mut buf[..]);
            socket.send(&buf).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn udp_multiple_conns() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5557".parse().unwrap());
        listener.listen().await.unwrap();

        let _lis = tokio::spawn(async move {
            loop {
                let ret = listener.accept().await.unwrap();
                assert_eq!(
                    ret.info()
                        .unwrap()
                        .local_addr
                        .unwrap_or_default()
                        .to_string(),
                    listener.local_url().to_string()
                );
                tokio::spawn(async move { _tunnel_echo_server(ret, false).await });
            }
        });

        let mut connector1 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());
        let mut connector2 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());

        let t1 = connector1.connect().await.unwrap();
        let t2 = connector2.connect().await.unwrap();

        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().local_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().remote_addr.unwrap().into()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t2.info().unwrap().remote_addr.unwrap().into()),
        ));

        let sender1 = tokio::spawn(async move {
            let (mut stream, mut sink) = t1.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello1".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t1 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello1".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let sender2 = tokio::spawn(async move {
            let (mut stream, mut sink) = t2.split();

            for i in 0..10 {
                sink.send(ZCPacket::new_with_payload("hello2".as_bytes()))
                    .await
                    .unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t2 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv.payload(), "hello2".as_bytes());
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let _ = tokio::join!(sender1, sender2);
    }

    #[tokio::test]
    async fn bind_multi_ip_to_same_dev() {
        let global_ctx = get_mock_global_ctx();
        let ips = global_ctx
            .get_ip_collector()
            .collect_ip_addrs()
            .await
            .interface_ipv4s;
        if ips.is_empty() {
            return;
        }
        let bind_dev = get_interface_name_by_ip(&IpAddr::V4(ips[0].into()));

        for ip in ips {
            println!("bind to ip: {}, {:?}", ip, bind_dev);
            let addr = SocketAddr::from_url(
                format!("udp://{}:11111", ip).parse().unwrap(),
                IpVersion::Both,
            )
            .await
            .unwrap();
            let _ = bind::<UdpSocket>()
                .addr(addr)
                .maybe_dev(bind_dev.clone())
                .only_v6(true)
                .call()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn bind_same_port() {
        println!("{}", "[::]:8888".parse::<SocketAddr>().unwrap());
        let mut listener = UdpTunnelListener::new("udp://[::]:31014".parse().unwrap());
        let mut listener2 = UdpTunnelListener::new("udp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31015".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = UdpTunnelListener::new("udp://[::1]:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = UdpTunnelListener::new("udp://127.0.0.1:31016".parse().unwrap());
        let mut connector =
            UdpTunnelConnector::new("udp://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }

    #[tokio::test]
    async fn test_conn_counter() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            let _c1 = connector.connect().await.unwrap();
            let _c2 = connector.connect().await.unwrap();
        });

        let conn_counter = listener.get_conn_counter();

        listener.listen().await.unwrap();
        let c1 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(1));
        let c2 = listener.accept().await.unwrap();
        assert_eq!(conn_counter.get(), Some(2));

        drop(c2);
        wait_for_condition(
            || async { conn_counter.get() == Some(1) },
            Duration::from_secs(1),
        )
        .await;

        drop(c1);
        wait_for_condition(
            || async { conn_counter.get().unwrap_or(0) == 0 },
            Duration::from_secs(1),
        )
        .await;
    }

    #[test]
    fn v6_hole_punch_packet_preserves_preferred_source_ifindex() {
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

    #[tokio::test]
    async fn test_v6_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://[::]:0".parse().unwrap());
        lis.listen().await.unwrap();

        // a socket to receive forwarded hole punch packets
        let socket = Arc::new(UdpSocket::bind("[::]:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tracing::info!("lis local addr: {:?}", lis.local_url());
        tracing::info!("socket local addr: {:?}", socket.local_addr().unwrap());

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // a socket to send v6 hole punch packets
        send_v6_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V6(addr_v6) => addr_v6,
                _ => panic!("Expected an IPv6 address"),
            },
            None,
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v6 hole punch packet")
            .unwrap();
    }

    #[tokio::test]
    async fn test_v4_hole_punch_packet() {
        let mut lis = UdpTunnelListener::new("udp://0.0.0.0:0".parse().unwrap());
        lis.listen().await.unwrap();

        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_clone = socket.clone();
        let t = tokio::spawn(async move {
            let mut buf = BytesMut::new();
            buf.resize(128, 0);
            socket_clone.recv_from(&mut buf).await.unwrap();
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        send_v4_hole_punch_packet(
            lis.local_url().port().unwrap(),
            match socket.local_addr().unwrap() {
                std::net::SocketAddr::V4(addr_v4) => addr_v4,
                _ => panic!("Expected an IPv4 address"),
            },
        )
        .await
        .unwrap();

        tokio::time::timeout(tokio::time::Duration::from_secs(2), t)
            .await
            .expect("Timeout waiting for v4 hole punch packet")
            .unwrap();
    }
}

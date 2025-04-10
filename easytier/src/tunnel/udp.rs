use std::{
    fmt::Debug,
    sync::{Arc, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::{stream::FuturesUnordered, StreamExt};
use rand::{Rng, SeedableRng};
use zerocopy::AsBytes;

use std::net::SocketAddr;
use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender, UnboundedReceiver, UnboundedSender},
    task::JoinSet,
};

use tracing::{instrument, Instrument};

use super::TunnelInfo;
use crate::{
    common::{join_joinset_background, scoped_task::ScopedTask},
    tunnel::{
        build_url_from_socket_addr,
        common::{reserve_buf, TunnelWrapper},
        packet_def::{UdpPacketType, ZCPacket, ZCPacketType},
        ring::RingTunnel,
    },
};

use super::{
    common::{setup_sokcet2, setup_sokcet2_ext, wait_for_connect_futures},
    packet_def::{UDPTunnelHeader, UDP_TUNNEL_HEADER_SIZE},
    ring::{RingSink, RingStream},
    IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelListener, TunnelUrl,
};

pub const UDP_DATA_MTU: usize = 2000;

type UdpCloseEventSender = UnboundedSender<(SocketAddr, Option<TunnelError>)>;
type UdpCloseEventReceiver = UnboundedReceiver<(SocketAddr, Option<TunnelError>)>;

fn new_udp_packet<F>(f: F, udp_body: Option<&mut [u8]>) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(
        UDP_TUNNEL_HEADER_SIZE + udp_body.as_ref().map(|v| v.len()).unwrap_or(0),
        0,
    );
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body.unwrap());

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&mut magic.to_le_bytes()),
    )
}

fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        Some(&mut magic.to_le_bytes()),
    )
}

pub fn new_hole_punch_packet(tid: u32, buf_len: u16) -> ZCPacket {
    // generate a 128 bytes vec with random data
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut buf = vec![0u8; buf_len as usize];
    rng.fill(&mut buf[..]);
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::HolePunch as u8;
            header.conn_id.set(tid);
            header.len.set(buf_len);
        },
        Some(&mut buf),
    )
}

fn is_stun_packet(b: &[u8]) -> bool {
    // stun has following pattern:
    // 1. first two bits are 0b00
    // 2. magic cookie between 32-64 bits: 0x2112A442
    b[4..8] == [0x21, 0x12, 0xA4, 0x42] && b[0] & 0xC0 == 0
}

async fn respond_stun_packet(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    req_buf: Vec<u8>,
) -> Result<(), anyhow::Error> {
    use crate::common::stun_codec_ext::*;
    use bytecodec::DecodeExt as _;
    use bytecodec::EncodeExt as _;
    use stun_codec::rfc5389::attributes::MappedAddress;
    use stun_codec::rfc5389::methods::BINDING;
    use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

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
    resp_msg.add_attribute(Attribute::MappedAddress(MappedAddress::new(addr.clone())));

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
            .send_to(&rsp_buf, addr.clone())
            .await
            .with_context(|| "send stun response error")?;
    } else {
        // send from a new udp socket
        let socket = if addr.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0").await?
        } else {
            UdpSocket::bind("[::]:0").await?
        };
        socket.send_to(&rsp_buf, addr.clone()).await?;
    }

    tracing::debug!(?addr, ?req_msg, ?change_req, "udp respond stun packet done");
    Ok(())
}

fn get_zcpacket_from_buf(buf: BytesMut, allow_stun: bool) -> Result<ZCPacket, TunnelError> {
    let dg_size = buf.len();
    if dg_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "udp packet size too small: {:?}, packet: {:?}",
            dg_size, buf
        )));
    }

    if allow_stun && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]) {
        return Ok(ZCPacket::new_from_buf(buf, ZCPacketType::UDP));
    }

    let zc_packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = zc_packet.udp_tunnel_header().unwrap();
    let payload_len = header.len.get() as usize;
    if payload_len != dg_size - UDP_TUNNEL_HEADER_SIZE {
        return Err(TunnelError::InvalidPacket(format!(
            "udp packet payload len not match: header len: {:?}, real len: {:?}",
            payload_len, dg_size
        )));
    }

    Ok(zc_packet)
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
        let Some(buf) = ring_recv.next().await else {
            return None;
        };
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

async fn udp_recv_from_socket_forward_task<F>(socket: Arc<UdpSocket>, allow_stun: bool, mut f: F)
where
    F: FnMut(ZCPacket, SocketAddr) -> (),
{
    let mut buf = BytesMut::new();
    loop {
        reserve_buf(&mut buf, UDP_DATA_MTU, UDP_DATA_MTU * 4);
        let (dg_size, addr) = match socket.recv_buf_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(?e, "udp recv from socket error");
                break;
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

        f(zc_packet, addr);
    }
}

struct UdpConnection {
    socket: Arc<UdpSocket>,
    conn_id: u32,
    dst_addr: SocketAddr,

    ring_sender: RingSink,
    forward_task: ScopedTask<()>,
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
        let forward_task = tokio::spawn(async move {
            let close_event_sender = close_event_sender;
            let err = forward_from_ring_to_udp(ring_recv, &s, &dst_addr, conn_id).await;
            if let Err(e) = close_event_sender.send((dst_addr, err)) {
                tracing::error!(?e, "udp send close event error");
            }
        })
        .into();

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

        if zc_packet.is_lossy() {
            if let Err(e) = self.ring_sender.try_send(zc_packet) {
                tracing::trace!(?e, "ring sender full, drop lossy packet");
            }
        } else {
            if let Err(e) = self.ring_sender.force_send(zc_packet) {
                tracing::trace!(?e, "ring sender full, drop non-lossy packet");
            }
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

    async fn handle_new_connect(self: Self, remote_addr: SocketAddr, zc_packet: ZCPacket) {
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
        if let Err(e) = socket.send_to(&sack_buf, remote_addr).await {
            tracing::error!(?e, "udp send sack packet error");
            return;
        }

        let ring_for_send_udp = Arc::new(RingTunnel::new(128));
        let ring_for_recv_udp = Arc::new(RingTunnel::new(128));
        tracing::debug!(
            ?ring_for_send_udp,
            ?ring_for_recv_udp,
            "udp build tunnel for listener"
        );

        let internal_conn = UdpConnection::new(
            socket.clone(),
            conn_id,
            remote_addr,
            RingSink::new(ring_for_recv_udp.clone()),
            RingStream::new(ring_for_send_udp.clone()),
            self.close_event_sender.clone(),
        );
        self.sock_map.insert(remote_addr, internal_conn);

        let conn = Box::new(TunnelWrapper::new(
            Box::new(RingStream::new(ring_for_recv_udp)),
            Box::new(RingSink::new(ring_for_send_udp)),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(self.local_url.clone().into()),
                remote_addr: Some(
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
        } else if header.msg_type != UdpPacketType::HolePunch as u8 {
            let Some(mut conn) = self.sock_map.get_mut(&addr) else {
                tracing::trace!(?header, "udp forward packet error, connection not found");
                return;
            };
            if let Err(e) = conn.handle_packet_from_remote(zc_packet) {
                tracing::trace!(?e, "udp forward packet error");
            }
        }
    }

    async fn do_forward_task(self: Self) {
        let socket = self.socket.as_ref().unwrap().clone();
        udp_recv_from_socket_forward_task(socket, true, |zc_packet, addr| {
            self.do_forward_one_packet_to_conn(zc_packet, addr);
        })
        .await;
    }
}

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,

    conn_recv: Receiver<Box<dyn Tunnel>>,
    data: UdpTunnelListenerData,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    close_event_recv: Option<UdpCloseEventReceiver>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (close_event_send, close_event_recv) = tokio::sync::mpsc::unbounded_channel();
        let (conn_send, conn_recv) = tokio::sync::mpsc::channel(100);
        Self {
            addr: addr.clone(),
            socket: None,
            conn_recv,
            data: UdpTunnelListenerData::new(addr, conn_send, close_event_send),
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            close_event_recv: Some(close_event_recv),
        }
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), super::TunnelError> {
        let addr = super::check_scheme_and_get_socket_addr::<SocketAddr>(
            &self.addr,
            "udp",
            IpVersion::Both,
        )?;

        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        let tunnel_url: TunnelUrl = self.addr.clone().into();
        if let Some(bind_dev) = tunnel_url.bind_dev() {
            setup_sokcet2_ext(&socket2_socket, &addr, Some(bind_dev))?;
        } else {
            setup_sokcet2(&socket2_socket, &addr)?;
        }

        self.socket = Some(Arc::new(UdpSocket::from_std(socket2_socket.into())?));
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
                sock_map.upgrade().map(|v| v.remove(&dst_addr));
            }
        });

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::info!("start udp accept: {:?}", self.addr);
        while let Some(conn) = self.conn_recv.recv().await {
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
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
        }
    }

    async fn wait_sack(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, TunnelError> {
        let mut buf = BytesMut::new();
        buf.reserve(UDP_DATA_MTU);

        let (usize, recv_addr) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            socket.recv_buf_from(&mut buf),
        )
        .await??;
        let zc_packet = get_zcpacket_from_buf(buf.split(), false)?;
        if recv_addr != addr {
            tracing::warn!(?recv_addr, ?addr, ?usize, "udp wait sack addr not match");
        }

        let header = zc_packet.udp_tunnel_header().unwrap();

        if header.conn_id.get() != conn_id {
            return Err(super::TunnelError::ConnIdNotMatch(
                header.conn_id.get(),
                conn_id,
            ));
        }

        if header.msg_type != UdpPacketType::Sack as u8 {
            return Err(TunnelError::InvalidPacket("not sack packet".to_owned()));
        }

        let payload = zc_packet.udp_payload();
        if payload.len() != 8 {
            return Err(TunnelError::InvalidPacket(
                "udp sack packet payload len not match".to_owned(),
            ));
        }

        let sack_magic = u64::from_le_bytes(payload[..8].try_into().unwrap());
        if sack_magic != magic {
            return Err(TunnelError::InvalidPacket(
                "udp sack magic not match".to_owned(),
            ));
        }

        Ok(recv_addr)
    }

    async fn wait_sack_loop(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
        magic: u64,
    ) -> Result<SocketAddr, super::TunnelError> {
        loop {
            let ret = Self::wait_sack(socket, addr, conn_id, magic).await;
            if ret.is_err() {
                tracing::debug!(?ret, "udp wait sack error");
                continue;
            } else {
                return ret;
            }
        }
    }

    async fn build_tunnel(
        &self,
        socket: Arc<UdpSocket>,
        dst_addr: SocketAddr,
        conn_id: u32,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let ring_for_send_udp = Arc::new(RingTunnel::new(128));
        let ring_for_recv_udp = Arc::new(RingTunnel::new(128));
        tracing::debug!(
            ?ring_for_send_udp,
            ?ring_for_recv_udp,
            "udp build tunnel for connector"
        );

        let (close_event_sender, mut close_event_recv) = tokio::sync::mpsc::unbounded_channel();

        let ring_recv = RingStream::new(ring_for_send_udp.clone());
        let ring_sender = RingSink::new(ring_for_recv_udp.clone());
        let mut udp_conn = UdpConnection::new(
            socket.clone(),
            conn_id,
            dst_addr,
            ring_sender,
            ring_recv,
            close_event_sender,
        );

        let socket_clone = socket.clone();
        tokio::spawn(
            async move {
                tokio::select! {
                    _ = close_event_recv.recv() => {
                        tracing::debug!("connector udp close event");
                        return;
                    }
                    _ = udp_recv_from_socket_forward_task(socket_clone,false, |zc_packet, addr| {
                        tracing::trace!(?addr, "connector udp forward task done");
                        if let Err(e) = udp_conn.handle_packet_from_remote(zc_packet) {
                            tracing::trace!(?e, ?addr, "udp forward packet error");
                        }
                    }) => {
                        tracing::debug!("connector udp forward task done");
                        return;
                    }
                }
            }
            .instrument(tracing::info_span!(
                "udp forward from udp to ring",
                ?conn_id,
                ?dst_addr,
            )),
        );

        Ok(Box::new(TunnelWrapper::new(
            Box::new(RingStream::new(ring_for_recv_udp)),
            Box::new(RingSink::new(ring_for_send_udp)),
            Some(TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(
                    build_url_from_socket_addr(&socket.local_addr()?.to_string(), "udp").into(),
                ),
                remote_addr: Some(self.addr.clone().into()),
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

        // send syn
        let conn_id = rand::random();
        let magic = rand::random();
        let udp_packet = new_syn_packet(conn_id, magic).into_bytes();
        let ret = socket.send_to(&udp_packet, &addr).await?;
        tracing::warn!(?udp_packet, ?ret, "udp send syn");

        // wait sack
        let recv_addr = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            Self::wait_sack_loop(&socket, addr, conn_id, magic),
        )
        .await??;

        if recv_addr != addr {
            tracing::debug!(?recv_addr, ?addr, "udp connect addr not match");
        }

        self.build_tunnel(socket, addr, conn_id).await
    }

    async fn connect_with_default_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let socket = if addr.is_ipv4() {
            UdpSocket::bind("0.0.0.0:0").await?
        } else {
            UdpSocket::bind("[::]:0").await?
        };

        return self.try_connect_with_socket(Arc::new(socket), addr).await;
    }

    async fn connect_with_custom_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(*bind_addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            if let Err(e) = setup_sokcet2(&socket2_socket, bind_addr) {
                tracing::error!(bind_addr = ?bind_addr, ?addr, "bind addr fail: {:?}", e);
                continue;
            }
            let socket = UdpSocket::from_std(socket2_socket.into())?;
            futures.push(self.try_connect_with_socket(Arc::new(socket), addr));
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let addr = super::check_scheme_and_get_socket_addr_ext::<SocketAddr>(
            &self.addr,
            "udp",
            self.ip_version,
        )?;
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
}

#[cfg(test)]
mod tests {
    use std::{net::IpAddr, time::Duration};

    use futures::SinkExt;
    use tokio::time::timeout;

    use super::*;
    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnel::{
            check_scheme_and_get_socket_addr,
            common::{
                get_interface_name_by_ip,
                tests::{_tunnel_bench, _tunnel_echo_server, _tunnel_pingpong, wait_for_condition},
            },
            TunnelConnector,
        },
    };

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
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
            println!("bind to ip: {:?}, {:?}", ip, bind_dev);
            let addr = check_scheme_and_get_socket_addr::<SocketAddr>(
                &format!("udp://{}:11111", ip.to_string()).parse().unwrap(),
                "udp",
                IpVersion::Both,
            )
            .unwrap();
            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            setup_sokcet2_ext(&socket2_socket, &addr, bind_dev.clone()).unwrap();
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
}

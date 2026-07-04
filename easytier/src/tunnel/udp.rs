use std::{
    fmt::Debug,
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use anyhow::Context;
use async_trait::async_trait;
use bytes::BytesMut;
use easytier_core::socket::udp::{
    EasyTierUdpSessionLayer, UdpSessionConnectError, UdpSessionLayerControl, UdpSessionSocket,
    VirtualUdpSocket,
};
pub use easytier_core::{
    hole_punch::udp::new_hole_punch_packet,
    socket::udp::{PreferredIpv6Source, new_v4_hole_punch_packet, new_v6_hole_punch_packet},
};
use futures::{StreamExt, stream::FuturesUnordered};

use tokio::{
    net::UdpSocket,
    sync::mpsc::{Receiver, Sender, channel},
    task::JoinSet,
};
use tracing::Instrument;

use super::{
    FromUrl, IpVersion, Tunnel, TunnelConnCounter, TunnelError, TunnelInfo, TunnelListener,
    TunnelUrl,
    common::wait_for_connect_futures,
    ring::{RingSink, RingSinkSendError, RingStream, create_ring_socket_pair, split_ring_socket},
};
use crate::tunnel::common::bind;
use crate::{
    common::join_joinset_background,
    tunnel::{
        build_url_from_socket_addr,
        common::TunnelWrapper,
        packet_def::{UDP_TUNNEL_HEADER_SIZE, UdpPacketType, ZCPacket, ZCPacketType},
        udp_src,
    },
};

pub const UDP_DATA_MTU: usize = 2000;

pub(crate) struct RuntimeUdpSocket {
    socket: Arc<UdpSocket>,
    easy_tier_layer: StdMutex<Option<Weak<EasyTierUdpSessionLayer<RuntimeUdpSocket>>>>,
}

impl RuntimeUdpSocket {
    pub(crate) fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            easy_tier_layer: StdMutex::new(None),
        }
    }

    pub(crate) fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    pub(crate) fn easy_tier_layer(self: &Arc<Self>) -> Arc<EasyTierUdpSessionLayer<Self>> {
        let mut weak_layer = self.easy_tier_layer.lock().unwrap();
        if let Some(layer) = weak_layer.as_ref().and_then(Weak::upgrade) {
            return layer;
        }

        let layer = Arc::new(EasyTierUdpSessionLayer::new(self.clone()));
        *weak_layer = Some(Arc::downgrade(&layer));
        layer
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

async fn handle_udp_session_control(
    runtime_socket: Arc<RuntimeUdpSocket>,
    control: UdpSessionLayerControl,
) {
    match control {
        UdpSessionLayerControl::Stun {
            remote_addr,
            datagram,
        } => {
            let ret =
                respond_stun_packet(runtime_socket.socket(), remote_addr, datagram.to_vec()).await;
            if let Err(err) = ret {
                tracing::error!(?err, "udp respond stun packet error");
            }
        }
        UdpSessionLayerControl::V4HolePunch {
            remote_addr,
            dst_addr,
        } => {
            let udp_packet = new_hole_punch_packet(1, 32).into_bytes();
            if let Err(err) = runtime_socket
                .socket()
                .try_send_to(&udp_packet, SocketAddr::V4(dst_addr))
            {
                tracing::error!(?err, ?remote_addr, "udp send hole punch packet error");
            }
            tracing::debug!(
                ?remote_addr,
                ?dst_addr,
                "udp control send v4 hole punch packet"
            );
        }
        UdpSessionLayerControl::V6HolePunch {
            remote_addr,
            dst_addr,
            preferred_src,
        } => {
            let socket = runtime_socket.socket();
            let udp_packet = new_hole_punch_packet(1, 32).into_bytes();
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
                            "udp control send v6 hole punch packet with preferred source"
                        );
                        true
                    }
                    Err(err) => {
                        tracing::debug!(
                            ?src,
                            ?dst_addr,
                            ?err,
                            "udp control preferred v6 source failed, falling back"
                        );
                        false
                    }
                }
            } else {
                false
            };
            if !sent_with_src && let Err(err) = socket.try_send_to(&udp_packet, dst_addr.into()) {
                tracing::error!(?err, ?remote_addr, "udp send hole punch packet error");
            }
            tracing::debug!(
                ?remote_addr,
                ?dst_addr,
                ?preferred_src,
                "udp control send v6 hole punch packet"
            );
        }
    }
}

async fn run_udp_session_control_loop(
    layer: Arc<EasyTierUdpSessionLayer<RuntimeUdpSocket>>,
    runtime_socket: Arc<RuntimeUdpSocket>,
) {
    loop {
        match layer.recv_control().await {
            Ok(control) => handle_udp_session_control(runtime_socket.clone(), control).await,
            Err(err) => {
                tracing::debug!(?err, "udp session control loop stopped");
                break;
            }
        }
    }
}

fn build_udp_tunnel_from_session(
    session: Arc<dyn UdpSessionSocket>,
    tunnel_info: TunnelInfo,
    keep_layer_alive: Option<Arc<EasyTierUdpSessionLayer<RuntimeUdpSocket>>>,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let (tunnel_ring, udp_ring) = create_ring_socket_pair(128);
    tracing::debug!(?tunnel_ring, ?udp_ring, "udp build tunnel from session");

    let (ring_recv, ring_sender) = split_ring_socket(udp_ring);
    let send_session = session.clone();
    let recv_session = session.clone();
    let dst_addr = session.peer_addr()?;
    tokio::spawn(
        async move {
            let _keep_layer_alive = keep_layer_alive;
            tokio::select! {
                err = forward_from_ring_to_udp_session(ring_recv, send_session) => {
                    tracing::debug!(?err, "udp ring-to-session task done");
                }
                err = forward_from_udp_session_to_ring(recv_session, ring_sender) => {
                    tracing::debug!(?err, "udp session-to-ring task done");
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
        Some(tunnel_info),
    )))
}

async fn accept_udp_session_tunnels(
    layer: Arc<EasyTierUdpSessionLayer<RuntimeUdpSocket>>,
    conn_send: Sender<Box<dyn Tunnel>>,
    local_url: url::Url,
) {
    loop {
        let session = match layer.accept().await {
            Ok(session) => Arc::new(session) as Arc<dyn UdpSessionSocket>,
            Err(err) => {
                tracing::debug!(?err, "udp session accept loop stopped");
                break;
            }
        };
        let remote_addr = match session.peer_addr() {
            Ok(addr) => addr,
            Err(err) => {
                tracing::debug!(?err, "udp accepted session has invalid peer addr");
                continue;
            }
        };
        let tunnel_info = TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: Some(local_url.clone().into()),
            remote_addr: Some(build_url_from_socket_addr(&remote_addr.to_string(), "udp").into()),
            resolved_remote_addr: Some(
                build_url_from_socket_addr(&remote_addr.to_string(), "udp").into(),
            ),
        };
        let conn = match build_udp_tunnel_from_session(session, tunnel_info, Some(layer.clone())) {
            Ok(conn) => conn,
            Err(err) => {
                tracing::debug!(?err, "udp accepted session build tunnel failed");
                continue;
            }
        };
        tracing::info!(info = ?conn.info().unwrap().remote_addr, "udp connection accept done");

        if let Err(err) = conn_send.send(conn).await {
            tracing::warn!(?err, "udp send conn to accept channel error");
            break;
        }
    }
}

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,
    runtime_socket: Option<Arc<RuntimeUdpSocket>>,
    session_layer: Option<Arc<EasyTierUdpSessionLayer<RuntimeUdpSocket>>>,
    session_layer_ref: Arc<StdMutex<Option<Weak<EasyTierUdpSessionLayer<RuntimeUdpSocket>>>>>,

    conn_send: Sender<Box<dyn Tunnel>>,
    conn_recv: Receiver<Box<dyn Tunnel>>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    socket_mark: Option<u32>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (conn_send, conn_recv) = channel(100);
        Self {
            addr,
            socket: None,
            runtime_socket: None,
            session_layer: None,
            session_layer_ref: Arc::new(StdMutex::new(None)),
            conn_send,
            conn_recv,
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    pub fn new_with_socket(addr: url::Url, socket: Arc<UdpSocket>) -> Self {
        let mut listener = Self::new(addr);
        listener.runtime_socket = Some(Arc::new(RuntimeUdpSocket::new(socket.clone())));
        listener.socket = Some(socket);
        listener
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }

    pub(crate) fn get_runtime_socket(&self) -> Option<Arc<RuntimeUdpSocket>> {
        self.runtime_socket.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        if self.session_layer.is_some() {
            return Ok(());
        }

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

        self.addr
            .set_port(Some(self.socket.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

        let runtime_socket = match self.runtime_socket.clone() {
            Some(socket) => socket,
            None => {
                let socket = Arc::new(RuntimeUdpSocket::new(self.socket.as_ref().unwrap().clone()));
                self.runtime_socket = Some(socket.clone());
                socket
            }
        };
        let layer = runtime_socket.easy_tier_layer();
        *self.session_layer_ref.lock().unwrap() = Some(Arc::downgrade(&layer));
        self.session_layer = Some(layer.clone());

        self.forward_tasks.lock().unwrap().spawn(
            accept_udp_session_tunnels(layer.clone(), self.conn_send.clone(), self.addr.clone())
                .instrument(tracing::info_span!("udp session accept loop")),
        );
        self.forward_tasks.lock().unwrap().spawn(
            run_udp_session_control_loop(layer, runtime_socket)
                .instrument(tracing::info_span!("udp session control loop")),
        );

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
            session_layer: Arc<StdMutex<Option<Weak<EasyTierUdpSessionLayer<RuntimeUdpSocket>>>>>,
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                let session_layer = self.session_layer.lock().unwrap();
                let Some(session_layer) = session_layer.as_ref() else {
                    return Some(0);
                };
                session_layer
                    .upgrade()
                    .map(|layer| layer.active_session_count() as u32)
            }
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("session_count", &self.get())
                    .finish()
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            session_layer: self.session_layer_ref.clone(),
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
        let dst_addr = session.peer_addr()?;
        build_udp_tunnel_from_session(
            session,
            TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: Some(
                    build_url_from_socket_addr(&socket.local_addr()?.to_string(), "udp").into(),
                ),
                remote_addr: Some(self.addr.clone().into()),
                resolved_remote_addr: Some(
                    build_url_from_socket_addr(&dst_addr.to_string(), "udp").into(),
                ),
            },
            Some(layer),
        )
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        self.try_connect_with_runtime_socket(Arc::new(RuntimeUdpSocket::new(socket)), addr)
            .await
    }

    pub(crate) async fn try_connect_with_runtime_socket(
        &self,
        runtime_socket: Arc<RuntimeUdpSocket>,
        addr: SocketAddr,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        tracing::warn!("udp connect: {:?}", self.addr);

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(runtime_socket.socket().as_ref())?;

        let layer = runtime_socket.easy_tier_layer();
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

        self.build_tunnel(runtime_socket.socket(), layer, Arc::new(session))
            .await
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
    use easytier_core::socket::udp::{UdpSessionKind, extract_v6_hole_punch_packet};
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

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn udp_listener_reuses_runtime_socket_session_layer() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let port = socket.local_addr().unwrap().port();
        let mut listener = UdpTunnelListener::new_with_socket(
            format!("udp://127.0.0.1:{port}").parse().unwrap(),
            socket,
        );

        listener.listen().await.unwrap();
        let runtime_socket = listener.get_runtime_socket().unwrap();
        let listener_layer = listener.session_layer.as_ref().unwrap();
        let socket_layer = runtime_socket.easy_tier_layer();

        assert!(Arc::ptr_eq(listener_layer, &socket_layer));
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

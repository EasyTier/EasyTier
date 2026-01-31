use crate::common::acl_processor::PacketInfo;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::PeerId;
use crate::gateway::tcp_proxy::{NatDstConnector, TcpProxy};
use crate::gateway::wrapped_proxy::{ProxyAclHandler, TcpProxyForWrappedSrcTrait};
use crate::gateway::CidrSet;
use crate::peers::peer_manager::PeerManager;
use crate::peers::PeerPacketFilter;
use crate::proto::acl::{ChainType, Protocol};
use crate::proto::api::instance::{
    ListTcpProxyEntryRequest, ListTcpProxyEntryResponse, TcpProxyEntry, TcpProxyEntryState,
    TcpProxyEntryTransportType, TcpProxyRpc,
};
use crate::proto::peer_rpc::KcpConnData as QuicConnData;
use crate::proto::rpc_types;
use crate::proto::rpc_types::controller::BaseController;
use crate::tunnel::packet_def::{
    PacketType, PeerManagerHeader, ZCPacket, ZCPacketType, TAIL_RESERVED_SIZE,
};
use crate::tunnel::quic::{client_config, endpoint_config, server_config};
use anyhow::{anyhow, Context, Error};
use atomic_refcell::AtomicRefCell;
use bytes::{BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use derivative::Derivative;
use derive_more::{Constructor, Deref, DerefMut, From, Into};
use pnet::packet::ipv4::Ipv4Packet;
use prost::Message;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, Endpoint, RecvStream, SendStream, StreamId, TokioRuntime, UdpPoller};
use std::future::Future;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::ptr::copy_nonoverlapping;
use std::sync::{Arc, Weak};
use std::task::Poll;
use std::time::Duration;
use tokio::io::{join, AsyncReadExt, Join};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinSet;
use tokio::time::Instant;
use tokio::{join, pin, select};
use tokio_util::sync::PollSender;
use tracing::{debug, error, info, instrument, trace, warn};

//region packet
#[derive(Debug, Constructor)]
struct QuicPacket {
    addr: SocketAddr,
    payload: BytesMut,
    segment: Option<usize>,
    ecn: Option<EcnCodepoint>,
}

#[derive(Debug, Clone, Copy, From, Into)]
pub struct PacketMargins {
    pub header: usize,
    pub trailer: usize,
}

impl PacketMargins {
    pub fn len(&self) -> usize {
        self.header + self.trailer
    }
}
//endregion

//region socket
#[derive(Debug)]
struct QuicSocketPoller {
    tx: PollSender<QuicPacket>,
}

impl UdpPoller for QuicSocketPoller {
    fn poll_writable(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context,
    ) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .tx
            .poll_reserve(cx)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
    }
}

#[derive(Debug)]
pub struct QuicSocket {
    addr: SocketAddr,
    rx: AtomicRefCell<Receiver<QuicPacket>>,
    tx: Sender<QuicPacket>,
    margins: PacketMargins,
}

impl AsyncUdpSocket for QuicSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::into_pin(Box::new(QuicSocketPoller {
            tx: PollSender::new(self.tx.clone()),
        }))
    }

    fn try_send(&self, transmit: &Transmit) -> std::io::Result<()> {
        match transmit.destination {
            SocketAddr::V4(addr) => {
                let len = transmit.contents.len();
                trace!("{:?} sending {:?} bytes to {:?}", self.addr, len, addr);

                let permit = self.tx.try_reserve().map_err(|e| match e {
                    TrySendError::Full(_) => std::io::ErrorKind::WouldBlock,
                    TrySendError::Closed(_) => std::io::ErrorKind::BrokenPipe,
                })?;

                let segment_size = transmit.segment_size.unwrap_or(len);
                let chunks = transmit.contents.chunks(segment_size);
                let segment = segment_size + self.margins.len();

                let mut payload = BytesMut::with_capacity(chunks.len() * segment);

                for chunk in chunks {
                    unsafe {
                        copy_nonoverlapping(
                            chunk.as_ptr(),
                            payload.as_mut_ptr().add(self.margins.header),
                            segment_size,
                        );
                        payload.advance_mut(segment);
                    }
                }

                permit.send(QuicPacket {
                    addr: transmit.destination,
                    payload,
                    segment: Some(segment),
                    ecn: transmit.ecn,
                });

                Ok(())
            }
            _ => Err(std::io::ErrorKind::ConnectionRefused.into()),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        if bufs.is_empty() || meta.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut rx = self.rx.borrow_mut();
        let mut count = 0;

        for (buf, meta) in bufs.iter_mut().zip(meta.iter_mut()) {
            match rx.poll_recv(cx) {
                Poll::Ready(Some(packet)) => {
                    let len = packet.payload.len();
                    if len > buf.len() {
                        warn!(
                            "buffer too small for packet: {:?} < {:?}, dropped",
                            buf.len(),
                            len,
                        );
                        continue;
                    }
                    trace!(
                        "{:?} received {:?} bytes from {:?}",
                        self.addr,
                        len,
                        packet.addr
                    );
                    buf[0..len].copy_from_slice(&packet.payload);
                    *meta = RecvMeta {
                        addr: packet.addr,
                        len,
                        stride: len,
                        ecn: packet.ecn,
                        dst_ip: None,
                    };
                    count += 1;
                }
                Poll::Ready(None) if count > 0 => break,
                Poll::Ready(None) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionAborted,
                        "socket closed",
                    )))
                }
                Poll::Pending => break,
            }
        }

        if count > 0 {
            Poll::Ready(Ok(count))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        Ok(self.addr)
    }
}
//endregion

//region addr
#[derive(Debug, Clone, Copy, Constructor)]
struct QuicAddr {
    peer_id: PeerId,
    packet_type: PacketType,
}

impl From<QuicAddr> for SocketAddr {
    #[inline]
    fn from(value: QuicAddr) -> Self {
        SocketAddr::new(IpAddr::V4(value.peer_id.into()), value.packet_type as u16)
    }
}

impl TryFrom<SocketAddr> for QuicAddr {
    type Error = ();

    #[inline]
    fn try_from(value: SocketAddr) -> Result<Self, Self::Error> {
        let IpAddr::V4(ipv4) = value.ip() else {
            return Err(());
        };
        let peer_id = ipv4.into();

        let packet_type = match value.port() {
            p if p == PacketType::QuicSrc as u16 => PacketType::QuicSrc,
            p if p == PacketType::QuicDst as u16 => PacketType::QuicDst,
            _ => return Err(()),
        };

        Ok(Self {
            peer_id,
            packet_type,
        })
    }
}
//endregion

//region stream
type QuicStreamInner = Join<RecvStream, SendStream>;
#[derive(Debug, Deref, DerefMut, From, Into)]
struct QuicStream {
    #[deref]
    #[deref_mut]
    inner: QuicStreamInner,
}

impl QuicStream {
    #[inline]
    fn id(&self) -> (StreamId, StreamId) {
        (self.reader().id(), self.writer().id())
    }
}

impl From<(SendStream, RecvStream)> for QuicStream {
    #[inline]
    fn from(value: (SendStream, RecvStream)) -> Self {
        join(value.1, value.0).into()
    }
}
//endregion

#[derive(Debug, Clone)]
pub struct NatDstQuicConnector {
    pub(crate) endpoint: Endpoint,
    pub(crate) peer_mgr: Weak<PeerManager>,
}

#[async_trait::async_trait]
impl NatDstConnector for NatDstQuicConnector {
    type DstStream = QuicStreamInner;

    async fn connect(
        &self,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> crate::common::error::Result<Self::DstStream> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is not available").into());
        };

        let Some(dst_peer_id) = (match nat_dst {
            SocketAddr::V4(addr) => peer_mgr.get_peer_map().get_peer_id_by_ipv4(addr.ip()).await,
            SocketAddr::V6(_) => return Err(anyhow::anyhow!("ipv6 is not supported").into()),
        }) else {
            return Err(anyhow::anyhow!("no peer found for nat dst: {}", nat_dst).into());
        };

        trace!("quic nat dst: {:?}, dst peers: {:?}", nat_dst, dst_peer_id);

        let addr = QuicAddr::new(dst_peer_id, PacketType::QuicSrc).into();
        let header = {
            let conn_data = QuicConnData {
                src: Some(src.into()),
                dst: Some(nat_dst.into()),
            };

            let len = conn_data.encoded_len();
            if len > (u16::MAX as usize) {
                return Err(anyhow!("conn data too large: {:?}", len).into());
            }

            let mut buf = BytesMut::with_capacity(2 + len);

            buf.put_u16(len as u16);
            conn_data.encode(&mut buf).unwrap();

            buf.freeze()
        };

        let mut connect_tasks = JoinSet::<Result<QuicStream, Error>>::new();
        let connect = |tasks: &mut JoinSet<_>| {
            let endpoint = self.endpoint.clone();
            let header = header.clone();

            tasks.spawn(async move {
                let connection = endpoint.connect(addr, "")?.await?;
                let mut stream: QuicStream = connection.open_bi().await?.into();
                stream.writer_mut().write_chunk(header).await?;
                Ok(stream)
            });
        };

        connect(&mut connect_tasks);

        let timer = tokio::time::sleep(Duration::from_millis(200));
        pin!(timer);

        let mut retry_remain = 5;
        loop {
            select! {
                Some(result) = connect_tasks.join_next() => {
                    match result {
                        Ok(Ok(stream)) => return Ok(stream.into()),
                        _ => {
                            if connect_tasks.is_empty() {
                                if retry_remain == 0 {
                                    return Err(anyhow!("failed to connect to nat dst: {:?}", nat_dst).into())
                                }

                                retry_remain -= 1;
                                connect(&mut connect_tasks);
                                timer.as_mut().reset(Instant::now() + Duration::from_millis(200))
                            }
                        }
                    }
                }
                _ = &mut timer, if retry_remain > 0 => {
                    retry_remain -= 1;
                    connect(&mut connect_tasks);
                    timer.as_mut().reset(Instant::now() + Duration::from_millis(200));
                }
            }
        }
    }

    #[inline]
    fn check_packet_from_peer_fast(&self, _cidr_set: &CidrSet, _global_ctx: &GlobalCtx) -> bool {
        true
    }

    #[inline]
    fn check_packet_from_peer(
        &self,
        _cidr_set: &CidrSet,
        _global_ctx: &GlobalCtx,
        hdr: &PeerManagerHeader,
        _ipv4: &Ipv4Packet,
        _real_dst_ip: &mut Ipv4Addr,
    ) -> bool {
        hdr.from_peer_id == hdr.to_peer_id && hdr.is_quic_src_modified()
    }

    #[inline]
    fn transport_type(&self) -> TcpProxyEntryTransportType {
        TcpProxyEntryTransportType::Quic
    }
}

#[derive(Clone)]
struct TcpProxyForQuicSrc(Arc<TcpProxy<NatDstQuicConnector>>);

#[async_trait::async_trait]
impl TcpProxyForWrappedSrcTrait for TcpProxyForQuicSrc {
    type Connector = NatDstQuicConnector;

    #[inline]
    fn get_tcp_proxy(&self) -> &Arc<TcpProxy<Self::Connector>> {
        &self.0
    }

    #[inline]
    fn set_src_modified(hdr: &mut PeerManagerHeader, modified: bool) -> &mut PeerManagerHeader {
        hdr.set_quic_src_modified(modified)
    }

    #[inline]
    async fn check_dst_allow_wrapped_input(&self, dst_ip: &Ipv4Addr) -> bool {
        let Some(peer_manager) = self.0.get_peer_manager() else {
            return false;
        };
        peer_manager
            .check_allow_quic_to_dst(&IpAddr::V4(*dst_ip))
            .await
    }
}

#[derive(Debug)]
enum QuicProxyRole {
    Src,
    Dst,
}

impl QuicProxyRole {
    #[inline]
    const fn incoming(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicDst,
            QuicProxyRole::Dst => PacketType::QuicSrc,
        }
    }

    #[inline]
    const fn outgoing(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicSrc,
            QuicProxyRole::Dst => PacketType::QuicDst,
        }
    }
}

// Receive packets from peers and forward them to the QUIC endpoint
#[derive(Debug)]
struct QuicPacketReceiver {
    tx: Sender<QuicPacket>,
    role: QuicProxyRole,
}

#[async_trait::async_trait]
impl PeerPacketFilter for QuicPacketReceiver {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let header = packet.peer_manager_header().unwrap();

        if header.packet_type != self.role.incoming() as u8 {
            return Some(packet);
        }

        let addr = QuicAddr::new(header.from_peer_id.get(), self.role.outgoing());

        if let Err(e) = self.tx.try_send(QuicPacket::new(
            addr.into(),
            packet.payload_bytes(),
            None,
            None,
        )) {
            debug!("failed to send quic packet to endpoint: {:?}", e);
        }

        None
    }
}

// Send to peers packets received from the QUIC endpoint
#[derive(Debug)]
struct QuicPacketSender {
    peer_mgr: Arc<PeerManager>,
    rx: Receiver<QuicPacket>,

    header: Bytes,
    zc_packet_type: ZCPacketType,
    margins: PacketMargins,
}

impl QuicPacketSender {
    #[instrument]
    pub async fn run(mut self) {
        while let Some(packet) = self.rx.recv().await {
            let Ok(addr) = QuicAddr::try_from(packet.addr) else {
                error!("invalid quic packet addr: {:?}", packet.addr);
                continue;
            };

            let mut payload = packet.payload;
            let segment = packet
                .segment
                .expect("segment size must be set for outgoing quic packet");

            while !payload.is_empty() {
                let mut payload = payload.split_to(segment);
                payload[..self.margins.header].copy_from_slice(&self.header);
                payload.truncate(segment - self.margins.trailer);
                let mut packet = ZCPacket::new_from_buf(payload, self.zc_packet_type);

                packet.fill_peer_manager_hdr(
                    self.peer_mgr.my_peer_id(),
                    addr.peer_id,
                    addr.packet_type as u8,
                );

                if let Err(e) = self.peer_mgr.send_msg_for_proxy(packet, addr.peer_id).await {
                    error!("failed to send QUIC packet to peer: {:?}", e);
                }
            }
        }
    }
}

#[derive(Derivative, Clone)]
#[derivative(Debug)]
struct QuicStreamContext {
    global_ctx: ArcGlobalCtx,
    proxy_entries: Arc<DashMap<(StreamId, StreamId), TcpProxyEntry>>,
    cidr_set: Arc<CidrSet>,
    #[derivative(Debug = "ignore")]
    route: Arc<dyn crate::peers::route_trait::Route + Send + Sync + 'static>,
}

impl QuicStreamContext {
    fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let global_ctx = peer_mgr.get_global_ctx();
        Self {
            global_ctx: global_ctx.clone(),
            proxy_entries: Arc::new(DashMap::new()),
            cidr_set: Arc::new(CidrSet::new(global_ctx.clone())),
            route: Arc::new(peer_mgr.get_route()),
        }
    }
}

struct QuicStreamReceiver {
    endpoint: Endpoint,
    tasks: JoinSet<()>,
    ctx: Arc<QuicStreamContext>,
}

impl QuicStreamReceiver {
    async fn run(mut self) {
        loop {
            select! {
                biased;

                Some(incoming) = self.endpoint.accept() => {
                    let addr = incoming.remote_address();
                    let connection = match incoming.accept() {
                        Ok(connection) => connection,
                        Err(e) => {
                            error!("failed to accept quic connection from {:?}: {:?}", addr, e);
                            continue;
                        }
                    };

                    let addr = connection.remote_address();
                    let connection = match connection.await {
                        Ok(connection) => connection,
                        Err(e) => {
                            error!("failed to accept quic connection from {:?}: {:?}", addr, e);
                            continue;
                        }
                    };

                    let ctx = self.ctx.clone();
                    self.tasks.spawn(async move {
                        let mut tasks = JoinSet::new();
                        loop {
                            select! {
                                biased;

                                e = connection.closed() => {
                                    info!("connection to {:?} closed: {:?}", addr, e);
                                    break;
                                }

                                stream = connection.accept_bi() => {
                                    let stream = match stream {
                                        Ok(stream) => stream.into(),
                                        Err(e) => {
                                            warn!("failed to accept bi stream from {:?}: {:?}", connection.remote_address(), e);
                                            break;
                                        }
                                    };

                                    match Self::establish_stream(stream, ctx.clone()).await {
                                        Ok(stream) => drop(tasks.spawn(stream)),
                                        Err(e) => warn!("failed to establish quic stream from {:?}: {:?}", connection.remote_address(), e),
                                    }
                                }

                                res = tasks.join_next(), if !tasks.is_empty() => {
                                    debug!("quic stream task completed for {:?}: {:?}", addr, res);
                                }
                            }
                        }

                        connection.close(1u32.into(), b"error");
                    });
                }

                _ = self.tasks.join_next(), if !self.tasks.is_empty() => {}
            }
        }
    }

    async fn read_stream_header(stream: &mut QuicStream) -> Result<Bytes, Error> {
        let len = stream.read_u16().await?;
        let mut header = Vec::with_capacity(len as usize);
        stream
            .reader_mut()
            .take(len as u64)
            .read_to_end(&mut header)
            .await?;
        Ok(header.into())
    }

    async fn establish_stream(
        mut stream: QuicStream,
        ctx: Arc<QuicStreamContext>,
    ) -> Result<impl Future<Output = crate::common::error::Result<()>>, Error> {
        let conn_data = Self::read_stream_header(&mut stream).await?;
        let conn_data_parsed = QuicConnData::decode(conn_data.as_ref())
            .context("failed to decode quic stream header")?;

        let handle = stream.id();
        let proxy_entries = &ctx.proxy_entries;
        proxy_entries.insert(
            handle,
            TcpProxyEntry {
                src: conn_data_parsed.src,
                dst: conn_data_parsed.dst,
                start_time: chrono::Local::now().timestamp() as u64,
                state: TcpProxyEntryState::ConnectingDst.into(),
                transport_type: TcpProxyEntryTransportType::Quic.into(),
            },
        );
        crate::defer! {
            proxy_entries.remove(&handle);
            if proxy_entries.capacity() - proxy_entries.len() > 16 {
                proxy_entries.shrink_to_fit();
            }
        }

        let src_socket: SocketAddr = conn_data_parsed
            .src
            .ok_or_else(|| anyhow!("missing src addr in quic stream header"))?
            .into();
        let mut dst_socket: SocketAddr = conn_data_parsed
            .dst
            .ok_or_else(|| anyhow!("missing dst addr in quic stream header"))?
            .into();

        if let IpAddr::V4(dst_v4_ip) = dst_socket.ip() {
            let mut real_ip = dst_v4_ip;
            if ctx.cidr_set.contains_v4(dst_v4_ip, &mut real_ip) {
                dst_socket.set_ip(real_ip.into());
            }
        };

        let src_ip = src_socket.ip();
        let dst_ip = dst_socket.ip();

        let route = ctx.route.clone();
        let (src_groups, dst_groups) = join!(
            route.get_peer_groups_by_ip(&src_ip),
            route.get_peer_groups_by_ip(&dst_ip)
        );

        let global_ctx = ctx.global_ctx.clone();
        if global_ctx.should_deny_proxy(&dst_socket, false) {
            return Err(anyhow::anyhow!(
                "dst socket {:?} is in running listeners, ignore it",
                dst_socket
            ));
        }

        let send_to_self = global_ctx.is_ip_local_virtual_ip(&dst_ip);
        if send_to_self && global_ctx.no_tun() {
            dst_socket = format!("127.0.0.1:{}", dst_socket.port()).parse()?;
        }

        let acl_handler = ProxyAclHandler {
            acl_filter: global_ctx.get_acl_filter().clone(),
            packet_info: PacketInfo {
                src_ip,
                dst_ip,
                src_port: Some(src_socket.port()),
                dst_port: Some(dst_socket.port()),
                protocol: Protocol::Tcp,
                packet_size: conn_data.len(),
                src_groups,
                dst_groups,
            },
            chain_type: if send_to_self {
                ChainType::Inbound
            } else {
                ChainType::Forward
            },
        };
        acl_handler.handle_packet(&conn_data)?;

        debug!("quic connect to dst socket: {:?}", dst_socket);

        let _g = global_ctx.net_ns.guard();
        let connector = crate::gateway::tcp_proxy::NatDstTcpConnector {};
        let ret = connector.connect("0.0.0.0:0".parse()?, dst_socket).await?;

        if let Some(mut e) = proxy_entries.get_mut(&handle) {
            e.state = TcpProxyEntryState::Connected.into();
        }

        Ok(async move {
            acl_handler
                .copy_bidirection_with_acl(stream.inner, ret)
                .await
        })
    }
}

pub struct QuicProxy {
    peer_mgr: Arc<PeerManager>,

    endpoint: Option<Endpoint>,

    src: Option<QuicProxySrc>,
    dst: Option<QuicProxyDst>,

    tasks: JoinSet<()>,
}

impl QuicProxy {
    #[inline]
    pub fn src(&self) -> Option<&QuicProxySrc> {
        self.src.as_ref()
    }

    #[inline]
    pub fn dst(&self) -> Option<&QuicProxyDst> {
        self.dst.as_ref()
    }
}

impl QuicProxy {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            peer_mgr,
            endpoint: None,
            src: None,
            dst: None,
            tasks: JoinSet::new(),
        }
    }

    pub async fn run(&mut self, src: bool, dst: bool) {
        trace!("quic proxy starting");

        if self.endpoint.is_some() {
            error!("quic proxy already running");
            return;
        }

        let (header, zc_packet_type) = {
            let header = ZCPacket::new_with_payload(&[]);
            let zc_packet_type = header.packet_type();
            let payload_offset = header.payload_offset();
            (
                header.inner().split_to(payload_offset).freeze(),
                zc_packet_type,
            )
        };

        let margins = (header.len(), TAIL_RESERVED_SIZE).into();

        // TODO: subject to change
        let (in_tx, in_rx) = channel(1 << 20);
        let (out_tx, out_rx) = channel(1 << 20);

        let socket = QuicSocket {
            addr: SocketAddr::new(Ipv4Addr::from(self.peer_mgr.my_peer_id()).into(), 0),
            rx: AtomicRefCell::new(in_rx),
            tx: out_tx,
            margins,
        };

        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            Some(server_config()),
            Arc::new(socket),
            Arc::new(TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(client_config());
        self.endpoint = Some(endpoint.clone());

        let peer_mgr = self.peer_mgr.clone();
        self.tasks.spawn(
            QuicPacketSender {
                peer_mgr,
                rx: out_rx,
                header,
                zc_packet_type,
                margins,
            }
            .run(),
        );

        let peer_mgr = self.peer_mgr.clone();

        if src {
            if self.src.is_some() {
                error!("quic proxy src already running");
                return;
            }

            let tcp_proxy = TcpProxyForQuicSrc(TcpProxy::new(
                peer_mgr.clone(),
                NatDstQuicConnector {
                    endpoint: endpoint.clone(),
                    peer_mgr: Arc::downgrade(&peer_mgr),
                },
            ));

            let src = QuicProxySrc {
                peer_mgr: peer_mgr.clone(),
                tcp_proxy,
                tx: in_tx.clone(),
            };
            src.run().await;

            self.src = Some(src);
        }

        if dst {
            if self.dst.is_some() {
                error!("quic proxy dst already running");
                return;
            }

            let stream_ctx = Arc::new(QuicStreamContext::new(peer_mgr.clone()));

            let dst = QuicProxyDst {
                peer_mgr: peer_mgr.clone(),
                tx: in_tx.clone(),
                stream_ctx: stream_ctx.clone(),
            };
            dst.run().await;

            self.tasks.spawn(
                QuicStreamReceiver {
                    endpoint: endpoint.clone(),
                    tasks: JoinSet::new(),
                    ctx: stream_ctx,
                }
                .run(),
            );

            self.dst = Some(dst);
        }
    }
}

pub struct QuicProxySrc {
    peer_mgr: Arc<PeerManager>,
    tcp_proxy: TcpProxyForQuicSrc,

    tx: Sender<QuicPacket>,
}

impl QuicProxySrc {
    #[inline]
    pub fn get_tcp_proxy(&self) -> Arc<TcpProxy<NatDstQuicConnector>> {
        self.tcp_proxy.get_tcp_proxy().clone()
    }
}

impl QuicProxySrc {
    async fn run(&self) {
        trace!("quic proxy src starting");
        self.peer_mgr
            .add_nic_packet_process_pipeline(Box::new(self.tcp_proxy.clone()))
            .await;
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(self.tcp_proxy.0.clone()))
            .await;
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(QuicPacketReceiver {
                tx: self.tx.clone(),
                role: QuicProxyRole::Src,
            }))
            .await;
        self.tcp_proxy.0.start(false).await.unwrap();
    }
}

pub struct QuicProxyDst {
    peer_mgr: Arc<PeerManager>,

    tx: Sender<QuicPacket>,
    stream_ctx: Arc<QuicStreamContext>,
}

impl QuicProxyDst {
    async fn run(&self) {
        trace!("quic proxy dst starting");
        self.peer_mgr
            .add_packet_process_pipeline(Box::new(QuicPacketReceiver {
                tx: self.tx.clone(),
                role: QuicProxyRole::Dst,
            }))
            .await;
    }
}

#[derive(Clone, Deref, DerefMut, From, Into)]
pub struct QuicProxyDstRpcService(Weak<DashMap<(StreamId, StreamId), TcpProxyEntry>>);

impl QuicProxyDstRpcService {
    pub fn new(quic_proxy_dst: &QuicProxyDst) -> Self {
        Self(Arc::downgrade(&quic_proxy_dst.stream_ctx.proxy_entries))
    }
}

#[async_trait::async_trait]
impl TcpProxyRpc for QuicProxyDstRpcService {
    type Controller = BaseController;
    async fn list_tcp_proxy_entry(
        &self,
        _: BaseController,
        _request: ListTcpProxyEntryRequest, // Accept request of type HelloRequest
    ) -> Result<ListTcpProxyEntryResponse, rpc_types::error::Error> {
        let mut reply = ListTcpProxyEntryResponse::default();
        if let Some(tcp_proxy) = self.0.upgrade() {
            for item in tcp_proxy.iter() {
                reply.entries.push(*item.value());
            }
        }
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;

    fn init() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("debug")
            .try_init();
    }

    /// 辅助函数：创建一对相互连接的 QuicSocket
    /// socket_a 发送的数据会进入 socket_b 的 rx，反之亦然。
    fn make_socket_pair() -> (QuicSocket, QuicSocket) {
        let addr_a: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        // 两个方向的通道：A->B 和 B->A
        // 容量给够，防止高并发时丢包
        let (tx_a_out, rx_a_out) = channel::<QuicPacket>(50_000);
        let (tx_b_in, rx_b_in) = channel::<QuicPacket>(50_000);

        let (tx_b_out, rx_b_out) = channel::<QuicPacket>(50_000);
        let (tx_a_in, rx_a_in) = channel::<QuicPacket>(50_000);

        let margins = (20, 25).into();

        forward(rx_a_out, tx_b_in, addr_a, margins);
        forward(rx_b_out, tx_a_in, addr_b, margins);

        let socket_a = QuicSocket {
            addr: addr_a,
            rx: AtomicRefCell::new(rx_a_in),
            tx: tx_a_out,
            margins,
        };

        let socket_b = QuicSocket {
            addr: addr_b,
            rx: AtomicRefCell::new(rx_b_in),
            tx: tx_b_out,
            margins,
        };

        (socket_a, socket_b)
    }

    fn endpoint() -> (Endpoint, Endpoint) {
        let endpoint_config = endpoint_config();
        let server_config = server_config();
        let client_config = client_config();

        // 1. 创建内存 Socket 对
        let (socket_client, socket_server) = make_socket_pair();
        let socket_client = Arc::new(socket_client);
        let socket_server = Arc::new(socket_server);

        // 3. 配置 Client Endpoint
        let mut client_endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config.clone(),
            Some(server_config.clone()),
            socket_client.clone(),
            Arc::new(TokioRuntime),
        )
        .unwrap();
        client_endpoint.set_default_client_config(client_config.clone());

        // 2. 配置 Server Endpoint
        let mut server_endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config.clone(),
            Some(server_config.clone()),
            socket_server.clone(),
            Arc::new(TokioRuntime),
        )
        .unwrap();
        server_endpoint.set_default_client_config(client_config.clone());

        (client_endpoint, server_endpoint)
    }

    fn forward(
        mut rx: Receiver<QuicPacket>,
        tx: Sender<QuicPacket>,
        addr: SocketAddr,
        margins: PacketMargins,
    ) {
        const BATCH_SIZE: usize = 128;
        tokio::spawn(async move {
            // 关键优化：使用 buffer 批量处理
            let mut buffer = Vec::with_capacity(BATCH_SIZE);

            // recv_many 会在有数据时唤醒，一次最多拿 100 个包
            // 这比每次拿 1 个包减少了 99 次上下文切换开销
            while rx.recv_many(&mut buffer, BATCH_SIZE).await > 0 {
                for packet in buffer.iter_mut() {
                    // 【过滤逻辑】：在此处修改地址
                    packet.addr = addr;
                    packet.payload.advance(margins.header);
                    packet
                        .payload
                        .truncate(packet.payload.len() - margins.trailer);
                }
                // 批量转发
                for packet in buffer.drain(..) {
                    if let Err(e) = tx.send(packet).await {
                        info!("{:?}", e);
                        return; // 通道已关闭
                    }
                }
            }
        });
    }

    #[tokio::test]
    async fn test_ping() -> anyhow::Result<()> {
        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // 4. Server 接收任务
        let server_handle = tokio::spawn(async move {
            println!("Server: Waiting for connection...");
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                println!(
                    "Server: Connection accepted from {}",
                    connection.remote_address()
                );

                // 接收双向流
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();

                // 读取数据
                let mut buf = vec![0u8; 10];
                recv.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping______");
                println!("Server: Received 'ping______'");

                // 发送回复
                send.write_all(b"pong______").await.unwrap();
                send.finish().unwrap();

                let _ = connection.closed().await;
            }
        });

        // 5. Client 发起连接
        // 注意：这里的 connect 地址必须是 V4，因为你的 try_send 限制了 SocketAddr::V4
        println!("Client: Connecting...");
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        println!("Client: Connected!");

        // 打开流并发送数据
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"ping______").await?;
        send.finish()?;

        // 读取回复
        let mut buf = vec![0u8; 10];
        recv.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"pong______");
        println!("Client: Received 'pong______'");

        // 6. 清理
        connection.close(0u32.into(), b"done");
        // 等待 Server 结束
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "consumes massive memory (~16GB)"]
    async fn test_bandwidth() -> anyhow::Result<()> {
        // --- 3. 定义测试数据量 ---
        // 测试总量: 512 MB
        const TOTAL_SIZE: usize = 32768 * 1024 * 1024;
        // 每次写入块大小: 1 MB (模拟大块写入)
        const CHUNK_SIZE: usize = 1024 * 1024;

        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // --- 4. Server 端 (接收并计时) ---
        let server_handle = tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                // 接收单向流
                let mut recv = connection.accept_uni().await.unwrap();

                let start = std::time::Instant::now();
                let mut received = 0;

                // 循环读取直到流结束
                // read_chunk 比 read_exact 性能稍好，因为它减少了内部 buffer拷贝
                while let Some(chunk) = recv.read_chunk(usize::MAX, true).await.unwrap() {
                    received += chunk.bytes.len();
                }

                let duration = start.elapsed();
                assert_eq!(received, TOTAL_SIZE, "Data length mismatch");

                let seconds = duration.as_secs_f64();
                let mbps = (received as f64 * 8.0) / (1_000_000.0 * seconds);
                let gbps = mbps / 1000.0;

                println!("--------------------------------------------------");
                println!("Server Recv Statistics:");
                println!("  Total Data: {} MB", received / 1024 / 1024);
                println!("  Duration  : {:.2?}", duration);
                println!("  Throughput: {:.2} Gbps ({:.2} Mbps)", gbps, mbps);
                println!("--------------------------------------------------");

                // 保持连接直到 Client 断开
                let _ = connection.closed().await;
            }
        });

        // --- 5. Client 端 (发送) ---
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        let mut send = connection.open_uni().await?;

        // 构造一个 1MB 的数据块
        let data_chunk = vec![0u8; CHUNK_SIZE];
        let bytes_data = Bytes::from(data_chunk); // 使用 Bytes 避免重复分配

        println!("Client: Start sending {} MB...", TOTAL_SIZE / 1024 / 1024);
        let start_send = std::time::Instant::now();

        let chunks = TOTAL_SIZE / CHUNK_SIZE;
        for _ in 0..chunks {
            // write_chunk 配合 Bytes 使用效率最高
            send.write_chunk(bytes_data.clone()).await?;
        }

        // 告诉对端发送完毕
        send.finish()?;
        // 等待流彻底关闭（确保对方收到了 FIN）
        send.stopped().await?;

        let send_duration = start_send.elapsed();
        println!("Client: Send finished in {:.2?}", send_duration);

        // 关闭连接
        connection.close(0u32.into(), b"done");

        // 等待 Server 打印结果
        let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "consumes massive memory (~16GB)"]
    async fn test_bandwidth_parallel() -> anyhow::Result<()> {
        // --- 1. 配置参数 ---
        const STREAM_COUNT: usize = 16; // 并发流数量
        const STREAM_SIZE: usize = 1024 * 1024 * 1024; // 每个流发送 256KB

        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // --- 3. Server 端 (并发接收器) ---
        let server_handle = tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                println!("Server: Accepted connection");

                let mut stream_handles = Vec::new();
                let start = std::time::Instant::now();

                // 接收预期数量的流
                for i in 0..STREAM_COUNT {
                    match connection.accept_uni().await {
                        Ok(mut recv) => {
                            // 为每个流启动一个独立的处理任务
                            let handle = tokio::spawn(async move {
                                // 读取所有数据
                                match recv.read_to_end(usize::MAX).await {
                                    Ok(data) => {
                                        // 校验长度
                                        assert_eq!(
                                            data.len(),
                                            STREAM_SIZE,
                                            "Stream {} length mismatch",
                                            i
                                        );
                                        // 校验数据内容 (验证数据隔离性)
                                        // 我们约定数据的第一个字节是 (stream_index % 255)
                                        // 这样可以确保流的数据没串
                                        let expected_byte = data[0] as usize; // 获取实际收到的标记
                                                                              // 这里只是简单校验首尾，实际生产可以使用 CRC
                                        if data[data.len() - 1] != data[0] {
                                            panic!("Stream data corruption");
                                        }
                                        expected_byte // 返回标记用于统计
                                    }
                                    Err(e) => panic!("Stream read error: {}", e),
                                }
                            });
                            stream_handles.push(handle);
                        }
                        Err(e) => panic!("Failed to accept stream {}: {}", i, e),
                    }
                }

                // 等待所有流处理完毕
                let results = futures::future::join_all(stream_handles).await;
                let duration = start.elapsed();

                let speed = ((STREAM_COUNT * STREAM_SIZE) as f64 * 8.0)
                    / (duration.as_secs_f64() * 1_000_000.0);

                println!("--------------------------------------------------");
                println!("Server: All {} streams received processing.", results.len());
                println!("Total Time: {:.2?}", duration);
                println!(
                    "Total Data: {} MB",
                    (STREAM_COUNT * STREAM_SIZE) / 1024 / 1024
                );
                println!(
                    "Average Speed: {:.2} Gbps ({:.2} Mbps)",
                    speed / 1024.0,
                    speed
                );
                println!("--------------------------------------------------");

                // 保持连接直到 Client 断开
                let _ = connection.closed().await;
            }
        });

        // --- 4. Client 端 (并发发送器) ---
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        println!(
            "Client: Connected, starting {} parallel streams...",
            STREAM_COUNT
        );

        let start_send = std::time::Instant::now();
        let mut client_tasks = Vec::new();

        // 并发启动发送任务
        for i in 0..STREAM_COUNT {
            let conn = connection.clone();
            client_tasks.push(tokio::spawn(async move {
                // 打开单向流
                let mut send = conn.open_uni().await.expect("Failed to open stream");

                // 构造数据：为了验证隔离性，我们用 i 作为填充标记
                // 所有的字节都填成 (i % 255)
                let fill_byte = (i % 255) as u8;
                let data = vec![fill_byte; STREAM_SIZE];
                let bytes_data = Bytes::from(data);

                send.write_chunk(bytes_data).await.expect("Write failed");
                send.finish().expect("Finish failed");
                // 等待 Server 确认收到 FIN
                send.stopped().await.expect("Stopped failed");
            }));
        }

        // 等待所有发送任务完成
        futures::future::join_all(client_tasks).await;

        let send_duration = start_send.elapsed();
        println!("Client: All streams sent in {:.2?}", send_duration);

        // 关闭连接
        connection.close(0u32.into(), b"done");

        // 等待 Server 结束
        let _ = tokio::time::timeout(Duration::from_secs(10), server_handle).await;

        Ok(())
    }
}

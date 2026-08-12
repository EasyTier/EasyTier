use super::hedge::HedgeExt;
use crate::proto::peer_rpc::KcpConnData as QuicConnData;
use crate::tunnel::quic::{client_config, endpoint_config, server_config};
use anyhow::{Context, Error, anyhow, ensure};
use atomic_refcell::AtomicRefCell;
use bytes::{BufMut, Bytes, BytesMut};
use derive_more::{Constructor, Deref, DerefMut, From, Into};
use easytier_core::config::PeerId;
use easytier_core::packet::{PacketType, TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType};
use moka::future::Cache;
use prost::Message;
use quinn::udp::{EcnCodepoint, RecvMeta, Transmit};
use quinn::{
    AsyncUdpSocket, Connection, ConnectionError, Endpoint, RecvStream, SendStream, UdpPoller,
    WriteError, default_runtime,
};
use std::cmp::min;
use std::io::IoSliceMut;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::ptr::copy_nonoverlapping;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;
use tokio::io::{AsyncReadExt, Join, join};
use tokio::select;
use tokio::sync::Mutex;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::timeout;
use tokio_util::sync::{CancellationToken, PollSender};
use tracing::{debug, error, info, instrument, trace, warn};

use easytier_core::{
    gateway::proxy::traits::TcpProxyStream,
    gateway::proxy::wrapped_transport::{
        WrappedTransportAcceptedStream, WrappedTransportConnect, WrappedTransportDatagram,
        WrappedTransportDatagramBuffer, WrappedTransportDestinationIngress, WrappedTransportEngine,
        WrappedTransportEngineStart, WrappedTransportKind, WrappedTransportRole,
    },
};

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
        let tx = &mut self.get_mut().tx;

        let poll = tx.poll_reserve(cx);
        if let Poll::Ready(Ok(_)) = poll {
            tx.abort_send();
        }

        poll.map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))
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

                // The length of the last chunk could be smaller than segment_size
                for chunk in chunks {
                    let len = chunk.len();
                    unsafe {
                        copy_nonoverlapping(
                            chunk.as_ptr(),
                            payload.chunk_mut().as_mut_ptr().add(self.margins.header),
                            len,
                        );
                        payload.advance_mut(len + self.margins.len());
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
                        self.addr, len, packet.addr
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
                    )));
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
    pub(crate) conn_map: Cache<PeerId, Connection>,
}

impl NatDstQuicConnector {
    async fn connect_to_peer(
        &self,
        dst_peer: PeerId,
        src: SocketAddr,
        nat_dst: SocketAddr,
    ) -> anyhow::Result<QuicStreamInner> {
        tracing::trace!(?nat_dst, ?dst_peer, "quic nat");

        let header = {
            let conn_data = QuicConnData {
                src: Some(src.into()),
                dst: Some(nat_dst.into()),
            };

            let len = conn_data.encoded_len();
            ensure!(len <= u16::MAX as usize, "conn data too large: {len}");

            let mut buf = BytesMut::with_capacity(2 + len);

            buf.put_u16(len as u16);
            conn_data.encode(&mut buf)?;

            buf.freeze()
        };

        let reconnect = || async move {
            self.conn_map.invalidate(&dst_peer).await;

            let connect = (0..5)
                .map(|_| {
                    let endpoint = self.endpoint.clone();
                    async move {
                        endpoint
                            .connect(QuicAddr::new(dst_peer, PacketType::QuicSrc).into(), "")
                            .context("failed to create connection")?
                            .await
                            .context("connection failed")
                    }
                })
                .hedge(Duration::from_millis(200));

            self.conn_map
                .try_get_with(dst_peer, connect)
                .await
                .context("failed to connect to peer")
        };

        let mut reconnected = false;

        let mut connection = if let Some(connection) = self.conn_map.get(&dst_peer).await
            && connection.close_reason().is_none()
        {
            connection
        } else {
            reconnected = true;
            reconnect().await?
        };

        loop {
            let is_retryable = |error: &ConnectionError| {
                matches!(
                    error,
                    ConnectionError::ConnectionClosed(_)
                        | ConnectionError::ApplicationClosed(_)
                        | ConnectionError::Reset
                        | ConnectionError::TimedOut
                )
            };
            let mut retry = !reconnected;
            let header = header.clone();
            let result = async {
                let mut stream: QuicStream = connection
                    .open_bi()
                    .await
                    .inspect_err(|error| retry &= is_retryable(error))?
                    .into();
                stream
                    .writer_mut()
                    .write_chunk(header)
                    .await
                    .inspect_err(|error| {
                        retry &= matches!(error, WriteError::ConnectionLost(error) if is_retryable(error))
                    })?;
                Ok(stream.into())
            }
                .await;

            if let Err(error) = &result {
                if retry {
                    debug!(?error, "failed to open quic stream, retrying...");
                    reconnected = true;
                    connection = reconnect().await?;
                    continue;
                } else {
                    self.conn_map.invalidate(&dst_peer).await;
                }
            }

            break result;
        }
    }
}

#[derive(Debug)]
enum QuicProxyRole {
    Src,
    Dst,
}

impl QuicProxyRole {
    #[inline]
    const fn outgoing(&self) -> PacketType {
        match self {
            QuicProxyRole::Src => PacketType::QuicSrc,
            QuicProxyRole::Dst => PacketType::QuicDst,
        }
    }
}

// Send to peers packets received from the QUIC endpoint
#[derive(Debug)]
struct QuicPacketSender {
    datagrams: Sender<WrappedTransportDatagram>,
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
                let len = min(payload.len(), segment);
                let mut payload = payload.split_to(len);
                payload[..self.margins.header].copy_from_slice(&self.header);
                payload.truncate(len - self.margins.trailer);
                let role = match addr.packet_type {
                    PacketType::QuicSrc => WrappedTransportRole::Source,
                    PacketType::QuicDst => WrappedTransportRole::Destination,
                    packet_type => {
                        error!(?packet_type, "invalid QUIC proxy output packet type");
                        continue;
                    }
                };
                if self
                    .datagrams
                    .send(WrappedTransportDatagram {
                        transport: WrappedTransportKind::Quic,
                        role,
                        peer_id: addr.peer_id,
                        buffer: WrappedTransportDatagramBuffer::from_packet_buffer(
                            payload,
                            self.zc_packet_type,
                        ),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

struct QuicStreamReceiver {
    endpoint: Endpoint,
    tasks: JoinSet<()>,
    destination_ingress: WrappedTransportDestinationIngress,
    cancel: CancellationToken,
}

impl QuicStreamReceiver {
    async fn run(mut self) {
        loop {
            select! {
                biased;

                _ = self.cancel.cancelled() => break,

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
                    let connection = select! {
                        biased;
                        _ = self.cancel.cancelled() => break,
                        result = connection => {
                            match result {
                                Ok(connection) => connection,
                                Err(e) => {
                                    error!("failed to accept quic connection from {:?}: {:?}", addr, e);
                                    continue;
                                }
                            }
                        }
                    };

                    let destination_ingress = self.destination_ingress.clone();
                    let cancel = self.cancel.clone();
                    self.tasks.spawn(async move {
                        let mut tasks = JoinSet::new();
                        loop {
                            select! {
                                biased;

                                _ = cancel.cancelled() => break,

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

                                    let destination_ingress = destination_ingress.clone();
                                    tasks.spawn(async move {
                                        if let Err(e) = Self::submit_stream(stream, destination_ingress).await {
                                            warn!("failed to submit quic stream: {:?}", e);
                                        }
                                    });
                                }

                                res = tasks.join_next(), if !tasks.is_empty() => {
                                    debug!("quic stream task completed for {:?}: {:?}", addr, res);
                                }
                            }
                        }

                        tasks.shutdown().await;
                        connection.close(1u32.into(), b"error");
                    });
                }

                _ = self.tasks.join_next(), if !self.tasks.is_empty() => {}

                else => {
                    info!("quic stream receiver endpoint closed, exiting");
                    break;
                }
            }
        }
        if self.cancel.is_cancelled() {
            while self.tasks.join_next().await.is_some() {}
        } else {
            self.tasks.shutdown().await;
        }
    }

    async fn read_stream_header(stream: &mut QuicStream) -> Result<Bytes, Error> {
        const STREAM_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
        const STREAM_HEADER_LIMIT: u16 = 512;
        let len = timeout(STREAM_HEADER_READ_TIMEOUT, stream.read_u16())
            .await
            .context("timeout reading header length")??;
        if len > STREAM_HEADER_LIMIT {
            return Err(anyhow::anyhow!("stream header too long"));
        }
        let mut header = Vec::with_capacity(len as usize);
        timeout(
            STREAM_HEADER_READ_TIMEOUT,
            stream
                .reader_mut()
                .take(len as u64)
                .read_to_end(&mut header),
        )
        .await
        .context("timeout reading header")??;
        Ok(header.into())
    }

    async fn submit_stream(
        mut stream: QuicStream,
        destination_ingress: WrappedTransportDestinationIngress,
    ) -> Result<(), Error> {
        let conn_data = Self::read_stream_header(&mut stream).await?;
        let conn_data_parsed = QuicConnData::decode(conn_data.as_ref())
            .context("failed to decode quic stream header")?;

        let src_socket: SocketAddr = conn_data_parsed
            .src
            .ok_or_else(|| anyhow!("missing src addr in quic stream header"))?
            .into();
        let dst_socket: SocketAddr = conn_data_parsed
            .dst
            .ok_or_else(|| anyhow!("missing dst addr in quic stream header"))?
            .into();

        destination_ingress
            .submit(WrappedTransportAcceptedStream {
                src: src_socket,
                dst: dst_socket,
                initial_acl_packet_size: conn_data.len(),
                stream: Box::new(stream.inner),
            })
            .await
    }
}

pub struct QuicProxy {
    endpoint: Option<Endpoint>,
    input_tx: Option<Arc<Sender<QuicPacket>>>,

    source_connector: Option<NatDstQuicConnector>,
    destination_ingress: Option<WrappedTransportDestinationIngress>,

    tasks: JoinSet<()>,
    stream_cancel: CancellationToken,
    stream_task: Option<JoinHandle<()>>,
}

impl QuicProxy {
    pub fn new() -> Self {
        Self {
            endpoint: None,
            input_tx: None,
            source_connector: None,
            destination_ingress: None,
            tasks: JoinSet::new(),
            stream_cancel: CancellationToken::new(),
            stream_task: None,
        }
    }

    pub async fn prepare(
        &mut self,
        my_peer_id: u32,
        src: bool,
        destination_ingress: Option<WrappedTransportDestinationIngress>,
        datagrams: Sender<WrappedTransportDatagram>,
    ) {
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

        let (in_tx, in_rx) = channel(1024);
        let in_tx = Arc::new(in_tx);
        self.input_tx = Some(in_tx.clone());
        let (out_tx, out_rx) = channel(1024);

        let socket = QuicSocket {
            addr: SocketAddr::new(Ipv4Addr::from(my_peer_id).into(), 0),
            rx: AtomicRefCell::new(in_rx),
            tx: out_tx,
            margins,
        };

        let mut endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config(),
            Some(server_config()),
            Arc::new(socket),
            default_runtime().unwrap(),
        )
        .unwrap(); // TODO: maybe a different transport config
        endpoint.set_default_client_config(client_config());
        self.endpoint = Some(endpoint.clone());

        self.tasks.spawn(
            QuicPacketSender {
                datagrams,
                rx: out_rx,
                header,
                zc_packet_type,
                margins,
            }
            .run(),
        );

        if src {
            if self.source_connector.is_some() {
                error!("quic proxy src already running");
                return;
            }

            self.source_connector = Some(NatDstQuicConnector {
                endpoint: endpoint.clone(),
                conn_map: Cache::builder()
                    .max_capacity(u8::MAX.into()) // cf. quinn transport config (max_concurrent_bidi_streams)
                    .time_to_idle(Duration::from_secs(600)) // cf. quinn transport config (max_idle_timeout)
                    .build(),
            });
        }

        if let Some(destination_ingress) = destination_ingress {
            if self.destination_ingress.is_some() {
                error!("quic proxy dst already running");
                return;
            }
            self.destination_ingress = Some(destination_ingress);
        }
    }

    async fn activate(&mut self) -> anyhow::Result<()> {
        if let Some(destination_ingress) = self.destination_ingress.as_ref() {
            let endpoint = self
                .endpoint
                .as_ref()
                .cloned()
                .ok_or_else(|| anyhow!("QUIC endpoint is not prepared"))?;
            self.stream_task = Some(tokio::spawn(
                QuicStreamReceiver {
                    endpoint,
                    tasks: JoinSet::new(),
                    destination_ingress: destination_ingress.clone(),
                    cancel: self.stream_cancel.clone(),
                }
                .run(),
            ));
        }
        Ok(())
    }

    async fn stop(&mut self) {
        self.stream_cancel.cancel();
        if let Some(task) = self.stream_task.as_mut() {
            let _ = task.await;
        }
        self.stream_task.take();
        self.tasks.shutdown().await;
        if let Some(endpoint) = self.endpoint.take() {
            endpoint.close(1u32.into(), b"stopped");
        }
    }
}

pub struct QuicProxyService {
    state: Mutex<Option<QuicProxy>>,
}

impl QuicProxyService {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }
}

#[async_trait::async_trait]
impl WrappedTransportEngine for QuicProxyService {
    async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if state.is_some() {
            return Ok(());
        }
        let directions = options.directions;
        let destination_ingress = if directions.destination {
            Some(
                options
                    .destination_ingress
                    .ok_or_else(|| anyhow!("QUIC destination ingress is required"))?,
            )
        } else {
            None
        };

        let mut proxy = QuicProxy::new();
        if directions.source || directions.destination {
            proxy
                .prepare(
                    options.my_peer_id,
                    directions.source,
                    destination_ingress,
                    options.datagrams,
                )
                .await;
        }

        *state = Some(proxy);
        Ok(())
    }

    async fn activate(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        state
            .as_mut()
            .ok_or_else(|| anyhow!("QUIC engine is not prepared"))?
            .activate()
            .await
    }

    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()> {
        let tx = {
            let state = self.state.lock().await;
            state.as_ref().and_then(|proxy| proxy.input_tx.clone())
        }
        .ok_or_else(|| anyhow!("QUIC endpoint is not active"))?;
        let role = match role {
            WrappedTransportRole::Source => QuicProxyRole::Src,
            WrappedTransportRole::Destination => QuicProxyRole::Dst,
        };
        tx.try_send(QuicPacket::new(
            QuicAddr::new(from_peer_id, role.outgoing()).into(),
            payload.into(),
            None,
            None,
        ))
        .map_err(|error| anyhow!("failed to inject QUIC datagram: {error}"))
    }

    async fn connect_source(
        &self,
        request: WrappedTransportConnect,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
        let connector = {
            let state = self.state.lock().await;
            state
                .as_ref()
                .and_then(|proxy| proxy.source_connector.clone())
        }
        .ok_or_else(|| anyhow!("QUIC source endpoint is not prepared"))?;
        let stream = connector
            .connect_to_peer(request.dst_peer_id, request.src, request.dst)
            .await?;
        Ok(Box::new(stream))
    }

    async fn stop(&self) {
        let mut state = self.state.lock().await;
        if let Some(active) = state.as_mut() {
            active.stop().await;
        }
        state.take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Buf;
    use quanta::Instant;

    /// Helper function: Create a pair of interconnected QuicSockets.
    /// Data sent by socket_a will enter socket_b's rx, and vice versa.
    fn make_socket_pair() -> (QuicSocket, QuicSocket) {
        let addr_a: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.1:5001".parse().unwrap();

        // Bidirectional channels: A->B and B->A
        // Sufficient capacity to prevent packet loss during high concurrency
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

        // 1. Create an in-memory Socket pair
        let (socket_client, socket_server) = make_socket_pair();
        let socket_client = Arc::new(socket_client);
        let socket_server = Arc::new(socket_server);

        // 3. Configure Client Endpoint
        let mut client_endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config.clone(),
            Some(server_config.clone()),
            socket_client.clone(),
            default_runtime().unwrap(),
        )
        .unwrap();
        client_endpoint.set_default_client_config(client_config.clone());

        // 2. Configure Server Endpoint
        let mut server_endpoint = Endpoint::new_with_abstract_socket(
            endpoint_config.clone(),
            Some(server_config.clone()),
            socket_server.clone(),
            default_runtime().unwrap(),
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
            // Key optimization: use buffer for batch processing
            let mut buffer = Vec::with_capacity(BATCH_SIZE);

            // recv_many wakes up when data is available, taking up to 100 packets at a time
            // This reduces context switch overhead by 99 times compared to taking 1 packet at a time
            while rx.recv_many(&mut buffer, BATCH_SIZE).await > 0 {
                for packet in buffer.iter_mut() {
                    // [Filter Logic]: Modify address here
                    packet.addr = addr;
                    packet.payload.advance(margins.header);
                    packet
                        .payload
                        .truncate(packet.payload.len() - margins.trailer);
                }
                // Batch forward
                for packet in buffer.drain(..) {
                    if let Err(e) = tx.send(packet).await {
                        info!("{:?}", e);
                        return; // Channel closed
                    }
                }
            }
        });
    }

    #[tokio::test]
    async fn test_ping() -> anyhow::Result<()> {
        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // 4. Server receive task
        let server_handle = tokio::spawn(async move {
            println!("Server: Waiting for connection...");
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                println!(
                    "Server: Connection accepted from {}",
                    connection.remote_address()
                );

                // Accept bidirectional stream
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();

                // Read data
                let mut buf = vec![0u8; 10];
                recv.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping______");
                println!("Server: Received 'ping______'");

                // Send reply
                send.write_all(b"pong______").await.unwrap();
                send.finish().unwrap();

                let _ = connection.closed().await;
            }
        });

        // 5. Client initiates connection
        // Note: The connect address here must be V4, because try_send is limited to SocketAddr::V4
        println!("Client: Connecting...");
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        println!("Client: Connected!");

        // Open a stream and send data
        let (mut send, mut recv) = connection.open_bi().await?;
        send.write_all(b"ping______").await?;
        send.finish()?;

        // Read reply
        let mut buf = vec![0u8; 10];
        recv.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"pong______");
        println!("Client: Received 'pong______'");

        // 6. Cleanup
        connection.close(0u32.into(), b"done");
        // Wait for Server to finish
        let _ = tokio::time::timeout(Duration::from_secs(2), server_handle).await;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "consumes massive memory (~16GB)"]
    async fn test_bandwidth() -> anyhow::Result<()> {
        // --- 3. Define test data volume ---
        // Total test size: 512 MB
        const TOTAL_SIZE: usize = 32768 * 1024 * 1024;
        // Write chunk size: 1 MB (simulate large chunk write)
        const CHUNK_SIZE: usize = 1024 * 1024;

        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // --- 4. Server side (receive and timing) ---
        let server_handle = tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                // Accept unidirectional stream
                let mut recv = connection.accept_uni().await.unwrap();

                let start = Instant::now();
                let mut received = 0;

                // Loop read until the stream ends
                // read_chunk performs slightly better than read_exact because it reduces internal buffer copying
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

                // Keep connection until the Client disconnects
                let _ = connection.closed().await;
            }
        });

        // --- 5. Client side (send) ---
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        let mut send = connection.open_uni().await?;

        // Construct a 1MB data chunk
        let data_chunk = vec![0u8; CHUNK_SIZE];
        let bytes_data = Bytes::from(data_chunk); // Use Bytes to avoid repeated allocation

        println!("Client: Start sending {} MB...", TOTAL_SIZE / 1024 / 1024);
        let start_send = Instant::now();

        let chunks = TOTAL_SIZE / CHUNK_SIZE;
        for _ in 0..chunks {
            // write_chunk is most efficient when used with Bytes
            send.write_chunk(bytes_data.clone()).await?;
        }

        // Tell peer sending is finished
        send.finish()?;
        // Wait for the stream to close completely (ensure peer received FIN)
        send.stopped().await?;

        let send_duration = start_send.elapsed();
        println!("Client: Send finished in {:.2?}", send_duration);

        // Close connection
        connection.close(0u32.into(), b"done");

        // Wait for Server to print results
        let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

        Ok(())
    }

    #[tokio::test]
    #[ignore = "consumes massive memory (~16GB)"]
    async fn test_bandwidth_parallel() -> anyhow::Result<()> {
        // --- 1. Configuration parameters ---
        const STREAM_COUNT: usize = 16; // Number of concurrent streams
        const STREAM_SIZE: usize = 1024 * 1024 * 1024; // Each stream sends 1GB

        let (client_endpoint, server_endpoint) = endpoint();
        let server_addr = server_endpoint.local_addr()?;

        // --- 3. Server side (concurrent receiver) ---
        let server_handle = tokio::spawn(async move {
            if let Some(conn) = server_endpoint.accept().await {
                let connection = conn.await.unwrap();
                println!("Server: Accepted connection");

                let mut stream_handles = Vec::new();
                let start = Instant::now();

                // Accept an expected number of streams
                for i in 0..STREAM_COUNT {
                    match connection.accept_uni().await {
                        Ok(mut recv) => {
                            // Start an independent processing task for each stream
                            let handle = tokio::spawn(async move {
                                // Read all data
                                match recv.read_to_end(usize::MAX).await {
                                    Ok(data) => {
                                        // Verify length
                                        assert_eq!(
                                            data.len(),
                                            STREAM_SIZE,
                                            "Stream {} length mismatch",
                                            i
                                        );
                                        // Verify data content (verify data isolation)
                                        // We agree that the first byte of data is (stream_index % 255)
                                        // This ensures stream data is not mixed
                                        let expected_byte = data[0] as usize; // Get the actual received marker
                                        // Simple check of head and tail here, CRC can be used in production
                                        if data[data.len() - 1] != data[0] {
                                            panic!("Stream data corruption");
                                        }
                                        expected_byte // Return marker for statistics
                                    }
                                    Err(e) => panic!("Stream read error: {}", e),
                                }
                            });
                            stream_handles.push(handle);
                        }
                        Err(e) => panic!("Failed to accept stream {}: {}", i, e),
                    }
                }

                // Wait for all streams to finish processing
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

                // Keep connection until the Client disconnects
                let _ = connection.closed().await;
            }
        });

        // --- 4. Client side (concurrent sender) ---
        let connection = client_endpoint.connect(server_addr, "localhost")?.await?;
        println!(
            "Client: Connected, starting {} parallel streams...",
            STREAM_COUNT
        );

        let start_send = Instant::now();
        let mut client_tasks = Vec::new();

        // Start sending tasks concurrently
        for i in 0..STREAM_COUNT {
            let conn = connection.clone();
            client_tasks.push(tokio::spawn(async move {
                // Open unidirectional stream
                let mut send = conn.open_uni().await.expect("Failed to open stream");

                // Construct data: use i as the padding marker to verify isolation
                // All bytes are filled with (i % 255)
                let fill_byte = (i % 255) as u8;
                let data = vec![fill_byte; STREAM_SIZE];
                let bytes_data = Bytes::from(data);

                send.write_chunk(bytes_data).await.expect("Write failed");
                send.finish().expect("Finish failed");
                // Wait for Server to acknowledge receipt of FIN
                send.stopped().await.expect("Stopped failed");
            }));
        }

        // Wait for all sending tasks to complete
        futures::future::join_all(client_tasks).await;

        let send_duration = start_send.elapsed();
        println!("Client: All streams sent in {:.2?}", send_duration);

        // Close connection
        connection.close(0u32.into(), b"done");

        // Wait for Server to finish
        let _ = tokio::time::timeout(Duration::from_secs(10), server_handle).await;

        Ok(())
    }

    #[tokio::test]
    async fn test_gso() {
        let margins = PacketMargins {
            header: 20,
            trailer: 25,
        };
        let (tx, rx) = channel(10);

        let socket = QuicSocket {
            addr: "127.0.0.1:0".parse().unwrap(),
            rx: AtomicRefCell::new(rx),
            tx,
            margins,
        };

        let total_len = 3000;
        let segment_size = 1000;
        let mut contents = Vec::with_capacity(total_len);

        contents.extend(vec![1u8; 1000]);
        contents.extend(vec![2u8; 1000]);
        contents.extend(vec![3u8; 1000]);

        let transmit = Transmit {
            destination: "127.0.0.1:8000".parse().unwrap(),
            ecn: None,
            contents: &contents,
            segment_size: Some(segment_size),
            src_ip: None,
        };

        socket.try_send(&transmit).unwrap();

        let mut rx = socket.rx.into_inner();
        let packet = rx.recv().await.unwrap();

        let actual_segment_size = segment_size + margins.len();
        let payload = packet.payload;

        let chunk1_start = margins.header;
        let chunk1_data = &payload[chunk1_start..chunk1_start + segment_size];
        assert_eq!(chunk1_data[0], 1u8, "Chunk 1 corrupted");

        let chunk2_start = actual_segment_size + margins.header;
        let chunk2_data = &payload[chunk2_start..chunk2_start + segment_size];
        assert_eq!(chunk2_data[0], 2u8, "Chunk 2 corrupted");

        let chunk3_start = actual_segment_size * 2 + margins.header;
        let chunk3_data = &payload[chunk3_start..chunk3_start + segment_size];
        assert_eq!(chunk3_data[0], 3u8, "Chunk 3 corrupted");
    }
}

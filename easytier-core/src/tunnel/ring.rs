use std::{
    collections::HashMap,
    fmt::Debug,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};

use crate::{
    proto::common::TunnelInfo,
    socket::ring::{
        RING_SOCKET_CAPACITY, RingSocket, RingSocketId, RingSocketReceiver, RingSocketSendError,
        RingSocketSender,
    },
    tunnel::{SinkError, SinkItem, StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream},
};

pub const RING_TUNNEL_CAP: usize = RING_SOCKET_CAPACITY;

type RingItem = SinkItem;
pub type RingTunnelSocket = RingSocket<RingItem>;
pub type RingSinkSendError = RingSocketSendError<RingItem>;

pub struct RingByteStream {
    receiver: RingSocketReceiver<RingItem>,
    sender: RingSocketSender<RingItem>,
    buffered: Option<(RingItem, usize)>,
}

impl RingByteStream {
    pub fn new(socket: Arc<RingTunnelSocket>) -> io::Result<Self> {
        let (receiver, sender) = socket
            .try_split()
            .map_err(|error| io::Error::other(error.to_string()))?;
        Ok(Self {
            receiver,
            sender,
            buffered: None,
        })
    }
}

impl AsyncRead for RingByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if let Some((packet, offset)) = &mut self.buffered {
                if *offset == packet.payload().len() {
                    self.buffered = None;
                    continue;
                }
                let remaining = &packet.payload()[*offset..];
                let copy_len = remaining.len().min(buffer.remaining());
                buffer.put_slice(&remaining[..copy_len]);
                *offset += copy_len;
                return Poll::Ready(Ok(()));
            }

            match ready!(Pin::new(&mut self.receiver).poll_next(cx)) {
                Some(Ok(packet)) => self.buffered = Some((packet, 0)),
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error.to_string()))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for RingByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Pin::new(&mut self.sender).poll_ready(cx))
            .map_err(|error| io::Error::other(error.to_string()))?;
        Pin::new(&mut self.sender)
            .start_send(crate::packet::ZCPacket::new_with_payload(buffer))
            .map_err(|error| io::Error::other(error.to_string()))?;
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sender)
            .poll_flush(cx)
            .map_err(|error| io::Error::other(error.to_string()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.sender)
            .poll_close(cx)
            .map_err(|error| io::Error::other(error.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RingTunnelRegistryError {
    #[error("ring listener already registered: {0}")]
    AlreadyRegistered(RingSocketId),
    #[error("ring listener not found: {0}")]
    NotFound(RingSocketId),
    #[error("ring listener closed: {0}")]
    Closed(RingSocketId),
    #[error("ring listener {listener_id} received socket for {socket_id}")]
    SocketIdMismatch {
        listener_id: RingSocketId,
        socket_id: RingSocketId,
    },
}

struct PendingRingConnection {
    client: Arc<RingTunnelSocket>,
    server: Arc<RingTunnelSocket>,
}

type ConnectionMap = HashMap<RingSocketId, UnboundedSender<Arc<PendingRingConnection>>>;

#[derive(Default)]
pub struct RingTunnelRegistry {
    connections: Mutex<ConnectionMap>,
}

impl RingTunnelRegistry {
    pub fn bind(
        self: &Arc<Self>,
        local_id: RingSocketId,
    ) -> Result<RingTunnelSocketListener, RingTunnelRegistryError> {
        let (conn_sender, conn_receiver) = unbounded_channel();
        let mut connections = self.connections.lock().unwrap();
        if connections.contains_key(&local_id) {
            return Err(RingTunnelRegistryError::AlreadyRegistered(local_id));
        }

        connections.insert(local_id, conn_sender.clone());
        Ok(RingTunnelSocketListener {
            registry: self.clone(),
            local_id,
            conn_sender,
            conn_receiver,
        })
    }

    pub fn connect(
        &self,
        remote_id: RingSocketId,
    ) -> Result<DialedRingSocket, RingTunnelRegistryError> {
        let conn_sender = self
            .connections
            .lock()
            .unwrap()
            .get(&remote_id)
            .cloned()
            .ok_or(RingTunnelRegistryError::NotFound(remote_id))?;
        let (client, server) =
            RingSocket::pair_with_ids(uuid::Uuid::new_v4(), remote_id, RING_TUNNEL_CAP);
        let conn = Arc::new(PendingRingConnection {
            client: client.clone(),
            server,
        });

        conn_sender
            .send(conn)
            .map_err(|_| RingTunnelRegistryError::Closed(remote_id))?;

        Ok(DialedRingSocket {
            local_id: client.id(),
            socket: client,
            remote_id,
        })
    }
}

pub struct AcceptedRingSocket {
    pub socket: Arc<RingTunnelSocket>,
    pub local_id: RingSocketId,
    pub remote_id: RingSocketId,
}

pub struct DialedRingSocket {
    pub socket: Arc<RingTunnelSocket>,
    pub local_id: RingSocketId,
    pub remote_id: RingSocketId,
}

pub struct RingTunnelSocketListener {
    registry: Arc<RingTunnelRegistry>,
    local_id: RingSocketId,
    conn_sender: UnboundedSender<Arc<PendingRingConnection>>,
    conn_receiver: UnboundedReceiver<Arc<PendingRingConnection>>,
}

impl Debug for RingTunnelSocketListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingTunnelSocketListener")
            .field("local_id", &self.local_id)
            .finish_non_exhaustive()
    }
}

impl RingTunnelSocketListener {
    pub fn local_id(&self) -> RingSocketId {
        self.local_id
    }

    pub async fn accept(&mut self) -> Result<AcceptedRingSocket, RingTunnelRegistryError> {
        let conn = self
            .conn_receiver
            .recv()
            .await
            .ok_or(RingTunnelRegistryError::Closed(self.local_id))?;

        let socket_id = conn.server.id();
        if socket_id != self.local_id {
            return Err(RingTunnelRegistryError::SocketIdMismatch {
                listener_id: self.local_id,
                socket_id,
            });
        }

        Ok(AcceptedRingSocket {
            socket: conn.server.clone(),
            local_id: self.local_id,
            remote_id: conn.client.id(),
        })
    }
}

impl Drop for RingTunnelSocketListener {
    fn drop(&mut self) {
        let mut connections = self.registry.connections.lock().unwrap();
        if connections
            .get(&self.local_id)
            .is_some_and(|sender| sender.same_channel(&self.conn_sender))
        {
            connections.remove(&self.local_id);
        }
    }
}

pub struct RingStream {
    id: RingSocketId,
    inner: RingSocketReceiver<RingItem>,
}

impl RingStream {
    pub fn new(inner: RingSocketReceiver<RingItem>, id: RingSocketId) -> Self {
        Self { id, inner }
    }
}

impl Stream for RingStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ret = std::task::ready!(Pin::new(&mut self.get_mut().inner).poll_next(cx));
        Poll::Ready(ret.map(|item| item.map_err(|_| TunnelError::Shutdown)))
    }
}

impl Debug for RingStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingStream")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub struct RingSink {
    id: RingSocketId,
    inner: RingSocketSender<RingItem>,
}

impl RingSink {
    pub fn new(inner: RingSocketSender<RingItem>, id: RingSocketId) -> Self {
        Self { id, inner }
    }

    pub fn try_send(&mut self, item: RingItem) -> Result<(), RingSinkSendError> {
        self.inner.try_send(item)
    }

    pub fn force_send(&mut self, item: RingItem) -> Result<(), RingSinkSendError> {
        self.inner.force_send(item)
    }
}

fn map_ring_send_error(error: RingSinkSendError) -> TunnelError {
    match error {
        RingSocketSendError::Closed(_) => TunnelError::Shutdown,
        RingSocketSendError::Full(_) => TunnelError::BufferFull,
    }
}

impl Sink<SinkItem> for RingSink {
    type Error = SinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_ready(cx)
            .map_err(|_| TunnelError::Shutdown)
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        self.get_mut()
            .inner
            .force_send(item)
            .map_err(map_ring_send_error)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(|_| TunnelError::Shutdown)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(|_| TunnelError::Shutdown)
    }
}

impl Debug for RingSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingSink")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub fn create_ring_socket_pair(capacity: usize) -> (Arc<RingTunnelSocket>, Arc<RingTunnelSocket>) {
    RingSocket::pair(capacity)
}

pub fn split_ring_socket(socket: Arc<RingTunnelSocket>) -> (RingStream, RingSink) {
    let id = socket.id();
    let (recv, send) = socket.split();
    (RingStream::new(recv, id), RingSink::new(send, id))
}

pub struct RingTunnel {
    socket: Arc<RingTunnelSocket>,
    info: Option<TunnelInfo>,
}

impl RingTunnel {
    pub fn new(socket: Arc<RingTunnelSocket>, info: Option<TunnelInfo>) -> Self {
        Self { socket, info }
    }

    pub fn socket(&self) -> Arc<RingTunnelSocket> {
        self.socket.clone()
    }
}

impl Debug for RingTunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingTunnel")
            .field("socket", &self.socket)
            .field("info", &self.info)
            .finish()
    }
}

impl Tunnel for RingTunnel {
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        let (stream, sink) = split_ring_socket(self.socket.clone());
        (Box::pin(stream), Box::pin(sink))
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub fn create_ring_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let (first, second) = create_ring_socket_pair(RING_TUNNEL_CAP);
    (
        Box::new(RingTunnel::new(first, None)),
        Box::new(RingTunnel::new(second, None)),
    )
}

#[cfg(test)]
mod tests {
    use futures::{SinkExt, StreamExt};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        time::{Duration, timeout},
    };

    use crate::packet::ZCPacket;

    use super::*;

    #[tokio::test]
    async fn explicit_registries_isolate_ring_listener_namespaces() {
        let listener_id = uuid::Uuid::new_v4();
        let first = Arc::new(RingTunnelRegistry::default());
        let second = Arc::new(RingTunnelRegistry::default());
        let mut listener = first.bind(listener_id).unwrap();

        assert!(matches!(
            second.connect(listener_id),
            Err(RingTunnelRegistryError::NotFound(id)) if id == listener_id
        ));

        let dialed = first.connect(listener_id).unwrap();
        let accepted = listener.accept().await.unwrap();
        assert_eq!(dialed.remote_id, listener_id);
        assert_eq!(accepted.local_id, listener_id);
        assert_eq!(accepted.remote_id, dialed.local_id);

        drop(listener);
        assert!(matches!(
            first.connect(listener_id),
            Err(RingTunnelRegistryError::NotFound(id)) if id == listener_id
        ));
    }

    #[tokio::test]
    async fn ring_tunnel_pair_transfers_packets() {
        let (left, right) = create_ring_tunnel_pair();
        let (_left_stream, mut left_sink) = left.split();
        let (mut right_stream, _right_sink) = right.split();

        let packet = ZCPacket::new_with_payload(&[1, 2, 3]);
        left_sink.send(packet.clone()).await.unwrap();

        let received = right_stream.next().await.unwrap().unwrap();
        assert_eq!(received.payload(), packet.payload());
    }

    #[tokio::test]
    async fn byte_stream_preserves_bytes_across_partial_reads() {
        let (left, right) = RingTunnelSocket::pair(8);
        let mut left = RingByteStream::new(left).unwrap();
        let mut right = RingByteStream::new(right).unwrap();

        timeout(Duration::from_millis(50), right.read(&mut []))
            .await
            .expect("zero-capacity read should not wait")
            .unwrap();
        left.write_all(b"abcdef").await.unwrap();

        let mut prefix = [0; 2];
        right.read_exact(&mut prefix).await.unwrap();
        let mut suffix = [0; 4];
        right.read_exact(&mut suffix).await.unwrap();
        assert_eq!(&prefix, b"ab");
        assert_eq!(&suffix, b"cdef");
    }

    #[tokio::test]
    async fn byte_stream_skips_empty_packets_without_reporting_eof() {
        let (left, right) = RingTunnelSocket::pair(8);
        let (_left_receiver, mut left_sender) = left.split();
        let mut right = RingByteStream::new(right).unwrap();

        left_sender
            .send(crate::packet::ZCPacket::new_with_payload(b""))
            .await
            .unwrap();
        left_sender
            .send(crate::packet::ZCPacket::new_with_payload(b"data"))
            .await
            .unwrap();

        let mut received = [0; 4];
        right.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"data");
    }
}

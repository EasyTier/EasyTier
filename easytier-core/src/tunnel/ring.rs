use std::{
    collections::HashMap,
    fmt::Debug,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex},
    task::{Context, Poll},
};

use futures::{Sink, Stream};
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

static CONNECTION_MAP: LazyLock<Mutex<ConnectionMap>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
    pub fn bind(local_id: RingSocketId) -> Result<Self, RingTunnelRegistryError> {
        let (conn_sender, conn_receiver) = unbounded_channel();
        let mut map = CONNECTION_MAP.lock().unwrap();
        if map.contains_key(&local_id) {
            return Err(RingTunnelRegistryError::AlreadyRegistered(local_id));
        }

        map.insert(local_id, conn_sender.clone());
        Ok(Self {
            local_id,
            conn_sender,
            conn_receiver,
        })
    }

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
        let mut map = CONNECTION_MAP.lock().unwrap();
        if map
            .get(&self.local_id)
            .is_some_and(|sender| sender.same_channel(&self.conn_sender))
        {
            map.remove(&self.local_id);
        }
    }
}

pub fn connect_ring_socket(
    remote_id: RingSocketId,
) -> Result<DialedRingSocket, RingTunnelRegistryError> {
    let conn_sender = CONNECTION_MAP
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

    use crate::packet::ZCPacket;

    use super::*;

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
}

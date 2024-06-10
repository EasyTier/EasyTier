use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Poll, Waker},
};

use atomicbox::AtomicOptionBox;
use crossbeam_queue::ArrayQueue;

use async_trait::async_trait;
use futures::{Sink, Stream};
use once_cell::sync::Lazy;

use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    Mutex,
};

use uuid::Uuid;

use crate::tunnel::{SinkError, SinkItem};

use super::{
    build_url_from_socket_addr, check_scheme_and_get_socket_addr, common::TunnelWrapper,
    StreamItem, Tunnel, TunnelConnector, TunnelError, TunnelInfo, TunnelListener,
};

static RING_TUNNEL_CAP: usize = 128;

#[derive(Debug)]
pub struct RingTunnel {
    id: Uuid,
    ring: ArrayQueue<SinkItem>,
    closed: AtomicBool,

    wait_for_new_item: AtomicOptionBox<Waker>,
    wait_for_empty_slot: AtomicOptionBox<Waker>,
}

impl RingTunnel {
    fn wait_for_new_item<T>(&self, cx: &mut std::task::Context<'_>) -> Poll<T> {
        let ret = self
            .wait_for_new_item
            .swap(Some(Box::new(cx.waker().clone())), Ordering::AcqRel);
        if let Some(old_waker) = ret {
            assert!(old_waker.will_wake(cx.waker()));
        }
        Poll::Pending
    }

    fn wait_for_empty_slot<T>(&self, cx: &mut std::task::Context<'_>) -> Poll<T> {
        let ret = self
            .wait_for_empty_slot
            .swap(Some(Box::new(cx.waker().clone())), Ordering::AcqRel);
        if let Some(old_waker) = ret {
            assert!(old_waker.will_wake(cx.waker()));
        }
        Poll::Pending
    }

    fn notify_new_item(&self) {
        if let Some(w) = self.wait_for_new_item.take(Ordering::AcqRel) {
            tracing::trace!(?self.id, "notify new item");
            w.wake();
        }
    }

    fn notify_empty_slot(&self) {
        if let Some(w) = self.wait_for_empty_slot.take(Ordering::AcqRel) {
            tracing::trace!(?self.id, "notify empty slot");
            w.wake();
        }
    }

    fn id(&self) -> &Uuid {
        &self.id
    }

    pub fn len(&self) -> usize {
        self.ring.len()
    }

    pub fn capacity(&self) -> usize {
        self.ring.capacity()
    }

    fn close(&self) {
        tracing::info!("close ring tunnel {:?}", self.id);
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.notify_new_item();
    }

    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn new(cap: usize) -> Self {
        let id = Uuid::new_v4();
        Self {
            id: id.clone(),
            ring: ArrayQueue::new(cap),
            closed: AtomicBool::new(false),

            wait_for_new_item: AtomicOptionBox::new(None),
            wait_for_empty_slot: AtomicOptionBox::new(None),
        }
    }

    pub fn new_with_id(id: Uuid, cap: usize) -> Self {
        let mut ret = Self::new(cap);
        ret.id = id;
        ret
    }
}

#[derive(Debug)]
pub struct RingStream {
    tunnel: Arc<RingTunnel>,
}

impl RingStream {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self { tunnel }
    }
}

impl Stream for RingStream {
    type Item = StreamItem;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        let ret = s.tunnel.ring.pop();
        match ret {
            Some(v) => {
                s.tunnel.notify_empty_slot();
                return Poll::Ready(Some(Ok(v)));
            }
            None => {
                if s.tunnel.closed() {
                    tracing::warn!("ring recv tunnel {:?} closed", s.tunnel.id());
                    return Poll::Ready(None);
                } else {
                    tracing::trace!("waiting recv buffer, id: {}", s.tunnel.id());
                }
                s.tunnel.wait_for_new_item(cx)
            }
        }
    }
}

#[derive(Debug)]
pub struct RingSink {
    tunnel: Arc<RingTunnel>,
}

impl Drop for RingSink {
    fn drop(&mut self) {
        self.tunnel.close();
    }
}

impl RingSink {
    pub fn new(tunnel: Arc<RingTunnel>) -> Self {
        Self { tunnel }
    }

    pub fn push_no_check(&self, item: SinkItem) -> Result<(), TunnelError> {
        if self.tunnel.closed() {
            return Err(TunnelError::Shutdown);
        }

        tracing::trace!(id=?self.tunnel.id(), ?item, "send buffer");
        let _ = self.tunnel.ring.push(item);
        self.tunnel.notify_new_item();

        Ok(())
    }

    pub fn has_empty_slot(&self) -> bool {
        self.tunnel.len() < self.tunnel.capacity()
    }
}

impl Sink<SinkItem> for RingSink {
    type Error = SinkError;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let self_mut = self.get_mut();
        if !self_mut.has_empty_slot() {
            if self_mut.tunnel.closed() {
                return Poll::Ready(Err(TunnelError::Shutdown));
            }
            self_mut.tunnel.wait_for_empty_slot(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        self.push_no_check(item)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        if self.tunnel.closed() {
            return Poll::Ready(Err(TunnelError::Shutdown));
        }
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.tunnel.close();
        Poll::Ready(Ok(()))
    }
}

struct Connection {
    client: Arc<RingTunnel>,
    server: Arc<RingTunnel>,
}

static CONNECTION_MAP: Lazy<Arc<Mutex<HashMap<uuid::Uuid, UnboundedSender<Arc<Connection>>>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

#[derive(Debug)]
pub struct RingTunnelListener {
    listerner_addr: url::Url,
    conn_sender: UnboundedSender<Arc<Connection>>,
    conn_receiver: UnboundedReceiver<Arc<Connection>>,
}

impl RingTunnelListener {
    pub fn new(key: url::Url) -> Self {
        let (conn_sender, conn_receiver) = tokio::sync::mpsc::unbounded_channel();
        RingTunnelListener {
            listerner_addr: key,
            conn_sender,
            conn_receiver,
        }
    }
}

fn get_tunnel_for_client(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.client.clone()),
        RingSink::new(conn.server.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&conn.client.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&conn.server.id.into(), "ring").into(),
        }),
    )
}

fn get_tunnel_for_server(conn: Arc<Connection>) -> impl Tunnel {
    TunnelWrapper::new(
        RingStream::new(conn.server.clone()),
        RingSink::new(conn.client.clone()),
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&conn.server.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&conn.client.id.into(), "ring").into(),
        }),
    )
}

impl RingTunnelListener {
    fn get_addr(&self) -> Result<uuid::Uuid, TunnelError> {
        check_scheme_and_get_socket_addr::<Uuid>(&self.listerner_addr, "ring")
    }
}

#[async_trait]
impl TunnelListener for RingTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        tracing::info!("listen new conn of key: {}", self.listerner_addr);
        CONNECTION_MAP
            .lock()
            .await
            .insert(self.get_addr()?, self.conn_sender.clone());
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::info!("waiting accept new conn of key: {}", self.listerner_addr);
        let my_addr = self.get_addr()?;
        if let Some(conn) = self.conn_receiver.recv().await {
            if conn.server.id == my_addr {
                tracing::info!("accept new conn of key: {}", self.listerner_addr);
                return Ok(Box::new(get_tunnel_for_server(conn)));
            } else {
                tracing::error!(?conn.server.id, ?my_addr, "got new conn with wrong id");
                return Err(TunnelError::InternalError(
                    "accept got wrong ring server id".to_owned(),
                ));
            }
        }

        return Err(TunnelError::InternalError(
            "conn receiver stopped".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.listerner_addr.clone()
    }
}

pub struct RingTunnelConnector {
    remote_addr: url::Url,
}

impl RingTunnelConnector {
    pub fn new(remote_addr: url::Url) -> Self {
        RingTunnelConnector { remote_addr }
    }
}

#[async_trait]
impl TunnelConnector for RingTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let remote_addr = check_scheme_and_get_socket_addr::<Uuid>(&self.remote_addr, "ring")?;
        let entry = CONNECTION_MAP
            .lock()
            .await
            .get(&remote_addr)
            .unwrap()
            .clone();
        tracing::info!("connecting");
        let conn = Arc::new(Connection {
            client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
            server: Arc::new(RingTunnel::new_with_id(
                remote_addr.clone(),
                RING_TUNNEL_CAP,
            )),
        });
        entry
            .send(conn.clone())
            .map_err(|_| TunnelError::InternalError("send conn to listner failed".to_owned()))?;
        Ok(Box::new(get_tunnel_for_client(conn)))
    }

    fn remote_url(&self) -> url::Url {
        self.remote_addr.clone()
    }
}

pub fn create_ring_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let conn = Arc::new(Connection {
        client: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
        server: Arc::new(RingTunnel::new(RING_TUNNEL_CAP)),
    });
    (
        Box::new(get_tunnel_for_server(conn.clone())),
        Box::new(get_tunnel_for_client(conn)),
    )
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;
    use tokio::time::timeout;

    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};

    use super::*;

    #[tokio::test]
    async fn ring_pingpong() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id.clone());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ring_bench() {
        let id: url::Url = format!("ring://{}", Uuid::new_v4()).parse().unwrap();
        let listener = RingTunnelListener::new(id.clone());
        let connector = RingTunnelConnector::new(id);
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn ring_close() {
        let (stunnel, ctunnel) = create_ring_tunnel_pair();
        drop(stunnel);

        let mut stream = ctunnel.split().0;
        let ret = stream.next().await;
        assert!(ret.as_ref().is_none(), "expect none, got {:?}", ret);
    }

    #[tokio::test]
    async fn abort_ring_stream() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let task = tokio::spawn(async move {
            let _ = stream.next().await;
        });
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        task.abort();
        let _ = tokio::join!(task);
    }

    #[tokio::test]
    async fn ring_stream_recv_timeout() {
        let (_stunnel, ctunnel) = create_ring_tunnel_pair();
        let mut stream = ctunnel.split().0;
        let _ = timeout(tokio::time::Duration::from_millis(10), stream.next()).await;
    }
}

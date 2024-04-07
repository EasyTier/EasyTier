use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU32},
        Arc,
    },
    task::Poll,
};

use async_stream::stream;
use crossbeam_queue::ArrayQueue;

use async_trait::async_trait;
use futures::Sink;
use once_cell::sync::Lazy;
use tokio::sync::{
    mpsc::{UnboundedReceiver, UnboundedSender},
    Mutex, Notify,
};

use futures::FutureExt;
use tokio_util::bytes::BytesMut;
use uuid::Uuid;

use crate::tunnels::{SinkError, SinkItem};

use super::{
    build_url_from_socket_addr, check_scheme_and_get_socket_addr, common::FramedTunnel,
    DatagramSink, DatagramStream, Tunnel, TunnelConnector, TunnelError, TunnelInfo, TunnelListener,
};

static RING_TUNNEL_CAP: usize = 1000;

struct Ring {
    id: Uuid,
    ring: ArrayQueue<SinkItem>,
    consume_notify: Notify,
    produce_notify: Notify,
    closed: AtomicBool,
}

impl Ring {
    fn new(cap: usize, id: uuid::Uuid) -> Self {
        Self {
            id,
            ring: ArrayQueue::new(cap),
            consume_notify: Notify::new(),
            produce_notify: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.produce_notify.notify_one();
    }

    fn closed(&self) -> bool {
        self.closed.load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct RingTunnel {
    id: Uuid,
    ring: Arc<Ring>,
    sender_counter: Arc<AtomicU32>,
}

impl RingTunnel {
    pub fn new(cap: usize) -> Self {
        let id = Uuid::new_v4();
        RingTunnel {
            id: id.clone(),
            ring: Arc::new(Ring::new(cap, id)),
            sender_counter: Arc::new(AtomicU32::new(1)),
        }
    }

    pub fn new_with_id(id: Uuid, cap: usize) -> Self {
        let mut ret = Self::new(cap);
        ret.id = id;
        ret
    }

    fn recv_stream(&self) -> impl DatagramStream {
        let ring = self.ring.clone();
        let id = self.id;
        stream! {
            loop {
                match ring.ring.pop() {
                    Some(v) => {
                        let mut out = BytesMut::new();
                        out.extend_from_slice(&v);
                        ring.consume_notify.notify_one();
                        log::trace!("id: {}, recv buffer, len: {:?}, buf: {:?}", id, v.len(), &v);
                        yield Ok(out);
                    },
                    None => {
                        if ring.closed() {
                            log::warn!("ring recv tunnel {:?} closed", id);
                            yield Err(TunnelError::CommonError("ring closed".to_owned()));
                        }
                        log::trace!("waiting recv buffer, id: {}", id);
                        ring.produce_notify.notified().await;
                    }
                }
            }
        }
    }

    fn send_sink(&self) -> impl DatagramSink {
        let ring = self.ring.clone();
        let sender_counter = self.sender_counter.clone();
        use tokio::task::JoinHandle;

        struct T {
            ring: Arc<Ring>,
            wait_consume_task: Option<JoinHandle<()>>,
            sender_counter: Arc<AtomicU32>,
        }

        impl T {
            fn wait_ring_consume(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                expected_size: usize,
            ) -> std::task::Poll<()> {
                let self_mut = self.get_mut();
                if self_mut.ring.ring.len() <= expected_size {
                    return Poll::Ready(());
                }
                if self_mut.wait_consume_task.is_none() {
                    let id = self_mut.ring.id;
                    let ring = self_mut.ring.clone();
                    let task = async move {
                        log::trace!(
                            "waiting ring consume done, expected_size: {}, id: {}",
                            expected_size,
                            id
                        );
                        while ring.ring.len() > expected_size {
                            ring.consume_notify.notified().await;
                        }
                        log::trace!(
                            "ring consume done, expected_size: {}, id: {}",
                            expected_size,
                            id
                        );
                    };
                    self_mut.wait_consume_task = Some(tokio::spawn(task));
                }
                let task = self_mut.wait_consume_task.as_mut().unwrap();
                match task.poll_unpin(cx) {
                    Poll::Ready(_) => {
                        self_mut.wait_consume_task = None;
                        Poll::Ready(())
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }

        impl Sink<SinkItem> for T {
            type Error = SinkError;

            fn poll_ready(
                self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                if self.ring.closed() {
                    return Poll::Ready(Err(TunnelError::CommonError(
                        "ring closed during ready".to_owned(),
                    )
                    .into()));
                }
                let expected_size = self.ring.ring.capacity() - 1;
                match self.wait_ring_consume(cx, expected_size) {
                    Poll::Ready(_) => Poll::Ready(Ok(())),
                    Poll::Pending => Poll::Pending,
                }
            }

            fn start_send(
                self: std::pin::Pin<&mut Self>,
                item: SinkItem,
            ) -> Result<(), Self::Error> {
                if self.ring.closed() {
                    return Err(
                        TunnelError::CommonError("ring closed during send".to_owned()).into(),
                    );
                }
                log::trace!("id: {}, send buffer, buf: {:?}", self.ring.id, &item);
                self.ring.ring.push(item).unwrap();
                self.ring.produce_notify.notify_one();
                Ok(())
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                if self.ring.closed() {
                    return Poll::Ready(Err(TunnelError::CommonError(
                        "ring closed during flush".to_owned(),
                    )
                    .into()));
                }
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                self.ring.close();
                Poll::Ready(Ok(()))
            }
        }

        impl Drop for T {
            fn drop(&mut self) {
                let rem = self
                    .sender_counter
                    .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                if rem == 1 {
                    self.ring.close()
                }
            }
        }

        sender_counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        T {
            ring,
            wait_consume_task: None,
            sender_counter,
        }
    }
}

impl Drop for RingTunnel {
    fn drop(&mut self) {
        let rem = self
            .sender_counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        if rem == 1 {
            self.ring.close()
        }
    }
}

struct Connection {
    client: RingTunnel,
    server: RingTunnel,
}

impl Tunnel for RingTunnel {
    fn stream(&self) -> Box<dyn DatagramStream> {
        Box::new(self.recv_stream())
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        Box::new(self.send_sink())
    }

    fn info(&self) -> Option<TunnelInfo> {
        None
    }
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

fn get_tunnel_for_client(conn: Arc<Connection>) -> Box<dyn Tunnel> {
    FramedTunnel::new_tunnel_with_info(
        Box::pin(conn.client.recv_stream()),
        conn.server.send_sink(),
        TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&conn.client.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&conn.server.id.into(), "ring").into(),
        },
    )
}

fn get_tunnel_for_server(conn: Arc<Connection>) -> Box<dyn Tunnel> {
    FramedTunnel::new_tunnel_with_info(
        Box::pin(conn.server.recv_stream()),
        conn.client.send_sink(),
        TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&conn.server.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&conn.client.id.into(), "ring").into(),
        },
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
        log::info!("listen new conn of key: {}", self.listerner_addr);
        CONNECTION_MAP
            .lock()
            .await
            .insert(self.get_addr()?, self.conn_sender.clone());
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        log::info!("waiting accept new conn of key: {}", self.listerner_addr);
        let my_addr = self.get_addr()?;
        if let Some(conn) = self.conn_receiver.recv().await {
            if conn.server.id == my_addr {
                log::info!("accept new conn of key: {}", self.listerner_addr);
                return Ok(get_tunnel_for_server(conn));
            } else {
                tracing::error!(?conn.server.id, ?my_addr, "got new conn with wrong id");
                return Err(TunnelError::CommonError(
                    "accept got wrong ring server id".to_owned(),
                ));
            }
        }

        return Err(TunnelError::CommonError("conn receiver stopped".to_owned()));
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
        log::info!("connecting");
        let conn = Arc::new(Connection {
            client: RingTunnel::new(RING_TUNNEL_CAP),
            server: RingTunnel::new_with_id(remote_addr.clone(), RING_TUNNEL_CAP),
        });
        entry
            .send(conn.clone())
            .map_err(|_| TunnelError::CommonError("send conn to listner failed".to_owned()))?;
        Ok(get_tunnel_for_client(conn))
    }

    fn remote_url(&self) -> url::Url {
        self.remote_addr.clone()
    }
}

pub fn create_ring_tunnel_pair() -> (Box<dyn Tunnel>, Box<dyn Tunnel>) {
    let conn = Arc::new(Connection {
        client: RingTunnel::new(RING_TUNNEL_CAP),
        server: RingTunnel::new(RING_TUNNEL_CAP),
    });
    (
        Box::new(get_tunnel_for_server(conn.clone())),
        Box::new(get_tunnel_for_client(conn)),
    )
}

#[cfg(test)]
mod tests {
    use futures::StreamExt;

    use crate::tunnels::common::tests::{_tunnel_bench, _tunnel_pingpong};

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

        let mut stream = ctunnel.pin_stream();
        let ret = stream.next().await;
        assert!(ret.as_ref().unwrap().is_err(), "expect Err, got {:?}", ret);
    }
}

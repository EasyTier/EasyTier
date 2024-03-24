use std::{
    collections::HashMap,
    sync::{atomic::AtomicBool, Arc},
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
    build_url_from_socket_addr, check_scheme_and_get_socket_addr, DatagramSink, DatagramStream,
    Tunnel, TunnelConnector, TunnelError, TunnelInfo, TunnelListener,
};

static RING_TUNNEL_CAP: usize = 1000;

pub struct RingTunnel {
    id: Uuid,
    ring: Arc<ArrayQueue<SinkItem>>,
    consume_notify: Arc<Notify>,
    produce_notify: Arc<Notify>,
    closed: Arc<AtomicBool>,
}

impl RingTunnel {
    pub fn new(cap: usize) -> Self {
        RingTunnel {
            id: Uuid::new_v4(),
            ring: Arc::new(ArrayQueue::new(cap)),
            consume_notify: Arc::new(Notify::new()),
            produce_notify: Arc::new(Notify::new()),
            closed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn new_with_id(id: Uuid, cap: usize) -> Self {
        let mut ret = Self::new(cap);
        ret.id = id;
        ret
    }

    fn recv_stream(&self) -> impl DatagramStream {
        let ring = self.ring.clone();
        let produce_notify = self.produce_notify.clone();
        let consume_notify = self.consume_notify.clone();
        let closed = self.closed.clone();
        let id = self.id;
        stream! {
            loop {
                if closed.load(std::sync::atomic::Ordering::Relaxed) {
                    log::warn!("ring recv tunnel {:?} closed", id);
                    yield Err(TunnelError::CommonError("Closed".to_owned()));
                }
                match ring.pop() {
                    Some(v) => {
                        let mut out = BytesMut::new();
                        out.extend_from_slice(&v);
                        consume_notify.notify_one();
                        log::trace!("id: {}, recv buffer, len: {:?}, buf: {:?}", id, v.len(), &v);
                        yield Ok(out);
                    },
                    None => {
                        log::trace!("waiting recv buffer, id: {}", id);
                        produce_notify.notified().await;
                    }
                }
            }
        }
    }

    fn send_sink(&self) -> impl DatagramSink {
        let ring = self.ring.clone();
        let produce_notify = self.produce_notify.clone();
        let consume_notify = self.consume_notify.clone();
        let closed = self.closed.clone();
        let id = self.id;

        // type T = RingTunnel;

        use tokio::task::JoinHandle;

        struct T {
            ring: RingTunnel,
            wait_consume_task: Option<JoinHandle<()>>,
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
                    let consume_notify = self_mut.ring.consume_notify.clone();
                    let ring = self_mut.ring.ring.clone();
                    let task = async move {
                        log::trace!(
                            "waiting ring consume done, expected_size: {}, id: {}",
                            expected_size,
                            id
                        );
                        while ring.len() > expected_size {
                            consume_notify.notified().await;
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
                log::trace!("id: {}, send buffer, buf: {:?}", self.ring.id, &item);
                self.ring.ring.push(item).unwrap();
                self.ring.produce_notify.notify_one();
                Ok(())
            }

            fn poll_flush(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                Poll::Ready(Ok(()))
            }

            fn poll_close(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                self.ring
                    .closed
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                log::warn!("ring tunnel send {:?} closed", self.ring.id);
                self.ring.produce_notify.notify_one();
                Poll::Ready(Ok(()))
            }
        }

        T {
            ring: RingTunnel {
                id,
                ring,
                consume_notify,
                produce_notify,
                closed,
            },
            wait_consume_task: None,
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
        // Some(TunnelInfo {
        //     tunnel_type: "ring".to_owned(),
        //     local_addr: format!("ring://{}", self.id),
        //     remote_addr: format!("ring://{}", self.id),
        // })
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
struct ConnectionForServer {
    conn: Arc<Connection>,
}

impl Tunnel for ConnectionForServer {
    fn stream(&self) -> Box<dyn DatagramStream> {
        Box::new(self.conn.server.recv_stream())
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        Box::new(self.conn.client.send_sink())
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&self.conn.server.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&self.conn.client.id.into(), "ring").into(),
        })
    }
}

struct ConnectionForClient {
    conn: Arc<Connection>,
}

impl Tunnel for ConnectionForClient {
    fn stream(&self) -> Box<dyn DatagramStream> {
        Box::new(self.conn.client.recv_stream())
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        Box::new(self.conn.server.send_sink())
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(TunnelInfo {
            tunnel_type: "ring".to_owned(),
            local_addr: build_url_from_socket_addr(&self.conn.client.id.into(), "ring").into(),
            remote_addr: build_url_from_socket_addr(&self.conn.server.id.into(), "ring").into(),
        })
    }
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
                return Ok(Box::new(ConnectionForServer { conn }));
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
        Ok(Box::new(ConnectionForClient { conn }))
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
        Box::new(ConnectionForServer { conn: conn.clone() }),
        Box::new(ConnectionForClient { conn }),
    )
}

#[cfg(test)]
mod tests {
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
}

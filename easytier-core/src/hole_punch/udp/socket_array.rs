use std::{
    fmt::Debug,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use dashmap::{DashMap, DashSet};
use tokio::task::JoinSet;
use tracing::{Instrument, Level, instrument};

use super::{HOLE_PUNCH_PACKET_BODY_LEN, hole_punch_packet_tid};
use crate::socket::{
    IpVersion, SocketContext,
    udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
};

pub struct PunchedUdpSocket<S> {
    pub socket: Arc<S>,
    pub tid: u32,
    pub remote_addr: SocketAddr,
}

impl<S> Debug for PunchedUdpSocket<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchedUdpSocket")
            .field("tid", &self.tid)
            .field("remote_addr", &self.remote_addr)
            .finish_non_exhaustive()
    }
}

pub struct UdpSocketArray<R>
where
    R: VirtualUdpSocketFactory,
{
    sockets: Arc<DashMap<SocketAddr, Arc<R::Socket>>>,
    max_socket_count: usize,
    socket_factory: Arc<R>,
    socket_context: SocketContext,
    tasks: Arc<Mutex<JoinSet<()>>>,

    interest_tids: Arc<DashSet<u32>>,
    tid_to_socket: Arc<DashMap<u32, Vec<PunchedUdpSocket<R::Socket>>>>,
}

impl<R> UdpSocketArray<R>
where
    R: VirtualUdpSocketFactory,
{
    #[cfg(test)]
    pub fn new(max_socket_count: usize, socket_factory: Arc<R>) -> Self {
        Self::new_with_context(max_socket_count, socket_factory, SocketContext::default())
    }

    pub fn new_with_context(
        max_socket_count: usize,
        socket_factory: Arc<R>,
        socket_context: SocketContext,
    ) -> Self {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "UdpSocketArray");

        Self {
            sockets: Arc::new(DashMap::new()),
            max_socket_count,
            socket_factory,
            socket_context,
            tasks,

            interest_tids: Arc::new(DashSet::new()),
            tid_to_socket: Arc::new(DashMap::new()),
        }
    }

    pub fn started(&self) -> bool {
        !self.sockets.is_empty()
    }

    pub async fn add_new_socket(&self, socket: Arc<R::Socket>) -> anyhow::Result<()> {
        let socket_map = self.sockets.clone();
        let local_addr = socket.local_addr()?;
        let interest_tids = self.interest_tids.clone();
        let tid_to_socket = self.tid_to_socket.clone();
        socket_map.insert(local_addr, socket.clone());
        self.tasks.lock().unwrap().spawn(
            async move {
                let _socket_map_guard = RemoveSocketOnDrop {
                    sockets: socket_map,
                    local_addr,
                };
                let mut buf = [0u8; super::udp_packet_len(HOLE_PUNCH_PACKET_BODY_LEN)];
                tracing::trace!(?local_addr, "udp socket added");
                loop {
                    let Ok((len, addr)) = socket.recv_from(&mut buf).await else {
                        break;
                    };

                    tracing::debug!(?len, ?addr, "got raw packet");

                    let packet = &buf[..len];
                    let Some(tid) = hole_punch_packet_tid(packet, HOLE_PUNCH_PACKET_BODY_LEN)
                    else {
                        continue;
                    };

                    tracing::debug!(?addr, ?tid, "got udp hole punch packet");

                    if interest_tids.contains(&tid) {
                        tracing::info!(?addr, ?tid, "got hole punching packet with interest tid");
                        tid_to_socket
                            .entry(tid)
                            .or_default()
                            .push(PunchedUdpSocket {
                                socket: socket.clone(),
                                tid,
                                remote_addr: addr,
                            });
                        break;
                    }
                }
                tracing::debug!(?local_addr, "udp socket recv loop end");
            }
            .instrument(tracing::info_span!("udp array socket recv loop")),
        );
        Ok(())
    }

    #[instrument(err)]
    pub async fn start(&self) -> anyhow::Result<()> {
        tracing::info!("starting udp socket array");

        while self.sockets.len() < self.max_socket_count {
            let socket = self
                .socket_factory
                .bind_udp(
                    UdpBindOptions::hole_punch_candidate()
                        .with_context(self.socket_context.clone().with_ip_version(IpVersion::V4)),
                )
                .await?;
            self.add_new_socket(socket).await?;
        }

        Ok(())
    }

    #[instrument(err)]
    pub async fn send_with_all(&self, data: &[u8], addr: SocketAddr) -> anyhow::Result<()> {
        tracing::info!(?addr, "sending hole punching packet");

        let sockets = self
            .sockets
            .iter()
            .map(|s| s.value().clone())
            .collect::<Vec<_>>();

        for socket in sockets.iter() {
            for _ in 0..3 {
                socket.send_to(data, addr).await?;
            }
        }

        Ok(())
    }

    #[instrument(ret(level = Level::DEBUG))]
    pub fn try_fetch_punched_socket(&self, tid: u32) -> Option<PunchedUdpSocket<R::Socket>> {
        tracing::debug!(?tid, "try fetch punched socket");
        self.tid_to_socket.get_mut(&tid)?.value_mut().pop()
    }

    pub fn add_interest_tid(&self, tid: u32) {
        self.interest_tids.insert(tid);
    }

    pub fn add_intreast_tid(&self, tid: u32) {
        self.add_interest_tid(tid);
    }

    pub fn remove_interest_tid(&self, tid: u32) {
        self.interest_tids.remove(&tid);
        self.tid_to_socket.remove(&tid);
    }

    pub fn remove_intreast_tid(&self, tid: u32) {
        self.remove_interest_tid(tid);
    }
}

impl<R> Debug for UdpSocketArray<R>
where
    R: VirtualUdpSocketFactory,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UdpSocketArray")
            .field("sockets", &self.sockets.len())
            .field("max_socket_count", &self.max_socket_count)
            .field("started", &self.started())
            .field("interest_tids", &self.interest_tids.len())
            .field("tid_to_socket", &self.tid_to_socket.len())
            .finish()
    }
}

struct RemoveSocketOnDrop<S> {
    sockets: Arc<DashMap<SocketAddr, Arc<S>>>,
    local_addr: SocketAddr,
}

impl<S> Drop for RemoveSocketOnDrop<S> {
    fn drop(&mut self) {
        self.sockets.remove(&self.local_addr);
    }
}

fn join_joinset_background<T: Debug + Send + Sync + 'static>(
    js: Arc<Mutex<JoinSet<T>>>,
    origin: &'static str,
) {
    let js = Arc::downgrade(&js);
    tokio::spawn(
        async move {
            while js.strong_count() > 0 {
                crate::runtime_time::sleep(std::time::Duration::from_secs(1)).await;

                let fut = std::future::poll_fn(|cx| {
                    let Some(js) = js.upgrade() else {
                        return std::task::Poll::Ready(());
                    };

                    let mut js = js.lock().unwrap();
                    while !js.is_empty() {
                        let ret = js.poll_join_next(cx);
                        match ret {
                            std::task::Poll::Ready(Some(_)) => {
                                continue;
                            }
                            std::task::Poll::Ready(None) => {
                                break;
                            }
                            std::task::Poll::Pending => {
                                return std::task::Poll::Pending;
                            }
                        }
                    }
                    std::task::Poll::Ready(())
                });

                let _ = crate::runtime_time::timeout(std::time::Duration::from_secs(5), fut).await;
            }
            tracing::debug!(?origin, "joinset task exit");
        }
        .instrument(tracing::info_span!(
            "join_joinset_background",
            origin = origin
        )),
    );
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::atomic::{AtomicU16, Ordering},
    };

    use async_trait::async_trait;
    use tokio::sync::Mutex as TokioMutex;

    use super::*;
    use crate::{hole_punch::udp::new_hole_punch_packet, socket::NetNamespace};

    struct MockSocket {
        local_addr: SocketAddr,
        incoming: TokioMutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        sent: TokioMutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockSocket {
        fn new(local_addr: SocketAddr, incoming: Vec<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                local_addr,
                incoming: TokioMutex::new(incoming.into()),
                sent: TokioMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().await.push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let packet = self.incoming.lock().await.pop_front();
            let Some((packet, addr)) = packet else {
                return std::future::pending().await;
            };
            buf[..packet.len()].copy_from_slice(&packet);
            Ok((packet.len(), addr))
        }
    }

    struct MockFactory {
        next_port: AtomicU16,
        bind_options: TokioMutex<Vec<UdpBindOptions>>,
    }

    impl MockFactory {
        fn new() -> Self {
            Self {
                next_port: AtomicU16::new(10000),
                bind_options: TokioMutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockFactory {
        type Socket = MockSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_options.lock().await.push(options);
            let port = self.next_port.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(MockSocket::new(
                SocketAddr::from(([127, 0, 0, 1], port)),
                Vec::new(),
            )))
        }
    }

    #[tokio::test]
    async fn fetches_socket_when_interested_tid_is_received() {
        let runtime = Arc::new(MockFactory::new());
        let array = UdpSocketArray::new(0, runtime);
        let tid = 7;
        let remote_addr = SocketAddr::from(([10, 0, 0, 1], 1234));
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN)
            .into_bytes()
            .to_vec();
        let socket = Arc::new(MockSocket::new(
            SocketAddr::from(([127, 0, 0, 1], 20000)),
            vec![(packet, remote_addr)],
        ));

        array.add_interest_tid(tid);
        array.add_new_socket(socket.clone()).await.unwrap();

        for _ in 0..10 {
            if let Some(punched) = array.try_fetch_punched_socket(tid) {
                assert_eq!(punched.tid, tid);
                assert_eq!(punched.remote_addr, remote_addr);
                assert!(Arc::ptr_eq(&punched.socket, &socket));
                return;
            }
            tokio::task::yield_now().await;
        }

        panic!("punched socket was not recorded");
    }

    #[tokio::test]
    async fn send_with_all_sends_three_packets_per_socket() {
        let runtime = Arc::new(MockFactory::new());
        let array = UdpSocketArray::new(0, runtime);
        let socket = Arc::new(MockSocket::new(
            SocketAddr::from(([127, 0, 0, 1], 20001)),
            Vec::new(),
        ));
        let remote_addr = SocketAddr::from(([10, 0, 0, 2], 1235));

        array.add_new_socket(socket.clone()).await.unwrap();
        array.send_with_all(b"abc", remote_addr).await.unwrap();

        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 3);
        assert!(
            sent.iter()
                .all(|(data, addr)| data == b"abc" && *addr == remote_addr)
        );
    }

    #[tokio::test]
    async fn start_binds_up_to_max_socket_count() {
        let runtime = Arc::new(MockFactory::new());
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(NetNamespace::new("instance-a")));
        let array = UdpSocketArray::new_with_context(2, runtime.clone(), context.clone());

        array.start().await.unwrap();

        assert!(array.started());
        assert_eq!(array.sockets.len(), 2);

        let bind_options = runtime.bind_options.lock().await;
        assert_eq!(
            bind_options.as_slice(),
            &[
                UdpBindOptions::hole_punch_candidate()
                    .with_context(context.clone().with_ip_version(IpVersion::V4)),
                UdpBindOptions::hole_punch_candidate()
                    .with_context(context.with_ip_version(IpVersion::V4)),
            ]
        );
    }
}

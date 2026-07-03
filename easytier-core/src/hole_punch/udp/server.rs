use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use crossbeam::atomic::AtomicCell;
use quanta::Instant;
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::task::AbortOnDropHandle;

use super::{
    HOLE_PUNCH_PACKET_BODY_LEN, MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS, ReusableUdpPunchListener,
    SendPunchPacketCone, UdpHolePunchRuntime, UdpHolePunchTunnelSink, UdpPortMappingLease,
    UdpPunchListener, UdpPunchSocket, can_reuse_port_mapping_listener, can_reuse_public_listener,
    new_hole_punch_packet, select_reusable_port_mapping_listener_idx,
    select_reusable_public_listener_idx, should_create_public_listener,
    should_retry_public_listener_selection,
};

pub struct SelectedUdpPunchListener<S> {
    pub socket: Arc<S>,
    pub mapped_addr: SocketAddr,
}

pub struct UdpHolePunchServerCommon<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTunnelSink + 'static,
{
    runtime: Arc<R>,
    tunnel_sink: Arc<T>,
    listeners: Arc<Mutex<Vec<UdpPunchListenerRecord<R::Socket>>>>,
    _cleanup_task: AbortOnDropHandle<()>,
}

impl<R, T> UdpHolePunchServerCommon<R, T>
where
    R: UdpHolePunchRuntime,
    T: UdpHolePunchTunnelSink + 'static,
{
    pub fn new(runtime: Arc<R>, tunnel_sink: Arc<T>) -> Self {
        let listeners = Arc::new(Mutex::new(Vec::<UdpPunchListenerRecord<R::Socket>>::new()));
        let cleanup_listeners = listeners.clone();
        let cleanup_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                cleanup_listeners.lock().await.retain(|listener| {
                    listener.last_active_time.load().elapsed().as_secs() < 40
                        || listener.last_select_time.load().elapsed().as_secs() < 30
                });
            }
        }));

        Self {
            runtime,
            tunnel_sink,
            listeners,
            _cleanup_task: cleanup_task,
        }
    }

    pub async fn add_listener(&self, listener: UdpPunchListener<R::Socket>) {
        self.listeners
            .lock()
            .await
            .push(UdpPunchListenerRecord::new(
                listener,
                self.tunnel_sink.clone(),
            ));
    }

    pub async fn find_listener(&self, addr: &SocketAddr) -> Option<Arc<R::Socket>> {
        let listeners = self.listeners.lock().await;

        let listener = listeners
            .iter()
            .find(|listener| listener.mapped_addr == *addr && listener.running.load())?;

        Some(listener.get_socket())
    }

    pub async fn select_listener(
        &self,
        force_new_listener: bool,
        prefer_port_mapping: bool,
    ) -> Option<SelectedUdpPunchListener<R::Socket>> {
        let mut force_new_listener = force_new_listener;

        loop {
            let (listener_count, has_reusable_listener, has_port_mapping_listener) = {
                let listeners = self.listeners.lock().await;
                let states = listener_reuse_states(listeners.as_slice());
                (
                    states.len(),
                    states.iter().any(can_reuse_public_listener),
                    states.iter().any(can_reuse_port_mapping_listener),
                )
            };
            let should_create = should_create_public_listener(
                listener_count,
                has_reusable_listener,
                has_port_mapping_listener,
                force_new_listener,
                prefer_port_mapping,
            );

            if should_create {
                tracing::warn!(
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "creating udp hole punching listener"
                );
                match self.runtime.create_listener(prefer_port_mapping).await {
                    Ok(listener) => self.add_listener(listener).await,
                    Err(err) => {
                        tracing::warn!(?err, "failed to create udp hole punching listener");
                    }
                }
            }

            let mut listeners = self.listeners.lock().await;
            let listener_count = listeners.len();
            let states = listener_reuse_states(listeners.as_slice());
            let listener_idx = if prefer_port_mapping {
                select_reusable_port_mapping_listener_idx(&states)
                    .or_else(|| {
                        if should_create && states.last().is_some_and(can_reuse_public_listener) {
                            Some(states.len() - 1)
                        } else {
                            None
                        }
                    })
                    .or_else(|| select_reusable_public_listener_idx(&states))
            } else if should_create {
                listeners.len().checked_sub(1)
            } else {
                select_reusable_public_listener_idx(&states)
            };

            let Some(listener_idx) = listener_idx else {
                tracing::warn!(
                    ?force_new_listener,
                    ?prefer_port_mapping,
                    listener_count,
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "no available udp hole punching listener with mapped address"
                );
                if should_retry_public_listener_selection(
                    force_new_listener,
                    listener_count,
                    prefer_port_mapping,
                    has_port_mapping_listener,
                ) {
                    force_new_listener = true;
                    continue;
                }
                return None;
            };

            let listener = &mut listeners[listener_idx];
            if !can_reuse_public_listener(&listener.reuse_state()) {
                tracing::warn!(
                    ?force_new_listener,
                    ?prefer_port_mapping,
                    listener_count,
                    max_listeners = MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                    "selected udp hole punching listener is not reusable"
                );
                return None;
            }

            return Some(SelectedUdpPunchListener {
                socket: listener.get_socket(),
                mapped_addr: listener.mapped_addr,
            });
        }
    }
}

struct UdpPunchListenerRecord<S> {
    socket: Arc<S>,
    _tasks: JoinSet<()>,
    running: Arc<AtomicCell<bool>>,
    mapped_addr: SocketAddr,
    has_port_mapping_lease: bool,
    _port_mapping_lease: Option<Box<dyn UdpPortMappingLease>>,

    _listen_time: Instant,
    last_select_time: AtomicCell<Instant>,
    last_active_time: Arc<AtomicCell<Instant>>,
}

impl<S> UdpPunchListenerRecord<S>
where
    S: UdpPunchSocket + 'static,
{
    fn new<T>(listener: UdpPunchListener<S>, tunnel_sink: Arc<T>) -> Self
    where
        T: UdpHolePunchTunnelSink + 'static,
    {
        let UdpPunchListener {
            socket,
            mapped_addr,
            conn_counter,
            mut acceptor,
            port_mapping_lease,
        } = listener;

        let running = Arc::new(AtomicCell::new(true));
        let running_clone = running.clone();
        let mut tasks = JoinSet::new();

        tasks.spawn(async move {
            while let Ok(conn) = acceptor.accept().await {
                tracing::warn!(?conn, "udp hole punching listener got peer connection");
                let tunnel_sink = tunnel_sink.clone();
                tokio::spawn(async move {
                    if let Err(err) = tunnel_sink.add_server_tunnel(conn).await {
                        tracing::error!(
                            ?err,
                            "failed to add tunnel as server in hole punch listener"
                        );
                    }
                });
            }

            running_clone.store(false);
        });

        let last_active_time = Arc::new(AtomicCell::new(Instant::now()));
        let conn_counter_clone = conn_counter.clone();
        let last_active_time_clone = last_active_time.clone();
        tasks.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if conn_counter_clone.get().unwrap_or(0) != 0 {
                    last_active_time_clone.store(Instant::now());
                }
            }
        });

        tracing::warn!(?mapped_addr, "udp hole punching listener started");

        Self {
            socket,
            _tasks: tasks,
            running,
            mapped_addr,
            has_port_mapping_lease: port_mapping_lease.is_some(),
            _port_mapping_lease: port_mapping_lease,

            _listen_time: Instant::now(),
            last_select_time: AtomicCell::new(Instant::now()),
            last_active_time,
        }
    }

    fn get_socket(&self) -> Arc<S> {
        self.last_select_time.store(Instant::now());
        self.socket.clone()
    }

    fn reuse_state(&self) -> ReusableUdpPunchListener {
        ReusableUdpPunchListener {
            running: self.running.load(),
            mapped_addr: self.mapped_addr,
            has_port_mapping_lease: self.has_port_mapping_lease,
            last_active_time: self.last_active_time.load(),
        }
    }
}

fn listener_reuse_states<S>(
    listeners: &[UdpPunchListenerRecord<S>],
) -> Vec<ReusableUdpPunchListener>
where
    S: UdpPunchSocket + 'static,
{
    listeners
        .iter()
        .map(UdpPunchListenerRecord::reuse_state)
        .collect()
}

pub async fn send_cone_hole_punch_packets<S>(
    udp: Arc<S>,
    request: &SendPunchPacketCone,
) -> anyhow::Result<()>
where
    S: UdpPunchSocket + 'static,
{
    let dest_ip = request.dest_addr.ip();
    if dest_ip.is_unspecified() || dest_ip.is_multicast() {
        anyhow::bail!(
            "send_punch_packet_for_cone dest_ip is malformed: {:?}",
            request
        );
    }

    for _ in 0..request.packet_batch_count {
        tracing::info!(?request, "sending hole punching packet");

        for _ in 0..request.packet_count_per_batch {
            let udp_packet =
                new_hole_punch_packet(request.transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
            if let Err(err) = udp
                .send_to(&udp_packet.into_bytes(), request.dest_addr)
                .await
            {
                tracing::error!(?err, "failed to send hole punch packet to dest addr");
            }
        }
        tokio::time::sleep(Duration::from_millis(request.packet_interval_ms as u64)).await;
    }

    Ok(())
}

#[tracing::instrument(err, ret(level = tracing::Level::DEBUG), skip(ports, udp))]
pub async fn send_symmetric_hole_punch_packet<S>(
    ports: &[u16],
    udp: Arc<S>,
    transaction_id: u32,
    public_ips: &[Ipv4Addr],
    port_start_idx: usize,
    max_packets: usize,
) -> anyhow::Result<usize>
where
    S: UdpPunchSocket + 'static,
{
    tracing::debug!("sending hard symmetric hole punching packet");
    let mut sent_packets = 0;
    let mut cur_port_idx = port_start_idx;
    while sent_packets < max_packets {
        let port = ports[cur_port_idx % ports.len()];
        for pub_ip in public_ips {
            let addr = SocketAddr::V4(SocketAddrV4::new(*pub_ip, port));
            for _ in 0..3 {
                let packet = new_hole_punch_packet(transaction_id, HOLE_PUNCH_PACKET_BODY_LEN);
                udp.send_to(&packet.into_bytes(), addr).await?;
            }
            sent_packets += 1;
        }
        cur_port_idx = cur_port_idx.wrapping_add(1);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    Ok(cur_port_idx % ports.len())
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{
        hole_punch::udp::{UdpPunchAcceptor, UdpPunchConnCounter, UdpResolvedPublicAddr},
        proto::common::StunInfo,
        tunnel::{Tunnel, memory::create_memory_tunnel_pair},
    };

    struct MockSocket {
        local_addr: SocketAddr,
        sent: tokio::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
        fail_next_send: AtomicUsize,
    }

    #[async_trait]
    impl UdpPunchSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            if self.fail_next_send.load(Ordering::Relaxed) != 0 {
                self.fail_next_send.fetch_sub(1, Ordering::Relaxed);
                return Err(io::Error::new(io::ErrorKind::Other, "mock send failure"));
            }
            self.sent.lock().await.push((data.to_vec(), _addr));
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct MockCounter {
        count: AtomicCell<u32>,
    }

    impl UdpPunchConnCounter for MockCounter {
        fn get(&self) -> Option<u32> {
            Some(self.count.load())
        }
    }

    struct MockAcceptor {
        tunnels: VecDeque<Box<dyn Tunnel>>,
    }

    #[async_trait]
    impl UdpPunchAcceptor for MockAcceptor {
        async fn accept(&mut self) -> anyhow::Result<Box<dyn Tunnel>> {
            let Some(tunnel) = self.tunnels.pop_front() else {
                return std::future::pending().await;
            };
            Ok(tunnel)
        }
    }

    struct MockRuntime {
        listeners: StdMutex<VecDeque<UdpPunchListener<MockSocket>>>,
    }

    impl MockRuntime {
        fn new(listeners: Vec<UdpPunchListener<MockSocket>>) -> Self {
            Self {
                listeners: StdMutex::new(listeners.into()),
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchRuntime for MockRuntime {
        type Socket = MockSocket;

        fn stun_info(&self) -> StunInfo {
            StunInfo::default()
        }

        async fn bind_udp(&self, _port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>> {
            Ok(Arc::new(MockSocket {
                local_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
                sent: tokio::sync::Mutex::new(Vec::new()),
                fail_next_send: AtomicUsize::new(0),
            }))
        }

        async fn resolve_udp_public_addr(
            &self,
            socket: Arc<Self::Socket>,
        ) -> anyhow::Result<UdpResolvedPublicAddr> {
            Ok(UdpResolvedPublicAddr {
                mapped_addr: socket.local_addr()?,
                port_mapping_lease: None,
            })
        }

        async fn create_listener(
            &self,
            _prefer_port_mapping: bool,
        ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
            self.listeners
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| anyhow::anyhow!("no listener"))
        }

        async fn create_port_bound_listener(
            &self,
            _port: u16,
        ) -> anyhow::Result<UdpPunchListener<Self::Socket>> {
            self.create_listener(false).await
        }

        async fn connect_with_socket(
            &self,
            _socket: Arc<Self::Socket>,
            _remote: SocketAddr,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            let (tunnel, _) = create_memory_tunnel_pair();
            Ok(tunnel)
        }
    }

    #[derive(Default)]
    struct MockSink {
        server_tunnels: AtomicUsize,
    }

    #[async_trait]
    impl UdpHolePunchTunnelSink for MockSink {
        async fn add_client_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            Ok(())
        }

        async fn add_server_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.server_tunnels.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn listener(port: u16, tunnels: Vec<Box<dyn Tunnel>>) -> UdpPunchListener<MockSocket> {
        UdpPunchListener {
            socket: Arc::new(MockSocket {
                local_addr: SocketAddr::from(([127, 0, 0, 1], port)),
                sent: tokio::sync::Mutex::new(Vec::new()),
                fail_next_send: AtomicUsize::new(0),
            }),
            mapped_addr: SocketAddr::from(([203, 0, 113, 1], port)),
            conn_counter: Arc::new(MockCounter::default()),
            acceptor: Box::new(MockAcceptor {
                tunnels: tunnels.into(),
            }),
            port_mapping_lease: None,
        }
    }

    #[tokio::test]
    async fn select_listener_creates_and_finds_listener() {
        let runtime = Arc::new(MockRuntime::new(vec![listener(10000, Vec::new())]));
        let sink = Arc::new(MockSink::default());
        let common = UdpHolePunchServerCommon::new(runtime, sink);

        let selected = common.select_listener(false, true).await.unwrap();

        assert_eq!(
            selected.mapped_addr,
            SocketAddr::from(([203, 0, 113, 1], 10000))
        );
        assert_eq!(
            selected.socket.local_addr().unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 10000))
        );
        assert!(common.find_listener(&selected.mapped_addr).await.is_some());
    }

    #[tokio::test]
    async fn accepted_tunnel_is_forwarded_to_sink() {
        let (server_tunnel, _) = create_memory_tunnel_pair();
        let runtime = Arc::new(MockRuntime::new(vec![listener(10001, vec![server_tunnel])]));
        let sink = Arc::new(MockSink::default());
        let common = UdpHolePunchServerCommon::new(runtime, sink.clone());

        common.select_listener(false, false).await.unwrap();

        for _ in 0..10 {
            if sink.server_tunnels.load(Ordering::Relaxed) == 1 {
                return;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(sink.server_tunnels.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn cone_packet_sender_keeps_old_batch_shape() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10002)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10002)),
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 3,
            packet_interval_ms: 0,
        };

        send_cone_hole_punch_packets(socket.clone(), &request)
            .await
            .unwrap();

        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 6);
        assert!(sent.iter().all(|(_, addr)| *addr == request.dest_addr));
    }

    #[tokio::test]
    async fn cone_packet_sender_rejects_malformed_dest_ip() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10004)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10004)),
            dest_addr: SocketAddr::from(([0, 0, 0, 0], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 3,
            packet_interval_ms: 0,
        };

        let err = send_cone_hole_punch_packets(socket.clone(), &request)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("dest_ip is malformed"));
        assert!(socket.sent.lock().await.is_empty());
    }

    #[tokio::test]
    async fn cone_packet_sender_continues_after_send_error() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10005)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(1),
        });
        let request = SendPunchPacketCone {
            listener_mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10005)),
            dest_addr: SocketAddr::from(([198, 51, 100, 1], 20000)),
            transaction_id: 9,
            packet_count_per_batch: 2,
            packet_batch_count: 1,
            packet_interval_ms: 0,
        };

        send_cone_hole_punch_packets(socket.clone(), &request)
            .await
            .unwrap();

        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 1);
    }

    #[tokio::test]
    async fn symmetric_packet_sender_returns_next_port_index() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10003)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(0),
        });
        let next_idx = send_symmetric_hole_punch_packet(
            &[10, 11, 12],
            socket.clone(),
            9,
            &[Ipv4Addr::new(198, 51, 100, 1)],
            1,
            2,
        )
        .await
        .unwrap();

        assert_eq!(next_idx, 0);
        let sent = socket.sent.lock().await;
        assert_eq!(sent.len(), 6);
        assert_eq!(sent[0].1, SocketAddr::from(([198, 51, 100, 1], 11)));
        assert_eq!(sent[3].1, SocketAddr::from(([198, 51, 100, 1], 12)));
    }

    #[tokio::test]
    async fn symmetric_packet_sender_returns_send_error() {
        let socket = Arc::new(MockSocket {
            local_addr: SocketAddr::from(([127, 0, 0, 1], 10006)),
            sent: tokio::sync::Mutex::new(Vec::new()),
            fail_next_send: AtomicUsize::new(1),
        });

        let err = send_symmetric_hole_punch_packet(
            &[10],
            socket.clone(),
            9,
            &[Ipv4Addr::new(198, 51, 100, 1)],
            0,
            1,
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("mock send failure"));
        assert!(socket.sent.lock().await.is_empty());
    }
}

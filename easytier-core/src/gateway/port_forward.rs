//! Host port-forward adapter backed by the data-plane runtime.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use quanta::Instant;
use tokio::{
    select,
    sync::{Mutex, OwnedMutexGuard, OwnedSemaphorePermit, Semaphore},
    task::JoinSet,
};
use tokio_util::{
    sync::{CancellationToken, DropGuard},
    task::AbortOnDropHandle,
};

use crate::{
    config::{gateway::PortForwardConfig, runtime::CoreRuntimeConfigStore},
    events::{CoreEvent, CoreEventSink},
    foundation::task::reap_joinset_background,
    gateway::dataplane::{
        DataPlaneConsumerLease, DataPlaneRuntime, DataPlaneTcpConnectOptions, DataPlaneTcpStream,
        DataPlaneUdpSocket,
    },
    socket::{
        SocketContext,
        tcp::{
            TcpListenOptions, TcpSocketPurpose, VirtualTcpListener, VirtualTcpListenerFactory,
            VirtualTcpSocket, VirtualTcpSocketFactory,
        },
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

const MAX_UDP_PAYLOAD_SIZE: usize = 65_507;
// A remote flow owns roughly 320 KiB of smoltcp and response buffers.
// Keep the per-instance worst case near 80 MiB instead of allowing a
// source-port flood to grow the WASM heap without bound.
const MAX_ACTIVE_UDP_CLIENTS: usize = 256;

#[derive(Debug, Eq, PartialEq, Hash, Clone)]
struct UdpClientKey {
    client_addr: SocketAddr,
    forward: PortForwardConfig,
}

enum PortForwardUdpFlow<H>
where
    H: VirtualUdpSocketFactory,
{
    Host(Arc<H::Socket>),
    DataPlane(Arc<DataPlaneUdpSocket>),
}

impl<H> PortForwardUdpFlow<H>
where
    H: VirtualUdpSocketFactory,
{
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> std::io::Result<usize> {
        match self {
            Self::Host(socket) => socket.send_to(buf, addr).await,
            Self::DataPlane(socket) => socket.send_to(buf, addr).await,
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
        match self {
            Self::Host(socket) => socket.recv_from(buf).await,
            Self::DataPlane(socket) => socket.recv_from(buf).await,
        }
    }
}

struct UdpClientInfo<H>
where
    H: VirtualUdpSocketFactory,
{
    flow: Arc<PortForwardUdpFlow<H>>,
    last_active: AtomicCell<Instant>,
    _slot: Arc<OwnedSemaphorePermit>,
}

struct UdpClientReservation {
    slot: OwnedSemaphorePermit,
    admission: OwnedMutexGuard<()>,
}

pub(crate) struct PortForwardAdapter<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    operation: Mutex<()>,
    started: AtomicBool,
    runtime_config: CoreRuntimeConfigStore,
    data_plane: Arc<DataPlaneRuntime<H>>,
    host: Arc<H>,
    socket_context: SocketContext,
    events: Arc<dyn CoreEventSink>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    cancel_tokens: Arc<DashMap<PortForwardConfig, DropGuard>>,
    udp_clients: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo<H>>>>,
    udp_response_tasks: Arc<DashMap<UdpClientKey, AbortOnDropHandle<()>>>,
    udp_client_admission: Arc<Mutex<()>>,
    udp_client_slots: Arc<Semaphore>,
    consumer_lease: Mutex<Option<DataPlaneConsumerLease>>,
}

impl<H> PortForwardAdapter<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new(
        runtime_config: CoreRuntimeConfigStore,
        data_plane: Arc<DataPlaneRuntime<H>>,
        host: Arc<H>,
        socket_context: SocketContext,
        events: Arc<dyn CoreEventSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            operation: Mutex::new(()),
            started: AtomicBool::new(false),
            runtime_config,
            data_plane,
            host,
            socket_context,
            events,
            tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            cancel_tokens: Arc::new(DashMap::new()),
            udp_clients: Arc::new(DashMap::new()),
            udp_response_tasks: Arc::new(DashMap::new()),
            udp_client_admission: Arc::new(Mutex::new(())),
            udp_client_slots: Arc::new(Semaphore::new(MAX_ACTIVE_UDP_CLIENTS)),
            consumer_lease: Mutex::new(None),
        })
    }

    pub(crate) async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.tasks.lock().unwrap().spawn(reap_joinset_background(
            self.tasks.clone(),
            "port-forward adapter",
        ));
        self.start_udp_reaper();
        let cfgs = self
            .runtime_config
            .snapshot()
            .services
            .gateway
            .port_forwards
            .clone();
        if let Err(error) = self.apply_port_forwards(&cfgs).await {
            self.stop_inner().await;
            return Err(error);
        }
        self.started.store(true, Ordering::Release);
        Ok(())
    }

    pub(crate) async fn reload(&self, cfgs: &[PortForwardConfig]) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if !self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        self.apply_port_forwards(cfgs).await
    }

    async fn apply_port_forwards(&self, cfgs: &[PortForwardConfig]) -> anyhow::Result<()> {
        for cfg in cfgs {
            if !matches!(cfg.proto.to_lowercase().as_str(), "tcp" | "udp") {
                anyhow::bail!(
                    "unsupported protocol: {}, only support udp / tcp",
                    cfg.proto
                );
            }
        }

        if !cfgs.is_empty() {
            let mut consumer_lease = self.consumer_lease.lock().await;
            if consumer_lease.is_none() {
                consumer_lease.replace(self.data_plane.acquire_consumer_lease()?);
            }
        }

        self.cancel_tokens.retain(|current, _| {
            cfgs.iter().any(|next| {
                if next.dst_addr.ip().is_unspecified() {
                    current.bind_addr == next.bind_addr && current.proto == next.proto
                } else {
                    current == next
                }
            })
        });
        self.udp_clients
            .retain(|key, _| self.cancel_tokens.contains_key(&key.forward));
        self.udp_response_tasks
            .retain(|key, _| self.udp_clients.contains_key(key));
        for cfg in cfgs {
            if !self.cancel_tokens.contains_key(cfg) {
                self.add_port_forward(cfg.clone()).await?;
            }
        }
        if cfgs.is_empty() {
            self.consumer_lease.lock().await.take();
        }
        Ok(())
    }

    async fn add_port_forward(&self, cfg: PortForwardConfig) -> anyhow::Result<()> {
        match cfg.proto.to_lowercase().as_str() {
            "tcp" => self.add_tcp_port_forward(&cfg).await?,
            "udp" => self.add_udp_port_forward(&cfg).await?,
            _ => {
                anyhow::bail!(
                    "unsupported protocol: {}, only support udp / tcp",
                    cfg.proto
                )
            }
        }
        self.events.emit(CoreEvent::GatewayPortForwardAdded(cfg));
        Ok(())
    }

    async fn add_tcp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let options = TcpListenOptions::port_forward(bind_addr);
        let bind = options
            .bind
            .clone()
            .with_context(self.socket_context.clone());
        let listener = self.host.bind_tcp(options.with_bind(bind)).await?;
        let cancel = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel.clone().drop_guard());

        let data_plane = self.data_plane.clone();
        let connections = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        connections.lock().unwrap().spawn(reap_joinset_background(
            connections.clone(),
            "TCP port-forward connections",
        ));
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let (incoming, source_addr) = select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    result = listener.accept() => match result {
                        Ok(accepted) => accepted,
                        Err(error) => {
                            tracing::error!(?error, ?bind_addr, "port-forward accept failed");
                            continue;
                        }
                    },
                };
                let data_plane = data_plane.clone();
                connections.lock().unwrap().spawn(async move {
                    let options = DataPlaneTcpConnectOptions::gateway(
                        Duration::from_secs(10),
                        TcpSocketPurpose::PortForward,
                        source_addr,
                    );
                    let outgoing = match data_plane.connect_tcp(dst_addr, options).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            tracing::error!(?error, ?dst_addr, "port-forward connect failed");
                            return;
                        }
                    };
                    copy_tcp(incoming, outgoing, dst_addr).await;
                });
            }
        });
        Ok(())
    }

    async fn add_udp_port_forward(&self, cfg: &PortForwardConfig) -> anyhow::Result<()> {
        let (bind_addr, dst_addr) = (cfg.bind_addr, cfg.dst_addr);
        let forward = cfg.clone();
        let socket = self
            .host
            .bind_udp(
                UdpBindOptions::port_forward(bind_addr).with_context(self.socket_context.clone()),
            )
            .await?;
        let cancel = CancellationToken::new();
        self.cancel_tokens
            .insert(cfg.clone(), cancel.clone().drop_guard());

        let data_plane = self.data_plane.clone();
        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let udp_clients = self.udp_clients.clone();
        let response_tasks = self.udp_response_tasks.clone();
        let client_admission = self.udp_client_admission.clone();
        let client_slots = self.udp_client_slots.clone();
        self.tasks.lock().unwrap().spawn(async move {
            let adapter = UdpFlowFactory {
                data_plane,
                host,
                socket_context,
            };
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD_SIZE];
            loop {
                let (len, client_addr) = select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    result = socket.recv_from(&mut buf) => match result {
                        Ok(packet) => packet,
                        Err(error) => {
                            tracing::error!(?error, ?bind_addr, "UDP port-forward receive failed");
                            continue;
                        }
                    },
                };
                let key = UdpClientKey {
                    client_addr,
                    forward: forward.clone(),
                };
                let flow = match udp_clients.get(&key) {
                    Some(client) => client.clone(),
                    None => {
                        let flow = match adapter.open(dst_addr).await {
                            Ok(flow) => flow,
                            Err(error) => {
                                tracing::error!(
                                    ?error,
                                    ?dst_addr,
                                    "open UDP data-plane flow failed"
                                );
                                continue;
                            }
                        };
                        let Some(reservation) = reserve_udp_client_slot(
                            &cancel,
                            &client_admission,
                            &client_slots,
                            &udp_clients,
                            &response_tasks,
                        )
                        .await
                        else {
                            tracing::trace!(
                                ?client_addr,
                                "UDP port-forward client limit remains full"
                            );
                            continue;
                        };
                        let UdpClientReservation { slot, admission } = reservation;
                        let slot = Arc::new(slot);
                        let client = Arc::new(UdpClientInfo {
                            flow: flow.clone(),
                            last_active: AtomicCell::new(Instant::now()),
                            _slot: slot.clone(),
                        });
                        udp_clients.insert(key.clone(), client.clone());

                        let inbound = socket.clone();
                        let response_flow = flow.clone();
                        let response_client = client_addr;
                        let response_slot = slot;
                        response_tasks.insert(
                            key.clone(),
                            AbortOnDropHandle::new(tokio::spawn(async move {
                                let _slot = response_slot;
                                let mut buf = vec![0u8; MAX_UDP_PAYLOAD_SIZE];
                                loop {
                                    match response_flow.recv_from(&mut buf).await {
                                        Ok((len, remote)) => {
                                            tracing::trace!(
                                                ?remote,
                                                ?response_client,
                                                len,
                                                "forwarding UDP data-plane response"
                                            );
                                            if let Err(error) =
                                                inbound.send_to(&buf[..len], response_client).await
                                            {
                                                tracing::error!(?error, "send UDP response failed");
                                                return;
                                            }
                                        }
                                        Err(error) => {
                                            tracing::error!(?error, "receive UDP response failed");
                                            return;
                                        }
                                    }
                                }
                            })),
                        );
                        drop(admission);
                        client
                    }
                };
                flow.last_active.store(Instant::now());
                if let Err(error) = flow.flow.send_to(&buf[..len], dst_addr).await {
                    tracing::error!(?error, ?dst_addr, "send UDP data-plane packet failed");
                }
            }
        });

        Ok(())
    }

    fn start_udp_reaper(&self) {
        let udp_clients = self.udp_clients.clone();
        let response_tasks = self.udp_response_tasks.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(30)).await;
                let now = Instant::now();
                udp_clients.retain(|_, client| {
                    now.duration_since(client.last_active.load()).as_secs() < 600
                });
                response_tasks.retain(|key, _| udp_clients.contains_key(key));
                udp_clients.shrink_to_fit();
                response_tasks.shrink_to_fit();
            }
        });
    }

    async fn stop_inner(&self) {
        self.started.store(false, Ordering::Release);
        self.cancel_tokens.clear();
        self.udp_response_tasks.clear();
        self.udp_clients.clear();
        self.consumer_lease.lock().await.take();
        let mut tasks = {
            let mut tasks = self.tasks.lock().unwrap();
            std::mem::replace(&mut *tasks, JoinSet::new())
        };
        tasks.shutdown().await;
    }

    pub(crate) async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_inner().await;
    }
}

async fn reserve_udp_client_slot<H>(
    cancel: &CancellationToken,
    admission: &Arc<Mutex<()>>,
    slots: &Arc<Semaphore>,
    clients: &DashMap<UdpClientKey, Arc<UdpClientInfo<H>>>,
    response_tasks: &DashMap<UdpClientKey, AbortOnDropHandle<()>>,
) -> Option<UdpClientReservation>
where
    H: VirtualUdpSocketFactory,
{
    // Keep eviction, permit handoff, and publication in one critical section.
    let admission = select! {
        biased;
        _ = cancel.cancelled() => return None,
        admission = admission.clone().lock_owned() => admission,
    };
    loop {
        if let Ok(slot) = slots.clone().try_acquire_owned() {
            return Some(UdpClientReservation { slot, admission });
        }

        let oldest = clients
            .iter()
            .min_by_key(|entry| entry.value().last_active.load())
            .map(|entry| entry.key().clone())?;
        let Some(evicted) = clients.remove(&oldest) else {
            continue;
        };
        drop(response_tasks.remove(&oldest));
        drop(evicted);
        let slot = select! {
            biased;
            _ = cancel.cancelled() => return None,
            slot = slots.clone().acquire_owned() => slot.ok()?,
        };
        return Some(UdpClientReservation { slot, admission });
    }
}

struct UdpFlowFactory<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    data_plane: Arc<DataPlaneRuntime<H>>,
    host: Arc<H>,
    socket_context: SocketContext,
}

impl<H> UdpFlowFactory<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    async fn open(&self, dst_addr: SocketAddr) -> anyhow::Result<Arc<PortForwardUdpFlow<H>>> {
        if self.data_plane.is_local_virtual_ip(dst_addr.ip()) {
            let socket = self
                .host
                .bind_udp(
                    UdpBindOptions::port_lease("0.0.0.0:0".parse().unwrap())
                        .with_context(self.socket_context.clone()),
                )
                .await?;
            Ok(Arc::new(PortForwardUdpFlow::Host(socket)))
        } else {
            let socket = self
                .data_plane
                .data_plane_udp_bind(0, Duration::from_secs(10))
                .await?;
            Ok(Arc::new(PortForwardUdpFlow::DataPlane(Arc::new(socket))))
        }
    }
}

async fn copy_tcp<S>(mut incoming: S, mut outgoing: DataPlaneTcpStream, dst_addr: SocketAddr)
where
    S: VirtualTcpSocket,
{
    match tokio::io::copy_bidirectional(&mut incoming, &mut outgoing).await {
        Ok((from_client, from_server)) => tracing::info!(
            ?dst_addr,
            from_client,
            from_server,
            "port-forward connection finished"
        ),
        Err(error) => tracing::error!(?error, ?dst_addr, "port-forward connection failed"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::testkit::{TestHost, TestUdpSocket};

    fn udp_client_key(port: u16) -> UdpClientKey {
        UdpClientKey {
            client_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            forward: PortForwardConfig {
                bind_addr: "127.0.0.1:5202".parse().unwrap(),
                dst_addr: "10.144.0.20:5201".parse().unwrap(),
                proto: "udp".to_owned(),
            },
        }
    }

    fn udp_client(slots: &Arc<Semaphore>, last_active: Instant) -> Arc<UdpClientInfo<TestHost>> {
        udp_client_with_slot(
            Arc::new(slots.clone().try_acquire_owned().unwrap()),
            last_active,
        )
    }

    fn udp_client_with_slot(
        slot: Arc<OwnedSemaphorePermit>,
        last_active: Instant,
    ) -> Arc<UdpClientInfo<TestHost>> {
        let flow: Arc<PortForwardUdpFlow<TestHost>> = Arc::new(PortForwardUdpFlow::Host(Arc::new(
            TestUdpSocket("127.0.0.1:20002".parse().unwrap()),
        )));
        Arc::new(UdpClientInfo {
            flow,
            last_active: AtomicCell::new(last_active),
            _slot: slot,
        })
    }

    fn pending_response_task(slot: Arc<OwnedSemaphorePermit>) -> AbortOnDropHandle<()> {
        AbortOnDropHandle::new(tokio::spawn(async move {
            let _slot = slot;
            std::future::pending().await
        }))
    }

    #[tokio::test]
    async fn udp_client_capacity_evicts_least_recently_active_flow() {
        let slots = Arc::new(Semaphore::new(2));
        let admission = Arc::new(Mutex::new(()));
        let clients: DashMap<UdpClientKey, Arc<UdpClientInfo<TestHost>>> = DashMap::new();
        let response_tasks: DashMap<UdpClientKey, AbortOnDropHandle<()>> = DashMap::new();
        let oldest = udp_client_key(40001);
        let newest = udp_client_key(40002);
        let now = Instant::now();
        let oldest_client = udp_client(&slots, now - Duration::from_secs(2));
        let newest_client = udp_client(&slots, now - Duration::from_secs(1));
        response_tasks.insert(
            oldest.clone(),
            pending_response_task(oldest_client._slot.clone()),
        );
        response_tasks.insert(
            newest.clone(),
            pending_response_task(newest_client._slot.clone()),
        );
        clients.insert(oldest.clone(), oldest_client);
        clients.insert(newest.clone(), newest_client);
        assert_eq!(slots.available_permits(), 0);

        let replacement = reserve_udp_client_slot(
            &CancellationToken::new(),
            &admission,
            &slots,
            &clients,
            &response_tasks,
        )
        .await
        .unwrap();

        assert!(!clients.contains_key(&oldest));
        assert!(!response_tasks.contains_key(&oldest));
        assert!(clients.contains_key(&newest));
        assert!(response_tasks.contains_key(&newest));
        assert_eq!(slots.available_permits(), 0);

        drop(replacement);
        response_tasks.clear();
        clients.clear();
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn udp_client_admission_covers_client_and_response_task_publication() {
        let slots = Arc::new(Semaphore::new(1));
        let admission = Arc::new(Mutex::new(()));
        let clients: Arc<DashMap<UdpClientKey, Arc<UdpClientInfo<TestHost>>>> =
            Arc::new(DashMap::new());
        let response_tasks: Arc<DashMap<UdpClientKey, AbortOnDropHandle<()>>> =
            Arc::new(DashMap::new());
        let oldest = udp_client_key(40001);
        let oldest_client = udp_client(&slots, Instant::now());
        response_tasks.insert(
            oldest.clone(),
            pending_response_task(oldest_client._slot.clone()),
        );
        clients.insert(oldest.clone(), oldest_client.clone());

        let reserve = || {
            let admission = admission.clone();
            let slots = slots.clone();
            let clients = clients.clone();
            let response_tasks = response_tasks.clone();
            tokio::spawn(async move {
                reserve_udp_client_slot(
                    &CancellationToken::new(),
                    &admission,
                    &slots,
                    &clients,
                    &response_tasks,
                )
                .await
            })
        };
        let first = reserve();
        tokio::time::timeout(Duration::from_secs(1), async {
            while clients.contains_key(&oldest) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        let mut second = reserve();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );

        drop(oldest_client);
        let first_slot = tokio::time::timeout(Duration::from_secs(1), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );

        let UdpClientReservation {
            slot,
            admission: admission_guard,
        } = first_slot;
        let replacement = udp_client_key(40002);
        let replacement_slot = Arc::new(slot);
        let replacement_client = udp_client_with_slot(replacement_slot.clone(), Instant::now());
        clients.insert(replacement.clone(), replacement_client.clone());

        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut second)
                .await
                .is_err()
        );
        assert!(clients.contains_key(&replacement));

        response_tasks.insert(replacement.clone(), pending_response_task(replacement_slot));
        drop(admission_guard);

        tokio::time::timeout(Duration::from_secs(1), async {
            while clients.contains_key(&replacement) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!response_tasks.contains_key(&replacement));

        drop(replacement_client);
        let second_slot = tokio::time::timeout(Duration::from_secs(1), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        drop(second_slot);
        tokio::task::yield_now().await;
        assert_eq!(slots.available_permits(), 1);
    }
}

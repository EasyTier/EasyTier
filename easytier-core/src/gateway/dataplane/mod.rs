//! Data-plane access built on top of the core gateway smoltcp stack.
//!
//! This module exposes TCP streams and UDP sockets (mainly for FFI callers that
//! send traffic through EasyTier without creating OS-level proxy listeners).
//!
//! Typical usage:
//!
//! ```ignore
//! let instance = CoreInstance::new(...);
//! instance.start().await?;
//!
//! let socket = instance.data_plane_udp_bind(local_port, timeout).await?;
//! socket.send_to(buf, peer_addr).await?;
//! ```

use std::{
    any::Any,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use pnet_packet::{Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket};
use tokio::{
    select,
    sync::{Mutex, mpsc},
    task::JoinSet,
};

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    foundation::task::reap_joinset_background,
    gateway::{
        proxy::{
            traits::TcpProxyStream,
            wrapped_transport::{WrappedTransportKind, WrappedTransportProxyModule},
        },
        smoltcp::{Net, UdpSocket},
    },
    packet::{PacketType, ZCPacket},
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    socket::{
        SocketContext,
        tcp::{
            TcpBindOptions, TcpConnectOptions, TcpListenOptions, TcpSocketPurpose,
            VirtualTcpListener, VirtualTcpListenerFactory, VirtualTcpSocket,
            VirtualTcpSocketFactory,
        },
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

mod deadline;
mod error;
mod flow;
mod operation;
mod packet;
mod resource;
mod route;
mod session;
mod stack;
mod tcp;
#[cfg(test)]
mod tests;
mod udp;

use self::{
    deadline::{DataPlaneDeadline, DataPlaneIoDeadline},
    error::DataPlaneResult,
    flow::{FlowKey, FlowKind, FlowLease, FlowTable},
    packet::PeerPacketRoute,
    resource::{DataPlaneConsumers, DataPlaneIoGuard, DataPlaneLease},
    route::{
        DataPlaneRoutePolicy, DataPlaneTcpRoute, DataPlaneTcpRouteInput,
        DataPlaneTransportPreference,
    },
    stack::SmoltcpPlane,
};

pub(crate) use self::resource::DataPlaneConsumerLease;
use self::tcp::DataPlaneTcpStreamRoute;
pub use self::{
    error::{DataPlaneError, DataPlaneErrorKind},
    operation::{
        DataPlaneCompletionDescriptor, DataPlaneCompletionStatus, DataPlaneOperationId,
        DataPlaneOperationKind, DataPlaneOperationOutcome, DataPlaneOperationResult,
        DataPlaneResourceId,
    },
    session::{DataPlaneSession, DataPlaneSessionLimits},
    tcp::{DataPlaneTcpListener, DataPlaneTcpStream},
    udp::DataPlaneUdpSocket,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct DataPlaneTcpConnectOptions {
    policy: DataPlaneRoutePolicy,
    transport: DataPlaneTransportPreference,
    purpose: TcpSocketPurpose,
    source_hint: Option<SocketAddr>,
    deadline: DataPlaneDeadline,
}

impl DataPlaneTcpConnectOptions {
    fn public(timeout: Duration) -> Self {
        Self::public_with_timeout(Some(timeout))
    }

    fn public_with_timeout(timeout: Option<Duration>) -> Self {
        Self::public_with_deadline(DataPlaneDeadline::from_optional_timeout(timeout))
    }

    fn public_with_deadline(deadline: DataPlaneDeadline) -> Self {
        Self {
            policy: DataPlaneRoutePolicy::OverlayOnly,
            transport: DataPlaneTransportPreference::SmoltcpOnly,
            purpose: TcpSocketPurpose::DataPlane,
            source_hint: None,
            deadline,
        }
    }

    pub(crate) fn gateway(
        timeout: Duration,
        purpose: TcpSocketPurpose,
        source_hint: SocketAddr,
    ) -> Self {
        Self {
            policy: DataPlaneRoutePolicy::OverlayOrDirect,
            transport: DataPlaneTransportPreference::PreferKcp,
            purpose,
            source_hint: Some(source_hint),
            deadline: DataPlaneDeadline::from_timeout(timeout),
        }
    }
}

pub(super) struct DataPlaneUdpIo(UdpSocket);

impl DataPlaneUdpIo {
    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        self.0.send_to(buf, addr).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.0.recv_from(buf).await
    }

    pub async fn recv_from_limited(
        &self,
        max_len: usize,
    ) -> Result<(Vec<u8>, SocketAddr, bool), std::io::Error> {
        self.0.recv_from_limited(max_len).await
    }
}

pub(super) enum FlowData {
    Tcp {
        _reservation: Arc<dyn Any + Send + Sync>,
    },
    // a data-plane routing entry that owns no resource. the entry_type in the
    // key distinguishes a listen route from an actively outbound route.
    DataPlaneRoute,
    Udp,
}

const UDP_ENTRY: FlowKind = FlowKind::Udp;
const TCP_ENTRY: FlowKind = FlowKind::Tcp;
const TCP_LISTEN_ENTRY: FlowKind = FlowKind::TcpListen;

type FlowSet = Arc<FlowTable<FlowData>>;
type DataPlaneTcpIo = Box<dyn TcpProxyStream>;

pub(crate) struct DataPlaneRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    operation: Mutex<()>,
    pub(super) runtime_started: AtomicBool,
    runtime_guard: DataPlaneIoGuard,
    runtime_config: CoreRuntimeConfigStore,
    pub(super) peer_manager: Weak<PeerManagerCore>,
    pub(super) transport_proxy: Option<Weak<WrappedTransportProxyModule>>,
    pub(super) host: Arc<H>,
    pub(super) socket_context: SocketContext,

    pub(super) runtime_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    packet_sender: mpsc::Sender<ZCPacket>,
    packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,

    net: Arc<Mutex<Option<SmoltcpPlane>>>,
    pub(super) entries: FlowSet,

    data_plane_consumers: Arc<DataPlaneConsumers>,
    // Tracks whether the smoltcp `net` is ready for data-plane callers.
    data_plane_net_ready: tokio::sync::watch::Sender<bool>,
    pipeline_guard: Mutex<Option<PipelineRegistrationGuard>>,
}

#[async_trait::async_trait]
impl<H> PeerPacketFilter for DataPlaneRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        if self.entries.is_idle() {
            if tracing::enabled!(tracing::Level::TRACE)
                && let Some(hdr) = packet.peer_manager_header()
                && matches!(
                    hdr.packet_type,
                    x if x == PacketType::Data as u8
                        || x == PacketType::DataWithKcpSrcModified as u8
                        || x == PacketType::DataWithQuicSrcModified as u8
                )
            {
                if let Some(ipv4) = Ipv4Packet::new(packet.payload()) {
                    let (tcp_src_port, tcp_dst_port, tcp_flags) =
                        if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                            TcpPacket::new(ipv4.payload())
                                .map(|tcp| {
                                    (
                                        Some(tcp.get_source()),
                                        Some(tcp.get_destination()),
                                        Some(tcp.get_flags()),
                                    )
                                })
                                .unwrap_or((None, None, None))
                        } else {
                            (None, None, None)
                        };
                    tracing::trace!(
                        packet_type = hdr.packet_type,
                        from_peer_id = hdr.from_peer_id.get(),
                        to_peer_id = hdr.to_peer_id.get(),
                        ipv4_src = %ipv4.get_source(),
                        ipv4_dst = %ipv4.get_destination(),
                        next_protocol = ?ipv4.get_next_level_protocol(),
                        ?tcp_src_port,
                        ?tcp_dst_port,
                        ?tcp_flags,
                        entry_count = 0,
                        "data plane fast gate passed packet from peer"
                    );
                } else {
                    tracing::trace!(
                        packet_type = hdr.packet_type,
                        from_peer_id = hdr.from_peer_id.get(),
                        to_peer_id = hdr.to_peer_id.get(),
                        entry_count = 0,
                        "data plane fast gate passed non-ipv4 packet from peer"
                    );
                }
            }
            return Some(packet);
        }
        let route = self.entries.route_peer_packet(&packet, true);
        let (entry_key, tcp_flags) = match route {
            PeerPacketRoute::Pass => return Some(packet),
            PeerPacketRoute::Unmatched { entry, tcp_flags } => {
                tracing::trace!(
                    entry_key = ?entry,
                    ?tcp_flags,
                    ipv4_src = %entry.dst.ip(),
                    ipv4_dst = %entry.src.ip(),
                    entry_count = self.entries.count(),
                    "data plane has no flow for packet from peer"
                );
                return Some(packet);
            }
            PeerPacketRoute::Deliver { entry, tcp_flags } => (entry, tcp_flags),
            PeerPacketRoute::FragmentedUdp { source, mirror } => {
                let source: IpAddr = source.into();
                tracing::trace!(
                    is_in_entries = mirror,
                    "ipv4 src = {:?}, check need send both smoltcp and kernel tun",
                    source
                );
                if mirror {
                    // if the packet is fragmented, no matther what the payload is, need send it to both smoltcp and kernel tun. because
                    // we cannot determine the udp port of the packet.
                    match self.packet_sender.try_send(packet.clone()) {
                        Ok(()) => tracing::trace!(
                            ?source,
                            entry_count = self.entries.count(),
                            "data plane delivered fragmented packet from peer to smoltcp"
                        ),
                        Err(err) => tracing::trace!(
                            ?source,
                            ?err,
                            entry_count = self.entries.count(),
                            "data plane failed to deliver fragmented packet from peer to smoltcp"
                        ),
                    }
                }
                return Some(packet);
            }
        };

        tracing::trace!(
            ?entry_key,
            ?tcp_flags,
            ipv4_src = %entry_key.dst.ip(),
            ipv4_dst = %entry_key.src.ip(),
            entry_count = self.entries.count(),
            "data plane found entry for packet from peer"
        );

        match self.packet_sender.try_send(packet) {
            Ok(()) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                entry_count = self.entries.count(),
                "data plane delivered packet from peer to smoltcp"
            ),
            Err(err) => tracing::trace!(
                ?entry_key,
                ?tcp_flags,
                ?err,
                entry_count = self.entries.count(),
                "data plane failed to deliver packet from peer to smoltcp"
            ),
        }

        None
    }
}

impl<H> DataPlaneRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    pub(crate) fn new(
        runtime_config: CoreRuntimeConfigStore,
        peer_manager: Arc<PeerManagerCore>,
        transport_proxy: Option<&Arc<WrappedTransportProxyModule>>,
        host: Arc<H>,
        socket_context: SocketContext,
    ) -> Arc<Self> {
        let (packet_sender, packet_recv) = mpsc::channel(1024);
        Arc::new(Self {
            operation: Mutex::new(()),
            runtime_started: AtomicBool::new(false),
            runtime_guard: DataPlaneIoGuard::new(),
            runtime_config,
            peer_manager: Arc::downgrade(&peer_manager),
            transport_proxy: transport_proxy.map(Arc::downgrade),
            host,
            socket_context,

            runtime_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            packet_recv: Arc::new(Mutex::new(packet_recv)),
            packet_sender,

            net: Arc::new(Mutex::new(None)),
            entries: Arc::new(FlowTable::default()),

            data_plane_consumers: Arc::new(DataPlaneConsumers::new()),
            data_plane_net_ready: tokio::sync::watch::channel(false).0,
            pipeline_guard: Mutex::new(None),
        })
    }

    fn runtime_ipv4(runtime_config: &CoreRuntimeConfigStore) -> Option<cidr::Ipv4Inet> {
        let prefix = runtime_config
            .snapshot()
            .peer
            .runtime
            .core
            .routes
            .ipv4
            .clone()?;
        let IpAddr::V4(address) = prefix.address else {
            return None;
        };
        cidr::Ipv4Inet::new(address, prefix.prefix_len).ok()
    }

    pub(crate) fn is_local_virtual_ip(&self, ip: IpAddr) -> bool {
        Self::runtime_ipv4(&self.runtime_config)
            .is_some_and(|inet| IpAddr::V4(inet.address()) == ip)
    }

    async fn run_net_update_task(self: &Arc<Self>) {
        let net = self.net.clone();
        let runtime_config = self.runtime_config.clone();
        let peer_manager = self.peer_manager.clone();
        let packet_recv = self.packet_recv.clone();
        let entries = self.entries.clone();
        let data_plane_consumers = self.data_plane_consumers.clone();
        let data_plane_net_ready = self.data_plane_net_ready.clone();
        self.runtime_tasks.lock().unwrap().spawn(async move {
            let mut prev_ipv4 = None;
            let mut peer_changes = runtime_config.subscribe_peer_runtime_changes();
            loop {
                let data_plane_active = data_plane_consumers.has_consumers();

                if !data_plane_active {
                    let old_net = {
                        let mut net_guard = net.lock().await;
                        // New leases and the zero-consumer teardown decision
                        // are serialized while this net slot is held. A bind
                        // can retain this generation or wait for its
                        // replacement, but cannot receive a stale generation.
                        if data_plane_consumers.has_consumers() {
                            continue;
                        }
                        net_guard.take()
                    };
                    if let Some(old_net) = &old_net {
                        old_net.close(DataPlaneErrorKind::HandleClosed);
                    }
                    let had_net = old_net.is_some();
                    prev_ipv4 = None;
                    let cleared = entries.clear();
                    tracing::trace!(
                        had_net,
                        data_plane_active,
                        removed_entries = cleared.removed,
                        entry_count = cleared.count.current,
                        entries_len = entries.len(),
                        "data plane waiting for consumers"
                    );
                    let _ = data_plane_net_ready.send_replace(false);
                    select! {
                        _ = peer_changes.changed() => {}
                        _ = data_plane_consumers.changed() => {}
                    }
                    continue;
                }

                let cur_ipv4 = Self::runtime_ipv4(&runtime_config);
                if prev_ipv4 != cur_ipv4 {
                    let old_ipv4 = prev_ipv4;
                    prev_ipv4 = cur_ipv4;

                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        old_entry_count = entries.count(),
                        old_entries_len = entries.len(),
                        "data plane resetting flows for ipv4 change"
                    );
                    let _ = data_plane_net_ready.send_replace(false);
                    let old_net = net.lock().await.take();
                    if let Some(old_net) = old_net {
                        old_net.close(DataPlaneErrorKind::NetworkChanged);
                    }
                    let cleared = entries.clear();
                    tracing::trace!(
                        ?old_ipv4,
                        ?cur_ipv4,
                        removed_entries = cleared.removed,
                        new_entry_count = cleared.count.current,
                        new_entries_len = entries.len(),
                        "data plane reset flows complete"
                    );

                    if let Some(cur_ipv4) = cur_ipv4 {
                        net.lock().await.replace(SmoltcpPlane::new(
                            cur_ipv4,
                            peer_manager.clone(),
                            packet_recv.clone(),
                        ));
                        tracing::trace!(
                            ?cur_ipv4,
                            entry_count = entries.count(),
                            entries_len = entries.len(),
                            "data plane installed smoltcp net"
                        );
                        // Wake any data-plane callers waiting in
                        // `wait_data_plane_net` for the smoltcp net to appear.
                        let _ = data_plane_net_ready.send_replace(true);
                    } else {
                        tracing::trace!(
                            entry_count = entries.count(),
                            entries_len = entries.len(),
                            "data plane removed smoltcp net"
                        );
                    }
                }

                select! {
                    _ = peer_changes.changed() => {}
                    _ = data_plane_consumers.changed() => {}
                }
            }
        });
    }

    async fn start_runtime_inner(self: &Arc<Self>) -> anyhow::Result<()> {
        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is gone"));
        };
        let guard = peer_manager
            .add_managed_packet_process_pipeline(Box::new(self.clone()))
            .await;
        self.pipeline_guard.lock().await.replace(guard);

        self.runtime_tasks
            .lock()
            .unwrap()
            .spawn(reap_joinset_background(
                self.runtime_tasks.clone(),
                "data plane runtime",
            ));
        self.run_net_update_task().await;

        tracing::trace!("data plane peer packet pipeline registered");
        Ok(())
    }

    pub(crate) async fn start_runtime(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.runtime_started.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.start_runtime_inner().await {
            self.stop_runtime_inner().await;
            return Err(error);
        }
        self.runtime_started.store(true, Ordering::Release);
        Ok(())
    }

    async fn shutdown_tasks(tasks: &Arc<std::sync::Mutex<JoinSet<()>>>) {
        let mut tasks = {
            let mut guard = tasks.lock().unwrap();
            std::mem::replace(&mut *guard, JoinSet::new())
        };
        tasks.shutdown().await;
    }

    async fn stop_runtime_inner(&self) {
        self.runtime_started.store(false, Ordering::Release);
        self.runtime_guard
            .close(DataPlaneErrorKind::InstanceStopped);
        if let Some(guard) = self.pipeline_guard.lock().await.take() {
            guard.close();
        }
        if let Some(net) = self.net.lock().await.take() {
            net.close(DataPlaneErrorKind::InstanceStopped);
        }
        let _ = self.data_plane_net_ready.send_replace(false);
        self.entries.clear();
        Self::shutdown_tasks(&self.runtime_tasks).await;
    }

    pub(crate) async fn stop_runtime(&self) {
        let _operation = self.operation.lock().await;
        self.stop_runtime_inner().await;
    }
}

impl<H> DataPlaneRuntime<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    async fn tcp_route_input(
        &self,
        dst_addr: SocketAddr,
        options: DataPlaneTcpConnectOptions,
    ) -> DataPlaneResult<DataPlaneTcpRouteInput> {
        let IpAddr::V4(dst_ip) = dst_addr.ip() else {
            return Err(DataPlaneError::new(
                DataPlaneErrorKind::AddressFamilyUnsupported,
                "the EasyTier data plane currently supports IPv4 destinations only",
            ));
        };
        self.runtime_guard.ensure_open()?;
        let local_virtual_ip = Self::runtime_ipv4(&self.runtime_config).map(|inet| inet.address());
        let local_virtual_destination = local_virtual_ip == Some(dst_ip);
        let local_endpoint = local_virtual_destination
            && self.entries.contains_key(&FlowKey {
                src: dst_addr,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: TCP_LISTEN_ENTRY,
            });

        let peer_manager = self.peer_manager.upgrade().ok_or_else(|| {
            DataPlaneError::new(
                DataPlaneErrorKind::InstanceStopped,
                "peer manager is no longer available",
            )
        })?;
        let overlay_destination = if local_virtual_destination {
            true
        } else {
            let (peers, _) = options
                .deadline
                .run(async {
                    Ok::<_, DataPlaneError>(peer_manager.get_msg_dst_peer(&dst_addr.ip()).await)
                })
                .await?;
            !peers.is_empty()
        };

        let prefer_kcp = options.transport == DataPlaneTransportPreference::PreferKcp;
        let transport_proxy = self.transport_proxy.as_ref().and_then(Weak::upgrade);
        let kcp_ready = if prefer_kcp && overlay_destination {
            match &transport_proxy {
                Some(proxy) => {
                    options
                        .deadline
                        .run(async {
                            Ok::<_, DataPlaneError>(
                                proxy.source_connect_ready(WrappedTransportKind::Kcp).await,
                            )
                        })
                        .await?
                }
                None => false,
            }
        } else {
            false
        };
        let kcp_allowed = if prefer_kcp && kcp_ready {
            options
                .deadline
                .run(async {
                    Ok::<_, DataPlaneError>(
                        peer_manager.check_allow_kcp_to_dst(&dst_addr.ip()).await,
                    )
                })
                .await?
        } else {
            false
        };

        Ok(DataPlaneTcpRouteInput {
            policy: options.policy,
            transport: options.transport,
            local_endpoint,
            local_virtual_destination,
            overlay_destination,
            smoltcp_ready: self.net.lock().await.is_some(),
            kcp_ready,
            kcp_allowed,
        })
    }

    async fn connect_smoltcp_tcp(
        &self,
        dst_addr: SocketAddr,
        deadline: DataPlaneDeadline,
        data_plane_ref: DataPlaneLease,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        let (ipv4_addr, smoltcp_net, generation) = self.wait_data_plane_net(deadline).await?;
        let listen_options = TcpListenOptions::port_lease("0.0.0.0:0".parse().unwrap());
        let reservation = generation
            .while_open(
                deadline.run(
                    self.host.bind_tcp(
                        listen_options.clone().with_bind(
                            listen_options
                                .bind
                                .with_context(self.socket_context.clone()),
                        ),
                    ),
                ),
            )
            .await?;
        let local_port = reservation
            .local_addr()
            .map_err(DataPlaneError::from)?
            .port();
        let local_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let (flow, _) = FlowLease::register(
            self.entries.clone(),
            FlowKey {
                src: local_addr,
                dst: dst_addr,
                kind: TCP_ENTRY,
            },
            FlowData::Tcp {
                _reservation: reservation,
            },
        );
        let stream = generation
            .while_open(deadline.run(smoltcp_net.tcp_connect(dst_addr, local_port)))
            .await?;
        generation.ensure_open()?;

        Ok(DataPlaneTcpStream::new(
            Box::new(stream),
            local_addr,
            Some(data_plane_ref),
            DataPlaneTcpStreamRoute::Outbound { _flow: flow },
            generation,
        ))
    }

    async fn connect_host_tcp(
        &self,
        dst_addr: SocketAddr,
        options: DataPlaneTcpConnectOptions,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        let connect_options = TcpConnectOptions::direct_connect(dst_addr)
            .with_purpose(options.purpose)
            .with_bind(TcpBindOptions::default().with_context(self.socket_context.clone()));
        let socket = self
            .runtime_guard
            .while_open(options.deadline.run(self.host.connect_tcp(connect_options)))
            .await?;
        let local_addr = socket.local_addr().map_err(DataPlaneError::from)?;
        Ok(DataPlaneTcpStream::new(
            Box::new(socket),
            local_addr,
            None,
            DataPlaneTcpStreamRoute::External,
            self.runtime_guard.clone(),
        ))
    }

    async fn connect_kcp_tcp(
        &self,
        dst_addr: SocketAddr,
        options: DataPlaneTcpConnectOptions,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        let source_addr = options.source_hint.ok_or_else(|| {
            DataPlaneError::new(
                DataPlaneErrorKind::PathNotReady,
                "KCP gateway route requires a logical source address",
            )
        })?;
        let transport_proxy = self
            .transport_proxy
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                DataPlaneError::new(
                    DataPlaneErrorKind::PathNotReady,
                    "KCP source transport is not ready",
                )
            })?;
        let stream = self
            .runtime_guard
            .while_open(options.deadline.run(transport_proxy.connect_source(
                WrappedTransportKind::Kcp,
                source_addr,
                dst_addr,
            )))
            .await?;
        Ok(DataPlaneTcpStream::new(
            stream,
            source_addr,
            None,
            DataPlaneTcpStreamRoute::External,
            self.runtime_guard.clone(),
        ))
    }

    pub(crate) async fn connect_tcp(
        &self,
        dst_addr: SocketAddr,
        options: DataPlaneTcpConnectOptions,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        let mut route_input = self.tcp_route_input(dst_addr, options).await?;
        let route = match route_input.select() {
            Ok(route) => route,
            Err(error) if error.kind() == DataPlaneErrorKind::PathNotReady => {
                let data_plane_ref = self.acquire_data_plane_ref()?;
                let _ = self.wait_data_plane_net(options.deadline).await?;
                route_input.smoltcp_ready = true;
                let route = route_input.select()?;
                return self
                    .connect_selected_tcp(dst_addr, options, route, Some(data_plane_ref))
                    .await;
            }
            Err(error) => return Err(error),
        };
        self.connect_selected_tcp(dst_addr, options, route, None)
            .await
    }

    async fn connect_selected_tcp(
        &self,
        dst_addr: SocketAddr,
        options: DataPlaneTcpConnectOptions,
        route: DataPlaneTcpRoute,
        data_plane_ref: Option<DataPlaneLease>,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        tracing::debug!(?dst_addr, ?route, "selected data-plane TCP route");
        match route {
            DataPlaneTcpRoute::LocalEndpoint | DataPlaneTcpRoute::Smoltcp => {
                let data_plane_ref = match data_plane_ref {
                    Some(lease) => lease,
                    None => self.acquire_data_plane_ref()?,
                };
                self.connect_smoltcp_tcp(dst_addr, options.deadline, data_plane_ref)
                    .await
            }
            DataPlaneTcpRoute::LocalHost => {
                self.connect_host_tcp(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dst_addr.port()),
                    options,
                )
                .await
            }
            DataPlaneTcpRoute::Kcp => self.connect_kcp_tcp(dst_addr, options).await,
            DataPlaneTcpRoute::Direct => self.connect_host_tcp(dst_addr, options).await,
        }
    }

    fn acquire_data_plane_ref(&self) -> DataPlaneResult<DataPlaneLease> {
        if !self.runtime_started.load(Ordering::Acquire) || self.runtime_guard.is_closed() {
            return Err(DataPlaneError::new(
                DataPlaneErrorKind::InstanceStopped,
                "data-plane runtime is not running",
            ));
        }
        let lease = DataPlaneLease::acquire(self.data_plane_consumers.clone());
        if !self.runtime_started.load(Ordering::Acquire) || self.runtime_guard.is_closed() {
            drop(lease);
            return Err(DataPlaneError::new(
                DataPlaneErrorKind::InstanceStopped,
                "data-plane runtime stopped while acquiring a resource",
            ));
        }
        Ok(lease)
    }

    pub(crate) fn acquire_consumer_lease(&self) -> DataPlaneResult<DataPlaneConsumerLease> {
        self.acquire_data_plane_ref()
            .map(DataPlaneConsumerLease::new)
    }

    async fn wait_data_plane_net(
        &self,
        deadline: DataPlaneDeadline,
    ) -> DataPlaneResult<(cidr::Ipv4Inet, Arc<Net>, DataPlaneIoGuard)> {
        let mut ready = self.data_plane_net_ready.subscribe();
        loop {
            if let Some(net) = self
                .net
                .lock()
                .await
                .as_ref()
                .map(|plane| (plane.ipv4_addr, plane.net.clone(), plane.lease()))
            {
                net.2.ensure_open()?;
                return Ok(net);
            }

            tokio::select! {
                _ = self.runtime_guard.closed() => {
                    return Err(DataPlaneError::new(
                        DataPlaneErrorKind::InstanceStopped,
                        "data-plane runtime stopped while waiting for the stack",
                    ));
                }
                result = deadline.run(async {
                    ready
                        .wait_for(|ready| *ready)
                        .await
                        .map(|_| ())
                        .map_err(|_| DataPlaneError::new(
                            DataPlaneErrorKind::InstanceStopped,
                            "data-plane readiness channel closed",
                        ))
                }) => {
                    result?;
                }
            }
        }
    }

    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> DataPlaneResult<DataPlaneTcpStream> {
        self.connect_tcp(dst_addr, DataPlaneTcpConnectOptions::public(timeout))
            .await
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> DataPlaneResult<DataPlaneTcpListener> {
        self.data_plane_tcp_bind_with_deadline(local_port, DataPlaneDeadline::from_timeout(timeout))
            .await
    }

    async fn data_plane_tcp_bind_with_deadline(
        &self,
        local_port: u16,
        deadline: DataPlaneDeadline,
    ) -> DataPlaneResult<DataPlaneTcpListener> {
        let data_plane_ref = self.acquire_data_plane_ref()?;
        let (ipv4_addr, smoltcp_net, generation) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let listener = generation
            .while_open(deadline.run(smoltcp_net.tcp_bind(bind_addr)))
            .await?;
        generation.ensure_open()?;
        let local_addr = listener.local_addr().map_err(DataPlaneError::from)?;
        let listen_route = FlowLease::try_register(
            self.entries.clone(),
            FlowKey {
                src: local_addr,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: TCP_LISTEN_ENTRY,
            },
            FlowData::DataPlaneRoute,
        )
        .ok_or_else(|| {
            DataPlaneError::new(
                DataPlaneErrorKind::AddressInUse,
                "data-plane TCP listener already exists",
            )
        })?;

        Ok(DataPlaneTcpListener {
            listener,
            local_addr,
            flows: self.entries.clone(),
            _listen_flow: listen_route,
            data_plane_lease: data_plane_ref,
            generation,
        })
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> DataPlaneResult<DataPlaneUdpSocket> {
        self.data_plane_udp_bind_with_deadline(local_port, DataPlaneDeadline::from_timeout(timeout))
            .await
    }

    async fn data_plane_udp_bind_with_deadline(
        &self,
        local_port: u16,
        deadline: DataPlaneDeadline,
    ) -> DataPlaneResult<DataPlaneUdpSocket> {
        let data_plane_ref = self.acquire_data_plane_ref()?;
        let (ipv4_addr, smoltcp_net, generation) = self.wait_data_plane_net(deadline).await?;
        let reservation_options = UdpBindOptions::port_lease(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            local_port,
        ))
        .with_context(self.socket_context.clone());
        let reservation = generation
            .while_open(deadline.run(self.host.bind_udp(reservation_options)))
            .await?;
        let reserved_port = reservation
            .local_addr()
            .map_err(DataPlaneError::from)?
            .port();
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), reserved_port);
        let smol = generation
            .while_open(deadline.run(smoltcp_net.udp_bind(bind_addr)))
            .await?;
        generation.ensure_open()?;
        let local_addr = smol.local_addr().map_err(DataPlaneError::from)?;
        let socket = Arc::new(DataPlaneUdpIo(smol));

        Ok(DataPlaneUdpSocket {
            socket,
            flows: self.entries.clone(),
            routes: std::sync::Mutex::new(std::collections::HashMap::new()),
            local_addr,
            _reservation: reservation,
            _data_plane_lease: data_plane_ref,
            generation,
        })
    }
}

#[cfg(feature = "proxy-packet")]
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "proxy-packet")]
use std::sync::Mutex as StdMutex;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::{sync::Mutex, task::JoinSet};

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    connectivity::direct::DirectConnectorHost,
    connectivity::hole_punch::tcp::TcpHolePunchHost,
    listener::RunningListenerRegistry,
    packet::{PacketType, ZCPacket, ZCPacketType},
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
    proxy::cidr_table::ProxyCidrTable,
    socket::SocketContext,
};

#[cfg(feature = "proxy-packet")]
pub use crate::proxy::wrapped_transport_destination::WrappedTransportDestinationIngress;
#[cfg(feature = "proxy-packet")]
use crate::proxy::wrapped_transport_destination::{
    WrappedTransportDestinationIngresses, WrappedTransportDestinationLifecycle,
    WrappedTransportDestinationModule,
};
#[cfg(feature = "proxy-packet")]
use crate::proxy::{
    runtime::{ProxyRuntimeInfo, TcpProxyDestinationConnector, TcpProxyStream},
    service::CoreProxyRuntime,
    tcp_proxy_engine::{TcpNatEntrySnapshot, TcpProxyMode, TcpProxyNicContext},
    tcp_proxy_service::TcpProxyService,
    wrapped_tcp_proxy::{
        WrappedTcpProxyNicContext, WrappedTcpProxyTransport,
        try_process_wrapped_tcp_packet_from_nic,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WrappedTransportDirections {
    pub source: bool,
    pub destination: bool,
}

impl WrappedTransportDirections {
    fn enabled(self) -> bool {
        self.source || self.destination
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedTransportKind {
    Kcp,
    Quic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappedTransportRole {
    Source,
    Destination,
}

#[derive(Debug, Clone)]
pub struct WrappedTransportDatagram {
    pub transport: WrappedTransportKind,
    pub role: WrappedTransportRole,
    pub peer_id: u32,
    pub buffer: WrappedTransportDatagramBuffer,
}

#[derive(Debug, Clone)]
pub struct WrappedTransportDatagramBuffer(ZCPacket);

impl WrappedTransportDatagramBuffer {
    pub fn copy_from_payload(payload: &[u8]) -> Self {
        Self(ZCPacket::new_with_payload(payload))
    }

    pub fn from_packet_buffer(buffer: BytesMut, packet_type: ZCPacketType) -> Self {
        Self(ZCPacket::new_from_buf(buffer, packet_type))
    }
}

impl WrappedTransportDatagram {
    fn into_packet(self, my_peer_id: u32) -> ZCPacket {
        let mut packet = self.buffer.0;
        packet.fill_peer_manager_hdr(
            my_peer_id,
            self.peer_id,
            self.transport.packet_type(self.role) as u8,
        );
        packet
    }
}

#[derive(Clone)]
pub struct WrappedTransportEngineStart {
    pub directions: WrappedTransportDirections,
    pub my_peer_id: u32,
    pub datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
    #[cfg(feature = "proxy-packet")]
    pub destination_ingress: Option<WrappedTransportDestinationIngress>,
}

#[cfg(feature = "proxy-packet")]
#[derive(Debug, Clone, Copy)]
pub struct WrappedTransportConnect {
    pub my_peer_id: u32,
    pub dst_peer_id: u32,
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

#[cfg(feature = "proxy-packet")]
pub struct WrappedTransportAcceptedStream {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub initial_acl_packet_size: usize,
    pub stream: Box<dyn TcpProxyStream>,
}

#[async_trait]
pub trait WrappedTransportEngine: Send + Sync + 'static {
    async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()>;
    async fn activate(&self) -> anyhow::Result<()>;
    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()>;
    #[cfg(feature = "proxy-packet")]
    async fn connect_source(
        &self,
        request: WrappedTransportConnect,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>>;
    async fn stop(&self);
}

#[derive(Default)]
pub struct WrappedTransportEngines {
    pub kcp: Option<Arc<dyn WrappedTransportEngine>>,
    pub quic: Option<Arc<dyn WrappedTransportEngine>>,
}

#[cfg(feature = "proxy-packet")]
#[derive(Clone)]
struct WrappedTransportSourceConnector {
    peer_manager: Arc<PeerManagerCore>,
    engine: Weak<dyn WrappedTransportEngine>,
    transport: WrappedTransportKind,
}

#[cfg(feature = "proxy-packet")]
async fn connect_wrapped_transport_source(
    peer_manager: &PeerManagerCore,
    engine: Arc<dyn WrappedTransportEngine>,
    src: SocketAddr,
    dst: SocketAddr,
) -> anyhow::Result<Box<dyn TcpProxyStream>> {
    let SocketAddr::V4(dst_v4) = dst else {
        anyhow::bail!("IPv6 is not supported by wrapped TCP proxy");
    };
    let dst_peer_id = peer_manager
        .get_peer_map()
        .get_peer_id_by_ipv4(dst_v4.ip())
        .await
        .ok_or_else(|| anyhow::anyhow!("no peer found for wrapped TCP dst: {dst}"))?;
    engine
        .connect_source(WrappedTransportConnect {
            my_peer_id: peer_manager.my_peer_id(),
            dst_peer_id,
            src,
            dst,
        })
        .await
}

#[cfg(feature = "proxy-packet")]
#[async_trait]
impl TcpProxyDestinationConnector for WrappedTransportSourceConnector {
    type DstStream = Box<dyn TcpProxyStream>;

    async fn connect(&self, src: SocketAddr, dst: SocketAddr) -> anyhow::Result<Self::DstStream> {
        let engine = self
            .engine
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("wrapped transport engine is not available"))?;
        connect_wrapped_transport_source(&self.peer_manager, engine, src, dst).await
    }

    fn proxy_mode(&self) -> TcpProxyMode {
        match self.transport {
            WrappedTransportKind::Kcp => TcpProxyMode::KcpSrc,
            WrappedTransportKind::Quic => TcpProxyMode::QuicSrc,
        }
    }
}

#[cfg(feature = "proxy-packet")]
type WrappedTransportSourceService<H> =
    TcpProxyService<CoreProxyRuntime<H>, H, WrappedTransportSourceConnector>;

#[cfg(feature = "proxy-packet")]
struct WrappedTransportSource<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<CoreProxyRuntime<H>>,
    host: Arc<H>,
    connector: Arc<WrappedTransportSourceConnector>,
    cidr_table: Arc<ProxyCidrTable>,
    socket_context: SocketContext,
    service: StdMutex<Option<Arc<WrappedTransportSourceService<H>>>>,
    transport: WrappedTransportKind,
}

#[cfg(feature = "proxy-packet")]
impl<H> WrappedTransportSource<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        running_listeners: Arc<RunningListenerRegistry>,
        runtime_config: CoreRuntimeConfigStore,
        cidr_table: Arc<ProxyCidrTable>,
        socket_context: SocketContext,
        engine: &Arc<dyn WrappedTransportEngine>,
        transport: WrappedTransportKind,
    ) -> Arc<Self> {
        let protocol_label = match transport {
            WrappedTransportKind::Kcp => "KCP",
            WrappedTransportKind::Quic => "QUIC",
        };
        let runtime = CoreProxyRuntime::new(
            peer_manager.clone(),
            host.clone(),
            running_listeners,
            runtime_config,
            protocol_label,
        );
        let connector = Arc::new(WrappedTransportSourceConnector {
            peer_manager: peer_manager.clone(),
            engine: Arc::downgrade(engine),
            transport,
        });
        Arc::new(Self {
            peer_manager,
            runtime,
            host,
            connector,
            cidr_table,
            socket_context,
            service: StdMutex::new(None),
            transport,
        })
    }

    fn build_service(&self) -> Arc<WrappedTransportSourceService<H>> {
        TcpProxyService::new_with_socket_context(
            self.peer_manager.clone(),
            self.runtime.clone(),
            self.host.clone(),
            self.connector.clone(),
            self.cidr_table.clone(),
            self.socket_context.clone(),
        )
    }

    async fn start_service(self: &Arc<Self>) -> Result<PipelineRegistrationGuard, anyhow::Error> {
        let service = {
            let mut active = self.service.lock().unwrap();
            if active.is_some() {
                anyhow::bail!("wrapped transport source is already started");
            }
            let service = self.build_service();
            active.replace(service.clone());
            service
        };
        self.runtime.latch_smoltcp();
        let guard = self
            .peer_manager
            .add_managed_nic_packet_process_pipeline(Box::new(WrappedTransportSourceFilter {
                source: Arc::downgrade(self),
            }))
            .await;
        service.register_peer_pipeline().await;
        if let Err(error) = service.start(false).await {
            guard.close();
            self.stop_service().await;
            return Err(anyhow::Error::new(error));
        }
        Ok(guard)
    }

    async fn stop_service(&self) {
        let service = self.service.lock().unwrap().take();
        if let Some(service) = service {
            service.stop_and_wait().await;
        }
    }

    fn source_entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot> {
        self.service
            .lock()
            .unwrap()
            .as_ref()
            .map_or_else(Vec::new, |service| service.engine().list_entries())
    }

    async fn try_process_nic_packet(&self, packet: &mut ZCPacket) -> bool {
        let Some(service) = self.service.lock().unwrap().clone() else {
            return false;
        };
        let snapshot = self.runtime.proxy_runtime_snapshot();
        let engine = service.engine();
        if engine.try_process_packet_from_nic(
            packet,
            TcpProxyNicContext {
                local_inet: snapshot.local_inet,
                local_port: engine.local_port(),
                my_peer_id: self.peer_manager.my_peer_id(),
                smoltcp_enabled: snapshot.smoltcp_enabled,
            },
        ) {
            return true;
        }

        let connection_engine = engine.clone();
        let peer_manager = self.peer_manager.clone();
        let transport = self.transport;
        try_process_wrapped_tcp_packet_from_nic(
            packet,
            WrappedTcpProxyNicContext {
                transport: match transport {
                    WrappedTransportKind::Kcp => WrappedTcpProxyTransport::Kcp,
                    WrappedTransportKind::Quic => WrappedTcpProxyTransport::Quic,
                },
                my_peer_id: self.peer_manager.my_peer_id(),
                local_ipv4: snapshot.local_inet.map(|inet| inet.address()),
                smoltcp_enabled: snapshot.smoltcp_enabled,
            },
            move |src| connection_engine.is_tcp_proxy_connection(src),
            move |dst_ip| async move {
                match transport {
                    WrappedTransportKind::Kcp => {
                        peer_manager
                            .check_allow_kcp_to_dst(&IpAddr::V4(dst_ip))
                            .await
                    }
                    WrappedTransportKind::Quic => {
                        peer_manager
                            .check_allow_quic_to_dst(&IpAddr::V4(dst_ip))
                            .await
                    }
                }
            },
        )
        .await
    }
}

#[cfg(feature = "proxy-packet")]
#[async_trait]
trait WrappedTransportSourceLifecycle: Send + Sync {
    async fn start(self: Arc<Self>) -> anyhow::Result<PipelineRegistrationGuard>;
    async fn stop(&self);
    fn entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot>;
    fn is_started(&self) -> bool;
}

#[cfg(feature = "proxy-packet")]
#[async_trait]
impl<H> WrappedTransportSourceLifecycle for WrappedTransportSource<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    async fn start(self: Arc<Self>) -> anyhow::Result<PipelineRegistrationGuard> {
        self.start_service().await
    }

    async fn stop(&self) {
        self.stop_service().await;
    }

    fn entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot> {
        self.source_entry_snapshots()
    }

    fn is_started(&self) -> bool {
        self.service
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|service| service.is_started())
    }
}

#[cfg(feature = "proxy-packet")]
struct WrappedTransportSourceFilter<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    source: Weak<WrappedTransportSource<H>>,
}

#[cfg(feature = "proxy-packet")]
#[async_trait]
impl<H> crate::peers::NicPacketFilter for WrappedTransportSourceFilter<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    async fn try_process_packet_from_nic(&self, packet: &mut ZCPacket) -> bool {
        let Some(source) = self.source.upgrade() else {
            return false;
        };
        source.try_process_nic_packet(packet).await
    }
}

#[derive(Default)]
struct WrappedTransportProxyState {
    active: bool,
    kcp_started: bool,
    quic_started: bool,
    #[cfg(feature = "proxy-packet")]
    kcp_source_connect_ready: bool,
    #[cfg(feature = "proxy-packet")]
    quic_source_connect_ready: bool,
    #[cfg(feature = "proxy-packet")]
    kcp_source_started: bool,
    #[cfg(feature = "proxy-packet")]
    quic_source_started: bool,
    #[cfg(feature = "proxy-packet")]
    destination_started: bool,
    #[cfg(feature = "proxy-packet")]
    kcp_source_guard: Option<PipelineRegistrationGuard>,
    #[cfg(feature = "proxy-packet")]
    quic_source_guard: Option<PipelineRegistrationGuard>,
    pipeline_guards: Vec<PipelineRegistrationGuard>,
    tasks: JoinSet<()>,
}

impl WrappedTransportProxyState {
    fn has_partial_start(&self) -> bool {
        self.kcp_started
            || self.quic_started
            || !self.pipeline_guards.is_empty()
            || !self.tasks.is_empty()
            || {
                #[cfg(feature = "proxy-packet")]
                {
                    self.kcp_source_started || self.quic_source_started || self.destination_started
                }
                #[cfg(not(feature = "proxy-packet"))]
                {
                    false
                }
            }
    }
}

impl WrappedTransportKind {
    fn packet_type(self, role: WrappedTransportRole) -> PacketType {
        match (self, role) {
            (Self::Kcp, WrappedTransportRole::Source) => PacketType::KcpSrc,
            (Self::Kcp, WrappedTransportRole::Destination) => PacketType::KcpDst,
            (Self::Quic, WrappedTransportRole::Source) => PacketType::QuicSrc,
            (Self::Quic, WrappedTransportRole::Destination) => PacketType::QuicDst,
        }
    }

    fn incoming_packet_type(self, role: WrappedTransportRole) -> PacketType {
        match role {
            WrappedTransportRole::Source => self.packet_type(WrappedTransportRole::Destination),
            WrappedTransportRole::Destination => self.packet_type(WrappedTransportRole::Source),
        }
    }
}

struct WrappedTransportPeerFilter {
    engine: Weak<dyn WrappedTransportEngine>,
    transport: WrappedTransportKind,
    role: WrappedTransportRole,
}

#[async_trait]
impl PeerPacketFilter for WrappedTransportPeerFilter {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(header) = packet.peer_manager_header() else {
            return Some(packet);
        };
        if header.packet_type != self.transport.incoming_packet_type(self.role) as u8 {
            return Some(packet);
        }
        let Some(engine) = self.engine.upgrade() else {
            return Some(packet);
        };
        let from_peer_id = header.from_peer_id.get();
        if let Err(error) = engine
            .inject_peer_datagram(self.role, from_peer_id, packet.payload_bytes().freeze())
            .await
        {
            tracing::debug!(
                ?error,
                transport = ?self.transport,
                role = ?self.role,
                "failed to inject wrapped transport packet"
            );
        }
        None
    }
}

pub(crate) struct WrappedTransportProxyModule {
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    kcp: Option<Arc<dyn WrappedTransportEngine>>,
    quic: Option<Arc<dyn WrappedTransportEngine>>,
    #[cfg(feature = "proxy-packet")]
    kcp_source: Option<Arc<dyn WrappedTransportSourceLifecycle>>,
    #[cfg(feature = "proxy-packet")]
    quic_source: Option<Arc<dyn WrappedTransportSourceLifecycle>>,
    #[cfg(feature = "proxy-packet")]
    destination: Option<Arc<dyn WrappedTransportDestinationLifecycle>>,
    state: Mutex<WrappedTransportProxyState>,
}

impl WrappedTransportProxyModule {
    const DATAGRAM_QUEUE_CAPACITY: usize = 1024;

    pub(crate) fn new<H>(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        kcp: Option<Arc<dyn WrappedTransportEngine>>,
        quic: Option<Arc<dyn WrappedTransportEngine>>,
        host: Arc<H>,
        running_listeners: Arc<RunningListenerRegistry>,
        cidr_table: Arc<ProxyCidrTable>,
        socket_context: SocketContext,
    ) -> Option<Arc<Self>>
    where
        H: DirectConnectorHost + TcpHolePunchHost,
    {
        if kcp.is_none() && quic.is_none() {
            return None;
        }
        #[cfg(feature = "proxy-packet")]
        let kcp_source: Option<Arc<dyn WrappedTransportSourceLifecycle>> =
            kcp.as_ref().map(|engine| {
                WrappedTransportSource::new(
                    peer_manager.clone(),
                    host.clone(),
                    running_listeners.clone(),
                    runtime_config.clone(),
                    cidr_table.clone(),
                    socket_context.clone(),
                    engine,
                    WrappedTransportKind::Kcp,
                ) as Arc<dyn WrappedTransportSourceLifecycle>
            });
        #[cfg(feature = "proxy-packet")]
        let quic_source: Option<Arc<dyn WrappedTransportSourceLifecycle>> =
            quic.as_ref().map(|engine| {
                WrappedTransportSource::new(
                    peer_manager.clone(),
                    host.clone(),
                    running_listeners.clone(),
                    runtime_config.clone(),
                    cidr_table.clone(),
                    socket_context.clone(),
                    engine,
                    WrappedTransportKind::Quic,
                ) as Arc<dyn WrappedTransportSourceLifecycle>
            });
        #[cfg(feature = "proxy-packet")]
        let destination: Option<Arc<dyn WrappedTransportDestinationLifecycle>> =
            (kcp.is_some() || quic.is_some()).then(|| {
                WrappedTransportDestinationModule::new(
                    peer_manager.clone(),
                    host.clone(),
                    running_listeners.clone(),
                    runtime_config.clone(),
                    cidr_table.clone(),
                    socket_context.clone(),
                ) as Arc<dyn WrappedTransportDestinationLifecycle>
            });
        #[cfg(not(feature = "proxy-packet"))]
        let _ = (host, running_listeners, cidr_table, socket_context);
        Some(Arc::new(Self {
            peer_manager,
            runtime_config,
            kcp,
            quic,
            #[cfg(feature = "proxy-packet")]
            kcp_source,
            #[cfg(feature = "proxy-packet")]
            quic_source,
            #[cfg(feature = "proxy-packet")]
            destination,
            state: Mutex::new(WrappedTransportProxyState::default()),
        }))
    }

    fn directions(&self) -> (WrappedTransportDirections, WrappedTransportDirections) {
        let snapshot = self.runtime_config.snapshot();
        let flags = &snapshot.peer.flags;
        (
            WrappedTransportDirections {
                source: flags.enable_kcp_proxy,
                destination: !flags.disable_kcp_input,
            },
            WrappedTransportDirections {
                source: flags.enable_quic_proxy,
                destination: !flags.disable_quic_input,
            },
        )
    }

    fn spawn_datagram_egress(
        &self,
        state: &mut WrappedTransportProxyState,
    ) -> tokio::sync::mpsc::Sender<WrappedTransportDatagram> {
        let (tx, mut rx) =
            tokio::sync::mpsc::channel::<WrappedTransportDatagram>(Self::DATAGRAM_QUEUE_CAPACITY);
        let peer_manager = self.peer_manager.clone();
        state.tasks.spawn(async move {
            while let Some(datagram) = rx.recv().await {
                let peer_id = datagram.peer_id;
                let transport = datagram.transport;
                let role = datagram.role;
                let packet = datagram.into_packet(peer_manager.my_peer_id());
                if let Err(error) = peer_manager.send_msg_for_proxy(packet, peer_id).await {
                    tracing::error!(
                        ?error,
                        ?transport,
                        ?role,
                        peer_id,
                        "failed to send wrapped transport packet"
                    );
                }
            }
        });
        tx
    }

    async fn register_peer_filters(
        &self,
        state: &mut WrappedTransportProxyState,
        engine: &Arc<dyn WrappedTransportEngine>,
        transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
    ) {
        if directions.source {
            let guard = self
                .peer_manager
                .add_managed_packet_process_pipeline(Box::new(WrappedTransportPeerFilter {
                    engine: Arc::downgrade(engine),
                    transport,
                    role: WrappedTransportRole::Source,
                }))
                .await;
            state.pipeline_guards.push(guard);
        }
        if directions.destination {
            let guard = self
                .peer_manager
                .add_managed_packet_process_pipeline(Box::new(WrappedTransportPeerFilter {
                    engine: Arc::downgrade(engine),
                    transport,
                    role: WrappedTransportRole::Destination,
                }))
                .await;
            state.pipeline_guards.push(guard);
        }
    }

    async fn stop_started(&self, state: &mut WrappedTransportProxyState) {
        #[cfg(feature = "proxy-packet")]
        {
            state.kcp_source_connect_ready = false;
            state.quic_source_connect_ready = false;
        }
        for guard in state.pipeline_guards.drain(..).rev() {
            guard.close();
        }
        if state.quic_started {
            #[cfg(feature = "proxy-packet")]
            {
                if let Some(guard) = state.quic_source_guard.take() {
                    guard.close();
                }
            }
            #[cfg(feature = "proxy-packet")]
            if state.quic_source_started {
                if let Some(source) = &self.quic_source {
                    source.stop().await;
                }
                state.quic_source_started = false;
            }
            if let Some(quic) = &self.quic {
                quic.stop().await;
            }
            state.quic_started = false;
        }
        if state.kcp_started {
            #[cfg(feature = "proxy-packet")]
            {
                if let Some(guard) = state.kcp_source_guard.take() {
                    guard.close();
                }
            }
            #[cfg(feature = "proxy-packet")]
            if state.kcp_source_started {
                if let Some(source) = &self.kcp_source {
                    source.stop().await;
                }
                state.kcp_source_started = false;
            }
            if let Some(kcp) = &self.kcp {
                kcp.stop().await;
            }
            state.kcp_started = false;
        }
        #[cfg(feature = "proxy-packet")]
        if state.destination_started {
            if let Some(destination) = &self.destination {
                destination.stop().await;
            }
            state.destination_started = false;
        }
        state.tasks.shutdown().await;
        state.active = false;
    }

    pub(crate) async fn start(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if state.active {
            return Ok(());
        }
        if state.has_partial_start() {
            self.stop_started(&mut state).await;
        }
        let (kcp_directions, quic_directions) = self.directions();
        #[cfg(feature = "proxy-packet")]
        let kcp_destination = kcp_directions.destination && self.kcp.is_some();
        #[cfg(feature = "proxy-packet")]
        let quic_destination = quic_directions.destination && self.quic.is_some();
        #[cfg(feature = "proxy-packet")]
        let destination_ingresses = if kcp_destination || quic_destination {
            state.destination_started = true;
            let destination = self
                .destination
                .as_ref()
                .expect("wrapped destination owner must match its engines")
                .clone();
            match destination.start(kcp_destination, quic_destination).await {
                Ok(ingresses) => ingresses,
                Err(error) => {
                    self.stop_started(&mut state).await;
                    return Err(error);
                }
            }
        } else {
            WrappedTransportDestinationIngresses::default()
        };

        if let Some(kcp) = &self.kcp
            && kcp_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.kcp_started = true;
            if let Err(error) = kcp
                .prepare(WrappedTransportEngineStart {
                    directions: kcp_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
                    #[cfg(feature = "proxy-packet")]
                    destination_ingress: destination_ingresses.kcp.clone(),
                })
                .await
            {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            self.register_peer_filters(&mut state, kcp, WrappedTransportKind::Kcp, kcp_directions)
                .await;
            #[cfg(feature = "proxy-packet")]
            if kcp_directions.source
                && let Some(source) = &self.kcp_source
            {
                state.kcp_source_started = true;
                match source.clone().start().await {
                    Ok(guard) => state.kcp_source_guard = Some(guard),
                    Err(error) => {
                        self.stop_started(&mut state).await;
                        return Err(error);
                    }
                }
            }
            if let Err(error) = kcp.activate().await {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            #[cfg(feature = "proxy-packet")]
            if kcp_directions.source {
                state.kcp_source_connect_ready = true;
            }
        }
        if let Some(quic) = &self.quic
            && quic_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.quic_started = true;
            if let Err(error) = quic
                .prepare(WrappedTransportEngineStart {
                    directions: quic_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
                    #[cfg(feature = "proxy-packet")]
                    destination_ingress: destination_ingresses.quic.clone(),
                })
                .await
            {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            self.register_peer_filters(
                &mut state,
                quic,
                WrappedTransportKind::Quic,
                quic_directions,
            )
            .await;
            #[cfg(feature = "proxy-packet")]
            if quic_directions.source
                && let Some(source) = &self.quic_source
            {
                state.quic_source_started = true;
                match source.clone().start().await {
                    Ok(guard) => state.quic_source_guard = Some(guard),
                    Err(error) => {
                        self.stop_started(&mut state).await;
                        return Err(error);
                    }
                }
            }
            if let Err(error) = quic.activate().await {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            #[cfg(feature = "proxy-packet")]
            if quic_directions.source {
                state.quic_source_connect_ready = true;
            }
        }
        state.active = true;
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let mut state = self.state.lock().await;
        self.stop_started(&mut state).await;
    }

    #[cfg(feature = "proxy-packet")]
    #[cfg(any(feature = "proxy-smoltcp-stack", test))]
    pub(crate) async fn source_connect_ready(&self, transport: WrappedTransportKind) -> bool {
        let state = self.state.lock().await;
        state.active
            && match transport {
                WrappedTransportKind::Kcp => state.kcp_source_connect_ready,
                WrappedTransportKind::Quic => state.quic_source_connect_ready,
            }
    }

    #[cfg(feature = "proxy-packet")]
    #[cfg(any(feature = "proxy-smoltcp-stack", test))]
    pub(crate) async fn connect_source(
        &self,
        transport: WrappedTransportKind,
        src: SocketAddr,
        dst: SocketAddr,
    ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
        let engine = {
            let state = self.state.lock().await;
            let ready = state.active
                && match transport {
                    WrappedTransportKind::Kcp => state.kcp_source_connect_ready,
                    WrappedTransportKind::Quic => state.quic_source_connect_ready,
                };
            if !ready {
                anyhow::bail!("{transport:?} source is not ready");
            }
            match transport {
                WrappedTransportKind::Kcp => self.kcp.clone(),
                WrappedTransportKind::Quic => self.quic.clone(),
            }
        }
        .ok_or_else(|| anyhow::anyhow!("{transport:?} engine is not available"))?;

        connect_wrapped_transport_source(&self.peer_manager, engine, src, dst).await
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) fn source_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
    ) -> Vec<TcpNatEntrySnapshot> {
        match transport {
            WrappedTransportKind::Kcp => self.kcp_source.as_ref(),
            WrappedTransportKind::Quic => self.quic_source.as_ref(),
        }
        .map_or_else(Vec::new, |source| source.entry_snapshots())
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) fn source_is_started(&self, transport: WrappedTransportKind) -> bool {
        match transport {
            WrappedTransportKind::Kcp => self.kcp_source.as_ref(),
            WrappedTransportKind::Quic => self.quic_source.as_ref(),
        }
        .is_some_and(|source| source.is_started())
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) fn destination_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
    ) -> Vec<TcpNatEntrySnapshot> {
        self.destination
            .as_ref()
            .map_or_else(Vec::new, |destination| {
                destination.entry_snapshots(transport)
            })
    }

    #[cfg(feature = "proxy-packet")]
    pub(crate) fn destination_is_started(&self, transport: WrappedTransportKind) -> bool {
        self.destination
            .as_ref()
            .is_some_and(|destination| destination.is_started(transport))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use crate::{
        config::runtime::CoreRuntimeConfig,
        config::{CoreConfig, NetworkIdentity, NodeConfig},
        host::dns::{DnsQuery, DnsResolver},
        peers::{
            context::{HostRoutingPolicy, PeerRuntimeConfig, PeerRuntimeSnapshot},
            create_packet_recv_chan,
            peer_manager::PortablePeerManagerConfig,
        },
    };

    use super::*;

    #[cfg(feature = "proxy-packet")]
    #[derive(Default)]
    struct TestWrappedTransportDestination {
        active: std::sync::atomic::AtomicBool,
        enabled: std::sync::atomic::AtomicU8,
    }

    #[cfg(feature = "proxy-packet")]
    #[async_trait]
    impl WrappedTransportDestinationLifecycle for TestWrappedTransportDestination {
        async fn start(
            self: Arc<Self>,
            kcp: bool,
            quic: bool,
        ) -> anyhow::Result<WrappedTransportDestinationIngresses> {
            self.active
                .store(true, std::sync::atomic::Ordering::Release);
            self.enabled.store(
                (kcp as u8) | ((quic as u8) << 1),
                std::sync::atomic::Ordering::Release,
            );
            Ok(WrappedTransportDestinationIngresses::default())
        }

        async fn stop(&self) {
            self.active
                .store(false, std::sync::atomic::Ordering::Release);
            self.enabled.store(0, std::sync::atomic::Ordering::Release);
        }

        fn entry_snapshots(&self, _transport: WrappedTransportKind) -> Vec<TcpNatEntrySnapshot> {
            Vec::new()
        }

        fn is_started(&self, transport: WrappedTransportKind) -> bool {
            let mask = match transport {
                WrappedTransportKind::Kcp => 1,
                WrappedTransportKind::Quic => 2,
            };
            self.active.load(std::sync::atomic::Ordering::Acquire)
                && self.enabled.load(std::sync::atomic::Ordering::Acquire) & mask != 0
        }
    }

    impl WrappedTransportProxyModule {
        fn new_without_sources(
            peer_manager: Arc<PeerManagerCore>,
            runtime_config: CoreRuntimeConfigStore,
            kcp: Option<Arc<dyn WrappedTransportEngine>>,
            quic: Option<Arc<dyn WrappedTransportEngine>>,
        ) -> Option<Arc<Self>> {
            if kcp.is_none() && quic.is_none() {
                return None;
            }
            Some(Arc::new(Self {
                peer_manager,
                runtime_config,
                kcp,
                quic,
                #[cfg(feature = "proxy-packet")]
                kcp_source: None,
                #[cfg(feature = "proxy-packet")]
                quic_source: None,
                #[cfg(feature = "proxy-packet")]
                destination: Some(Arc::new(TestWrappedTransportDestination::default())),
                state: tokio::sync::Mutex::new(WrappedTransportProxyState::default()),
            }))
        }
    }

    struct RecordingWrappedTransportEngine {
        name: &'static str,
        fail_start: bool,
        events: Arc<Mutex<Vec<String>>>,
    }

    struct CancelOnceStopEngine {
        stop_calls: AtomicUsize,
        stop_entered: Notify,
        release_first_stop: Notify,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Default)]
    struct AbortOncePrepareEngine {
        prepare_calls: AtomicUsize,
        activate_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        first_prepare_entered: Notify,
    }

    #[derive(Default)]
    struct RecordingDatagramEngine {
        injections: Mutex<Vec<(WrappedTransportRole, u32, Bytes)>>,
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingDatagramEngine {
        async fn prepare(&self, _options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            role: WrappedTransportRole,
            from_peer_id: u32,
            payload: Bytes,
        ) -> anyhow::Result<()> {
            self.injections
                .lock()
                .unwrap()
                .push((role, from_peer_id, payload));
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
            anyhow::bail!("recording engine does not open streams")
        }

        async fn stop(&self) {}
    }

    #[async_trait]
    impl WrappedTransportEngine for CancelOnceStopEngine {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("prepare:blocking".into());
            assert_eq!(
                options.directions,
                WrappedTransportDirections {
                    source: true,
                    destination: true,
                }
            );
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("activate:blocking".into());
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
            anyhow::bail!("blocking engine does not open streams")
        }

        async fn stop(&self) {
            let call = self.stop_calls.fetch_add(1, Ordering::AcqRel);
            self.events.lock().unwrap().push("stop:blocking".into());
            if call == 0 {
                self.stop_entered.notify_one();
                self.release_first_stop.notified().await;
            }
        }
    }

    #[async_trait]
    impl WrappedTransportEngine for AbortOncePrepareEngine {
        async fn prepare(&self, _options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            if self.prepare_calls.fetch_add(1, Ordering::AcqRel) == 0 {
                self.first_prepare_entered.notify_one();
                std::future::pending::<()>().await;
            }
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            self.activate_calls.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
            anyhow::bail!("blocking engine does not open streams")
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingWrappedTransportEngine {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            let directions = options.directions;
            self.events.lock().unwrap().push(format!(
                "prepare:{}:{}:{}",
                self.name, directions.source, directions.destination
            ));
            if self.fail_start {
                anyhow::bail!("{} start failed", self.name);
            }
            Ok(())
        }

        async fn activate(&self) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("activate:{}", self.name));
            Ok(())
        }

        async fn inject_peer_datagram(
            &self,
            _role: WrappedTransportRole,
            _from_peer_id: u32,
            _payload: Bytes,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        #[cfg(feature = "proxy-packet")]
        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn TcpProxyStream>> {
            anyhow::bail!("recording engine does not open streams")
        }

        async fn stop(&self) {
            self.events
                .lock()
                .unwrap()
                .push(format!("stop:{}", self.name));
        }
    }

    fn wrapped_transport_engine(
        name: &'static str,
        fail_start: bool,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> Arc<dyn WrappedTransportEngine> {
        Arc::new(RecordingWrappedTransportEngine {
            name,
            fail_start,
            events: events.clone(),
        })
    }

    struct TestDnsResolver;

    #[async_trait]
    impl DnsResolver for TestDnsResolver {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<std::net::IpAddr>> {
            Ok(Vec::new())
        }
    }

    fn wrapped_transport_peer_manager() -> Arc<PeerManagerCore> {
        let (packet_tx, _packet_rx) = create_packet_recv_chan();
        Arc::new(
            PeerManagerCore::new_portable_for_test(
                PortablePeerManagerConfig::new(PeerRuntimeConfig {
                    core: CoreConfig {
                        node: NodeConfig {
                            peer_id: Some(1),
                            network_name: "wrapped-transport-test".to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    network_identity: NetworkIdentity {
                        network_name: "wrapped-transport-test".to_owned(),
                        network_secret: Some("secret".to_owned()),
                        network_secret_digest: None,
                    },
                    stun_info: Default::default(),
                    feature_flags: Default::default(),
                    secure_mode: None,
                    host_routing: HostRoutingPolicy::default(),
                }),
                Arc::new(TestDnsResolver),
                packet_tx,
            )
            .unwrap(),
        )
    }

    fn wrapped_transport_runtime(
        kcp: WrappedTransportDirections,
        quic: WrappedTransportDirections,
    ) -> CoreRuntimeConfigStore {
        let mut peer = PeerRuntimeSnapshot::default();
        peer.flags.enable_kcp_proxy = kcp.source;
        peer.flags.disable_kcp_input = !kcp.destination;
        peer.flags.enable_quic_proxy = quic.source;
        peer.flags.disable_quic_input = !quic.destination;
        CoreRuntimeConfigStore::new(CoreRuntimeConfig::default(), Arc::new(peer))
    }

    #[tokio::test]
    async fn peer_filter_maps_packet_role_and_releases_stale_engine() {
        let engine = Arc::new(RecordingDatagramEngine::default());
        let dyn_engine: Arc<dyn WrappedTransportEngine> = engine.clone();
        let filter = WrappedTransportPeerFilter {
            engine: Arc::downgrade(&dyn_engine),
            transport: WrappedTransportKind::Kcp,
            role: WrappedTransportRole::Source,
        };
        let mut packet = ZCPacket::new_with_payload(b"payload");
        packet.fill_peer_manager_hdr(7, 1, PacketType::KcpDst as u8);

        assert!(filter.try_process_packet_from_peer(packet).await.is_none());
        assert_eq!(
            *engine.injections.lock().unwrap(),
            [(
                WrappedTransportRole::Source,
                7,
                Bytes::from_static(b"payload"),
            )]
        );

        drop(dyn_engine);
        drop(engine);
        let mut packet = ZCPacket::new_with_payload(b"stale");
        packet.fill_peer_manager_hdr(7, 1, PacketType::KcpDst as u8);
        assert!(filter.try_process_packet_from_peer(packet).await.is_some());
    }

    #[test]
    fn datagram_preserves_wire_packet_types() {
        for (transport, role, packet_type) in [
            (
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
                PacketType::KcpSrc,
            ),
            (
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Destination,
                PacketType::KcpDst,
            ),
            (
                WrappedTransportKind::Quic,
                WrappedTransportRole::Source,
                PacketType::QuicSrc,
            ),
            (
                WrappedTransportKind::Quic,
                WrappedTransportRole::Destination,
                PacketType::QuicDst,
            ),
        ] {
            let packet = WrappedTransportDatagram {
                transport,
                role,
                peer_id: 9,
                buffer: WrappedTransportDatagramBuffer::copy_from_payload(b"wire"),
            }
            .into_packet(7);
            let header = packet.peer_manager_header().unwrap();

            assert_eq!(header.from_peer_id.get(), 7);
            assert_eq!(header.to_peer_id.get(), 9);
            assert_eq!(header.packet_type, packet_type as u8);
            assert_eq!(packet.payload(), b"wire");
        }
    }

    #[test]
    fn packet_buffer_preserves_headroom_allocation() {
        let packet = ZCPacket::new_with_payload(b"wire");
        let packet_type = packet.packet_type();
        let buffer = packet.inner();
        let allocation = buffer.as_ptr();

        let mut packet = WrappedTransportDatagram {
            transport: WrappedTransportKind::Quic,
            role: WrappedTransportRole::Source,
            peer_id: 9,
            buffer: WrappedTransportDatagramBuffer::from_packet_buffer(buffer, packet_type),
        }
        .into_packet(7);

        assert_eq!(packet.mut_inner().as_ptr(), allocation);
        assert_eq!(packet.payload(), b"wire");
    }

    #[tokio::test]
    async fn module_reads_activation_flags_and_stops_in_reverse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: false,
                destination: false,
            },
            WrappedTransportDirections {
                source: false,
                destination: false,
            },
        );
        let module = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            runtime.clone(),
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(wrapped_transport_engine("quic", false, &events)),
        )
        .unwrap();

        runtime.update_peer(Arc::new({
            let mut peer = PeerRuntimeSnapshot::default();
            peer.flags.enable_kcp_proxy = true;
            peer.flags.disable_kcp_input = true;
            peer.flags.enable_quic_proxy = false;
            peer.flags.disable_quic_input = false;
            peer
        }));

        module.start().await.unwrap();
        module.start().await.unwrap();
        module.stop().await;
        module.stop().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:false",
                "activate:kcp",
                "prepare:quic:false:true",
                "activate:quic",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn destination_state_only_reports_available_engines() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: false,
                destination: true,
            },
            WrappedTransportDirections {
                source: false,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            None,
        )
        .unwrap();

        module.start().await.unwrap();

        assert!(module.destination_is_started(WrappedTransportKind::Kcp));
        assert!(!module.destination_is_started(WrappedTransportKind::Quic));
        module.stop().await;
    }

    #[cfg(feature = "proxy-packet")]
    #[tokio::test]
    async fn source_connect_readiness_tracks_active_direction() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let destination_only = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            wrapped_transport_runtime(
                WrappedTransportDirections {
                    source: false,
                    destination: true,
                },
                WrappedTransportDirections {
                    source: false,
                    destination: false,
                },
            ),
            Some(wrapped_transport_engine("kcp", false, &events)),
            None,
        )
        .unwrap();
        destination_only.start().await.unwrap();
        assert!(
            !destination_only
                .source_connect_ready(WrappedTransportKind::Kcp)
                .await
        );
        destination_only.stop().await;

        let source = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            wrapped_transport_runtime(
                WrappedTransportDirections {
                    source: true,
                    destination: false,
                },
                WrappedTransportDirections {
                    source: false,
                    destination: false,
                },
            ),
            Some(wrapped_transport_engine("kcp", false, &events)),
            None,
        )
        .unwrap();
        source.start().await.unwrap();
        assert!(source.source_connect_ready(WrappedTransportKind::Kcp).await);
        source.stop().await;
        assert!(!source.source_connect_ready(WrappedTransportKind::Kcp).await);
    }

    #[tokio::test]
    async fn module_rolls_back_failing_engine_and_predecessor() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(wrapped_transport_engine("quic", true, &events)),
        )
        .unwrap();

        assert!(module.start().await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:true",
                "activate:kcp",
                "prepare:quic:true:true",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn module_retries_cleanup_after_stop_is_cancelled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let blocking = Arc::new(CancelOnceStopEngine {
            stop_calls: AtomicUsize::new(0),
            stop_entered: Notify::new(),
            release_first_stop: Notify::new(),
            events: events.clone(),
        });
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(blocking.clone()),
        )
        .unwrap();
        module.start().await.unwrap();

        let stop_task = tokio::spawn({
            let module = module.clone();
            async move { module.stop().await }
        });
        blocking.stop_entered.notified().await;
        stop_task.abort();
        assert!(stop_task.await.unwrap_err().is_cancelled());

        module.stop().await;

        assert_eq!(blocking.stop_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:true",
                "activate:kcp",
                "prepare:blocking",
                "activate:blocking",
                "stop:blocking",
                "stop:blocking",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn module_cleans_partial_start_before_retry() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let blocking = Arc::new(AbortOncePrepareEngine::default());
        let runtime = wrapped_transport_runtime(
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
            WrappedTransportDirections {
                source: true,
                destination: true,
            },
        );
        let module = WrappedTransportProxyModule::new_without_sources(
            wrapped_transport_peer_manager(),
            runtime,
            Some(wrapped_transport_engine("kcp", false, &events)),
            Some(blocking.clone()),
        )
        .unwrap();

        let first_start = tokio::spawn({
            let module = module.clone();
            async move { module.start().await }
        });
        blocking.first_prepare_entered.notified().await;
        first_start.abort();
        assert!(first_start.await.unwrap_err().is_cancelled());
        #[cfg(feature = "proxy-packet")]
        assert!(!module.source_connect_ready(WrappedTransportKind::Kcp).await);

        module.start().await.unwrap();

        assert_eq!(blocking.prepare_calls.load(Ordering::Acquire), 2);
        assert_eq!(blocking.activate_calls.load(Ordering::Acquire), 1);
        assert_eq!(blocking.stop_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "prepare:kcp:true:true",
                "activate:kcp",
                "stop:kcp",
                "prepare:kcp:true:true",
                "activate:kcp",
            ]
        );

        module.stop().await;
        assert_eq!(blocking.stop_calls.load(Ordering::Acquire), 2);
    }
}

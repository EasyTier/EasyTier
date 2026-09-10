use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use async_trait::async_trait;

use crate::{
    config::runtime::CoreRuntimeConfigStore,
    connectivity::direct::DirectConnectorHost,
    connectivity::hole_punch::tcp::TcpHolePunchHost,
    gateway::proxy::{
        cidr_table::ProxyCidrTable,
        service::CoreProxyRuntime,
        tcp_proxy_engine::{TcpNatEntrySnapshot, TcpProxyMode, TcpProxyNicContext},
        tcp_proxy_service::TcpProxyService,
        traits::{ProxyRuntimeInfo, TcpProxyDestinationConnector, TcpProxyStream},
        wrapped_tcp_proxy::{
            WrappedTcpProxyNicContext, WrappedTcpProxyTransport,
            try_process_wrapped_tcp_packet_from_nic,
        },
        wrapped_transport_destination::{
            WrappedTransportDestinationIngresses, WrappedTransportDestinationLifecycle,
            WrappedTransportDestinationModule,
        },
    },
    listener::RunningListenerRegistry,
    packet::ZCPacket,
    peers::peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    process_runtime::ProtectedTcpPortRegistry,
    socket::SocketContext,
};

pub use crate::gateway::proxy::wrapped_transport_destination::WrappedTransportDestinationIngress;

use super::{
    WrappedTransportConnect, WrappedTransportDatagram, WrappedTransportDirections,
    WrappedTransportEngine, WrappedTransportEngineStart, WrappedTransportKind,
};

#[derive(Default)]
pub(super) struct WrappedTransportPacketState {
    pub(super) kcp_source_connect_ready: bool,
    pub(super) quic_source_connect_ready: bool,
    pub(super) kcp_source_started: bool,
    pub(super) quic_source_started: bool,
    pub(super) destination_started: bool,
    pub(super) kcp_source_guard: Option<PipelineRegistrationGuard>,
    pub(super) quic_source_guard: Option<PipelineRegistrationGuard>,
    destination_ingresses: WrappedTransportDestinationIngresses,
}

impl WrappedTransportPacketState {
    fn has_partial_start(&self) -> bool {
        self.kcp_source_started || self.quic_source_started || self.destination_started
    }
}

#[derive(Default)]
pub(super) struct WrappedTransportPacketPlane {
    pub(super) kcp_source: Option<Arc<dyn WrappedTransportSourceLifecycle>>,
    pub(super) quic_source: Option<Arc<dyn WrappedTransportSourceLifecycle>>,
    pub(super) destination: Option<Arc<dyn WrappedTransportDestinationLifecycle>>,
}

#[derive(Clone)]
struct WrappedTransportSourceConnector {
    peer_manager: Arc<PeerManagerCore>,
    engine: Weak<dyn WrappedTransportEngine>,
    transport: WrappedTransportKind,
}

pub(super) async fn connect_wrapped_transport_source(
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

type WrappedTransportSourceService<H> =
    TcpProxyService<CoreProxyRuntime<H>, H, WrappedTransportSourceConnector>;

pub(super) struct WrappedTransportSource<H>
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

impl<H> WrappedTransportSource<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
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
            protected_tcp_ports,
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

#[async_trait]
pub(super) trait WrappedTransportSourceLifecycle: Send + Sync {
    async fn start(self: Arc<Self>) -> anyhow::Result<PipelineRegistrationGuard>;
    async fn stop(&self);
    fn entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot>;
    fn is_started(&self) -> bool;
}

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

struct WrappedTransportSourceFilter<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    source: Weak<WrappedTransportSource<H>>,
}

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

impl WrappedTransportPacketPlane {
    pub(super) fn has_partial_start(&self, state: &WrappedTransportPacketState) -> bool {
        state.has_partial_start()
    }

    pub(super) fn clear_connect_ready(&self, state: &mut WrappedTransportPacketState) {
        state.kcp_source_connect_ready = false;
        state.quic_source_connect_ready = false;
    }

    pub(super) async fn stop_source(
        &self,
        state: &mut WrappedTransportPacketState,
        transport: WrappedTransportKind,
    ) {
        let (source, started, guard) = match transport {
            WrappedTransportKind::Kcp => (
                &self.kcp_source,
                &mut state.kcp_source_started,
                &mut state.kcp_source_guard,
            ),
            WrappedTransportKind::Quic => (
                &self.quic_source,
                &mut state.quic_source_started,
                &mut state.quic_source_guard,
            ),
        };
        if let Some(guard) = guard.take() {
            guard.close();
        }
        if *started {
            if let Some(source) = source {
                source.stop().await;
            }
            *started = false;
        }
    }

    pub(super) async fn stop_destination(&self, state: &mut WrappedTransportPacketState) {
        if state.destination_started {
            if let Some(destination) = &self.destination {
                destination.stop().await;
            }
            state.destination_started = false;
        }
        state.destination_ingresses = WrappedTransportDestinationIngresses::default();
    }

    pub(super) async fn start_destinations(
        &self,
        state: &mut WrappedTransportPacketState,
        kcp_directions: WrappedTransportDirections,
        quic_directions: WrappedTransportDirections,
        kcp_available: bool,
        quic_available: bool,
    ) -> anyhow::Result<()> {
        let kcp = kcp_directions.destination && kcp_available;
        let quic = quic_directions.destination && quic_available;
        state.destination_ingresses = if kcp || quic {
            state.destination_started = true;
            self.destination
                .as_ref()
                .expect("wrapped destination owner must match its engines")
                .clone()
                .start(kcp, quic)
                .await?
        } else {
            WrappedTransportDestinationIngresses::default()
        };
        Ok(())
    }

    pub(super) fn engine_start(
        &self,
        state: &WrappedTransportPacketState,
        transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
        my_peer_id: u32,
        datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
    ) -> WrappedTransportEngineStart {
        let destination_ingress = match transport {
            WrappedTransportKind::Kcp => state.destination_ingresses.kcp.clone(),
            WrappedTransportKind::Quic => state.destination_ingresses.quic.clone(),
        };
        WrappedTransportEngineStart {
            directions,
            my_peer_id,
            datagrams,
            destination_ingress,
        }
    }

    pub(super) async fn start_source(
        &self,
        state: &mut WrappedTransportPacketState,
        transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
    ) -> anyhow::Result<()> {
        if !directions.source {
            return Ok(());
        }
        let (source, started, guard) = match transport {
            WrappedTransportKind::Kcp => (
                &self.kcp_source,
                &mut state.kcp_source_started,
                &mut state.kcp_source_guard,
            ),
            WrappedTransportKind::Quic => (
                &self.quic_source,
                &mut state.quic_source_started,
                &mut state.quic_source_guard,
            ),
        };
        let Some(source) = source else {
            return Ok(());
        };
        *started = true;
        *guard = Some(source.clone().start().await?);
        Ok(())
    }

    pub(super) fn mark_source_connect_ready(
        &self,
        state: &mut WrappedTransportPacketState,
        transport: WrappedTransportKind,
        directions: WrappedTransportDirections,
    ) {
        if !directions.source {
            return;
        }
        match transport {
            WrappedTransportKind::Kcp => state.kcp_source_connect_ready = true,
            WrappedTransportKind::Quic => state.quic_source_connect_ready = true,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn new<H>(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        kcp: &Option<Arc<dyn WrappedTransportEngine>>,
        quic: &Option<Arc<dyn WrappedTransportEngine>>,
        host: Arc<H>,
        protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
        running_listeners: Arc<RunningListenerRegistry>,
        cidr_table: Arc<ProxyCidrTable>,
        socket_context: SocketContext,
    ) -> Self
    where
        H: DirectConnectorHost + TcpHolePunchHost,
    {
        let kcp_source = kcp.as_ref().map(|engine| {
            WrappedTransportSource::new(
                peer_manager.clone(),
                host.clone(),
                protected_tcp_ports.clone(),
                running_listeners.clone(),
                runtime_config.clone(),
                cidr_table.clone(),
                socket_context.clone(),
                engine,
                WrappedTransportKind::Kcp,
            ) as Arc<dyn WrappedTransportSourceLifecycle>
        });
        let quic_source = quic.as_ref().map(|engine| {
            WrappedTransportSource::new(
                peer_manager.clone(),
                host.clone(),
                protected_tcp_ports.clone(),
                running_listeners.clone(),
                runtime_config.clone(),
                cidr_table.clone(),
                socket_context.clone(),
                engine,
                WrappedTransportKind::Quic,
            ) as Arc<dyn WrappedTransportSourceLifecycle>
        });
        let destination = (kcp.is_some() || quic.is_some()).then(|| {
            WrappedTransportDestinationModule::new(
                peer_manager,
                host,
                protected_tcp_ports,
                running_listeners,
                runtime_config,
                cidr_table,
                socket_context,
            ) as Arc<dyn WrappedTransportDestinationLifecycle>
        });
        Self {
            kcp_source,
            quic_source,
            destination,
        }
    }
}

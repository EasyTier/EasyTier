//! Lifecycle owner for the portable EasyTier runtime.

pub mod packet_io;

use std::net::IpAddr;
use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::{
    connectivity::{
        direct::{DirectConnectorHost, DirectConnectorManager, DirectConnectorOptions},
        manual::{
            ManualConnectivityEventSink, ManualConnectorManager, ManualConnectorOptions,
            ManualConnectorSnapshot, ManualEndpointResolver,
        },
        protocol::{ClientProtocolUpgrader, RawClientProtocolUpgrader},
    },
    hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    listener::{
        AcceptedSocketHandler, RunningListenerProvider, RunningListenerRegistry,
        transport::{
            AcceptedTransport, HostAcceptedTcpSocket, RawAcceptedTransportHandler,
            TransportListenerConfig, TransportListenerService,
        },
    },
    peers::{
        create_packet_recv_chan,
        peer_manager::{PeerManagerCore, PortablePeerManagerConfig},
    },
    socket::{dns::DnsResolver, tcp::VirtualTcpSocketFactory},
};

pub use packet_io::PacketSink;
use packet_io::{PacketEgress, parse_ip_packet};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CoreInstanceState {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

impl CoreInstanceState {
    fn from_u8(value: u8) -> Self {
        match value {
            value if value == Self::Created as u8 => Self::Created,
            value if value == Self::Starting as u8 => Self::Starting,
            value if value == Self::Running as u8 => Self::Running,
            value if value == Self::Stopping as u8 => Self::Stopping,
            value if value == Self::Stopped as u8 => Self::Stopped,
            _ => unreachable!("invalid core instance state"),
        }
    }
}

struct RecoveryGuard<F>
where
    F: FnOnce(),
{
    recovery: Option<F>,
}

impl<F> RecoveryGuard<F>
where
    F: FnOnce(),
{
    fn new(recovery: F) -> Self {
        Self {
            recovery: Some(recovery),
        }
    }

    fn disarm(&mut self) {
        self.recovery.take();
    }
}

impl<F> Drop for RecoveryGuard<F>
where
    F: FnOnce(),
{
    fn drop(&mut self) {
        if let Some(recovery) = self.recovery.take() {
            recovery();
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub listeners: Vec<TransportListenerConfig>,
    pub manual: ManualConnectorOptions,
    pub direct: DirectConnectorOptions,
}

impl Default for CoreInstanceConfig {
    fn default() -> Self {
        Self {
            initial_peers: Vec::new(),
            listeners: Vec::new(),
            manual: ManualConnectorOptions::default(),
            direct: DirectConnectorOptions::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortableCoreInstanceConfig {
    pub peer: PortablePeerManagerConfig,
    pub connectivity: CoreInstanceConfig,
}

fn validate_portable_connectivity_config(
    config: &PortableCoreInstanceConfig,
) -> anyhow::Result<()> {
    let peer_flags = &config.peer.flags;
    let direct = &config.connectivity.direct;
    if (direct.lazy_p2p, direct.disable_p2p, direct.need_p2p)
        != (
            peer_flags.lazy_p2p,
            peer_flags.disable_p2p,
            peer_flags.need_p2p,
        )
    {
        anyhow::bail!("direct connectivity P2P policy does not match peer policy");
    }
    Ok(())
}

fn validate_listener_protocols(
    listeners: &[TransportListenerConfig],
    has_custom_handler: bool,
) -> anyhow::Result<()> {
    if has_custom_handler {
        return Ok(());
    }
    if let Some(listener) = listeners
        .iter()
        .find(|listener| !listener.supports_raw_handler())
    {
        anyhow::bail!(
            "listener {} requires a custom accepted transport handler",
            listener.url()
        );
    }
    Ok(())
}

pub struct CoreInstanceAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub host: Arc<H>,
    pub dns: Arc<dyn DnsResolver>,
    pub endpoint_resolver: Arc<dyn ManualEndpointResolver>,
    pub protocol: Option<Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>>,
    pub manual_events: Option<Arc<dyn ManualConnectivityEventSink>>,
    pub listener: Option<Arc<dyn ListenerService>>,
    pub accepted_transport_handler:
        Option<Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>>,
    pub udp_hole_punch: Option<Arc<dyn UdpHolePunchService>>,
}

#[async_trait]
pub trait ListenerService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

#[async_trait]
impl<H> ListenerService for TransportListenerService<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    async fn start(&self) -> anyhow::Result<()> {
        TransportListenerService::start(self).await
    }

    async fn stop(&self) {
        TransportListenerService::stop(self).await;
    }
}

#[async_trait]
pub trait UdpHolePunchService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

/// Owns the portable peer and connectivity runtime for one EasyTier instance.
///
/// An instance is intentionally one-shot: after it is stopped, construct a new
/// instance rather than trying to rebuild partially consumed peer-manager state.
pub struct CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    state: AtomicU8,
    operation: Mutex<()>,
    cancel: CancellationToken,
    peer_manager: Arc<PeerManagerCore>,
    manual: ManualConnectorManager<H>,
    direct: DirectConnectorManager<H>,
    tcp_hole_punch: TcpHolePunchConnector<H>,
    listener: Option<Arc<dyn ListenerService>>,
    listener_started: AtomicBool,
    udp_hole_punch: Option<Arc<dyn UdpHolePunchService>>,
    udp_hole_punch_started: AtomicBool,
    packet_egress: Option<PacketEgress>,
}

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub fn new_portable(
        adapters: CoreInstanceAdapters<H>,
        config: PortableCoreInstanceConfig,
        packet_sink: Arc<dyn PacketSink>,
    ) -> anyhow::Result<Self> {
        validate_portable_connectivity_config(&config)?;
        validate_listener_protocols(
            &config.connectivity.listeners,
            adapters.accepted_transport_handler.is_some(),
        )?;
        let network_name = &config.peer.runtime.network_identity.network_name;
        if config.connectivity.direct.network_name != *network_name {
            anyhow::bail!(
                "direct connectivity network {:?} does not match peer identity {:?}",
                config.connectivity.direct.network_name,
                network_name
            );
        }
        let (packet_tx, packet_rx) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManagerCore::new_portable(
            config.peer,
            adapters.dns.clone(),
            packet_tx,
        )?);
        let mut instance = Self::new(peer_manager, adapters, config.connectivity)?;
        instance.packet_egress = Some(PacketEgress::new(packet_rx, packet_sink));
        Ok(instance)
    }

    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
    ) -> anyhow::Result<Self> {
        validate_listener_protocols(
            &config.listeners,
            adapters.accepted_transport_handler.is_some(),
        )?;
        let CoreInstanceAdapters {
            host,
            dns,
            endpoint_resolver,
            protocol,
            manual_events,
            listener,
            accepted_transport_handler,
            udp_hole_punch,
        } = adapters;
        let CoreInstanceConfig {
            initial_peers,
            listeners,
            manual: manual_options,
            direct: direct_options,
        } = config;

        let (listener, running_listeners): (
            Option<Arc<dyn ListenerService>>,
            Option<Arc<dyn RunningListenerProvider>>,
        ) = match (listener, listeners.is_empty()) {
            (Some(_), false) => {
                anyhow::bail!("external and core transport listeners cannot both be configured")
            }
            (Some(listener), true) => (Some(listener), None),
            (None, true) => (None, None),
            (None, false) => {
                let handler = accepted_transport_handler
                    .unwrap_or_else(|| Arc::new(RawAcceptedTransportHandler::new(&peer_manager)));
                let registry = Arc::new(RunningListenerRegistry::default());
                let listener = Arc::new(TransportListenerService::new_with_events(
                    host.clone(),
                    listeners,
                    handler,
                    registry.clone(),
                ));
                (Some(listener), Some(registry))
            }
        };
        let protocol = protocol.unwrap_or_else(|| Arc::new(RawClientProtocolUpgrader));
        let manual = match manual_events {
            Some(events) => ManualConnectorManager::new_with_events(
                peer_manager.clone(),
                host.clone(),
                dns.clone(),
                endpoint_resolver,
                protocol.clone(),
                manual_options,
                events,
            ),
            None => ManualConnectorManager::new(
                peer_manager.clone(),
                host.clone(),
                dns.clone(),
                endpoint_resolver,
                protocol.clone(),
                manual_options,
            ),
        };
        for url in initial_peers {
            manual.add_connector(url)?;
        }

        let direct = match running_listeners {
            Some(running_listeners) => DirectConnectorManager::new_with_running_listeners(
                peer_manager.clone(),
                host.clone(),
                running_listeners,
                dns,
                protocol,
                direct_options,
            ),
            None => DirectConnectorManager::new(
                peer_manager.clone(),
                host.clone(),
                dns,
                protocol,
                direct_options,
            ),
        };
        let tcp_hole_punch = TcpHolePunchConnector::new(peer_manager.clone(), host);

        Ok(Self {
            state: AtomicU8::new(CoreInstanceState::Created as u8),
            operation: Mutex::new(()),
            cancel: CancellationToken::new(),
            peer_manager,
            manual,
            direct,
            tcp_hole_punch,
            listener,
            listener_started: AtomicBool::new(false),
            udp_hole_punch,
            udp_hole_punch_started: AtomicBool::new(false),
            packet_egress: None,
        })
    }

    pub fn state(&self) -> CoreInstanceState {
        CoreInstanceState::from_u8(self.state.load(Ordering::Acquire))
    }

    fn set_state(&self, state: CoreInstanceState) {
        self.state.store(state as u8, Ordering::Release);
    }

    fn recovery_guard(self: &Arc<Self>) -> RecoveryGuard<impl FnOnce() + Send + use<H>> {
        let weak: Weak<Self> = Arc::downgrade(self);
        RecoveryGuard::new(move || {
            if let Some(instance) = weak.upgrade() {
                tokio::spawn(async move {
                    instance.stop().await;
                });
            }
        })
    }

    async fn stop_components(&self) {
        if let Some(listener) = &self.listener {
            listener.stop().await;
            self.listener_started.store(false, Ordering::Release);
        }
        if let Some(udp_hole_punch) = &self.udp_hole_punch {
            udp_hole_punch.stop().await;
            self.udp_hole_punch_started.store(false, Ordering::Release);
        }
        self.manual.stop().await;
        self.tcp_hole_punch.stop().await;
        self.direct.stop().await;
        self.peer_manager.clear_resources().await;
        if let Some(packet_egress) = &self.packet_egress {
            packet_egress.stop().await;
        }
    }

    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Created {
            anyhow::bail!("core instance cannot start from state {state:?}");
        }
        self.set_state(CoreInstanceState::Starting);
        let mut recovery = self.recovery_guard();

        if let Some(packet_egress) = &self.packet_egress
            && let Err(error) = packet_egress.start()
        {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }

        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("core instance start cancelled")),
            result = self.peer_manager.run() => result.map_err(anyhow::Error::from),
        };
        if let Err(error) = start_result {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            anyhow::bail!("core instance start cancelled");
        }

        self.direct.run();
        self.tcp_hole_punch.run();
        self.manual.start();

        self.set_state(CoreInstanceState::Running);
        recovery.disarm();
        Ok(())
    }

    pub async fn start_listeners(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Created {
            anyhow::bail!("listeners cannot start from core instance state {state:?}");
        }
        let Some(listener) = &self.listener else {
            return Ok(());
        };
        if self.listener_started.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.listener_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("listener start cancelled")),
            result = listener.start() => result,
        };
        if let Err(error) = start_result {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }
        recovery.disarm();
        Ok(())
    }

    pub async fn start_udp_hole_punch(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("UDP hole punching cannot start from core instance state {state:?}");
        }
        let Some(udp_hole_punch) = &self.udp_hole_punch else {
            return Ok(());
        };
        if self.udp_hole_punch_started.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.udp_hole_punch_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("UDP hole punching start cancelled"))
            }
            result = udp_hole_punch.start() => result,
        };
        if let Err(error) = start_result {
            udp_hole_punch.stop().await;
            self.udp_hole_punch_started.store(false, Ordering::Release);
            recovery.disarm();
            return Err(error);
        }
        recovery.disarm();
        Ok(())
    }

    pub async fn stop(self: &Arc<Self>) {
        self.cancel.cancel();
        let mut recovery = self.recovery_guard();
        let _operation = self.operation.lock().await;
        match self.state() {
            CoreInstanceState::Stopped => {
                self.set_state(CoreInstanceState::Stopped);
                recovery.disarm();
                return;
            }
            CoreInstanceState::Created
            | CoreInstanceState::Starting
            | CoreInstanceState::Running
            | CoreInstanceState::Stopping => {
                self.set_state(CoreInstanceState::Stopping);
            }
        }

        self.stop_components().await;
        self.set_state(CoreInstanceState::Stopped);
        recovery.disarm();
    }

    pub fn add_connector(&self, url: Url) -> anyhow::Result<()> {
        self.manual.add_connector(url)
    }

    pub fn remove_connector(&self, url: &Url) -> bool {
        self.manual.remove_connector(url)
    }

    pub fn clear_connectors(&self) {
        self.manual.clear_connectors();
    }

    pub fn list_connectors(&self) -> Vec<ManualConnectorSnapshot> {
        self.manual.list_connectors()
    }

    pub fn running_listeners(&self) -> Vec<Url> {
        self.direct.running_listeners()
    }

    pub fn peer_id(&self) -> crate::config::PeerId {
        self.peer_manager.my_peer_id()
    }

    pub async fn connected_peers(&self) -> Vec<crate::config::PeerId> {
        self.peer_manager
            .get_peer_map()
            .list_peers_with_conn()
            .await
    }

    pub async fn send_ip_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        let meta = parse_ip_packet(&packet)?;
        let source_is_local = self.peer_manager.is_local_virtual_ip(&meta.source);
        if matches!(meta.source, IpAddr::V6(ip) if ip.is_unicast_link_local()) && !source_is_local {
            return Ok(());
        }
        self.peer_manager
            .send_msg_by_ip(
                crate::packet::ZCPacket::new_with_payload(&packet),
                meta.destination,
                source_is_local,
            )
            .await
            .map_err(Into::into)
    }
}

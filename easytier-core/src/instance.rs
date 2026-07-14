//! Lifecycle owner for the portable EasyTier runtime.

pub mod host;
pub mod packet_io;
pub mod public_ipv6_provider;
pub mod udp_hole_punch;

#[cfg(any(test, target_os = "wasi"))]
mod runtime_driver;

use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::{
        direct::{DirectConnectorHost, DirectConnectorManager, DirectConnectorOptions},
        manual::{
            ManualConnectivityEventSink, ManualConnectorManager, ManualConnectorOptions,
            ManualConnectorSnapshot,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::{
            ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader,
            CoreServerProtocolConfig, CoreServerProtocolUpgrader,
        },
    },
    dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource, DhcpIpv4Service},
    hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    listener::{
        AcceptedSocketHandler, ListenerEventSink, ListenerEventSinkGroup, RunningListenerProvider,
        RunningListenerProviderGroup, RunningListenerRegistry,
        transport::{
            AcceptedTransport, HostAcceptedTcpSocket, RawAcceptedTransportHandler,
            TransportListenerConfig, TransportListenerService,
        },
    },
    packet::{PacketType, ZCPacket},
    peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService},
    peers::{
        PeerPacketFilter,
        acl_config::AclRuleConfig,
        context::{PeerRuntimeSnapshot, PeerStunInfoSource},
        create_packet_recv_chan,
        credential_manager::{CredentialInfo, GeneratedCredential},
        peer_conn::PeerConnId,
        peer_manager::{
            PeerManagerCore, PeerSnapshot, PipelineRegistrationGuard, PortablePeerManagerConfig,
        },
    },
    proxy::{
        cidr_monitor::{
            ProxyCidrDiff, ProxyCidrMonitor, ProxyCidrMonitorHost, collect_proxy_cidr_diff,
        },
        cidr_table::{ProxyCidrSnapshot, ProxyCidrTable},
    },
    runtime_config::{CoreInstanceRuntimeConfig, CoreRuntimeConfig, CoreRuntimeConfigStore},
    socket::{
        dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        tcp::VirtualTcpSocketFactory,
        udp::VirtualUdpSocketFactory,
    },
    stun::{
        StunInfoCollector, StunInfoProvider, StunProviderSlot, StunServerConfig, StunSocketMapper,
    },
    tunnel::ring::RingTunnelRegistry,
};

use self::{
    public_ipv6_provider::{PublicIpv6ProviderHost, PublicIpv6ProviderService},
    udp_hole_punch::{CoreUdpHolePunchService, UdpHolePunchPlatform},
};
#[cfg(feature = "proxy-packet")]
use crate::proxy::{runtime::IcmpProxyHost, service::CoreProxyModule};

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AclWhitelistSnapshot {
    pub tcp_ports: Vec<String>,
    pub udp_ports: Vec<String>,
}

impl From<&AclRuleConfig> for AclWhitelistSnapshot {
    fn from(config: &AclRuleConfig) -> Self {
        Self {
            tcp_ports: config.tcp_whitelist.clone(),
            udp_ports: config.udp_whitelist.clone(),
        }
    }
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub listeners: Vec<TransportListenerConfig>,
    pub runtime: CoreRuntimeConfig,
    pub stun: StunServerConfig,
    pub endpoint_discovery: ManualEndpointDiscoveryConfig,
    pub manual: ManualConnectorOptions,
    pub direct: DirectConnectorOptions,
}

impl Default for CoreInstanceConfig {
    fn default() -> Self {
        Self {
            initial_peers: Vec::new(),
            listeners: Vec::new(),
            runtime: CoreRuntimeConfig::default(),
            stun: StunServerConfig::default(),
            endpoint_discovery: ManualEndpointDiscoveryConfig::default(),
            manual: ManualConnectorOptions::default(),
            direct: DirectConnectorOptions::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortableCoreInstanceConfig {
    pub peer: PortablePeerManagerConfig,
    pub connectivity: CoreInstanceConfig,
}

#[derive(Debug, Clone)]
pub struct CredentialCreateOptions {
    pub groups: Vec<String>,
    pub allow_relay: bool,
    pub allowed_proxy_cidrs: Vec<String>,
    pub ttl: Duration,
    pub credential_id: Option<String>,
    pub reusable: bool,
}

fn validate_portable_connectivity_config(
    config: &PortableCoreInstanceConfig,
) -> anyhow::Result<()> {
    let peer_flags = &config.peer.snapshot.flags;
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
    config.connectivity.runtime.acl.build()?;
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

fn proxy_cidr_snapshot(config: &CoreInstanceRuntimeConfig) -> ProxyCidrSnapshot {
    ProxyCidrSnapshot::from_proxy_networks(&config.peer.runtime.core.routes.proxy_networks)
}

pub struct CoreInstanceAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub host: Arc<H>,
    /// Optional stable projection used by native services and test overrides.
    /// Core installs its collector only when the slot is empty.
    pub stun_projection: Option<Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>>>,
    pub dns: Arc<dyn DnsResolver>,
    /// Optional listener-specific resolver. When absent, listeners share `dns` with connectors.
    pub listener_dns: Option<Arc<dyn DnsResolver>>,
    pub dns_records: Arc<dyn DnsRecordResolver>,
    pub ring_registry: Arc<RingTunnelRegistry>,
    pub protocol: Option<Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>>,
    pub manual_events: Option<Arc<dyn ManualConnectivityEventSink>>,
    pub listener: Option<Arc<dyn ListenerService>>,
    pub listener_events: Option<Arc<dyn ListenerEventSink>>,
    pub accepted_transport_handler:
        Option<Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>>,
    /// Optional OS port-mapping adapter. STUN-only hole punching remains
    /// available when the host does not provide one.
    pub udp_hole_punch_platform: Option<Arc<dyn UdpHolePunchPlatform>>,
    #[cfg(feature = "proxy-packet")]
    pub icmp_proxy_host: Option<Arc<dyn IcmpProxyHost>>,
    pub proxy_cidr_monitor: Option<Arc<dyn ProxyCidrMonitorHost>>,
    pub public_ipv6_provider: Option<Arc<dyn PublicIpv6ProviderHost>>,
}

struct CoreStunDnsAdapter {
    addresses: Arc<dyn DnsResolver>,
    records: Arc<dyn DnsRecordResolver>,
}

#[async_trait]
impl DnsResolver for CoreStunDnsAdapter {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        self.addresses.resolve(query).await
    }
}

#[async_trait]
impl DnsRecordResolver for CoreStunDnsAdapter {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        self.records.resolve_txt(query).await
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        self.records.resolve_srv(query).await
    }
}

struct CoreStunPeerInfoSource(Arc<dyn StunInfoProvider>);

impl PeerStunInfoSource for CoreStunPeerInfoSource {
    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.0.get_stun_info()
    }
}

struct HostRunningListenerProvider<H>(Arc<H>);

impl<H> std::fmt::Debug for HostRunningListenerProvider<H> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostRunningListenerProvider")
            .finish_non_exhaustive()
    }
}

impl<H> RunningListenerProvider for HostRunningListenerProvider<H>
where
    H: DirectConnectorHost,
{
    fn running_listeners(&self) -> Vec<Url> {
        self.0.running_listeners()
    }
}

#[async_trait]
pub trait ListenerService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

pub struct ListenerServiceGroup {
    operation: Mutex<()>,
    services: Vec<Arc<dyn ListenerService>>,
    started_count: AtomicUsize,
}

impl ListenerServiceGroup {
    pub fn new(services: Vec<Arc<dyn ListenerService>>) -> Arc<Self> {
        Arc::new(Self {
            operation: Mutex::new(()),
            services,
            started_count: AtomicUsize::new(0),
        })
    }

    async fn stop_started(&self) {
        loop {
            let started_count = self.started_count.load(Ordering::Acquire);
            if started_count == 0 {
                break;
            }
            self.services[started_count - 1].stop().await;
            self.started_count
                .store(started_count - 1, Ordering::Release);
        }
    }
}

#[async_trait]
impl ListenerService for ListenerServiceGroup {
    async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started_count.load(Ordering::Acquire) != 0 {
            return Ok(());
        }

        for (index, service) in self.services.iter().enumerate() {
            self.started_count.store(index + 1, Ordering::Release);
            if let Err(error) = service.start().await {
                self.stop_started().await;
                return Err(error);
            }
        }
        Ok(())
    }

    async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_started().await;
    }
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
pub trait ProxyService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

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
    pub payload: Bytes,
}

impl WrappedTransportDatagram {
    fn into_packet(self, my_peer_id: u32) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&self.payload);
        packet.fill_peer_manager_hdr(
            my_peer_id,
            self.peer_id,
            self.transport.packet_type(self.role) as u8,
        );
        packet
    }
}

#[derive(Debug, Clone)]
pub struct WrappedTransportEngineStart {
    pub directions: WrappedTransportDirections,
    pub my_peer_id: u32,
    pub datagrams: tokio::sync::mpsc::Sender<WrappedTransportDatagram>,
}

#[async_trait]
pub trait WrappedTransportEngine: Send + Sync + 'static {
    async fn start(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()>;
    async fn inject_peer_datagram(
        &self,
        role: WrappedTransportRole,
        from_peer_id: u32,
        payload: Bytes,
    ) -> anyhow::Result<()>;
    async fn stop(&self);
}

pub struct WrappedTransportEngineBuild<A> {
    pub kcp: Option<Arc<dyn WrappedTransportEngine>>,
    pub quic: Option<Arc<dyn WrappedTransportEngine>>,
    pub attachment: A,
}

pub trait WrappedTransportEngineFactory: Send + 'static {
    type Attachment: Send + Sync + 'static;

    fn build(
        self,
        cidr_table: Arc<ProxyCidrTable>,
    ) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>>;
}

pub struct NoWrappedTransportEngineFactory;

impl WrappedTransportEngineFactory for NoWrappedTransportEngineFactory {
    type Attachment = ();

    fn build(
        self,
        _cidr_table: Arc<ProxyCidrTable>,
    ) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>> {
        Ok(WrappedTransportEngineBuild {
            kcp: None,
            quic: None,
            attachment: (),
        })
    }
}

#[derive(Default)]
struct WrappedTransportProxyState {
    active: bool,
    kcp_started: bool,
    quic_started: bool,
    pipeline_guards: Vec<PipelineRegistrationGuard>,
    tasks: JoinSet<()>,
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

struct WrappedTransportProxyModule {
    peer_manager: Arc<PeerManagerCore>,
    runtime_config: CoreRuntimeConfigStore,
    kcp: Option<Arc<dyn WrappedTransportEngine>>,
    quic: Option<Arc<dyn WrappedTransportEngine>>,
    state: Mutex<WrappedTransportProxyState>,
}

impl WrappedTransportProxyModule {
    const DATAGRAM_QUEUE_CAPACITY: usize = 1024;

    fn new(
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
        for guard in state.pipeline_guards.drain(..).rev() {
            guard.close();
        }
        if state.quic_started {
            if let Some(quic) = &self.quic {
                quic.stop().await;
            }
            state.quic_started = false;
        }
        if state.kcp_started {
            if let Some(kcp) = &self.kcp {
                kcp.stop().await;
            }
            state.kcp_started = false;
        }
        state.tasks.shutdown().await;
        state.active = false;
    }

    async fn start(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        if state.active {
            return Ok(());
        }
        let (kcp_directions, quic_directions) = self.directions();

        if let Some(kcp) = &self.kcp
            && kcp_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.kcp_started = true;
            if let Err(error) = kcp
                .start(WrappedTransportEngineStart {
                    directions: kcp_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
                })
                .await
            {
                self.stop_started(&mut state).await;
                return Err(error);
            }
            self.register_peer_filters(&mut state, kcp, WrappedTransportKind::Kcp, kcp_directions)
                .await;
        }
        if let Some(quic) = &self.quic
            && quic_directions.enabled()
        {
            let datagrams = self.spawn_datagram_egress(&mut state);
            state.quic_started = true;
            if let Err(error) = quic
                .start(WrappedTransportEngineStart {
                    directions: quic_directions,
                    my_peer_id: self.peer_manager.my_peer_id(),
                    datagrams,
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
        }
        state.active = true;
        Ok(())
    }

    async fn stop(&self) {
        let mut state = self.state.lock().await;
        self.stop_started(&mut state).await;
    }
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
    udp_hole_punch: CoreUdpHolePunchService<H>,
    udp_hole_punch_started: AtomicBool,
    transport_proxy: Option<Arc<WrappedTransportProxyModule>>,
    proxy_cidr_table: Arc<ProxyCidrTable>,
    #[cfg(feature = "proxy-packet")]
    proxy: Arc<CoreProxyModule<H>>,
    #[cfg(feature = "proxy-packet")]
    proxy_started: AtomicBool,
    proxy_cidr_monitor: Option<Arc<dyn ProxyCidrMonitorHost>>,
    proxy_cidr_monitor_task: Mutex<Option<AbortOnDropHandle<()>>>,
    dhcp_ipv4_task: Mutex<Option<AbortOnDropHandle<()>>>,
    packet_egress: Option<PacketEgress>,
    peer_center: Arc<PeerCenterInstance>,
    peer_center_started: AtomicBool,
    public_ipv6_provider: Option<Arc<PublicIpv6ProviderService>>,
    initial_peers: Vec<Url>,
    initial_peers_started: AtomicBool,
    runtime_config: CoreRuntimeConfigStore,
    acl_whitelist: RwLock<AclWhitelistSnapshot>,
    initial_acl_loaded: AtomicBool,
}

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    fn prepare_stun(
        adapters: &CoreInstanceAdapters<H>,
        config: &CoreInstanceConfig,
    ) -> Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>> {
        let dns = Arc::new(CoreStunDnsAdapter {
            addresses: adapters.dns.clone(),
            records: adapters.dns_records.clone(),
        });
        let collector: Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>> =
            Arc::new(StunInfoCollector::new_with_socket_contexts(
                adapters.host.clone(),
                dns,
                config.direct.udp_bind.context.clone(),
                config.direct.tcp_bind.context.clone(),
                config.stun.udp_servers.clone(),
                config.stun.tcp_servers.clone(),
                config.stun.udp_v6_servers.clone(),
            ));
        match &adapters.stun_projection {
            Some(projection) => {
                projection.install_if_empty(collector);
                projection.clone()
            }
            None => Arc::new(StunProviderSlot::new(collector)),
        }
    }

    pub fn new_portable(
        adapters: CoreInstanceAdapters<H>,
        mut config: PortableCoreInstanceConfig,
        packet_sink: Arc<dyn PacketSink>,
    ) -> anyhow::Result<Self> {
        validate_portable_connectivity_config(&config)?;
        validate_listener_protocols(
            &config.connectivity.listeners,
            adapters.accepted_transport_handler.is_some(),
        )?;
        let network_name = &config.peer.snapshot.runtime.network_identity.network_name;
        if config.connectivity.direct.network_name != *network_name {
            anyhow::bail!(
                "direct connectivity network {:?} does not match peer identity {:?}",
                config.connectivity.direct.network_name,
                network_name
            );
        }
        let (packet_tx, packet_rx) = create_packet_recv_chan();
        let dns_context = config.connectivity.direct.tcp_bind.context.clone();
        config
            .peer
            .snapshot
            .set_acl_groups(config.connectivity.runtime.acl.acl.as_ref());
        let runtime_config = CoreRuntimeConfigStore::new(
            config.connectivity.runtime.clone(),
            Arc::new(config.peer.snapshot.clone()),
        );
        let stun = Self::prepare_stun(&adapters, &config.connectivity);
        let peer_stun: Arc<dyn StunInfoProvider> = stun.clone();
        let peer_manager = Arc::new(
            PeerManagerCore::new_portable_with_runtime_config_store_and_stun_info_source(
                config.peer,
                runtime_config.clone(),
                adapters.dns.clone(),
                dns_context,
                Arc::new(CoreStunPeerInfoSource(peer_stun)),
                packet_tx,
            )?,
        );
        let (mut instance, ()) = Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config.connectivity,
            runtime_config,
            stun,
            NoWrappedTransportEngineFactory,
        )?;
        instance.packet_egress = Some(PacketEgress::new(packet_rx, packet_sink));
        Ok(instance)
    }

    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
    ) -> anyhow::Result<Self> {
        let runtime_config = CoreRuntimeConfigStore::new(
            config.runtime.clone(),
            Arc::new(PeerRuntimeSnapshot::default()),
        );
        Self::new_with_runtime_config_store(peer_manager, adapters, config, runtime_config)
    }

    pub fn new_with_runtime_config_store(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
        runtime_config: CoreRuntimeConfigStore,
    ) -> anyhow::Result<Self> {
        validate_listener_protocols(
            &config.listeners,
            adapters.accepted_transport_handler.is_some(),
        )?;
        let stun = Self::prepare_stun(&adapters, &config);
        Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config,
            runtime_config,
            stun,
            NoWrappedTransportEngineFactory,
        )
        .map(|(instance, ())| instance)
    }

    pub fn new_with_runtime_config_store_and_transport_factory<F>(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
        runtime_config: CoreRuntimeConfigStore,
        transport_proxy_factory: F,
    ) -> anyhow::Result<(Self, F::Attachment)>
    where
        F: WrappedTransportEngineFactory,
    {
        validate_listener_protocols(
            &config.listeners,
            adapters.accepted_transport_handler.is_some(),
        )?;
        let stun = Self::prepare_stun(&adapters, &config);
        Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config,
            runtime_config,
            stun,
            transport_proxy_factory,
        )
    }

    fn new_with_prepared_stun<F>(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
        runtime_config: CoreRuntimeConfigStore,
        stun: Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>>,
        transport_proxy_factory: F,
    ) -> anyhow::Result<(Self, F::Attachment)>
    where
        F: WrappedTransportEngineFactory,
    {
        let CoreInstanceAdapters {
            host,
            stun_projection: _,
            dns,
            listener_dns,
            dns_records,
            ring_registry,
            protocol,
            manual_events,
            listener,
            listener_events,
            accepted_transport_handler,
            udp_hole_punch_platform,
            #[cfg(feature = "proxy-packet")]
            icmp_proxy_host,
            proxy_cidr_monitor,
            public_ipv6_provider,
        } = adapters;
        let CoreInstanceConfig {
            initial_peers,
            listeners,
            runtime: initial_runtime_config,
            stun: _,
            endpoint_discovery,
            manual: manual_options,
            direct: direct_options,
        } = config;

        let has_external_listener = listener.is_some();
        let (transport_listener, core_running_listeners): (
            Option<Arc<dyn ListenerService>>,
            Option<Arc<dyn RunningListenerProvider>>,
        ) = if listeners.is_empty() {
            (None, None)
        } else {
            let handler = accepted_transport_handler
                .unwrap_or_else(|| Arc::new(RawAcceptedTransportHandler::new(&peer_manager)));
            let registry = Arc::new(RunningListenerRegistry::default());
            let events: Arc<dyn ListenerEventSink> = match listener_events {
                Some(listener_events) => {
                    ListenerEventSinkGroup::new(vec![registry.clone(), listener_events])
                }
                None => registry.clone(),
            };
            let listener = Arc::new(TransportListenerService::new_with_events(
                host.clone(),
                listener_dns.unwrap_or_else(|| dns.clone()),
                ring_registry.clone(),
                listeners,
                handler,
                events,
            ));
            (Some(listener), Some(registry))
        };
        let running_listeners: Arc<dyn RunningListenerProvider> =
            match (core_running_listeners, has_external_listener) {
                (Some(core), true) => RunningListenerProviderGroup::new(vec![
                    core,
                    Arc::new(HostRunningListenerProvider(host.clone())),
                ]) as Arc<dyn RunningListenerProvider>,
                (Some(core), false) => core,
                (None, _) => Arc::new(HostRunningListenerProvider(host.clone())),
            };
        let listener = match (transport_listener, listener) {
            (Some(transport), Some(external)) => {
                Some(ListenerServiceGroup::new(vec![transport, external])
                    as Arc<dyn ListenerService>)
            }
            (Some(transport), None) => Some(transport),
            (None, Some(external)) => Some(external),
            (None, None) => None,
        };
        let protocol = protocol.unwrap_or_else(|| {
            Arc::new(CoreClientProtocolUpgrader::new(
                CoreClientProtocolConfig::default(),
            ))
        });
        let endpoint_resolver = Arc::new(CoreManualEndpointResolver::new(
            host.clone(),
            dns.clone(),
            dns_records,
            endpoint_discovery,
        ));
        let acl_whitelist = AclWhitelistSnapshot::from(&initial_runtime_config.acl);
        runtime_config.update_services(|services| *services = initial_runtime_config.clone());
        let manual = match manual_events {
            Some(events) => ManualConnectorManager::new_with_events(
                peer_manager.clone(),
                host.clone(),
                dns.clone(),
                endpoint_resolver,
                protocol.clone(),
                ring_registry.clone(),
                manual_options,
                events,
            ),
            None => ManualConnectorManager::new(
                peer_manager.clone(),
                host.clone(),
                dns.clone(),
                endpoint_resolver,
                protocol.clone(),
                ring_registry,
                manual_options,
            ),
        };
        let tcp_hole_punch_protocol = protocol.clone();
        let tcp_hole_punch_socket_context = direct_options.tcp_bind.context.clone();
        let udp_hole_punch_socket_context = direct_options.udp_bind.context.clone();
        let tcp_stun: Arc<dyn StunInfoProvider> = stun.clone();
        let udp_hole_punch = CoreUdpHolePunchService::new(
            peer_manager.clone(),
            host.clone(),
            stun.clone(),
            udp_hole_punch_platform.unwrap_or_else(|| Arc::new(())),
            udp_hole_punch_socket_context,
            protocol.clone(),
        );
        let proxy_cidr_table = Arc::new(ProxyCidrTable::from_snapshot(proxy_cidr_snapshot(
            runtime_config.snapshot().as_ref(),
        )));
        #[cfg(feature = "proxy-packet")]
        let proxy = {
            let tcp_socket_context = direct_options.tcp_bind.context.clone();
            let udp_socket_context = direct_options.udp_bind.context.clone();
            // Raw ICMP shares the datagram/network-layer routing context.
            let icmp_socket_context = direct_options.udp_bind.context.clone();
            CoreProxyModule::new(
                peer_manager.clone(),
                host.clone(),
                running_listeners.clone(),
                runtime_config.clone(),
                proxy_cidr_table.clone(),
                tcp_socket_context,
                udp_socket_context,
                icmp_socket_context,
                icmp_proxy_host,
            )
        };
        let WrappedTransportEngineBuild {
            kcp,
            quic,
            attachment: transport_proxy_attachment,
        } = transport_proxy_factory.build(proxy_cidr_table.clone())?;
        let transport_proxy = WrappedTransportProxyModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            kcp,
            quic,
        );
        let direct = DirectConnectorManager::new_with_running_listeners(
            peer_manager.clone(),
            host.clone(),
            stun.clone(),
            running_listeners,
            dns,
            protocol,
            direct_options,
        );
        let tcp_hole_punch = TcpHolePunchConnector::new(
            peer_manager.clone(),
            host,
            tcp_stun,
            tcp_hole_punch_socket_context,
            tcp_hole_punch_protocol,
            Arc::new(CoreServerProtocolUpgrader::<HostAcceptedTcpSocket<H>>::new(
                CoreServerProtocolConfig::default(),
            )),
        );
        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));
        let public_ipv6_provider = public_ipv6_provider.map(PublicIpv6ProviderService::new);

        Ok((
            Self {
                state: AtomicU8::new(CoreInstanceState::Created as u8),
                operation: Mutex::new(()),
                cancel: CancellationToken::new(),
                peer_manager,
                manual,
                direct,
                tcp_hole_punch,
                listener,
                udp_hole_punch,
                udp_hole_punch_started: AtomicBool::new(false),
                transport_proxy,
                proxy_cidr_table,
                #[cfg(feature = "proxy-packet")]
                proxy,
                #[cfg(feature = "proxy-packet")]
                proxy_started: AtomicBool::new(false),
                proxy_cidr_monitor,
                proxy_cidr_monitor_task: Mutex::new(None),
                dhcp_ipv4_task: Mutex::new(None),
                packet_egress: None,
                peer_center,
                peer_center_started: AtomicBool::new(false),
                public_ipv6_provider,
                initial_peers,
                initial_peers_started: AtomicBool::new(false),
                runtime_config,
                acl_whitelist: RwLock::new(acl_whitelist),
                initial_acl_loaded: AtomicBool::new(false),
            },
            transport_proxy_attachment,
        ))
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
        if let Some(public_ipv6_provider) = &self.public_ipv6_provider {
            public_ipv6_provider.stop().await;
        }
        self.dhcp_ipv4_task.lock().await.take();
        self.proxy_cidr_monitor_task.lock().await.take();
        if let Some(listener) = &self.listener {
            listener.stop().await;
        }
        self.udp_hole_punch.stop().await;
        self.udp_hole_punch_started.store(false, Ordering::Release);
        if let Some(transport_proxy) = &self.transport_proxy {
            transport_proxy.stop().await;
        }
        #[cfg(feature = "proxy-packet")]
        if self.proxy_started.load(Ordering::Acquire) {
            self.proxy.stop().await;
            self.proxy_started.store(false, Ordering::Release);
        }
        self.manual.stop().await;
        self.tcp_hole_punch.stop().await;
        self.direct.stop().await;
        self.peer_center.stop().await;
        self.peer_center_started.store(false, Ordering::Release);
        self.peer_manager.clear_resources().await;
        if let Some(packet_egress) = &self.packet_egress {
            packet_egress.stop().await;
        }
    }

    async fn start_listener(&self) -> anyhow::Result<()> {
        let Some(listener) = &self.listener else {
            return Ok(());
        };
        tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("listener start cancelled")),
            result = listener.start() => result,
        }
    }

    pub async fn start(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Created {
            anyhow::bail!("core instance cannot start from state {state:?}");
        }

        let public_ipv6_config = self.runtime_config.snapshot().services.public_ipv6_provider;
        public_ipv6_config.validate().map_err(anyhow::Error::new)?;
        if public_ipv6_config.provider_enabled && self.public_ipv6_provider.is_none() {
            anyhow::bail!("public IPv6 provider is enabled but no host adapter was provided");
        }
        if let Some(public_ipv6_provider) = &self.public_ipv6_provider {
            public_ipv6_provider.apply_config().await;
        }

        self.set_state(CoreInstanceState::Starting);
        let mut recovery = self.recovery_guard();

        if let Err(error) = self.start_listener().await {
            self.stop_components().await;
            self.set_state(CoreInstanceState::Stopped);
            recovery.disarm();
            return Err(error);
        }

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
        self.start_public_ipv6_provider().await;
        recovery.disarm();
        Ok(())
    }

    pub async fn start_udp_hole_punch(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("UDP hole punching cannot start from core instance state {state:?}");
        }
        if self.udp_hole_punch_started.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.udp_hole_punch_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("UDP hole punching start cancelled"))
            }
            result = self.udp_hole_punch.start() => result,
        };
        if let Err(error) = start_result {
            self.udp_hole_punch.stop().await;
            self.udp_hole_punch_started.store(false, Ordering::Release);
            recovery.disarm();
            return Err(error);
        }
        recovery.disarm();
        Ok(())
    }

    pub async fn start_peer_center(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("peer center cannot start from core instance state {state:?}");
        }
        if self.peer_center_started.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("peer center start cancelled");
        }

        self.peer_center.init().await;
        self.peer_manager
            .get_route()
            .set_route_cost_fn(self.peer_center.get_cost_calculator())
            .await;
        self.peer_center_started.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn start_initial_peers(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("initial peers cannot start from core instance state {state:?}");
        }
        if !self.peer_center_started.load(Ordering::Acquire) {
            anyhow::bail!("initial peers cannot start before peer center");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("initial peer start cancelled");
        }
        if self.initial_peers_started.load(Ordering::Acquire) {
            return Ok(());
        }

        for url in &self.initial_peers {
            if self.cancel.is_cancelled() {
                anyhow::bail!("initial peer start cancelled");
            }
            self.manual.add_connector(url.clone())?;
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("initial peer start cancelled");
        }
        self.initial_peers_started.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn start_transport_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("transport proxy cannot start from core instance state {state:?}");
        }
        let Some(transport_proxy) = &self.transport_proxy else {
            return Ok(());
        };
        let mut recovery = self.recovery_guard();
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("transport proxy start cancelled"))
            }
            result = transport_proxy.start() => result,
        };
        if let Err(error) = start_result {
            transport_proxy.stop().await;
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            transport_proxy.stop().await;
            recovery.disarm();
            anyhow::bail!("transport proxy start cancelled");
        }
        recovery.disarm();
        Ok(())
    }

    pub async fn reconcile_public_ipv6_provider(&self) -> bool {
        let Some(public_ipv6_provider) = &self.public_ipv6_provider else {
            return false;
        };
        public_ipv6_provider.apply_config().await
    }

    pub async fn start_public_ipv6_provider(&self) {
        let Some(public_ipv6_provider) = &self.public_ipv6_provider else {
            return;
        };
        public_ipv6_provider.start().await;
    }

    /// Starts proxy services after the host has prepared its packet interface.
    #[cfg(feature = "proxy-packet")]
    pub async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy services cannot start from core instance state {state:?}");
        }
        let proxy = &self.proxy;
        if self.proxy_started.load(Ordering::Acquire) {
            return Ok(());
        }
        let config = self.runtime_config.snapshot();
        let has_proxy_networks = !config.peer.runtime.core.routes.proxy_networks.is_empty();
        if !config.services.proxy.should_start(has_proxy_networks) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.proxy_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("proxy service start cancelled"))
            }
            result = proxy.start() => result.map_err(anyhow::Error::new),
        };
        if let Err(error) = start_result {
            proxy.stop().await;
            self.proxy_started.store(false, Ordering::Release);
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            proxy.stop().await;
            self.proxy_started.store(false, Ordering::Release);
            recovery.disarm();
            anyhow::bail!("proxy service start cancelled");
        }
        recovery.disarm();
        Ok(())
    }

    /// Validates proxy lifecycle ordering when packet proxy support is absent.
    #[cfg(not(feature = "proxy-packet"))]
    pub async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy services cannot start from core instance state {state:?}");
        }
        Ok(())
    }

    pub async fn start_proxy_cidr_monitor(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy CIDR monitor cannot start from core instance state {state:?}");
        }
        let Some(host) = &self.proxy_cidr_monitor else {
            return Ok(());
        };
        let mut task = self.proxy_cidr_monitor_task.lock().await;
        if task.is_some() {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("proxy CIDR monitor start cancelled");
        }

        task.replace(ProxyCidrMonitor::new(&self.peer_manager, host.clone()).start());
        if self.cancel.is_cancelled() {
            task.take();
            anyhow::bail!("proxy CIDR monitor start cancelled");
        }
        Ok(())
    }

    /// Starts the core-owned services that run after the host has prepared its
    /// packet interface.
    pub async fn start_network_services(
        self: &Arc<Self>,
        dhcp_ipv4_host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()> {
        if self.runtime_config.snapshot().services.dhcp_ipv4 {
            let host = dhcp_ipv4_host.ok_or_else(|| {
                anyhow::anyhow!("DHCP IPv4 is enabled but no host adapter was provided")
            })?;
            self.start_dhcp_ipv4(host).await?;
        }
        self.refresh_proxy_cidr_table().await?;
        self.start_transport_proxy().await?;
        self.load_initial_acl().await?;
        self.start_proxy().await?;
        self.start_udp_hole_punch().await?;
        self.start_peer_center().await?;
        self.start_initial_peers().await?;
        self.start_proxy_cidr_monitor().await?;
        Ok(())
    }

    async fn refresh_proxy_cidr_table(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy CIDR table cannot update from core instance state {state:?}");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("proxy CIDR table update cancelled");
        }
        self.proxy_cidr_table
            .update_snapshot(proxy_cidr_snapshot(self.runtime_config.snapshot().as_ref()));
        Ok(())
    }

    async fn load_initial_acl(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("ACL cannot load from core instance state {state:?}");
        }
        if self.initial_acl_loaded.load(Ordering::Acquire) {
            return Ok(());
        }

        let config = self.runtime_config.snapshot().services.acl.clone();
        *self.acl_whitelist.write() = AclWhitelistSnapshot::from(&config);
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
        self.initial_acl_loaded.store(true, Ordering::Release);
        Ok(())
    }

    /// Applies ACL runtime effects without publishing a separate config
    /// version. The caller must subsequently submit the complete instance
    /// runtime config, including this ACL.
    pub async fn reload_acl_config(&self, config: &AclRuleConfig) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        self.reload_acl_config_inner(config).await
    }

    async fn reload_acl_config_inner(&self, config: &AclRuleConfig) -> anyhow::Result<()> {
        *self.acl_whitelist.write() = AclWhitelistSnapshot::from(config);
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
        Ok(())
    }

    /// Publishes one complete instance configuration version. Host changes have
    /// no effect until submitted through this method.
    pub async fn update_runtime_config(&self, config: CoreInstanceRuntimeConfig) {
        let _operation = self.operation.lock().await;
        let current = self.runtime_config.snapshot();
        let refresh_acl_groups = current.peer.peer_group_memberships
            != config.peer.peer_group_memberships
            || current.peer.acl_group_declarations != config.peer.acl_group_declarations;
        self.runtime_config.replace(config);
        self.proxy_cidr_table
            .update_snapshot(proxy_cidr_snapshot(self.runtime_config.snapshot().as_ref()));
        if refresh_acl_groups {
            self.refresh_acl_groups().await;
        }
    }

    pub async fn start_dhcp_ipv4(
        self: &Arc<Self>,
        host: Arc<dyn DhcpIpv4Host>,
    ) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("DHCP IPv4 cannot start from core instance state {state:?}");
        }
        let mut task = self.dhcp_ipv4_task.lock().await;
        if task.is_some() {
            return Ok(());
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("DHCP IPv4 start cancelled");
        }

        let route_source: Arc<dyn DhcpIpv4RouteSource> = self.peer_manager.clone();
        task.replace(DhcpIpv4Service::new(route_source, host).start());
        if self.cancel.is_cancelled() {
            task.take();
            anyhow::bail!("DHCP IPv4 start cancelled");
        }
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

    pub fn peer_center_rpc_service(&self) -> PeerCenterInstanceService {
        self.peer_center.get_rpc_service()
    }

    pub async fn connected_peers(&self) -> Vec<crate::config::PeerId> {
        self.peer_manager
            .get_peer_map()
            .list_peers_with_conn()
            .await
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peer_manager.list_peer_snapshots().await
    }

    pub async fn node_snapshot(&self) -> crate::peers::peer_manager::NodeSnapshot {
        self.peer_manager
            .node_snapshot(self.running_listeners())
            .await
    }

    pub async fn route_snapshots(&self) -> Vec<crate::proto::core_peer::peer::Route> {
        self.peer_manager.list_route_snapshots().await
    }

    pub async fn public_ipv6_routes(&self) -> BTreeSet<cidr::Ipv6Inet> {
        self.peer_manager.list_public_ipv6_routes().await
    }

    pub async fn public_ipv6_addr(&self) -> Option<cidr::Ipv6Inet> {
        self.peer_manager.public_ipv6_addr().await
    }

    pub async fn dump_route(&self) -> String {
        self.peer_manager.dump_route().await
    }

    pub async fn local_public_ipv6_info(
        &self,
    ) -> crate::proto::core_peer::peer::ListPublicIpv6InfoResponse {
        self.peer_manager.local_public_ipv6_info().await
    }

    pub async fn foreign_network_route_infos(
        &self,
    ) -> crate::proto::peer_rpc::RouteForeignNetworkInfos {
        self.peer_manager.foreign_network_route_infos().await
    }

    pub async fn foreign_network_snapshots(
        &self,
        include_trusted_keys: bool,
    ) -> std::collections::HashMap<
        String,
        crate::peers::foreign_network_manager::ForeignNetworkEntryInfo,
    > {
        self.peer_manager
            .list_foreign_network_infos(include_trusted_keys)
            .await
    }

    pub async fn foreign_network_route_summary(
        &self,
    ) -> crate::proto::peer_rpc::RouteForeignNetworkSummary {
        self.peer_manager.foreign_network_route_summary().await
    }

    pub fn acl_stats(&self) -> crate::proto::acl::AclStats {
        self.peer_manager.acl_stats()
    }

    pub fn acl_whitelist_snapshot(&self) -> AclWhitelistSnapshot {
        self.acl_whitelist.read().clone()
    }

    pub fn runtime_config_snapshot(&self) -> CoreRuntimeConfig {
        self.runtime_config.snapshot().services.clone()
    }

    pub fn proxy_is_started(&self) -> bool {
        #[cfg(feature = "proxy-packet")]
        {
            self.proxy_started.load(Ordering::Acquire)
        }
        #[cfg(not(feature = "proxy-packet"))]
        {
            false
        }
    }

    #[cfg(feature = "proxy-packet")]
    pub fn tcp_proxy_entry_snapshots(
        &self,
    ) -> Vec<crate::proxy::tcp_proxy_engine::TcpNatEntrySnapshot> {
        self.proxy.tcp_entry_snapshots()
    }

    pub fn generate_credential(
        &self,
        options: CredentialCreateOptions,
    ) -> anyhow::Result<GeneratedCredential> {
        if !self.peer_manager.can_manage_credentials() {
            anyhow::bail!("only admin nodes (with network_secret) can generate credentials");
        }
        if options.ttl.is_zero() {
            anyhow::bail!("ttl_seconds must be positive");
        }
        let generated = self
            .peer_manager
            .credential_manager()
            .generate_credential_with_options(
                options.groups,
                options.allow_relay,
                options.allowed_proxy_cidrs,
                options.ttl,
                options.credential_id,
                options.reusable,
            );
        self.peer_manager.notify_credential_changed();
        Ok(generated)
    }

    pub fn revoke_credential(&self, credential_id: &str) -> anyhow::Result<bool> {
        if !self.peer_manager.can_manage_credentials() {
            anyhow::bail!("only admin nodes (with network_secret) can revoke credentials");
        }
        let revoked = self
            .peer_manager
            .credential_manager()
            .revoke_credential(credential_id);
        if revoked {
            self.peer_manager.notify_credential_changed();
        }
        Ok(revoked)
    }

    pub fn credential_snapshots(&self) -> Vec<CredentialInfo> {
        self.peer_manager.credential_manager().list_credentials()
    }

    pub async fn close_peer_conn(
        &self,
        peer_id: crate::config::PeerId,
        conn_id: &PeerConnId,
    ) -> Result<(), crate::peers::error::Error> {
        self.peer_manager.close_peer_conn(peer_id, conn_id).await
    }

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }

    pub async fn update_exit_nodes(&self, exit_nodes: Vec<IpAddr>) {
        self.peer_manager.update_exit_nodes(exit_nodes).await;
    }

    pub async fn refresh_acl_groups(&self) {
        self.peer_manager.get_route().refresh_acl_groups().await;
    }

    pub async fn proxy_cidr_diff(
        &self,
        previous: &BTreeSet<cidr::Ipv4Cidr>,
    ) -> Option<ProxyCidrDiff> {
        let host = self.proxy_cidr_monitor.as_ref()?;
        Some(collect_proxy_cidr_diff(self.peer_manager.as_ref(), host.as_ref(), previous).await)
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

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use tokio::sync::Notify;

    use super::*;
    #[test]
    fn portable_instance_config_round_trips_as_normalized_json() {
        let mut core = crate::config::CoreConfig::default();
        core.peer_policy.encryption_required = false;
        core.peer_policy.p2p_enabled = false;
        let peer = crate::peers::peer_manager::PortablePeerManagerConfig::new(
            crate::peers::context::PeerRuntimeConfig {
                core,
                network_identity: crate::config::NetworkIdentity {
                    network_name: "default".to_owned(),
                    network_secret: Some("test".to_owned()),
                    network_secret_digest: None,
                },
                stun_info: crate::proto::common::StunInfo::default(),
                feature_flags: crate::proto::common::PeerFeatureFlag::default(),
                secure_mode: None,
                host_routing: crate::peers::context::HostRoutingPolicy::default(),
            },
        );
        let config = PortableCoreInstanceConfig {
            peer,
            connectivity: CoreInstanceConfig::default(),
        };

        let mut config = config;
        config.connectivity.direct.disable_p2p = true;
        config.connectivity.direct.testing = true;
        let encoded = serde_json::to_value(&config).unwrap();
        assert!(encoded["connectivity"]["direct"].get("testing").is_none());
        let decoded: PortableCoreInstanceConfig = serde_json::from_value(encoded.clone()).unwrap();

        assert!(!decoded.connectivity.direct.testing);
        assert_eq!(serde_json::to_value(&decoded).unwrap(), encoded);

        let mut create = crate::instance::host::HostCoreInstanceCreateConfig {
            version: crate::instance::host::HOST_CORE_INSTANCE_CONFIG_VERSION,
            instance: decoded,
            environment:
                crate::connectivity::host::environment::HostConnectorEnvironmentSnapshot::default(),
        };
        create.validate().unwrap();
        let fixture = include_bytes!("../../easytier-go-host/testdata/minimal_core_instance.json");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(fixture).unwrap(),
            serde_json::to_value(&create).unwrap()
        );
        let create_json = serde_json::to_vec(&create).unwrap();
        serde_json::from_slice::<crate::instance::host::HostCoreInstanceCreateConfig>(&create_json)
            .unwrap()
            .validate()
            .unwrap();
        create.version += 1;
        assert!(create.validate().is_err());
    }

    #[test]
    fn portable_config_validation_rejects_invalid_acl_whitelist() {
        let peer = crate::peers::peer_manager::PortablePeerManagerConfig::new(
            crate::peers::context::PeerRuntimeConfig {
                core: crate::config::CoreConfig::default(),
                network_identity: crate::config::NetworkIdentity {
                    network_name: "default".to_owned(),
                    network_secret: Some("test".to_owned()),
                    network_secret_digest: None,
                },
                stun_info: crate::proto::common::StunInfo::default(),
                feature_flags: crate::proto::common::PeerFeatureFlag::default(),
                secure_mode: None,
                host_routing: crate::peers::context::HostRoutingPolicy::default(),
            },
        );
        let mut config = PortableCoreInstanceConfig {
            peer,
            connectivity: CoreInstanceConfig::default(),
        };
        config.connectivity.direct.lazy_p2p = config.peer.snapshot.flags.lazy_p2p;
        config.connectivity.direct.disable_p2p = config.peer.snapshot.flags.disable_p2p;
        config.connectivity.direct.need_p2p = config.peer.snapshot.flags.need_p2p;
        config.connectivity.runtime.acl.tcp_whitelist = vec!["9000-8000".to_owned()];

        let error = validate_portable_connectivity_config(&config).unwrap_err();

        assert!(error.to_string().contains("Start port must be <= end port"));
    }

    struct RecordingWrappedTransportEngine {
        name: &'static str,
        fail_start: bool,
        events: Arc<Mutex<Vec<String>>>,
    }

    struct RecordingListenerService {
        name: &'static str,
        fail_start: bool,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Debug)]
    struct StaticRunningListeners(Vec<Url>);

    impl RunningListenerProvider for StaticRunningListeners {
        fn running_listeners(&self) -> Vec<Url> {
            self.0.clone()
        }
    }

    struct CancelOnceStopEngine {
        stop_calls: AtomicUsize,
        stop_entered: Notify,
        release_first_stop: Notify,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[derive(Default)]
    struct RecordingDatagramEngine {
        injections: Mutex<Vec<(WrappedTransportRole, u32, Bytes)>>,
    }

    #[async_trait]
    impl WrappedTransportEngine for RecordingDatagramEngine {
        async fn start(&self, _options: WrappedTransportEngineStart) -> anyhow::Result<()> {
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

        async fn stop(&self) {}
    }

    #[async_trait]
    impl WrappedTransportEngine for CancelOnceStopEngine {
        async fn start(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("start:blocking".into());
            assert_eq!(
                options.directions,
                WrappedTransportDirections {
                    source: true,
                    destination: true,
                }
            );
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
    impl WrappedTransportEngine for RecordingWrappedTransportEngine {
        async fn start(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            let directions = options.directions;
            self.events.lock().unwrap().push(format!(
                "start:{}:{}:{}",
                self.name, directions.source, directions.destination
            ));
            if self.fail_start {
                anyhow::bail!("{} start failed", self.name);
            }
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

        async fn stop(&self) {
            self.events
                .lock()
                .unwrap()
                .push(format!("stop:{}", self.name));
        }
    }

    #[async_trait]
    impl ListenerService for RecordingListenerService {
        async fn start(&self) -> anyhow::Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("start:{}", self.name));
            if self.fail_start {
                anyhow::bail!("{} start failed", self.name);
            }
            Ok(())
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
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(Vec::new())
        }
    }

    fn wrapped_transport_peer_manager() -> Arc<PeerManagerCore> {
        let (packet_tx, _packet_rx) = create_packet_recv_chan();
        Arc::new(
            PeerManagerCore::new_portable(
                PortablePeerManagerConfig::new(crate::peers::context::PeerRuntimeConfig {
                    core: crate::config::CoreConfig {
                        node: crate::config::NodeConfig {
                            peer_id: Some(1),
                            network_name: "wrapped-transport-test".to_owned(),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                    network_identity: crate::config::NetworkIdentity {
                        network_name: "wrapped-transport-test".to_owned(),
                        network_secret: Some("secret".to_owned()),
                        network_secret_digest: None,
                    },
                    stun_info: crate::proto::common::StunInfo::default(),
                    feature_flags: crate::proto::common::PeerFeatureFlag::default(),
                    secure_mode: None,
                    host_routing: crate::peers::context::HostRoutingPolicy::default(),
                }),
                Arc::new(TestDnsResolver),
                packet_tx,
            )
            .unwrap(),
        )
    }

    fn listener_service(
        name: &'static str,
        fail_start: bool,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> Arc<dyn ListenerService> {
        Arc::new(RecordingListenerService {
            name,
            fail_start,
            events: events.clone(),
        })
    }

    #[tokio::test]
    async fn listener_group_starts_in_order_and_stops_in_reverse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let group = ListenerServiceGroup::new(vec![
            listener_service("transport", false, &events),
            listener_service("external", false, &events),
        ]);

        group.start().await.unwrap();
        group.stop().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "start:transport",
                "start:external",
                "stop:external",
                "stop:transport",
            ]
        );
    }

    #[tokio::test]
    async fn listener_group_rolls_back_the_failing_service_and_predecessors() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let group = ListenerServiceGroup::new(vec![
            listener_service("transport", false, &events),
            listener_service("external", true, &events),
        ]);

        assert!(group.start().await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            [
                "start:transport",
                "start:external",
                "stop:external",
                "stop:transport",
            ]
        );
    }

    #[test]
    fn running_listener_group_keeps_core_and_host_listeners() {
        let core = Arc::new(StaticRunningListeners(vec![
            "tcp://127.0.0.1:11010".parse().unwrap(),
        ]));
        let host = Arc::new(StaticRunningListeners(vec![
            "udp://127.0.0.1:11010".parse().unwrap(),
        ]));
        let group = RunningListenerProviderGroup::new(vec![core, host]);

        assert_eq!(
            group.running_listeners(),
            [
                "tcp://127.0.0.1:11010".parse().unwrap(),
                "udp://127.0.0.1:11010".parse().unwrap(),
            ]
        );
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
    async fn wrapped_transport_peer_filter_maps_packet_role_and_releases_stale_engine() {
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
    fn wrapped_transport_datagram_preserves_wire_packet_types() {
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
                payload: Bytes::from_static(b"wire"),
            }
            .into_packet(7);
            let header = packet.peer_manager_header().unwrap();

            assert_eq!(header.from_peer_id.get(), 7);
            assert_eq!(header.to_peer_id.get(), 9);
            assert_eq!(header.packet_type, packet_type as u8);
            assert_eq!(packet.payload(), b"wire");
        }
    }

    #[tokio::test]
    async fn wrapped_transport_module_reads_activation_flags_and_stops_in_reverse() {
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
        let module = WrappedTransportProxyModule::new(
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
                "start:kcp:true:false",
                "start:quic:false:true",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn wrapped_transport_module_rolls_back_failing_engine_and_predecessor() {
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
        let module = WrappedTransportProxyModule::new(
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
                "start:kcp:true:true",
                "start:quic:true:true",
                "stop:quic",
                "stop:kcp",
            ]
        );
    }

    #[tokio::test]
    async fn wrapped_transport_module_retries_cleanup_after_stop_is_cancelled() {
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
        let module = WrappedTransportProxyModule::new(
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
                "start:kcp:true:true",
                "start:blocking",
                "stop:blocking",
                "stop:blocking",
                "stop:kcp",
            ]
        );
    }
}

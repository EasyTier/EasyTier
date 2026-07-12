//! Lifecycle owner for the portable EasyTier runtime.

pub mod packet_io;
pub mod public_ipv6_provider;

use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering},
};
use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::Mutex;
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
        protocol::{ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader},
    },
    dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource, DhcpIpv4Service},
    hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    listener::{
        AcceptedSocketHandler, RunningListenerProvider, RunningListenerProviderGroup,
        RunningListenerRegistry,
        transport::{
            AcceptedTransport, HostAcceptedTcpSocket, RawAcceptedTransportHandler,
            TransportListenerConfig, TransportListenerService,
        },
    },
    peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService},
    peers::{
        acl_config::AclRuleConfig,
        create_packet_recv_chan,
        credential_manager::{CredentialInfo, GeneratedCredential},
        peer_conn::PeerConnId,
        peer_manager::{PeerManagerCore, PeerSnapshot, PortablePeerManagerConfig},
        public_ipv6::PublicIpv6ProviderConfig,
    },
    proxy::{
        ProxyStartupContext,
        cidr_monitor::{
            ProxyCidrDiff, ProxyCidrMonitor, ProxyCidrMonitorHost, collect_proxy_cidr_diff,
        },
        cidr_table::ProxyCidrRuntime,
    },
    socket::{
        dns::{DnsRecordResolver, DnsResolver},
        tcp::VirtualTcpSocketFactory,
    },
};

use self::public_ipv6_provider::{PublicIpv6ProviderHost, PublicIpv6ProviderService};

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

#[derive(Debug, Clone)]
pub struct CoreRuntimeConfig {
    pub acl: AclRuleConfig,
    pub dhcp_ipv4: bool,
    pub proxy: ProxyStartupContext,
    pub public_ipv6_provider: PublicIpv6ProviderConfig,
}

impl Default for CoreRuntimeConfig {
    fn default() -> Self {
        Self {
            acl: AclRuleConfig::default(),
            dhcp_ipv4: false,
            proxy: ProxyStartupContext::default(),
            public_ipv6_provider: PublicIpv6ProviderConfig {
                provider_enabled: false,
                configured_prefix: None,
                provider_supported: false,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub listeners: Vec<TransportListenerConfig>,
    pub runtime: CoreRuntimeConfig,
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
            endpoint_discovery: ManualEndpointDiscoveryConfig::default(),
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
    pub dns_records: Arc<dyn DnsRecordResolver>,
    pub protocol: Option<Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>>,
    pub manual_events: Option<Arc<dyn ManualConnectivityEventSink>>,
    pub listener: Option<Arc<dyn ListenerService>>,
    pub accepted_transport_handler:
        Option<Arc<dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>>>,
    pub udp_hole_punch: Option<Arc<dyn UdpHolePunchService>>,
    pub runtime_config: Option<Arc<dyn CoreRuntimeConfigProvider>>,
    pub transport_proxy: Option<Arc<dyn ProxyService>>,
    pub proxy: Option<Arc<dyn ProxyService>>,
    pub proxy_cidr_runtime: Option<Arc<dyn ProxyCidrRuntime>>,
    pub proxy_cidr_monitor: Option<Arc<dyn ProxyCidrMonitorHost>>,
    pub public_ipv6_provider: Option<Arc<dyn PublicIpv6ProviderHost>>,
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

pub trait CoreRuntimeConfigProvider: Send + Sync + 'static {
    fn current_runtime_config(&self) -> CoreRuntimeConfig;
}

struct StaticCoreRuntimeConfigProvider(CoreRuntimeConfig);

impl CoreRuntimeConfigProvider for StaticCoreRuntimeConfigProvider {
    fn current_runtime_config(&self) -> CoreRuntimeConfig {
        self.0.clone()
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
pub trait UdpHolePunchService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

#[async_trait]
pub trait ProxyService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

pub trait ProxyStartupPolicy: Send + Sync + 'static {
    fn should_start(&self) -> bool;
}

pub struct ProxyServiceGroup {
    operation: Mutex<()>,
    policy: Arc<dyn ProxyStartupPolicy>,
    services: Vec<Arc<dyn ProxyService>>,
    started_count: AtomicUsize,
}

struct UnconditionalProxyStartupPolicy;

impl ProxyStartupPolicy for UnconditionalProxyStartupPolicy {
    fn should_start(&self) -> bool {
        true
    }
}

impl ProxyServiceGroup {
    pub fn new(
        policy: Arc<dyn ProxyStartupPolicy>,
        services: Vec<Arc<dyn ProxyService>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            operation: Mutex::new(()),
            policy,
            services,
            started_count: AtomicUsize::new(0),
        })
    }

    pub fn new_unconditional(services: Vec<Arc<dyn ProxyService>>) -> Arc<Self> {
        Self::new(Arc::new(UnconditionalProxyStartupPolicy), services)
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
impl ProxyService for ProxyServiceGroup {
    async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started_count.load(Ordering::Acquire) != 0 || !self.policy.should_start() {
            return Ok(());
        }

        for (index, service) in self.services.iter().enumerate() {
            self.started_count.store(index + 1, Ordering::Release);
            if let Err(err) = service.start().await {
                self.stop_started().await;
                return Err(err);
            }
        }
        Ok(())
    }

    async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_started().await;
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
    udp_hole_punch: Option<Arc<dyn UdpHolePunchService>>,
    udp_hole_punch_started: AtomicBool,
    transport_proxy: Option<Arc<dyn ProxyService>>,
    transport_proxy_started: AtomicBool,
    proxy: Option<Arc<dyn ProxyService>>,
    proxy_started: AtomicBool,
    proxy_cidr_runtime: Option<Arc<dyn ProxyCidrRuntime>>,
    proxy_cidr_runtime_started: AtomicBool,
    proxy_cidr_monitor: Option<Arc<dyn ProxyCidrMonitorHost>>,
    proxy_cidr_monitor_task: Mutex<Option<AbortOnDropHandle<()>>>,
    dhcp_ipv4_task: Mutex<Option<AbortOnDropHandle<()>>>,
    packet_egress: Option<PacketEgress>,
    peer_center: Arc<PeerCenterInstance>,
    peer_center_started: AtomicBool,
    public_ipv6_provider: Option<Arc<PublicIpv6ProviderService>>,
    initial_peers: Vec<Url>,
    initial_peers_started: AtomicBool,
    runtime_config: Arc<dyn CoreRuntimeConfigProvider>,
    acl_whitelist: RwLock<AclWhitelistSnapshot>,
    initial_acl_loaded: AtomicBool,
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
            dns_records,
            protocol,
            manual_events,
            listener,
            accepted_transport_handler,
            udp_hole_punch,
            runtime_config,
            transport_proxy,
            proxy,
            proxy_cidr_runtime,
            proxy_cidr_monitor,
            public_ipv6_provider,
        } = adapters;
        let CoreInstanceConfig {
            initial_peers,
            listeners,
            runtime: initial_runtime_config,
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
            let listener = Arc::new(TransportListenerService::new_with_events(
                host.clone(),
                listeners,
                handler,
                registry.clone(),
            ));
            (Some(listener), Some(registry))
        };
        let running_listeners = match (core_running_listeners, has_external_listener) {
            (Some(core), true) => Some(RunningListenerProviderGroup::new(vec![
                core,
                Arc::new(HostRunningListenerProvider(host.clone())),
            ]) as Arc<dyn RunningListenerProvider>),
            (core, _) => core,
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
        peer_manager.initialize_portable_acl(&initial_runtime_config.acl)?;
        let acl_whitelist = AclWhitelistSnapshot::from(&initial_runtime_config.acl);
        let runtime_config: Arc<dyn CoreRuntimeConfigProvider> = runtime_config
            .unwrap_or_else(|| Arc::new(StaticCoreRuntimeConfigProvider(initial_runtime_config)));
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
        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));
        let public_ipv6_provider = public_ipv6_provider.map(PublicIpv6ProviderService::new);

        Ok(Self {
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
            transport_proxy_started: AtomicBool::new(false),
            proxy,
            proxy_started: AtomicBool::new(false),
            proxy_cidr_runtime,
            proxy_cidr_runtime_started: AtomicBool::new(false),
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
        if let Some(public_ipv6_provider) = &self.public_ipv6_provider {
            public_ipv6_provider.stop().await;
        }
        self.dhcp_ipv4_task.lock().await.take();
        self.proxy_cidr_monitor_task.lock().await.take();
        if let Some(listener) = &self.listener {
            listener.stop().await;
        }
        if let Some(udp_hole_punch) = &self.udp_hole_punch {
            udp_hole_punch.stop().await;
            self.udp_hole_punch_started.store(false, Ordering::Release);
        }
        if let Some(transport_proxy) = &self.transport_proxy
            && self.transport_proxy_started.load(Ordering::Acquire)
        {
            transport_proxy.stop().await;
            self.transport_proxy_started.store(false, Ordering::Release);
        }
        if let Some(proxy) = &self.proxy
            && self.proxy_started.load(Ordering::Acquire)
        {
            proxy.stop().await;
            self.proxy_started.store(false, Ordering::Release);
        }
        if let Some(proxy_cidr_runtime) = &self.proxy_cidr_runtime
            && self
                .proxy_cidr_runtime_started
                .swap(false, Ordering::AcqRel)
        {
            proxy_cidr_runtime.stop_updater();
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

        let public_ipv6_config = self
            .runtime_config
            .current_runtime_config()
            .public_ipv6_provider;
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
        if self.transport_proxy_started.load(Ordering::Acquire) {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.transport_proxy_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("transport proxy start cancelled"))
            }
            result = transport_proxy.start() => result,
        };
        if let Err(error) = start_result {
            transport_proxy.stop().await;
            self.transport_proxy_started.store(false, Ordering::Release);
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            transport_proxy.stop().await;
            self.transport_proxy_started.store(false, Ordering::Release);
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
    pub async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy services cannot start from core instance state {state:?}");
        }
        let Some(proxy) = &self.proxy else {
            return Ok(());
        };
        if self.proxy_started.load(Ordering::Acquire) {
            return Ok(());
        }
        if !self
            .runtime_config
            .current_runtime_config()
            .proxy
            .should_start()
        {
            return Ok(());
        }

        let mut recovery = self.recovery_guard();
        self.proxy_started.store(true, Ordering::Release);
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => {
                Err(anyhow::anyhow!("proxy service start cancelled"))
            }
            result = proxy.start() => result,
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
        if self.runtime_config.current_runtime_config().dhcp_ipv4 {
            let host = dhcp_ipv4_host.ok_or_else(|| {
                anyhow::anyhow!("DHCP IPv4 is enabled but no host adapter was provided")
            })?;
            self.start_dhcp_ipv4(host).await?;
        }
        self.start_proxy_cidr_runtime().await?;
        self.start_transport_proxy().await?;
        self.load_initial_acl().await?;
        self.start_proxy().await?;
        self.start_udp_hole_punch().await?;
        self.start_peer_center().await?;
        self.start_initial_peers().await?;
        self.start_proxy_cidr_monitor().await?;
        Ok(())
    }

    async fn start_proxy_cidr_runtime(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy CIDR runtime cannot start from core instance state {state:?}");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("proxy CIDR runtime start cancelled");
        }
        if let Some(proxy_cidr_runtime) = &self.proxy_cidr_runtime
            && !self.proxy_cidr_runtime_started.swap(true, Ordering::AcqRel)
        {
            proxy_cidr_runtime.start_updater();
        }
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

        let config = self.runtime_config.current_runtime_config().acl;
        *self.acl_whitelist.write() = AclWhitelistSnapshot::from(&config);
        let acl = config.build()?;
        if self.peer_manager.reload_acl(acl.as_ref()) {
            self.refresh_acl_groups().await;
        }
        self.initial_acl_loaded.store(true, Ordering::Release);
        Ok(())
    }

    pub async fn apply_acl_config(&self, config: AclRuleConfig) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        *self.acl_whitelist.write() = AclWhitelistSnapshot::from(&config);
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
        self.refresh_acl_groups().await;
        Ok(())
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

    struct StaticProxyPolicy(bool);

    impl ProxyStartupPolicy for StaticProxyPolicy {
        fn should_start(&self) -> bool {
            self.0
        }
    }

    struct RecordingProxyService {
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

    struct CancelOnceStopService {
        stop_calls: AtomicUsize,
        stop_entered: Notify,
        release_first_stop: Notify,
        events: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProxyService for CancelOnceStopService {
        async fn start(&self) -> anyhow::Result<()> {
            self.events.lock().unwrap().push("start:blocking".into());
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
    impl ProxyService for RecordingProxyService {
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

    fn service(
        name: &'static str,
        fail_start: bool,
        events: &Arc<Mutex<Vec<String>>>,
    ) -> Arc<dyn ProxyService> {
        Arc::new(RecordingProxyService {
            name,
            fail_start,
            events: events.clone(),
        })
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

    #[tokio::test]
    async fn proxy_group_starts_in_order_and_stops_in_reverse() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let group = ProxyServiceGroup::new(
            Arc::new(StaticProxyPolicy(true)),
            vec![
                service("tcp", false, &events),
                service("icmp", false, &events),
                service("udp", false, &events),
            ],
        );

        group.start().await.unwrap();
        group.stop().await;

        assert_eq!(
            *events.lock().unwrap(),
            [
                "start:tcp",
                "start:icmp",
                "start:udp",
                "stop:udp",
                "stop:icmp",
                "stop:tcp",
            ]
        );
    }

    #[tokio::test]
    async fn proxy_group_rolls_back_the_failing_service_and_predecessors() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let group = ProxyServiceGroup::new(
            Arc::new(StaticProxyPolicy(true)),
            vec![
                service("tcp", false, &events),
                service("icmp", true, &events),
                service("udp", false, &events),
            ],
        );

        assert!(group.start().await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            ["start:tcp", "start:icmp", "stop:icmp", "stop:tcp"]
        );
    }

    #[tokio::test]
    async fn proxy_group_skips_services_when_policy_is_disabled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let group = ProxyServiceGroup::new(
            Arc::new(StaticProxyPolicy(false)),
            vec![service("tcp", false, &events)],
        );

        group.start().await.unwrap();
        group.stop().await;

        assert!(events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_group_retries_cleanup_after_stop_is_cancelled() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let blocking = Arc::new(CancelOnceStopService {
            stop_calls: AtomicUsize::new(0),
            stop_entered: Notify::new(),
            release_first_stop: Notify::new(),
            events: events.clone(),
        });
        let group = ProxyServiceGroup::new(
            Arc::new(StaticProxyPolicy(true)),
            vec![service("tcp", false, &events), blocking.clone()],
        );
        group.start().await.unwrap();

        let stop_task = tokio::spawn({
            let group = group.clone();
            async move { group.stop().await }
        });
        blocking.stop_entered.notified().await;
        stop_task.abort();
        assert!(stop_task.await.unwrap_err().is_cancelled());

        group.stop().await;

        assert_eq!(blocking.stop_calls.load(Ordering::Acquire), 2);
        assert_eq!(
            *events.lock().unwrap(),
            [
                "start:tcp",
                "start:blocking",
                "stop:blocking",
                "stop:blocking",
                "stop:tcp",
            ]
        );
    }
}

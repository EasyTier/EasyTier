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
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
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
    peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService},
    peers::{
        acl_config::AclRuleConfig,
        context::{PeerRuntimeSnapshot, PeerStunInfoSource},
        create_packet_recv_chan,
        credential_manager::{CredentialInfo, GeneratedCredential},
        peer_conn::PeerConnId,
        peer_manager::{PeerManagerCore, PeerSnapshot, PortablePeerManagerConfig},
    },
    proxy::{
        cidr_monitor::{
            ProxyCidrDiff, ProxyCidrMonitor, ProxyCidrMonitorHost, collect_proxy_cidr_diff,
        },
        cidr_table::ProxyCidrRuntime,
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
    pub udp_hole_punch: Option<Arc<dyn UdpHolePunchService>>,
    pub transport_proxy: Option<Arc<dyn ProxyService>>,
    pub proxy: Option<Arc<dyn ProxyService>>,
    pub proxy_cidr_runtime: Option<Arc<dyn ProxyCidrRuntime>>,
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
pub trait UdpHolePunchService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

#[async_trait]
pub trait ProxyService: Send + Sync + 'static {
    async fn start(&self) -> anyhow::Result<()>;
    async fn stop(&self);
}

pub struct ProxyServiceGroup {
    operation: Mutex<()>,
    services: Vec<Arc<dyn ProxyService>>,
    started_count: AtomicUsize,
}

impl ProxyServiceGroup {
    pub fn new(services: Vec<Arc<dyn ProxyService>>) -> Arc<Self> {
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
impl ProxyService for ProxyServiceGroup {
    async fn start(&self) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        if self.started_count.load(Ordering::Acquire) != 0 {
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
        let mut instance = Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config.connectivity,
            runtime_config,
            stun,
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
        Self::new_with_prepared_stun(peer_manager, adapters, config, runtime_config, stun)
    }

    fn new_with_prepared_stun(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
        runtime_config: CoreRuntimeConfigStore,
        stun: Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>>,
    ) -> anyhow::Result<Self> {
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
            udp_hole_punch,
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
        let tcp_stun: Arc<dyn StunInfoProvider> = stun.clone();
        let direct = match running_listeners {
            Some(running_listeners) => DirectConnectorManager::new_with_running_listeners(
                peer_manager.clone(),
                host.clone(),
                stun.clone(),
                running_listeners,
                dns,
                protocol,
                direct_options,
            ),
            None => DirectConnectorManager::new(
                peer_manager.clone(),
                host.clone(),
                stun,
                dns,
                protocol,
                direct_options,
            ),
        };
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
        if !self.runtime_config.snapshot().services.proxy.should_start() {
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
        if self.runtime_config.snapshot().services.dhcp_ipv4 {
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
        let group = ProxyServiceGroup::new(vec![
            service("tcp", false, &events),
            service("icmp", false, &events),
            service("udp", false, &events),
        ]);

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
        let group = ProxyServiceGroup::new(vec![
            service("tcp", false, &events),
            service("icmp", true, &events),
            service("udp", false, &events),
        ]);

        assert!(group.start().await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            ["start:tcp", "start:icmp", "stop:icmp", "stop:tcp"]
        );
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
        let group = ProxyServiceGroup::new(vec![service("tcp", false, &events), blocking.clone()]);
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

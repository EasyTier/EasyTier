//! Lifecycle owner for the portable EasyTier runtime.

pub mod host;
pub mod packet_io;
pub mod public_ipv6_provider;
pub mod udp_hole_punch;

#[cfg(any(test, target_os = "wasi"))]
mod runtime_driver;

use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

#[cfg(feature = "test-utils")]
use std::sync::atomic::AtomicUsize;
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
        direct::{
            DirectConnectorHost, DirectConnectorManager, DirectConnectorOptions,
            ForeignDirectConnectorRpcRegistrar,
        },
        manual::{
            ManualConnectivityEventSink, ManualConnectorManager, ManualConnectorOptions,
            ManualConnectorSnapshot,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::{
            ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader,
            CoreServerProtocolConfig, CoreServerProtocolUpgrader, ServerProtocolUpgrader,
        },
    },
    dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource, DhcpIpv4Service},
    hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    hole_punch::udp::{UdpPortMappingEventSink, UdpPortMappingPlatform},
    listener::{
        AcceptedSocketHandler, ListenerEventSink, ListenerEventSinkGroup, ListenerFactory,
        RunningListenerProvider, RunningListenerRegistry, SocketListener,
        plan::{
            ListenerKind, ListenerPlanFailure, ListenerRuntimeConfig, ListenerSchemeRegistry,
            PlannedListener,
        },
        transport::{
            AcceptedTransport, AcceptedTunnelEventSink, CoreListenerRuntime, HostAcceptedTcpSocket,
            PeerAcceptedTunnelHandler, ProtocolAcceptedTransportHandler,
            RawAcceptedTransportHandler, TransportListenerConfig,
        },
    },
    magic_dns::{MagicDnsRouteSnapshot, MagicDnsRouteSource},
    peer_center::instance::{PeerCenterInstance, PeerCenterInstanceService},
    peers::{
        acl_config::AclRuleConfig,
        context::{PeerRuntimeSnapshot, PeerStunInfoSource},
        create_packet_recv_chan,
        credential_manager::{CredentialInfo, GeneratedCredential},
        peer_conn::PeerConnId,
        peer_manager::{
            PeerManagerCore, PeerManagerHostAdapters, PeerSnapshot, PortablePeerManagerConfig,
        },
        public_ipv6::{CorePublicIpv6Runtime, PublicIpv6Host},
    },
    process_runtime::CoreProcessRuntime,
    proxy::{
        cidr_monitor::{
            ProxyCidrDiff, ProxyCidrMonitor, ProxyCidrMonitorHost, collect_proxy_cidr_diff,
        },
        cidr_table::{ProxyCidrSnapshot, ProxyCidrTable},
        wrapped_transport::{
            NoWrappedTransportEngineFactory, WrappedTransportEngineBuild,
            WrappedTransportEngineFactory, WrappedTransportProxyModule,
        },
    },
    runtime_config::{CoreInstanceRuntimeConfig, CoreRuntimeConfig, CoreRuntimeConfigStore},
    socket::{
        SocketContext,
        dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        tcp::VirtualTcpSocketFactory,
        udp::{UdpSessionAcceptKind, UdpSessionProtocol, VirtualUdpSocketFactory},
    },
    stats_manager::{CounterHandle, LabelSet, LabelType, MetricName, MetricSnapshot},
    stun::{
        StunInfoCollector, StunInfoProvider, StunProviderSlot, StunServerConfig, StunSocketMapper,
    },
    vpn_portal::{VpnPortalEventSink, VpnPortalHost, VpnPortalInfoSnapshot, VpnPortalModule},
};

#[cfg(feature = "proxy-smoltcp-stack")]
use crate::proxy::gateway::{GatewayEventSink, GatewayModule};

use self::{
    public_ipv6_provider::{PublicIpv6ProviderPlatform, PublicIpv6ProviderService},
    udp_hole_punch::CoreUdpHolePunchService,
};
#[cfg(feature = "proxy-packet")]
use crate::proxy::wrapped_transport::{WrappedTransportKind, WrappedTransportRole};
#[cfg(feature = "proxy-packet")]
use crate::proxy::{runtime::IcmpProxyHost, service::CoreProxyModule};
#[cfg(feature = "proxy-packet")]
use crate::{
    magic_dns::{MagicDnsQueryResolver, magic_dns_packet_filter},
    peers::peer_manager::PipelineRegistrationGuard,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreInstanceStartupPlan {
    pub gateway: bool,
}

impl CoreInstanceStartupPlan {
    fn is_default(&self) -> bool {
        self == &Self::default()
    }
}

impl Default for CoreInstanceStartupPlan {
    fn default() -> Self {
        Self { gateway: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub listeners: Option<ListenerRuntimeConfig>,
    pub runtime: CoreRuntimeConfig,
    #[serde(default, skip_serializing_if = "CoreInstanceStartupPlan::is_default")]
    pub startup_plan: CoreInstanceStartupPlan,
    pub stun: StunServerConfig,
    pub endpoint_discovery: ManualEndpointDiscoveryConfig,
    pub manual: ManualConnectorOptions,
    pub direct: DirectConnectorOptions,
}

impl Default for CoreInstanceConfig {
    fn default() -> Self {
        Self {
            initial_peers: Vec::new(),
            listeners: None,
            runtime: CoreRuntimeConfig::default(),
            startup_plan: CoreInstanceStartupPlan::default(),
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

#[derive(Clone)]
pub struct UdpBroadcastRelayStats {
    packets_captured: CounterHandle,
    packets_ignored: CounterHandle,
    packets_forwarded: CounterHandle,
    packets_forward_failed: CounterHandle,
}

#[cfg(feature = "test-utils")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRelaySessionSnapshot {
    pub has_state: bool,
    pub has_session: bool,
}

impl UdpBroadcastRelayStats {
    pub fn record_captured(&self) {
        self.packets_captured.inc();
    }

    pub fn record_ignored(&self) {
        self.packets_ignored.inc();
    }

    pub fn record_forwarded(&self) {
        self.packets_forwarded.inc();
    }

    pub fn record_forward_failed(&self) {
        self.packets_forward_failed.inc();
    }
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
    has_server_protocol: bool,
) -> anyhow::Result<()> {
    if has_server_protocol {
        return Ok(());
    }
    if let Some(listener) = listeners
        .iter()
        .find(|listener| !listener.supports_raw_handler())
    {
        anyhow::bail!(
            "listener {} requires a server protocol upgrader",
            listener.url()
        );
    }
    Ok(())
}

struct PreparedListenerPlan {
    transports: Vec<TransportListenerConfig>,
    external: Vec<(PlannedListener, SocketContext)>,
    failures: Vec<ListenerPlanFailure>,
}

fn prepare_listener_plan<Accepted, TcpSocket: 'static>(
    config: Option<&ListenerRuntimeConfig>,
    self_id: uuid::Uuid,
    server_protocol: Option<&dyn ServerProtocolUpgrader<TcpSocket>>,
    external_factory: Option<&dyn ExternalListenerFactory<Accepted>>,
) -> anyhow::Result<PreparedListenerPlan>
where
    Accepted: Send + 'static,
{
    let Some(config) = config else {
        return Ok(PreparedListenerPlan {
            transports: Vec::new(),
            external: Vec::new(),
            failures: Vec::new(),
        });
    };
    let mut schemes = ListenerSchemeRegistry::new()
        .support("tcp", ListenerKind::TcpStream)
        .support("udp", ListenerKind::UdpSession);
    for (scheme, kind) in [
        ("ws", ListenerKind::TcpStream),
        ("wss", ListenerKind::TcpStream),
        ("wg", ListenerKind::UdpSession),
        ("quic", ListenerKind::UdpSession),
    ] {
        if server_protocol.is_some_and(|protocol| protocol.supports_scheme(scheme)) {
            schemes = schemes.support(scheme, kind);
        }
    }
    schemes = schemes.disable_ipv6_shadow("quic");
    if server_protocol.is_some_and(|protocol| protocol.supports_scheme("faketcp"))
        && external_factory.is_some_and(|factory| factory.supports_scheme("faketcp"))
    {
        schemes = schemes.support("faketcp", ListenerKind::External);
    }
    if external_factory.is_some_and(|factory| factory.supports_scheme("unix")) {
        schemes = schemes.support("unix", ListenerKind::External);
    }
    schemes = schemes.disable_ipv6_shadow("faketcp");
    let plan = crate::listener::plan::plan_listeners(config.request(self_id), &schemes);
    let mut transports = Vec::new();
    let mut external = Vec::new();
    for listener in plan.listeners {
        let must_succeed = listener.must_succeed;
        match listener.kind {
            ListenerKind::Ring => transports.push(TransportListenerConfig::Ring {
                url: listener.url,
                must_succeed,
            }),
            ListenerKind::TcpStream => {
                let max_pending_upgrades = server_protocol
                    .and_then(|protocol| protocol.max_pending_tcp_upgrades(listener.url.scheme()));
                transports.push(TransportListenerConfig::Tcp {
                    url: listener.url,
                    options: crate::listener::plan::unresolved_tcp_listener_options(
                        config.socket_context.clone(),
                    ),
                    max_pending_upgrades,
                    must_succeed,
                });
            }
            ListenerKind::UdpSession => {
                let accept_kind = match listener.url.scheme() {
                    "udp" => UdpSessionAcceptKind::EasyTierMux,
                    "wg" => UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
                    "quic" => UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
                    scheme => {
                        anyhow::bail!("listener scheme {scheme} cannot produce a core UDP session")
                    }
                };
                let request = crate::listener::plan::unresolved_udp_session_listen_request(
                    &listener.url,
                    config.socket_context.clone(),
                );
                transports.push(TransportListenerConfig::Udp {
                    url: listener.url,
                    request,
                    accept_kind,
                    must_succeed,
                });
            }
            ListenerKind::External => external.push((listener, config.socket_context.clone())),
        }
    }
    Ok(PreparedListenerPlan {
        transports,
        external,
        failures: plan.failures,
    })
}

fn proxy_cidr_snapshot(config: &CoreInstanceRuntimeConfig) -> ProxyCidrSnapshot {
    ProxyCidrSnapshot::from_proxy_networks(&config.peer.runtime.core.routes.proxy_networks)
}

fn retain_core_peer_identity(
    peer: &mut Arc<PeerRuntimeSnapshot>,
    peer_id: crate::config::PeerId,
    instance_id: Option<[u8; 16]>,
) {
    let peer = Arc::make_mut(peer);
    peer.runtime.core.node.peer_id = Some(peer_id);
    peer.runtime.core.node.instance_id = instance_id;
}

pub struct CoreInstanceAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub host: Arc<H>,
    /// Optional preinstalled stable slot for deterministic adapters and tests.
    /// Core installs its production collector only when the slot is empty.
    pub stun_projection: Option<Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>>>,
    pub dns: Arc<dyn DnsResolver>,
    /// Optional listener-specific resolver. When absent, listeners share `dns` with connectors.
    pub listener_dns: Option<Arc<dyn DnsResolver>>,
    pub dns_records: Arc<dyn DnsRecordResolver>,
    pub process_runtime: Arc<CoreProcessRuntime>,
    pub protocol: Option<Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>>,
    pub manual_events: Option<Arc<dyn ManualConnectivityEventSink>>,
    pub external_listener_factory:
        Option<Arc<dyn ExternalListenerFactory<AcceptedTransport<HostAcceptedTcpSocket<H>>>>>,
    pub listener_events: Option<Arc<dyn ListenerEventSink>>,
    pub server_protocol: Option<Arc<dyn ServerProtocolUpgrader<HostAcceptedTcpSocket<H>>>>,
    pub accepted_tunnel_events: Option<Arc<dyn AcceptedTunnelEventSink>>,
    /// Optional OS port-mapping adapter. STUN-only hole punching remains
    /// available when the host does not provide one.
    pub udp_hole_punch_platform: Option<Arc<dyn UdpPortMappingPlatform>>,
    /// Optional presentation sink for successful UDP port mappings.
    pub udp_hole_punch_events: Option<Arc<dyn UdpPortMappingEventSink>>,
    #[cfg(feature = "proxy-packet")]
    pub icmp_proxy_host: Option<Arc<dyn IcmpProxyHost>>,
    pub proxy_cidr_monitor: Option<Arc<dyn ProxyCidrMonitorHost>>,
    pub public_ipv6_host: Option<Arc<dyn PublicIpv6Host>>,
    pub public_ipv6_provider: Option<Arc<dyn PublicIpv6ProviderPlatform>>,
    pub vpn_portal: Option<Arc<dyn VpnPortalHost>>,
    pub vpn_portal_events: Option<Arc<dyn VpnPortalEventSink>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    pub gateway_events: Option<Arc<dyn GatewayEventSink>>,
}

pub trait ExternalListenerFactory<Accepted>: Send + Sync + 'static
where
    Accepted: Send + 'static,
{
    fn supports_scheme(&self, scheme: &str) -> bool;

    fn create(
        &self,
        request: ExternalListenerRequest,
    ) -> Box<dyn SocketListener<Accepted = Accepted>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalListenerRequest {
    pub url: Url,
    pub socket_context: SocketContext,
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

/// Owns one Magic DNS resolver installed in the core NIC pipeline.
///
/// `close` waits until readers that may already be invoking the resolver have
/// finished, then removes the entry so the resolver can be dropped promptly.
#[cfg(feature = "proxy-packet")]
pub struct MagicDnsResolverRegistration {
    peer_manager: Weak<PeerManagerCore>,
    pipeline: PipelineRegistrationGuard,
    runtime: tokio::runtime::Handle,
}

#[cfg(feature = "proxy-packet")]
impl MagicDnsResolverRegistration {
    pub async fn close(&self) {
        self.pipeline.close();
        if let Some(peer_manager) = self.peer_manager.upgrade() {
            peer_manager
                .remove_managed_nic_packet_process_pipeline(&self.pipeline)
                .await;
        }
    }
}

#[cfg(feature = "proxy-packet")]
impl Drop for MagicDnsResolverRegistration {
    fn drop(&mut self) {
        self.pipeline.close();
        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return;
        };
        let pipeline = self.pipeline.clone();
        self.runtime.spawn(async move {
            peer_manager
                .remove_managed_nic_packet_process_pipeline(&pipeline)
                .await;
        });
    }
}

#[async_trait]
pub trait ProxyService: Send + Sync + 'static {
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
    listener: Option<Arc<CoreListenerRuntime<H>>>,
    udp_hole_punch: CoreUdpHolePunchService<H>,
    udp_hole_punch_started: AtomicBool,
    transport_proxy: Option<Arc<WrappedTransportProxyModule>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    gateway: Arc<GatewayModule<H>>,
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
    vpn_portal: Arc<VpnPortalModule>,
    initial_peers: Vec<Url>,
    initial_peers_started: AtomicBool,
    startup_plan: CoreInstanceStartupPlan,
    runtime_config: CoreRuntimeConfigStore,
    acl_whitelist: RwLock<AclWhitelistSnapshot>,
    initial_acl_loaded: AtomicBool,
    #[cfg(feature = "test-utils")]
    acl_reload_count: AtomicUsize,
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
        config: PortableCoreInstanceConfig,
        packet_sink: Arc<dyn PacketSink>,
    ) -> anyhow::Result<Self> {
        Self::new_portable_with_peer_adapters(
            adapters,
            PeerManagerHostAdapters::default(),
            config,
            packet_sink,
        )
    }

    pub fn new_portable_with_peer_adapters(
        adapters: CoreInstanceAdapters<H>,
        peer_adapters: PeerManagerHostAdapters,
        config: PortableCoreInstanceConfig,
        packet_sink: Arc<dyn PacketSink>,
    ) -> anyhow::Result<Self> {
        Self::new_portable_with_peer_adapters_and_transport_factory(
            adapters,
            peer_adapters,
            config,
            packet_sink,
            NoWrappedTransportEngineFactory,
        )
        .map(|(instance, ())| instance)
    }

    pub fn new_portable_with_peer_adapters_and_transport_factory<F>(
        mut adapters: CoreInstanceAdapters<H>,
        peer_adapters: PeerManagerHostAdapters,
        config: PortableCoreInstanceConfig,
        packet_sink: Arc<dyn PacketSink>,
        transport_proxy_factory: F,
    ) -> anyhow::Result<(Self, F::Attachment)>
    where
        F: WrappedTransportEngineFactory,
    {
        validate_portable_connectivity_config(&config)?;
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
        let runtime_config = CoreRuntimeConfigStore::new(
            config.connectivity.runtime.clone(),
            Arc::new(config.peer.snapshot.clone()),
        );
        let public_ipv6_host: Arc<dyn PublicIpv6Host> = adapters
            .public_ipv6_host
            .take()
            .unwrap_or_else(|| Arc::new(()));
        let public_ipv6_runtime =
            CorePublicIpv6Runtime::new(runtime_config.clone(), public_ipv6_host);
        let stun = Self::prepare_stun(&adapters, &config.connectivity);
        let peer_stun: Arc<dyn StunInfoProvider> = stun.clone();
        let foreign_rpc_registrar = Arc::new(ForeignDirectConnectorRpcRegistrar::new(
            adapters.host.clone(),
            stun.clone(),
        ));
        let peer_manager = Arc::new(
            PeerManagerCore::new_portable_with_runtime_config_store_and_host_adapters(
                config.peer,
                runtime_config.clone(),
                adapters.dns.clone(),
                dns_context,
                Arc::new(CoreStunPeerInfoSource(peer_stun)),
                packet_tx,
                public_ipv6_runtime.clone(),
                peer_adapters,
                foreign_rpc_registrar,
            )?,
        );
        let (mut instance, attachment) = Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config.connectivity,
            runtime_config,
            stun,
            Some(public_ipv6_runtime),
            transport_proxy_factory,
        )?;
        instance.packet_egress = Some(PacketEgress::new(packet_rx, packet_sink));
        Ok((instance, attachment))
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
        let stun = Self::prepare_stun(&adapters, &config);
        Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config,
            runtime_config,
            stun,
            None,
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
        let stun = Self::prepare_stun(&adapters, &config);
        Self::new_with_prepared_stun(
            peer_manager,
            adapters,
            config,
            runtime_config,
            stun,
            None,
            transport_proxy_factory,
        )
    }

    fn new_with_prepared_stun<F>(
        peer_manager: Arc<PeerManagerCore>,
        adapters: CoreInstanceAdapters<H>,
        config: CoreInstanceConfig,
        runtime_config: CoreRuntimeConfigStore,
        stun: Arc<StunProviderSlot<<H as VirtualUdpSocketFactory>::Socket>>,
        public_ipv6_runtime: Option<Arc<CorePublicIpv6Runtime>>,
        transport_proxy_factory: F,
    ) -> anyhow::Result<(Self, F::Attachment)>
    where
        F: WrappedTransportEngineFactory,
    {
        let listener_plan = prepare_listener_plan(
            config.listeners.as_ref(),
            peer_manager.instance_id(),
            adapters.server_protocol.as_deref(),
            adapters.external_listener_factory.as_deref(),
        )?;
        validate_listener_protocols(
            &listener_plan.transports,
            adapters.server_protocol.is_some(),
        )?;
        let CoreInstanceAdapters {
            host,
            stun_projection: _,
            dns,
            listener_dns,
            dns_records,
            process_runtime,
            protocol,
            manual_events,
            external_listener_factory,
            listener_events,
            server_protocol,
            accepted_tunnel_events,
            udp_hole_punch_platform,
            udp_hole_punch_events,
            #[cfg(feature = "proxy-packet")]
            icmp_proxy_host,
            proxy_cidr_monitor,
            public_ipv6_host: _,
            public_ipv6_provider,
            vpn_portal,
            vpn_portal_events,
            #[cfg(feature = "proxy-smoltcp-stack")]
            gateway_events,
        } = adapters;
        let ring_registry = process_runtime.ring_registry();
        let CoreInstanceConfig {
            initial_peers,
            listeners: _,
            runtime: initial_runtime_config,
            startup_plan,
            stun: _,
            endpoint_discovery,
            manual: manual_options,
            direct: direct_options,
        } = config;

        let accepted_transport_handler: Arc<
            dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>,
        > = match server_protocol {
            Some(server_protocol) => {
                let tunnel_handler = PeerAcceptedTunnelHandler::new(
                    &peer_manager,
                    accepted_tunnel_events.unwrap_or_else(|| Arc::new(())),
                );
                Arc::new(ProtocolAcceptedTransportHandler::new(
                    &tunnel_handler,
                    server_protocol,
                ))
            }
            None => Arc::new(RawAcceptedTransportHandler::new(&peer_manager)),
        };
        let registry = Arc::new(RunningListenerRegistry::default());
        let events: Arc<dyn ListenerEventSink> = match listener_events {
            Some(listener_events) => {
                ListenerEventSinkGroup::new(vec![registry.clone(), listener_events])
            }
            None => registry.clone(),
        };
        let PreparedListenerPlan {
            transports,
            external,
            failures,
        } = listener_plan;
        let mut external_factories = Vec::with_capacity(external.len());
        if !external.is_empty() && external_listener_factory.is_none() {
            anyhow::bail!("listener plan requires an external listener factory");
        }
        for (listener, socket_context) in external {
            let factory = external_listener_factory.clone().unwrap();
            let request = ExternalListenerRequest {
                url: listener.url,
                socket_context,
            };
            external_factories.push(ListenerFactory::new(
                move || factory.create(request.clone()),
                listener.must_succeed,
            ));
        }
        let has_listener_work =
            !transports.is_empty() || !external_factories.is_empty() || !failures.is_empty();
        let listener = has_listener_work.then(|| {
            Arc::new(CoreListenerRuntime::new_with_events(
                host.clone(),
                listener_dns.unwrap_or_else(|| dns.clone()),
                ring_registry.clone(),
                transports,
                external_factories,
                failures,
                accepted_transport_handler,
                events,
            ))
        });
        let running_listeners: Arc<dyn RunningListenerProvider> = registry;
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
            udp_hole_punch_platform,
            udp_hole_punch_events.unwrap_or_else(|| Arc::new(())),
            udp_hole_punch_socket_context,
            protocol.clone(),
        );
        let proxy_cidr_table = Arc::new(ProxyCidrTable::from_snapshot(proxy_cidr_snapshot(
            runtime_config.snapshot().as_ref(),
        )));
        let tcp_proxy_socket_context = direct_options.tcp_bind.context.clone();
        #[cfg(feature = "proxy-packet")]
        let proxy = {
            let udp_socket_context = direct_options.udp_bind.context.clone();
            // Raw ICMP shares the datagram/network-layer routing context.
            let icmp_socket_context = direct_options.udp_bind.context.clone();
            CoreProxyModule::new(
                peer_manager.clone(),
                host.clone(),
                running_listeners.clone(),
                runtime_config.clone(),
                proxy_cidr_table.clone(),
                tcp_proxy_socket_context.clone(),
                udp_socket_context,
                icmp_socket_context,
                icmp_proxy_host,
            )
        };
        let WrappedTransportEngineBuild {
            kcp,
            quic,
            attachment: transport_proxy_attachment,
        } = transport_proxy_factory.build()?;
        let transport_proxy = WrappedTransportProxyModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            kcp,
            quic,
            host.clone(),
            running_listeners.clone(),
            proxy_cidr_table.clone(),
            tcp_proxy_socket_context,
        );
        #[cfg(feature = "proxy-smoltcp-stack")]
        let gateway = GatewayModule::new(
            runtime_config.clone(),
            peer_manager.clone(),
            transport_proxy.as_ref(),
            host.clone(),
            dns.clone(),
            direct_options.tcp_bind.context.clone(),
            gateway_events.unwrap_or_else(|| Arc::new(())),
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
        let public_ipv6_provider = match (public_ipv6_provider, public_ipv6_runtime) {
            (Some(host), Some(runtime)) => Some(PublicIpv6ProviderService::new(
                host,
                runtime_config.clone(),
                runtime,
            )),
            (None, _) => None,
            (Some(_), None) => {
                anyhow::bail!("public IPv6 provider requires the portable core-owned peer runtime")
            }
        };
        let vpn_portal = VpnPortalModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            vpn_portal,
            vpn_portal_events.unwrap_or_else(|| Arc::new(())),
        );

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
                #[cfg(feature = "proxy-smoltcp-stack")]
                gateway,
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
                vpn_portal,
                initial_peers,
                initial_peers_started: AtomicBool::new(false),
                startup_plan,
                runtime_config,
                acl_whitelist: RwLock::new(acl_whitelist),
                initial_acl_loaded: AtomicBool::new(false),
                #[cfg(feature = "test-utils")]
                acl_reload_count: AtomicUsize::new(0),
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
        self.vpn_portal.stop().await;
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
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.gateway.stop().await;
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

    async fn start_udp_hole_punch(self: &Arc<Self>) -> anyhow::Result<()> {
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

    async fn start_peer_center(self: &Arc<Self>) -> anyhow::Result<()> {
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

    async fn start_initial_peers(self: &Arc<Self>) -> anyhow::Result<()> {
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

    async fn start_transport_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
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
        let applied = public_ipv6_provider.apply_config().await;
        public_ipv6_provider.start().await;
        applied
    }

    async fn start_public_ipv6_provider(&self) {
        let Some(public_ipv6_provider) = &self.public_ipv6_provider else {
            return;
        };
        public_ipv6_provider.start().await;
    }

    /// Starts proxy services after the host has prepared its packet interface.
    #[cfg(feature = "proxy-packet")]
    async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
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
    async fn start_proxy(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("proxy services cannot start from core instance state {state:?}");
        }
        Ok(())
    }

    async fn start_proxy_cidr_monitor(self: &Arc<Self>) -> anyhow::Result<()> {
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

        task.replace(
            ProxyCidrMonitor::new(
                &self.peer_manager,
                self.runtime_config.clone(),
                host.clone(),
            )
            .start(),
        );
        if self.cancel.is_cancelled() {
            task.take();
            anyhow::bail!("proxy CIDR monitor start cancelled");
        }
        Ok(())
    }

    /// Starts the core-owned services that run after the host has prepared its
    /// packet interface.
    async fn start_network_services(
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
        self.start_vpn_portal().await?;
        Ok(())
    }

    /// Completes startup after the host packet interface is ready. Core owns
    /// the service order and rolls back the whole instance on partial failure.
    pub async fn start_after_host_ready(
        self: &Arc<Self>,
        dhcp_ipv4_host: Option<Arc<dyn DhcpIpv4Host>>,
    ) -> anyhow::Result<()> {
        let result = async {
            self.start_network_services(dhcp_ipv4_host).await?;
            if self.startup_plan.gateway {
                self.start_gateway().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            self.stop().await;
            return Err(error);
        }
        Ok(())
    }

    async fn start_vpn_portal(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("VPN portal cannot start from core instance state {state:?}");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("VPN portal start cancelled");
        }
        let mut recovery = self.recovery_guard();
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("VPN portal start cancelled")),
            result = self.vpn_portal.start() => result,
        };
        if let Err(error) = start_result {
            self.vpn_portal.stop().await;
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            self.vpn_portal.stop().await;
            recovery.disarm();
            anyhow::bail!("VPN portal start cancelled");
        }
        recovery.disarm();
        Ok(())
    }

    pub async fn vpn_portal_info(&self) -> VpnPortalInfoSnapshot {
        self.vpn_portal.info_snapshot().await
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    async fn start_gateway(self: &Arc<Self>) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("gateway cannot start from core instance state {state:?}");
        }
        if self.cancel.is_cancelled() {
            anyhow::bail!("gateway start cancelled");
        }
        let mut recovery = self.recovery_guard();
        let start_result = tokio::select! {
            _ = self.cancel.cancelled() => Err(anyhow::anyhow!("gateway start cancelled")),
            result = self.gateway.start() => result,
        };
        if let Err(error) = start_result {
            self.gateway.stop().await;
            recovery.disarm();
            return Err(error);
        }
        if self.cancel.is_cancelled() {
            self.gateway.stop().await;
            recovery.disarm();
            anyhow::bail!("gateway start cancelled");
        }
        recovery.disarm();
        Ok(())
    }

    #[cfg(not(feature = "proxy-smoltcp-stack"))]
    async fn start_gateway(self: &Arc<Self>) -> anyhow::Result<()> {
        let state = self.state();
        if state != CoreInstanceState::Running {
            anyhow::bail!("gateway cannot start from core instance state {state:?}");
        }
        Ok(())
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: std::net::SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<crate::proxy::gateway::DataPlaneTcpStream> {
        self.gateway.data_plane_tcp_connect(dst_addr, timeout).await
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<crate::proxy::gateway::DataPlaneTcpListener> {
        self.gateway.data_plane_tcp_bind(local_port, timeout).await
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<crate::proxy::gateway::DataPlaneUdpSocket> {
        self.gateway.data_plane_udp_bind(local_port, timeout).await
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

    async fn reload_acl_config_inner(&self, config: &AclRuleConfig) -> anyhow::Result<()> {
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
        *self.acl_whitelist.write() = AclWhitelistSnapshot::from(config);
        #[cfg(feature = "test-utils")]
        self.acl_reload_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn sync_peer_runtime_state(&self, snapshot: &PeerRuntimeSnapshot) {
        self.peer_manager
            .set_avoid_relay_data_preference(snapshot.avoid_relay_data_preference);
    }

    /// Publishes one complete instance configuration version. Host changes have
    /// no effect until submitted through this method.
    pub async fn update_runtime_config(
        &self,
        mut config: CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        let current = self.runtime_config.snapshot();
        retain_core_peer_identity(
            &mut config.peer,
            self.peer_id(),
            current.peer.runtime.core.node.instance_id,
        );
        let refresh_acl_groups = current.peer.peer_group_memberships
            != config.peer.peer_group_memberships
            || current.peer.acl_group_declarations != config.peer.acl_group_declarations;
        let acl_loaded = self.initial_acl_loaded.load(Ordering::Acquire);
        if acl_loaded && current.services.acl != config.services.acl {
            self.reload_acl_config_inner(&config.services.acl).await?;
        } else if !acl_loaded {
            *self.acl_whitelist.write() = AclWhitelistSnapshot::from(&config.services.acl);
        }
        self.sync_peer_runtime_state(&config.peer);
        self.runtime_config.replace(config);
        self.proxy_cidr_table
            .update_snapshot(proxy_cidr_snapshot(self.runtime_config.snapshot().as_ref()));
        if refresh_acl_groups {
            self.refresh_acl_groups().await;
        }
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.gateway
            .reload_port_forwards(
                &self
                    .runtime_config
                    .snapshot()
                    .services
                    .gateway
                    .port_forwards,
            )
            .await?;
        Ok(())
    }

    async fn start_dhcp_ipv4(self: &Arc<Self>, host: Arc<dyn DhcpIpv4Host>) -> anyhow::Result<()> {
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
        task.replace(DhcpIpv4Service::new(route_source, self.runtime_config.clone(), host).start());
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

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn admit_client_tunnel_for_test(
        &self,
        tunnel: Box<dyn crate::tunnel::Tunnel>,
        is_directly_connected: bool,
    ) -> Result<(crate::config::PeerId, PeerConnId), crate::peers::error::Error> {
        self.peer_manager
            .add_client_tunnel(tunnel, is_directly_connected)
            .await
    }

    pub async fn peer_snapshots(&self) -> Vec<PeerSnapshot> {
        self.peer_manager.list_peer_snapshots().await
    }

    pub async fn node_snapshot(&self) -> crate::peers::peer_manager::NodeSnapshot {
        let mut snapshot = self
            .peer_manager
            .node_snapshot(self.running_listeners())
            .await;
        snapshot.ip_list = self
            .direct
            .local_address_observations_with_stun(&snapshot.stun_info)
            .await;
        snapshot
    }

    pub async fn route_snapshots(&self) -> Vec<crate::proto::core_peer::peer::Route> {
        self.peer_manager.list_route_snapshots().await
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub async fn relay_route_has_static_key_for_test(
        &self,
        peer_id: crate::config::PeerId,
    ) -> bool {
        self.peer_manager
            .get_peer_map()
            .get_route_peer_info(peer_id)
            .await
            .is_some_and(|info| !info.noise_static_pubkey.is_empty())
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn relay_session_snapshot_for_test(
        &self,
        peer_id: crate::config::PeerId,
    ) -> PeerRelaySessionSnapshot {
        let relay = self.peer_manager.get_relay_peer_map();
        PeerRelaySessionSnapshot {
            has_state: relay.has_state(peer_id),
            has_session: relay.has_session_without_touch(peer_id),
        }
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn evict_idle_relay_sessions_for_test(&self, idle: Duration) {
        self.peer_manager
            .get_relay_peer_map()
            .evict_idle_sessions(idle);
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn evict_unused_peer_sessions_for_test(&self, idle: Duration) {
        self.peer_manager
            .get_peer_session_store()
            .evict_unused_sessions_idle(idle);
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

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn proxy_cidr_lookup_for_test(
        &self,
        address: std::net::Ipv4Addr,
    ) -> Option<std::net::Ipv4Addr> {
        self.proxy_cidr_table.lookup_v4(address)
    }

    #[cfg(feature = "test-utils")]
    #[doc(hidden)]
    pub fn acl_reload_count_for_test(&self) -> usize {
        self.acl_reload_count.load(Ordering::Relaxed)
    }

    pub async fn update_peer_runtime_snapshot(&self, mut snapshot: Arc<PeerRuntimeSnapshot>) {
        let _operation = self.operation.lock().await;
        let current = self.runtime_config.snapshot();
        retain_core_peer_identity(
            &mut snapshot,
            self.peer_id(),
            current.peer.runtime.core.node.instance_id,
        );
        let refresh_acl_groups = current.peer.peer_group_memberships
            != snapshot.peer_group_memberships
            || current.peer.acl_group_declarations != snapshot.acl_group_declarations;
        self.sync_peer_runtime_state(&snapshot);
        self.runtime_config.update_peer(snapshot);
        self.proxy_cidr_table
            .update_snapshot(proxy_cidr_snapshot(self.runtime_config.snapshot().as_ref()));
        if refresh_acl_groups {
            self.refresh_acl_groups().await;
        }
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

    #[cfg(feature = "proxy-packet")]
    pub fn wrapped_tcp_proxy_entry_snapshots(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> Vec<crate::proxy::tcp_proxy_engine::TcpNatEntrySnapshot> {
        self.transport_proxy
            .as_ref()
            .map_or_else(Vec::new, |proxy| match role {
                WrappedTransportRole::Source => proxy.source_entry_snapshots(transport),
                WrappedTransportRole::Destination => proxy.destination_entry_snapshots(transport),
            })
    }

    #[cfg(feature = "proxy-packet")]
    pub fn wrapped_transport_is_started(
        &self,
        transport: WrappedTransportKind,
        role: WrappedTransportRole,
    ) -> bool {
        self.transport_proxy
            .as_ref()
            .is_some_and(|proxy| match role {
                WrappedTransportRole::Source => proxy.source_is_started(transport),
                WrappedTransportRole::Destination => proxy.destination_is_started(transport),
            })
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

    pub fn metric_snapshots(&self) -> Vec<MetricSnapshot> {
        self.peer_manager.stats_manager().get_all_metrics()
    }

    pub fn prometheus_metrics(&self) -> String {
        self.peer_manager.stats_manager().export_prometheus()
    }

    pub fn udp_broadcast_relay_stats(&self) -> UdpBroadcastRelayStats {
        let network_name = self
            .runtime_config
            .snapshot()
            .peer
            .runtime
            .network_identity
            .network_name
            .clone();
        let labels = LabelSet::new().with_label_type(LabelType::NetworkName(network_name));
        let stats = self.peer_manager.stats_manager();
        UdpBroadcastRelayStats {
            packets_captured: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsCaptured, labels.clone()),
            packets_ignored: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsIgnored, labels.clone()),
            packets_forwarded: stats.get_counter(
                MetricName::UdpBroadcastRelayPacketsForwarded,
                labels.clone(),
            ),
            packets_forward_failed: stats
                .get_counter(MetricName::UdpBroadcastRelayPacketsForwardFailed, labels),
        }
    }

    #[cfg(feature = "proxy-packet")]
    pub async fn register_magic_dns_resolver(
        &self,
        fake_ip: std::net::Ipv4Addr,
        resolver: Arc<dyn MagicDnsQueryResolver>,
    ) -> MagicDnsResolverRegistration {
        let runtime = tokio::runtime::Handle::current();
        let pipeline = self
            .peer_manager
            .add_managed_nic_packet_process_pipeline(magic_dns_packet_filter(
                fake_ip,
                self.peer_id(),
                resolver,
            ))
            .await;
        MagicDnsResolverRegistration {
            peer_manager: Arc::downgrade(&self.peer_manager),
            pipeline,
            runtime,
        }
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
        self.proxy_cidr_monitor.as_ref()?;
        Some(
            collect_proxy_cidr_diff(self.peer_manager.as_ref(), &self.runtime_config, previous)
                .await,
        )
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

    pub async fn send_local_ip_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        let destination = parse_ip_packet(&packet)?.destination;
        self.peer_manager
            .send_msg_by_ip(
                crate::packet::ZCPacket::new_with_payload(&packet),
                destination,
                true,
            )
            .await
            .map_err(Into::into)
    }
}

#[async_trait]
impl<H> MagicDnsRouteSource for CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    async fn snapshot(&self) -> MagicDnsRouteSnapshot {
        MagicDnsRouteSource::snapshot(self.peer_manager.as_ref()).await
    }

    async fn revision(&self) -> quanta::Instant {
        MagicDnsRouteSource::revision(self.peer_manager.as_ref()).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct TestServerProtocol;

    #[async_trait]
    impl ServerProtocolUpgrader<()> for TestServerProtocol {
        fn supports_scheme(&self, scheme: &str) -> bool {
            matches!(scheme, "ws" | "wss" | "wg" | "quic" | "faketcp" | "unix")
        }

        async fn upgrade_tcp(
            &self,
            _socket: (),
            _local_url: Url,
        ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
            unreachable!()
        }

        async fn upgrade_udp(
            &self,
            _session: crate::socket::udp::UdpSession,
            _local_url: Url,
            _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
        ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
            unreachable!()
        }

        async fn upgrade_byte_stream(
            &self,
            _socket: (),
            _local_url: Url,
            _remote_url: Option<Url>,
        ) -> anyhow::Result<crate::connectivity::protocol::ServerProtocolUpgrade> {
            unreachable!()
        }
    }

    struct TestExternalListenerFactory;

    impl ExternalListenerFactory<()> for TestExternalListenerFactory {
        fn supports_scheme(&self, scheme: &str) -> bool {
            matches!(scheme, "faketcp" | "unix")
        }

        fn create(
            &self,
            _request: ExternalListenerRequest,
        ) -> Box<dyn SocketListener<Accepted = ()>> {
            unreachable!()
        }
    }

    #[test]
    fn runtime_updates_retain_core_owned_peer_identity() {
        let mut snapshot = Arc::new(PeerRuntimeSnapshot::default());
        Arc::make_mut(&mut snapshot).runtime.core.node.peer_id = Some(17);
        Arc::make_mut(&mut snapshot).runtime.core.node.instance_id = Some([1; 16]);
        let submitted = snapshot.clone();

        retain_core_peer_identity(&mut snapshot, 23, Some([2; 16]));

        assert_eq!(snapshot.runtime.core.node.peer_id, Some(23));
        assert_eq!(snapshot.runtime.core.node.instance_id, Some([2; 16]));
        assert_eq!(submitted.runtime.core.node.peer_id, Some(17));
        assert_eq!(submitted.runtime.core.node.instance_id, Some([1; 16]));
    }

    #[test]
    fn core_plans_transport_and_external_listener_capabilities() {
        let self_id = uuid::Uuid::new_v4();
        let config = ListenerRuntimeConfig::new(
            [
                "tcp://127.0.0.1:1",
                "udp://127.0.0.1:2",
                "ws://127.0.0.1:3",
                "wg://127.0.0.1:4",
                "quic://127.0.0.1:5",
                "faketcp://127.0.0.1:6",
                "unix:///tmp/easytier-test",
                "http://127.0.0.1:7",
            ]
            .into_iter()
            .map(str::parse)
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
            false,
            SocketContext::default().with_socket_mark(Some(7)),
        );

        let plan = prepare_listener_plan::<(), ()>(
            Some(&config),
            self_id,
            Some(&TestServerProtocol),
            Some(&TestExternalListenerFactory),
        )
        .unwrap();

        assert_eq!(plan.transports.len(), 6);
        assert_eq!(plan.external.len(), 2);
        assert_eq!(plan.failures.len(), 1);
        assert_eq!(
            plan.transports[0].url(),
            &crate::listener::plan::ring_listener_url(self_id)
        );
        assert!(matches!(
            &plan.transports[4],
            TransportListenerConfig::Udp {
                accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::WireGuard),
                ..
            }
        ));
        assert!(matches!(
            &plan.transports[5],
            TransportListenerConfig::Udp {
                accept_kind: UdpSessionAcceptKind::Classified(UdpSessionProtocol::Quic),
                ..
            }
        ));
        assert_eq!(plan.external[0].0.url.scheme(), "faketcp");
        assert_eq!(plan.external[0].1.socket_mark, Some(7));
    }

    #[test]
    fn unsupported_protocol_listener_becomes_a_plan_failure() {
        let config = ListenerRuntimeConfig::new(
            vec!["wg://127.0.0.1:11011".parse().unwrap()],
            false,
            SocketContext::default(),
        );

        let plan = prepare_listener_plan::<(), ()>(Some(&config), uuid::Uuid::new_v4(), None, None)
            .unwrap();

        assert_eq!(plan.transports.len(), 1);
        assert!(plan.external.is_empty());
        assert_eq!(plan.failures.len(), 1);
    }

    #[test]
    fn raw_unix_listener_does_not_require_a_server_protocol() {
        let config = ListenerRuntimeConfig::new(
            vec!["unix:///tmp/easytier-test".parse().unwrap()],
            false,
            SocketContext::default(),
        );

        let plan = prepare_listener_plan::<(), ()>(
            Some(&config),
            uuid::Uuid::new_v4(),
            None,
            Some(&TestExternalListenerFactory),
        )
        .unwrap();

        assert_eq!(plan.transports.len(), 1);
        assert_eq!(plan.external.len(), 1);
        assert!(plan.failures.is_empty());
        assert_eq!(plan.external[0].0.url.scheme(), "unix");
    }

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
        assert!(decoded.connectivity.startup_plan.gateway);
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

    mod portable_runtime {
        use std::{
            io,
            net::{IpAddr, Ipv6Addr, SocketAddr},
            pin::Pin,
            sync::{
                Arc,
                atomic::{AtomicUsize, Ordering},
            },
            task::{Context, Poll},
        };

        use tokio::{
            io::{AsyncRead, AsyncWrite, ReadBuf},
            sync::Notify,
        };
        use tokio_util::task::AbortOnDropHandle;

        #[cfg(feature = "proxy-packet")]
        use std::sync::Mutex as StdMutex;

        use super::*;
        use crate::{
            config::{CoreConfig, IpPrefix, NetworkIdentity, ProxyNetworkConfig},
            connectivity::manual::{ManualConnectorHost, ManualInterfaceAddrs},
            listener::transport::AcceptedTransport,
            peers::{
                context::{HostRoutingPolicy, PeerRuntimeConfig},
                peer_manager::{PeerManagerHostAdapters, PortablePeerManagerConfig},
            },
            proto::{common::StunInfo, peer_rpc::GetIpListResponse},
            proxy::wrapped_transport::{
                NoWrappedTransportEngineFactory, WrappedTransportEngine,
                WrappedTransportEngineBuild, WrappedTransportEngineFactory,
                WrappedTransportEngineStart, WrappedTransportRole,
            },
            runtime_config::CoreInstanceRuntimeConfig,
            socket::{
                SocketContext,
                dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
                tcp::{
                    TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose,
                    VirtualTcpListener, VirtualTcpListenerFactory, VirtualTcpSocket,
                    VirtualTcpSocketFactory,
                },
                udp::{
                    PreferredIpv6Source, UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory,
                },
            },
        };

        #[cfg(feature = "proxy-packet")]
        use crate::proxy::wrapped_transport::WrappedTransportKind;

        struct TestTcpSocket(tokio::io::DuplexStream);

        impl AsyncRead for TestTcpSocket {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(_cx, buf)
            }
        }

        impl AsyncWrite for TestTcpSocket {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                buf: &[u8],
            ) -> Poll<io::Result<usize>> {
                Pin::new(&mut self.get_mut().0).poll_write(_cx, buf)
            }

            fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_flush(cx)
            }

            fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
            }
        }

        impl VirtualTcpSocket for TestTcpSocket {
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:20000".parse().unwrap())
            }

            fn peer_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:20001".parse().unwrap())
            }
        }

        struct TestTcpListener(SocketAddr);

        #[async_trait]
        impl VirtualTcpListener for TestTcpListener {
            type Socket = TestTcpSocket;

            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok(self.0)
            }

            async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
                std::future::pending().await
            }
        }

        struct TestUdpSocket(SocketAddr);

        #[async_trait]
        impl VirtualUdpSocket for TestUdpSocket {
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok(self.0)
            }

            async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
                Ok(data.len())
            }

            async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
                std::future::pending().await
            }
        }

        #[derive(Default)]
        struct TestHost {
            proxy_nat_connections:
                Option<tokio::sync::mpsc::UnboundedSender<(SocketAddr, tokio::io::DuplexStream)>>,
            reject_socks5_listener: bool,
        }

        #[async_trait]
        impl VirtualTcpSocketFactory for TestHost {
            type Socket = TestTcpSocket;

            async fn connect_tcp(
                &self,
                options: TcpConnectOptions,
            ) -> anyhow::Result<Self::Socket> {
                if options.purpose != TcpSocketPurpose::ProxyNat {
                    anyhow::bail!("test host does not connect non-proxy TCP sockets");
                }
                let connections = self
                    .proxy_nat_connections
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("test host proxy NAT is disabled"))?;
                let (socket, peer) = tokio::io::duplex(1024);
                connections
                    .send((options.remote_addr, peer))
                    .map_err(|_| anyhow::anyhow!("test host proxy NAT receiver is closed"))?;
                Ok(TestTcpSocket(socket))
            }
        }

        #[async_trait]
        impl VirtualTcpListenerFactory for TestHost {
            type Listener = TestTcpListener;

            async fn bind_tcp(
                &self,
                options: TcpListenOptions,
            ) -> anyhow::Result<Arc<Self::Listener>> {
                if self.reject_socks5_listener && options.purpose == TcpListenPurpose::Socks5 {
                    anyhow::bail!("test host rejected SOCKS5 listener");
                }
                let address = options
                    .bind
                    .local_addr
                    .unwrap_or_else(|| "127.0.0.1:20000".parse().unwrap());
                Ok(Arc::new(TestTcpListener(address)))
            }
        }

        #[async_trait]
        impl VirtualUdpSocketFactory for TestHost {
            type Socket = TestUdpSocket;

            async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
                let address = options
                    .local_addr
                    .unwrap_or_else(|| "127.0.0.1:20002".parse().unwrap());
                Ok(Arc::new(TestUdpSocket(address)))
            }
        }

        #[async_trait]
        impl ManualConnectorHost for TestHost {
            async fn local_addr_for_remote(
                &self,
                remote_addr: SocketAddr,
                _context: SocketContext,
            ) -> anyhow::Result<SocketAddr> {
                Ok(match remote_addr {
                    SocketAddr::V4(_) => "127.0.0.1:0".parse().unwrap(),
                    SocketAddr::V6(_) => "[::1]:0".parse().unwrap(),
                })
            }

            async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs> {
                Ok(ManualInterfaceAddrs {
                    interface_ipv4s: vec![],
                    interface_ipv6s: vec![],
                    public_ipv6: None,
                })
            }
        }

        #[async_trait]
        impl DirectConnectorHost for TestHost {
            async fn collect_ip_addrs(&self, _context: &SocketContext) -> GetIpListResponse {
                GetIpListResponse::default()
            }

            fn mapped_listeners(&self) -> Vec<Url> {
                Vec::new()
            }

            fn is_local_ip(&self, _ip: &IpAddr) -> bool {
                false
            }

            fn is_protected_tcp_port(&self, _port: u16) -> bool {
                false
            }

            async fn preferred_ipv6_source(
                &self,
                _ip: Ipv6Addr,
                _context: SocketContext,
            ) -> Option<PreferredIpv6Source> {
                None
            }
        }

        struct TestDns;

        #[async_trait]
        impl DnsResolver for TestDns {
            async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
                Ok(query.host.parse().into_iter().collect())
            }
        }

        #[async_trait]
        impl DnsRecordResolver for TestDns {
            async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
                anyhow::bail!("test DNS has no TXT records")
            }

            async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
                Ok(Vec::new())
            }
        }

        fn test_config(network_name: &str) -> PortableCoreInstanceConfig {
            let mut core = CoreConfig::default();
            core.node.network_name = network_name.to_owned();
            core.peer_policy.encryption_required = false;
            let peer = PortablePeerManagerConfig::new(PeerRuntimeConfig {
                core,
                network_identity: NetworkIdentity {
                    network_name: network_name.to_owned(),
                    network_secret: Some(String::new()),
                    network_secret_digest: None,
                },
                stun_info: StunInfo::default(),
                feature_flags: Default::default(),
                secure_mode: None,
                host_routing: HostRoutingPolicy::default(),
            });
            let mut connectivity = CoreInstanceConfig::default();
            connectivity.direct.network_name = network_name.to_owned();
            connectivity.direct.lazy_p2p = peer.snapshot.flags.lazy_p2p;
            connectivity.direct.disable_p2p = peer.snapshot.flags.disable_p2p;
            connectivity.direct.need_p2p = peer.snapshot.flags.need_p2p;
            PortableCoreInstanceConfig { peer, connectivity }
        }

        fn runtime_snapshot(config: &PortableCoreInstanceConfig) -> CoreInstanceRuntimeConfig {
            CoreInstanceRuntimeConfig {
                services: config.connectivity.runtime.clone(),
                peer: Arc::new(config.peer.snapshot.clone()),
            }
        }

        fn proxy_network(real: &str, mapped: Option<&str>) -> ProxyNetworkConfig {
            fn prefix(value: &str) -> IpPrefix {
                let (address, prefix_len) = value.split_once('/').unwrap();
                IpPrefix {
                    address: address.parse().unwrap(),
                    prefix_len: prefix_len.parse().unwrap(),
                }
            }

            ProxyNetworkConfig {
                real: prefix(real),
                mapped: mapped.map(prefix),
            }
        }

        fn adapters(
            external_listener_factory: Option<
                Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
            >,
        ) -> CoreInstanceAdapters<TestHost> {
            adapters_with_host(Arc::new(TestHost::default()), external_listener_factory)
        }

        fn adapters_with_host(
            host: Arc<TestHost>,
            external_listener_factory: Option<
                Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
            >,
        ) -> CoreInstanceAdapters<TestHost> {
            let dns = Arc::new(TestDns);
            CoreInstanceAdapters {
                host,
                stun_projection: None,
                dns: dns.clone(),
                listener_dns: None,
                dns_records: dns,
                process_runtime: CoreProcessRuntime::new(),
                protocol: None,
                manual_events: None,
                external_listener_factory,
                listener_events: None,
                server_protocol: None,
                accepted_tunnel_events: None,
                udp_hole_punch_platform: None,
                udp_hole_punch_events: None,
                #[cfg(feature = "proxy-packet")]
                icmp_proxy_host: None,
                proxy_cidr_monitor: None,
                public_ipv6_host: None,
                public_ipv6_provider: None,
                vpn_portal: None,
                vpn_portal_events: None,
                #[cfg(feature = "proxy-smoltcp-stack")]
                gateway_events: None,
            }
        }

        fn build_with_factory<F>(
            config: PortableCoreInstanceConfig,
            factory: F,
        ) -> anyhow::Result<(Arc<CoreInstance<TestHost>>, F::Attachment)>
        where
            F: WrappedTransportEngineFactory,
        {
            build_with_factory_and_listener(config, factory, None)
        }

        fn build_with_factory_and_listener<F>(
            config: PortableCoreInstanceConfig,
            factory: F,
            external_listener_factory: Option<
                Arc<dyn ExternalListenerFactory<AcceptedTransport<TestTcpSocket>>>,
            >,
        ) -> anyhow::Result<(Arc<CoreInstance<TestHost>>, F::Attachment)>
        where
            F: WrappedTransportEngineFactory,
        {
            let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
            CoreInstance::new_portable_with_peer_adapters_and_transport_factory(
                adapters(external_listener_factory),
                PeerManagerHostAdapters::default(),
                config,
                Arc::new(packet_sink),
                factory,
            )
            .map(|(instance, attachment)| (Arc::new(instance), attachment))
        }

        fn build_instance(
            config: PortableCoreInstanceConfig,
        ) -> anyhow::Result<Arc<CoreInstance<TestHost>>> {
            build_with_factory(config, NoWrappedTransportEngineFactory)
                .map(|(instance, ())| instance)
        }

        #[derive(Default)]
        struct RecordingProxyService {
            start_calls: AtomicUsize,
            stop_calls: AtomicUsize,
            start_gate: Option<Arc<ProxyStartGate>>,
            #[cfg(feature = "proxy-packet")]
            destination_ingress: StdMutex<
                Option<crate::proxy::wrapped_transport::WrappedTransportDestinationIngress>,
            >,
        }

        #[derive(Default)]
        struct ProxyStartGate {
            entered: Notify,
            release: Notify,
        }

        impl RecordingProxyService {
            fn blocking() -> (Arc<Self>, Arc<ProxyStartGate>) {
                let gate = Arc::new(ProxyStartGate::default());
                (
                    Arc::new(Self {
                        start_gate: Some(gate.clone()),
                        ..Default::default()
                    }),
                    gate,
                )
            }

            #[cfg(feature = "proxy-packet")]
            fn destination_ingress(
                &self,
            ) -> Option<crate::proxy::wrapped_transport::WrappedTransportDestinationIngress>
            {
                self.destination_ingress.lock().unwrap().clone()
            }
        }

        #[async_trait]
        impl WrappedTransportEngine for RecordingProxyService {
            async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
                self.start_calls.fetch_add(1, Ordering::Relaxed);
                #[cfg(feature = "proxy-packet")]
                {
                    *self.destination_ingress.lock().unwrap() = options.destination_ingress;
                }
                #[cfg(not(feature = "proxy-packet"))]
                let _ = options;
                if let Some(gate) = &self.start_gate {
                    gate.entered.notify_one();
                    gate.release.notified().await;
                }
                Ok(())
            }

            async fn activate(&self) -> anyhow::Result<()> {
                Ok(())
            }

            async fn inject_peer_datagram(
                &self,
                _role: WrappedTransportRole,
                _from_peer_id: u32,
                _payload: bytes::Bytes,
            ) -> anyhow::Result<()> {
                Ok(())
            }

            #[cfg(feature = "proxy-packet")]
            async fn connect_source(
                &self,
                _request: crate::proxy::wrapped_transport::WrappedTransportConnect,
            ) -> anyhow::Result<Box<dyn crate::proxy::runtime::TcpProxyStream>> {
                anyhow::bail!("recording engine does not open streams")
            }

            async fn stop(&self) {
                self.stop_calls.fetch_add(1, Ordering::Relaxed);
            }
        }

        struct TestTransportProxyFactory {
            service: Arc<dyn WrappedTransportEngine>,
        }

        impl WrappedTransportEngineFactory for TestTransportProxyFactory {
            type Attachment = ();

            fn build(self) -> anyhow::Result<WrappedTransportEngineBuild<Self::Attachment>> {
                Ok(WrappedTransportEngineBuild {
                    kcp: Some(self.service),
                    quic: None,
                    attachment: (),
                })
            }
        }

        #[derive(Debug, Default)]
        struct BlockingListenerState {
            start_entered: Notify,
            drop_calls: AtomicUsize,
        }

        #[derive(Debug)]
        struct BlockingSocketListener {
            url: Url,
            state: Arc<BlockingListenerState>,
        }

        #[async_trait]
        impl SocketListener for BlockingSocketListener {
            type Accepted = AcceptedTransport<TestTcpSocket>;

            async fn listen(&mut self) -> anyhow::Result<()> {
                self.state.start_entered.notify_one();
                std::future::pending().await
            }

            async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
                std::future::pending().await
            }

            fn local_url(&self) -> Url {
                self.url.clone()
            }
        }

        impl Drop for BlockingSocketListener {
            fn drop(&mut self) {
                self.state.drop_calls.fetch_add(1, Ordering::Relaxed);
            }
        }

        struct BlockingExternalListenerFactory {
            state: Arc<BlockingListenerState>,
        }

        impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for BlockingExternalListenerFactory {
            fn supports_scheme(&self, scheme: &str) -> bool {
                scheme == "unix"
            }

            fn create(
                &self,
                request: ExternalListenerRequest,
            ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
                Box::new(BlockingSocketListener {
                    url: request.url,
                    state: self.state.clone(),
                })
            }
        }

        #[derive(Debug)]
        struct ReadySocketListener(Url);

        #[async_trait]
        impl SocketListener for ReadySocketListener {
            type Accepted = AcceptedTransport<TestTcpSocket>;

            async fn listen(&mut self) -> anyhow::Result<()> {
                Ok(())
            }

            async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
                std::future::pending().await
            }

            fn local_url(&self) -> Url {
                self.0.clone()
            }
        }

        struct ReadyExternalListenerFactory;

        impl ExternalListenerFactory<AcceptedTransport<TestTcpSocket>> for ReadyExternalListenerFactory {
            fn supports_scheme(&self, scheme: &str) -> bool {
                scheme == "unix"
            }

            fn create(
                &self,
                request: ExternalListenerRequest,
            ) -> Box<dyn SocketListener<Accepted = AcceptedTransport<TestTcpSocket>>> {
                Box::new(ReadySocketListener(request.url))
            }
        }

        #[tokio::test]
        async fn runtime_updates_refresh_avoid_relay_preference() {
            let config = test_config("portable-runtime-update");
            let instance = build_instance(config.clone()).unwrap();

            assert!(
                !instance
                    .node_snapshot()
                    .await
                    .feature_flags
                    .avoid_relay_data
            );

            let mut enabled = Arc::new(config.peer.snapshot.clone());
            Arc::make_mut(&mut enabled).avoid_relay_data_preference = true;
            instance.update_peer_runtime_snapshot(enabled).await;
            assert!(
                instance
                    .node_snapshot()
                    .await
                    .feature_flags
                    .avoid_relay_data
            );

            let mut disabled = runtime_snapshot(&config);
            Arc::make_mut(&mut disabled.peer).avoid_relay_data_preference = false;
            instance.update_runtime_config(disabled).await.unwrap();
            assert!(
                !instance
                    .node_snapshot()
                    .await
                    .feature_flags
                    .avoid_relay_data
            );
        }

        #[cfg(feature = "test-utils")]
        #[cfg_attr(
            not(target_os = "wasi"),
            tokio::test(flavor = "multi_thread", worker_threads = 2)
        )]
        #[cfg_attr(target_os = "wasi", tokio::test)]
        async fn concurrent_runtime_updates_keep_snapshot_and_derived_state_coherent() {
            let config = test_config("concurrent-runtime-update");
            let instance = build_instance(config.clone()).unwrap();
            instance.start().await.unwrap();
            instance.start_network_services(None).await.unwrap();

            let original = instance.node_snapshot().await;
            let mut full = runtime_snapshot(&config);
            full.services.dhcp_ipv4 = true;
            full.services.acl.tcp_whitelist = vec!["80".to_owned()];
            {
                let peer = Arc::make_mut(&mut full.peer);
                peer.runtime.core.node.hostname = Some("full".to_owned());
                peer.runtime.core.routes.proxy_networks =
                    vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
            }
            let mut peer_only = Arc::new(config.peer.snapshot.clone());
            {
                let peer = Arc::make_mut(&mut peer_only);
                peer.runtime.core.node.hostname = Some("peer".to_owned());
                peer.runtime.core.routes.proxy_networks =
                    vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];
            }

            let start = Arc::new(tokio::sync::Barrier::new(3));
            let full_update = tokio::spawn({
                let instance = instance.clone();
                let start = start.clone();
                async move {
                    start.wait().await;
                    instance.update_runtime_config(full).await
                }
            });
            let peer_update = tokio::spawn({
                let instance = instance.clone();
                let start = start.clone();
                async move {
                    start.wait().await;
                    instance.update_peer_runtime_snapshot(peer_only).await;
                }
            });
            start.wait().await;
            full_update.await.unwrap().unwrap();
            peer_update.await.unwrap();

            assert!(instance.runtime_config_snapshot().dhcp_ipv4);
            assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["80"]);
            assert_eq!(instance.acl_reload_count_for_test(), 1);
            let node = instance.node_snapshot().await;
            assert_eq!(node.peer_id, original.peer_id);
            assert_eq!(node.instance_id, original.instance_id);
            match node.hostname.as_str() {
                "full" => assert_eq!(
                    instance.proxy_cidr_lookup_for_test("198.51.100.42".parse().unwrap()),
                    Some("192.0.2.42".parse().unwrap())
                ),
                "peer" => assert_eq!(
                    instance.proxy_cidr_lookup_for_test("10.20.30.42".parse().unwrap()),
                    Some("203.0.113.42".parse().unwrap())
                ),
                hostname => panic!("unexpected final hostname: {hostname:?}"),
            }

            instance.stop().await;
        }

        #[cfg(feature = "test-utils")]
        #[tokio::test]
        async fn active_runtime_update_skips_unchanged_and_rejects_invalid_acl() {
            let config = test_config("invalid-active-acl-update");
            let instance = build_instance(config.clone()).unwrap();
            instance.start().await.unwrap();
            instance.start_network_services(None).await.unwrap();

            let mut unrelated = runtime_snapshot(&config);
            Arc::make_mut(&mut unrelated.peer)
                .runtime
                .core
                .node
                .hostname = Some("accepted".to_owned());
            instance.update_runtime_config(unrelated).await.unwrap();
            assert_eq!(instance.acl_reload_count_for_test(), 0);
            let before = instance.node_snapshot().await;

            let mut rejected = runtime_snapshot(&config);
            rejected.services.dhcp_ipv4 = true;
            rejected.services.acl.tcp_whitelist = vec!["invalid".to_owned()];
            Arc::make_mut(&mut rejected.peer).runtime.core.node.hostname =
                Some("rejected".to_owned());

            let error = instance.update_runtime_config(rejected).await.unwrap_err();
            assert!(error.to_string().contains("Invalid port number"));
            assert!(!instance.runtime_config_snapshot().dhcp_ipv4);
            assert!(instance.acl_whitelist_snapshot().tcp_ports.is_empty());
            assert_eq!(instance.acl_reload_count_for_test(), 0);
            assert_eq!(instance.node_snapshot().await.hostname, before.hostname);
            instance.stop().await;
        }

        #[cfg(feature = "proxy-packet")]
        #[tokio::test]
        async fn runtime_core_instance_owns_connectivity_lifecycle() {
            let mut config = test_config("connectivity-lifecycle");
            config.peer.snapshot.runtime.core.routes.proxy_networks =
                vec![proxy_network("10.1.2.0/24", None)];
            let initial_peer: Url = "tcp://127.0.0.1:29999".parse().unwrap();
            config.connectivity.initial_peers = vec![initial_peer.clone()];
            let proxy = Arc::new(RecordingProxyService::default());
            let (instance, ()) = build_with_factory(
                config,
                TestTransportProxyFactory {
                    service: proxy.clone(),
                },
            )
            .unwrap();

            assert_eq!(instance.state(), CoreInstanceState::Created);
            assert!(instance.list_connectors().is_empty());
            assert!(instance.start_transport_proxy().await.is_err());
            assert!(instance.start_network_services(None).await.is_err());
            assert!(instance.start_proxy().await.is_err());
            assert!(instance.start_peer_center().await.is_err());
            instance.start().await.unwrap();
            assert_eq!(instance.state(), CoreInstanceState::Running);
            assert!(instance.list_connectors().is_empty());
            assert!(instance.start_initial_peers().await.is_err());
            assert!(instance.start().await.is_err());
            instance.start_after_host_ready(None).await.unwrap();
            instance.start_after_host_ready(None).await.unwrap();
            assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
            assert_eq!(instance.list_connectors().len(), 1);
            assert_eq!(instance.list_connectors()[0].url, initial_peer);
            assert!(instance.proxy_is_started());

            instance.stop().await;
            instance.stop().await;
            assert_eq!(instance.state(), CoreInstanceState::Stopped);
            assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
            assert!(!instance.proxy_is_started());
        }

        #[cfg(feature = "proxy-smoltcp-stack")]
        #[tokio::test]
        async fn startup_plan_controls_gateway_for_initial_and_updated_config() {
            fn build(config: PortableCoreInstanceConfig) -> Arc<CoreInstance<TestHost>> {
                let host = Arc::new(TestHost {
                    reject_socks5_listener: true,
                    ..Default::default()
                });
                let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
                Arc::new(
                    CoreInstance::new_portable(
                        adapters_with_host(host, None),
                        config,
                        Arc::new(packet_sink),
                    )
                    .unwrap(),
                )
            }

            let mut enabled_config = test_config("gateway-enabled-by-default");
            enabled_config.connectivity.runtime.gateway.socks5_bind =
                Some("127.0.0.1:1080".parse().unwrap());
            let enabled = build(enabled_config);
            enabled.start().await.unwrap();
            let error = enabled.start_after_host_ready(None).await.unwrap_err();
            assert!(error.to_string().contains("rejected SOCKS5 listener"));
            assert_eq!(enabled.state(), CoreInstanceState::Stopped);

            let mut disabled_config = test_config("gateway-disabled-by-plan");
            disabled_config.connectivity.startup_plan.gateway = false;
            let disabled = build(disabled_config.clone());
            let mut updated = runtime_snapshot(&disabled_config);
            updated.services.gateway.socks5_bind = Some("127.0.0.1:1080".parse().unwrap());
            disabled.update_runtime_config(updated).await.unwrap();
            disabled.start().await.unwrap();
            disabled.start_after_host_ready(None).await.unwrap();
            assert_eq!(disabled.state(), CoreInstanceState::Running);
            disabled.stop().await;
        }

        #[cfg(feature = "proxy-packet")]
        #[tokio::test]
        async fn runtime_core_instance_owns_wrapped_transport_source_nat() {
            let mut config = test_config("wrapped-source");
            config.peer.snapshot.flags.enable_kcp_proxy = true;
            config.peer.snapshot.flags.disable_kcp_input = true;
            let engine = Arc::new(RecordingProxyService::default());
            let (instance, ()) = build_with_factory(
                config,
                TestTransportProxyFactory {
                    service: engine.clone(),
                },
            )
            .unwrap();

            instance.start().await.unwrap();
            instance.start_network_services(None).await.unwrap();
            assert!(instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            ));
            assert!(
                instance
                    .wrapped_tcp_proxy_entry_snapshots(
                        WrappedTransportKind::Kcp,
                        WrappedTransportRole::Source,
                    )
                    .is_empty()
            );

            instance.stop().await;
            assert!(!instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Source,
            ));
            assert_eq!(engine.stop_calls.load(Ordering::Relaxed), 1);
        }

        #[cfg(feature = "proxy-packet")]
        #[tokio::test]
        async fn runtime_core_instance_owns_wrapped_transport_destination_sessions() {
            let mut config = test_config("wrapped-destination");
            config.peer.snapshot.flags.enable_kcp_proxy = false;
            config.peer.snapshot.flags.disable_kcp_input = false;
            let engine = Arc::new(RecordingProxyService::default());
            let (connections, mut connection_receiver) = tokio::sync::mpsc::unbounded_channel();
            let host = Arc::new(TestHost {
                proxy_nat_connections: Some(connections),
                ..Default::default()
            });
            let (packet_sink, _packet_receiver) = tokio::sync::mpsc::channel(16);
            let (instance, ()) =
                CoreInstance::new_portable_with_peer_adapters_and_transport_factory(
                    adapters_with_host(host, None),
                    PeerManagerHostAdapters::default(),
                    config,
                    Arc::new(packet_sink),
                    TestTransportProxyFactory {
                        service: engine.clone(),
                    },
                )
                .unwrap();
            let instance = Arc::new(instance);

            instance.start().await.unwrap();
            instance.start_network_services(None).await.unwrap();
            assert!(instance.wrapped_transport_is_started(
                WrappedTransportKind::Kcp,
                WrappedTransportRole::Destination,
            ));

            let destination: SocketAddr = "127.0.0.1:20100".parse().unwrap();
            let ingress = engine
                .destination_ingress()
                .expect("core should inject a destination ingress");
            let (core_stream, peer_stream) = tokio::io::duplex(1024);
            ingress
                .submit(
                    crate::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                        src: "10.0.0.2:40000".parse().unwrap(),
                        dst: destination,
                        initial_acl_packet_size: 16,
                        stream: Box::new(core_stream),
                    },
                )
                .await
                .unwrap();
            let (connected_destination, destination_stream) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection_receiver.recv(),
            )
            .await
            .expect("core should request the destination socket")
            .unwrap();
            assert_eq!(connected_destination, destination);
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                loop {
                    let entries = instance.wrapped_tcp_proxy_entry_snapshots(
                        WrappedTransportKind::Kcp,
                        WrappedTransportRole::Destination,
                    );
                    if entries.iter().any(|entry| {
                        entry.state == crate::proxy::tcp_proxy_engine::TcpNatEntryState::Connected
                    }) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("core should own the connected destination entry");

            drop(peer_stream);
            drop(destination_stream);
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while !instance
                    .wrapped_tcp_proxy_entry_snapshots(
                        WrappedTransportKind::Kcp,
                        WrappedTransportRole::Destination,
                    )
                    .is_empty()
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("completed destination entry should be removed");

            let (core_stream, _blocked_peer_stream) = tokio::io::duplex(1024);
            ingress
                .submit(
                    crate::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                        src: "10.0.0.2:40001".parse().unwrap(),
                        dst: destination,
                        initial_acl_packet_size: 16,
                        stream: Box::new(core_stream),
                    },
                )
                .await
                .unwrap();
            let (connected_destination, _blocked_destination_stream) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                connection_receiver.recv(),
            )
            .await
            .expect("second destination session should request a socket")
            .unwrap();
            assert_eq!(connected_destination, destination);
            tokio::time::timeout(std::time::Duration::from_secs(2), async {
                while instance
                    .wrapped_tcp_proxy_entry_snapshots(
                        WrappedTransportKind::Kcp,
                        WrappedTransportRole::Destination,
                    )
                    .is_empty()
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("blocked destination session should be visible");

            tokio::time::timeout(std::time::Duration::from_secs(2), instance.stop())
                .await
                .expect("stop should cancel core-owned destination sessions");
            assert!(
                instance
                    .wrapped_tcp_proxy_entry_snapshots(
                        WrappedTransportKind::Kcp,
                        WrappedTransportRole::Destination,
                    )
                    .is_empty()
            );
            assert!(
                ingress
                    .submit(
                        crate::proxy::wrapped_transport::WrappedTransportAcceptedStream {
                            src: "10.0.0.2:40002".parse().unwrap(),
                            dst: destination,
                            initial_acl_packet_size: 16,
                            stream: Box::new(tokio::io::duplex(64).0),
                        },
                    )
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn runtime_core_instance_owns_the_transport_proxy_cidr_table() {
            let mut config = test_config("transport-proxy-cidr");
            config.peer.snapshot.runtime.core.routes.proxy_networks =
                vec![proxy_network("192.0.2.0/24", Some("198.51.100.0/24"))];
            let mut updated = runtime_snapshot(&config);
            let proxy = Arc::new(RecordingProxyService::default());
            let (instance, ()) = build_with_factory(
                config,
                TestTransportProxyFactory {
                    service: proxy.clone(),
                },
            )
            .unwrap();

            assert!(instance.start_network_services(None).await.is_err());
            assert_eq!(instance.node_snapshot().await.proxy_networks.len(), 1);
            instance.start().await.unwrap();
            instance.start_network_services(None).await.unwrap();
            instance.start_network_services(None).await.unwrap();
            assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

            Arc::make_mut(&mut updated.peer)
                .runtime
                .core
                .routes
                .proxy_networks = vec![proxy_network("203.0.113.0/24", Some("10.20.30.0/24"))];
            instance.update_runtime_config(updated).await.unwrap();
            let proxy_networks = instance.node_snapshot().await.proxy_networks;
            assert_eq!(proxy_networks.len(), 1);
            assert_eq!(
                proxy_networks[0].real.address,
                "203.0.113.0".parse::<IpAddr>().unwrap()
            );
            assert_eq!(
                proxy_networks[0].mapped.as_ref().unwrap().address,
                "10.20.30.0".parse::<IpAddr>().unwrap()
            );

            instance.stop().await;
            assert!(instance.start_network_services(None).await.is_err());
            assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn runtime_core_accepts_explicit_acl_runtime_snapshot() {
            let config = test_config("explicit-acl");
            let instance = build_instance(config.clone()).unwrap();
            assert_eq!(instance.acl_whitelist_snapshot(), Default::default());

            let mut updated = runtime_snapshot(&config);
            updated.services.acl.tcp_whitelist = vec!["invalid".to_owned()];
            instance.update_runtime_config(updated).await.unwrap();
            instance.start().await.unwrap();
            let error = instance.start_network_services(None).await.unwrap_err();
            assert!(error.to_string().contains("Invalid port number"));
            assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["invalid"]);
            instance.stop().await;
        }

        #[tokio::test]
        async fn runtime_core_accepts_explicit_dhcp_runtime_snapshot() {
            let config = test_config("explicit-dhcp");
            let instance = build_instance(config.clone()).unwrap();
            let mut updated = runtime_snapshot(&config);
            updated.services.dhcp_ipv4 = true;
            instance.update_runtime_config(updated).await.unwrap();
            instance.start().await.unwrap();
            let error = instance.start_after_host_ready(None).await.unwrap_err();
            assert!(error.to_string().contains("no host adapter was provided"));
            assert_eq!(instance.state(), CoreInstanceState::Stopped);
        }

        #[tokio::test]
        async fn runtime_core_accepts_explicit_public_ipv6_runtime_snapshot() {
            let config = test_config("explicit-public-ipv6");
            let instance = build_instance(config.clone()).unwrap();
            let mut updated = runtime_snapshot(&config);
            updated.services.public_ipv6_provider.provider_enabled = true;
            updated.services.public_ipv6_provider.provider_supported = true;
            updated.services.public_ipv6_provider.configured_prefix =
                Some("fd00::/64".parse().unwrap());
            instance.update_runtime_config(updated).await.unwrap();

            let error = instance.start().await.unwrap_err();
            assert!(error.to_string().contains("not a valid global unicast"));
            assert_eq!(instance.state(), CoreInstanceState::Created);
        }

        #[tokio::test]
        async fn stopping_while_transport_proxy_starts_rolls_back_once() {
            let mut config = test_config("blocking-transport-proxy");
            config.peer.snapshot.runtime.core.routes.proxy_networks =
                vec![proxy_network("10.1.2.0/24", None)];
            config.connectivity.initial_peers = vec!["tcp://127.0.0.1:29998".parse().unwrap()];
            let (proxy, start_gate) = RecordingProxyService::blocking();
            let (instance, ()) = build_with_factory(
                config,
                TestTransportProxyFactory {
                    service: proxy.clone(),
                },
            )
            .unwrap();
            instance.start().await.unwrap();
            instance.start_peer_center().await.unwrap();

            let start_task = tokio::spawn({
                let instance = instance.clone();
                async move { instance.start_transport_proxy().await }
            });
            start_gate.entered.notified().await;
            let initial_peer_task = tokio::spawn({
                let instance = instance.clone();
                async move { instance.start_initial_peers().await }
            });
            tokio::task::yield_now().await;
            let stop_task = tokio::spawn({
                let instance = instance.clone();
                async move { instance.stop().await }
            });
            tokio::task::yield_now().await;
            start_gate.release.notify_one();

            assert!(start_task.await.unwrap().is_err());
            assert!(initial_peer_task.await.unwrap().is_err());
            stop_task.await.unwrap();
            assert!(instance.list_connectors().is_empty());
            assert_eq!(instance.state(), CoreInstanceState::Stopped);
            assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);
            assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn invalid_initial_peer_fails_during_activation() {
            let mut config = test_config("invalid-initial-peer");
            config.connectivity.initial_peers =
                vec!["unsupported://peer.example:1234".parse().unwrap()];
            let instance = build_instance(config).unwrap();

            instance.start().await.unwrap();
            instance.start_peer_center().await.unwrap();
            let error = instance.start_initial_peers().await.unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("unsupported core manual connector URL")
            );
            instance.stop().await;
        }

        #[test]
        fn portable_core_instance_rejects_conflicting_p2p_policy() {
            let mut config = test_config("conflicting-p2p");
            config.connectivity.direct.disable_p2p = !config.peer.snapshot.flags.disable_p2p;

            let error = build_instance(config)
                .err()
                .expect("conflicting P2P policy should be rejected");
            assert!(error.to_string().contains("P2P policy"));
        }

        #[tokio::test]
        async fn runtime_core_instances_keep_lifecycle_and_connectors_isolated() {
            let instance_a = build_instance(test_config("instance-a")).unwrap();
            let instance_b = build_instance(test_config("instance-b")).unwrap();
            let connector_a: Url = "tcp://127.0.0.1:21001".parse().unwrap();
            let connector_b: Url = "udp://127.0.0.1:21002".parse().unwrap();

            instance_a.add_connector(connector_a.clone()).unwrap();
            instance_b.add_connector(connector_b.clone()).unwrap();
            assert_eq!(instance_a.list_connectors()[0].url, connector_a);
            assert_eq!(instance_b.list_connectors()[0].url, connector_b);
            instance_a.clear_connectors();
            instance_b.clear_connectors();

            let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
            start_a.unwrap();
            start_b.unwrap();
            let (udp_a, udp_b) = tokio::join!(
                instance_a.start_udp_hole_punch(),
                instance_b.start_udp_hole_punch()
            );
            udp_a.unwrap();
            udp_b.unwrap();
            assert_eq!(instance_a.state(), CoreInstanceState::Running);
            assert_eq!(instance_b.state(), CoreInstanceState::Running);

            instance_a.stop().await;
            assert_eq!(instance_a.state(), CoreInstanceState::Stopped);
            assert_eq!(instance_b.state(), CoreInstanceState::Running);
            instance_b.stop().await;
            assert_eq!(instance_b.state(), CoreInstanceState::Stopped);
        }

        #[cfg(unix)]
        #[tokio::test]
        async fn stop_cancels_pending_listener_start() {
            let state = Arc::new(BlockingListenerState::default());
            let mut config = test_config("pending-listener");
            config.connectivity.listeners = Some(ListenerRuntimeConfig::new(
                vec!["unix:///tmp/easytier-pending-listener".parse().unwrap()],
                false,
                SocketContext::default(),
            ));
            let (instance, ()) = build_with_factory_and_listener(
                config,
                NoWrappedTransportEngineFactory,
                Some(Arc::new(BlockingExternalListenerFactory {
                    state: state.clone(),
                })),
            )
            .unwrap();
            let start_instance = instance.clone();
            let start_task =
                AbortOnDropHandle::new(tokio::spawn(async move { start_instance.start().await }));
            let start_result = tokio::time::timeout(Duration::from_secs(1), async {
                state.start_entered.notified().await;
                instance.stop().await;
                start_task.await.unwrap()
            })
            .await
            .expect("listener cancellation should complete promptly");

            assert!(start_result.is_err());
            assert_eq!(instance.state(), CoreInstanceState::Stopped);
            assert_eq!(state.drop_calls.load(Ordering::Relaxed), 1);
        }

        #[tokio::test]
        async fn external_listener_uses_core_running_listener_registry() {
            let external_url: Url = "unix:///tmp/easytier-external-listener-test"
                .parse()
                .unwrap();
            let mut config = test_config("external-listener-registry");
            config.connectivity.listeners = Some(ListenerRuntimeConfig::new(
                vec![external_url.clone()],
                false,
                SocketContext::default(),
            ));
            let (instance, ()) = build_with_factory_and_listener(
                config,
                NoWrappedTransportEngineFactory,
                Some(Arc::new(ReadyExternalListenerFactory)),
            )
            .unwrap();

            instance.start().await.unwrap();
            let running = instance.running_listeners();
            assert_eq!(running.len(), 2);
            assert!(running.iter().any(|url| url.scheme() == "ring"));
            assert!(running.contains(&external_url));
            assert_eq!(instance.node_snapshot().await.listeners, running);

            instance.stop().await;
            assert!(instance.running_listeners().is_empty());
        }
    }
}

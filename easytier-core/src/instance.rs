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
    udp_hole_punch::{CoreUdpHolePunchService, UdpHolePunchPlatform},
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInstanceConfig {
    pub initial_peers: Vec<Url>,
    pub listeners: Option<ListenerRuntimeConfig>,
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
            listeners: None,
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
            ListenerKind::TcpStream => transports.push(TransportListenerConfig::Tcp {
                url: listener.url,
                options: crate::listener::plan::unresolved_tcp_listener_options(
                    config.socket_context.clone(),
                ),
                must_succeed,
            }),
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
    /// Optional stable projection used by native services and test overrides.
    /// Core installs its collector only when the slot is empty.
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
    pub udp_hole_punch_platform: Option<Arc<dyn UdpHolePunchPlatform>>,
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
        mut config: PortableCoreInstanceConfig,
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
        config
            .peer
            .snapshot
            .set_acl_groups(config.connectivity.runtime.acl.acl.as_ref());
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
            udp_hole_punch_platform.unwrap_or_else(|| Arc::new(())),
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
        self.start_vpn_portal().await?;
        Ok(())
    }

    pub async fn start_vpn_portal(self: &Arc<Self>) -> anyhow::Result<()> {
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
    pub async fn start_gateway(self: &Arc<Self>) -> anyhow::Result<()> {
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
    pub async fn start_gateway(self: &Arc<Self>) -> anyhow::Result<()> {
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
}

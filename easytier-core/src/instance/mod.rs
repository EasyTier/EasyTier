//! Lifecycle owner for the portable EasyTier runtime.

mod management;
mod packet_io;
mod packet_plane;
#[cfg(any(test, target_os = "wasi"))]
mod wasi;

#[cfg(any(test, target_os = "wasi"))]
mod runtime_driver;

use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, AtomicU8, Ordering},
};

use serde::{Deserialize, Serialize};
#[cfg(feature = "test-utils")]
use std::sync::atomic::AtomicUsize;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfig, CoreRuntimeConfigStore},
    connectivity::hole_punch::port_mapping::{UdpPortMappingEventSink, UdpPortMappingPlatform},
    connectivity::hole_punch::tcp::{TcpHolePunchConnector, TcpHolePunchHost},
    connectivity::stun::{
        StunDnsRuntime, StunInfoCollector, StunInfoProvider, StunServerConfig, StunSocketMapper,
    },
    connectivity::{
        direct::{
            DirectConnectorHost, DirectConnectorManager, DirectConnectorOptions,
            ForeignDirectConnectorRpcRegistrar,
        },
        hole_punch::udp::CoreUdpHolePunchService,
        manual::{
            ManualConnectivityEventSink, ManualConnectorManager, ManualConnectorOptions,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::{
            ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader,
            CoreServerProtocolConfig, CoreServerProtocolUpgrader, ServerProtocolUpgrader,
        },
    },
    gateway::dhcp::{DhcpIpv4Host, DhcpIpv4RouteSource, DhcpIpv4Service},
    gateway::proxy::{
        cidr_monitor::{ProxyCidrMonitor, ProxyCidrMonitorHost},
        cidr_table::{ProxyCidrSnapshot, ProxyCidrTable},
        wrapped_transport::{WrappedTransportEngines, WrappedTransportProxyModule},
    },
    gateway::vpn_portal::{
        VpnPortalEventSink, VpnPortalHost, VpnPortalInfoSnapshot, VpnPortalModule,
    },
    host::dns::{DnsRecordResolver, DnsResolver},
    listener::{
        AcceptedSocketHandler, ExternalListenerFactory, ExternalListenerRequest, ListenerEventSink,
        ListenerEventSinkGroup, ListenerFactory, RunningListenerRegistry,
        plan::{ListenerRuntimeConfig, PreparedListenerPlan, prepare_listener_plan},
        transport::{
            AcceptedTransport, AcceptedTunnelEventSink, CoreListenerRuntime, HostAcceptedTcpSocket,
            PeerAcceptedTunnelHandler, ProtocolAcceptedTransportHandler,
            RawAcceptedTransportHandler,
        },
    },
    peers::peer_center::instance::PeerCenterInstance,
    peers::{
        acl_config::AclRuleConfig,
        context::{PeerRuntimeSnapshot, PeerStunInfoSource},
        create_packet_recv_chan,
        peer_manager::{PeerManagerCore, PeerManagerHostAdapters, PortablePeerManagerConfig},
        public_ipv6::{CorePublicIpv6Runtime, PublicIpv6Host},
    },
    process_runtime::CoreProcessRuntime,
    socket::{tcp::VirtualTcpSocketFactory, udp::VirtualUdpSocketFactory},
};

#[cfg(feature = "proxy-smoltcp-stack")]
use crate::gateway::{GatewayEventSink, GatewayModule};

#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::{runtime::IcmpProxyHost, service::CoreProxyModule};
use crate::peers::public_ipv6::provider::{PublicIpv6ProviderPlatform, PublicIpv6ProviderService};

use crate::host::packet::PacketSink;
use packet_io::PacketEgress;
pub use packet_plane::CorePacketPlane;

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
pub struct CoreConnectivityConfig {
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

impl Default for CoreConnectivityConfig {
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
pub struct CoreInstanceConfig {
    pub peer: PortablePeerManagerConfig,
    pub connectivity: CoreConnectivityConfig,
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRelaySessionSnapshot {
    pub has_state: bool,
    pub has_session: bool,
}

fn validate_core_instance_config(config: &CoreInstanceConfig) -> anyhow::Result<()> {
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

/// Host Adapters and optional native capabilities for one core instance.
///
/// Callers provide this bundle and one normalized [`CoreInstanceConfig`] to
/// [`CoreInstance::new`]. Core constructs and owns every portable runtime
/// Module behind that seam.
pub struct CoreHostAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    host: Arc<H>,
    #[cfg(any(test, feature = "test-utils"))]
    /// Optional construction-time STUN provider used by deterministic tests.
    stun_override: Option<Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>>,
    dns: Arc<dyn StunDnsRuntime>,
    process_runtime: Arc<CoreProcessRuntime>,
    packet_sink: Arc<dyn PacketSink>,
    pub peer_adapters: PeerManagerHostAdapters,
    pub wrapped_transports: WrappedTransportEngines,
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

impl<H> CoreHostAdapters<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    /// Creates the minimal host bundle. Optional native capabilities can be
    /// installed on the returned value before constructing the instance.
    pub fn new(
        host: Arc<H>,
        dns: Arc<dyn StunDnsRuntime>,
        packet_sink: Arc<dyn PacketSink>,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> Self {
        Self {
            host,
            #[cfg(any(test, feature = "test-utils"))]
            stun_override: None,
            dns,
            process_runtime,
            packet_sink,
            peer_adapters: PeerManagerHostAdapters::default(),
            wrapped_transports: WrappedTransportEngines::default(),
            protocol: None,
            manual_events: None,
            external_listener_factory: None,
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
}

struct CoreStunPeerInfoSource(Arc<dyn StunInfoProvider>);

impl PeerStunInfoSource for CoreStunPeerInfoSource {
    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.0.get_stun_info()
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
    packet_plane: Arc<CorePacketPlane>,
    manual: ManualConnectorManager<H>,
    direct: DirectConnectorManager<H>,
    tcp_hole_punch: TcpHolePunchConnector<H>,
    listener: Option<Arc<CoreListenerRuntime<H>>>,
    running_listeners: Arc<RunningListenerRegistry>,
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
    initial_acl_loaded: AtomicBool,
    #[cfg(feature = "test-utils")]
    acl_reload_count: AtomicUsize,
}

impl<H> CoreInstance<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    fn prepare_stun(
        adapters: &CoreHostAdapters<H>,
        config: &CoreConnectivityConfig,
    ) -> Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(stun_override) = &adapters.stun_override {
            return stun_override.clone();
        }
        Arc::new(StunInfoCollector::new_with_socket_contexts(
            adapters.host.clone(),
            adapters.dns.clone(),
            config.direct.udp_bind.context.clone(),
            config.direct.tcp_bind.context.clone(),
            config.stun.udp_servers.clone(),
            config.stun.tcp_servers.clone(),
            config.stun.udp_v6_servers.clone(),
        ))
    }

    /// Constructs the complete portable runtime for one EasyTier instance.
    ///
    /// This is the only instance construction entry. The normalized config is
    /// authoritative after creation; all platform behavior enters through the
    /// supplied Host Adapters.
    pub fn new(
        config: CoreInstanceConfig,
        mut adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        validate_core_instance_config(&config)?;
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
        let peer_dns: Arc<dyn DnsResolver> = adapters.dns.clone();
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
        let peer_manager = Arc::new(PeerManagerCore::new(
            config.peer,
            runtime_config.clone(),
            peer_dns,
            dns_context,
            Arc::new(CoreStunPeerInfoSource(peer_stun)),
            packet_tx,
            public_ipv6_runtime.clone(),
            std::mem::take(&mut adapters.peer_adapters),
            foreign_rpc_registrar,
        )?);
        let config = config.connectivity;
        let listener_plan = prepare_listener_plan(
            config.listeners.as_ref(),
            peer_manager.instance_id(),
            adapters.server_protocol.as_deref(),
            adapters.external_listener_factory.as_deref(),
        )?;
        let CoreHostAdapters {
            host,
            #[cfg(any(test, feature = "test-utils"))]
                stun_override: _,
            dns,
            process_runtime,
            packet_sink,
            peer_adapters: _,
            wrapped_transports,
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
        let dns_records: Arc<dyn DnsRecordResolver> = dns.clone();
        let dns: Arc<dyn DnsResolver> = dns;
        let ring_registry = process_runtime.ring_registry();
        let CoreConnectivityConfig {
            initial_peers,
            listeners: _,
            runtime: _,
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
        let running_listeners = Arc::new(RunningListenerRegistry::default());
        let events: Arc<dyn ListenerEventSink> = match listener_events {
            Some(listener_events) => {
                ListenerEventSinkGroup::new(vec![running_listeners.clone(), listener_events])
            }
            None => running_listeners.clone(),
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
                dns.clone(),
                ring_registry.clone(),
                transports,
                external_factories,
                failures,
                accepted_transport_handler,
                events,
            ))
        });
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
        let WrappedTransportEngines { kcp, quic } = wrapped_transports;
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
            running_listeners.clone(),
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
        let public_ipv6_provider = public_ipv6_provider.map(|host| {
            PublicIpv6ProviderService::new(host, runtime_config.clone(), public_ipv6_runtime)
        });
        let vpn_portal = VpnPortalModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            vpn_portal,
            vpn_portal_events.unwrap_or_else(|| Arc::new(())),
        );
        let packet_plane = Arc::new(CorePacketPlane::new(
            peer_manager.clone(),
            runtime_config.clone(),
            proxy_cidr_monitor.is_some(),
        ));

        Ok(Arc::new(Self {
            state: AtomicU8::new(CoreInstanceState::Created as u8),
            operation: Mutex::new(()),
            cancel: CancellationToken::new(),
            peer_manager,
            packet_plane,
            manual,
            direct,
            tcp_hole_punch,
            listener,
            running_listeners,
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
            packet_egress: Some(PacketEgress::new(packet_rx, packet_sink)),
            peer_center,
            peer_center_started: AtomicBool::new(false),
            public_ipv6_provider,
            vpn_portal,
            initial_peers,
            initial_peers_started: AtomicBool::new(false),
            startup_plan,
            runtime_config,
            initial_acl_loaded: AtomicBool::new(false),
            #[cfg(feature = "test-utils")]
            acl_reload_count: AtomicUsize::new(0),
        }))
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
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpStream> {
        self.gateway.data_plane_tcp_connect(dst_addr, timeout).await
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpListener> {
        self.gateway.data_plane_tcp_bind(local_port, timeout).await
    }

    #[cfg(feature = "proxy-smoltcp-stack")]
    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneUdpSocket> {
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
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
        self.initial_acl_loaded.store(true, Ordering::Release);
        Ok(())
    }

    async fn reload_acl_config_inner(&self, config: &AclRuleConfig) -> anyhow::Result<()> {
        let acl = config.build()?;
        self.peer_manager.reload_acl(acl.as_ref());
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

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }
}

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

#[cfg(test)]
mod tests;

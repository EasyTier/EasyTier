//! Lifecycle owner for the portable EasyTier runtime.

mod build_capabilities;
mod config;
#[cfg(feature = "proxy-smoltcp-stack")]
mod data_plane_extension;
mod lifecycle;
mod management;
#[cfg(feature = "management")]
mod management_extension;
mod management_state;
pub mod manager;
mod packet_io;
mod packet_plane;
#[cfg(feature = "proxy-packet")]
mod packet_proxy_extension;
#[cfg(feature = "public-ipv6-provider")]
mod public_ipv6_extension;
#[cfg(feature = "vpn-portal")]
mod vpn_portal_extension;

use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
#[cfg(feature = "test-utils")]
use std::sync::atomic::AtomicUsize;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

#[cfg(feature = "tcp-hole-punch")]
use crate::connectivity::hole_punch::tcp::TcpHolePunchConnector;
use crate::{
    config::peers::{AclRuleConfig, PeerRuntimeSnapshot},
    config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfig, CoreRuntimeConfigStore},
    config::toml::TomlConfig,
    connectivity::hole_punch::port_mapping::UdpPortMappingPlatform,
    connectivity::hole_punch::tcp::TcpHolePunchHost,
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
            ManualConnectorManager, ManualConnectorOptions,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::{
            ClientProtocolUpgrader, CoreClientProtocolConfig, CoreClientProtocolUpgrader,
            ServerProtocolUpgrader,
        },
    },
    events::CoreEventSink,
    gateway::dhcp::DhcpIpv4Host,
    host::{
        dns::{DnsRecordResolver, DnsResolver},
        packet::{HostPacketReceiver, PacketSink, host_packet_channel},
    },
    listener::{
        AcceptedSocketHandler, ExternalListenerFactory, ExternalListenerRequest, ListenerFactory,
        RunningListenerRegistry,
        plan::{ListenerRuntimeConfig, PreparedListenerPlan, prepare_listener_plan},
        transport::{
            AcceptedTransport, CoreListenerRuntime, HostAcceptedTcpSocket,
            ProtocolAcceptedTransportHandler,
        },
    },
    peers::peer_center::instance::PeerCenterInstance,
    peers::{
        admission::{PeerAcceptedTunnelHandler, RawAcceptedTransportHandler},
        context::PeerStunInfoSource,
        credential_manager::CredentialStorage,
        peer_manager::{PeerManagerCore, PortablePeerManagerConfig},
        public_ipv6::{CorePublicIpv6Runtime, PublicIpv6Host},
    },
    process_runtime::CoreProcessRuntime,
    socket::{tcp::VirtualTcpSocketFactory, udp::VirtualUdpSocketFactory},
};

use crate::gateway::proxy::cidr_table::{ProxyCidrSnapshot, ProxyCidrTable};
#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::icmp_host::IcmpProxyHost;
#[cfg(feature = "wrapped-transport")]
use crate::gateway::proxy::wrapped_transport::WrappedTransportEngines;
#[cfg(feature = "vpn-portal")]
use crate::gateway::vpn_portal::VpnPortalHost;

#[cfg(feature = "public-ipv6-provider")]
use crate::peers::public_ipv6::provider::PublicIpv6ProviderPlatform;

#[cfg(feature = "dhcp-ipv4")]
use crate::gateway::dhcp::DhcpIpv4Runtime;
#[cfg(feature = "proxy-cidr-monitor")]
use crate::gateway::proxy::cidr_monitor::ProxyCidrMonitorRuntime;
#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::service::CoreProxyModule;
#[cfg(feature = "wrapped-transport")]
use crate::gateway::proxy::wrapped_transport::WrappedTransportProxyModule;
#[cfg(feature = "vpn-portal")]
use crate::gateway::vpn_portal::VpnPortalModule;
#[cfg(feature = "proxy-smoltcp-stack")]
use crate::gateway::{
    DataPlaneRuntime, DataPlaneSession, PortForwardAdapter, Socks5GatewayAdapter,
};
#[cfg(feature = "public-ipv6-provider")]
use crate::peers::public_ipv6::provider::PublicIpv6ProviderRuntime;
pub use config::CoreInstanceHostConfig;
use management_state::ManagementState;
pub use packet_io::PacketEgressHost;
use packet_io::PacketSinkEgress;
pub use packet_plane::CorePacketPlane;

/// Complete Host capability set required by one portable core instance.
pub trait CoreInstanceHost: DirectConnectorHost + TcpHolePunchHost {}

impl<T> CoreInstanceHost for T where T: DirectConnectorHost + TcpHolePunchHost {}

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreInstanceConfig {
    #[serde(default = "crate::config::toml::default_instance_name")]
    pub instance_name: String,
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

fn validate_core_instance_config(
    config: &CoreInstanceConfig,
) -> anyhow::Result<Option<crate::proto::acl::Acl>> {
    let acl = config.connectivity.runtime.acl.build()?;
    build_capabilities::validate(config)?;
    Ok(acl)
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

/// Host-owned resources that must be prepared for the complete Instance
/// lifetime, such as a native packet interface.
#[async_trait::async_trait]
pub trait InstanceRuntimeHost: std::any::Any + Send + Sync + 'static {
    async fn prepare(
        &self,
        packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>>;

    async fn shutdown(&self);

    /// Requests prompt Host cleanup when the canonical instance owner is
    /// dropped without an opportunity to await [`Self::shutdown`].
    fn request_shutdown(&self) {}

    /// Returns the bounded, serialized event journal exposed by process
    /// management. Hosts that do not produce events keep the default empty
    /// journal.
    fn management_events(&self) -> Vec<String> {
        Vec::new()
    }

    /// Applies Host-side cached views of fields already committed to the
    /// shared TOML model.
    #[cfg(feature = "management")]
    fn synchronize_config(&self, _patch: &crate::proto::api::config::InstanceConfigPatch) {}

    #[cfg(feature = "management")]
    fn publish_config_patch(&self, _patch: crate::proto::api::config::InstanceConfigPatch) {}

    fn attach_tun_fd(&self, _fd: i32) -> anyhow::Result<()> {
        anyhow::bail!("external TUN attachment is not supported by this Host")
    }
}

#[async_trait::async_trait]
impl InstanceRuntimeHost for () {
    async fn prepare(
        &self,
        _packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
        Ok(None)
    }

    async fn shutdown(&self) {}
}

/// Host Adapters and optional native capabilities for one core instance.
///
/// Callers provide this bundle and one normalized [`CoreInstanceConfig`] to
/// [`CoreInstance::new`]. Core constructs and owns every portable runtime
/// Module behind that seam.
pub struct CoreHostAdapters<H>
where
    H: CoreInstanceHost,
{
    host: Arc<H>,
    /// Host OS policy and build capabilities used during configuration
    /// normalization. It contains no portable TOML-derived state.
    pub config: CoreInstanceHostConfig,
    #[cfg(any(test, feature = "test-utils"))]
    /// Optional construction-time STUN provider used by deterministic tests.
    stun_override: Option<Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>>,
    dns: Arc<dyn StunDnsRuntime>,
    process_runtime: Arc<CoreProcessRuntime>,
    pub packet_egress: Arc<dyn PacketEgressHost>,
    pub instance_runtime: Arc<dyn InstanceRuntimeHost>,
    pub events: Arc<dyn CoreEventSink>,
    pub credential_storage: Option<Arc<dyn CredentialStorage>>,
    #[cfg(feature = "wrapped-transport")]
    pub wrapped_transports: WrappedTransportEngines,
    pub protocol: Option<Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>>,
    pub external_listener_factory:
        Option<Arc<dyn ExternalListenerFactory<AcceptedTransport<HostAcceptedTcpSocket<H>>>>>,
    pub server_protocol: Option<Arc<dyn ServerProtocolUpgrader<HostAcceptedTcpSocket<H>>>>,
    /// Optional OS port-mapping adapter. STUN-only hole punching remains
    /// available when the host does not provide one.
    pub udp_hole_punch_platform: Option<Arc<dyn UdpPortMappingPlatform>>,
    #[cfg(feature = "proxy-packet")]
    pub icmp_proxy_host: Option<Arc<dyn IcmpProxyHost>>,
    #[cfg(feature = "proxy-cidr-monitor")]
    pub proxy_cidr_monitor_enabled: bool,
    #[cfg(feature = "public-ipv6-provider")]
    pub public_ipv6_host: Option<Arc<dyn PublicIpv6Host>>,
    #[cfg(feature = "public-ipv6-provider")]
    pub public_ipv6_provider: Option<Arc<dyn PublicIpv6ProviderPlatform>>,
    #[cfg(feature = "vpn-portal")]
    pub vpn_portal: Option<Arc<dyn VpnPortalHost>>,
}

impl<H> CoreHostAdapters<H>
where
    H: CoreInstanceHost,
{
    /// Creates the minimal host bundle. Optional native capabilities can be
    /// installed on the returned value before constructing the instance.
    pub fn new(
        host: Arc<H>,
        dns: Arc<dyn StunDnsRuntime>,
        packet_sink: Arc<dyn PacketSink>,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> Self {
        Self::new_with_packet_egress(
            host,
            dns,
            Arc::new(PacketSinkEgress::new(packet_sink)),
            process_runtime,
        )
    }

    /// Creates a host bundle whose packet runtime owns the core's single
    /// bounded egress receiver directly.
    pub fn new_with_packet_egress(
        host: Arc<H>,
        dns: Arc<dyn StunDnsRuntime>,
        packet_egress: Arc<dyn PacketEgressHost>,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> Self {
        Self {
            host,
            config: CoreInstanceHostConfig::default(),
            #[cfg(any(test, feature = "test-utils"))]
            stun_override: None,
            dns,
            process_runtime,
            packet_egress,
            instance_runtime: Arc::new(()),
            events: Arc::new(()),
            credential_storage: None,
            #[cfg(feature = "wrapped-transport")]
            wrapped_transports: WrappedTransportEngines::default(),
            protocol: None,
            external_listener_factory: None,
            server_protocol: None,
            udp_hole_punch_platform: None,
            #[cfg(feature = "proxy-packet")]
            icmp_proxy_host: None,
            #[cfg(feature = "proxy-cidr-monitor")]
            proxy_cidr_monitor_enabled: false,
            #[cfg(feature = "public-ipv6-provider")]
            public_ipv6_host: None,
            #[cfg(feature = "public-ipv6-provider")]
            public_ipv6_provider: None,
            #[cfg(feature = "vpn-portal")]
            vpn_portal: None,
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
    H: CoreInstanceHost,
{
    instance_name: String,
    #[allow(dead_code)]
    management: ManagementState,
    pub(super) instance_runtime: Arc<dyn InstanceRuntimeHost>,
    state: AtomicU8,
    latest_error: RwLock<Option<String>>,
    pub(super) operation: Mutex<()>,
    pub(super) cancel: CancellationToken,
    pub(super) peer_manager: Arc<PeerManagerCore>,
    packet_plane: Arc<CorePacketPlane>,
    pub(super) manual: ManualConnectorManager<H>,
    pub(super) direct: DirectConnectorManager<H>,
    #[cfg(feature = "tcp-hole-punch")]
    tcp_hole_punch: TcpHolePunchConnector<H, PeerManagerCore>,
    pub(super) listener: Option<Arc<CoreListenerRuntime<H>>>,
    running_listeners: Arc<RunningListenerRegistry>,
    pub(super) udp_hole_punch: CoreUdpHolePunchService<H, PeerManagerCore>,
    #[cfg(feature = "wrapped-transport")]
    wrapped_transport: Option<Arc<WrappedTransportProxyModule>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    data_plane_runtime: Arc<DataPlaneRuntime<H>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    data_plane_session: Arc<DataPlaneSession<H>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    socks5_adapter: Arc<Socks5GatewayAdapter<H>>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    port_forward_adapter: Arc<PortForwardAdapter<H>>,
    proxy_cidr_table: Arc<ProxyCidrTable>,
    #[cfg(feature = "proxy-packet")]
    packet_proxy: Arc<CoreProxyModule<H>>,
    #[cfg(feature = "proxy-cidr-monitor")]
    proxy_cidr_monitor: ProxyCidrMonitorRuntime,
    #[cfg(feature = "dhcp-ipv4")]
    dhcp_ipv4: DhcpIpv4Runtime,
    pub(super) packet_egress: Arc<dyn PacketEgressHost>,
    pub(super) packet_receiver: Mutex<Option<HostPacketReceiver>>,
    pub(super) peer_center: Arc<PeerCenterInstance>,
    #[cfg(feature = "public-ipv6-provider")]
    public_ipv6_provider: PublicIpv6ProviderRuntime,
    #[cfg(feature = "vpn-portal")]
    vpn_portal: Arc<VpnPortalModule>,
    #[cfg(feature = "proxy-smoltcp-stack")]
    pub(super) startup_plan: CoreInstanceStartupPlan,
    pub(super) runtime_config: CoreRuntimeConfigStore,
    #[cfg(feature = "test-utils")]
    acl_reload_count: AtomicUsize,
}

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
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
        adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        let host_config = adapters.config.clone();
        Self::new_inner(config, None, host_config, adapters)
    }

    /// Constructs an instance from the shared TOML model and retains that
    /// model as the authoritative management configuration.
    pub fn from_toml(
        toml_config: TomlConfig,
        adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        let host_config = adapters.config.clone();
        let config = CoreInstanceConfig::from_toml_with_host(&toml_config, &host_config)?;
        Self::new_inner(config, Some(toml_config), host_config, adapters)
    }

    fn new_inner(
        config: CoreInstanceConfig,
        toml_config: Option<TomlConfig>,
        host_config: CoreInstanceHostConfig,
        mut adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        let initial_acl = validate_core_instance_config(&config)?;
        let instance_name = config.instance_name;
        let (packet_tx, packet_rx) = host_packet_channel();
        let runtime_config = CoreRuntimeConfigStore::new(
            config.connectivity.runtime.clone(),
            Arc::new(config.peer.snapshot.clone()),
        );
        let events = adapters.events.clone();
        #[cfg(feature = "public-ipv6-provider")]
        let public_ipv6_host: Arc<dyn PublicIpv6Host> = adapters
            .public_ipv6_host
            .take()
            .unwrap_or_else(|| Arc::new(()));
        #[cfg(not(feature = "public-ipv6-provider"))]
        let public_ipv6_host: Arc<dyn PublicIpv6Host> = Arc::new(());
        #[cfg(feature = "public-ipv6-provider")]
        let public_ipv6_events = events.clone();
        #[cfg(not(feature = "public-ipv6-provider"))]
        let public_ipv6_events: Arc<dyn CoreEventSink> = Arc::new(());
        let public_ipv6_runtime = CorePublicIpv6Runtime::new(
            runtime_config.clone(),
            public_ipv6_host,
            public_ipv6_events,
        );
        let stun = Self::prepare_stun(&adapters, &config.connectivity);
        let peer_stun: Arc<dyn StunInfoProvider> = stun.clone();
        let foreign_rpc_registrar = Arc::new(ForeignDirectConnectorRpcRegistrar::new(
            adapters.host.clone(),
            stun.clone(),
        ));
        let peer_manager = Arc::new(PeerManagerCore::new(
            config.peer,
            runtime_config.clone(),
            Arc::new(CoreStunPeerInfoSource(peer_stun)),
            packet_tx,
            public_ipv6_runtime.clone(),
            events.clone(),
            adapters.credential_storage.take(),
            foreign_rpc_registrar,
        )?);
        peer_manager.reload_acl(initial_acl.as_ref());
        let config = config.connectivity;
        let listener_plan = prepare_listener_plan(
            config.listeners.as_ref(),
            peer_manager.instance_id(),
            adapters.server_protocol.as_deref(),
            adapters.external_listener_factory.as_deref(),
        )?;
        let CoreHostAdapters {
            host,
            config: _,
            #[cfg(any(test, feature = "test-utils"))]
                stun_override: _,
            dns,
            process_runtime,
            packet_egress,
            instance_runtime,
            events,
            credential_storage: _,
            #[cfg(feature = "wrapped-transport")]
            wrapped_transports,
            protocol,
            external_listener_factory,
            server_protocol,
            udp_hole_punch_platform,
            #[cfg(feature = "proxy-packet")]
            icmp_proxy_host,
            #[cfg(feature = "proxy-cidr-monitor")]
            proxy_cidr_monitor_enabled,
            #[cfg(feature = "public-ipv6-provider")]
                public_ipv6_host: _,
            #[cfg(feature = "public-ipv6-provider")]
            public_ipv6_provider,
            #[cfg(feature = "vpn-portal")]
            vpn_portal,
        } = adapters;
        let dns_records: Arc<dyn DnsRecordResolver> = dns.clone();
        let dns: Arc<dyn DnsResolver> = dns;
        let ring_registry = process_runtime.ring_registry();
        let protected_tcp_ports = process_runtime.protected_tcp_ports();
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
        #[cfg(not(feature = "proxy-smoltcp-stack"))]
        let _ = startup_plan;
        let accepted_transport_handler: Arc<
            dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>,
        > = match server_protocol {
            Some(server_protocol) => {
                let tunnel_handler = PeerAcceptedTunnelHandler::new(&peer_manager, events.clone());
                Arc::new(ProtocolAcceptedTransportHandler::new(
                    &tunnel_handler,
                    server_protocol,
                ))
            }
            None => Arc::new(RawAcceptedTransportHandler::new(&peer_manager)),
        };
        let running_listeners = Arc::new(RunningListenerRegistry::default());
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
                events.clone(),
                running_listeners.clone(),
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
        let manual = ManualConnectorManager::new(
            peer_manager.clone(),
            host.clone(),
            dns.clone(),
            endpoint_resolver,
            protocol.clone(),
            ring_registry,
            manual_options,
            events.clone(),
        );
        for url in initial_peers {
            manual.add_connector(url)?;
        }
        let udp_hole_punch_socket_context = direct_options.udp_bind.context.clone();
        let udp_hole_punch = CoreUdpHolePunchService::new(
            peer_manager.clone(),
            host.clone(),
            stun.clone(),
            udp_hole_punch_platform,
            events.clone(),
            udp_hole_punch_socket_context,
            protocol.clone(),
        );
        let proxy_cidr_table = Arc::new(ProxyCidrTable::from_snapshot(proxy_cidr_snapshot(
            runtime_config.snapshot().as_ref(),
        )));
        #[cfg(feature = "wrapped-transport")]
        let tcp_proxy_socket_context = direct_options.tcp_bind.context.clone();
        #[cfg(feature = "proxy-packet")]
        let packet_proxy = CoreProxyModule::new(
            peer_manager.clone(),
            host.clone(),
            protected_tcp_ports.clone(),
            running_listeners.clone(),
            runtime_config.clone(),
            proxy_cidr_table.clone(),
            tcp_proxy_socket_context.clone(),
            direct_options.udp_bind.context.clone(),
            // Raw ICMP shares the datagram/network-layer routing context.
            direct_options.udp_bind.context.clone(),
            icmp_proxy_host,
        );
        #[cfg(feature = "wrapped-transport")]
        let wrapped_transport = {
            let WrappedTransportEngines { kcp, quic } = wrapped_transports;
            WrappedTransportProxyModule::new(
                peer_manager.clone(),
                runtime_config.clone(),
                kcp,
                quic,
                host.clone(),
                protected_tcp_ports.clone(),
                running_listeners.clone(),
                proxy_cidr_table.clone(),
                tcp_proxy_socket_context,
            )
        };
        #[cfg(feature = "proxy-smoltcp-stack")]
        let data_plane_runtime = DataPlaneRuntime::new(
            runtime_config.clone(),
            peer_manager.clone(),
            wrapped_transport.as_ref(),
            host.clone(),
            direct_options.tcp_bind.context.clone(),
        );
        #[cfg(feature = "proxy-smoltcp-stack")]
        let data_plane_session = DataPlaneSession::new(&data_plane_runtime);
        #[cfg(feature = "proxy-smoltcp-stack")]
        let socks5_adapter = Socks5GatewayAdapter::new(
            runtime_config.clone(),
            data_plane_runtime.clone(),
            host.clone(),
            dns.clone(),
            direct_options.tcp_bind.context.clone(),
        );
        #[cfg(feature = "proxy-smoltcp-stack")]
        let port_forward_adapter = PortForwardAdapter::new(
            runtime_config.clone(),
            data_plane_runtime.clone(),
            host.clone(),
            direct_options.tcp_bind.context.clone(),
            events.clone(),
        );
        #[cfg(feature = "tcp-hole-punch")]
        let tcp_hole_punch = TcpHolePunchConnector::new(
            peer_manager.clone(),
            host.clone(),
            stun.clone(),
            direct_options.tcp_bind.context.clone(),
            protocol.clone(),
            Arc::new(crate::connectivity::protocol::CoreServerProtocolUpgrader::<
                HostAcceptedTcpSocket<H>,
            >::new(
                crate::connectivity::protocol::CoreServerProtocolConfig::default(),
            )),
        );
        let direct = DirectConnectorManager::new_with_running_listeners(
            peer_manager.clone(),
            host.clone(),
            protected_tcp_ports,
            stun.clone(),
            running_listeners.clone(),
            dns,
            protocol,
            direct_options,
        );
        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));
        #[cfg(feature = "public-ipv6-provider")]
        let public_ipv6_provider = PublicIpv6ProviderRuntime::new(
            public_ipv6_provider,
            runtime_config.clone(),
            public_ipv6_runtime,
        );
        #[cfg(feature = "vpn-portal")]
        let vpn_portal = VpnPortalModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            vpn_portal,
            events.clone(),
        );
        #[cfg(feature = "proxy-cidr-monitor")]
        let proxy_cidr_monitor =
            ProxyCidrMonitorRuntime::new(proxy_cidr_monitor_enabled, events.clone());
        #[cfg(feature = "proxy-cidr-monitor")]
        let proxy_cidr_monitor_available = proxy_cidr_monitor.is_enabled();
        #[cfg(not(feature = "proxy-cidr-monitor"))]
        let proxy_cidr_monitor_available = false;
        let packet_plane = Arc::new(CorePacketPlane::new(
            peer_manager.clone(),
            runtime_config.clone(),
            proxy_cidr_monitor_available,
        ));

        Ok(Arc::new(Self {
            instance_name,
            management: ManagementState::new(toml_config, host_config),
            instance_runtime,
            state: AtomicU8::new(CoreInstanceState::Created as u8),
            latest_error: RwLock::new(None),
            operation: Mutex::new(()),
            cancel: CancellationToken::new(),
            peer_manager,
            packet_plane,
            manual,
            direct,
            #[cfg(feature = "tcp-hole-punch")]
            tcp_hole_punch,
            listener,
            running_listeners,
            udp_hole_punch,
            #[cfg(feature = "wrapped-transport")]
            wrapped_transport,
            #[cfg(feature = "proxy-smoltcp-stack")]
            data_plane_runtime,
            #[cfg(feature = "proxy-smoltcp-stack")]
            data_plane_session,
            #[cfg(feature = "proxy-smoltcp-stack")]
            socks5_adapter,
            #[cfg(feature = "proxy-smoltcp-stack")]
            port_forward_adapter,
            proxy_cidr_table,
            #[cfg(feature = "proxy-packet")]
            packet_proxy,
            #[cfg(feature = "proxy-cidr-monitor")]
            proxy_cidr_monitor,
            #[cfg(feature = "dhcp-ipv4")]
            dhcp_ipv4: DhcpIpv4Runtime::new(),
            packet_egress,
            packet_receiver: Mutex::new(Some(packet_rx)),
            peer_center,
            #[cfg(feature = "public-ipv6-provider")]
            public_ipv6_provider,
            #[cfg(feature = "vpn-portal")]
            vpn_portal,
            #[cfg(feature = "proxy-smoltcp-stack")]
            startup_plan,
            runtime_config,
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
        config: CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        self.update_runtime_config_under_operation(config).await
    }

    pub(crate) async fn update_runtime_config_under_operation(
        &self,
        mut config: CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<()> {
        if matches!(
            self.state(),
            CoreInstanceState::Stopping | CoreInstanceState::Stopped
        ) {
            anyhow::bail!("runtime config cannot update while instance is stopping or stopped");
        }
        self.validate_runtime_config_capabilities(&config)?;
        let current = self.runtime_config.snapshot();
        retain_core_peer_identity(
            &mut config.peer,
            self.peer_id(),
            current.peer.runtime.core.node.instance_id,
        );
        let refresh_acl_groups = current.peer.peer_group_memberships
            != config.peer.peer_group_memberships
            || current.peer.acl_group_declarations != config.peer.acl_group_declarations;
        if current.services.acl != config.services.acl {
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
        self.port_forward_adapter
            .reload(
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

    pub(crate) fn validate_runtime_config_capabilities(
        &self,
        config: &CoreInstanceRuntimeConfig,
    ) -> anyhow::Result<()> {
        build_capabilities::validate_runtime(config)
    }

    pub async fn wait(&self) {
        self.peer_manager.wait().await;
    }
}

impl<H> Drop for CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn drop(&mut self) {
        self.cancel.cancel();
        self.instance_runtime.request_shutdown();
        self.packet_egress.request_stop();
    }
}

#[cfg(any(test, feature = "test-utils"))]
mod test_utils;

#[cfg(test)]
mod tests;

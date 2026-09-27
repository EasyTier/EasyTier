//! Lifecycle owner for the portable EasyTier runtime.

mod build_capabilities;
mod config;
#[cfg(feature = "proxy-smoltcp-stack")]
mod data_plane_extension;
mod lifecycle;
mod management;
mod management_extension;
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

#[cfg(feature = "tcp-hole-punch")]
use crate::connectivity::hole_punch::tcp::TcpHolePunchConnector;
use crate::{
    config::{
        InstanceConfig, InstanceConfigParsed, runtime::InstanceConfigStore, toml::TomlConfig,
    },
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
        AcceptedSocketHandler, ExternalListenerFactory, ExternalListenerRequest,
        HostListenerRegistration, ListenerFactory, RunningListenerRegistry,
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
        peer_manager::PeerManagerCore,
        public_ipv6::{CorePublicIpv6Runtime, PublicIpv6Host},
    },
    process_runtime::CoreProcessRuntime,
    socket::{
        NetNamespace, SocketContext, tcp::TcpBindOptions, tcp::VirtualTcpSocketFactory,
        udp::UdpBindOptions, udp::VirtualUdpSocketFactory,
    },
};

use crate::gateway::proxy::cidr_table::{ProxyCidrSnapshot, ProxyCidrTable};
#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::icmp_host::IcmpProxyHost;
#[cfg(feature = "wrapped-transport")]
use crate::gateway::proxy::wrapped_transport::WrappedTransportEngines;
#[cfg(feature = "vpn-portal")]
use crate::gateway::vpn_portal::PortalHost;

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
use crate::gateway::vpn_portal::PortalModule;
#[cfg(feature = "proxy-smoltcp-stack")]
use crate::gateway::{
    DataPlaneRuntime, DataPlaneSession, PortForwardAdapter, Socks5GatewayAdapter,
};
#[cfg(feature = "public-ipv6-provider")]
use crate::peers::public_ipv6::provider::PublicIpv6ProviderRuntime;
pub use config::CoreInstanceHostConfig;
pub use config::prepare_instance_config;
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

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreInstanceStartupPlan {
    #[serde(default = "default_true")]
    pub gateway: bool,
    #[serde(default = "default_true")]
    pub packet_proxy: bool,
    #[serde(default)]
    pub connectivity: CoreConnectivityMode,
}

impl Default for CoreInstanceStartupPlan {
    fn default() -> Self {
        Self {
            gateway: true,
            packet_proxy: true,
            connectivity: CoreConnectivityMode::Full,
        }
    }
}

/// Selects which portable connectivity Modules participate in one instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CoreConnectivityMode {
    #[default]
    Full,
    /// Dial configured peers without listeners, discovery, or direct connectivity.
    OutboundOnly,
    /// Accept Host-registered listeners without constructing outbound socket Modules.
    InboundOnly,
}

#[cfg(any(test, feature = "test-utils"))]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRelaySessionSnapshot {
    pub has_state: bool,
    pub has_session: bool,
}

fn proxy_cidr_snapshot(config: &InstanceConfigParsed) -> ProxyCidrSnapshot {
    ProxyCidrSnapshot::from_proxy_networks(&config.proxy_network)
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

    #[cfg(feature = "web-client")]
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
/// Callers provide this bundle and one normalized [`InstanceConfig`] to
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
    pub host_listener_registrations: Vec<HostListenerRegistration>,
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
    pub vpn_portal: Option<Arc<dyn PortalHost>>,
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
            host_listener_registrations: Vec::new(),
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
    pub(super) host_config: CoreInstanceHostConfig,
    pub(super) instance_runtime: Arc<dyn InstanceRuntimeHost>,
    state: AtomicU8,
    latest_error: RwLock<Option<String>>,
    pub(super) operation: Mutex<()>,
    pub(super) cancel: CancellationToken,
    pub(super) peer_manager: Arc<PeerManagerCore>,
    packet_plane: Arc<CorePacketPlane>,
    pub(super) manual: Option<ManualConnectorManager<H>>,
    pub(super) direct: Option<DirectConnectorManager<H>>,
    #[cfg(feature = "tcp-hole-punch")]
    tcp_hole_punch: Option<TcpHolePunchConnector<H, PeerManagerCore>>,
    pub(super) listener: Option<Arc<CoreListenerRuntime<H>>>,
    running_listeners: Arc<RunningListenerRegistry>,
    pub(super) udp_hole_punch: Option<CoreUdpHolePunchService<H, PeerManagerCore>>,
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
    vpn_portal: Arc<PortalModule>,
    #[cfg(feature = "proxy-packet")]
    pub(super) startup_plan: CoreInstanceStartupPlan,
    pub(super) runtime_config: InstanceConfigStore,
    #[cfg(feature = "test-utils")]
    acl_reload_count: AtomicUsize,
}

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    fn prepare_stun(
        adapters: &CoreHostAdapters<H>,
        udp_bind_context: &SocketContext,
        tcp_bind_context: &SocketContext,
        stun: &StunServerConfig,
    ) -> Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>> {
        #[cfg(any(test, feature = "test-utils"))]
        if let Some(stun_override) = &adapters.stun_override {
            return stun_override.clone();
        }
        Arc::new(StunInfoCollector::new_with_socket_contexts(
            adapters.host.clone(),
            adapters.dns.clone(),
            udp_bind_context.clone(),
            tcp_bind_context.clone(),
            stun.udp_servers.clone(),
            stun.tcp_servers.clone(),
            stun.udp_v6_servers.clone(),
        ))
    }

    /// Constructs the complete portable runtime for one EasyTier instance.
    ///
    /// This is the only instance construction entry. The normalized config is
    /// authoritative after creation; all platform behavior enters through the
    /// supplied Host Adapters.
    pub fn new(config: InstanceConfig, adapters: CoreHostAdapters<H>) -> anyhow::Result<Arc<Self>> {
        let host_config = adapters.config.clone();
        let prepared = prepare_instance_config(config, &host_config)?;
        build_capabilities::validate(prepared.parsed(), &host_config)?;
        let runtime_config = InstanceConfigStore::new(prepared);
        Self::new_with_store(runtime_config, host_config, adapters)
    }

    pub fn compose_with_toml<F>(
        toml_config: &TomlConfig,
        host_config: CoreInstanceHostConfig,
        build_adapters: F,
    ) -> anyhow::Result<Arc<Self>>
    where
        F: FnOnce(&InstanceConfigStore, &TomlConfig) -> anyhow::Result<CoreHostAdapters<H>>,
    {
        toml_config.ensure_id();
        let snapshot = toml_config.snapshot()?;
        let prepared = prepare_instance_config(snapshot, &host_config)?;
        build_capabilities::validate(prepared.parsed(), &host_config)?;
        let management_toml = TomlConfig::from_instance_config(prepared.clone());
        let runtime_config = InstanceConfigStore::new(prepared);
        let adapters = build_adapters(&runtime_config, &management_toml)?;
        if adapters.config != host_config {
            anyhow::bail!(
                "adapters host configuration does not match the instance host configuration"
            );
        }
        Self::new_with_store_and_toml(runtime_config, host_config, adapters, Some(management_toml))
    }

    /// Constructs an instance from the shared TOML model and retains that
    /// model as the authoritative management configuration.
    pub fn from_toml(
        toml_config: impl std::borrow::Borrow<TomlConfig>,
        adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        let host_config = adapters.config.clone();
        Self::compose_with_toml(toml_config.borrow(), host_config, |_store, _toml| {
            Ok(adapters)
        })
    }

    pub fn new_with_store(
        runtime_config: InstanceConfigStore,
        host_config: CoreInstanceHostConfig,
        adapters: CoreHostAdapters<H>,
    ) -> anyhow::Result<Arc<Self>> {
        Self::new_with_store_and_toml(runtime_config, host_config, adapters, None)
    }

    pub fn new_with_store_and_toml(
        runtime_config: InstanceConfigStore,
        host_config: CoreInstanceHostConfig,
        mut adapters: CoreHostAdapters<H>,
        _management_toml: Option<TomlConfig>,
    ) -> anyhow::Result<Arc<Self>> {
        let snapshot = runtime_config.snapshot();
        let parsed = snapshot.as_ref();
        let connectivity_mode = host_config.connectivity;
        let startup_plan = CoreInstanceStartupPlan {
            gateway: host_config.gateway_enabled,
            packet_proxy: host_config.proxy_enabled,
            connectivity: host_config.connectivity,
        };
        let instance_name = parsed.instance_name.clone();
        #[cfg(feature = "vpn-portal")]
        let vpn_portal_config = parsed.vpn_portal_config.clone().map(Into::into);
        let (packet_tx, packet_rx) = host_packet_channel();
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
        let socket_context = SocketContext::default()
            .with_socket_mark(parsed.flags.socket_mark)
            .with_netns(parsed.netns.clone().map(NetNamespace::new));
        let tcp_bind = TcpBindOptions::default().with_context(socket_context.clone());
        let udp_bind = UdpBindOptions::direct_connect().with_context(socket_context.clone());
        let stun_servers = parsed.stun_servers.clone();
        let stun_config = StunServerConfig {
            udp_servers: stun_servers
                .clone()
                .unwrap_or_else(|| StunServerConfig::default().udp_servers),
            tcp_servers: parsed
                .tcp_stun_servers
                .clone()
                .or_else(|| stun_servers.clone())
                .unwrap_or_else(|| StunServerConfig::default().tcp_servers),
            udp_v6_servers: parsed
                .stun_servers_v6
                .clone()
                .or_else(|| stun_servers.as_ref().map(|_| Vec::new()))
                .unwrap_or_else(|| StunServerConfig::default().udp_v6_servers),
        };
        let stun = (connectivity_mode == CoreConnectivityMode::Full).then(|| {
            Self::prepare_stun(
                &adapters,
                &udp_bind.context,
                &tcp_bind.context,
                &stun_config,
            )
        });
        let (peer_stun, foreign_rpc_registrar): (
            Arc<dyn PeerStunInfoSource>,
            Arc<dyn crate::peers::foreign_network::ForeignNetworkRpcRegistrar>,
        ) = match &stun {
            Some(stun) => (
                Arc::new(CoreStunPeerInfoSource(stun.clone())),
                Arc::new(ForeignDirectConnectorRpcRegistrar::new(
                    adapters.host.clone(),
                    stun.clone(),
                )),
            ),
            None => (Arc::new(()), Arc::new(())),
        };
        let peer_manager = Arc::new(PeerManagerCore::new(
            runtime_config.clone(),
            peer_stun,
            packet_tx,
            public_ipv6_runtime.clone(),
            events.clone(),
            adapters.credential_storage.take(),
            foreign_rpc_registrar,
            host_config.host_routing,
        )?);
        let configured_listeners = (connectivity_mode != CoreConnectivityMode::OutboundOnly)
            .then(|| {
                parsed.listeners.as_ref().map(|urls| {
                    ListenerRuntimeConfig::new(
                        urls.iter()
                            .filter(|url| host_config.accepts_runtime_url(url))
                            .cloned()
                            .collect(),
                        parsed.flags.enable_ipv6,
                        socket_context.clone(),
                    )
                })
            })
            .flatten();
        let listener_plan = prepare_listener_plan(
            configured_listeners.as_ref(),
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
            host_listener_registrations,
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
        let host_listener_registrations = if connectivity_mode == CoreConnectivityMode::OutboundOnly
        {
            Vec::new()
        } else {
            host_listener_registrations
        };
        let dns_records: Arc<dyn DnsRecordResolver> = dns.clone();
        let dns: Arc<dyn DnsResolver> = dns;
        let ring_registry = process_runtime.ring_registry();
        let protected_tcp_ports = process_runtime.protected_tcp_ports();
        let initial_peers = parsed
            .peer
            .iter()
            .map(|p| p.uri.clone())
            .collect::<Vec<_>>();
        let direct_options = DirectConnectorOptions {
            default_protocol: parsed.flags.default_protocol.clone(),
            enable_ipv6: parsed.flags.enable_ipv6,
            allow_public_server: true,
            bind_device: parsed.flags.bind_device,
            allow_interface_bind: host_config.allow_interface_bind,
            tcp_bind: tcp_bind.clone(),
            udp_bind: udp_bind.clone(),
            testing: host_config.direct_testing,
        };
        let manual_options = ManualConnectorOptions {
            bind_device: parsed.flags.bind_device,
            allow_interface_bind: host_config.allow_interface_bind,
            tcp_bind: tcp_bind.clone(),
            udp_bind: udp_bind.clone(),
            ..Default::default()
        };
        let endpoint_discovery = ManualEndpointDiscoveryConfig {
            user_agent: format!("easytier/{}", host_config.easytier_version),
            network_name: parsed.network_identity.network_name.clone(),
            http_tcp_bind: tcp_bind.clone(),
            dns_record_context: socket_context.clone(),
            srv_protocols: host_config.endpoint_protocols.clone(),
            ..Default::default()
        };
        #[cfg(not(feature = "proxy-packet"))]
        let _ = startup_plan;
        if connectivity_mode == CoreConnectivityMode::InboundOnly && !initial_peers.is_empty() {
            anyhow::bail!("inbound-only connectivity does not support outbound peers");
        }
        let accepted_tunnel_handler = PeerAcceptedTunnelHandler::new(&peer_manager, events.clone());
        let accepted_transport_handler: Arc<
            dyn AcceptedSocketHandler<AcceptedTransport<HostAcceptedTcpSocket<H>>>,
        > = match server_protocol {
            Some(server_protocol) => Arc::new(ProtocolAcceptedTransportHandler::new(
                &accepted_tunnel_handler,
                server_protocol,
            )),
            None => Arc::new(RawAcceptedTransportHandler::new(
                accepted_tunnel_handler.clone(),
            )),
        };
        let running_listeners = Arc::new(RunningListenerRegistry::default());
        let PreparedListenerPlan {
            transports,
            external,
            failures,
        } = listener_plan;
        let mut external_factories =
            Vec::with_capacity(external.len() + host_listener_registrations.len());
        if (!external.is_empty() || !host_listener_registrations.is_empty())
            && external_listener_factory.is_none()
        {
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
        for request in host_listener_registrations {
            let factory = external_listener_factory.clone().unwrap();
            if !factory.supports_scheme(request.url.scheme()) {
                anyhow::bail!(
                    "external listener factory does not support Host listener scheme {}",
                    request.url.scheme()
                );
            }
            external_factories.push(ListenerFactory::new(
                move || factory.create(request.clone()),
                true,
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
        let protocol = (connectivity_mode != CoreConnectivityMode::InboundOnly).then(|| {
            protocol.unwrap_or_else(|| {
                Arc::new(CoreClientProtocolUpgrader::new(
                    CoreClientProtocolConfig::default(),
                ))
            })
        });
        let manual = if let Some(protocol) = &protocol {
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
            Some(manual)
        } else {
            None
        };
        let udp_hole_punch = stun
            .as_ref()
            .zip(protocol.as_ref())
            .map(|(stun, protocol)| {
                CoreUdpHolePunchService::new(
                    peer_manager.clone(),
                    host.clone(),
                    stun.clone(),
                    udp_hole_punch_platform,
                    events.clone(),
                    direct_options.udp_bind.context.clone(),
                    protocol.clone(),
                )
            });
        let proxy_cidr_table = Arc::new(ProxyCidrTable::from_snapshot(proxy_cidr_snapshot(parsed)));
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
            (&host_config).into(),
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
        let tcp_hole_punch = stun
            .as_ref()
            .zip(protocol.as_ref())
            .map(|(stun, protocol)| {
                TcpHolePunchConnector::new(
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
                )
            });
        let direct = match (stun, protocol) {
            (Some(stun), Some(protocol)) => {
                Some(DirectConnectorManager::new_with_running_listeners(
                    peer_manager.clone(),
                    host.clone(),
                    protected_tcp_ports,
                    stun,
                    running_listeners.clone(),
                    dns,
                    protocol,
                    direct_options,
                ))
            }
            _ => None,
        };
        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));
        #[cfg(feature = "public-ipv6-provider")]
        let public_ipv6_provider = PublicIpv6ProviderRuntime::new(
            public_ipv6_provider,
            runtime_config.clone(),
            public_ipv6_runtime,
        );
        #[cfg(feature = "vpn-portal")]
        let vpn_portal = PortalModule::new(
            peer_manager.clone(),
            runtime_config.clone(),
            vpn_portal_config,
            vpn_portal,
            events.clone(),
        )?;
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
            host_config,
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
            #[cfg(feature = "proxy-packet")]
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

    /// Publishes one complete instance configuration version. Host changes have
    /// no effect until submitted through this method.
    pub async fn update_runtime_config(&self, config: InstanceConfig) -> anyhow::Result<()> {
        let _operation = self.operation.lock().await;
        self.update_runtime_config_under_operation(config).await
    }

    pub(crate) async fn update_runtime_config_under_operation(
        &self,
        config: InstanceConfig,
    ) -> anyhow::Result<()> {
        if matches!(
            self.state(),
            CoreInstanceState::Stopping | CoreInstanceState::Stopped
        ) {
            anyhow::bail!("runtime config cannot update while instance is stopping or stopped");
        }
        self.validate_runtime_config_capabilities(config.parsed())?;
        #[cfg(feature = "test-utils")]
        let reload_acl = {
            let current = self.runtime_config.snapshot();
            let new = config.parsed();
            current.acl != new.acl
                || current.tcp_whitelist != new.tcp_whitelist
                || current.udp_whitelist != new.udp_whitelist
        };
        let published = self.peer_manager.update_runtime_config(config).await?;
        #[cfg(feature = "test-utils")]
        if reload_acl {
            self.acl_reload_count.fetch_add(1, Ordering::Relaxed);
        }
        self.proxy_cidr_table
            .update_snapshot(proxy_cidr_snapshot(published.parsed()));
        #[cfg(feature = "proxy-smoltcp-stack")]
        self.port_forward_adapter
            .reload(&self.runtime_config.snapshot().port_forward)
            .await?;
        Ok(())
    }

    pub(crate) fn validate_runtime_config_capabilities(
        &self,
        config: &InstanceConfigParsed,
    ) -> anyhow::Result<()> {
        build_capabilities::validate(config, &self.host_config)?;
        #[cfg(feature = "vpn-portal")]
        self.vpn_portal.validate_runtime_config(config)?;
        Ok(())
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

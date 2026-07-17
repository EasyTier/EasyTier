use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use cidr::Ipv4Inet;
use tokio::sync::Mutex;

use crate::{
    config::IpPrefix,
    config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfigStore},
    connectivity::direct::DirectConnectorHost,
    connectivity::hole_punch::tcp::TcpHolePunchHost,
    foundation::stats::{LabelSet, LabelType, MetricName, StatsManager},
    listener::RunningListenerRegistry,
    peers::peer_manager::PeerManagerCore,
    socket::{IpVersion, SocketContext, udp::UdpBindOptions},
};

use super::{
    cidr_table::ProxyCidrTable,
    icmp_proxy_service::IcmpProxyService,
    runtime::{
        IcmpProxyHost, IcmpProxyRuntime, IcmpProxySocket, ProxyRuntimeError, ProxyRuntimeInfo,
        ProxyRuntimeSnapshot, TcpProxyConnectContext, TcpProxyRuntime, UdpProxyPolicy,
        WrappedTcpDestinationRuntime,
    },
    tcp_proxy_engine::TcpNatEntrySnapshot,
    tcp_proxy_service::TcpProxyService,
    tcp_socket_connector::TcpSocketProxyConnector,
    udp_proxy_service::UdpProxyService,
    udp_socket_runtime::UdpSocketProxyRuntime,
};

const UDP_PROXY_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const PROXY_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

fn udp_proxy_bind_options(context: SocketContext) -> UdpBindOptions {
    UdpBindOptions::proxy_nat().with_context(context.with_ip_version(IpVersion::V4))
}

fn ipv4_inet(prefix: &IpPrefix) -> Option<Ipv4Inet> {
    let IpAddr::V4(address) = prefix.address else {
        return None;
    };
    Ipv4Inet::new(address, prefix.prefix_len).ok()
}

fn smoltcp_proxy_inet() -> Ipv4Inet {
    Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24)
        .expect("smoltcp proxy address must be a valid IPv4 interface")
}

fn runtime_snapshot(
    config: &CoreInstanceRuntimeConfig,
    smoltcp_enabled: bool,
) -> ProxyRuntimeSnapshot {
    let virtual_inet = config
        .peer
        .runtime
        .core
        .routes
        .ipv4
        .as_ref()
        .and_then(ipv4_inet);
    ProxyRuntimeSnapshot {
        local_inet: smoltcp_enabled.then(smoltcp_proxy_inet).or(virtual_inet),
        virtual_ipv4: virtual_inet.map(|inet| inet.address()),
        no_tun: config.services.proxy.no_tun,
        enable_exit_node: config.services.proxy.enable_exit_node,
        smoltcp_enabled,
        latency_first: config.peer.flags.latency_first && !config.peer.flags.p2p_only,
    }
}

fn listener_uses_udp(url: &url::Url) -> bool {
    matches!(url.scheme(), "udp" | "wg" | "quic")
}

pub(crate) struct CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    peer_manager: Arc<PeerManagerCore>,
    host: Arc<H>,
    running_listeners: Arc<RunningListenerRegistry>,
    config: CoreRuntimeConfigStore,
    stats: Arc<StatsManager>,
    protocol_label: &'static str,
    smoltcp_enabled: AtomicBool,
}

impl<H> CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        running_listeners: Arc<RunningListenerRegistry>,
        config: CoreRuntimeConfigStore,
        protocol_label: &'static str,
    ) -> Arc<Self> {
        Arc::new(Self {
            stats: peer_manager.stats_manager(),
            peer_manager,
            host,
            running_listeners,
            config,
            protocol_label,
            smoltcp_enabled: AtomicBool::new(false),
        })
    }

    pub(crate) fn latch_smoltcp(&self) {
        self.smoltcp_enabled.store(
            self.config.snapshot().services.proxy.force_smoltcp,
            Ordering::Release,
        );
    }

    fn should_deny_proxy(&self, destination: SocketAddr, is_udp: bool) -> bool {
        let destination_is_local = self.host.is_local_ip(&destination.ip())
            || self.peer_manager.is_local_virtual_ip(&destination.ip());
        if !destination_is_local {
            return false;
        }

        self.running_listeners
            .running_listeners()
            .iter()
            .any(|listener| {
                listener.port() == Some(destination.port()) && listener_uses_udp(listener) == is_udp
            })
            || (!is_udp && self.host.is_protected_tcp_port(destination.port()))
    }
}

impl<H> ProxyRuntimeInfo for CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        runtime_snapshot(
            self.config.snapshot().as_ref(),
            self.smoltcp_enabled.load(Ordering::Acquire),
        )
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.peer_manager.is_local_virtual_ip(ip)
    }
}

impl<H> TcpProxyRuntime for CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn should_deny_tcp_proxy(&self, destination: SocketAddr) -> bool {
        self.should_deny_proxy(destination, false)
    }

    fn record_tcp_proxy_connect(&self, context: TcpProxyConnectContext, socket_dst: SocketAddr) {
        self.stats
            .get_counter(
                MetricName::TcpProxyConnect,
                LabelSet::new()
                    .with_label_type(LabelType::Protocol(self.protocol_label.to_owned()))
                    .with_label_type(LabelType::DstIp(socket_dst.ip().to_string()))
                    .with_label_type(LabelType::MappedDstIp(context.mapped_dst.ip().to_string())),
            )
            .inc();
    }
}

impl<H> WrappedTcpDestinationRuntime for CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        ProxyRuntimeInfo::is_ip_local_virtual_ip(self, ip)
    }

    fn no_tun(&self) -> bool {
        self.proxy_runtime_snapshot().no_tun
    }

    fn should_deny_tcp_proxy(&self, dst: SocketAddr) -> bool {
        TcpProxyRuntime::should_deny_tcp_proxy(self, dst)
    }
}

#[async_trait::async_trait]
impl<H> UdpProxyPolicy for CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn should_deny_udp_proxy(&self, destination: SocketAddr) -> bool {
        self.should_deny_proxy(destination, true)
    }

    fn udp_response_ipv4_mtu(&self) -> usize {
        self.config.snapshot().services.proxy.udp_response_ipv4_mtu
    }
}

struct CoreIcmpProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    policy: Arc<CoreProxyRuntime<H>>,
    host: Arc<dyn IcmpProxyHost>,
    socket: std::sync::Mutex<Option<Arc<dyn IcmpProxySocket>>>,
    context: SocketContext,
}

impl<H> ProxyRuntimeInfo for CoreIcmpProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        self.policy.proxy_runtime_snapshot()
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        ProxyRuntimeInfo::is_ip_local_virtual_ip(self.policy.as_ref(), ip)
    }
}

#[async_trait::async_trait]
impl<H> IcmpProxyRuntime for CoreIcmpProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    type Socket = dyn IcmpProxySocket;

    async fn start_icmp(&self) -> Result<Arc<Self::Socket>, ProxyRuntimeError> {
        let socket = self.host.open_icmp_v4(self.context.clone()).await?;
        self.socket.lock().unwrap().replace(socket.clone());
        Ok(socket)
    }

    fn stop_icmp(&self) {
        if let Some(socket) = self.socket.lock().unwrap().take() {
            socket.close();
        }
    }
}

type CoreTcpProxy<H> = TcpProxyService<CoreProxyRuntime<H>, H, TcpSocketProxyConnector<H>>;
type CoreUdpProxyRuntime<H> = UdpSocketProxyRuntime<H, CoreProxyRuntime<H>>;
type CoreUdpProxy<H> = UdpProxyService<CoreUdpProxyRuntime<H>>;
type CoreIcmpProxy<H> = IcmpProxyService<CoreIcmpProxyRuntime<H>>;

/// Deep portable proxy Module owned by one `CoreInstance`.
///
/// The Host supplies socket creation and an optional raw-ICMP capability. Core
/// owns policy, CIDR authority, packet pipelines, NAT entries, and lifecycle.
pub(crate) struct CoreProxyModule<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    operation: Mutex<()>,
    runtime: Arc<CoreProxyRuntime<H>>,
    tcp: Arc<CoreTcpProxy<H>>,
    icmp: Option<Arc<CoreIcmpProxy<H>>>,
    udp_runtime: Arc<CoreUdpProxyRuntime<H>>,
    udp: Arc<CoreUdpProxy<H>>,
    tcp_started: AtomicBool,
    icmp_started: AtomicBool,
    udp_started: AtomicBool,
}

impl<H> CoreProxyModule<H>
where
    H: DirectConnectorHost + TcpHolePunchHost,
{
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        running_listeners: Arc<RunningListenerRegistry>,
        config: CoreRuntimeConfigStore,
        cidr_table: Arc<ProxyCidrTable>,
        tcp_socket_context: SocketContext,
        udp_socket_context: SocketContext,
        icmp_socket_context: SocketContext,
        icmp_host: Option<Arc<dyn IcmpProxyHost>>,
    ) -> Arc<Self> {
        let runtime = CoreProxyRuntime::new(
            peer_manager.clone(),
            host.clone(),
            running_listeners,
            config.clone(),
            "TCP",
        );
        let tcp_connector = Arc::new(
            TcpSocketProxyConnector::new(host.clone())
                .with_socket_context(tcp_socket_context.clone()),
        );
        let tcp = TcpProxyService::new_with_socket_context(
            peer_manager.clone(),
            runtime.clone(),
            host.clone(),
            tcp_connector,
            cidr_table.clone(),
            tcp_socket_context,
        );
        let icmp = icmp_host.map(|host| {
            IcmpProxyService::new(
                peer_manager.clone(),
                Arc::new(CoreIcmpProxyRuntime {
                    policy: runtime.clone(),
                    host,
                    socket: std::sync::Mutex::new(None),
                    context: icmp_socket_context.with_ip_version(IpVersion::V4),
                }),
                cidr_table.clone(),
                PROXY_FRAGMENT_TIMEOUT,
            )
        });
        let udp_runtime = Arc::new(UdpSocketProxyRuntime::new(
            host,
            runtime.clone(),
            udp_proxy_bind_options(udp_socket_context),
            UDP_PROXY_SOCKET_IDLE_TIMEOUT,
        ));
        let udp = UdpProxyService::new(
            peer_manager,
            udp_runtime.clone(),
            cidr_table.clone(),
            PROXY_FRAGMENT_TIMEOUT,
        );

        Arc::new(Self {
            operation: Mutex::new(()),
            runtime,
            tcp,
            icmp,
            udp_runtime,
            udp,
            tcp_started: AtomicBool::new(false),
            icmp_started: AtomicBool::new(false),
            udp_started: AtomicBool::new(false),
        })
    }

    pub(crate) fn tcp_entry_snapshots(&self) -> Vec<TcpNatEntrySnapshot> {
        self.tcp.engine().list_entries()
    }

    fn stop_started(&self) {
        if self.udp_started.swap(false, Ordering::AcqRel) {
            self.udp.stop();
            self.udp_runtime.close_all();
        }
        if self.icmp_started.swap(false, Ordering::AcqRel)
            && let Some(icmp) = &self.icmp
        {
            icmp.stop();
        }
        if self.tcp_started.swap(false, Ordering::AcqRel) {
            self.tcp.stop();
        }
    }

    pub(crate) async fn start(&self) -> Result<(), ProxyRuntimeError> {
        let _operation = self.operation.lock().await;
        if self.tcp_started.load(Ordering::Acquire) {
            return Ok(());
        }

        self.runtime.latch_smoltcp();
        self.tcp_started.store(true, Ordering::Release);
        if let Err(error) = self.tcp.start(true).await {
            self.stop_started();
            return Err(error);
        }

        if let Some(icmp) = &self.icmp {
            self.icmp_started.store(true, Ordering::Release);
            if let Err(error) = icmp.start().await {
                self.icmp_started.store(false, Ordering::Release);
                if self
                    .runtime
                    .config
                    .snapshot()
                    .services
                    .proxy
                    .icmp_failure_is_fatal
                {
                    self.stop_started();
                    return Err(error);
                }
                tracing::warn!(?error, "optional ICMP proxy runtime failed to start");
            }
        }

        self.udp_started.store(true, Ordering::Release);
        self.udp.start().await;
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let _operation = self.operation.lock().await;
        self.stop_started();
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::{
        config::gateway::ProxyRuntimeConfig,
        config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfig},
        config::{CoreConfig, IpPrefix, PeerPolicyConfig, ProxyNetworkConfig, RouteConfig},
        peers::context::{PeerRuntimeConfig, PeerRuntimeSnapshot},
    };

    use super::*;

    fn test_config() -> CoreInstanceRuntimeConfig {
        let mut peer = PeerRuntimeSnapshot::new(
            PeerRuntimeConfig {
                core: CoreConfig {
                    routes: RouteConfig {
                        ipv4: Some(IpPrefix {
                            address: IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
                            prefix_len: 24,
                        }),
                        proxy_networks: vec![ProxyNetworkConfig {
                            real: IpPrefix {
                                address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
                                prefix_len: 24,
                            },
                            mapped: Some(IpPrefix {
                                address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
                                prefix_len: 24,
                            }),
                        }],
                        ..Default::default()
                    },
                    peer_policy: PeerPolicyConfig {
                        latency_first: true,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                network_identity: Default::default(),
                stun_info: Default::default(),
                feature_flags: Default::default(),
                secure_mode: None,
                host_routing: Default::default(),
            },
            Default::default(),
        );
        peer.flags.latency_first = true;
        CoreInstanceRuntimeConfig {
            services: CoreRuntimeConfig {
                proxy: ProxyRuntimeConfig {
                    enable_exit_node: true,
                    no_tun: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            peer: Arc::new(peer),
        }
    }

    #[test]
    fn runtime_snapshot_uses_submitted_policy_and_latched_smoltcp() {
        let config = test_config();

        let kernel = runtime_snapshot(&config, false);
        assert_eq!(kernel.local_inet.unwrap().to_string(), "10.1.2.3/24");
        assert_eq!(kernel.virtual_ipv4, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(kernel.enable_exit_node);
        assert!(kernel.no_tun);
        assert!(kernel.latency_first);

        let smoltcp = runtime_snapshot(&config, true);
        assert_eq!(smoltcp.local_inet, Some(smoltcp_proxy_inet()));
        assert_eq!(smoltcp.virtual_ipv4, kernel.virtual_ipv4);
    }

    #[test]
    fn listener_protocol_classification_matches_native_proxy_guard() {
        for scheme in ["udp", "wg", "quic"] {
            assert!(listener_uses_udp(
                &format!("{scheme}://127.0.0.1:11010").parse().unwrap()
            ));
        }
        for scheme in ["tcp", "ws", "wss", "faketcp"] {
            assert!(!listener_uses_udp(
                &format!("{scheme}://127.0.0.1:11010").parse().unwrap()
            ));
        }
    }

    #[test]
    fn udp_proxy_bind_options_preserve_the_datagram_context() {
        let context = SocketContext::default()
            .with_socket_mark(Some(73))
            .with_netns(Some(crate::socket::NetNamespace::new("udp-proxy")));

        let options = udp_proxy_bind_options(context);

        assert_eq!(options.context.ip_version, IpVersion::V4);
        assert_eq!(options.context.socket_mark, Some(73));
        assert_eq!(
            options.context.netns.as_ref().map(|netns| netns.token()),
            Some("udp-proxy")
        );
        assert_eq!(
            options.purpose,
            crate::socket::udp::UdpSocketPurpose::ProxyNat
        );
    }
}

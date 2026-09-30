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
    config::{InstanceConfig, runtime::InstanceConfigStore},
    connectivity::{
        direct::DirectConnectorHost, hole_punch::tcp::TcpHolePunchHost, protocol::protocol_uses_udp,
    },
    foundation::stats::{LabelSet, LabelType, MetricName, StatsManager},
    listener::RunningListenerRegistry,
    peers::peer_manager::PeerManagerCore,
    process_runtime::ProtectedTcpPortRegistry,
    socket::{IpVersion, SocketContext, udp::UdpBindOptions},
};

use super::{
    cidr_table::ProxyCidrTable,
    icmp_proxy_service::IcmpProxyService,
    tcp_proxy_engine::TcpNatEntrySnapshot,
    tcp_proxy_service::TcpProxyService,
    tcp_socket_connector::TcpSocketProxyConnector,
    traits::{
        IcmpProxyHost, IcmpProxyRuntime, IcmpProxySocket, ProxyRuntimeError, ProxyRuntimeInfo,
        ProxyRuntimeSnapshot, TcpProxyConnectContext, TcpProxyRuntime, UdpProxyPolicy,
        WrappedTcpDestinationRuntime,
    },
    udp_proxy_service::UdpProxyService,
    udp_socket_runtime::UdpSocketProxyRuntime,
};

const UDP_PROXY_SOCKET_IDLE_TIMEOUT: Duration = Duration::from_secs(120);
const PROXY_FRAGMENT_TIMEOUT: Duration = Duration::from_secs(10);

fn udp_proxy_bind_options(context: SocketContext) -> UdpBindOptions {
    UdpBindOptions::proxy_nat().with_context(context.with_ip_version(IpVersion::V4))
}
pub fn smoltcp_proxy_inet() -> Ipv4Inet {
    Ipv4Inet::new(Ipv4Addr::new(192, 88, 99, 254), 24)
        .expect("smoltcp proxy address must be a valid IPv4 interface")
}

pub(crate) use super::ProxyHostPolicy;

fn runtime_snapshot(
    config: &InstanceConfig,
    effective_ipv4: Option<Ipv4Inet>,
    smoltcp_enabled: bool,
    force_exit_node: bool,
) -> ProxyRuntimeSnapshot {
    let virtual_inet = effective_ipv4;
    ProxyRuntimeSnapshot {
        local_inet: smoltcp_enabled.then(smoltcp_proxy_inet).or(virtual_inet),
        virtual_ipv4: virtual_inet.map(|inet| inet.address()),
        no_tun: config.flags.no_tun,
        enable_exit_node: config.flags.enable_exit_node || force_exit_node,
        smoltcp_enabled,
        latency_first: config.flags.latency_first && !config.flags.p2p_only,
    }
}

pub(crate) struct CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    peer_manager: Arc<PeerManagerCore>,
    host: Arc<H>,
    protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
    running_listeners: Arc<RunningListenerRegistry>,
    config: InstanceConfigStore,
    stats: Arc<StatsManager>,
    protocol_label: &'static str,
    smoltcp_enabled: AtomicBool,
    host_policy: ProxyHostPolicy,
}

impl<H> CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
        running_listeners: Arc<RunningListenerRegistry>,
        config: InstanceConfigStore,
        protocol_label: &'static str,
        host_policy: ProxyHostPolicy,
    ) -> Arc<Self> {
        Arc::new(Self {
            stats: peer_manager.stats_manager(),
            peer_manager,
            host,
            protected_tcp_ports,
            running_listeners,
            config,
            protocol_label,
            smoltcp_enabled: AtomicBool::new(false),
            host_policy,
        })
    }

    pub(crate) fn latch_smoltcp(&self) {
        let snapshot = self.config.snapshot();
        let force_smoltcp = self.host_policy.smoltcp_available
            && (snapshot.flags.use_smoltcp
                || snapshot.flags.no_tun
                || self.host_policy.requires_smoltcp);
        self.smoltcp_enabled.store(force_smoltcp, Ordering::Release);
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
                listener.port() == Some(destination.port())
                    && protocol_uses_udp(listener.scheme()) == is_udp
            })
            || (!is_udp && self.protected_tcp_ports.contains(destination.port()))
    }
}

impl<H> ProxyRuntimeInfo for CoreProxyRuntime<H>
where
    H: DirectConnectorHost,
{
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        runtime_snapshot(
            &self.config.snapshot(),
            self.peer_manager.my_ipv4(),
            self.smoltcp_enabled.load(Ordering::Acquire),
            self.host_policy.force_exit_node,
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
        1280
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
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        protected_tcp_ports: Arc<ProtectedTcpPortRegistry>,
        running_listeners: Arc<RunningListenerRegistry>,
        config: InstanceConfigStore,
        cidr_table: Arc<ProxyCidrTable>,
        tcp_socket_context: SocketContext,
        udp_socket_context: SocketContext,
        icmp_socket_context: SocketContext,
        icmp_host: Option<Arc<dyn IcmpProxyHost>>,
        host_policy: ProxyHostPolicy,
    ) -> Arc<Self> {
        let runtime = CoreProxyRuntime::new(
            peer_manager.clone(),
            host.clone(),
            protected_tcp_ports,
            running_listeners,
            config,
            "TCP",
            host_policy,
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
                if self.runtime.host_policy.icmp_failure_is_fatal {
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
    use std::net::Ipv4Addr;

    use optionize::Optionizable;

    use super::*;

    fn test_config() -> InstanceConfig {
        let parsed = crate::config::InstanceConfigParsed {
            ipv4: Some(cidr::Ipv4Inet::new(Ipv4Addr::new(10, 1, 2, 3), 24).unwrap()),
            flags: crate::config::toml::Flags {
                enable_exit_node: true,
                no_tun: true,
                latency_first: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let raw = parsed.clone().downgrade();
        InstanceConfig::new(parsed, raw, ())
    }

    #[test]
    fn runtime_snapshot_uses_submitted_policy_and_latched_smoltcp() {
        let config = test_config();

        let kernel = runtime_snapshot(&config, config.ipv4, false, false);
        assert_eq!(kernel.local_inet.unwrap().to_string(), "10.1.2.3/24");
        assert_eq!(kernel.virtual_ipv4, Some(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(kernel.enable_exit_node);
        assert!(kernel.no_tun);
        assert!(kernel.latency_first);

        let smoltcp = runtime_snapshot(&config, config.ipv4, true, false);
        assert_eq!(smoltcp.local_inet, Some(smoltcp_proxy_inet()));
        assert_eq!(smoltcp.virtual_ipv4, kernel.virtual_ipv4);

        // Host policy force_exit_node overrides disabled exit node in config
        let mut disabled_exit_node_parsed = config.parsed().clone();
        disabled_exit_node_parsed.flags.enable_exit_node = false;
        disabled_exit_node_parsed.ipv4 = None;
        let disabled_raw = disabled_exit_node_parsed.clone().downgrade();
        let disabled_config = InstanceConfig::new(disabled_exit_node_parsed, disabled_raw, ());

        let forced = runtime_snapshot(&disabled_config, None, false, true);
        assert!(forced.enable_exit_node);
        assert_eq!(forced.virtual_ipv4, None);

        // Effective IPv4 provided from DHCP (even when config.ipv4 is unset)
        let dhcp_inet: Ipv4Inet = "10.126.1.5/24".parse().unwrap();
        let dhcp_snapshot = runtime_snapshot(&disabled_config, Some(dhcp_inet), false, false);
        assert_eq!(dhcp_snapshot.local_inet, Some(dhcp_inet));
        assert_eq!(dhcp_snapshot.virtual_ipv4, Some(dhcp_inet.address()));
    }

    #[test]
    fn listener_protocol_classification_matches_native_proxy_guard() {
        for scheme in ["udp", "wg", "quic"] {
            assert!(protocol_uses_udp(scheme));
        }
        for scheme in ["tcp", "ws", "wss", "faketcp"] {
            assert!(!protocol_uses_udp(scheme));
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

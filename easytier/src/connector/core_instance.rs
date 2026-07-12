use std::{sync::Arc, time::Duration};

use easytier_core::{
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{
            ManualConnectivityEvent, ManualConnectivityEventSink, ManualConnectorOptions,
            discovery::ManualEndpointDiscoveryConfig,
        },
    },
    instance::{
        CoreInstance, CoreInstanceAdapters, CoreInstanceConfig, CoreInstanceRuntimeConfig,
        CoreRuntimeConfig,
    },
    proxy::{ProxyStartupContext, cidr_table::ProxyCidrRuntime},
    socket::{
        IpVersion, SocketContext,
        dns::{DnsRecordResolver, DnsResolver},
        tcp::TcpBindOptions,
        udp::UdpBindOptions,
    },
    tunnel::ring::RingTunnelRegistry,
};
use strum::VariantArray as _;

use crate::{
    VERSION,
    common::{
        acl_processor::runtime_acl_config,
        config::ConfigLoader as _,
        dns::RuntimeDnsResolver,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    instance::listeners::RuntimeListenerService,
    instance::proxy_cidrs_monitor::runtime_proxy_cidr_monitor_host,
    instance::public_ipv6_provider::{
        runtime_public_ipv6_provider_config, runtime_public_ipv6_provider_host,
    },
    peers::peer_manager::PeerManager,
    tunnel::IpScheme,
    use_global_var,
};

use super::{protocol::runtime_client_protocol_upgrader, runtime::RuntimeConnectorHost};

pub(crate) type RuntimeCoreInstance = CoreInstance<RuntimeConnectorHost>;

struct GlobalCtxManualConnectivityEventSink {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_core_config(global_ctx: &ArcGlobalCtx) -> CoreRuntimeConfig {
    CoreRuntimeConfig {
        acl: runtime_acl_config(global_ctx),
        dhcp_ipv4: global_ctx.config.get_dhcp(),
        proxy: runtime_proxy_startup_context(global_ctx),
        public_ipv6_provider: runtime_public_ipv6_provider_config(global_ctx),
    }
}

pub(crate) fn runtime_instance_config(global_ctx: &ArcGlobalCtx) -> CoreInstanceRuntimeConfig {
    CoreInstanceRuntimeConfig {
        services: runtime_core_config(global_ctx),
        peer: Arc::new(crate::peers::context::runtime_peer_snapshot(global_ctx)),
    }
}

pub(crate) fn runtime_proxy_startup_context(global_ctx: &ArcGlobalCtx) -> ProxyStartupContext {
    ProxyStartupContext {
        has_proxy_cidrs: !global_ctx.config.get_proxy_cidrs().is_empty(),
        already_started: false,
        enable_exit_node: global_ctx.enable_exit_node(),
        no_tun: global_ctx.no_tun(),
        forward_by_system: global_ctx.proxy_forward_by_system(),
    }
}

impl ManualConnectivityEventSink for GlobalCtxManualConnectivityEventSink {
    fn emit(&self, event: ManualConnectivityEvent) {
        match event {
            ManualConnectivityEvent::Connecting { url } => {
                self.global_ctx.issue_event(GlobalCtxEvent::Connecting(url));
            }
            ManualConnectivityEvent::ConnectError {
                url,
                ip_version,
                error,
            } => {
                self.global_ctx.issue_event(GlobalCtxEvent::ConnectError(
                    url.to_string(),
                    format!("{ip_version:?}"),
                    error,
                ));
            }
        }
    }
}

pub(crate) fn runtime_manual_options(global_ctx: &ArcGlobalCtx) -> ManualConnectorOptions {
    let flags = global_ctx.config.get_flags();
    ManualConnectorOptions {
        reconnect_interval: Duration::from_millis(use_global_var!(
            MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS
        )),
        connect_timeout: Duration::from_secs(2),
        websocket_connect_timeout: Duration::from_secs(20),
        bind_device: flags.bind_device,
        allow_interface_bind: !cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        tcp_bind: TcpBindOptions::default().with_socket_mark(flags.socket_mark),
        udp_bind: UdpBindOptions::direct_connect().with_socket_mark(flags.socket_mark),
    }
}

pub(crate) fn runtime_endpoint_discovery_config(
    global_ctx: &ArcGlobalCtx,
) -> ManualEndpointDiscoveryConfig {
    ManualEndpointDiscoveryConfig {
        user_agent: format!("easytier/{VERSION}"),
        network_name: global_ctx.network.network_name.clone(),
        http_timeout: Duration::from_secs(20),
        http_ip_version: IpVersion::Both,
        http_tcp_bind: runtime_manual_options(global_ctx).tcp_bind,
        dns_record_context: SocketContext::default(),
        srv_protocols: IpScheme::VARIANTS.iter().map(ToString::to_string).collect(),
    }
}

pub(crate) fn runtime_direct_options(
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> DirectConnectorOptions {
    let flags = global_ctx.config.get_flags();
    DirectConnectorOptions {
        network_name: global_ctx.get_network_name(),
        default_protocol: flags.default_protocol,
        enable_ipv6: flags.enable_ipv6,
        allow_public_server: use_global_var!(DIRECT_CONNECT_TO_PUBLIC_SERVER),
        lazy_p2p: flags.lazy_p2p,
        disable_p2p: flags.disable_p2p,
        need_p2p: flags.need_p2p,
        bind_device: flags.bind_device,
        allow_interface_bind: !cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        tcp_bind: TcpBindOptions::default().with_socket_mark(flags.socket_mark),
        udp_bind: UdpBindOptions::direct_connect().with_socket_mark(flags.socket_mark),
        testing,
    }
}

pub(crate) fn runtime_core_instance_adapters(
    global_ctx: ArcGlobalCtx,
) -> CoreInstanceAdapters<RuntimeConnectorHost> {
    runtime_core_instance_adapters_with_ring_registry(
        global_ctx,
        Arc::new(RingTunnelRegistry::default()),
    )
}

pub(crate) fn runtime_core_instance_adapters_with_ring_registry(
    global_ctx: ArcGlobalCtx,
    ring_registry: Arc<RingTunnelRegistry>,
) -> CoreInstanceAdapters<RuntimeConnectorHost> {
    let host = Arc::new(RuntimeConnectorHost::new_with_ring_registry(
        global_ctx.clone(),
        ring_registry,
    ));
    let dns: Arc<dyn DnsResolver> = Arc::new(RuntimeDnsResolver::new());
    let dns_records: Arc<dyn DnsRecordResolver> = Arc::new(RuntimeDnsResolver::new());
    CoreInstanceAdapters {
        host,
        dns,
        dns_records,
        protocol: Some(runtime_client_protocol_upgrader(global_ctx.clone())),
        manual_events: Some(Arc::new(GlobalCtxManualConnectivityEventSink {
            global_ctx: global_ctx.clone(),
        })),
        listener: None,
        accepted_transport_handler: None,
        udp_hole_punch: None,
        transport_proxy: None,
        proxy: None,
        proxy_cidr_runtime: None,
        proxy_cidr_monitor: Some(runtime_proxy_cidr_monitor_host(global_ctx.clone())),
        public_ipv6_provider: Some(runtime_public_ipv6_provider_host(&global_ctx)),
    }
}

pub(crate) fn build_runtime_core_instance(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
) -> anyhow::Result<RuntimeCoreInstance> {
    build_runtime_core_instance_with_transport(global_ctx, peer_manager, None, proxy)
}

pub(crate) fn build_runtime_core_instance_with_transport(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    transport_proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
    proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
) -> anyhow::Result<RuntimeCoreInstance> {
    build_runtime_core_instance_with_services(
        global_ctx,
        peer_manager,
        transport_proxy,
        proxy,
        None,
    )
}

pub(crate) fn build_runtime_core_instance_with_services(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    transport_proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
    proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
    proxy_cidr_runtime: Option<Arc<dyn ProxyCidrRuntime>>,
) -> anyhow::Result<RuntimeCoreInstance> {
    build_runtime_core_instance_with_services_and_ring_registry(
        global_ctx,
        peer_manager,
        transport_proxy,
        proxy,
        proxy_cidr_runtime,
        Arc::new(RingTunnelRegistry::default()),
    )
}

pub(crate) fn build_runtime_core_instance_with_services_and_ring_registry(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
    transport_proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
    proxy: Option<Arc<dyn easytier_core::instance::ProxyService>>,
    proxy_cidr_runtime: Option<Arc<dyn ProxyCidrRuntime>>,
    ring_registry: Arc<RingTunnelRegistry>,
) -> anyhow::Result<RuntimeCoreInstance> {
    let config = CoreInstanceConfig {
        initial_peers: global_ctx
            .config
            .get_peers()
            .into_iter()
            .map(|peer| peer.uri)
            .collect(),
        listeners: Vec::new(),
        runtime: runtime_core_config(&global_ctx),
        endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
        manual: runtime_manual_options(&global_ctx),
        direct: runtime_direct_options(&global_ctx, false),
    };
    let mut adapters = runtime_core_instance_adapters_with_ring_registry(
        global_ctx.clone(),
        ring_registry.clone(),
    );
    adapters.transport_proxy = transport_proxy;
    adapters.proxy = proxy;
    adapters.proxy_cidr_runtime = proxy_cidr_runtime;
    adapters.listener = Some(Arc::new(RuntimeListenerService::new(
        global_ctx,
        peer_manager.core(),
        ring_registry,
    )));
    adapters.udp_hole_punch = Some(Arc::new(super::udp_hole_punch::UdpHolePunchConnector::new(
        peer_manager.clone(),
    )));
    CoreInstance::new_with_runtime_config_store(
        peer_manager.core(),
        adapters,
        config,
        peer_manager.runtime_config_store(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    use easytier_core::{
        instance::{CoreInstanceState, ListenerService, PortableCoreInstanceConfig, ProxyService},
        listener::transport::TransportListenerConfig,
        peers::{context::PeerContext, peer_manager::PortablePeerManagerConfig},
        socket::{
            tcp::TcpListenOptions,
            udp::{UdpBindOptions, UdpSessionAcceptKind, UdpSessionListenRequest},
        },
    };
    use pnet::packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket},
    };
    use tokio::sync::Notify;
    use tokio_util::task::AbortOnDropHandle;

    use crate::{
        common::{
            config::PeerConfig,
            global_ctx::{
                NetworkIdentity,
                tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            },
        },
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
        },
    };

    use super::*;

    fn create_host_packet_channel() -> (
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        tokio::sync::mpsc::channel(16)
    }

    #[derive(Default)]
    struct BlockingListenerService {
        start_entered: Notify,
        stop_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ListenerService for BlockingListenerService {
        async fn start(&self) -> anyhow::Result<()> {
            self.start_entered.notify_one();
            std::future::pending().await
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Default)]
    struct RecordingProxyService {
        start_calls: AtomicUsize,
        stop_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ProxyService for RecordingProxyService {
        async fn start(&self) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    struct OrderedProxyService {
        name: &'static str,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[async_trait::async_trait]
    impl ProxyService for OrderedProxyService {
        async fn start(&self) -> anyhow::Result<()> {
            self.events.lock().unwrap().push(match self.name {
                "transport" => "start:transport",
                "proxy" => "start:proxy",
                _ => unreachable!(),
            });
            Ok(())
        }

        async fn stop(&self) {
            self.events.lock().unwrap().push(match self.name {
                "transport" => "stop:transport",
                "proxy" => "stop:proxy",
                _ => unreachable!(),
            });
        }
    }

    struct RecordingProxyCidrRuntime {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl ProxyCidrRuntime for RecordingProxyCidrRuntime {
        fn start_updater(&self) {
            self.events.lock().unwrap().push("start:cidr");
        }

        fn stop_updater(&self) {
            self.events.lock().unwrap().push("stop:cidr");
        }
    }

    #[derive(Default)]
    struct BlockingProxyService {
        start_entered: Notify,
        release_start: Notify,
        start_calls: AtomicUsize,
        stop_calls: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl ProxyService for BlockingProxyService {
        async fn start(&self) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            self.start_entered.notify_one();
            self.release_start.notified().await;
            Ok(())
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn build_test_instance_with_listener(
        network_name: &str,
        listener: Arc<dyn ListenerService>,
    ) -> Arc<RuntimeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let config = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: Vec::new(),
            runtime: Default::default(),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let mut adapters = runtime_core_instance_adapters(global_ctx);
        adapters.listener = Some(listener);
        Arc::new(CoreInstance::new(peer_manager.core(), adapters, config).unwrap())
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_connectivity_lifecycle() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        let initial_peer: url::Url = "tcp://127.0.0.1:29999".parse().unwrap();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: initial_peer.clone(),
            peer_public_key: None,
        }]);
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let proxy = Arc::new(RecordingProxyService::default());
        let transport_proxy = Arc::new(RecordingProxyService::default());
        let instance = Arc::new(
            build_runtime_core_instance_with_transport(
                global_ctx,
                peer_manager,
                Some(transport_proxy.clone()),
                Some(proxy.clone()),
            )
            .expect("runtime core composition should succeed"),
        );

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
        instance.start_network_services(None).await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert_eq!(transport_proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(instance.list_connectors().len(), 1);
        assert_eq!(instance.list_connectors()[0].url, initial_peer);
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(transport_proxy.stop_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_proxy_cidr_lifecycle() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = |name| {
            Arc::new(OrderedProxyService {
                name,
                events: events.clone(),
            }) as Arc<dyn ProxyService>
        };
        let cidr_runtime = Arc::new(RecordingProxyCidrRuntime {
            events: events.clone(),
        });
        let instance = Arc::new(
            build_runtime_core_instance_with_services(
                global_ctx,
                peer_manager,
                Some(service("transport")),
                Some(service("proxy")),
                Some(cidr_runtime),
            )
            .expect("runtime core composition should succeed"),
        );

        assert!(instance.start_network_services(None).await.is_err());
        assert!(events.lock().unwrap().is_empty());
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        instance.start_network_services(None).await.unwrap();
        instance.stop().await;
        assert!(instance.start_network_services(None).await.is_err());

        assert_eq!(
            *events.lock().unwrap(),
            [
                "start:cidr",
                "start:transport",
                "start:proxy",
                "stop:transport",
                "stop:proxy",
                "stop:cidr",
            ]
        );
    }

    #[tokio::test]
    async fn runtime_core_requires_explicit_proxy_policy_update() {
        let global_ctx = get_mock_global_ctx();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let proxy = Arc::new(RecordingProxyService::default());
        let transport_proxy = Arc::new(RecordingProxyService::default());
        let instance = Arc::new(
            build_runtime_core_instance_with_transport(
                global_ctx.clone(),
                peer_manager,
                Some(transport_proxy.clone()),
                Some(proxy.clone()),
            )
            .expect("runtime core composition should succeed"),
        );

        instance.start().await.unwrap();
        instance.start_transport_proxy().await.unwrap();
        instance.start_proxy().await.unwrap();
        assert_eq!(transport_proxy.start_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 0);

        global_ctx
            .config
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        instance.start_proxy().await.unwrap();
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 0);

        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await;
        instance.start_proxy().await.unwrap();
        assert_eq!(proxy.start_calls.load(Ordering::Relaxed), 1);

        instance.stop().await;
        assert_eq!(transport_proxy.stop_calls.load(Ordering::Relaxed), 1);
        assert_eq!(proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_acl_runtime_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx.clone(), peer_manager, None)
                .expect("runtime core composition should succeed"),
        );
        assert_eq!(instance.acl_whitelist_snapshot(), Default::default());

        global_ctx
            .config
            .set_tcp_whitelist(vec!["invalid".to_string()]);
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await;
        instance.start().await.unwrap();
        let error = instance.start_network_services(None).await.unwrap_err();
        assert!(
            error.to_string().contains("Invalid port number"),
            "unexpected ACL activation error: {error:#}"
        );
        assert_eq!(instance.acl_whitelist_snapshot().tcp_ports, ["invalid"]);
        instance.stop().await;
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_dhcp_runtime_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx.clone(), peer_manager, None)
                .expect("runtime core composition should succeed"),
        );

        global_ctx.config.set_dhcp(true);
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await;
        instance.start().await.unwrap();
        let error = instance.start_network_services(None).await.unwrap_err();
        assert!(
            error.to_string().contains("no host adapter was provided"),
            "unexpected DHCP activation error: {error:#}"
        );
        instance.stop().await;
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_public_ipv6_runtime_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx.clone(), peer_manager, None)
                .expect("runtime core composition should succeed"),
        );

        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx
            .config
            .set_ipv6_public_addr_prefix(Some("fd00::/64".parse().unwrap()));
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await;
        let error = instance.start().await.unwrap_err();
        assert!(
            error.to_string().contains("not a valid global unicast"),
            "unexpected public IPv6 activation error: {error:#}"
        );
        assert_eq!(instance.state(), CoreInstanceState::Created);
    }

    #[tokio::test]
    async fn stopping_while_proxy_starts_rolls_back_once() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        let initial_peer: url::Url = "tcp://127.0.0.1:29998".parse().unwrap();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: initial_peer,
            peer_public_key: None,
        }]);
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let proxy = Arc::new(BlockingProxyService::default());
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx, peer_manager, Some(proxy.clone()))
                .expect("runtime core composition should succeed"),
        );
        instance.start().await.unwrap();
        instance.start_peer_center().await.unwrap();

        let start_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start_proxy().await }
        });
        proxy.start_entered.notified().await;
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
        proxy.release_start.notify_one();

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
        let global_ctx = get_mock_global_ctx();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: "unsupported://peer.example:1234".parse().unwrap(),
            peer_public_key: None,
        }]);
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx, peer_manager, None)
                .expect("invalid peer schemes must not panic during composition"),
        );

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

    #[tokio::test]
    async fn portable_core_instance_builds_peer_graph_from_native_adapters() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-core-instance".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let peer = PortablePeerManagerConfig::new(global_ctx.runtime_config())
            .with_flags(global_ctx.get_flags());
        let connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: vec![
                TransportListenerConfig::Tcp {
                    url: "tcp://127.0.0.1:0".parse().unwrap(),
                    options: TcpListenOptions::manual_connect("127.0.0.1:0".parse().unwrap()),
                    must_succeed: true,
                },
                TransportListenerConfig::Udp {
                    url: "udp://127.0.0.1:0".parse().unwrap(),
                    request: UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(
                        "127.0.0.1:0".parse().unwrap(),
                    )),
                    accept_kind: UdpSessionAcceptKind::EasyTierMux,
                    must_succeed: true,
                },
            ],
            runtime: Default::default(),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let instance = Arc::new(
            RuntimeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_ctx),
                PortableCoreInstanceConfig { peer, connectivity },
                Arc::new(packet_sink),
            )
            .unwrap(),
        );

        assert!(instance.running_listeners().is_empty());
        instance.start().await.unwrap();
        let running_listeners = instance.running_listeners();
        assert_eq!(running_listeners.len(), 2);
        assert!(
            running_listeners
                .iter()
                .all(|listener| listener.port().is_some_and(|port| port != 0))
        );
        assert_eq!(instance.state(), CoreInstanceState::Running);
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert!(instance.running_listeners().is_empty());
    }

    #[tokio::test]
    async fn portable_core_instances_connect_through_core_tcp_listener() {
        let global_a = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-connect-listen".to_owned(),
            "shared-secret".to_owned(),
        )));
        let global_b = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-connect-listen".to_owned(),
            "shared-secret".to_owned(),
        )));
        global_a.set_ipv4(Some("10.250.0.1/24".parse().unwrap()));
        global_b.set_ipv4(Some("10.250.0.2/24".parse().unwrap()));
        let (packet_sink_a, _packet_receiver_a) = create_host_packet_channel();
        let (packet_sink_b, mut packet_receiver_b) = create_host_packet_channel();
        let peer_a = PortablePeerManagerConfig::new(global_a.runtime_config())
            .with_flags(global_a.get_flags());
        let peer_b = PortablePeerManagerConfig::new(global_b.runtime_config())
            .with_flags(global_b.get_flags());
        let instance_a = Arc::new(
            RuntimeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_a.clone()),
                PortableCoreInstanceConfig {
                    peer: peer_a,
                    connectivity: CoreInstanceConfig {
                        initial_peers: Vec::new(),
                        listeners: vec![TransportListenerConfig::Tcp {
                            url: "tcp://127.0.0.1:0".parse().unwrap(),
                            options: TcpListenOptions::manual_connect(
                                "127.0.0.1:0".parse().unwrap(),
                            ),
                            must_succeed: true,
                        }],
                        runtime: Default::default(),
                        endpoint_discovery: runtime_endpoint_discovery_config(&global_a),
                        manual: Default::default(),
                        direct: runtime_direct_options(&global_a, true),
                    },
                },
                Arc::new(packet_sink_a),
            )
            .unwrap(),
        );
        let instance_b = Arc::new(
            RuntimeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_b.clone()),
                PortableCoreInstanceConfig {
                    peer: peer_b,
                    connectivity: CoreInstanceConfig {
                        initial_peers: Vec::new(),
                        listeners: Vec::new(),
                        runtime: Default::default(),
                        endpoint_discovery: runtime_endpoint_discovery_config(&global_b),
                        manual: Default::default(),
                        direct: runtime_direct_options(&global_b, true),
                    },
                },
                Arc::new(packet_sink_b),
            )
            .unwrap(),
        );

        let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
        start_a.unwrap();
        start_b.unwrap();
        let listener = instance_a.running_listeners().pop().unwrap();
        instance_b.add_connector(listener).unwrap();

        let peer_a_id = instance_a.peer_id();
        let peer_b_id = instance_b.peer_id();
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let a_peers = instance_a.connected_peers().await;
                let b_peers = instance_b.connected_peers().await;
                if a_peers.contains(&peer_b_id) && b_peers.contains(&peer_a_id) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("portable core instances did not connect through the core listener");

        let source_ip = "10.250.0.1".parse().unwrap();
        let destination_ip = "10.250.0.2".parse().unwrap();
        let mut ip_packet = vec![0u8; 28];
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ip_packet).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(28);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4.set_source(source_ip);
            ipv4.set_destination(destination_ip);
        }
        {
            let mut udp = MutableUdpPacket::new(&mut ip_packet[20..]).unwrap();
            udp.set_source(10000);
            udp.set_destination(10001);
            udp.set_length(8);
            udp.set_checksum(udp::ipv4_checksum(
                &udp.to_immutable(),
                &source_ip,
                &destination_ip,
            ));
        }
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut ip_packet).unwrap();
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
        }
        let received = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                instance_a.send_ip_packet(ip_packet.clone()).await.unwrap();
                match tokio::time::timeout(
                    std::time::Duration::from_millis(100),
                    packet_receiver_b.recv(),
                )
                .await
                {
                    Ok(Some(packet)) => break packet,
                    Ok(None) => panic!("portable host packet sink closed"),
                    Err(_) => {}
                }
            }
        })
        .await
        .expect("portable host packet sink did not receive the IP packet");
        assert_eq!(received, ip_packet);

        instance_b.stop().await;
        instance_a.stop().await;
    }

    #[tokio::test]
    async fn portable_core_instance_rejects_conflicting_p2p_policy() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-policy-validation".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let peer = PortablePeerManagerConfig::new(global_ctx.runtime_config())
            .with_flags(global_ctx.get_flags());
        let mut connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: Vec::new(),
            runtime: Default::default(),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        connectivity.direct.disable_p2p = !peer.flags.disable_p2p;

        let error = RuntimeCoreInstance::new_portable(
            runtime_core_instance_adapters(global_ctx),
            PortableCoreInstanceConfig { peer, connectivity },
            Arc::new(packet_sink),
        )
        .err()
        .expect("conflicting P2P policy should be rejected");

        assert!(error.to_string().contains("P2P policy"));
    }

    #[tokio::test]
    async fn portable_core_instance_rejects_optional_listener_without_handler() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-listener-validation".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let peer = PortablePeerManagerConfig::new(global_ctx.runtime_config())
            .with_flags(global_ctx.get_flags());
        let connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: vec![TransportListenerConfig::Udp {
                url: "udp://127.0.0.1:0".parse().unwrap(),
                request: UdpSessionListenRequest::new(UdpBindOptions::port_bound_listener(
                    "127.0.0.1:0".parse().unwrap(),
                )),
                accept_kind: UdpSessionAcceptKind::Classified(
                    easytier_core::socket::udp::UdpSessionProtocol::WireGuard,
                ),
                must_succeed: true,
            }],
            runtime: Default::default(),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };

        let error = RuntimeCoreInstance::new_portable(
            runtime_core_instance_adapters(global_ctx),
            PortableCoreInstanceConfig { peer, connectivity },
            Arc::new(packet_sink),
        )
        .err()
        .expect("optional listener without a handler should be rejected");

        assert!(
            error
                .to_string()
                .contains("custom accepted transport handler")
        );
    }

    fn build_test_instance(network_name: &str) -> Arc<RuntimeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        Arc::new(build_runtime_core_instance(global_ctx, peer_manager, None).unwrap())
    }

    #[tokio::test]
    async fn runtime_core_instances_keep_lifecycle_and_connectors_isolated() {
        let instance_a = build_test_instance("instance-a");
        let instance_b = build_test_instance("instance-b");
        let connector_a: url::Url = "tcp://127.0.0.1:21001".parse().unwrap();
        let connector_b: url::Url = "udp://127.0.0.1:21002".parse().unwrap();

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

    #[tokio::test]
    async fn stop_cancels_pending_listener_start() {
        let listener = Arc::new(BlockingListenerService::default());
        let instance = build_test_instance_with_listener("pending-listener", listener.clone());
        let start_instance = instance.clone();
        let start_task =
            AbortOnDropHandle::new(tokio::spawn(async move { start_instance.start().await }));
        let start_result = tokio::time::timeout(std::time::Duration::from_secs(1), async {
            listener.start_entered.notified().await;
            instance.stop().await;
            start_task.await.unwrap()
        })
        .await
        .expect("listener cancellation should complete promptly");

        assert!(start_result.is_err());
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(listener.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn stop_from_created_cleans_listener_service() {
        let listener = Arc::new(BlockingListenerService::default());
        let instance = build_test_instance_with_listener("created-listener", listener.clone());

        instance.stop().await;

        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(listener.stop_calls.load(Ordering::Relaxed), 1);
    }
}

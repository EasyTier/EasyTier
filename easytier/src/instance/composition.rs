use std::sync::Arc;

#[cfg(feature = "smoltcp")]
use easytier_core::proxy::gateway::{GatewayEvent, GatewayEventSink};
#[cfg(test)]
use easytier_core::proxy::wrapped_transport::NoWrappedTransportEngineFactory;
#[cfg(test)]
use easytier_core::stun::{StunProviderSlot, StunSocketMapper};
#[cfg(feature = "wireguard")]
use easytier_core::vpn_portal::VpnPortalHost;
use easytier_core::{
    connectivity::manual::{ManualConnectivityEvent, ManualConnectivityEventSink},
    instance::{CoreInstance, CoreInstanceAdapters, PacketSink, PortableCoreInstanceConfig},
    peers::peer_manager::RouteAlgoType,
    process_runtime::CoreProcessRuntime,
    proxy::wrapped_transport::WrappedTransportEngineFactory,
    socket::dns::{DnsRecordResolver, DnsResolver},
    vpn_portal::{VpnPortalEvent, VpnPortalEventSink},
};

#[cfg(test)]
use crate::socket::udp::RuntimeUdpSocket;
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    host_runtime::native_host_runtime,
    instance::config::{
        runtime_connectivity_config, runtime_peer_manager_config,
        runtime_peer_manager_host_adapters,
    },
    instance::listeners::{
        RuntimeExternalListenerFactory, runtime_accepted_tunnel_event_sink,
        runtime_listener_event_sink,
    },
    instance::proxy_cidrs_monitor::runtime_proxy_cidr_monitor_host,
    instance::public_ipv6_provider::runtime_public_ipv6_provider_platform,
};

use super::host::{NativeInstanceHost, native_instance_host};
use crate::tunnel::protocol::{runtime_client_protocol_upgrader, runtime_server_protocol_upgrader};

pub(crate) type NativeCoreInstance = CoreInstance<NativeInstanceHost>;

struct GlobalCtxManualConnectivityEventSink {
    global_ctx: ArcGlobalCtx,
}

struct GlobalCtxVpnPortalEventSink {
    global_ctx: ArcGlobalCtx,
}

impl VpnPortalEventSink for GlobalCtxVpnPortalEventSink {
    fn emit(&self, event: VpnPortalEvent) {
        let event = match event {
            VpnPortalEvent::Started(portal) => GlobalCtxEvent::VpnPortalStarted(portal),
            VpnPortalEvent::ClientConnected { portal, client } => {
                GlobalCtxEvent::VpnPortalClientConnected(portal, client)
            }
            VpnPortalEvent::ClientDisconnected { portal, client } => {
                GlobalCtxEvent::VpnPortalClientDisconnected(portal, client)
            }
        };
        self.global_ctx.issue_event(event);
    }
}

#[cfg(feature = "smoltcp")]
struct GlobalCtxGatewayEventSink {
    global_ctx: ArcGlobalCtx,
}

#[cfg(feature = "smoltcp")]
impl GatewayEventSink for GlobalCtxGatewayEventSink {
    fn emit(&self, event: GatewayEvent) {
        match event {
            GatewayEvent::PortForwardAdded(config) => self
                .global_ctx
                .issue_event(GlobalCtxEvent::PortForwardAdded(config.into())),
        }
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

pub(crate) fn runtime_core_instance_adapters(
    global_ctx: ArcGlobalCtx,
) -> CoreInstanceAdapters<NativeInstanceHost> {
    runtime_core_instance_adapters_with_process_runtime(global_ctx, CoreProcessRuntime::new())
}

pub(crate) fn runtime_core_instance_adapters_with_process_runtime(
    global_ctx: ArcGlobalCtx,
    process_runtime: Arc<CoreProcessRuntime>,
) -> CoreInstanceAdapters<NativeInstanceHost> {
    let host = native_instance_host(global_ctx.clone());
    let runtime_dns = native_host_runtime();
    let dns: Arc<dyn DnsResolver> = runtime_dns.clone();
    let dns_records: Arc<dyn DnsRecordResolver> = runtime_dns;
    CoreInstanceAdapters {
        host,
        stun_projection: None,
        dns,
        listener_dns: None,
        dns_records,
        process_runtime,
        protocol: Some(runtime_client_protocol_upgrader(global_ctx.clone())),
        manual_events: Some(Arc::new(GlobalCtxManualConnectivityEventSink {
            global_ctx: global_ctx.clone(),
        })),
        external_listener_factory: None,
        listener_events: None,
        server_protocol: Some(runtime_server_protocol_upgrader(global_ctx.clone())),
        accepted_tunnel_events: Some(runtime_accepted_tunnel_event_sink(global_ctx.clone())),
        udp_hole_punch_platform: Some(
            crate::instance::udp_hole_punch::runtime_udp_hole_punch_platform(global_ctx.clone()),
        ),
        icmp_proxy_host: {
            #[cfg(test)]
            {
                None
            }
            #[cfg(not(test))]
            {
                Some(crate::gateway::icmp_proxy::runtime_icmp_proxy_host())
            }
        },
        proxy_cidr_monitor: Some(runtime_proxy_cidr_monitor_host(global_ctx.clone())),
        public_ipv6_host: Some(global_ctx.clone()),
        public_ipv6_provider: Some(runtime_public_ipv6_provider_platform(&global_ctx)),
        vpn_portal: {
            #[cfg(feature = "wireguard")]
            {
                Some(
                    crate::vpn_portal::wireguard::WireGuardPortalHost::new(global_ctx.clone())
                        as Arc<dyn VpnPortalHost>,
                )
            }
            #[cfg(not(feature = "wireguard"))]
            {
                None
            }
        },
        vpn_portal_events: Some(Arc::new(GlobalCtxVpnPortalEventSink {
            global_ctx: global_ctx.clone(),
        })),
        #[cfg(feature = "smoltcp")]
        gateway_events: Some(Arc::new(GlobalCtxGatewayEventSink { global_ctx })),
    }
}

pub(crate) fn build_portable_runtime_core_instance_with_transport_factory_and_process_runtime<F>(
    global_ctx: ArcGlobalCtx,
    packet_sink: Arc<dyn PacketSink>,
    transport_proxy_factory: F,
    process_runtime: Arc<CoreProcessRuntime>,
) -> anyhow::Result<(NativeCoreInstance, F::Attachment)>
where
    F: WrappedTransportEngineFactory,
{
    let adapters =
        runtime_core_instance_adapters_with_process_runtime(global_ctx.clone(), process_runtime);
    build_portable_runtime_core_instance_with_transport_factory_and_adapters(
        global_ctx,
        packet_sink,
        transport_proxy_factory,
        adapters,
    )
}

pub(crate) fn build_portable_runtime_core_instance_with_transport_factory_and_adapters<F>(
    global_ctx: ArcGlobalCtx,
    packet_sink: Arc<dyn PacketSink>,
    transport_proxy_factory: F,
    mut adapters: CoreInstanceAdapters<NativeInstanceHost>,
) -> anyhow::Result<(NativeCoreInstance, F::Attachment)>
where
    F: WrappedTransportEngineFactory,
{
    let config = PortableCoreInstanceConfig {
        peer: runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf),
        connectivity: runtime_connectivity_config(&global_ctx),
    };
    adapters.listener_events = Some(runtime_listener_event_sink(global_ctx.clone()));
    adapters.external_listener_factory = Some(RuntimeExternalListenerFactory::new());
    CoreInstance::new_portable_with_peer_adapters_and_transport_factory(
        adapters,
        runtime_peer_manager_host_adapters(&global_ctx),
        config,
        packet_sink,
        transport_proxy_factory,
    )
}

#[cfg(test)]
pub(crate) fn build_portable_test_core_instance(
    global_ctx: ArcGlobalCtx,
    process_runtime: Arc<CoreProcessRuntime>,
    stun_collector: Box<dyn StunSocketMapper<RuntimeUdpSocket>>,
) -> anyhow::Result<(
    Arc<NativeCoreInstance>,
    tokio::sync::mpsc::Receiver<Vec<u8>>,
)> {
    let (packet_sink, packet_receiver) = tokio::sync::mpsc::channel(16);
    let mut adapters =
        runtime_core_instance_adapters_with_process_runtime(global_ctx.clone(), process_runtime);
    let provider: Arc<dyn StunSocketMapper<RuntimeUdpSocket>> = Arc::from(stun_collector);
    adapters.stun_projection = Some(Arc::new(StunProviderSlot::new(provider)));
    let (instance, ()) = build_portable_runtime_core_instance_with_transport_factory_and_adapters(
        global_ctx,
        Arc::new(packet_sink),
        NoWrappedTransportEngineFactory,
        adapters,
    )?;
    Ok((Arc::new(instance), packet_receiver))
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    use easytier_core::{
        instance::{
            CoreInstanceConfig, CoreInstanceState, ExternalListenerFactory,
            ExternalListenerRequest, PortableCoreInstanceConfig,
        },
        listener::{SocketListener, plan::ListenerRuntimeConfig},
        proxy::wrapped_transport::{
            WrappedTransportAcceptedStream, WrappedTransportConnect,
            WrappedTransportDestinationIngress, WrappedTransportEngine,
            WrappedTransportEngineStart, WrappedTransportKind, WrappedTransportRole,
        },
    };
    use pnet::packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket},
    };
    use tokio::sync::Notify;
    use tokio_util::task::AbortOnDropHandle;

    use crate::{
        common::{
            config::{ConfigLoader as _, PeerConfig},
            global_ctx::{
                NetworkIdentity,
                tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
            },
        },
        instance::config::{
            runtime_direct_options, runtime_endpoint_discovery_config, runtime_instance_config,
            runtime_manual_options, runtime_socket_context, runtime_stun_server_config,
        },
    };

    use super::*;

    fn create_host_packet_channel() -> (
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        tokio::sync::mpsc::channel(16)
    }

    fn build_portable_test_instance_with_transport_factory<F>(
        global_ctx: ArcGlobalCtx,
        transport_proxy_factory: F,
    ) -> anyhow::Result<(NativeCoreInstance, F::Attachment)>
    where
        F: WrappedTransportEngineFactory,
    {
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        build_portable_runtime_core_instance_with_transport_factory_and_process_runtime(
            global_ctx,
            Arc::new(packet_sink),
            transport_proxy_factory,
            CoreProcessRuntime::new(),
        )
    }

    fn build_portable_test_instance(
        global_ctx: ArcGlobalCtx,
    ) -> anyhow::Result<NativeCoreInstance> {
        build_portable_test_instance_with_transport_factory(
            global_ctx,
            NoWrappedTransportEngineFactory,
        )
        .map(|(instance, ())| instance)
    }

    #[derive(Debug, Default)]
    struct BlockingListenerState {
        start_entered: Notify,
        drop_calls: AtomicUsize,
    }

    #[derive(Debug)]
    struct ExternalRegistryListener {
        url: url::Url,
    }

    #[derive(Debug)]
    struct BlockingSocketListener {
        url: url::Url,
        state: Arc<BlockingListenerState>,
    }

    #[async_trait::async_trait]
    impl SocketListener for ExternalRegistryListener {
        type Accepted = easytier_core::listener::transport::AcceptedTransport<
            crate::socket::tcp::RuntimeTcpSocket,
        >;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> url::Url {
            self.url.clone()
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for BlockingSocketListener {
        type Accepted = easytier_core::listener::transport::AcceptedTransport<
            crate::socket::tcp::RuntimeTcpSocket,
        >;

        async fn listen(&mut self) -> anyhow::Result<()> {
            self.state.start_entered.notify_one();
            std::future::pending().await
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> url::Url {
            self.url.clone()
        }
    }

    impl Drop for BlockingSocketListener {
        fn drop(&mut self) {
            self.state.drop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    enum TestExternalListenerKind {
        Registry,
        Blocking(Arc<BlockingListenerState>),
    }

    struct TestExternalListenerFactory {
        kind: TestExternalListenerKind,
    }

    impl
        ExternalListenerFactory<
            easytier_core::listener::transport::AcceptedTransport<
                crate::socket::tcp::RuntimeTcpSocket,
            >,
        > for TestExternalListenerFactory
    {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "unix"
        }

        fn create(
            &self,
            request: ExternalListenerRequest,
        ) -> Box<
            dyn SocketListener<
                Accepted = easytier_core::listener::transport::AcceptedTransport<
                    crate::socket::tcp::RuntimeTcpSocket,
                >,
            >,
        > {
            match &self.kind {
                TestExternalListenerKind::Registry => {
                    Box::new(ExternalRegistryListener { url: request.url })
                }
                TestExternalListenerKind::Blocking(state) => Box::new(BlockingSocketListener {
                    url: request.url,
                    state: state.clone(),
                }),
            }
        }
    }

    #[derive(Default)]
    struct RecordingProxyService {
        start_calls: AtomicUsize,
        stop_calls: AtomicUsize,
        destination_ingress: StdMutex<Option<WrappedTransportDestinationIngress>>,
    }

    #[async_trait::async_trait]
    impl WrappedTransportEngine for RecordingProxyService {
        async fn prepare(&self, options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            *self.destination_ingress.lock().unwrap() = options.destination_ingress;
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

        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn easytier_core::proxy::runtime::TcpProxyStream>> {
            anyhow::bail!("recording engine does not open streams")
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl RecordingProxyService {
        fn destination_ingress(&self) -> Option<WrappedTransportDestinationIngress> {
            self.destination_ingress.lock().unwrap().clone()
        }
    }

    struct TestTransportProxyFactory {
        service: Arc<dyn WrappedTransportEngine>,
    }

    impl WrappedTransportEngineFactory for TestTransportProxyFactory {
        type Attachment = ();

        fn build(
            self,
        ) -> anyhow::Result<
            easytier_core::proxy::wrapped_transport::WrappedTransportEngineBuild<Self::Attachment>,
        > {
            Ok(
                easytier_core::proxy::wrapped_transport::WrappedTransportEngineBuild {
                    kcp: Some(self.service),
                    quic: None,
                    attachment: (),
                },
            )
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
    impl WrappedTransportEngine for BlockingProxyService {
        async fn prepare(&self, _options: WrappedTransportEngineStart) -> anyhow::Result<()> {
            self.start_calls.fetch_add(1, Ordering::Relaxed);
            self.start_entered.notify_one();
            self.release_start.notified().await;
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

        async fn connect_source(
            &self,
            _request: WrappedTransportConnect,
        ) -> anyhow::Result<Box<dyn easytier_core::proxy::runtime::TcpProxyStream>> {
            anyhow::bail!("blocking engine does not open streams")
        }

        async fn stop(&self) {
            self.stop_calls.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn build_test_instance_with_listener(
        network_name: &str,
        url: url::Url,
        factory: Arc<
            dyn ExternalListenerFactory<
                easytier_core::listener::transport::AcceptedTransport<
                    crate::socket::tcp::RuntimeTcpSocket,
                >,
            >,
        >,
    ) -> Arc<NativeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        let peer = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        let connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: Some(ListenerRuntimeConfig::new(
                vec![url],
                false,
                runtime_socket_context(&global_ctx),
            )),
            runtime: Default::default(),
            stun: runtime_stun_server_config(&global_ctx),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let mut adapters = runtime_core_instance_adapters(global_ctx);
        adapters.external_listener_factory = Some(factory);
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        Arc::new(
            CoreInstance::new_portable(
                adapters,
                PortableCoreInstanceConfig { peer, connectivity },
                Arc::new(packet_sink),
            )
            .unwrap(),
        )
    }

    #[tokio::test]
    async fn portable_runtime_builder_constructs_and_owns_peer_graph() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-runtime-builder".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let (instance, ()) =
            build_portable_runtime_core_instance_with_transport_factory_and_process_runtime(
                global_ctx,
                Arc::new(packet_sink),
                NoWrappedTransportEngineFactory,
                CoreProcessRuntime::new(),
            )
            .unwrap();
        let instance = Arc::new(instance);

        instance.start().await.unwrap();
        assert_ne!(instance.peer_id(), 0);
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    #[tokio::test]
    async fn runtime_updates_refresh_avoid_relay_preference() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "portable-runtime-update".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let (instance, ()) =
            build_portable_runtime_core_instance_with_transport_factory_and_process_runtime(
                global_ctx.clone(),
                Arc::new(packet_sink),
                NoWrappedTransportEngineFactory,
                CoreProcessRuntime::new(),
            )
            .unwrap();

        assert!(
            !instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut enabled = runtime_instance_config(&global_ctx).peer;
        Arc::make_mut(&mut enabled).avoid_relay_data_preference = true;
        instance.update_peer_runtime_snapshot(enabled).await;

        assert!(
            instance
                .node_snapshot()
                .await
                .feature_flags
                .avoid_relay_data
        );

        let mut disabled = runtime_instance_config(&global_ctx);
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_runtime_updates_keep_snapshot_and_derived_state_coherent() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "concurrent-runtime-update".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let (instance, ()) =
            build_portable_runtime_core_instance_with_transport_factory_and_process_runtime(
                global_ctx.clone(),
                Arc::new(packet_sink),
                NoWrappedTransportEngineFactory,
                CoreProcessRuntime::new(),
            )
            .unwrap();
        let instance = Arc::new(instance);
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();

        let original = instance.node_snapshot().await;
        let mut full = runtime_instance_config(&global_ctx);
        full.services.dhcp_ipv4 = true;
        full.services.acl.tcp_whitelist = vec!["80".to_owned()];
        {
            let peer = Arc::make_mut(&mut full.peer);
            peer.runtime.core.node.hostname = Some("full".to_owned());
            peer.runtime.core.routes.proxy_networks =
                vec![easytier_core::config::ProxyNetworkConfig {
                    real: easytier_core::config::IpPrefix {
                        address: "192.0.2.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    mapped: Some(easytier_core::config::IpPrefix {
                        address: "198.51.100.0".parse().unwrap(),
                        prefix_len: 24,
                    }),
                }];
        }
        let mut peer_only = runtime_instance_config(&global_ctx).peer;
        {
            let peer = Arc::make_mut(&mut peer_only);
            peer.runtime.core.node.hostname = Some("peer".to_owned());
            peer.runtime.core.routes.proxy_networks =
                vec![easytier_core::config::ProxyNetworkConfig {
                    real: easytier_core::config::IpPrefix {
                        address: "203.0.113.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    mapped: Some(easytier_core::config::IpPrefix {
                        address: "10.20.30.0".parse().unwrap(),
                        prefix_len: 24,
                    }),
                }];
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
        assert_eq!(
            instance.acl_whitelist_snapshot().tcp_ports,
            ["80".to_owned()]
        );
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

    #[tokio::test]
    async fn active_runtime_update_skips_unchanged_and_rejects_invalid_acl() {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            "invalid-active-acl-update".to_owned(),
            String::new(),
        )));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let (instance, ()) =
            build_portable_runtime_core_instance_with_transport_factory_and_process_runtime(
                global_ctx.clone(),
                Arc::new(packet_sink),
                NoWrappedTransportEngineFactory,
                CoreProcessRuntime::new(),
            )
            .unwrap();
        let instance = Arc::new(instance);
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();

        let mut unrelated = runtime_instance_config(&global_ctx);
        Arc::make_mut(&mut unrelated.peer)
            .runtime
            .core
            .node
            .hostname = Some("accepted".to_owned());
        instance.update_runtime_config(unrelated).await.unwrap();
        assert_eq!(instance.acl_reload_count_for_test(), 0);
        let before = instance.node_snapshot().await;

        let mut rejected = runtime_instance_config(&global_ctx);
        rejected.services.dhcp_ipv4 = true;
        rejected.services.acl.tcp_whitelist = vec!["invalid".to_owned()];
        Arc::make_mut(&mut rejected.peer).runtime.core.node.hostname = Some("rejected".to_owned());

        let error = instance.update_runtime_config(rejected).await.unwrap_err();

        assert!(error.to_string().contains("Invalid port number"));
        assert!(!instance.runtime_config_snapshot().dhcp_ipv4);
        assert!(instance.acl_whitelist_snapshot().tcp_ports.is_empty());
        assert_eq!(instance.acl_reload_count_for_test(), 0);
        assert_eq!(instance.node_snapshot().await.hostname, before.hostname);
        instance.stop().await;
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
        let transport_proxy = Arc::new(RecordingProxyService::default());
        let (instance, _cidr_table) = build_portable_test_instance_with_transport_factory(
            global_ctx,
            TestTransportProxyFactory {
                service: transport_proxy.clone(),
            },
        )
        .expect("runtime core composition should succeed");
        let instance = Arc::new(instance);

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
        assert!(instance.proxy_is_started());

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
        assert_eq!(transport_proxy.stop_calls.load(Ordering::Relaxed), 1);
        assert!(!instance.proxy_is_started());
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_wrapped_transport_destination_sessions() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.enable_kcp_proxy = false;
        flags.disable_kcp_input = false;
        global_ctx.set_flags(flags);
        let engine = Arc::new(RecordingProxyService::default());
        let (instance, ()) = build_portable_test_instance_with_transport_factory(
            global_ctx,
            TestTransportProxyFactory {
                service: engine.clone(),
            },
        )
        .expect("runtime core composition should succeed");
        let instance = Arc::new(instance);

        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert!(instance.wrapped_transport_is_started(
            WrappedTransportKind::Kcp,
            WrappedTransportRole::Destination,
        ));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination = listener.local_addr().unwrap();
        let ingress = engine
            .destination_ingress()
            .expect("core should inject a destination ingress");
        let (core_stream, peer_stream) = tokio::io::duplex(1024);
        ingress
            .submit(WrappedTransportAcceptedStream {
                src: "10.0.0.2:40000".parse().unwrap(),
                dst: destination,
                initial_acl_packet_size: 16,
                stream: Box::new(core_stream),
            })
            .await
            .unwrap();

        let (destination_stream, _) =
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("core should connect through the Host adapter")
                .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let entries = instance.wrapped_tcp_proxy_entry_snapshots(
                    WrappedTransportKind::Kcp,
                    WrappedTransportRole::Destination,
                );
                if entries.iter().any(|entry| {
                    entry.state
                        == easytier_core::proxy::tcp_proxy_engine::TcpNatEntryState::Connected
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
        tokio::time::timeout(Duration::from_secs(2), async {
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
            .submit(WrappedTransportAcceptedStream {
                src: "10.0.0.2:40001".parse().unwrap(),
                dst: destination,
                initial_acl_packet_size: 16,
                stream: Box::new(core_stream),
            })
            .await
            .unwrap();
        let (_blocked_destination_stream, _) =
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("second destination session should connect")
                .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
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

        tokio::time::timeout(Duration::from_secs(2), instance.stop())
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
                .submit(WrappedTransportAcceptedStream {
                    src: "10.0.0.2:40002".parse().unwrap(),
                    dst: destination,
                    initial_acl_packet_size: 16,
                    stream: Box::new(tokio::io::duplex(64).0),
                })
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn runtime_core_instance_owns_the_transport_proxy_cidr_table() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .add_proxy_cidr(
                "192.0.2.0/24".parse().unwrap(),
                Some("198.51.100.0/24".parse().unwrap()),
            )
            .unwrap();
        let transport_proxy = Arc::new(RecordingProxyService::default());
        let runtime_global_ctx = global_ctx.clone();
        let (instance, ()) = build_portable_test_instance_with_transport_factory(
            global_ctx,
            TestTransportProxyFactory {
                service: transport_proxy.clone(),
            },
        )
        .expect("runtime core composition should succeed");
        let instance = Arc::new(instance);

        assert!(instance.start_network_services(None).await.is_err());
        assert_eq!(instance.node_snapshot().await.proxy_networks.len(), 1);
        instance.start().await.unwrap();
        instance.start_network_services(None).await.unwrap();
        instance.start_network_services(None).await.unwrap();
        assert_eq!(transport_proxy.start_calls.load(Ordering::Relaxed), 1);

        let mut config = runtime_instance_config(&runtime_global_ctx);
        config.peer = Arc::new({
            let mut peer = config.peer.as_ref().clone();
            peer.runtime.core.routes.proxy_networks =
                vec![easytier_core::config::ProxyNetworkConfig {
                    real: easytier_core::config::IpPrefix {
                        address: "203.0.113.0".parse().unwrap(),
                        prefix_len: 24,
                    },
                    mapped: Some(easytier_core::config::IpPrefix {
                        address: "10.20.30.0".parse().unwrap(),
                        prefix_len: 24,
                    }),
                }];
            peer
        });
        instance.update_runtime_config(config).await.unwrap();
        let proxy_networks = instance.node_snapshot().await.proxy_networks;
        assert_eq!(proxy_networks.len(), 1);
        assert_eq!(
            proxy_networks[0].real.address,
            "203.0.113.0".parse::<std::net::IpAddr>().unwrap()
        );
        assert_eq!(
            proxy_networks[0].mapped.as_ref().unwrap().address,
            "10.20.30.0".parse::<std::net::IpAddr>().unwrap()
        );

        instance.stop().await;
        assert!(instance.start_network_services(None).await.is_err());
        assert_eq!(transport_proxy.stop_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn runtime_core_requires_explicit_proxy_policy_update() {
        let global_ctx = get_mock_global_ctx();
        let transport_proxy = Arc::new(RecordingProxyService::default());
        let (instance, _cidr_table) = build_portable_test_instance_with_transport_factory(
            global_ctx.clone(),
            TestTransportProxyFactory {
                service: transport_proxy.clone(),
            },
        )
        .expect("runtime core composition should succeed");
        let instance = Arc::new(instance);

        instance.start().await.unwrap();
        instance.start_transport_proxy().await.unwrap();
        instance.start_proxy().await.unwrap();
        assert_eq!(transport_proxy.start_calls.load(Ordering::Relaxed), 1);
        assert!(!instance.proxy_is_started());

        global_ctx
            .config
            .add_proxy_cidr("10.1.2.0/24".parse().unwrap(), None)
            .unwrap();
        instance.start_proxy().await.unwrap();
        assert!(!instance.proxy_is_started());

        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await
            .unwrap();
        instance.start_proxy().await.unwrap();
        assert!(instance.proxy_is_started());

        instance.stop().await;
        assert_eq!(transport_proxy.stop_calls.load(Ordering::Relaxed), 1);
        assert!(!instance.proxy_is_started());
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_acl_runtime_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let instance = Arc::new(
            build_portable_test_instance(global_ctx.clone())
                .expect("runtime core composition should succeed"),
        );
        assert_eq!(instance.acl_whitelist_snapshot(), Default::default());

        global_ctx
            .config
            .set_tcp_whitelist(vec!["invalid".to_string()]);
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await
            .unwrap();
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
    async fn runtime_core_owns_configured_transport_listener_lifecycle() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_listeners(vec!["tcp://127.0.0.1:0".parse().unwrap()]);
        let instance = Arc::new(
            build_portable_test_instance(global_ctx.clone())
                .expect("runtime core composition should succeed"),
        );

        instance.start().await.unwrap();
        let listeners = instance.running_listeners();
        assert_eq!(listeners.len(), 2);
        assert_eq!(
            listeners
                .iter()
                .filter(|listener| listener.scheme() == "tcp")
                .count(),
            1
        );
        instance.stop().await;
        assert!(instance.running_listeners().is_empty());
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn external_listener_uses_core_running_listener_registry() {
        let global_ctx = get_mock_global_ctx();
        let external_url: url::Url = "unix:///tmp/easytier-external-listener-test"
            .parse()
            .unwrap();
        let peer = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        let connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: Some(ListenerRuntimeConfig::new(
                vec![external_url.clone()],
                false,
                runtime_socket_context(&global_ctx),
            )),
            runtime: Default::default(),
            stun: runtime_stun_server_config(&global_ctx),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let mut adapters = runtime_core_instance_adapters(global_ctx);
        adapters.external_listener_factory = Some(Arc::new(TestExternalListenerFactory {
            kind: TestExternalListenerKind::Registry,
        }));
        let (packet_sink, _packet_receiver) = create_host_packet_channel();
        let instance = Arc::new(
            CoreInstance::new_portable(
                adapters,
                PortableCoreInstanceConfig { peer, connectivity },
                Arc::new(packet_sink),
            )
            .unwrap(),
        );

        instance.start().await.unwrap();
        let running = instance.running_listeners();
        assert_eq!(running.len(), 2);
        assert!(running.iter().any(|url| url.scheme() == "ring"));
        assert!(running.contains(&external_url));
        assert_eq!(instance.node_snapshot().await.listeners, running);

        instance.stop().await;
        assert!(instance.running_listeners().is_empty());
    }

    #[tokio::test]
    async fn runtime_core_accepts_explicit_dhcp_runtime_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let instance = Arc::new(
            build_portable_test_instance(global_ctx.clone())
                .expect("runtime core composition should succeed"),
        );

        global_ctx.config.set_dhcp(true);
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await
            .unwrap();
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
        let instance = Arc::new(
            build_portable_test_instance(global_ctx.clone())
                .expect("runtime core composition should succeed"),
        );

        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx
            .config
            .set_ipv6_public_addr_prefix(Some("fd00::/64".parse().unwrap()));
        instance
            .update_runtime_config(runtime_instance_config(&global_ctx))
            .await
            .unwrap();
        let error = instance.start().await.unwrap_err();
        assert!(
            error.to_string().contains("not a valid global unicast"),
            "unexpected public IPv6 activation error: {error:#}"
        );
        assert_eq!(instance.state(), CoreInstanceState::Created);
    }

    #[tokio::test]
    async fn stopping_while_transport_proxy_starts_rolls_back_once() {
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
        let proxy = Arc::new(BlockingProxyService::default());
        let (instance, _cidr_table) = build_portable_test_instance_with_transport_factory(
            global_ctx,
            TestTransportProxyFactory {
                service: proxy.clone(),
            },
        )
        .expect("runtime core composition should succeed");
        let instance = Arc::new(instance);
        instance.start().await.unwrap();
        instance.start_peer_center().await.unwrap();

        let start_task = tokio::spawn({
            let instance = instance.clone();
            async move { instance.start_transport_proxy().await }
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
        let instance = Arc::new(
            build_portable_test_instance(global_ctx)
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
        let peer = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        let connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: Some(ListenerRuntimeConfig::new(
                vec![
                    "tcp://127.0.0.1:0".parse().unwrap(),
                    "udp://127.0.0.1:0".parse().unwrap(),
                ],
                false,
                runtime_socket_context(&global_ctx),
            )),
            runtime: Default::default(),
            stun: runtime_stun_server_config(&global_ctx),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        let instance = Arc::new(
            NativeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_ctx),
                PortableCoreInstanceConfig { peer, connectivity },
                Arc::new(packet_sink),
            )
            .unwrap(),
        );

        assert!(instance.running_listeners().is_empty());
        instance.start().await.unwrap();
        let running_listeners = instance.running_listeners();
        assert_eq!(running_listeners.len(), 3);
        assert!(
            running_listeners
                .iter()
                .filter(|listener| matches!(listener.scheme(), "tcp" | "udp"))
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
        let peer_a = runtime_peer_manager_config(&global_a, RouteAlgoType::Ospf);
        let peer_b = runtime_peer_manager_config(&global_b, RouteAlgoType::Ospf);
        let instance_a = Arc::new(
            NativeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_a.clone()),
                PortableCoreInstanceConfig {
                    peer: peer_a,
                    connectivity: CoreInstanceConfig {
                        initial_peers: Vec::new(),
                        listeners: Some(ListenerRuntimeConfig::new(
                            vec!["tcp://127.0.0.1:0".parse().unwrap()],
                            false,
                            runtime_socket_context(&global_a),
                        )),
                        runtime: Default::default(),
                        stun: runtime_stun_server_config(&global_a),
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
            NativeCoreInstance::new_portable(
                runtime_core_instance_adapters(global_b.clone()),
                PortableCoreInstanceConfig {
                    peer: peer_b,
                    connectivity: CoreInstanceConfig {
                        initial_peers: Vec::new(),
                        listeners: None,
                        runtime: Default::default(),
                        stun: runtime_stun_server_config(&global_b),
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
        let peer = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        let mut connectivity = CoreInstanceConfig {
            initial_peers: Vec::new(),
            listeners: None,
            runtime: Default::default(),
            stun: runtime_stun_server_config(&global_ctx),
            endpoint_discovery: runtime_endpoint_discovery_config(&global_ctx),
            manual: runtime_manual_options(&global_ctx),
            direct: runtime_direct_options(&global_ctx, false),
        };
        connectivity.direct.disable_p2p = !peer.snapshot.flags.disable_p2p;

        let error = NativeCoreInstance::new_portable(
            runtime_core_instance_adapters(global_ctx),
            PortableCoreInstanceConfig { peer, connectivity },
            Arc::new(packet_sink),
        )
        .err()
        .expect("conflicting P2P policy should be rejected");

        assert!(error.to_string().contains("P2P policy"));
    }

    fn build_test_instance(network_name: &str) -> Arc<NativeCoreInstance> {
        let global_ctx = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
            network_name.to_owned(),
            String::new(),
        )));
        Arc::new(build_portable_test_instance(global_ctx).unwrap())
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
    #[cfg(unix)]
    async fn stop_cancels_pending_listener_start() {
        let listener = Arc::new(BlockingListenerState::default());
        let instance = build_test_instance_with_listener(
            "pending-listener",
            "unix:///tmp/easytier-pending-listener".parse().unwrap(),
            Arc::new(TestExternalListenerFactory {
                kind: TestExternalListenerKind::Blocking(listener.clone()),
            }),
        );
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
        assert_eq!(listener.drop_calls.load(Ordering::Relaxed), 1);
    }
}

use std::{sync::Arc, time::Duration};

use easytier_core::{
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{
            ManualConnectivityEvent, ManualConnectivityEventSink, ManualConnectorOptions,
            discovery::{CoreManualEndpointResolver, ManualEndpointDiscoveryConfig},
        },
        protocol::ClientProtocolUpgrader,
    },
    instance::{CoreInstance, CoreInstanceAdapters, CoreInstanceConfig},
    socket::{
        IpVersion, SocketContext,
        dns::{DnsRecordResolver, DnsResolver},
        tcp::TcpBindOptions,
        udp::UdpBindOptions,
    },
};
use strum::VariantArray as _;

use crate::{
    VERSION,
    common::{
        config::ConfigLoader as _,
        dns::RuntimeDnsResolver,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    instance::listeners::RuntimeListenerService,
    peers::peer_manager::PeerManager,
    tunnel::IpScheme,
    use_global_var,
};

use super::{protocol::RuntimeClientProtocolUpgrader, runtime::RuntimeConnectorHost};

pub(crate) type RuntimeCoreInstance = CoreInstance<RuntimeConnectorHost>;

struct GlobalCtxManualConnectivityEventSink {
    global_ctx: ArcGlobalCtx,
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
    let host = Arc::new(RuntimeConnectorHost::new(global_ctx.clone()));
    let dns: Arc<dyn DnsResolver> = Arc::new(RuntimeDnsResolver::new());
    let dns_records: Arc<dyn DnsRecordResolver> = Arc::new(RuntimeDnsResolver::new());
    let manual = runtime_manual_options(&global_ctx);
    let endpoint_resolver = Arc::new(CoreManualEndpointResolver::new(
        host.clone(),
        dns.clone(),
        dns_records,
        ManualEndpointDiscoveryConfig {
            user_agent: format!("easytier/{VERSION}"),
            network_name: global_ctx.network.network_name.clone(),
            http_timeout: Duration::from_secs(20),
            http_ip_version: IpVersion::Both,
            http_tcp_bind: manual.tcp_bind,
            dns_record_context: SocketContext::default(),
            srv_protocols: IpScheme::VARIANTS.iter().map(ToString::to_string).collect(),
        },
    ));
    CoreInstanceAdapters {
        host,
        dns,
        endpoint_resolver,
        protocol: Some(
            Arc::new(RuntimeClientProtocolUpgrader::new(global_ctx.clone()))
                as Arc<dyn ClientProtocolUpgrader<_>>,
        ),
        manual_events: Some(Arc::new(GlobalCtxManualConnectivityEventSink {
            global_ctx,
        })),
        listener: None,
        accepted_transport_handler: None,
        udp_hole_punch: None,
    }
}

pub(crate) fn build_runtime_core_instance(
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,
) -> anyhow::Result<RuntimeCoreInstance> {
    let config = CoreInstanceConfig {
        initial_peers: Vec::new(),
        listeners: Vec::new(),
        manual: runtime_manual_options(&global_ctx),
        direct: runtime_direct_options(&global_ctx, false),
    };
    let mut adapters = runtime_core_instance_adapters(global_ctx.clone());
    adapters.listener = Some(Arc::new(RuntimeListenerService::new(
        global_ctx,
        peer_manager.core(),
    )));
    adapters.udp_hole_punch = Some(Arc::new(super::udp_hole_punch::UdpHolePunchConnector::new(
        peer_manager.clone(),
    )));
    CoreInstance::new(peer_manager.core(), adapters, config)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use easytier_core::{
        instance::{CoreInstanceState, ListenerService, PortableCoreInstanceConfig},
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
        common::global_ctx::{
            NetworkIdentity,
            tests::{get_mock_global_ctx, get_mock_global_ctx_with_network},
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
        let (nic_channel, _nic_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            nic_channel,
        ));
        let instance = Arc::new(
            build_runtime_core_instance(global_ctx, peer_manager)
                .expect("runtime core composition should succeed"),
        );

        assert_eq!(instance.state(), CoreInstanceState::Created);
        instance.start_listeners().await.unwrap();
        instance.start_listeners().await.unwrap();
        instance.start().await.unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Running);
        assert!(instance.start_listeners().await.is_err());
        assert!(instance.start().await.is_err());
        instance.start_udp_hole_punch().await.unwrap();
        instance.start_udp_hole_punch().await.unwrap();

        instance.stop().await;
        instance.stop().await;
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
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
        instance.start_listeners().await.unwrap();
        let running_listeners = instance.running_listeners();
        assert_eq!(running_listeners.len(), 2);
        assert!(
            running_listeners
                .iter()
                .all(|listener| listener.port().is_some_and(|port| port != 0))
        );
        instance.start().await.unwrap();
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
                        manual: Default::default(),
                        direct: runtime_direct_options(&global_b, true),
                    },
                },
                Arc::new(packet_sink_b),
            )
            .unwrap(),
        );

        instance_a.start_listeners().await.unwrap();
        let listener = instance_a.running_listeners().pop().unwrap();
        let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
        start_a.unwrap();
        start_b.unwrap();
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
        Arc::new(build_runtime_core_instance(global_ctx, peer_manager).unwrap())
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
        let start_task = AbortOnDropHandle::new(tokio::spawn(async move {
            start_instance.start_listeners().await
        }));
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

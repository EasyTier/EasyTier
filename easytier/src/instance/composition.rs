use std::sync::Arc;

#[cfg(feature = "wireguard")]
use easytier_core::gateway::vpn_portal::VpnPortalHost;
#[cfg(feature = "smoltcp")]
use easytier_core::gateway::{GatewayEvent, GatewayEventSink};
use easytier_core::{
    connectivity::manual::{
        ManualConnectivityEvent, ManualConnectivityEventSink, ManualTunnelConnector,
    },
    gateway::proxy::wrapped_transport::WrappedTransportEngines,
    gateway::vpn_portal::{VpnPortalEvent, VpnPortalEventSink},
    host::dns::{DnsRecordResolver, DnsResolver},
    host::packet::PacketSink,
    instance::{CoreHostAdapters, CoreInstance, CoreInstanceConfig},
    peers::peer_manager::RouteAlgoType,
    process_runtime::CoreProcessRuntime,
};

use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    host_runtime::native_host_runtime,
    instance::config::{
        runtime_connectivity_config, runtime_endpoint_discovery_config, runtime_manual_options,
        runtime_peer_manager_config, runtime_peer_manager_host_adapters,
    },
    instance::listeners::{GlobalCtxListenerEvents, RuntimeExternalListenerFactory},
    instance::proxy_cidrs_monitor::runtime_proxy_cidr_monitor_host,
    instance::public_ipv6_provider::runtime_public_ipv6_provider_platform,
};

use super::host::{NativeInstanceHost, native_instance_host};
#[cfg(feature = "kcp")]
use crate::gateway::kcp_proxy::KcpProxyService;
#[cfg(feature = "quic")]
use crate::gateway::quic_proxy::QuicProxyService;
use crate::tunnel::protocol::{runtime_client_protocol_upgrader, runtime_server_protocol_upgrader};
#[cfg(any(feature = "kcp", feature = "quic"))]
use easytier_core::gateway::proxy::wrapped_transport::WrappedTransportEngine;

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

fn runtime_wrapped_transport_engines() -> WrappedTransportEngines {
    #[cfg(feature = "kcp")]
    let kcp = Some(Arc::new(KcpProxyService::new()) as Arc<dyn WrappedTransportEngine>);
    #[cfg(not(feature = "kcp"))]
    let kcp = None;
    #[cfg(feature = "quic")]
    let quic = Some(Arc::new(QuicProxyService::new()) as Arc<dyn WrappedTransportEngine>);
    #[cfg(not(feature = "quic"))]
    let quic = None;

    WrappedTransportEngines { kcp, quic }
}

pub(crate) fn runtime_core_host_adapters(
    global_ctx: ArcGlobalCtx,
    process_runtime: Arc<CoreProcessRuntime>,
    packet_sink: Arc<dyn PacketSink>,
) -> CoreHostAdapters<NativeInstanceHost> {
    let host = native_instance_host(global_ctx.clone());
    let runtime_dns = native_host_runtime();
    let mut adapters = CoreHostAdapters::new(host, runtime_dns, packet_sink, process_runtime);
    adapters.peer_adapters = runtime_peer_manager_host_adapters(&global_ctx);
    adapters.wrapped_transports = runtime_wrapped_transport_engines();
    adapters.protocol = Some(runtime_client_protocol_upgrader(global_ctx.clone()));
    adapters.manual_events = Some(Arc::new(GlobalCtxManualConnectivityEventSink {
        global_ctx: global_ctx.clone(),
    }));
    let listener_events = Arc::new(GlobalCtxListenerEvents::new(global_ctx.clone()));
    adapters.external_listener_factory = Some(Arc::new(RuntimeExternalListenerFactory));
    adapters.listener_events = Some(listener_events.clone());
    adapters.server_protocol = Some(runtime_server_protocol_upgrader(global_ctx.clone()));
    adapters.accepted_tunnel_events = Some(listener_events);
    adapters.udp_hole_punch_platform = Some(
        crate::instance::udp_hole_punch::runtime_udp_hole_punch_platform(global_ctx.net_ns.clone()),
    );
    adapters.udp_hole_punch_events = Some(
        crate::instance::udp_hole_punch::runtime_udp_port_mapping_event_sink(global_ctx.clone()),
    );
    #[cfg(not(test))]
    {
        adapters.icmp_proxy_host = Some(Arc::new(crate::gateway::icmp_proxy::RuntimeIcmpProxyHost));
    }
    adapters.proxy_cidr_monitor = Some(runtime_proxy_cidr_monitor_host(global_ctx.clone()));
    adapters.public_ipv6_host = Some(global_ctx.clone());
    adapters.public_ipv6_provider = Some(runtime_public_ipv6_provider_platform(&global_ctx));
    #[cfg(feature = "wireguard")]
    {
        use crate::common::config::ConfigLoader as _;

        adapters.vpn_portal = Some(crate::vpn_portal::wireguard::WireGuardPortalHost::new(
            global_ctx.clone(),
            global_ctx
                .config
                .get_vpn_portal_config()
                .map(|config| config.wireguard_listen),
        ) as Arc<dyn VpnPortalHost>);
    }
    adapters.vpn_portal_events = Some(Arc::new(GlobalCtxVpnPortalEventSink {
        global_ctx: global_ctx.clone(),
    }));
    #[cfg(feature = "smoltcp")]
    {
        adapters.gateway_events = Some(Arc::new(GlobalCtxGatewayEventSink { global_ctx }));
    }
    adapters
}

pub(crate) fn runtime_core_instance_config(global_ctx: &ArcGlobalCtx) -> CoreInstanceConfig {
    CoreInstanceConfig {
        peer: runtime_peer_manager_config(global_ctx, RouteAlgoType::Ospf),
        connectivity: runtime_connectivity_config(global_ctx),
    }
}

pub(crate) fn runtime_one_shot_manual_connector(
    global_ctx: ArcGlobalCtx,
    process_runtime: Arc<CoreProcessRuntime>,
) -> ManualTunnelConnector<NativeInstanceHost> {
    let host = native_instance_host(global_ctx.clone());
    let runtime_dns = native_host_runtime();
    let dns: Arc<dyn DnsResolver> = runtime_dns.clone();
    let dns_records: Arc<dyn DnsRecordResolver> = runtime_dns;
    process_runtime.manual_connector(
        host,
        dns,
        dns_records,
        runtime_client_protocol_upgrader(global_ctx.clone()),
        runtime_endpoint_discovery_config(&global_ctx),
        runtime_manual_options(&global_ctx),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    #[cfg(feature = "kcp")]
    use easytier_core::gateway::proxy::wrapped_transport::{
        WrappedTransportConnect, WrappedTransportEngine,
    };
    use easytier_core::{
        instance::{CoreConnectivityConfig, CoreInstanceConfig},
        listener::plan::ListenerRuntimeConfig,
    };
    use pnet::packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket},
    };
    #[cfg(feature = "kcp")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[cfg(feature = "kcp")]
    use crate::gateway::kcp_proxy::KcpProxyService;
    use crate::{
        common::{config::NetworkIdentity, global_ctx::tests::get_mock_global_ctx_with_network},
        instance::config::{
            runtime_direct_options, runtime_socket_context, runtime_stun_server_config,
        },
    };

    use super::*;

    fn create_host_packet_channel() -> (
        tokio::sync::mpsc::Sender<Vec<u8>>,
        tokio::sync::mpsc::Receiver<Vec<u8>>,
    ) {
        tokio::sync::mpsc::channel(16)
    }

    #[cfg(feature = "kcp")]
    fn build_native_kcp_test_instance(
        global_ctx: ArcGlobalCtx,
        packet_sink: tokio::sync::mpsc::Sender<Vec<u8>>,
        listeners: Option<ListenerRuntimeConfig>,
    ) -> anyhow::Result<(Arc<NativeCoreInstance>, Arc<KcpProxyService>)> {
        let mut adapters = runtime_core_host_adapters(
            global_ctx.clone(),
            CoreProcessRuntime::new(),
            Arc::new(packet_sink),
        );
        adapters.proxy_cidr_monitor = None;
        let service = Arc::new(KcpProxyService::new());
        adapters.wrapped_transports = WrappedTransportEngines {
            kcp: Some(service.clone()),
            quic: None,
        };

        let mut connectivity = runtime_connectivity_config(&global_ctx);
        connectivity.listeners = listeners;
        connectivity.startup_plan.gateway = false;
        connectivity.stun.udp_servers.clear();
        connectivity.stun.tcp_servers.clear();
        connectivity.stun.udp_v6_servers.clear();
        connectivity.manual = Default::default();
        connectivity.direct = runtime_direct_options(&global_ctx, true);

        let instance = NativeCoreInstance::new(
            CoreInstanceConfig {
                peer: runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf),
                connectivity,
            },
            adapters,
        )?;
        Ok((instance, service))
    }

    #[cfg(feature = "kcp")]
    #[tokio::test]
    async fn native_kcp_engine_round_trips_through_portable_cores() {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            const REQUEST: &[u8] = b"native-kcp-request";
            const REPLY: &[u8] = b"native-kcp-reply";

            let global_a = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "native-kcp-round-trip".to_owned(),
                "shared-secret".to_owned(),
            )));
            let global_b = get_mock_global_ctx_with_network(Some(NetworkIdentity::new(
                "native-kcp-round-trip".to_owned(),
                "shared-secret".to_owned(),
            )));
            global_a.set_ipv4(Some("10.250.0.1/24".parse().unwrap()));
            global_b.set_ipv4(Some("10.250.0.2/24".parse().unwrap()));

            let mut flags_a = global_a.get_flags();
            flags_a.enable_kcp_proxy = true;
            flags_a.disable_kcp_input = true;
            flags_a.disable_tcp_hole_punching = true;
            flags_a.disable_udp_hole_punching = true;
            flags_a.disable_sym_hole_punching = true;
            flags_a.disable_upnp = true;
            global_a.set_flags(flags_a);

            let mut flags_b = global_b.get_flags();
            flags_b.enable_kcp_proxy = false;
            flags_b.disable_kcp_input = false;
            flags_b.disable_tcp_hole_punching = true;
            flags_b.disable_udp_hole_punching = true;
            flags_b.disable_sym_hole_punching = true;
            flags_b.disable_upnp = true;
            global_b.set_flags(flags_b);

            let (packet_sink_a, _packet_receiver_a) = create_host_packet_channel();
            let (packet_sink_b, _packet_receiver_b) = create_host_packet_channel();
            let (instance_a, kcp_a) = build_native_kcp_test_instance(
                global_a.clone(),
                packet_sink_a,
                Some(ListenerRuntimeConfig::new(
                    vec!["tcp://127.0.0.1:0".parse().unwrap()],
                    false,
                    runtime_socket_context(&global_a),
                )),
            )
            .unwrap();
            let (instance_b, _kcp_b) =
                build_native_kcp_test_instance(global_b, packet_sink_b, None).unwrap();

            let (start_a, start_b) = tokio::join!(instance_a.start(), instance_b.start());
            start_a.unwrap();
            start_b.unwrap();
            let (ready_a, ready_b) = tokio::join!(
                instance_a.start_after_host_ready(None),
                instance_b.start_after_host_ready(None)
            );
            ready_a.unwrap();
            ready_b.unwrap();

            let listener = instance_a.running_listeners().pop().unwrap();
            instance_b.add_connector(listener).unwrap();
            let peer_a_id = instance_a.peer_id();
            let peer_b_id = instance_b.peer_id();
            loop {
                let a_peers = instance_a.connected_peers().await;
                let b_peers = instance_b.connected_peers().await;
                if a_peers.contains(&peer_b_id) && b_peers.contains(&peer_a_id) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }

            let echo_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_addr = echo_listener.local_addr().unwrap();
            let responder = tokio::spawn(async move {
                let (mut socket, _) = echo_listener.accept().await.unwrap();
                let mut request = [0; REQUEST.len()];
                socket.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, REQUEST);
                socket.write_all(REPLY).await.unwrap();
            });

            let mut stream = kcp_a
                .connect_source(WrappedTransportConnect {
                    my_peer_id: peer_a_id,
                    dst_peer_id: peer_b_id,
                    src: "10.250.0.1:40000".parse().unwrap(),
                    dst: echo_addr,
                })
                .await
                .unwrap();
            stream.write_all(REQUEST).await.unwrap();
            let mut reply = [0; REPLY.len()];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, REPLY);
            responder.await.unwrap();

            instance_b.stop().await;
            instance_a.stop().await;
        })
        .await
        .expect("native KCP round trip timed out");
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
        let instance_a = NativeCoreInstance::new(
            CoreInstanceConfig {
                peer: peer_a,
                connectivity: CoreConnectivityConfig {
                    initial_peers: Vec::new(),
                    listeners: Some(ListenerRuntimeConfig::new(
                        vec!["tcp://127.0.0.1:0".parse().unwrap()],
                        false,
                        runtime_socket_context(&global_a),
                    )),
                    runtime: Default::default(),
                    startup_plan: Default::default(),
                    stun: runtime_stun_server_config(&global_a),
                    endpoint_discovery: runtime_endpoint_discovery_config(&global_a),
                    manual: Default::default(),
                    direct: runtime_direct_options(&global_a, true),
                },
            },
            runtime_core_host_adapters(
                global_a.clone(),
                CoreProcessRuntime::new(),
                Arc::new(packet_sink_a),
            ),
        )
        .unwrap();
        let instance_b = NativeCoreInstance::new(
            CoreInstanceConfig {
                peer: peer_b,
                connectivity: CoreConnectivityConfig {
                    initial_peers: Vec::new(),
                    listeners: None,
                    runtime: Default::default(),
                    startup_plan: Default::default(),
                    stun: runtime_stun_server_config(&global_b),
                    endpoint_discovery: runtime_endpoint_discovery_config(&global_b),
                    manual: Default::default(),
                    direct: runtime_direct_options(&global_b, true),
                },
            },
            runtime_core_host_adapters(
                global_b.clone(),
                CoreProcessRuntime::new(),
                Arc::new(packet_sink_b),
            ),
        )
        .unwrap();

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
                instance_a
                    .packet_plane()
                    .send_ip_packet(ip_packet.clone())
                    .await
                    .unwrap();
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
}

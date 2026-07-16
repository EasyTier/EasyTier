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
    connectivity::manual::{
        ManualConnectivityEvent, ManualConnectivityEventSink, ManualTunnelConnector,
    },
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
        runtime_connectivity_config, runtime_endpoint_discovery_config, runtime_manual_options,
        runtime_peer_manager_config, runtime_peer_manager_host_adapters,
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
                use crate::common::config::ConfigLoader as _;

                Some(crate::vpn_portal::wireguard::WireGuardPortalHost::new(
                    global_ctx.clone(),
                    global_ctx
                        .config
                        .get_vpn_portal_config()
                        .map(|config| config.wireguard_listen),
                ) as Arc<dyn VpnPortalHost>)
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
    use std::sync::Arc;

    use easytier_core::{
        instance::{CoreInstanceConfig, PortableCoreInstanceConfig},
        listener::plan::ListenerRuntimeConfig,
    };
    use pnet::packet::{
        ip::IpNextHeaderProtocols,
        ipv4::{self, MutableIpv4Packet},
        udp::{self, MutableUdpPacket},
    };

    use crate::{
        common::global_ctx::{NetworkIdentity, tests::get_mock_global_ctx_with_network},
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
                runtime_core_instance_adapters_with_process_runtime(
                    global_a.clone(),
                    CoreProcessRuntime::new(),
                ),
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
                        startup_plan: Default::default(),
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
                runtime_core_instance_adapters_with_process_runtime(
                    global_b.clone(),
                    CoreProcessRuntime::new(),
                ),
                PortableCoreInstanceConfig {
                    peer: peer_b,
                    connectivity: CoreInstanceConfig {
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
}

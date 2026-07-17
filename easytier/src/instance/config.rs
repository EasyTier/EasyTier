use std::{sync::Arc, time::Duration};

use easytier_core::peers::context::{
    HostRoutingPolicy, NetworkIdentity as CoreNetworkIdentity, PeerCredentialEventSink, PeerEvent,
    PeerEventSink, PeerRuntimeSnapshot, PeerRuntimeSnapshotInput,
};
use easytier_core::peers::peer_manager::{
    PeerManagerHostAdapters, PortablePeerManagerConfig, RouteAlgoType,
};
use easytier_core::{
    config::runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfig},
    config::{IpPrefix, NodeConfig, ProxyNetworkConfig, RouteConfig},
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{ManualConnectorOptions, discovery::ManualEndpointDiscoveryConfig},
    },
    instance::{CoreConnectivityConfig, CoreInstanceStartupPlan},
    listener::plan::ListenerRuntimeConfig,
    peers::acl_config::AclRuleConfig,
    proxy::{ProxyRuntimeConfig, gateway::GatewayRuntimeConfig},
    socket::{IpVersion, NetNamespace, SocketContext, tcp::TcpBindOptions, udp::UdpBindOptions},
    stun::StunServerConfig,
};

use crate::{
    VERSION,
    common::{
        config::{ConfigLoader as _, TomlConfigLoader},
        constants::{
            DIRECT_CONNECT_TO_PUBLIC_SERVER, EASYTIER_VERSION, HMAC_SECRET_DIGEST,
            MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK,
            OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC,
        },
        credential_manager::runtime_credential_storage,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        stun::{default_tcp_stun_servers, default_udp_stun_servers, default_udp_v6_stun_servers},
    },
    instance::public_ipv6_provider::runtime_public_ipv6_provider_config,
    tunnel::IpScheme,
};
use strum::VariantArray as _;

pub(crate) fn runtime_acl_config(global_ctx: &ArcGlobalCtx) -> AclRuleConfig {
    AclRuleConfig {
        acl: global_ctx.config.get_acl(),
        tcp_whitelist: global_ctx.config.get_tcp_whitelist(),
        udp_whitelist: global_ctx.config.get_udp_whitelist(),
        whitelist_priority: None,
    }
}

pub(crate) fn runtime_core_config(global_ctx: &ArcGlobalCtx) -> CoreRuntimeConfig {
    CoreRuntimeConfig {
        acl: runtime_acl_config(global_ctx),
        dhcp_ipv4: global_ctx.config.get_dhcp(),
        gateway: GatewayRuntimeConfig {
            socks5_bind: global_ctx.config.get_socks5_portal().map(|proxy_url| {
                format!(
                    "{}:{}",
                    proxy_url.host_str().unwrap(),
                    proxy_url.port().unwrap()
                )
                .parse()
                .unwrap()
            }),
            port_forwards: global_ctx.config.get_port_forwards(),
        },
        manual_routes: global_ctx
            .config
            .get_routes()
            .map(|routes| routes.into_iter().collect()),
        proxy: runtime_proxy_startup_context(global_ctx),
        public_ipv6_auto: global_ctx.config.get_ipv6_public_addr_auto(),
        public_ipv6_provider: runtime_public_ipv6_provider_config(global_ctx),
    }
}

pub(crate) fn runtime_instance_config(global_ctx: &ArcGlobalCtx) -> CoreInstanceRuntimeConfig {
    CoreInstanceRuntimeConfig {
        services: runtime_core_config(global_ctx),
        peer: Arc::new(runtime_peer_manager_config(global_ctx, RouteAlgoType::Ospf).snapshot),
    }
}

pub(crate) fn runtime_proxy_startup_context(global_ctx: &ArcGlobalCtx) -> ProxyRuntimeConfig {
    ProxyRuntimeConfig {
        enable_exit_node: global_ctx.enable_exit_node(),
        no_tun: global_ctx.no_tun(),
        forward_by_system: global_ctx.proxy_forward_by_system(),
        force_smoltcp: cfg!(feature = "smoltcp")
            && (global_ctx.get_flags().use_smoltcp
                || global_ctx.no_tun()
                || cfg!(any(
                    target_os = "android",
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne"),
                    target_env = "ohos"
                ))),
        icmp_failure_is_fatal: cfg!(not(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        ))),
        udp_response_ipv4_mtu: 1280,
    }
}

pub(crate) fn runtime_manual_options(global_ctx: &ArcGlobalCtx) -> ManualConnectorOptions {
    let flags = global_ctx.config.get_flags();
    let socket_context = runtime_socket_context(global_ctx);
    ManualConnectorOptions {
        reconnect_interval: Duration::from_millis(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS),
        connect_timeout: Duration::from_secs(2),
        endpoint_discovery_timeout: Duration::from_secs(20),
        bind_device: flags.bind_device,
        allow_interface_bind: !cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        tcp_bind: TcpBindOptions::default().with_context(socket_context.clone()),
        udp_bind: UdpBindOptions::direct_connect().with_context(socket_context),
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
        dns_record_context: runtime_socket_context(global_ctx),
        srv_protocols: IpScheme::VARIANTS.iter().map(ToString::to_string).collect(),
    }
}

pub(crate) fn runtime_direct_options(
    global_ctx: &ArcGlobalCtx,
    testing: bool,
) -> DirectConnectorOptions {
    let flags = global_ctx.config.get_flags();
    let socket_context = runtime_socket_context(global_ctx);
    DirectConnectorOptions {
        network_name: global_ctx.get_network_name(),
        default_protocol: flags.default_protocol,
        enable_ipv6: flags.enable_ipv6,
        allow_public_server: DIRECT_CONNECT_TO_PUBLIC_SERVER,
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
        tcp_bind: TcpBindOptions::default().with_context(socket_context.clone()),
        udp_bind: UdpBindOptions::direct_connect().with_context(socket_context),
        testing,
    }
}

pub(crate) fn runtime_socket_context(global_ctx: &ArcGlobalCtx) -> SocketContext {
    SocketContext::default()
        .with_socket_mark(global_ctx.config.get_flags().socket_mark)
        .with_netns(global_ctx.net_ns.name().map(NetNamespace::new))
}

pub(crate) fn runtime_stun_server_config(global_ctx: &ArcGlobalCtx) -> StunServerConfig {
    StunServerConfig {
        udp_servers: global_ctx
            .config
            .get_stun_servers()
            .unwrap_or_else(default_udp_stun_servers),
        tcp_servers: default_tcp_stun_servers(),
        udp_v6_servers: global_ctx
            .config
            .get_stun_servers_v6()
            .unwrap_or_else(default_udp_v6_stun_servers),
    }
}

pub(crate) fn runtime_connectivity_config(global_ctx: &ArcGlobalCtx) -> CoreConnectivityConfig {
    CoreConnectivityConfig {
        initial_peers: global_ctx
            .config
            .get_peers()
            .into_iter()
            .map(|peer| peer.uri)
            .collect(),
        listeners: Some(ListenerRuntimeConfig::new(
            global_ctx.config.get_listener_uris(),
            global_ctx.config.get_flags().enable_ipv6,
            runtime_socket_context(global_ctx),
        )),
        runtime: runtime_core_config(global_ctx),
        startup_plan: CoreInstanceStartupPlan {
            gateway: cfg!(feature = "socks5"),
        },
        stun: runtime_stun_server_config(global_ctx),
        endpoint_discovery: runtime_endpoint_discovery_config(global_ctx),
        manual: runtime_manual_options(global_ctx),
        direct: runtime_direct_options(global_ctx, false),
    }
}

/// Normalizes one native configuration version for the core peer graph.
pub(crate) fn runtime_peer_manager_config(
    global_ctx: &ArcGlobalCtx,
    route_algo: RouteAlgoType,
) -> PortablePeerManagerConfig {
    let acl = global_ctx.config.get_acl();
    let flags = global_ctx.get_flags();
    let identity = global_ctx.get_network_identity();
    let network_identity = CoreNetworkIdentity::from(identity);
    let hostname = global_ctx.get_hostname();
    let proxy_networks = global_ctx
        .config
        .get_proxy_cidrs()
        .into_iter()
        .map(|proxy| ProxyNetworkConfig {
            real: IpPrefix {
                address: proxy.cidr.first_address().into(),
                prefix_len: proxy.cidr.network_length(),
            },
            mapped: proxy.mapped_cidr.map(|mapped| IpPrefix {
                address: mapped.first_address().into(),
                prefix_len: mapped.network_length(),
            }),
        })
        .collect();
    // Public-IPv6 provider state is live host state projected through
    // `PeerPublicIpv6State`, not submitted config.
    let snapshot = PeerRuntimeSnapshot::from_host_input(PeerRuntimeSnapshotInput {
        node: NodeConfig {
            peer_id: None,
            instance_id: Some(*global_ctx.get_id().as_bytes()),
            hostname: (!hostname.is_empty()).then_some(hostname),
            network_name: network_identity.network_name.clone(),
        },
        routes: RouteConfig {
            ipv4: global_ctx.get_ipv4().map(|value| IpPrefix {
                address: value.address().into(),
                prefix_len: value.network_length(),
            }),
            ipv6: global_ctx.get_ipv6().map(|value| IpPrefix {
                address: value.address().into(),
                prefix_len: value.network_length(),
            }),
            proxy_networks,
            ..Default::default()
        },
        network_identity,
        stun_info: Default::default(),
        flags,
        secure_mode: global_ctx.config.get_secure_mode(),
        host_routing: HostRoutingPolicy {
            local_exit_node_fallback: cfg!(target_env = "ohos"),
        },
        acl,
        easytier_version: EASYTIER_VERSION.to_owned(),
        vpn_portal_cidr: global_ctx.get_vpn_portal_cidr(),
        pinned_peers: global_ctx
            .config
            .get_peers()
            .into_iter()
            .map(|peer| (peer.uri, peer.peer_public_key))
            .collect(),
        ospf_update_my_foreign_network_interval_sec:
            OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC,
        max_direct_conns_per_peer_in_foreign_network: MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK
            as usize,
        hmac_secret_digest: HMAC_SECRET_DIGEST,
    });
    PortablePeerManagerConfig {
        snapshot,
        route_algo,
        exit_nodes: global_ctx.config.get_exit_nodes(),
        foreign_context_default_flags: TomlConfigLoader::default().get_flags(),
    }
}

pub(crate) struct GlobalCtxPeerEventSink {
    global_ctx: ArcGlobalCtx,
}

impl GlobalCtxPeerEventSink {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

impl PeerEventSink for GlobalCtxPeerEventSink {
    fn issue_event(&self, event: PeerEvent) {
        let event = match event {
            PeerEvent::PeerAdded(peer_id) => GlobalCtxEvent::PeerAdded(peer_id),
            PeerEvent::PeerRemoved(peer_id) => GlobalCtxEvent::PeerRemoved(peer_id),
            PeerEvent::PeerConnAdded(info) => GlobalCtxEvent::PeerConnAdded(info.into()),
            PeerEvent::PeerConnRemoved(info) => GlobalCtxEvent::PeerConnRemoved(info.into()),
        };
        self.global_ctx.issue_event(event);
    }
}

impl PeerCredentialEventSink for GlobalCtxPeerEventSink {
    fn credential_changed(&self) {
        self.global_ctx
            .issue_event(GlobalCtxEvent::CredentialChanged);
    }
}

pub(crate) fn runtime_peer_manager_host_adapters(
    global_ctx: &ArcGlobalCtx,
) -> PeerManagerHostAdapters {
    let event_sink = Arc::new(GlobalCtxPeerEventSink::new(global_ctx.clone()));
    PeerManagerHostAdapters {
        event_sink: event_sink.clone(),
        credential_storage: runtime_credential_storage(global_ctx.config.get_credential_file()),
        credential_event_sink: event_sink,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::{PeerConfig, VpnPortalConfig},
        global_ctx::tests::get_mock_global_ctx,
    };

    #[test]
    fn native_connectivity_config_maps_owned_runtime_inputs() {
        let global_ctx = get_mock_global_ctx();
        let peer_url: url::Url = "tcp://127.0.0.1:29999".parse().unwrap();
        let public_ipv6_prefix = "2001:db8:1::/64".parse().unwrap();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: peer_url.clone(),
            peer_public_key: None,
        }]);
        global_ctx.config.set_dhcp(true);
        global_ctx.config.set_tcp_whitelist(vec!["80".to_owned()]);
        global_ctx.config.set_udp_whitelist(vec!["53".to_owned()]);
        global_ctx.config.set_ipv6_public_addr_auto(true);
        global_ctx.config.set_ipv6_public_addr_provider(true);
        global_ctx
            .config
            .set_ipv6_public_addr_prefix(Some(public_ipv6_prefix));

        let config = runtime_connectivity_config(&global_ctx);

        assert_eq!(config.initial_peers, [peer_url]);
        assert!(config.runtime.dhcp_ipv4);
        assert_eq!(config.runtime.acl.tcp_whitelist, ["80"]);
        assert_eq!(config.runtime.acl.udp_whitelist, ["53"]);
        assert_eq!(config.startup_plan.gateway, cfg!(feature = "socks5"));
        assert!(config.runtime.public_ipv6_auto);
        assert!(config.runtime.public_ipv6_provider.provider_enabled);
        assert_eq!(
            config.runtime.public_ipv6_provider.configured_prefix,
            Some(public_ipv6_prefix)
        );
    }

    #[test]
    fn runtime_stun_config_normalizes_native_server_selection() {
        let global_ctx = get_mock_global_ctx();
        global_ctx
            .config
            .set_stun_servers(Some(vec!["stun-v4.example".to_owned()]));
        global_ctx
            .config
            .set_stun_servers_v6(Some(vec!["stun-v6.example".to_owned()]));

        let config = runtime_stun_server_config(&global_ctx);

        assert_eq!(config.udp_servers, vec!["stun-v4.example"]);
        assert_eq!(config.udp_v6_servers, vec!["stun-v6.example"]);
        assert_eq!(config.tcp_servers, default_tcp_stun_servers());
    }

    #[test]
    fn runtime_proxy_config_normalizes_platform_policy() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.use_smoltcp = true;
        global_ctx.set_flags(flags);

        let config = runtime_proxy_startup_context(&global_ctx);

        assert_eq!(config.force_smoltcp, cfg!(feature = "smoltcp"));
        assert_eq!(
            config.icmp_failure_is_fatal,
            cfg!(not(any(
                target_os = "android",
                target_os = "ios",
                all(target_os = "macos", feature = "macos-ne"),
                target_env = "ohos"
            )))
        );
        assert_eq!(config.udp_response_ipv4_mtu, 1280);
    }

    #[tokio::test]
    async fn peer_event_sink_projects_core_events_to_global_context() {
        let global_ctx = get_mock_global_ctx();
        let mut events = global_ctx.subscribe();
        let sink = GlobalCtxPeerEventSink::new(global_ctx);

        sink.issue_event(PeerEvent::PeerAdded(7));

        assert!(matches!(
            events.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(7)
        ));
    }

    #[tokio::test]
    async fn credential_event_sink_projects_core_changes_to_global_context() {
        let global_ctx = get_mock_global_ctx();
        let mut events = global_ctx.subscribe();
        let sink = GlobalCtxPeerEventSink::new(global_ctx);

        sink.credential_changed();

        assert!(matches!(
            events.recv().await.unwrap(),
            GlobalCtxEvent::CredentialChanged
        ));
    }

    #[test]
    fn native_peer_config_submits_host_inputs_and_manager_settings() {
        let global_ctx = get_mock_global_ctx();
        let peer_url: url::Url = "tcp://127.0.0.1:29999".parse().unwrap();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: peer_url.clone(),
            peer_public_key: Some("peer-key".to_owned()),
        }]);
        global_ctx.config.set_vpn_portal_config(VpnPortalConfig {
            client_cidr: "10.30.0.0/24".parse().unwrap(),
            wireguard_listen: "127.0.0.1:11010".parse().unwrap(),
        });
        global_ctx.set_hostname("native-host".to_owned());
        global_ctx.set_ipv4(Some("10.20.0.7/16".parse().unwrap()));
        let mut flags = global_ctx.get_flags();
        flags.relay_network_whitelist = "*".to_owned();
        global_ctx.set_flags(flags.clone());
        let exit_node = "192.0.2.9".parse().unwrap();
        global_ctx.config.set_exit_nodes(vec![exit_node]);

        let config = runtime_peer_manager_config(&global_ctx, RouteAlgoType::None);
        let runtime = &config.snapshot.runtime;

        assert_eq!(config.route_algo, RouteAlgoType::None);
        assert_eq!(config.exit_nodes, vec![exit_node]);
        assert_eq!(config.snapshot.flags, flags);
        assert_eq!(
            config.foreign_context_default_flags,
            TomlConfigLoader::default().get_flags()
        );
        assert_eq!(
            runtime.core.node.instance_id,
            Some(*global_ctx.get_id().as_bytes())
        );
        assert_eq!(runtime.core.node.hostname.as_deref(), Some("native-host"));
        assert_eq!(
            runtime.core.node.network_name,
            global_ctx.get_network_name()
        );
        assert_eq!(
            runtime.core.routes.ipv4,
            Some(IpPrefix::new("10.20.0.7".parse().unwrap(), 16).unwrap())
        );
        assert_eq!(config.snapshot.easytier_version, EASYTIER_VERSION);
        assert_eq!(
            config.snapshot.vpn_portal_cidr,
            Some("10.30.0.0/24".parse().unwrap())
        );
        assert_eq!(
            config.snapshot.pinned_peers,
            vec![(peer_url, Some("peer-key".to_owned()))]
        );
        assert_eq!(
            runtime.host_routing.local_exit_node_fallback,
            cfg!(target_env = "ohos")
        );
    }
}

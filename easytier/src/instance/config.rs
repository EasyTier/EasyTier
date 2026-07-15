use std::{sync::Arc, time::Duration};

use easytier_core::peers::context::{
    HostRoutingPolicy, NetworkIdentity as CoreNetworkIdentity, PeerCredentialEventSink, PeerEvent,
    PeerEventSink, PeerRuntimeConfig, PeerRuntimeSnapshot,
};
use easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist;
use easytier_core::peers::peer_manager::{
    PeerManagerHostAdapters, PortablePeerManagerConfig, RouteAlgoType,
};
use easytier_core::{
    config::{
        CoreConfig, IpPrefix, NodeConfig, PeerPolicyConfig, ProxyNetworkConfig, RouteConfig,
        TrafficConfig,
    },
    connectivity::{
        direct::DirectConnectorOptions,
        manual::{ManualConnectorOptions, discovery::ManualEndpointDiscoveryConfig},
    },
    instance::CoreInstanceConfig,
    listener::plan::ListenerRuntimeConfig,
    peers::acl_config::AclRuleConfig,
    proxy::{ProxyRuntimeConfig, gateway::GatewayRuntimeConfig},
    runtime_config::{CoreInstanceRuntimeConfig, CoreRuntimeConfig},
    socket::{IpVersion, NetNamespace, SocketContext, tcp::TcpBindOptions, udp::UdpBindOptions},
    stun::StunServerConfig,
};

use crate::{
    VERSION,
    common::{
        config::{ConfigLoader as _, Flags, TomlConfigLoader},
        constants::EASYTIER_VERSION,
        credential_manager::runtime_credential_storage,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        stun::{default_tcp_stun_servers, default_udp_stun_servers, default_udp_v6_stun_servers},
    },
    instance::public_ipv6_provider::runtime_public_ipv6_provider_config,
    proto::common::PeerFeatureFlag,
    tunnel::IpScheme,
    use_global_var,
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

pub(crate) fn runtime_connectivity_config(global_ctx: &ArcGlobalCtx) -> CoreInstanceConfig {
    CoreInstanceConfig {
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
        stun: runtime_stun_server_config(global_ctx),
        endpoint_discovery: runtime_endpoint_discovery_config(global_ctx),
        manual: runtime_manual_options(global_ctx),
        direct: runtime_direct_options(global_ctx, false),
    }
}

fn runtime_peer_feature_flags(flags: &Flags) -> PeerFeatureFlag {
    PeerFeatureFlag {
        kcp_input: !flags.disable_kcp_input,
        no_relay_kcp: flags.disable_relay_kcp,
        support_conn_list_sync: true,
        quic_input: !flags.disable_quic_input,
        no_relay_quic: flags.disable_relay_quic,
        need_p2p: flags.need_p2p,
        disable_p2p: flags.disable_p2p,
        avoid_relay_data: flags.disable_relay_data,
        ..Default::default()
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
    let network_identity = CoreNetworkIdentity {
        network_name: identity.network_name,
        network_secret: identity.network_secret,
        network_secret_digest: identity.network_secret_digest,
    };
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
    let feature_flags = runtime_peer_feature_flags(&flags);
    let runtime = PeerRuntimeConfig {
        core: CoreConfig {
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
            peer_policy: PeerPolicyConfig {
                p2p_enabled: !flags.disable_p2p,
                relay_peer_rpc: flags.relay_all_peer_rpc,
                relay_data: !flags.disable_relay_data,
                latency_first: flags.latency_first,
                encryption_required: flags.enable_encryption,
            },
            traffic: TrafficConfig {
                mtu: u16::try_from(flags.mtu)
                    .ok()
                    .filter(|configured| *configured != 0),
                instance_recv_bps_limit: (flags.instance_recv_bps_limit != u64::MAX)
                    .then_some(flags.instance_recv_bps_limit),
                foreign_relay_bps_limit: (flags.foreign_relay_bps_limit != u64::MAX)
                    .then_some(flags.foreign_relay_bps_limit),
            },
        },
        network_identity,
        stun_info: Default::default(),
        feature_flags,
        secure_mode: global_ctx.config.get_secure_mode(),
        host_routing: HostRoutingPolicy {
            local_exit_node_fallback: cfg!(target_env = "ohos"),
        },
    };
    let avoid_relay_data_preference = check_network_in_relay_whitelist(
        &flags.relay_network_whitelist,
        &global_ctx.get_network_name(),
    )
    .is_err();
    let mut snapshot = PeerRuntimeSnapshot::new(runtime, flags);
    snapshot.easytier_version = EASYTIER_VERSION.to_owned();
    snapshot.avoid_relay_data_preference = avoid_relay_data_preference;
    snapshot.vpn_portal_cidr = global_ctx.get_vpn_portal_cidr();
    snapshot.pinned_peers = global_ctx
        .config
        .get_peers()
        .into_iter()
        .map(|peer| (peer.uri, peer.peer_public_key))
        .collect();
    snapshot.ospf_update_my_foreign_network_interval_sec =
        use_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC);
    snapshot.max_direct_conns_per_peer_in_foreign_network =
        use_global_var!(MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK) as usize;
    snapshot.hmac_secret_digest = use_global_var!(HMAC_SECRET_DIGEST);
    snapshot.set_acl_groups(acl.as_ref());
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
        relay_state_sink: Arc::new(()),
        event_sink: event_sink.clone(),
        credential_storage: runtime_credential_storage(global_ctx.config.get_credential_file()),
        credential_event_sink: event_sink,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;

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
    fn native_peer_config_submits_one_complete_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.disable_p2p = true;
        flags.relay_all_peer_rpc = true;
        flags.disable_relay_data = true;
        flags.latency_first = true;
        flags.enable_encryption = false;
        flags.mtu = 1400;
        flags.instance_recv_bps_limit = 0;
        flags.foreign_relay_bps_limit = u64::MAX;
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
        assert!(!runtime.core.peer_policy.p2p_enabled);
        assert!(runtime.core.peer_policy.relay_peer_rpc);
        assert!(!runtime.core.peer_policy.relay_data);
        assert!(runtime.core.peer_policy.latency_first);
        assert!(!runtime.core.peer_policy.encryption_required);
        assert_eq!(runtime.core.traffic.mtu, Some(1400));
        assert_eq!(runtime.core.traffic.instance_recv_bps_limit, Some(0));
        assert_eq!(runtime.core.traffic.foreign_relay_bps_limit, None);
        assert_eq!(config.snapshot.easytier_version, EASYTIER_VERSION);
        assert!(!config.snapshot.avoid_relay_data_preference);
        assert_eq!(runtime.feature_flags.kcp_input, !flags.disable_kcp_input);
        assert_eq!(runtime.feature_flags.no_relay_kcp, flags.disable_relay_kcp);
        assert_eq!(runtime.feature_flags.quic_input, !flags.disable_quic_input);
        assert_eq!(
            runtime.feature_flags.no_relay_quic,
            flags.disable_relay_quic
        );
        assert!(runtime.feature_flags.support_conn_list_sync);
    }

    #[test]
    fn relay_whitelist_initialization_precedes_portable_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.relay_network_whitelist = "other-network".to_owned();
        global_ctx.set_flags(flags);

        let config = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);

        assert!(config.snapshot.avoid_relay_data_preference);
    }
}

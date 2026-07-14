use std::sync::Arc;

use easytier_core::config::{
    CoreConfig, IpPrefix, NodeConfig, PeerPolicyConfig, ProxyNetworkConfig, RouteConfig,
    TrafficConfig,
};
#[cfg(test)]
use easytier_core::peers::context::PeerContext;
use easytier_core::peers::context::{
    CorePeerContext, CorePeerContextAdapters, HostRoutingPolicy,
    NetworkIdentity as CoreNetworkIdentity, PeerCredentialEventSink, PeerEvent, PeerEventSink,
    PeerPublicIpv6State, PeerRelayStateSink, PeerRuntimeConfig, PeerRuntimeSnapshot,
    PeerStunInfoSource,
};
use easytier_core::peers::peer_manager::{
    PeerManagerHostAdapters, PeerPublicIpv6HostAdapters, PortablePeerManagerConfig, RouteAlgoType,
};
use easytier_core::runtime_config::{CoreRuntimeConfig, CoreRuntimeConfigStore};

use crate::{
    common::{
        config::{ConfigLoader as _, TomlConfigLoader},
        constants::EASYTIER_VERSION,
        credential_manager::runtime_credential_storage,
        global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent},
    },
    use_global_var,
};

use super::foreign_network_manager::RuntimeForeignNetworkRpcRegistrar;

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
    let mut feature_flags = global_ctx.get_feature_flags();
    // Public-IPv6 provider state is live host state, not submitted config.
    feature_flags.ipv6_public_addr_provider = false;
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
        stun_info: global_ctx.get_stun_info_collector().get_stun_info(),
        feature_flags,
        secure_mode: global_ctx.config.get_secure_mode(),
        host_routing: HostRoutingPolicy {
            local_exit_node_fallback: cfg!(target_env = "ohos"),
        },
    };
    let mut snapshot = PeerRuntimeSnapshot::new(runtime, flags);
    snapshot.easytier_version = EASYTIER_VERSION.to_owned();
    snapshot.avoid_relay_data_preference = global_ctx.get_avoid_relay_data_preference();
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

pub(crate) fn initialize_runtime_peer_host_state(global_ctx: &ArcGlobalCtx) {
    if global_ctx
        .check_network_in_whitelist(&global_ctx.get_network_name())
        .is_err()
    {
        // Preserve the legacy policy: a local network outside the relay
        // whitelist should not relay TUN traffic when another route exists.
        global_ctx.set_avoid_relay_data_preference(true);
    }
}

pub(crate) fn build_core_peer_context(
    global_ctx: &ArcGlobalCtx,
    config: &PortablePeerManagerConfig,
) -> (CoreRuntimeConfigStore, Arc<CorePeerContext>) {
    let runtime_config = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(config.snapshot.clone()),
    );
    let peer_context = Arc::new(CorePeerContext::new(
        runtime_config.clone(),
        core_peer_context_adapters(global_ctx),
    ));
    (runtime_config, peer_context)
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

pub(crate) fn core_peer_context_adapters(global_ctx: &ArcGlobalCtx) -> CorePeerContextAdapters {
    let event_sink = Arc::new(GlobalCtxPeerEventSink::new(global_ctx.clone()));
    CorePeerContextAdapters {
        relay_state_sink: global_ctx.clone(),
        stun_info_source: Some(global_ctx.clone()),
        public_ipv6_state: global_ctx.clone(),
        event_sink: event_sink.clone(),
        credential_storage: runtime_credential_storage(global_ctx.config.get_credential_file()),
        credential_event_sink: event_sink,
    }
}

pub(crate) fn runtime_peer_manager_host_adapters(
    global_ctx: &ArcGlobalCtx,
) -> PeerManagerHostAdapters {
    let event_sink = Arc::new(GlobalCtxPeerEventSink::new(global_ctx.clone()));
    PeerManagerHostAdapters {
        relay_state_sink: global_ctx.clone(),
        event_sink: event_sink.clone(),
        credential_storage: runtime_credential_storage(global_ctx.config.get_credential_file()),
        credential_event_sink: event_sink,
        public_ipv6: Some(PeerPublicIpv6HostAdapters::new(global_ctx.clone())),
        foreign_rpc_registrar: Arc::new(RuntimeForeignNetworkRpcRegistrar::new(global_ctx.clone())),
    }
}

impl PeerStunInfoSource for GlobalCtx {
    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.get_stun_info_collector().get_stun_info()
    }
}

impl PeerRelayStateSink for GlobalCtx {
    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) {
        GlobalCtx::set_avoid_relay_data_preference(self, avoid_relay_data);
    }
}

impl PeerPublicIpv6State for GlobalCtx {
    fn public_ipv6_lease_contains(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_public_ipv6_lease()
            .is_some_and(|address| address.address() == *ip)
    }

    fn public_ipv6_provider_enabled(&self) -> bool {
        self.get_feature_flags().ipv6_public_addr_provider
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        self.get_advertised_ipv6_public_addr_prefix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::common::{
        config::{PeerConfig, VpnPortalConfig},
        global_ctx::tests::get_mock_global_ctx,
    };
    use crate::proto::{
        acl::{Acl, AclV1, GroupIdentity, GroupInfo},
        common::TunnelInfo,
    };

    fn core_context_for_test(
        global_ctx: ArcGlobalCtx,
    ) -> (CoreRuntimeConfigStore, Arc<CorePeerContext>) {
        let config = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);
        build_core_peer_context(&global_ctx, &config)
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
        assert_eq!(
            config.snapshot.avoid_relay_data_preference,
            global_ctx.get_avoid_relay_data_preference()
        );
    }

    #[test]
    fn relay_whitelist_initialization_precedes_portable_snapshot() {
        let global_ctx = get_mock_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.relay_network_whitelist = "other-network".to_owned();
        global_ctx.set_flags(flags);

        initialize_runtime_peer_host_state(&global_ctx);
        let config = runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf);

        assert!(global_ctx.get_avoid_relay_data_preference());
        assert!(config.snapshot.avoid_relay_data_preference);
    }

    #[tokio::test]
    async fn config_changes_require_an_explicit_snapshot_update() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_hostname("before".to_owned());
        global_ctx.set_ipv4(Some("192.0.2.1/24".parse().unwrap()));
        let remote_url: url::Url = "tcp://198.51.100.1:11010".parse().unwrap();
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url.clone(),
            peer_public_key: Some("before-key".to_owned()),
        }]);
        global_ctx.config.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "before-group".to_owned(),
                        group_secret: "before-secret".to_owned(),
                    }],
                    members: vec!["before-group".to_owned()],
                }),
                ..Default::default()
            }),
        }));
        let (config, context) = core_context_for_test(global_ctx.clone());

        global_ctx.set_hostname("after".to_owned());
        global_ctx.set_ipv4(Some("198.51.100.1/24".parse().unwrap()));
        global_ctx
            .config
            .add_proxy_cidr("192.0.2.0/24".parse().unwrap(), None)
            .unwrap();
        global_ctx.config.set_vpn_portal_config(VpnPortalConfig {
            client_cidr: "203.0.113.0/24".parse().unwrap(),
            wireguard_listen: "0.0.0.0:11011".parse().unwrap(),
        });
        global_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url.clone(),
            peer_public_key: Some("after-key".to_owned()),
        }]);
        global_ctx.config.set_acl(Some(Acl {
            acl_v1: Some(AclV1 {
                group: Some(GroupInfo {
                    declares: vec![GroupIdentity {
                        group_name: "after-group".to_owned(),
                        group_secret: "after-secret".to_owned(),
                    }],
                    members: vec!["after-group".to_owned()],
                }),
                ..Default::default()
            }),
        }));
        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        let tunnel_info = TunnelInfo {
            remote_addr: Some(remote_url.into()),
            ..Default::default()
        };

        assert_eq!(context.hostname(), "before");
        assert!(context.proxy_networks().is_empty());
        assert!(!context.disable_relay_data());
        assert!(context.is_ip_in_same_network(&"192.0.2.8".parse().unwrap()));
        assert!(!context.is_ip_in_same_network(&"198.51.100.8".parse().unwrap()));
        assert_eq!(context.vpn_portal_cidr(), None);
        assert_eq!(
            context.pinned_remote_static_pubkey(Some(&tunnel_info)),
            Some("before-key".to_owned())
        );
        assert_eq!(
            context.acl_group_declarations()[0].group_name,
            "before-group"
        );
        assert_eq!(context.peer_groups(7)[0].group_name, "before-group");

        context.set_avoid_relay_data_preference(true);
        assert!(context.feature_flags().avoid_relay_data);
        assert!(global_ctx.get_avoid_relay_data_preference());

        config.update_peer(Arc::new(
            runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf).snapshot,
        ));
        assert_eq!(context.hostname(), "after");
        assert_eq!(context.proxy_networks().len(), 1);
        assert!(context.disable_relay_data());
        assert!(!context.is_ip_in_same_network(&"192.0.2.8".parse().unwrap()));
        assert!(context.is_ip_in_same_network(&"198.51.100.8".parse().unwrap()));
        assert_eq!(
            context.vpn_portal_cidr(),
            Some("203.0.113.0/24".parse().unwrap())
        );
        assert_eq!(
            context.pinned_remote_static_pubkey(Some(&tunnel_info)),
            Some("after-key".to_owned())
        );
        assert_eq!(
            context.acl_group_declarations()[0].group_name,
            "after-group"
        );
        assert_eq!(context.peer_groups(7)[0].group_name, "after-group");
    }

    #[tokio::test]
    async fn runtime_avoid_relay_preference_remains_reversible_after_refresh() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_avoid_relay_data_preference(true);
        let (config, context) = core_context_for_test(global_ctx.clone());

        assert!(context.feature_flags().avoid_relay_data);
        config.update_peer(Arc::new(
            runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf).snapshot,
        ));
        context.set_avoid_relay_data_preference(false);
        assert!(!context.feature_flags().avoid_relay_data);
        assert!(!global_ctx.get_avoid_relay_data_preference());

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        config.update_peer(Arc::new(
            runtime_peer_manager_config(&global_ctx, RouteAlgoType::Ospf).snapshot,
        ));
        assert!(context.feature_flags().avoid_relay_data);
    }
}

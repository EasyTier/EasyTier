use std::sync::Arc;

use easytier_core::config::{
    CoreConfig, IpPrefix, NodeConfig, PeerPolicyConfig, ProxyNetworkConfig, RouteConfig,
    TrafficConfig,
};
use easytier_core::peers::context::{
    HostRoutingPolicy, NetworkIdentity as CoreNetworkIdentity, PeerCredentialEventSink, PeerEvent,
    PeerEventSink, PeerRuntimeConfig, PeerRuntimeSnapshot,
};
use easytier_core::peers::foreign_network_manager::check_network_in_relay_whitelist;
use easytier_core::peers::peer_manager::{
    PeerManagerHostAdapters, PortablePeerManagerConfig, RouteAlgoType,
};

use crate::{
    common::{
        config::{ConfigLoader as _, Flags, TomlConfigLoader},
        constants::EASYTIER_VERSION,
        credential_manager::runtime_credential_storage,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    },
    proto::common::PeerFeatureFlag,
    use_global_var,
};

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

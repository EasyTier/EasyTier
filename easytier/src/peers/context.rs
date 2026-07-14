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
use easytier_core::runtime_config::{CoreRuntimeConfig, CoreRuntimeConfigStore};

use crate::{
    common::{
        constants::EASYTIER_VERSION,
        global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent},
    },
    use_global_var,
};

/// Normalizes the native host configuration into one portable peer version.
pub(crate) fn runtime_peer_snapshot(global_ctx: &ArcGlobalCtx) -> PeerRuntimeSnapshot {
    let acl = global_ctx.config.get_acl();
    let flags = global_ctx.get_flags();
    let mut snapshot =
        PeerRuntimeSnapshot::new_with_legacy_flags(runtime_peer_config(global_ctx), flags);
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
    snapshot
}

pub(crate) fn build_core_peer_context(
    global_ctx: &ArcGlobalCtx,
) -> (CoreRuntimeConfigStore, Arc<CorePeerContext>) {
    let runtime_config = CoreRuntimeConfigStore::new(
        CoreRuntimeConfig::default(),
        Arc::new(runtime_peer_snapshot(global_ctx)),
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
        traffic_sink: global_ctx.clone(),
        event_sink: event_sink.clone(),
        credentials: global_ctx.get_credential_manager().core(),
        trusted_keys: global_ctx.trusted_key_manager(),
        credential_event_sink: event_sink,
    }
}

fn runtime_peer_config(global_ctx: &ArcGlobalCtx) -> PeerRuntimeConfig {
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
    PeerRuntimeConfig {
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
            peer_policy: PeerPolicyConfig::default(),
            traffic: TrafficConfig::default(),
        },
        network_identity,
        stun_info: global_ctx.get_stun_info_collector().get_stun_info(),
        feature_flags,
        secure_mode: global_ctx.config.get_secure_mode(),
        host_routing: HostRoutingPolicy {
            local_exit_node_fallback: cfg!(target_env = "ohos"),
        },
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
    use easytier_core::stats_manager::{LabelSet, LabelType, MetricName};
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
        build_core_peer_context(&global_ctx)
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

    #[tokio::test]
    async fn control_traffic_sink_preserves_native_metric_labels() {
        let global_ctx = get_mock_global_ctx();
        let labels =
            LabelSet::new().with_label_type(LabelType::NetworkName("metrics-network".to_owned()));

        easytier_core::peers::context::PeerControlTrafficSink::record_control_tx(
            global_ctx.as_ref(),
            "metrics-network",
            128,
        );

        assert_eq!(
            global_ctx
                .stats_manager()
                .get_metric(MetricName::TrafficControlBytesTx, &labels)
                .unwrap()
                .value,
            128
        );
        assert_eq!(
            global_ctx
                .stats_manager()
                .get_metric(MetricName::TrafficControlPacketsTx, &labels)
                .unwrap()
                .value,
            1
        );
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

        config.update_peer(Arc::new(runtime_peer_snapshot(&global_ctx)));
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
        config.update_peer(Arc::new(runtime_peer_snapshot(&global_ctx)));
        context.set_avoid_relay_data_preference(false);
        assert!(!context.feature_flags().avoid_relay_data);
        assert!(!global_ctx.get_avoid_relay_data_preference());

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        config.update_peer(Arc::new(runtime_peer_snapshot(&global_ctx)));
        assert!(context.feature_flags().avoid_relay_data);
    }
}

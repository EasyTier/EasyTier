use std::{collections::HashSet, sync::Arc};

use easytier_core::peers::context::{
    ArcByteLimiter, PeerContext, PeerCredentialEventSink, PeerEvent, PeerEventSink,
    PeerLimiterFactory, PeerRuntimeConfig, PeerRuntimeSnapshot, PeerRuntimeSupport,
    SubmittedPeerContextCapabilities,
};

use crate::{
    common::{
        constants::EASYTIER_VERSION,
        global_ctx::{ArcGlobalCtx, GlobalCtx, GlobalCtxEvent},
    },
    proto::common::LimiterConfig,
    use_global_var,
};

/// Normalizes the native host configuration into one portable peer version.
pub(crate) fn runtime_peer_snapshot(global_ctx: &ArcGlobalCtx) -> PeerRuntimeSnapshot {
    let acl_group_declarations = PeerContext::acl_group_declarations(global_ctx.as_ref());
    let memberships = global_ctx
        .config
        .get_acl()
        .and_then(|acl| acl.acl_v1)
        .and_then(|acl| acl.group)
        .map(|group| group.members.into_iter().collect::<HashSet<_>>())
        .unwrap_or_default();
    let peer_group_memberships = acl_group_declarations
        .iter()
        .filter(|group| memberships.contains(&group.group_name))
        .cloned()
        .collect();
    PeerRuntimeSnapshot {
        runtime: runtime_peer_config(global_ctx),
        flags: global_ctx.get_flags(),
        vpn_portal_cidr: PeerContext::vpn_portal_cidr(global_ctx.as_ref()),
        pinned_peers: global_ctx
            .config
            .get_peers()
            .into_iter()
            .map(|peer| (peer.uri, peer.peer_public_key))
            .collect(),
        peer_group_memberships,
        acl_group_declarations,
        ospf_update_my_foreign_network_interval_sec: use_global_var!(
            OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC
        ),
        max_direct_conns_per_peer_in_foreign_network: use_global_var!(
            MAX_DIRECT_CONNS_PER_PEER_IN_FOREIGN_NETWORK
        ) as usize,
        hmac_secret_digest: use_global_var!(HMAC_SECRET_DIGEST),
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

pub(crate) fn submitted_peer_capabilities(
    global_ctx: &ArcGlobalCtx,
) -> SubmittedPeerContextCapabilities {
    let event_sink = Arc::new(GlobalCtxPeerEventSink::new(global_ctx.clone()));
    SubmittedPeerContextCapabilities {
        runtime_support: global_ctx.clone(),
        limiter_factory: global_ctx.clone(),
        traffic_sink: global_ctx.clone(),
        event_sink: event_sink.clone(),
        credentials: global_ctx.get_credential_manager().core(),
        trusted_keys: global_ctx.trusted_key_manager(),
        credential_event_sink: event_sink,
    }
}

impl PeerLimiterFactory for GlobalCtx {
    fn get_or_create_limiter(&self, key: &str, bps: u64) -> Option<ArcByteLimiter> {
        Some(
            self.token_bucket_manager().get_or_create(
                key,
                LimiterConfig {
                    burst_rate: None,
                    bps: Some(bps),
                    fill_duration_ms: None,
                }
                .into(),
            ),
        )
    }
}

fn runtime_peer_config(global_ctx: &ArcGlobalCtx) -> PeerRuntimeConfig {
    let mut runtime = PeerContext::runtime_config(global_ctx.as_ref());
    runtime.core.routes.proxy_networks = PeerContext::proxy_networks(global_ctx.as_ref());
    runtime
}

impl PeerRuntimeSupport for GlobalCtx {
    fn stun_info(&self) -> crate::proto::common::StunInfo {
        PeerContext::stun_info(self)
    }

    fn public_ipv6_lease_contains(&self, ip: &std::net::Ipv6Addr) -> bool {
        self.get_public_ipv6_lease()
            .is_some_and(|address| address.address() == *ip)
    }

    fn avoid_relay_data_preference(&self) -> bool {
        self.get_avoid_relay_data_preference()
    }

    fn set_avoid_relay_data_preference(&self, avoid_relay_data: bool) -> bool {
        GlobalCtx::set_avoid_relay_data_preference(self, avoid_relay_data)
    }

    fn subscribe_runtime_changes(
        &self,
    ) -> Option<easytier_core::peers::context::BoxPeerRuntimeChangeSubscriber> {
        Some(GlobalCtx::subscribe_runtime_changes(self))
    }

    fn public_ipv6_provider_enabled(&self) -> bool {
        self.get_feature_flags().ipv6_public_addr_provider
    }

    fn easytier_version(&self) -> String {
        EASYTIER_VERSION.to_owned()
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        self.get_advertised_ipv6_public_addr_prefix()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::{
        instance::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        peers::context::SubmittedPeerContext,
    };
    use std::sync::Arc;

    use crate::common::{
        config::{PeerConfig, VpnPortalConfig},
        global_ctx::tests::get_mock_global_ctx,
        stats_manager::{LabelSet, LabelType, MetricName},
    };
    use crate::proto::{
        acl::{Acl, AclV1, GroupIdentity, GroupInfo},
        common::TunnelInfo,
    };

    fn submitted_context(
        global_ctx: ArcGlobalCtx,
    ) -> (CoreRuntimeConfigStore, SubmittedPeerContext) {
        let config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(runtime_peer_snapshot(&global_ctx)),
        );
        let context = SubmittedPeerContext::new(
            Arc::new(config.clone()),
            submitted_peer_capabilities(&global_ctx),
        );
        (config, context)
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
        let (config, context) = submitted_context(global_ctx.clone());

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

        global_ctx.set_avoid_relay_data_preference(true);
        assert!(context.feature_flags().avoid_relay_data);

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
        let (config, context) = submitted_context(global_ctx.clone());

        assert!(context.feature_flags().avoid_relay_data);
        config.update_peer(Arc::new(runtime_peer_snapshot(&global_ctx)));
        global_ctx.set_avoid_relay_data_preference(false);
        assert!(!context.feature_flags().avoid_relay_data);

        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags);
        config.update_peer(Arc::new(runtime_peer_snapshot(&global_ctx)));
        assert!(context.feature_flags().avoid_relay_data);
    }
}

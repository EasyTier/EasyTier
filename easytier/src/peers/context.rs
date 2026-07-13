use std::collections::HashSet;

use easytier_core::peers::context::{
    ArcByteLimiter, PeerContext, PeerContextEventSubscriber, PeerEvent, PeerRuntimeConfig,
    PeerRuntimeSnapshot, PeerRuntimeSupport, TrustedKeyMap, TrustedKeySource,
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

    fn public_ipv6_provider_enabled(&self) -> bool {
        self.get_feature_flags().ipv6_public_addr_provider
    }

    fn easytier_version(&self) -> String {
        EASYTIER_VERSION.to_owned()
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<cidr::Ipv6Cidr> {
        self.get_advertised_ipv6_public_addr_prefix()
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        PeerContext::is_pubkey_trusted(self, pubkey, network_name)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        PeerContext::is_pubkey_trusted_with_source(self, pubkey, network_name, source)
    }

    fn list_trusted_keys(
        &self,
        network_name: &str,
    ) -> Vec<(Vec<u8>, easytier_core::peers::context::TrustedKeyMetadata)> {
        GlobalCtx::list_trusted_keys(self, network_name)
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<crate::proto::peer_rpc::TrustedCredentialPubkeyProof> {
        PeerContext::trusted_credential_pubkeys(self, network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        PeerContext::remove_expired_credentials(self)
    }

    fn issue_credential_changed(&self) {
        self.issue_event(GlobalCtxEvent::CredentialChanged);
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        PeerContext::update_trusted_keys(self, keys, network_name);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        PeerContext::remove_trusted_keys(self, network_name);
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        PeerContext::record_control_tx(self, network_name, bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        PeerContext::record_control_rx(self, network_name, bytes);
    }

    fn recv_limiter(&self, key: &str, bps: u64) -> Option<ArcByteLimiter> {
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

    fn issue_event(&self, event: PeerEvent) {
        PeerContext::issue_event(self, event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        PeerContext::subscribe_peer_events(self)
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
        let context = SubmittedPeerContext::new(Arc::new(config.clone()), global_ctx);
        (config, context)
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

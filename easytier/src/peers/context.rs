use std::{net::IpAddr, sync::Arc};

use arc_swap::ArcSwap;
use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use easytier_core::{
    config::{IpPrefix, PeerId, ProxyNetworkConfig},
    peers::context::{
        ArcByteLimiter, HostRoutingPolicy, PeerContext, PeerContextEventSubscriber,
        PeerGroupIdentity, PeerRuntimeConfig, TrustedKeyMap, TrustedKeySource,
    },
    proto::{
        common::{FlagsInConfig, PeerFeatureFlag, SecureModeConfig, StunInfo, TunnelInfo},
        peer_rpc::{PeerGroupInfo, TrustedCredentialPubkeyProof},
    },
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::common::global_ctx::ArcGlobalCtx;

/// Core-owned peer configuration plus narrow native runtime support.
///
/// Config decisions are read only from the submitted snapshots. `GlobalCtx`
/// remains behind this adapter for observations, events, metrics, credentials,
/// and trusted-key storage that have not yet moved into the core instance.
pub(crate) struct RuntimePeerContext {
    snapshot: ArcSwap<RuntimePeerSnapshot>,
    support: ArcGlobalCtx,
}

#[derive(Clone)]
struct RuntimePeerSnapshot {
    runtime: PeerRuntimeConfig,
    flags: FlagsInConfig,
    vpn_portal_cidr: Option<Ipv4Cidr>,
    pinned_peers: Vec<(url::Url, Option<String>)>,
}

impl RuntimePeerSnapshot {
    fn from_global_ctx(global_ctx: &ArcGlobalCtx) -> Self {
        Self {
            runtime: runtime_peer_config(global_ctx),
            flags: global_ctx.get_flags(),
            vpn_portal_cidr: PeerContext::vpn_portal_cidr(global_ctx.as_ref()),
            pinned_peers: global_ctx
                .config
                .get_peers()
                .into_iter()
                .map(|peer| (peer.uri, peer.peer_public_key))
                .collect(),
        }
    }
}

impl RuntimePeerContext {
    pub(crate) fn new(support: ArcGlobalCtx) -> Self {
        Self {
            snapshot: ArcSwap::from_pointee(RuntimePeerSnapshot::from_global_ctx(&support)),
            support,
        }
    }

    pub(crate) fn refresh(&self) {
        self.snapshot
            .store(Arc::new(RuntimePeerSnapshot::from_global_ctx(
                &self.support,
            )));
    }

    fn snapshot(&self) -> Arc<RuntimePeerSnapshot> {
        self.snapshot.load_full()
    }
}

fn runtime_peer_config(global_ctx: &ArcGlobalCtx) -> PeerRuntimeConfig {
    let mut runtime = PeerContext::runtime_config(global_ctx.as_ref());
    runtime.core.routes.proxy_networks = PeerContext::proxy_networks(global_ctx.as_ref());
    runtime
}

fn ipv4(prefix: &IpPrefix) -> Option<Ipv4Inet> {
    let IpAddr::V4(address) = prefix.address else {
        return None;
    };
    Ipv4Inet::new(address, prefix.prefix_len).ok()
}

fn ipv4_cidr(prefix: &IpPrefix) -> Option<Ipv4Cidr> {
    let IpAddr::V4(address) = prefix.address else {
        return None;
    };
    Ipv4Cidr::new(address, prefix.prefix_len).ok()
}

fn ipv6(prefix: &IpPrefix) -> Option<Ipv6Inet> {
    let IpAddr::V6(address) = prefix.address else {
        return None;
    };
    Ipv6Inet::new(address, prefix.prefix_len).ok()
}

impl PeerContext for RuntimePeerContext {
    fn runtime_config(&self) -> PeerRuntimeConfig {
        self.snapshot().runtime.clone()
    }

    fn network_identity(&self) -> easytier_core::config::NetworkIdentity {
        self.snapshot().runtime.network_identity.clone()
    }

    fn flags(&self) -> FlagsInConfig {
        self.snapshot().flags.clone()
    }

    fn host_routing_policy(&self) -> HostRoutingPolicy {
        self.snapshot().runtime.host_routing
    }

    fn secure_mode(&self) -> Option<SecureModeConfig> {
        self.snapshot().runtime.secure_mode.clone()
    }

    fn stun_info(&self) -> StunInfo {
        PeerContext::stun_info(self.support.as_ref())
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.snapshot()
            .runtime
            .core
            .node
            .instance_id
            .map(uuid::Uuid::from_bytes)
            .unwrap_or_else(uuid::Uuid::nil)
    }

    fn ipv4(&self) -> Option<Ipv4Inet> {
        self.snapshot()
            .runtime
            .core
            .routes
            .ipv4
            .as_ref()
            .and_then(ipv4)
    }

    fn ipv6(&self) -> Option<Ipv6Inet> {
        self.snapshot()
            .runtime
            .core
            .routes
            .ipv6
            .as_ref()
            .and_then(ipv6)
    }

    fn is_ip_local_ipv6(&self, ip: &std::net::Ipv6Addr) -> bool {
        // The delegated public-IPv6 lease is live host observation; the
        // configured virtual IPv6 address remains snapshot-owned above.
        self.ipv6().is_some_and(|address| address.address() == *ip)
            || self
                .support
                .get_public_ipv6_lease()
                .is_some_and(|address| address.address() == *ip)
    }

    fn proxy_cidrs(&self) -> Vec<Ipv4Cidr> {
        self.snapshot()
            .runtime
            .core
            .routes
            .proxy_networks
            .iter()
            .filter_map(|proxy| ipv4_cidr(proxy.mapped.as_ref().unwrap_or(&proxy.real)))
            .collect()
    }

    fn proxy_networks(&self) -> Vec<ProxyNetworkConfig> {
        self.snapshot().runtime.core.routes.proxy_networks.clone()
    }

    fn vpn_portal_cidr(&self) -> Option<Ipv4Cidr> {
        self.snapshot().vpn_portal_cidr
    }

    fn hostname(&self) -> String {
        self.snapshot()
            .runtime
            .core
            .node
            .hostname
            .clone()
            .unwrap_or_default()
    }

    fn feature_flags(&self) -> PeerFeatureFlag {
        let mut flags = self.snapshot().runtime.feature_flags;
        flags.ipv6_public_addr_provider =
            self.support.get_feature_flags().ipv6_public_addr_provider;
        flags
    }

    fn easytier_version(&self) -> String {
        PeerContext::easytier_version(self.support.as_ref())
    }

    fn ospf_update_my_foreign_network_interval_sec(&self) -> u64 {
        PeerContext::ospf_update_my_foreign_network_interval_sec(self.support.as_ref())
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        PeerContext::advertised_ipv6_public_addr_prefix(self.support.as_ref())
    }

    fn is_ip_in_same_network(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.ipv4().is_some_and(|network| network.contains(ip)),
            IpAddr::V6(ip) => self.ipv6().is_some_and(|network| network.contains(ip)),
        }
    }

    fn pinned_remote_static_pubkey(&self, tunnel_info: Option<&TunnelInfo>) -> Option<String> {
        let remote_url = tunnel_info
            .and_then(|info| info.remote_addr.as_ref())?
            .url
            .parse::<url::Url>()
            .ok()?;
        self.snapshot()
            .pinned_peers
            .iter()
            .find(|(uri, _)| *uri == remote_url)
            .and_then(|(_, public_key)| public_key.clone())
    }

    fn secret_proof(&self, challenge: &[u8]) -> Option<Hmac<Sha256>> {
        let secret = self
            .snapshot()
            .runtime
            .network_identity
            .network_secret
            .clone()?;
        easytier_core::peers::context::secret_proof_from_secret(&secret, challenge)
    }

    fn secret_digest(&self, network_identity: &easytier_core::config::NetworkIdentity) -> Vec<u8> {
        if crate::use_global_var!(HMAC_SECRET_DIGEST) {
            self.secret_proof(b"digest")
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network_identity
                .secret_digest()
                .unwrap_or_default()
                .to_vec()
        }
    }

    fn peer_groups(&self, peer_id: PeerId) -> Vec<PeerGroupInfo> {
        PeerContext::peer_groups(self.support.as_ref(), peer_id)
    }

    fn acl_group_declarations(&self) -> Vec<PeerGroupIdentity> {
        PeerContext::acl_group_declarations(self.support.as_ref())
    }

    fn is_pubkey_trusted(&self, pubkey: &[u8], network_name: &str) -> bool {
        PeerContext::is_pubkey_trusted(self.support.as_ref(), pubkey, network_name)
    }

    fn is_pubkey_trusted_with_source(
        &self,
        pubkey: &[u8],
        network_name: &str,
        source: TrustedKeySource,
    ) -> bool {
        PeerContext::is_pubkey_trusted_with_source(
            self.support.as_ref(),
            pubkey,
            network_name,
            source,
        )
    }

    fn trusted_credential_pubkeys(
        &self,
        network_secret: &str,
    ) -> Vec<TrustedCredentialPubkeyProof> {
        PeerContext::trusted_credential_pubkeys(self.support.as_ref(), network_secret)
    }

    fn remove_expired_credentials(&self) -> bool {
        PeerContext::remove_expired_credentials(self.support.as_ref())
    }

    fn issue_credential_changed(&self) {
        PeerContext::issue_credential_changed(self.support.as_ref());
    }

    fn update_trusted_keys(&self, keys: TrustedKeyMap, network_name: &str) {
        PeerContext::update_trusted_keys(self.support.as_ref(), keys, network_name);
    }

    fn remove_trusted_keys(&self, network_name: &str) {
        PeerContext::remove_trusted_keys(self.support.as_ref(), network_name);
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        PeerContext::record_control_tx(self.support.as_ref(), network_name, bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        PeerContext::record_control_rx(self.support.as_ref(), network_name, bytes);
    }

    fn recv_limiter(&self, network_name: &str, is_foreign_network: bool) -> Option<ArcByteLimiter> {
        PeerContext::recv_limiter(self.support.as_ref(), network_name, is_foreign_network)
    }

    fn issue_event(&self, event: easytier_core::peers::context::PeerEvent) {
        PeerContext::issue_event(self.support.as_ref(), event);
    }

    fn subscribe_peer_events(&self) -> Option<PeerContextEventSubscriber> {
        PeerContext::subscribe_peer_events(self.support.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::{PeerConfig, VpnPortalConfig},
        global_ctx::tests::get_mock_global_ctx,
    };

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
        let context = RuntimePeerContext::new(global_ctx.clone());

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
        let mut flags = global_ctx.get_flags();
        flags.disable_relay_data = true;
        global_ctx.set_flags(flags.clone());
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

        context.refresh();
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
    }
}

pub mod provider;
pub(crate) mod service;

pub(crate) use service::PublicIpv6Service;

use std::{collections::HashSet, net::Ipv6Addr, sync::Arc};

use cidr::{Ipv6Cidr, Ipv6Inet};

use crate::{
    config::PeerId, config::peers::PublicIpv6ProviderConfig,
    config::runtime::CoreRuntimeConfigStore, peers::context::PeerPublicIpv6State,
};

impl PublicIpv6ProviderConfig {
    pub fn validate(self) -> Result<(), PublicIpv6ProviderConfigError> {
        if !self.provider_enabled {
            return Ok(());
        }
        if !self.provider_supported {
            return Err(PublicIpv6ProviderConfigError::UnsupportedProvider);
        }
        if let Some(prefix) = self.configured_prefix
            && !is_global_routable_public_ipv6_prefix(prefix)
        {
            return Err(PublicIpv6ProviderConfigError::InvalidPrefix(prefix));
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PublicIpv6ProviderConfigError {
    #[error(
        "the provider feature requires Linux; run without --ipv6-public-addr-provider on this node, or move the provider role to a Linux node. client mode (--ipv6-public-addr-auto) works on all platforms"
    )]
    UnsupportedProvider,
    #[error(
        "the prefix {0} is not a valid global unicast IPv6 prefix; it must be a routable address range, not a private, link-local, or multicast address"
    )]
    InvalidPrefix(Ipv6Cidr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PublicIpv6ProviderResolution {
    Disabled,
    Pending(String),
    Active(Ipv6Cidr),
}

pub(crate) fn resolve_public_ipv6_provider(
    config: PublicIpv6ProviderConfig,
    detected_prefix: Result<Option<Ipv6Cidr>, String>,
) -> PublicIpv6ProviderResolution {
    if !config.provider_enabled {
        return PublicIpv6ProviderResolution::Disabled;
    }
    if !config.provider_supported {
        return PublicIpv6ProviderResolution::Pending(
            PublicIpv6ProviderConfigError::UnsupportedProvider.to_string(),
        );
    }

    if let Some(prefix) = config.configured_prefix {
        return if is_global_routable_public_ipv6_prefix(prefix) {
            PublicIpv6ProviderResolution::Active(prefix)
        } else {
            PublicIpv6ProviderResolution::Pending(format!(
                "the configured prefix {prefix} is not a valid global unicast IPv6 prefix"
            ))
        };
    }

    match detected_prefix {
        Ok(Some(prefix)) if is_global_routable_public_ipv6_prefix(prefix) => {
            PublicIpv6ProviderResolution::Active(prefix)
        }
        Ok(Some(prefix)) => PublicIpv6ProviderResolution::Pending(format!(
            "the detected prefix {prefix} is not a valid global unicast IPv6 prefix"
        )),
        Ok(None) => PublicIpv6ProviderResolution::Pending(
            "no public IPv6 prefix found on this system; set --ipv6-public-addr-prefix manually, or check that your ISP has delegated an IPv6 prefix and a default-from route exists in the kernel routing table".to_owned(),
        ),
        Err(error) => PublicIpv6ProviderResolution::Pending(error),
    }
}

pub fn is_global_routable_public_ipv6_prefix(prefix: Ipv6Cidr) -> bool {
    let addr = prefix.first_address();
    !addr.is_loopback()
        && !addr.is_multicast()
        && !addr.is_unicast_link_local()
        && !addr.is_unique_local()
        && !addr.is_unspecified()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicIpv6PeerRouteInfo {
    pub peer_id: PeerId,
    pub inst_id: Option<uuid::Uuid>,
    pub is_provider: bool,
    pub prefix: Option<Ipv6Cidr>,
    pub lease: Option<Ipv6Inet>,
    pub reachable: bool,
}

pub(crate) trait PublicIpv6RouteControl: Send + Sync {
    fn my_peer_id(&self) -> PeerId;
    fn peer_route_snapshot(&self) -> Vec<PublicIpv6PeerRouteInfo>;
    fn publish_self_public_ipv6_lease(&self, lease: Option<Ipv6Inet>) -> bool;
}

pub(crate) trait PublicIpv6SyncTrigger: Send + Sync {
    fn sync_now(&self, reason: &str);
}

#[async_trait::async_trait]
pub trait PublicIpv6Host: Send + Sync {
    async fn collect_reserved_public_ipv6_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr>;
    fn public_ipv6_lease_changed(&self, old: Option<Ipv6Inet>, new: Option<Ipv6Inet>);
    fn public_ipv6_routes_changed(&self, added: Vec<Ipv6Inet>, removed: Vec<Ipv6Inet>);
}

#[async_trait::async_trait]
impl PublicIpv6Host for () {
    async fn collect_reserved_public_ipv6_addrs(&self, _prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
        HashSet::new()
    }

    fn public_ipv6_lease_changed(&self, _old: Option<Ipv6Inet>, _new: Option<Ipv6Inet>) {}

    fn public_ipv6_routes_changed(&self, _added: Vec<Ipv6Inet>, _removed: Vec<Ipv6Inet>) {}
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub(crate) trait PublicIpv6Runtime: Send + Sync {
    fn ipv6_public_addr_auto(&self) -> bool;
    fn ipv6_public_addr_provider(&self) -> bool;
    fn instance_id(&self) -> uuid::Uuid;
    fn network_name(&self) -> String;
    async fn collect_reserved_public_ipv6_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr>;
    fn public_ipv6_lease_changed(&self, old: Option<Ipv6Inet>, new: Option<Ipv6Inet>);
    fn public_ipv6_routes_changed(&self, added: Vec<Ipv6Inet>, removed: Vec<Ipv6Inet>);
}

pub struct CorePublicIpv6Runtime {
    config: CoreRuntimeConfigStore,
    host: Arc<dyn PublicIpv6Host>,
    provider_prefix: std::sync::Mutex<Option<Ipv6Cidr>>,
    lease: std::sync::Mutex<Option<Ipv6Inet>>,
}

impl CorePublicIpv6Runtime {
    pub fn new(config: CoreRuntimeConfigStore, host: Arc<dyn PublicIpv6Host>) -> Arc<Self> {
        Arc::new(Self {
            config,
            host,
            provider_prefix: std::sync::Mutex::new(None),
            lease: std::sync::Mutex::new(None),
        })
    }

    pub fn set_provider_prefix(&self, prefix: Option<Ipv6Cidr>) -> bool {
        let mut current = self.provider_prefix.lock().unwrap();
        if *current == prefix {
            return false;
        }
        *current = prefix;
        true
    }
}

impl PeerPublicIpv6State for CorePublicIpv6Runtime {
    fn public_ipv6_lease_contains(&self, ip: &Ipv6Addr) -> bool {
        self.lease
            .lock()
            .unwrap()
            .is_some_and(|lease| lease.address() == *ip)
    }

    fn public_ipv6_provider_enabled(&self) -> bool {
        self.provider_prefix.lock().unwrap().is_some()
    }

    fn advertised_ipv6_public_addr_prefix(&self) -> Option<Ipv6Cidr> {
        *self.provider_prefix.lock().unwrap()
    }
}

#[async_trait::async_trait]
impl PublicIpv6Runtime for CorePublicIpv6Runtime {
    fn ipv6_public_addr_auto(&self) -> bool {
        self.config.snapshot().services.public_ipv6_auto
    }

    fn ipv6_public_addr_provider(&self) -> bool {
        self.config
            .snapshot()
            .services
            .public_ipv6_provider
            .provider_enabled
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.config
            .snapshot()
            .peer
            .runtime
            .core
            .node
            .instance_id
            .map(uuid::Uuid::from_bytes)
            .expect("core peer identity must be finalized before public IPv6 starts")
    }

    fn network_name(&self) -> String {
        self.config
            .snapshot()
            .peer
            .runtime
            .network_identity
            .network_name
            .clone()
    }

    async fn collect_reserved_public_ipv6_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
        self.host.collect_reserved_public_ipv6_addrs(prefix).await
    }

    fn public_ipv6_lease_changed(&self, old: Option<Ipv6Inet>, new: Option<Ipv6Inet>) {
        *self.lease.lock().unwrap() = new;
        self.host.public_ipv6_lease_changed(old, new);
    }

    fn public_ipv6_routes_changed(&self, added: Vec<Ipv6Inet>, removed: Vec<Ipv6Inet>) {
        self.host.public_ipv6_routes_changed(added, removed);
    }
}

pub(super) struct DisabledPublicIpv6Runtime {
    instance_id: uuid::Uuid,
    network_name: String,
}

impl DisabledPublicIpv6Runtime {
    pub(super) fn new(instance_id: uuid::Uuid, network_name: String) -> Self {
        Self {
            instance_id,
            network_name,
        }
    }
}

#[async_trait::async_trait]
impl PublicIpv6Runtime for DisabledPublicIpv6Runtime {
    fn ipv6_public_addr_auto(&self) -> bool {
        false
    }

    fn ipv6_public_addr_provider(&self) -> bool {
        false
    }

    fn instance_id(&self) -> uuid::Uuid {
        self.instance_id
    }

    fn network_name(&self) -> String {
        self.network_name.clone()
    }

    async fn collect_reserved_public_ipv6_addrs(&self, _prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
        HashSet::new()
    }

    fn public_ipv6_lease_changed(&self, _old: Option<Ipv6Inet>, _new: Option<Ipv6Inet>) {}

    fn public_ipv6_routes_changed(&self, _added: Vec<Ipv6Inet>, _removed: Vec<Ipv6Inet>) {}
}

#[cfg(test)]
mod tests {
    use std::net::Ipv6Addr;
    use std::{
        collections::{HashMap, HashSet},
        sync::{Arc, Mutex},
    };

    use cidr::{Ipv6Cidr, Ipv6Inet};

    use crate::{
        config::PeerId,
        config::runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        peers::{context::PeerPublicIpv6State, peer_rpc::PeerRpcManager},
    };

    use super::{
        CorePublicIpv6Runtime, PublicIpv6Host, PublicIpv6PeerRouteInfo, PublicIpv6ProviderConfig,
        PublicIpv6ProviderConfigError, PublicIpv6ProviderResolution, PublicIpv6RouteControl,
        PublicIpv6Runtime, PublicIpv6Service, PublicIpv6SyncTrigger, resolve_public_ipv6_provider,
        service::allocate_public_ipv6_leases,
    };

    struct TestRouteControl {
        my_peer_id: PeerId,
        peers: Mutex<Vec<PublicIpv6PeerRouteInfo>>,
    }

    impl PublicIpv6RouteControl for TestRouteControl {
        fn my_peer_id(&self) -> PeerId {
            self.my_peer_id
        }

        fn peer_route_snapshot(&self) -> Vec<PublicIpv6PeerRouteInfo> {
            self.peers.lock().unwrap().clone()
        }

        fn publish_self_public_ipv6_lease(&self, _lease: Option<Ipv6Inet>) -> bool {
            false
        }
    }

    struct TestSyncTrigger;

    impl PublicIpv6SyncTrigger for TestSyncTrigger {
        fn sync_now(&self, _reason: &str) {}
    }

    struct TestRuntime {
        auto: bool,
        provider: bool,
        inst_id: uuid::Uuid,
        network_name: String,
        reserved: Mutex<HashSet<Ipv6Addr>>,
        lease: Mutex<Option<Ipv6Inet>>,
    }

    impl TestRuntime {
        fn new(auto: bool) -> Self {
            Self {
                auto,
                provider: false,
                inst_id: uuid::Uuid::from_u128(1),
                network_name: "default".to_string(),
                reserved: Mutex::new(HashSet::new()),
                lease: Mutex::new(None),
            }
        }
    }

    #[async_trait::async_trait]
    impl PublicIpv6Runtime for TestRuntime {
        fn ipv6_public_addr_auto(&self) -> bool {
            self.auto
        }

        fn ipv6_public_addr_provider(&self) -> bool {
            self.provider
        }

        fn instance_id(&self) -> uuid::Uuid {
            self.inst_id
        }

        fn network_name(&self) -> String {
            self.network_name.clone()
        }

        async fn collect_reserved_public_ipv6_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
            self.reserved
                .lock()
                .unwrap()
                .iter()
                .copied()
                .filter(|addr| prefix.contains(addr))
                .collect()
        }

        fn public_ipv6_lease_changed(&self, _old: Option<Ipv6Inet>, new: Option<Ipv6Inet>) {
            *self.lease.lock().unwrap() = new;
        }

        fn public_ipv6_routes_changed(&self, _added: Vec<Ipv6Inet>, _removed: Vec<Ipv6Inet>) {}
    }

    #[derive(Default)]
    struct RecordingPublicIpv6Host {
        reserved: Mutex<HashSet<Ipv6Addr>>,
        leases: Mutex<Vec<(Option<Ipv6Inet>, Option<Ipv6Inet>)>>,
        route_deltas: Mutex<Vec<(Vec<Ipv6Inet>, Vec<Ipv6Inet>)>>,
    }

    #[async_trait::async_trait]
    impl PublicIpv6Host for RecordingPublicIpv6Host {
        async fn collect_reserved_public_ipv6_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
            self.reserved
                .lock()
                .unwrap()
                .iter()
                .copied()
                .filter(|addr| prefix.contains(addr))
                .collect()
        }

        fn public_ipv6_lease_changed(&self, old: Option<Ipv6Inet>, new: Option<Ipv6Inet>) {
            self.leases.lock().unwrap().push((old, new));
        }

        fn public_ipv6_routes_changed(&self, added: Vec<Ipv6Inet>, removed: Vec<Ipv6Inet>) {
            self.route_deltas.lock().unwrap().push((added, removed));
        }
    }

    #[tokio::test]
    async fn core_runtime_owns_public_ipv6_state_and_projects_only_host_effects() {
        let instance_id = uuid::Uuid::from_u128(42);
        let mut peer = crate::config::peers::PeerRuntimeSnapshot::default();
        peer.runtime.core.node.instance_id = Some(*instance_id.as_bytes());
        peer.runtime.network_identity.network_name = "owned-by-core".to_owned();
        let config = CoreRuntimeConfigStore::new(
            CoreRuntimeConfig {
                public_ipv6_auto: true,
                public_ipv6_provider: PublicIpv6ProviderConfig {
                    provider_enabled: true,
                    configured_prefix: None,
                    provider_supported: true,
                },
                ..Default::default()
            },
            Arc::new(peer),
        );
        let host = Arc::new(RecordingPublicIpv6Host::default());
        let reserved = "2001:db8::10".parse().unwrap();
        host.reserved.lock().unwrap().insert(reserved);
        let runtime = CorePublicIpv6Runtime::new(config.clone(), host.clone());
        let prefix = "2001:db8::/64".parse().unwrap();
        let lease = "2001:db8::20/64".parse().unwrap();
        let route = "2001:db8::30/128".parse().unwrap();

        assert!(runtime.ipv6_public_addr_auto());
        assert!(runtime.ipv6_public_addr_provider());
        assert_eq!(runtime.instance_id(), instance_id);
        assert_eq!(runtime.network_name(), "owned-by-core");
        assert_eq!(
            runtime.collect_reserved_public_ipv6_addrs(prefix).await,
            HashSet::from([reserved])
        );
        assert!(runtime.set_provider_prefix(Some(prefix)));
        assert!(!runtime.set_provider_prefix(Some(prefix)));
        assert_eq!(runtime.advertised_ipv6_public_addr_prefix(), Some(prefix));

        runtime.public_ipv6_lease_changed(None, Some(lease));
        assert!(runtime.public_ipv6_lease_contains(&lease.address()));
        runtime.public_ipv6_routes_changed(vec![route], Vec::new());
        assert_eq!(
            host.leases.lock().unwrap().as_slice(),
            &[(None, Some(lease))]
        );
        assert_eq!(
            host.route_deltas.lock().unwrap().as_slice(),
            &[(vec![route], Vec::new())]
        );

        config.update_services(|services| {
            services.public_ipv6_auto = false;
            services.public_ipv6_provider.provider_enabled = false;
        });
        assert!(!runtime.ipv6_public_addr_auto());
        assert!(!runtime.ipv6_public_addr_provider());
    }

    #[test]
    fn public_ipv6_lease_allocator_keeps_stable_addresses() {
        let prefix = "2001:db8::/124".parse::<Ipv6Cidr>().unwrap();
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);

        let leases =
            allocate_public_ipv6_leases(prefix, &[first, second], &HashSet::new(), &HashMap::new());
        assert_eq!(leases.len(), 2);
        assert_ne!(leases[0].addr, leases[1].addr);

        let initial_map = HashMap::from([(first, leases[0].addr)]);
        let next = allocate_public_ipv6_leases(prefix, &[first], &HashSet::new(), &initial_map);
        assert_eq!(next.len(), 1);
        assert_eq!(next[0].addr, leases[0].addr);
        assert!(next[0].reused);
    }

    #[test]
    fn public_ipv6_provider_prefers_smallest_instance_id() {
        let info_a = PublicIpv6PeerRouteInfo {
            peer_id: 2,
            inst_id: Some(uuid::Uuid::from_u128(2)),
            is_provider: true,
            prefix: Some("2001:db8:1::/120".parse().unwrap()),
            lease: None,
            reachable: true,
        };
        let info_b = PublicIpv6PeerRouteInfo {
            peer_id: 1,
            inst_id: Some(uuid::Uuid::from_u128(1)),
            is_provider: true,
            prefix: Some("2001:db8:2::/120".parse().unwrap()),
            lease: None,
            reachable: true,
        };

        let selected =
            PublicIpv6Service::selected_provider_from_snapshot(&[info_a, info_b]).unwrap();
        assert_eq!(selected.peer_id, 1);
    }

    #[test]
    fn public_ipv6_provider_prefers_reachable_provider() {
        let unreachable_lower_id = PublicIpv6PeerRouteInfo {
            peer_id: 1,
            inst_id: Some(uuid::Uuid::from_u128(1)),
            is_provider: true,
            prefix: Some("2001:db8:1::/120".parse().unwrap()),
            lease: None,
            reachable: false,
        };
        let reachable_higher_id = PublicIpv6PeerRouteInfo {
            peer_id: 2,
            inst_id: Some(uuid::Uuid::from_u128(2)),
            is_provider: true,
            prefix: Some("2001:db8:2::/120".parse().unwrap()),
            lease: None,
            reachable: true,
        };

        let selected = PublicIpv6Service::selected_provider_from_snapshot(&[
            unreachable_lower_id,
            reachable_higher_id,
        ])
        .unwrap();
        assert_eq!(selected.peer_id, 2);
    }

    #[test]
    fn public_ipv6_lease_allocator_stops_when_only_network_offset_is_left() {
        let prefix = "2001:db8::/126".parse::<Ipv6Cidr>().unwrap();
        let network = prefix.first_address();
        let reserved = HashSet::from([
            Ipv6Addr::from(u128::from(network) + 1),
            Ipv6Addr::from(u128::from(network) + 2),
            Ipv6Addr::from(u128::from(network) + 3),
        ]);

        let leases = allocate_public_ipv6_leases(
            prefix,
            &[uuid::Uuid::from_u128(42)],
            &reserved,
            &HashMap::new(),
        );

        assert!(leases.is_empty());
    }

    #[tokio::test]
    async fn reconcile_runtime_clears_public_ipv6_lease_when_auto_is_disabled() {
        let stale_addr = "2001:db8::123/64".parse().unwrap();
        let runtime = Arc::new(TestRuntime::new(false));
        *runtime.lease.lock().unwrap() = Some(stale_addr);

        let service = Arc::new(PublicIpv6Service::new(
            runtime.clone(),
            std::sync::Weak::<PeerRpcManager>::new(),
            Arc::new(TestRouteControl {
                my_peer_id: 1,
                peers: Mutex::new(Vec::new()),
            }),
            Arc::new(TestSyncTrigger),
        ));
        *service.my_addr_cache.lock().unwrap() = Some(stale_addr);

        service.reconcile_runtime_from_snapshot(&[]);

        assert_eq!(*service.my_addr_cache.lock().unwrap(), None);
        assert_eq!(*runtime.lease.lock().unwrap(), None);
    }

    #[tokio::test]
    async fn reconcile_runtime_updates_public_lease_when_auto_enabled() {
        let public_addr = "2001:db8::123/64".parse().unwrap();
        let runtime = Arc::new(TestRuntime::new(true));

        let service = Arc::new(PublicIpv6Service::new(
            runtime.clone(),
            std::sync::Weak::<PeerRpcManager>::new(),
            Arc::new(TestRouteControl {
                my_peer_id: 1,
                peers: Mutex::new(vec![PublicIpv6PeerRouteInfo {
                    peer_id: 1,
                    inst_id: Some(uuid::Uuid::from_u128(1)),
                    is_provider: false,
                    prefix: None,
                    lease: Some(public_addr),
                    reachable: true,
                }]),
            }),
            Arc::new(TestSyncTrigger),
        ));

        service.reconcile_runtime();

        assert_eq!(*runtime.lease.lock().unwrap(), Some(public_addr));
    }

    #[test]
    fn provider_config_uses_explicit_host_capability() {
        let unsupported = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: None,
            provider_supported: false,
        };
        assert_eq!(
            unsupported.validate(),
            Err(PublicIpv6ProviderConfigError::UnsupportedProvider)
        );

        let disabled = PublicIpv6ProviderConfig {
            provider_enabled: false,
            ..unsupported
        };
        assert!(disabled.validate().is_ok());
        assert!(!disabled.should_run_reconcile());
    }

    #[test]
    fn provider_config_rejects_non_global_prefixes() {
        for prefix in ["::1/128", "fe80::/64", "fd00::/48", "ff00::/8", "::/0"] {
            let config = PublicIpv6ProviderConfig {
                provider_enabled: true,
                configured_prefix: Some(prefix.parse().unwrap()),
                provider_supported: true,
            };
            assert!(matches!(
                config.validate(),
                Err(PublicIpv6ProviderConfigError::InvalidPrefix(_))
            ));
        }
    }

    #[test]
    fn provider_config_accepts_global_prefix() {
        let config = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: Some("2001:db8::/48".parse().unwrap()),
            provider_supported: true,
        };
        assert!(config.validate().is_ok());
        assert!(config.should_run_reconcile());
    }

    #[test]
    fn provider_resolution_prefers_configured_prefix_without_detection() {
        let prefix = "2001:db8::/48".parse().unwrap();
        let config = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: Some(prefix),
            provider_supported: true,
        };
        assert_eq!(
            resolve_public_ipv6_provider(config, Err("detection must be ignored".to_owned())),
            PublicIpv6ProviderResolution::Active(prefix)
        );
    }

    #[test]
    fn provider_resolution_normalizes_auto_detection_results() {
        let config = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: None,
            provider_supported: true,
        };
        let prefix = "2001:db8:1::/56".parse().unwrap();
        assert_eq!(
            resolve_public_ipv6_provider(config, Ok(Some(prefix))),
            PublicIpv6ProviderResolution::Active(prefix)
        );
        assert!(matches!(
            resolve_public_ipv6_provider(config, Ok(None)),
            PublicIpv6ProviderResolution::Pending(message)
                if message.contains("ipv6-public-addr-prefix")
        ));
        assert_eq!(
            resolve_public_ipv6_provider(config, Err("host detection failed".to_owned())),
            PublicIpv6ProviderResolution::Pending("host detection failed".to_owned())
        );
    }

    #[test]
    fn provider_resolution_rejects_invalid_configured_and_detected_prefixes() {
        let configured = PublicIpv6ProviderConfig {
            provider_enabled: true,
            configured_prefix: Some("fd00::/48".parse().unwrap()),
            provider_supported: true,
        };
        assert!(matches!(
            resolve_public_ipv6_provider(configured, Ok(None)),
            PublicIpv6ProviderResolution::Pending(message)
                if message.contains("configured prefix")
        ));

        let detected = PublicIpv6ProviderConfig {
            configured_prefix: None,
            ..configured
        };
        assert!(matches!(
            resolve_public_ipv6_provider(
                detected,
                Ok(Some("fe80::/64".parse().unwrap()))
            ),
            PublicIpv6ProviderResolution::Pending(message)
                if message.contains("detected prefix")
        ));
    }
}

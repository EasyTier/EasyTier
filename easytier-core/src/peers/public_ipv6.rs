use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    net::Ipv6Addr,
    sync::{Arc, Weak},
    time::{Duration, SystemTime},
};

use cidr::{Ipv6Cidr, Ipv6Inet};
use serde::{Deserialize, Serialize};

use crate::{
    config::PeerId,
    peers::{context::PeerPublicIpv6State, peer_rpc::PeerRpcManager},
    proto::{
        common::Void,
        peer_rpc::{
            AcquireIpv6PublicAddrLeaseRequest, GetIpv6PublicAddrLeaseRequest,
            Ipv6PublicAddrLeaseReply, PublicIpv6AddrRpc, PublicIpv6AddrRpcClientFactory,
            ReleaseIpv6PublicAddrLeaseRequest, RenewIpv6PublicAddrLeaseRequest,
        },
        rpc_types::{
            self,
            controller::{BaseController, Controller},
        },
    },
    runtime_config::CoreRuntimeConfigStore,
};

// Use a longer lease with an early renew window to reduce steady-state RPC
// churn while preserving enough margin for transient provider failures.
static PUBLIC_IPV6_LEASE_TTL: Duration = Duration::from_secs(120);
static PUBLIC_IPV6_RENEW_INTERVAL: Duration = Duration::from_secs(40);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicIpv6ProviderConfig {
    pub provider_enabled: bool,
    pub configured_prefix: Option<Ipv6Cidr>,
    pub provider_supported: bool,
}

impl PublicIpv6ProviderConfig {
    pub fn should_run_reconcile(self) -> bool {
        self.provider_enabled
    }

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
pub(crate) struct PublicIpv6Provider {
    pub peer_id: PeerId,
    pub inst_id: uuid::Uuid,
    pub prefix: Ipv6Cidr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PublicIpv6ProviderLease {
    pub peer_id: PeerId,
    pub inst_id: uuid::Uuid,
    pub addr: Ipv6Inet,
    pub valid_until: SystemTime,
    pub reused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicIpv6ProviderState {
    provider: PublicIpv6Provider,
    leases: BTreeMap<uuid::Uuid, PublicIpv6ProviderLease>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicIpv6ClientState {
    provider: PublicIpv6Provider,
    lease: PublicIpv6ProviderLease,
    last_error: Option<String>,
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

pub(crate) struct PublicIpv6Service {
    runtime: Arc<dyn PublicIpv6Runtime>,
    peer_rpc: Weak<PeerRpcManager>,
    route_control: Arc<dyn PublicIpv6RouteControl>,
    sync_trigger: Arc<dyn PublicIpv6SyncTrigger>,

    provider_state: std::sync::Mutex<Option<PublicIpv6ProviderState>>,
    client_state: std::sync::Mutex<Option<PublicIpv6ClientState>>,
    route_cache: std::sync::Mutex<BTreeSet<Ipv6Inet>>,
    my_addr_cache: std::sync::Mutex<Option<Ipv6Inet>>,
}

impl PublicIpv6Service {
    pub fn new(
        runtime: Arc<dyn PublicIpv6Runtime>,
        peer_rpc: Weak<PeerRpcManager>,
        route_control: Arc<dyn PublicIpv6RouteControl>,
        sync_trigger: Arc<dyn PublicIpv6SyncTrigger>,
    ) -> Self {
        Self {
            runtime,
            peer_rpc,
            route_control,
            sync_trigger,
            provider_state: std::sync::Mutex::new(None),
            client_state: std::sync::Mutex::new(None),
            route_cache: std::sync::Mutex::new(BTreeSet::new()),
            my_addr_cache: std::sync::Mutex::new(None),
        }
    }

    pub fn rpc_server(self: &Arc<Self>) -> PublicIpv6AddrRpcServerImpl {
        PublicIpv6AddrRpcServerImpl {
            service: Arc::downgrade(self),
        }
    }

    fn my_peer_id(&self) -> PeerId {
        self.route_control.my_peer_id()
    }

    fn selected_provider(&self) -> Option<PublicIpv6Provider> {
        Self::selected_provider_from_snapshot(&self.route_control.peer_route_snapshot())
    }

    fn current_provider_state(&self) -> Option<PublicIpv6ProviderState> {
        self.provider_state.lock().unwrap().clone()
    }

    fn current_client_state(&self) -> Option<PublicIpv6ClientState> {
        self.client_state.lock().unwrap().clone()
    }

    fn set_provider_state(&self, next: Option<PublicIpv6ProviderState>) -> bool {
        let mut guard = self.provider_state.lock().unwrap();
        if *guard == next {
            return false;
        }
        *guard = next;
        true
    }

    fn set_client_state(&self, next: Option<PublicIpv6ClientState>) -> bool {
        let mut guard = self.client_state.lock().unwrap();
        if *guard == next {
            return false;
        }
        *guard = next;
        true
    }

    fn selected_provider_from_snapshot(
        peers: &[PublicIpv6PeerRouteInfo],
    ) -> Option<PublicIpv6Provider> {
        peers
            .iter()
            .filter(|info| info.is_provider)
            .filter(|info| info.reachable)
            .filter_map(|info| {
                Some(PublicIpv6Provider {
                    peer_id: info.peer_id,
                    inst_id: info.inst_id?,
                    prefix: info.prefix?,
                })
            })
            .min_by_key(|provider| provider.inst_id)
    }

    fn clear_provider_state_if_provider_changed(
        &self,
        provider: Option<&PublicIpv6Provider>,
    ) -> bool {
        let current = self.current_provider_state();
        let should_clear = current
            .as_ref()
            .is_some_and(|state| provider != Some(&state.provider));
        should_clear && self.set_provider_state(None)
    }

    fn clear_client_state_if_provider_changed(
        &self,
        provider: Option<&PublicIpv6Provider>,
    ) -> bool {
        let current = self.current_client_state();
        let should_clear = current
            .as_ref()
            .is_some_and(|state| provider != Some(&state.provider));
        should_clear && self.set_client_state(None)
    }

    fn collect_runtime_from_snapshot(
        &self,
        peers: &[PublicIpv6PeerRouteInfo],
    ) -> (Option<Ipv6Inet>, BTreeSet<Ipv6Inet>) {
        let mut my_addr = self.current_client_state().map(|state| state.lease.addr);
        let mut routes = BTreeSet::new();

        for info in peers {
            let Some(lease) = info.lease else {
                continue;
            };

            if info.peer_id == self.my_peer_id() {
                my_addr = Some(lease);
                continue;
            }

            if info.reachable {
                routes.insert(lease);
            }
        }

        (my_addr, routes)
    }

    fn reconcile_runtime_from_snapshot(&self, peers: &[PublicIpv6PeerRouteInfo]) {
        let (mut my_addr, routes) = self.collect_runtime_from_snapshot(peers);
        if !self.runtime.ipv6_public_addr_auto() {
            my_addr = None;
        }

        let mut cached_my_addr = self.my_addr_cache.lock().unwrap();
        if *cached_my_addr != my_addr {
            let old = *cached_my_addr;
            *cached_my_addr = my_addr;
            self.runtime.public_ipv6_lease_changed(old, my_addr);
        }
        drop(cached_my_addr);

        let mut cached_routes = self.route_cache.lock().unwrap();
        if *cached_routes != routes {
            let added = routes
                .difference(&cached_routes)
                .copied()
                .collect::<Vec<_>>();
            let removed = cached_routes
                .difference(&routes)
                .copied()
                .collect::<Vec<_>>();
            *cached_routes = routes;
            self.runtime.public_ipv6_routes_changed(added, removed);
        }
    }

    fn reconcile_runtime(&self) {
        let peers = self.route_control.peer_route_snapshot();
        self.reconcile_runtime_from_snapshot(&peers);
    }

    pub fn handle_route_change(&self) -> bool {
        let peers = self.route_control.peer_route_snapshot();
        let provider = Self::selected_provider_from_snapshot(&peers);
        let _provider_changed = self.clear_provider_state_if_provider_changed(provider.as_ref());
        let client_changed = self.clear_client_state_if_provider_changed(provider.as_ref());

        let peer_info_changed = if client_changed {
            self.publish_current_client_lease()
        } else {
            false
        };

        // When client state changed, publish_current_client_lease() mutated the
        // local peer info synchronously, so the pre-update snapshot is stale for
        // this node's own entry.  Re-fetch to avoid reconciling against old data.
        if client_changed {
            self.reconcile_runtime();
        } else {
            self.reconcile_runtime_from_snapshot(&peers);
        }
        peer_info_changed
    }

    fn publish_current_client_lease(&self) -> bool {
        self.route_control.publish_self_public_ipv6_lease(
            self.current_client_state()
                .as_ref()
                .map(|state| state.lease.addr),
        )
    }

    fn clear_client_lease_state(&self, mut state_changed: bool) -> bool {
        state_changed |= self.set_client_state(None);
        let peer_info_changed = if state_changed {
            self.route_control.publish_self_public_ipv6_lease(None)
        } else {
            false
        };
        if state_changed {
            // publish_self_public_ipv6_lease mutated the local peer info above,
            // so the snapshot passed in is stale for this node.
            self.reconcile_runtime();
        }
        peer_info_changed
    }

    fn build_lease_reply(
        provider: &PublicIpv6Provider,
        lease: Option<&PublicIpv6ProviderLease>,
        error_msg: Option<String>,
    ) -> Ipv6PublicAddrLeaseReply {
        Ipv6PublicAddrLeaseReply {
            provider_peer_id: provider.peer_id,
            provider_inst_id: Some(provider.inst_id.into()),
            provider_prefix: Some(
                Ipv6Inet::new(
                    provider.prefix.first_address(),
                    provider.prefix.network_length(),
                )
                .unwrap()
                .into(),
            ),
            leased_addr: lease.map(|lease| lease.addr.into()),
            valid_until: lease.map(|lease| lease.valid_until.into()),
            reused: lease.map(|lease| lease.reused).unwrap_or(false),
            error_msg,
        }
    }

    async fn collect_reserved_addrs(&self, prefix: Ipv6Cidr) -> HashSet<Ipv6Addr> {
        self.runtime
            .collect_reserved_public_ipv6_addrs(prefix)
            .await
    }

    fn prune_expired_leases(
        provider: &PublicIpv6Provider,
        current: Option<PublicIpv6ProviderState>,
    ) -> PublicIpv6ProviderState {
        let mut state = current.unwrap_or_else(|| PublicIpv6ProviderState {
            provider: provider.clone(),
            leases: BTreeMap::new(),
        });
        state.provider = provider.clone();
        let now = SystemTime::now();
        state.leases.retain(|_, lease| lease.valid_until > now);
        state
    }

    async fn acquire_lease(
        &self,
        requester_peer_id: PeerId,
        requester_inst_id: uuid::Uuid,
        renew_only: bool,
        requested_addr: Option<Ipv6Inet>,
    ) -> Result<PublicIpv6ProviderLease, String> {
        let provider = self
            .selected_provider()
            .ok_or_else(|| "no active ipv6 public address provider".to_string())?;
        if provider.peer_id != self.my_peer_id() {
            return Err("this peer is not the selected ipv6 public address provider".to_string());
        }

        let mut state = Self::prune_expired_leases(&provider, self.current_provider_state());
        if let Some(existing) = state.leases.get_mut(&requester_inst_id) {
            if requested_addr.is_some() && requested_addr != Some(existing.addr) {
                return Err("requested lease does not match the active allocation".to_string());
            }
            existing.peer_id = requester_peer_id;
            existing.valid_until = SystemTime::now() + PUBLIC_IPV6_LEASE_TTL;
            existing.reused = true;
            let lease = existing.clone();
            self.set_provider_state(Some(state));
            return Ok(lease);
        }

        if renew_only {
            return Err("lease not found".to_string());
        }

        let mut reserved = self.collect_reserved_addrs(provider.prefix).await;
        let old_map = state
            .leases
            .iter()
            .map(|(inst_id, lease)| {
                reserved.insert(lease.addr.address());
                (*inst_id, lease.addr)
            })
            .collect::<HashMap<_, _>>();

        let mut allocated =
            allocate_public_ipv6_leases(provider.prefix, &[requester_inst_id], &reserved, &old_map);
        let Some(mut lease) = allocated.pop() else {
            return Err(format!(
                "no free ipv6 address left in provider prefix {}",
                provider.prefix
            ));
        };
        lease.peer_id = requester_peer_id;
        lease.valid_until = SystemTime::now() + PUBLIC_IPV6_LEASE_TTL;

        state.leases.insert(requester_inst_id, lease.clone());
        self.set_provider_state(Some(state));
        Ok(lease)
    }

    fn release_lease(&self, requester_peer_id: PeerId, requester_inst_id: uuid::Uuid) -> bool {
        let Some(provider) = self.selected_provider() else {
            return false;
        };
        if provider.peer_id != self.my_peer_id() {
            return false;
        }

        let mut state = Self::prune_expired_leases(&provider, self.current_provider_state());
        let removed = state
            .leases
            .get(&requester_inst_id)
            .map(|lease| lease.peer_id == requester_peer_id)
            .unwrap_or(false);
        if !removed {
            return false;
        }

        state.leases.remove(&requester_inst_id);
        self.set_provider_state(Some(state))
    }

    fn get_lease(
        &self,
        requester_peer_id: PeerId,
        requester_inst_id: uuid::Uuid,
        requested_addr: Option<Ipv6Inet>,
    ) -> Result<(PublicIpv6Provider, PublicIpv6ProviderLease), String> {
        let provider = self
            .selected_provider()
            .ok_or_else(|| "no active ipv6 public address provider".to_string())?;
        if provider.peer_id != self.my_peer_id() {
            return Err("this peer is not the selected ipv6 public address provider".to_string());
        }

        let state = Self::prune_expired_leases(&provider, self.current_provider_state());
        let Some(lease) = state.leases.get(&requester_inst_id) else {
            return Err("lease not found".to_string());
        };
        if lease.peer_id != requester_peer_id {
            return Err("lease owner mismatch".to_string());
        }
        if requested_addr.is_some() && requested_addr != Some(lease.addr) {
            return Err("requested lease does not match the active allocation".to_string());
        }
        Ok((provider, lease.clone()))
    }

    pub async fn gc_provider_leases(&self) {
        let peers = self.route_control.peer_route_snapshot();
        let provider = Self::selected_provider_from_snapshot(&peers);
        self.clear_provider_state_if_provider_changed(provider.as_ref());

        let Some(provider) = provider else {
            return;
        };
        if provider.peer_id != self.my_peer_id() {
            return;
        }

        let state = Self::prune_expired_leases(&provider, self.current_provider_state());
        self.set_provider_state(Some(state));
    }

    pub async fn sync_client_state(&self) -> bool {
        if !self.runtime.ipv6_public_addr_auto() {
            return self
                .clear_client_lease_state(self.clear_client_state_if_provider_changed(None));
        }

        let peers = self.route_control.peer_route_snapshot();
        let provider = Self::selected_provider_from_snapshot(&peers);
        self.clear_provider_state_if_provider_changed(provider.as_ref());
        let state_changed = self.clear_client_state_if_provider_changed(provider.as_ref());

        let Some(provider) = provider else {
            return self.clear_client_lease_state(state_changed);
        };

        if provider.peer_id == self.my_peer_id() {
            return self.clear_client_lease_state(state_changed);
        }

        let current = self.current_client_state();
        let need_rpc = current.as_ref().is_none_or(|state| {
            state.provider != provider
                || state.lease.valid_until <= SystemTime::now() + PUBLIC_IPV6_RENEW_INTERVAL
        });

        if !need_rpc {
            if state_changed {
                self.reconcile_runtime();
            }
            return false;
        }

        let Some(peer_rpc) = self.peer_rpc.upgrade() else {
            if state_changed {
                self.reconcile_runtime();
            }
            return false;
        };

        let mut ctrl = BaseController::default();
        ctrl.set_timeout_ms(3000);
        let rpc_stub = peer_rpc
            .rpc_client()
            .scoped_client::<PublicIpv6AddrRpcClientFactory<BaseController>>(
                self.my_peer_id(),
                provider.peer_id,
                self.runtime.network_name(),
            );

        let inst_id = self.runtime.instance_id();
        let reply = if let Some(state) = current.as_ref().filter(|state| state.provider == provider)
        {
            match rpc_stub
                .renew_lease(
                    ctrl.clone(),
                    RenewIpv6PublicAddrLeaseRequest {
                        peer_id: self.my_peer_id(),
                        inst_id: Some(inst_id.into()),
                        leased_addr: Some(state.lease.addr.into()),
                    },
                )
                .await
            {
                Ok(reply) if reply.error_msg.is_none() => Ok(reply),
                Ok(_) | Err(_) => {
                    rpc_stub
                        .acquire_lease(
                            ctrl.clone(),
                            AcquireIpv6PublicAddrLeaseRequest {
                                peer_id: self.my_peer_id(),
                                inst_id: Some(inst_id.into()),
                            },
                        )
                        .await
                }
            }
        } else {
            rpc_stub
                .acquire_lease(
                    ctrl,
                    AcquireIpv6PublicAddrLeaseRequest {
                        peer_id: self.my_peer_id(),
                        inst_id: Some(inst_id.into()),
                    },
                )
                .await
        };

        let mut state_changed = state_changed;

        match reply {
            Ok(reply) if reply.error_msg.is_none() => {
                let Some(leased_addr) = reply.leased_addr.map(Into::into) else {
                    return false;
                };
                let valid_until = reply
                    .valid_until
                    .and_then(|ts| SystemTime::try_from(ts).ok())
                    .unwrap_or_else(|| SystemTime::now() + PUBLIC_IPV6_LEASE_TTL);
                let next_state = PublicIpv6ClientState {
                    provider: provider.clone(),
                    lease: PublicIpv6ProviderLease {
                        peer_id: self.my_peer_id(),
                        inst_id,
                        addr: leased_addr,
                        valid_until,
                        reused: reply.reused,
                    },
                    last_error: None,
                };
                state_changed |= self.set_client_state(Some(next_state));
            }
            Ok(_) | Err(_) => {
                let should_clear = current
                    .as_ref()
                    .map(|state| state.lease.valid_until <= SystemTime::now())
                    .unwrap_or(true);
                if should_clear {
                    state_changed |= self.set_client_state(None);
                }
            }
        }

        let peer_info_changed = if state_changed {
            self.publish_current_client_lease()
        } else {
            false
        };

        if state_changed {
            self.reconcile_runtime();
        }

        peer_info_changed
    }

    pub async fn provider_gc_routine(self: Arc<Self>) {
        if !self.runtime.ipv6_public_addr_provider() {
            return;
        }
        loop {
            crate::runtime_time::sleep(Duration::from_secs(15)).await;
            self.gc_provider_leases().await;
        }
    }

    pub async fn client_routine(self: Arc<Self>) {
        loop {
            if self.sync_client_state().await {
                self.sync_trigger.sync_now("sync_public_ipv6_client_state");
            }
            crate::runtime_time::sleep(Duration::from_secs(5)).await;
        }
    }

    pub fn list_routes(&self) -> BTreeSet<Ipv6Inet> {
        self.route_cache.lock().unwrap().clone()
    }

    pub fn my_addr(&self) -> Option<Ipv6Inet> {
        *self.my_addr_cache.lock().unwrap()
    }

    pub fn provider_peer_id_for_client(&self) -> Option<PeerId> {
        self.current_client_state()
            .map(|state| state.provider.peer_id)
    }

    pub fn local_provider_state(
        &self,
    ) -> Option<(PublicIpv6Provider, Vec<PublicIpv6ProviderLease>)> {
        let provider = self.selected_provider()?;
        if provider.peer_id != self.my_peer_id() {
            return None;
        }

        let state = Self::prune_expired_leases(&provider, self.current_provider_state());
        let mut leases = state.leases.into_values().collect::<Vec<_>>();
        leases.sort_by_key(|lease| (lease.peer_id, lease.inst_id, lease.addr));
        Some((provider, leases))
    }
}

#[derive(Clone)]
pub(crate) struct PublicIpv6AddrRpcServerImpl {
    service: Weak<PublicIpv6Service>,
}

impl PublicIpv6AddrRpcServerImpl {
    fn selected_provider(
        service: &PublicIpv6Service,
    ) -> rpc_types::error::Result<PublicIpv6Provider> {
        service
            .selected_provider()
            .ok_or_else(|| anyhow::anyhow!("provider not available").into())
    }

    fn build_error_reply(
        service: &PublicIpv6Service,
        error_msg: String,
    ) -> rpc_types::error::Result<Ipv6PublicAddrLeaseReply> {
        Ok(PublicIpv6Service::build_lease_reply(
            &Self::selected_provider(service)?,
            None,
            Some(error_msg),
        ))
    }
}

#[async_trait::async_trait]
impl PublicIpv6AddrRpc for PublicIpv6AddrRpcServerImpl {
    type Controller = BaseController;

    async fn acquire_lease(
        &self,
        _: BaseController,
        request: AcquireIpv6PublicAddrLeaseRequest,
    ) -> rpc_types::error::Result<Ipv6PublicAddrLeaseReply> {
        let Some(service) = self.service.upgrade() else {
            return Err(anyhow::anyhow!("public ipv6 service stopped").into());
        };
        let inst_id: uuid::Uuid = request
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("inst_id is required"))?
            .into();

        match service
            .acquire_lease(request.peer_id, inst_id, false, None)
            .await
        {
            Ok(lease) => Ok(PublicIpv6Service::build_lease_reply(
                &Self::selected_provider(&service)?,
                Some(&lease),
                None,
            )),
            Err(error_msg) => Self::build_error_reply(&service, error_msg),
        }
    }

    async fn renew_lease(
        &self,
        _: BaseController,
        request: RenewIpv6PublicAddrLeaseRequest,
    ) -> rpc_types::error::Result<Ipv6PublicAddrLeaseReply> {
        let Some(service) = self.service.upgrade() else {
            return Err(anyhow::anyhow!("public ipv6 service stopped").into());
        };
        let inst_id: uuid::Uuid = request
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("inst_id is required"))?
            .into();
        let requested_addr = request.leased_addr.map(Into::into);

        match service
            .acquire_lease(request.peer_id, inst_id, true, requested_addr)
            .await
        {
            Ok(lease) => Ok(PublicIpv6Service::build_lease_reply(
                &Self::selected_provider(&service)?,
                Some(&lease),
                None,
            )),
            Err(error_msg) => Self::build_error_reply(&service, error_msg),
        }
    }

    async fn release_lease(
        &self,
        _: BaseController,
        request: ReleaseIpv6PublicAddrLeaseRequest,
    ) -> rpc_types::error::Result<Void> {
        let Some(service) = self.service.upgrade() else {
            return Err(anyhow::anyhow!("public ipv6 service stopped").into());
        };
        let inst_id: uuid::Uuid = request
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("inst_id is required"))?
            .into();
        service.release_lease(request.peer_id, inst_id);
        Ok(Default::default())
    }

    async fn get_lease(
        &self,
        _: BaseController,
        request: GetIpv6PublicAddrLeaseRequest,
    ) -> rpc_types::error::Result<Ipv6PublicAddrLeaseReply> {
        let Some(service) = self.service.upgrade() else {
            return Err(anyhow::anyhow!("public ipv6 service stopped").into());
        };
        let inst_id: uuid::Uuid = request
            .inst_id
            .ok_or_else(|| anyhow::anyhow!("inst_id is required"))?
            .into();
        match service.get_lease(request.peer_id, inst_id, None) {
            Ok((provider, lease)) => Ok(PublicIpv6Service::build_lease_reply(
                &provider,
                Some(&lease),
                None,
            )),
            Err(error_msg) => Self::build_error_reply(&service, error_msg),
        }
    }
}

fn allocate_public_ipv6_leases(
    prefix: Ipv6Cidr,
    auto_peer_ids: &[uuid::Uuid],
    reserved: &HashSet<Ipv6Addr>,
    old_map: &HashMap<uuid::Uuid, Ipv6Inet>,
) -> Vec<PublicIpv6ProviderLease> {
    let prefix_len = prefix.network_length();
    let host_bits = 128_u32.saturating_sub(prefix_len as u32);
    let max_offsets = if host_bits == 128 {
        None
    } else {
        Some(1_u128 << host_bits)
    };
    let network = u128::from(prefix.first_address());

    let mut used_offsets = reserved
        .iter()
        .filter(|addr| prefix.contains(addr))
        .map(|addr| u128::from(*addr).saturating_sub(network))
        .collect::<HashSet<_>>();

    let mut leases = Vec::with_capacity(auto_peer_ids.len());
    for inst_id in auto_peer_ids.iter().copied() {
        let addr = if let Some(existing) = old_map.get(&inst_id).copied()
            && prefix.contains(&existing.address())
            && used_offsets.insert(u128::from(existing.address()).saturating_sub(network))
        {
            existing
        } else {
            let Some(max_offsets) = max_offsets else {
                continue;
            };
            let usable_slots = max_offsets.saturating_sub(1);
            let offset = if usable_slots == 0 {
                used_offsets.insert(0).then_some(0)
            } else {
                let start_offset = (inst_id.as_u128() % usable_slots) + 1;
                (0..usable_slots)
                    .map(|step| ((start_offset - 1 + step) % usable_slots) + 1)
                    .find(|offset| used_offsets.insert(*offset))
            };
            let Some(offset) = offset else {
                break;
            };

            Ipv6Inet::new(Ipv6Addr::from(network + offset), 128).unwrap()
        };

        leases.push(PublicIpv6ProviderLease {
            peer_id: 0,
            inst_id,
            addr,
            valid_until: SystemTime::UNIX_EPOCH,
            reused: old_map
                .get(&inst_id)
                .map(|old| *old == addr)
                .unwrap_or(false),
        });
    }

    leases
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
        peers::{context::PeerPublicIpv6State, peer_rpc::PeerRpcManager},
        runtime_config::{CoreRuntimeConfig, CoreRuntimeConfigStore},
    };

    use super::{
        CorePublicIpv6Runtime, PublicIpv6Host, PublicIpv6PeerRouteInfo, PublicIpv6ProviderConfig,
        PublicIpv6ProviderConfigError, PublicIpv6ProviderResolution, PublicIpv6RouteControl,
        PublicIpv6Runtime, PublicIpv6Service, PublicIpv6SyncTrigger, allocate_public_ipv6_leases,
        resolve_public_ipv6_provider,
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
        let mut peer = crate::peers::context::PeerRuntimeSnapshot::default();
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

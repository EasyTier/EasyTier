use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};
use tokio::sync::{Mutex, Notify};

use crate::common::error::Error;
use easytier_core::tunnel::{Tunnel, ring::create_ring_tunnel_pair};

#[cfg(mobile)]
use super::virtual_nic::MobileTunSources;
use super::virtual_nic::{VirtualNic, VirtualNicConfig};

#[cfg(not(target_os = "linux"))]
use crate::common::ifcfg::IfConfiger;

mod dispatcher;

use dispatcher::{SharedVirtualNicDispatcher, SharedVirtualNicMemberTunnelTable};

pub type SharedVirtualNicMemberId = uuid::Uuid;
pub(super) type SharedVirtualNicMemberRegistrationId = uuid::Uuid;
pub(crate) type ArcSharedVirtualNicRegistry = Arc<Mutex<SharedVirtualNicRegistry>>;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SharedIpv4Route {
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub cost: Option<i32>,
}

impl SharedIpv4Route {
    pub fn new(address: Ipv4Addr, prefix: u8, cost: Option<i32>) -> Self {
        Self {
            address,
            prefix,
            cost,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SharedIpv6Route {
    pub address: Ipv6Addr,
    pub prefix: u8,
    pub cost: Option<i32>,
}

impl SharedIpv6Route {
    pub fn new(address: Ipv6Addr, prefix: u8, cost: Option<i32>) -> Self {
        Self {
            address,
            prefix,
            cost,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedIfConfigClaims {
    pub ipv4_addresses: BTreeSet<Ipv4Inet>,
    pub ipv6_addresses: BTreeSet<Ipv6Inet>,
    pub ipv4_routes: BTreeSet<SharedIpv4Route>,
    pub ipv6_routes: BTreeSet<SharedIpv6Route>,
    pub mtu: Option<u32>,
}

impl SharedIfConfigClaims {
    fn ipv4_destinations(&self) -> impl Iterator<Item = Ipv4Cidr> + '_ {
        self.ipv4_addresses.iter().map(Ipv4Inet::network).chain(
            self.ipv4_routes
                .iter()
                .filter_map(|route| Ipv4Inet::new(route.address, route.prefix).ok())
                .map(|route| route.network()),
        )
    }

    fn ipv6_destinations(&self) -> impl Iterator<Item = Ipv6Cidr> + '_ {
        self.ipv6_addresses.iter().map(Ipv6Inet::network).chain(
            self.ipv6_routes
                .iter()
                .filter_map(|route| Ipv6Inet::new(route.address, route.prefix).ok())
                .map(|route| route.network()),
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedItemDelta<T> {
    pub added: BTreeSet<T>,
    pub removed: BTreeSet<T>,
}

impl<T> Default for OwnedItemDelta<T> {
    fn default() -> Self {
        Self {
            added: BTreeSet::new(),
            removed: BTreeSet::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharedMtuChange {
    pub old: Option<u32>,
    pub new: Option<u32>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedIfConfigDelta {
    pub ipv4_addresses: OwnedItemDelta<Ipv4Inet>,
    pub ipv6_addresses: OwnedItemDelta<Ipv6Inet>,
    pub ipv4_routes: OwnedItemDelta<SharedIpv4Route>,
    pub ipv6_routes: OwnedItemDelta<SharedIpv6Route>,
    pub mtu: Option<SharedMtuChange>,
}

impl SharedIfConfigDelta {
    fn between(old: &EffectiveIfConfig, new: &EffectiveIfConfig) -> Self {
        Self {
            ipv4_addresses: item_delta(&old.ipv4_addresses, &new.ipv4_addresses),
            ipv6_addresses: item_delta(&old.ipv6_addresses, &new.ipv6_addresses),
            ipv4_routes: item_delta(&old.ipv4_routes, &new.ipv4_routes),
            ipv6_routes: item_delta(&old.ipv6_routes, &new.ipv6_routes),
            mtu: mtu_delta(old.effective_mtu, new.effective_mtu),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct EffectiveIfConfig {
    ipv4_addresses: BTreeSet<Ipv4Inet>,
    ipv6_addresses: BTreeSet<Ipv6Inet>,
    ipv4_routes: BTreeSet<SharedIpv4Route>,
    ipv6_routes: BTreeSet<SharedIpv6Route>,
    effective_mtu: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct SharedIfConfig {
    member_claims: BTreeMap<SharedVirtualNicMemberId, SharedIfConfigClaims>,
}

impl SharedIfConfig {
    fn ensure_disjoint(
        &self,
        member_id: SharedVirtualNicMemberId,
        claims: &SharedIfConfigClaims,
    ) -> anyhow::Result<()> {
        let magic_dns = Ipv4Cidr::new(crate::instance::dns_server::MAGIC_DNS_FAKE_IP.parse()?, 32)?;
        for (other_id, other) in &self.member_claims {
            if *other_id == member_id {
                continue;
            }
            for requested in claims.ipv4_destinations() {
                if let Some(existing) = other.ipv4_destinations().find(|existing| {
                    !(requested == magic_dns && *existing == magic_dns)
                        && ipv4_cidrs_overlap(requested, *existing)
                }) {
                    anyhow::bail!(
                        "shared virtual NIC destination {requested} overlaps member {other_id} destination {existing}"
                    );
                }
            }
            for requested in claims.ipv6_destinations() {
                if let Some(existing) = other
                    .ipv6_destinations()
                    .find(|existing| ipv6_cidrs_overlap(requested, *existing))
                {
                    anyhow::bail!(
                        "shared virtual NIC destination {requested} overlaps member {other_id} destination {existing}"
                    );
                }
            }
        }
        Ok(())
    }

    fn apply_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> SharedIfConfigDelta {
        let old = self.effective();
        self.member_claims.insert(member_id, claims);
        SharedIfConfigDelta::between(&old, &self.effective())
    }

    pub fn remove_member(
        &mut self,
        member_id: SharedVirtualNicMemberId,
    ) -> Option<SharedIfConfigDelta> {
        let old = self.effective();
        self.member_claims.remove(&member_id)?;
        Some(SharedIfConfigDelta::between(&old, &self.effective()))
    }

    pub fn effective_mtu(&self) -> Option<u32> {
        self.member_claims
            .values()
            .filter_map(|claims| claims.mtu)
            .min()
    }

    pub fn owners_of_ipv4_route(
        &self,
        route: &SharedIpv4Route,
    ) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_for(&self.member_claims, |claims| &claims.ipv4_routes, route)
    }

    pub fn owners_of_ipv4_address(&self, address: &Ipv4Inet) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_for(
            &self.member_claims,
            |claims| &claims.ipv4_addresses,
            address,
        )
    }

    fn effective(&self) -> EffectiveIfConfig {
        EffectiveIfConfig {
            ipv4_addresses: self
                .member_claims
                .values()
                .flat_map(|claims| claims.ipv4_addresses.iter().copied())
                .collect(),
            ipv6_addresses: self
                .member_claims
                .values()
                .flat_map(|claims| claims.ipv6_addresses.iter().copied())
                .collect(),
            ipv4_routes: self
                .member_claims
                .values()
                .flat_map(|claims| claims.ipv4_routes.iter().cloned())
                .collect(),
            ipv6_routes: self
                .member_claims
                .values()
                .flat_map(|claims| claims.ipv6_routes.iter().cloned())
                .collect(),
            effective_mtu: self.effective_mtu(),
        }
    }

    fn claims_of(&self, member_id: SharedVirtualNicMemberId) -> SharedIfConfigClaims {
        self.member_claims
            .get(&member_id)
            .cloned()
            .unwrap_or_default()
    }

    fn ipv4_route_source_hint(&self, route: &SharedIpv4Route) -> Option<Ipv4Addr> {
        let route_inet = Ipv4Inet::new(route.address, route.prefix).ok();
        let mut fallback = None;

        for claims in self.member_claims.values() {
            if !claims.ipv4_routes.contains(route) {
                continue;
            }

            for address in &claims.ipv4_addresses {
                fallback.get_or_insert(address.address());
                if route_inet
                    .as_ref()
                    .is_some_and(|route_inet| route_inet.contains(&address.address()))
                {
                    return Some(address.address());
                }
            }
        }

        fallback
    }

    fn changed_ipv4_route_sources(&self, next: &Self) -> BTreeSet<SharedIpv4Route> {
        let old_routes = self.effective().ipv4_routes;
        let next_routes = next.effective().ipv4_routes;
        old_routes
            .iter()
            .filter(|route| {
                next_routes.contains(*route)
                    && self.ipv4_route_source_hint(route) != next.ipv4_route_source_hint(route)
            })
            .cloned()
            .collect()
    }
}

pub struct SharedVirtualNic {
    nic: Arc<Mutex<VirtualNic>>,
    ifcfg: SharedIfConfig,
    valid: Arc<AtomicBool>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    member_registrations: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberRegistrationId>,
    dispatcher: Option<SharedVirtualNicDispatcher>,
}

impl SharedVirtualNic {
    pub fn new(config: VirtualNicConfig) -> Self {
        Self {
            nic: Arc::new(Mutex::new(VirtualNic::new(config))),
            ifcfg: SharedIfConfig::default(),
            valid: Arc::new(AtomicBool::new(true)),
            member_tunnel_table: SharedVirtualNicMemberTunnelTable::default(),
            member_registrations: BTreeMap::new(),
            dispatcher: None,
        }
    }

    pub fn mark_invalid(&self) {
        self.valid.store(false, Ordering::Release);
    }

    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    pub fn ifcfg(&self) -> &SharedIfConfig {
        &self.ifcfg
    }

    pub fn ifcfg_mut(&mut self) -> &mut SharedIfConfig {
        &mut self.ifcfg
    }

    pub fn nic(&self) -> Arc<Mutex<VirtualNic>> {
        self.nic.clone()
    }

    #[cfg(not(target_os = "linux"))]
    async fn ifcfg_and_ifname(&self) -> Result<(IfConfiger, String), Error> {
        self.ensure_valid()?;
        let nic = self.nic.lock().await;
        Ok((nic.get_ifcfg(), nic.ifname().to_owned()))
    }

    async fn link_up(&self) -> Result<(), Error> {
        self.ensure_valid()?;
        self.nic.lock().await.link_up().await
    }

    async fn attach_member_registration(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        match self.member_registrations.get(&member_id).copied() {
            Some(old_registration_id) if old_registration_id == registration_id => {
                return Ok(());
            }
            Some(_) => {
                if let Err(err) = self.remove_member_claims(member_id).await {
                    self.invalidate_and_shutdown_dispatcher().await;
                    return Err(err);
                }
            }
            None => {}
        }

        self.member_registrations.insert(member_id, registration_id);
        Ok(())
    }

    fn is_current_member_registration(
        &self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) -> bool {
        self.member_registrations
            .get(&member_id)
            .is_some_and(|current| *current == registration_id)
    }

    async fn apply_member_claims_for_registration(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            return Ok(());
        }
        self.apply_member_claims(member_id, claims).await
    }

    #[cfg(mobile)]
    async fn apply_member_claims_for_mobile_registration(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            return Ok(());
        }
        self.apply_member_claims_for_mobile(member_id, claims).await
    }

    async fn remove_member_registration_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            return Ok(());
        }

        if let Err(err) = self.remove_member_claims(member_id).await {
            self.member_registrations.remove(&member_id);
            self.invalidate_and_shutdown_dispatcher().await;
            return Err(err);
        }

        self.member_registrations.remove(&member_id);
        self.shutdown_dispatcher_if_idle().await;
        Ok(())
    }

    async fn apply_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        self.ensure_valid()?;
        self.ifcfg.ensure_disjoint(member_id, &claims)?;

        let mut next_ifcfg = self.ifcfg.clone();
        let old_claims = self.ifcfg.claims_of(member_id);
        let next_claims = claims.clone();
        let delta = next_ifcfg.apply_member_claims(member_id, claims);
        self.sync_dispatcher_sources_for_ifcfg_update(member_id, &old_claims, &next_claims)
            .await?;

        if let Err(err) = self.apply_ifcfg_delta(&delta, &next_ifcfg).await {
            let _ = self
                .sync_dispatcher_sources_for_claims(member_id, &old_claims)
                .await;
            return Err(err);
        }

        self.sync_dispatcher_sources_for_claims(member_id, &next_claims)
            .await?;
        self.ifcfg = next_ifcfg;

        Ok(())
    }

    #[cfg(mobile)]
    async fn apply_member_claims_for_mobile(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        self.ensure_valid()?;
        self.ifcfg.ensure_disjoint(member_id, &claims)?;

        let mut next_ifcfg = self.ifcfg.clone();
        let next_claims = claims.clone();
        next_ifcfg.apply_member_claims(member_id, claims);

        self.sync_dispatcher_sources_for_claims(member_id, &next_claims)
            .await?;
        self.ifcfg = next_ifcfg;

        Ok(())
    }

    async fn apply_member_mtu_for_registration(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        mtu: u32,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            return Ok(());
        }

        let mut claims = self.ifcfg.claims_of(member_id);
        claims.mtu = Some(mtu);
        self.apply_member_claims(member_id, claims).await
    }

    #[cfg(mobile)]
    async fn apply_member_mtu_for_mobile_registration(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        mtu: u32,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            return Ok(());
        }

        let mut claims = self.ifcfg.claims_of(member_id);
        claims.mtu = Some(mtu);
        self.apply_member_claims_for_mobile(member_id, claims).await
    }

    async fn remove_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        let mut next_ifcfg = self.ifcfg.clone();
        let Some(delta) = next_ifcfg.remove_member(member_id) else {
            return Ok(());
        };
        #[cfg(not(mobile))]
        self.apply_ifcfg_delta(&delta, &next_ifcfg).await?;
        #[cfg(mobile)]
        drop(delta);
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.remove_sources(member_id).await?;
        }
        self.ifcfg = next_ifcfg;

        Ok(())
    }

    async fn shutdown_dispatcher_if_idle(&mut self) {
        if !self.member_registrations.is_empty() {
            return;
        }

        self.shutdown_dispatcher().await;
    }

    async fn invalidate_and_shutdown_dispatcher(&mut self) {
        self.mark_invalid();
        self.shutdown_dispatcher().await;
    }

    async fn shutdown_dispatcher(&mut self) {
        if let Some(dispatcher) = self.dispatcher.take() {
            dispatcher.shutdown_without_invalidation().await;
        }
    }

    async fn apply_ifcfg_delta(
        &self,
        delta: &SharedIfConfigDelta,
        next_ifcfg: &SharedIfConfig,
    ) -> Result<(), Error> {
        let changed_routes = self.ifcfg.changed_ipv4_route_sources(next_ifcfg);
        #[cfg(target_os = "linux")]
        let next_effective = next_ifcfg.effective();
        let nic = self.nic.lock().await;

        for route in &delta.ipv4_routes.removed {
            let source_hint = self.ifcfg.ipv4_route_source_hint(route);
            ignore_removed_ifcfg_not_found(
                remove_shared_ipv4_route(&nic, route, source_hint).await,
            )?;
        }
        for route in &changed_routes {
            let source_hint = self.ifcfg.ipv4_route_source_hint(route);
            ignore_removed_ifcfg_not_found(
                remove_shared_ipv4_route(&nic, route, source_hint).await,
            )?;
        }
        for route in &delta.ipv6_routes.removed {
            ignore_removed_ifcfg_not_found(
                nic.remove_ipv6_route(route.address, route.prefix).await,
            )?;
        }
        for ip in &delta.ipv4_addresses.removed {
            ignore_removed_ifcfg_not_found(nic.remove_ip(Some(*ip)).await)?;
        }
        for ip in &delta.ipv6_addresses.removed {
            ignore_removed_ifcfg_not_found(nic.remove_ipv6(Some(*ip)).await)?;
        }

        for ip in &delta.ipv4_addresses.added {
            nic.add_ip(ip.address(), ip.network_length() as i32).await?;
        }
        for ip in &delta.ipv6_addresses.added {
            nic.add_ipv6(ip.address(), ip.network_length() as i32)
                .await?;
        }
        for route in &delta.ipv4_routes.added {
            add_shared_ipv4_route(&nic, route, next_ifcfg).await?;
        }
        for route in &changed_routes {
            add_shared_ipv4_route(&nic, route, next_ifcfg).await?;
        }
        for route in &delta.ipv6_routes.added {
            nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                .await?;
        }

        if let Some(mtu) = &delta.mtu {
            nic.set_mtu(mtu.new.unwrap_or_else(|| nic.configured_mtu()))
                .await?;
        }

        #[cfg(target_os = "linux")]
        if !delta.ipv4_addresses.removed.is_empty() {
            for route in &next_effective.ipv4_routes {
                ignore_added_ifcfg_already_exists(
                    add_shared_ipv4_route(&nic, route, next_ifcfg).await,
                )?;
            }
        }

        #[cfg(target_os = "linux")]
        if !delta.ipv6_addresses.removed.is_empty() {
            for route in &next_effective.ipv6_routes {
                ignore_added_ifcfg_already_exists(
                    nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                        .await,
                )?;
            }
        }

        Ok(())
    }

    fn ensure_valid(&self) -> Result<(), Error> {
        if self.is_valid() {
            return Ok(());
        }

        Err(anyhow::anyhow!("shared virtual nic is invalid").into())
    }

    fn member_tunnel_table(&self) -> SharedVirtualNicMemberTunnelTable {
        self.member_tunnel_table.clone()
    }

    fn valid_flag(&self) -> Arc<AtomicBool> {
        self.valid.clone()
    }

    async fn ensure_dispatcher(&mut self) -> Result<(), Error> {
        self.ensure_valid()?;

        if self.dispatcher.is_some() {
            return Ok(());
        }

        let tunnel = self.nic.lock().await.create_dev().await?;
        let dispatcher = SharedVirtualNicDispatcher::start(
            tunnel,
            self.member_tunnel_table.clone(),
            self.valid.clone(),
        );
        self.sync_dispatcher_sources(&dispatcher).await?;
        self.dispatcher = Some(dispatcher);
        Ok(())
    }

    #[cfg(mobile)]
    async fn ensure_dispatcher_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.update_mobile_tun_fd(tun_fd).await?;
            return Ok(());
        }

        let dispatcher = SharedVirtualNicDispatcher::start_for_mobile(
            self.nic.clone(),
            tun_fd,
            self.member_tunnel_table.clone(),
            self.valid.clone(),
        )
        .await?;
        self.sync_dispatcher_sources(&dispatcher).await?;
        self.dispatcher = Some(dispatcher);
        Ok(())
    }

    async fn sync_dispatcher_sources(
        &self,
        dispatcher: &SharedVirtualNicDispatcher,
    ) -> Result<(), Error> {
        for (member_id, claims) in &self.ifcfg.member_claims {
            dispatcher.update_sources(*member_id, claims).await?;
        }
        Ok(())
    }

    async fn sync_dispatcher_sources_for_ifcfg_update(
        &self,
        member_id: SharedVirtualNicMemberId,
        old_claims: &SharedIfConfigClaims,
        next_claims: &SharedIfConfigClaims,
    ) -> Result<(), Error> {
        let active_claims = dispatcher_claims_for_ifcfg_transition(old_claims, next_claims);
        self.sync_dispatcher_sources_for_claims(member_id, &active_claims)
            .await
    }

    async fn sync_dispatcher_sources_for_claims(
        &self,
        member_id: SharedVirtualNicMemberId,
        claims: &SharedIfConfigClaims,
    ) -> Result<(), Error> {
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.update_sources(member_id, claims).await?;
        }
        Ok(())
    }
}

fn dispatcher_claims_for_ifcfg_transition(
    old_claims: &SharedIfConfigClaims,
    next_claims: &SharedIfConfigClaims,
) -> SharedIfConfigClaims {
    SharedIfConfigClaims {
        ipv4_addresses: merged_items(&old_claims.ipv4_addresses, &next_claims.ipv4_addresses),
        ipv6_addresses: merged_items(&old_claims.ipv6_addresses, &next_claims.ipv6_addresses),
        ipv4_routes: merged_items(&old_claims.ipv4_routes, &next_claims.ipv4_routes),
        ipv6_routes: merged_items(&old_claims.ipv6_routes, &next_claims.ipv6_routes),
        mtu: None,
    }
}

async fn add_shared_ipv4_route(
    nic: &VirtualNic,
    route: &SharedIpv4Route,
    ifcfg: &SharedIfConfig,
) -> Result<(), Error> {
    nic.add_route_with_cost_and_source_hint(
        route.address,
        route.prefix,
        route.cost,
        ifcfg.ipv4_route_source_hint(route),
    )
    .await
}

async fn remove_shared_ipv4_route(
    nic: &VirtualNic,
    route: &SharedIpv4Route,
    source_hint: Option<Ipv4Addr>,
) -> Result<(), Error> {
    nic.remove_route_with_cost_and_source_hint(route.address, route.prefix, route.cost, source_hint)
        .await
}

fn merged_items<T>(old_items: &BTreeSet<T>, new_items: &BTreeSet<T>) -> BTreeSet<T>
where
    T: Ord + Clone,
{
    old_items.union(new_items).cloned().collect()
}

fn remove_claimed_item<T>(items: &mut BTreeSet<T>, item: Option<T>)
where
    T: Ord,
{
    match item {
        Some(item) => {
            items.remove(&item);
        }
        None => {
            items.clear();
        }
    }
}

fn ignore_removed_ifcfg_not_found(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(Error::NotFound) => Ok(()),
        other => other,
    }
}

#[cfg(target_os = "linux")]
fn ignore_added_ifcfg_already_exists(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(Error::IOError(err)) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        other => other,
    }
}

struct SharedVirtualNicMemberRegistration {
    member_id: SharedVirtualNicMemberId,
    registration_id: SharedVirtualNicMemberRegistrationId,
    shared_nic: Arc<Mutex<SharedVirtualNic>>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
}

impl SharedVirtualNicMemberRegistration {
    fn register_tunnel(
        &self,
        tunnel: Box<dyn Tunnel>,
        close_notifier: Arc<Notify>,
    ) -> Result<(), Error> {
        self.member_tunnel_table.register(
            self.member_id,
            self.registration_id,
            tunnel,
            close_notifier,
        )
    }
}

impl Drop for SharedVirtualNicMemberRegistration {
    fn drop(&mut self) {
        self.member_tunnel_table
            .unregister(self.member_id, self.registration_id);
        let shared_nic = self.shared_nic.clone();
        let member_id = self.member_id;
        let registration_id = self.registration_id;

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                ?member_id,
                "skip shared virtual nic member claim cleanup without tokio runtime"
            );
            return;
        };

        handle.spawn(async move {
            let mut shared_nic = shared_nic.lock().await;
            if let Err(err) = shared_nic
                .remove_member_registration_claims(member_id, registration_id)
                .await
            {
                tracing::warn!(
                    ?member_id,
                    ?err,
                    "failed to clean shared virtual nic member claims"
                );
            }
        });
    }
}

#[derive(Clone)]
pub struct SharedVirtualNicMember {
    member_id: SharedVirtualNicMemberId,
    configured_mtu: u32,
    shared_nic: Arc<Mutex<SharedVirtualNic>>,
    close_notifier: Arc<Notify>,
    registration: Arc<SharedVirtualNicMemberRegistration>,
}

impl SharedVirtualNicMember {
    fn new(
        member_id: SharedVirtualNicMemberId,
        configured_mtu: u32,
        shared_nic: Arc<Mutex<SharedVirtualNic>>,
        close_notifier: Arc<Notify>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    ) -> Self {
        let registration_id = uuid::Uuid::new_v4();
        Self {
            member_id,
            configured_mtu,
            shared_nic: shared_nic.clone(),
            close_notifier,
            registration: Arc::new(SharedVirtualNicMemberRegistration {
                member_id,
                registration_id,
                shared_nic: shared_nic.clone(),
                member_tunnel_table,
            }),
        }
    }

    pub fn member_id(&self) -> SharedVirtualNicMemberId {
        self.member_id
    }

    pub fn shared_nic(&self) -> Arc<Mutex<SharedVirtualNic>> {
        self.shared_nic.clone()
    }

    pub fn close_notifier(&self) -> Arc<Notify> {
        self.close_notifier.clone()
    }

    #[cfg(test)]
    fn configured_mtu_for_test(&self) -> u32 {
        self.configured_mtu
    }

    pub async fn create_dev(&self) -> Result<Box<dyn Tunnel>, Error> {
        let (member_tunnel, shared_tunnel) = create_ring_tunnel_pair();
        {
            let mut shared_nic = self.shared_nic.lock().await;
            shared_nic
                .attach_member_registration(self.member_id, self.registration.registration_id)
                .await?;
            shared_nic.ensure_dispatcher().await?;
            shared_nic
                .apply_member_mtu_for_registration(
                    self.member_id,
                    self.registration.registration_id,
                    self.configured_mtu,
                )
                .await?;
        }
        self.registration
            .register_tunnel(shared_tunnel, self.close_notifier.clone())?;
        Ok(member_tunnel)
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let (member_tunnel, shared_tunnel) = create_ring_tunnel_pair();
        {
            let mut shared_nic = self.shared_nic.lock().await;
            shared_nic
                .attach_member_registration(self.member_id, self.registration.registration_id)
                .await?;
            shared_nic.ensure_dispatcher_for_mobile(tun_fd).await?;
            shared_nic
                .apply_member_mtu_for_mobile_registration(
                    self.member_id,
                    self.registration.registration_id,
                    self.configured_mtu,
                )
                .await?;
        }
        self.registration
            .register_tunnel(shared_tunnel, self.close_notifier.clone())?;
        Ok(member_tunnel)
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn ifcfg_and_ifname(&self) -> Result<(IfConfiger, String), Error> {
        self.shared_nic.lock().await.ifcfg_and_ifname().await
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        self.shared_nic.lock().await.link_up().await
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let ip = ipv4_inet(ip, cidr)?;
        self.update_claims(|claims| {
            claims.ipv4_addresses.insert(ip);
        })
        .await
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        self.update_claims(|claims| {
            remove_claimed_item(&mut claims.ipv4_addresses, ip);
        })
        .await
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let ip = ipv6_inet(ip, cidr)?;
        self.update_claims(|claims| {
            claims.ipv6_addresses.insert(ip);
        })
        .await
    }

    #[cfg(mobile)]
    pub async fn add_mobile_sources(&self, sources: MobileTunSources) -> Result<(), Error> {
        let mut shared_nic = self.shared_nic.lock().await;
        let mut claims = shared_nic.ifcfg.claims_of(self.member_id);
        claims.ipv4_addresses.extend(sources.ipv4);
        claims.ipv6_addresses.extend(sources.ipv6);
        claims.ipv4_routes.extend(sources.ipv4_routes);
        claims.ipv6_routes.extend(sources.ipv6_routes);
        shared_nic
            .apply_member_claims_for_mobile_registration(
                self.member_id,
                self.registration.registration_id,
                claims,
            )
            .await
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        self.update_claims(|claims| {
            remove_claimed_item(&mut claims.ipv6_addresses, ip);
        })
        .await
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        self.add_route_with_cost(address, cidr, None).await
    }

    pub async fn add_route_with_cost(
        &self,
        address: Ipv4Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        self.update_claims(|claims| {
            claims
                .ipv4_routes
                .insert(SharedIpv4Route::new(address, cidr, cost));
        })
        .await
    }

    pub async fn remove_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        self.update_claims(|claims| {
            claims
                .ipv4_routes
                .retain(|route| route.address != address || route.prefix != cidr);
        })
        .await
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        self.add_ipv6_route_with_cost(address, cidr, None).await
    }

    pub async fn add_ipv6_route_with_cost(
        &self,
        address: Ipv6Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        self.update_claims(|claims| {
            claims
                .ipv6_routes
                .insert(SharedIpv6Route::new(address, cidr, cost));
        })
        .await
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        self.update_claims(|claims| {
            claims
                .ipv6_routes
                .retain(|route| route.address != address || route.prefix != cidr);
        })
        .await
    }

    async fn update_claims<F>(&self, update: F) -> Result<(), Error>
    where
        F: FnOnce(&mut SharedIfConfigClaims) + Send,
    {
        let mut shared_nic = self.shared_nic.lock().await;
        let mut claims = shared_nic.ifcfg.claims_of(self.member_id);
        update(&mut claims);
        shared_nic
            .apply_member_claims_for_registration(
                self.member_id,
                self.registration.registration_id,
                claims,
            )
            .await
    }
}

#[derive(Default)]
pub struct SharedVirtualNicRegistry {
    nics: BTreeMap<SharedVirtualNicRegistryKey, SharedVirtualNicRegistryEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedVirtualNicRegistryKey {
    net_ns: Option<String>,
    dev_name: String,
}

impl SharedVirtualNicRegistryKey {
    fn new(dev_name: String, config: &VirtualNicConfig) -> Self {
        Self {
            net_ns: config.net_ns_name(),
            dev_name,
        }
    }
}

struct SharedVirtualNicRegistryEntry {
    nic: Arc<Mutex<SharedVirtualNic>>,
    valid: Arc<AtomicBool>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
}

impl SharedVirtualNicRegistryEntry {
    fn new(nic: SharedVirtualNic) -> Self {
        Self {
            valid: nic.valid_flag(),
            member_tunnel_table: nic.member_tunnel_table(),
            nic: Arc::new(Mutex::new(nic)),
        }
    }

    fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
    }

    fn nic(&self) -> Arc<Mutex<SharedVirtualNic>> {
        self.nic.clone()
    }

    fn member_tunnel_table(&self) -> SharedVirtualNicMemberTunnelTable {
        self.member_tunnel_table.clone()
    }
}

impl SharedVirtualNicRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(
        &self,
        dev_name: &str,
        config: &VirtualNicConfig,
    ) -> Option<Arc<Mutex<SharedVirtualNic>>> {
        let key = SharedVirtualNicRegistryKey::new(dev_name.to_owned(), config);
        self.nics
            .get(&key)
            .filter(|entry| entry.is_valid())
            .map(|entry| entry.nic())
    }

    #[cfg(test)]
    pub fn get_by_dev_name_for_test(&self, dev_name: &str) -> Option<Arc<Mutex<SharedVirtualNic>>> {
        let mut matches = self
            .nics
            .iter()
            .filter(|(key, entry)| key.dev_name == dev_name && entry.is_valid())
            .map(|(_, entry)| entry.nic());
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    pub fn get_or_create(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
    ) -> Arc<Mutex<SharedVirtualNic>> {
        self.get_or_create_entry(dev_name, config).nic()
    }

    fn get_or_create_entry(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
    ) -> &SharedVirtualNicRegistryEntry {
        let key = SharedVirtualNicRegistryKey::new(dev_name, &config);
        let needs_new_entry = self.nics.get(&key).is_none_or(|entry| !entry.is_valid());
        if needs_new_entry {
            let entry = SharedVirtualNicRegistryEntry::new(SharedVirtualNic::new(config));
            self.nics.insert(key.clone(), entry);
        }

        self.nics
            .get(&key)
            .expect("shared virtual nic registry entry should exist")
    }

    pub fn create_member(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
        member_id: SharedVirtualNicMemberId,
        close_notifier: Arc<Notify>,
    ) -> SharedVirtualNicMember {
        let configured_mtu = config.mtu();
        let entry = self.get_or_create_entry(dev_name, config);
        SharedVirtualNicMember::new(
            member_id,
            configured_mtu,
            entry.nic(),
            close_notifier,
            entry.member_tunnel_table(),
        )
    }
}

fn item_delta<T>(old: &BTreeSet<T>, new: &BTreeSet<T>) -> OwnedItemDelta<T>
where
    T: Ord + Clone,
{
    OwnedItemDelta {
        added: new.difference(old).cloned().collect(),
        removed: old.difference(new).cloned().collect(),
    }
}

fn owners_for<T>(
    claims: &BTreeMap<SharedVirtualNicMemberId, SharedIfConfigClaims>,
    select: fn(&SharedIfConfigClaims) -> &BTreeSet<T>,
    item: &T,
) -> BTreeSet<SharedVirtualNicMemberId>
where
    T: Ord,
{
    claims
        .iter()
        .filter_map(|(member_id, claims)| select(claims).contains(item).then_some(*member_id))
        .collect()
}

fn mtu_delta(old: Option<u32>, new: Option<u32>) -> Option<SharedMtuChange> {
    (old != new).then_some(SharedMtuChange { old, new })
}

fn ipv4_cidrs_overlap(left: Ipv4Cidr, right: Ipv4Cidr) -> bool {
    left.contains(&right.first_address()) || right.contains(&left.first_address())
}

fn ipv6_cidrs_overlap(left: Ipv6Cidr, right: Ipv6Cidr) -> bool {
    left.contains(&right.first_address()) || right.contains(&left.first_address())
}

fn ipv4_inet(address: Ipv4Addr, prefix: i32) -> Result<Ipv4Inet, Error> {
    let prefix = u8::try_from(prefix)
        .map_err(|_| anyhow::anyhow!("invalid IPv4 prefix length {}", prefix))?;
    Ipv4Inet::new(address, prefix).map_err(|err| {
        anyhow::anyhow!("invalid IPv4 address {}/{}: {:?}", address, prefix, err).into()
    })
}

fn ipv6_inet(address: Ipv6Addr, prefix: i32) -> Result<Ipv6Inet, Error> {
    let prefix = u8::try_from(prefix)
        .map_err(|_| anyhow::anyhow!("invalid IPv6 prefix length {}", prefix))?;
    Ipv6Inet::new(address, prefix).map_err(|err| {
        anyhow::anyhow!("invalid IPv6 address {}/{}: {:?}", address, prefix, err).into()
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use crate::common::{ifcfg::IfConfiguerTrait, netns::NetNS};
    use tokio::sync::Notify;

    use super::*;

    struct FailingRemoveIpIfConfiger;

    #[async_trait::async_trait]
    impl IfConfiguerTrait for FailingRemoveIpIfConfiger {
        async fn remove_ip(&self, _name: &str, _ip: Option<Ipv4Inet>) -> Result<(), Error> {
            Err(anyhow::anyhow!("forced remove_ip failure").into())
        }
    }

    fn member_id(n: u128) -> SharedVirtualNicMemberId {
        uuid::Uuid::from_u128(n)
    }

    fn claims_with_ipv4_route(route: SharedIpv4Route, mtu: Option<u32>) -> SharedIfConfigClaims {
        SharedIfConfigClaims {
            ipv4_routes: BTreeSet::from([route]),
            mtu,
            ..Default::default()
        }
    }

    fn claims_with_ipv4_address_and_route(
        address: Ipv4Inet,
        route: SharedIpv4Route,
    ) -> SharedIfConfigClaims {
        SharedIfConfigClaims {
            ipv4_addresses: BTreeSet::from([address]),
            ipv4_routes: BTreeSet::from([route]),
            ..Default::default()
        }
    }

    fn virtual_nic_config() -> VirtualNicConfig {
        VirtualNicConfig::new(String::new(), 1500, NetNS::new(None))
    }

    fn virtual_nic_config_with_mtu(mtu: u32) -> VirtualNicConfig {
        VirtualNicConfig::new(String::new(), mtu, NetNS::new(None))
    }

    fn virtual_nic_config_in_netns(net_ns: &str) -> VirtualNicConfig {
        VirtualNicConfig::new(String::new(), 1500, NetNS::new(Some(net_ns.to_owned())))
    }

    #[test]
    fn duplicate_routes_keep_owner_sets_and_single_os_delta() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(100, 100, 100, 101), 32, None);
        let first = member_id(1);
        let second = member_id(2);
        let mut ifcfg = SharedIfConfig::default();

        let first_delta =
            ifcfg.apply_member_claims(first, claims_with_ipv4_route(route.clone(), Some(1400)));
        let second_delta =
            ifcfg.apply_member_claims(second, claims_with_ipv4_route(route.clone(), Some(1300)));

        assert_eq!(
            first_delta.ipv4_routes.added,
            BTreeSet::from([route.clone()])
        );
        assert!(second_delta.ipv4_routes.added.is_empty());
        assert_eq!(
            ifcfg.owners_of_ipv4_route(&route),
            BTreeSet::from([first, second])
        );
        assert_eq!(ifcfg.effective_mtu(), Some(1300));
    }

    #[test]
    fn removing_one_owner_keeps_shared_route_until_last_owner_leaves() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(100, 100, 100, 101), 32, None);
        let first = member_id(1);
        let second = member_id(2);
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(first, claims_with_ipv4_route(route.clone(), None));
        ifcfg.apply_member_claims(second, claims_with_ipv4_route(route.clone(), None));

        let first_delta = ifcfg.remove_member(first).unwrap();
        let second_delta = ifcfg.remove_member(second).unwrap();

        assert!(first_delta.ipv4_routes.removed.is_empty());
        assert_eq!(
            second_delta.ipv4_routes.removed,
            BTreeSet::from([route.clone()])
        );
        assert!(ifcfg.owners_of_ipv4_route(&route).is_empty());
    }

    #[tokio::test]
    async fn overlapping_member_claims_leave_existing_configuration_intact() {
        let first = member_id(1);
        let second = member_id(2);
        let mut shared_nic = SharedVirtualNic::new(virtual_nic_config());
        shared_nic.ifcfg_mut().apply_member_claims(
            first,
            SharedIfConfigClaims {
                ipv4_routes: BTreeSet::from([SharedIpv4Route::new(
                    Ipv4Addr::new(10, 144, 0, 0),
                    16,
                    None,
                )]),
                ..Default::default()
            },
        );
        let original = shared_nic.ifcfg().effective();

        let err = shared_nic
            .apply_member_claims(
                second,
                SharedIfConfigClaims {
                    ipv4_addresses: BTreeSet::from(["10.144.1.2/24".parse().unwrap()]),
                    ..Default::default()
                },
            )
            .await
            .unwrap_err();

        assert!(err.to_string().contains("overlaps member"));
        assert_eq!(shared_nic.ifcfg().effective(), original);
    }

    #[test]
    fn shared_magic_dns_route_is_not_a_member_conflict() {
        let first = member_id(1);
        let second = member_id(2);
        let route = SharedIpv4Route::new(Ipv4Addr::new(100, 100, 100, 101), 32, None);
        let claims = claims_with_ipv4_route(route, None);
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(first, claims.clone());

        assert!(ifcfg.ensure_disjoint(second, &claims).is_ok());
    }

    #[test]
    fn member_claim_update_tracks_ip_ownership() {
        let first_ip = Ipv4Inet::from_str("10.30.0.2/24").unwrap();
        let second_ip = Ipv4Inet::from_str("10.30.0.3/24").unwrap();
        let member = member_id(1);
        let mut ifcfg = SharedIfConfig::default();

        let first_delta = ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([first_ip]),
                ..Default::default()
            },
        );
        let second_delta = ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([second_ip]),
                ..Default::default()
            },
        );

        assert_eq!(first_delta.ipv4_addresses.added, BTreeSet::from([first_ip]));
        assert_eq!(
            second_delta.ipv4_addresses.removed,
            BTreeSet::from([first_ip])
        );
        assert_eq!(
            second_delta.ipv4_addresses.added,
            BTreeSet::from([second_ip])
        );
        assert_eq!(
            ifcfg.owners_of_ipv4_address(&second_ip),
            BTreeSet::from([member])
        );
    }

    #[test]
    fn ipv4_route_source_hint_prefers_address_inside_route() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 90, 1, 0), 24, None);
        let member = member_id(1);
        let mut ifcfg = SharedIfConfig::default();

        ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([
                    Ipv4Inet::from_str("10.1.1.1/24").unwrap(),
                    Ipv4Inet::from_str("10.90.1.1/24").unwrap(),
                ]),
                ipv4_routes: BTreeSet::from([route.clone()]),
                ..Default::default()
            },
        );

        assert_eq!(
            ifcfg.ipv4_route_source_hint(&route),
            Some(Ipv4Addr::new(10, 90, 1, 1))
        );
    }

    #[test]
    fn adding_better_ipv4_route_owner_marks_source_change() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 90, 2, 0), 24, None);
        let first = member_id(1);
        let second = member_id(2);
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(
            first,
            claims_with_ipv4_address_and_route(
                Ipv4Inet::from_str("10.1.2.1/24").unwrap(),
                route.clone(),
            ),
        );
        let old = ifcfg.clone();

        let delta = ifcfg.apply_member_claims(
            second,
            claims_with_ipv4_address_and_route(
                Ipv4Inet::from_str("10.90.2.1/24").unwrap(),
                route.clone(),
            ),
        );

        assert!(delta.ipv4_routes.added.is_empty());
        assert_eq!(
            old.changed_ipv4_route_sources(&ifcfg),
            BTreeSet::from([route.clone()])
        );
        assert_eq!(
            old.ipv4_route_source_hint(&route),
            Some(Ipv4Addr::new(10, 1, 2, 1))
        );
        assert_eq!(
            ifcfg.ipv4_route_source_hint(&route),
            Some(Ipv4Addr::new(10, 90, 2, 1))
        );
    }

    #[test]
    fn removing_ipv4_route_owner_marks_source_change_when_route_remains() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 90, 3, 0), 24, None);
        let first = member_id(1);
        let second = member_id(2);
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(
            first,
            claims_with_ipv4_address_and_route(
                Ipv4Inet::from_str("10.1.3.1/24").unwrap(),
                route.clone(),
            ),
        );
        ifcfg.apply_member_claims(
            second,
            claims_with_ipv4_address_and_route(
                Ipv4Inet::from_str("10.90.3.1/24").unwrap(),
                route.clone(),
            ),
        );
        let old = ifcfg.clone();

        let delta = ifcfg.remove_member(second).unwrap();

        assert!(delta.ipv4_routes.removed.is_empty());
        assert_eq!(
            old.changed_ipv4_route_sources(&ifcfg),
            BTreeSet::from([route.clone()])
        );
        assert_eq!(
            old.ipv4_route_source_hint(&route),
            Some(Ipv4Addr::new(10, 90, 3, 1))
        );
        assert_eq!(
            ifcfg.ipv4_route_source_hint(&route),
            Some(Ipv4Addr::new(10, 1, 3, 1))
        );
    }

    #[test]
    fn removing_ipv4_route_keeps_old_source_hint_available() {
        let kept_route = SharedIpv4Route::new(Ipv4Addr::new(10, 90, 4, 0), 24, Some(10));
        let removed_route = SharedIpv4Route::new(Ipv4Addr::new(10, 90, 4, 0), 24, Some(20));
        let member = member_id(1);
        let address = Ipv4Inet::from_str("10.90.4.1/24").unwrap();
        let mut ifcfg = SharedIfConfig::default();
        ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([address]),
                ipv4_routes: BTreeSet::from([kept_route.clone(), removed_route.clone()]),
                ..Default::default()
            },
        );
        let old = ifcfg.clone();

        let delta = ifcfg.apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([address]),
                ipv4_routes: BTreeSet::from([kept_route.clone()]),
                ..Default::default()
            },
        );

        assert_eq!(
            delta.ipv4_routes.removed,
            BTreeSet::from([removed_route.clone()])
        );
        assert_eq!(
            old.ipv4_route_source_hint(&removed_route),
            Some(Ipv4Addr::new(10, 90, 4, 1))
        );
    }

    #[test]
    fn shared_virtual_nic_wraps_virtual_nic_and_tracks_ifcfg() {
        let mut shared_nic = SharedVirtualNic::new(virtual_nic_config());
        let member = member_id(1);
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 40, 0, 0), 24, None);

        shared_nic
            .ifcfg_mut()
            .apply_member_claims(member, claims_with_ipv4_route(route.clone(), None));

        assert_eq!(
            shared_nic.ifcfg().owners_of_ipv4_route(&route),
            BTreeSet::from([member])
        );
        drop(shared_nic.nic());
    }

    #[tokio::test]
    async fn stale_member_registration_cleanup_keeps_current_claims() {
        let mut shared_nic = SharedVirtualNic::new(virtual_nic_config());
        let member = member_id(1);
        let old_registration = uuid::Uuid::from_u128(10);
        let current_registration = uuid::Uuid::from_u128(11);
        let ip = Ipv4Inet::from_str("10.50.0.2/24").unwrap();

        shared_nic
            .member_registrations
            .insert(member, current_registration);
        shared_nic.ifcfg_mut().apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([ip]),
                ..Default::default()
            },
        );

        shared_nic
            .remove_member_registration_claims(member, old_registration)
            .await
            .unwrap();

        assert_eq!(
            shared_nic.ifcfg().owners_of_ipv4_address(&ip),
            BTreeSet::from([member])
        );
        assert_eq!(
            shared_nic.member_registrations.get(&member),
            Some(&current_registration)
        );
    }

    #[tokio::test]
    async fn failed_member_registration_cleanup_invalidates_shared_nic() {
        let mut shared_nic = SharedVirtualNic::new(virtual_nic_config());
        let member = member_id(1);
        let registration = uuid::Uuid::from_u128(10);
        let ip = Ipv4Inet::from_str("10.60.0.2/24").unwrap();

        shared_nic.member_registrations.insert(member, registration);
        shared_nic.ifcfg_mut().apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([ip]),
                ..Default::default()
            },
        );
        let nic = shared_nic.nic();
        let mut nic = nic.lock().await;
        nic.set_ifname_for_test("et0".to_string());
        nic.set_ifcfg_for_test(Box::new(FailingRemoveIpIfConfiger));
        drop(nic);

        let result = shared_nic
            .remove_member_registration_claims(member, registration)
            .await;

        assert!(result.is_err());
        assert!(!shared_nic.is_valid());
        assert!(!shared_nic.member_registrations.contains_key(&member));
        assert_eq!(
            shared_nic.ifcfg().owners_of_ipv4_address(&ip),
            BTreeSet::from([member])
        );
    }

    #[tokio::test]
    async fn failed_registration_replacement_keeps_old_registration_and_invalidates() {
        let mut shared_nic = SharedVirtualNic::new(virtual_nic_config());
        let member = member_id(1);
        let old_registration = uuid::Uuid::from_u128(10);
        let next_registration = uuid::Uuid::from_u128(11);
        let ip = Ipv4Inet::from_str("10.70.0.2/24").unwrap();

        shared_nic
            .member_registrations
            .insert(member, old_registration);
        shared_nic.ifcfg_mut().apply_member_claims(
            member,
            SharedIfConfigClaims {
                ipv4_addresses: BTreeSet::from([ip]),
                ..Default::default()
            },
        );
        let nic = shared_nic.nic();
        let mut nic = nic.lock().await;
        nic.set_ifname_for_test("et0".to_string());
        nic.set_ifcfg_for_test(Box::new(FailingRemoveIpIfConfiger));
        drop(nic);

        let result = shared_nic
            .attach_member_registration(member, next_registration)
            .await;

        assert!(result.is_err());
        assert!(!shared_nic.is_valid());
        assert_eq!(
            shared_nic.member_registrations.get(&member),
            Some(&old_registration)
        );
    }

    #[test]
    fn registry_reuses_shared_virtual_nic_for_same_dev_name_and_netns() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.get_or_create("et0".to_string(), virtual_nic_config());
        let second = registry.get_or_create("et0".to_string(), virtual_nic_config());

        assert!(Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn registry_keeps_same_dev_name_in_different_netns_separate() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.get_or_create("et0".to_string(), virtual_nic_config_in_netns("net-a"));
        let second =
            registry.get_or_create("et0".to_string(), virtual_nic_config_in_netns("net-b"));

        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn registry_keeps_different_dev_names_separate() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.get_or_create("et0".to_string(), virtual_nic_config());
        let second = registry.get_or_create("et1".to_string(), virtual_nic_config());

        assert!(!Arc::ptr_eq(&first, &second));
    }

    #[test]
    fn registry_replaces_invalid_shared_virtual_nic() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.get_or_create("et0".to_string(), virtual_nic_config());
        first.try_lock().unwrap().mark_invalid();
        let second = registry.get_or_create("et0".to_string(), virtual_nic_config());

        assert!(!Arc::ptr_eq(&first, &second));
        assert!(
            registry
                .get("et0", &virtual_nic_config())
                .is_some_and(|nic| Arc::ptr_eq(&nic, &second))
        );
    }

    #[test]
    fn registry_create_member_uses_registered_shared_virtual_nic() {
        let mut registry = SharedVirtualNicRegistry::new();
        let member_id = member_id(1);

        let member = registry.create_member(
            "et0".to_string(),
            virtual_nic_config(),
            member_id,
            Arc::new(Notify::new()),
        );
        let shared_nic = registry.get("et0", &virtual_nic_config()).unwrap();

        assert_eq!(member.member_id(), member_id);
        assert!(Arc::ptr_eq(&member.shared_nic(), &shared_nic));
    }

    #[test]
    fn registry_create_member_keeps_member_configured_mtu() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.create_member(
            "et0".to_string(),
            virtual_nic_config_with_mtu(1400),
            member_id(1),
            Arc::new(Notify::new()),
        );
        let second = registry.create_member(
            "et0".to_string(),
            virtual_nic_config_with_mtu(1300),
            member_id(2),
            Arc::new(Notify::new()),
        );

        assert_eq!(first.configured_mtu_for_test(), 1400);
        assert_eq!(second.configured_mtu_for_test(), 1300);
        assert!(Arc::ptr_eq(&first.shared_nic(), &second.shared_nic()));
    }
}

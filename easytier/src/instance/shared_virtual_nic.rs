use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::sync::{Mutex, Notify};

use crate::common::error::Error;
use easytier_core::tunnel::Tunnel;

use super::virtual_nic::{VirtualNic, VirtualNicConfig};

#[cfg(not(target_os = "linux"))]
use crate::common::ifcfg::IfConfiger;

mod dispatcher;
mod ifcfg;

pub(crate) use ifcfg::SharedIfConfig;
#[cfg(any(mobile, test))]
pub(crate) use ifcfg::SharedIfConfigConflict;
use ifcfg::SharedIfConfigDelta;
pub use ifcfg::{SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route};

use dispatcher::{SharedVirtualNicDispatcher, SharedVirtualNicMemberTunnelTable};

pub type SharedVirtualNicMemberId = uuid::Uuid;
pub(super) type SharedVirtualNicMemberRegistrationId = uuid::Uuid;
pub(crate) type ArcSharedVirtualNicRegistry = Arc<Mutex<SharedVirtualNicRegistry>>;

// The host owns this driver independently of all instance runtimes.
fn shared_virtual_nic_runtime() -> tokio::runtime::Handle {
    crate::host_runtime::native_host_runtime()
        .shared_executor()
        .expect("native shared executor is unavailable")
}

pub struct SharedVirtualNic {
    managed_routes: bool,
    nic: Arc<Mutex<VirtualNic>>,
    ifcfg: SharedIfConfig,
    valid: Arc<AtomicBool>,
    lifetimes: Arc<std::sync::Mutex<Option<usize>>>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    member_registrations: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberRegistrationId>,
    dispatcher: Option<SharedVirtualNicDispatcher>,
}

impl SharedVirtualNic {
    pub fn new(config: VirtualNicConfig) -> Self {
        Self {
            managed_routes: config.routes_managed(),
            nic: Arc::new(Mutex::new(VirtualNic::new(config))),
            ifcfg: SharedIfConfig::default(),
            valid: Arc::new(AtomicBool::new(true)),
            lifetimes: Arc::new(std::sync::Mutex::new(Some(0))),
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

    pub(crate) fn current_registration(
        &self,
        member: SharedVirtualNicMemberId,
    ) -> Option<SharedVirtualNicMemberRegistrationId> {
        self.member_registrations.get(&member).copied()
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    pub(crate) fn prepare_managed_routes(
        &self,
        member: SharedVirtualNicMemberId,
        registration: SharedVirtualNicMemberRegistrationId,
        routes: &easytier_core::host::route::RouteSet,
    ) -> anyhow::Result<SharedIfConfigClaims> {
        anyhow::ensure!(
            self.managed_routes,
            "NIC routes are controlled by the legacy backend"
        );
        anyhow::ensure!(self.is_valid(), "NIC is invalid");
        anyhow::ensure!(
            self.is_current_member_registration(member, registration),
            "NIC member registration changed"
        );
        let mut claims = self.ifcfg.claims_of(member);
        claims.ipv4_routes.clear();
        claims.ipv6_routes.clear();
        let assigned = self.ifcfg.effective();
        for route in routes {
            crate::instance::route::validate_tun_spec(route).map_err(anyhow::Error::msg)?;
            if let Some(source) = route.preferred_source {
                anyhow::ensure!(
                    match source {
                        std::net::IpAddr::V4(ip) => assigned
                            .ipv4_addresses
                            .iter()
                            .any(|address| address.address() == ip),
                        std::net::IpAddr::V6(ip) => assigned
                            .ipv6_addresses
                            .iter()
                            .any(|address| address.address() == ip),
                    },
                    "preferred source is not a known assigned address"
                );
            }
            match route.destination {
                cidr::IpCidr::V4(prefix) => {
                    claims.ipv4_routes.insert(SharedIpv4Route::new(
                        prefix.first_address(),
                        prefix.network_length(),
                        None,
                    ));
                }
                cidr::IpCidr::V6(prefix) => {
                    claims.ipv6_routes.insert(SharedIpv6Route::new(
                        prefix.first_address(),
                        prefix.network_length(),
                        None,
                    ));
                }
            }
        }
        // Withdrawal must work even when historical claims are conflicting.
        if !routes.is_empty() {
            self.ifcfg.ensure_disjoint(member, &claims)?;
        }
        Ok(claims)
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    pub(crate) async fn commit_managed_routes(
        &mut self,
        member: SharedVirtualNicMemberId,
        registration: SharedVirtualNicMemberRegistrationId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        if !self.managed_routes || !self.is_current_member_registration(member, registration) {
            return Err(anyhow::anyhow!("NIC member registration changed").into());
        }
        self.sync_dispatcher_sources_for_claims(member, &claims)
            .await?;
        self.ifcfg.apply_member_claims(member, claims);
        Ok(())
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    pub(crate) fn managed_source_hint(
        &self,
        route: &easytier_core::host::route::RouteSpec,
    ) -> Option<std::net::IpAddr> {
        if let cidr::IpCidr::V4(prefix) = route.destination {
            self.ifcfg
                .ipv4_route_source_hint(&SharedIpv4Route::new(
                    prefix.first_address(),
                    prefix.network_length(),
                    None,
                ))
                .map(std::net::IpAddr::V4)
        } else {
            None
        }
    }

    #[cfg(test)]
    pub(crate) fn ifcfg(&self) -> &SharedIfConfig {
        &self.ifcfg
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
        #[cfg(not(mobile))]
        self.nic.lock().await.link_up().await?;
        Ok(())
    }

    pub(crate) async fn attach_member_registration(
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
        self.apply_member_claims(member_id, claims, !cfg!(mobile))
            .await
    }

    async fn remove_member_registration_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) -> Result<(), Error> {
        if !self.is_current_member_registration(member_id, registration_id) {
            self.shutdown_dispatcher_if_idle().await;
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
        configure_os: bool,
    ) -> Result<(), Error> {
        self.ensure_valid()?;
        self.ifcfg.ensure_disjoint(member_id, &claims)?;

        let mut next_ifcfg = self.ifcfg.clone();
        next_ifcfg.apply_member_claims(member_id, claims.clone());
        if configure_os {
            let old_claims = self.ifcfg.claims_of(member_id);
            let active_claims = dispatcher_claims_for_ifcfg_transition(&old_claims, &claims);
            self.sync_dispatcher_sources_for_claims(member_id, &active_claims)
                .await?;

            if let Err(err) = self.apply_ifcfg_update(&next_ifcfg).await {
                // Native operations may have already changed addresses or routes.
                // Recreate the device rather than retaining inconsistent claims.
                self.invalidate_and_shutdown_dispatcher().await;
                return Err(err);
            }
        }

        self.sync_dispatcher_sources_for_claims(member_id, &claims)
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
        let mut claims = self.ifcfg.claims_of(member_id);
        claims.mtu = Some(mtu);
        self.apply_member_claims_for_registration(member_id, registration_id, claims)
            .await
    }

    async fn remove_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        let mut next_ifcfg = self.ifcfg.clone();
        if !next_ifcfg.remove_member(member_id) {
            return Ok(());
        }
        #[cfg(not(mobile))]
        self.apply_ifcfg_update(&next_ifcfg).await?;
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
        // A member may have reserved its registration while shutdown awaited.
        let mut lifetimes = self.lifetimes.lock().unwrap();
        if *lifetimes == Some(0) {
            *lifetimes = None;
            self.mark_invalid();
        }
    }

    pub(crate) async fn invalidate_and_shutdown_dispatcher(&mut self) {
        self.mark_invalid();
        self.shutdown_dispatcher().await;
    }

    async fn shutdown_dispatcher(&mut self) {
        if let Some(dispatcher) = self.dispatcher.take() {
            dispatcher.shutdown_without_invalidation().await;
        }
        #[cfg(target_os = "windows")]
        self.nic.lock().await.clear_windows_device();
    }

    async fn apply_ifcfg_update(&self, next_ifcfg: &SharedIfConfig) -> Result<(), Error> {
        let old_effective = self.ifcfg.effective();
        let next_effective = next_ifcfg.effective();
        let delta = SharedIfConfigDelta::between(&old_effective, &next_effective);
        let changed_routes: Vec<_> = old_effective
            .ipv4_routes
            .intersection(&next_effective.ipv4_routes)
            .filter(|route| {
                self.ifcfg.ipv4_route_source_hint(route) != next_ifcfg.ipv4_route_source_hint(route)
            })
            .collect();
        let nic = self.nic.lock().await;
        #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
        let address_update = if !delta.ipv4_addresses.added.is_empty()
            || !delta.ipv4_addresses.removed.is_empty()
            || !delta.ipv6_addresses.added.is_empty()
            || !delta.ipv6_addresses.removed.is_empty()
        {
            nic.begin_address_update()
        } else {
            None
        };

        if !self.managed_routes {
            for route in delta
                .ipv4_routes
                .removed
                .iter()
                .chain(changed_routes.iter().copied())
            {
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
        if !self.managed_routes {
            for route in delta
                .ipv4_routes
                .added
                .iter()
                .chain(changed_routes.iter().copied())
            {
                add_shared_ipv4_route(&nic, route, next_ifcfg).await?;
            }
            for route in &delta.ipv6_routes.added {
                nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                    .await?;
            }
        }
        if old_effective.mtu != next_effective.mtu {
            nic.set_mtu(next_effective.mtu.unwrap_or_else(|| nic.configured_mtu()))
                .await?;
        }

        #[cfg(target_os = "linux")]
        if !self.managed_routes && !delta.ipv4_addresses.removed.is_empty() {
            for route in &next_effective.ipv4_routes {
                ignore_added_ifcfg_already_exists(
                    add_shared_ipv4_route(&nic, route, next_ifcfg).await,
                )?;
            }
        }

        #[cfg(target_os = "linux")]
        if !self.managed_routes && !delta.ipv6_addresses.removed.is_empty() {
            for route in &next_effective.ipv6_routes {
                ignore_added_ifcfg_already_exists(
                    nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                        .await,
                )?;
            }
        }

        #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
        if let Some((state, epoch)) = address_update {
            state.mark_ready(epoch);
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

        // AsyncDevice registers with the current I/O driver when it is created,
        // so moving only the dispatcher would still tie it to the first member.
        let tunnel = self.nic.lock().await.create_dev().await?;
        let dispatcher = SharedVirtualNicDispatcher::start(
            tunnel,
            self.member_tunnel_table.clone(),
            self.valid.clone(),
        );
        if let Err(err) = self.sync_dispatcher_sources(&dispatcher).await {
            dispatcher.shutdown_without_invalidation().await;
            return Err(err);
        }
        self.dispatcher = Some(dispatcher);
        Ok(())
    }

    #[cfg(mobile)]
    async fn ensure_dispatcher_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
        replace_tun_fd: bool,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        if let Some(dispatcher) = &self.dispatcher {
            if replace_tun_fd {
                if let Err(err) = dispatcher.update_mobile_tun_fd(tun_fd).await {
                    self.invalidate_and_shutdown_dispatcher().await;
                    return Err(err);
                }
            }
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
    lifetimes: Arc<std::sync::Mutex<Option<usize>>>,
}

impl SharedVirtualNicMemberRegistration {
    fn register_tunnel(&self, close_notifier: Arc<Notify>) -> Result<Box<dyn Tunnel>, Error> {
        self.member_tunnel_table
            .register(self.member_id, self.registration_id, close_notifier)
    }
}

impl Drop for SharedVirtualNicMemberRegistration {
    fn drop(&mut self) {
        {
            let mut lifetimes = self.lifetimes.lock().unwrap();
            let count = lifetimes
                .as_mut()
                .expect("live registration cannot belong to a retired NIC");
            *count = count
                .checked_sub(1)
                .expect("shared NIC registration count underflow");
        }
        self.member_tunnel_table
            .unregister(self.member_id, self.registration_id);
        let shared_nic = self.shared_nic.clone();
        let member_id = self.member_id;
        let registration_id = self.registration_id;

        let Ok(shared) = crate::host_runtime::native_host_runtime().shared_executor() else {
            // Global shutdown already stopped the dispatcher and its actual I/O.
            // Late registration destruction must not panic or restart a driver.
            return;
        };
        shared.spawn(async move {
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
    pub(crate) fn registration_id(&self) -> SharedVirtualNicMemberRegistrationId {
        self.registration.registration_id
    }
    fn new(
        member_id: SharedVirtualNicMemberId,
        configured_mtu: u32,
        shared_nic: Arc<Mutex<SharedVirtualNic>>,
        close_notifier: Arc<Notify>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        lifetimes: Arc<std::sync::Mutex<Option<usize>>>,
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
                lifetimes,
            }),
        }
    }

    #[cfg(mobile)]
    pub(crate) async fn claims(&self) -> SharedIfConfigClaims {
        self.shared_nic.lock().await.ifcfg.claims_of(self.member_id)
    }

    #[cfg(any(mobile, test))]
    pub(crate) async fn replace_claims(
        &self,
        mut claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        claims.mtu = Some(self.configured_mtu);
        let member = self.clone();
        shared_virtual_nic_runtime()
            .spawn(async move {
                let mut shared_nic = member.shared_nic.lock().await;
                shared_nic
                    .attach_member_registration(
                        member.member_id,
                        member.registration.registration_id,
                    )
                    .await?;
                shared_nic
                    .apply_member_claims_for_registration(
                        member.member_id,
                        member.registration.registration_id,
                        claims,
                    )
                    .await
            })
            .await
            .map_err(anyhow::Error::from)?
    }

    pub fn shared_nic(&self) -> Arc<Mutex<SharedVirtualNic>> {
        self.shared_nic.clone()
    }

    pub async fn create_dev(&self) -> Result<Box<dyn Tunnel>, Error> {
        Ok(self.create_dev_with_epoch().await?.0)
    }

    pub(crate) async fn create_dev_with_epoch(
        &self,
    ) -> Result<
        (
            Box<dyn Tunnel>,
            Option<easytier_core::host::route::DeviceEpoch>,
        ),
        Error,
    > {
        let member = self.clone();
        let epoch = shared_virtual_nic_runtime()
            .spawn(async move {
                let mut shared_nic = member.shared_nic.lock().await;
                shared_nic
                    .attach_member_registration(
                        member.member_id,
                        member.registration.registration_id,
                    )
                    .await?;
                shared_nic.ensure_dispatcher().await?;
                shared_nic
                    .apply_member_mtu_for_registration(
                        member.member_id,
                        member.registration.registration_id,
                        member.configured_mtu,
                    )
                    .await?;
                // Capture the epoch under the same NIC lock as dispatcher
                // creation/reuse. Ready/DNS must receive this causal result.
                let epoch = shared_nic.nic.lock().await.device_epoch();
                Ok::<_, Error>(epoch)
            })
            .await
            .map_err(anyhow::Error::from)??;
        let tunnel = self
            .registration
            .register_tunnel(self.close_notifier.clone())?;
        Ok((tunnel, epoch))
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &self,
        tun_fd: std::os::fd::RawFd,
        replace_tun_fd: bool,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let member = self.clone();
        shared_virtual_nic_runtime()
            .spawn(async move {
                let mut shared_nic = member.shared_nic.lock().await;
                shared_nic
                    .attach_member_registration(
                        member.member_id,
                        member.registration.registration_id,
                    )
                    .await?;
                shared_nic
                    .ensure_dispatcher_for_mobile(tun_fd, replace_tun_fd)
                    .await?;
                shared_nic
                    .apply_member_mtu_for_registration(
                        member.member_id,
                        member.registration.registration_id,
                        member.configured_mtu,
                    )
                    .await
            })
            .await
            .map_err(anyhow::Error::from)??;
        self.registration
            .register_tunnel(self.close_notifier.clone())
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
        self.update_claims(move |claims| {
            claims.ipv4_addresses.insert(ip);
        })
        .await
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        self.update_claims(move |claims| {
            remove_claimed_item(&mut claims.ipv4_addresses, ip);
        })
        .await
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let ip = ipv6_inet(ip, cidr)?;
        self.update_claims(move |claims| {
            claims.ipv6_addresses.insert(ip);
        })
        .await
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        self.update_claims(move |claims| {
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
        self.update_claims(move |claims| {
            claims
                .ipv4_routes
                .insert(SharedIpv4Route::new(address, cidr, cost));
        })
        .await
    }

    pub async fn remove_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        self.update_claims(move |claims| {
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
        self.update_claims(move |claims| {
            claims
                .ipv6_routes
                .insert(SharedIpv6Route::new(address, cidr, cost));
        })
        .await
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        self.update_claims(move |claims| {
            claims
                .ipv6_routes
                .retain(|route| route.address != address || route.prefix != cidr);
        })
        .await
    }

    async fn update_claims<F>(&self, update: F) -> Result<(), Error>
    where
        F: FnOnce(&mut SharedIfConfigClaims) + Send + 'static,
    {
        // Complete OS changes and commit their claims even if the caller is cancelled.
        // Holding the registration also defers member cleanup until the commit.
        let member = self.clone();
        shared_virtual_nic_runtime()
            .spawn(async move {
                let mut shared_nic = member.shared_nic.lock().await;
                let previous = shared_nic.ifcfg.claims_of(member.member_id);
                let mut claims = previous.clone();
                update(&mut claims);
                if shared_nic.managed_routes
                    && (claims.ipv4_routes != previous.ipv4_routes
                        || claims.ipv6_routes != previous.ipv6_routes)
                {
                    return Err(anyhow::anyhow!("route mutations belong to RouteController").into());
                }
                shared_nic
                    .apply_member_claims_for_registration(
                        member.member_id,
                        member.registration.registration_id,
                        claims,
                    )
                    .await
            })
            .await
            .map_err(anyhow::Error::from)?
    }
}

#[derive(Default)]
pub struct SharedVirtualNicRegistry {
    nics: BTreeMap<SharedVirtualNicRegistryKey, SharedVirtualNicRegistryEntry>,
    closing: Arc<AtomicBool>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SharedVirtualNicRegistryKey {
    Named(String),
    Anonymous(uuid::Uuid),
}

impl SharedVirtualNicRegistryKey {
    pub(crate) fn new(dev_name: String, member: uuid::Uuid) -> Self {
        if dev_name.is_empty() {
            return Self::Anonymous(member);
        }
        #[cfg(target_os = "windows")]
        let dev_name = dev_name.to_lowercase();
        Self::Named(dev_name)
    }
}

struct SharedVirtualNicRegistryEntry {
    managed_routes: bool,
    lifetimes: Arc<std::sync::Mutex<Option<usize>>>,
    nic: Arc<Mutex<SharedVirtualNic>>,
    valid: Arc<AtomicBool>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
}

impl SharedVirtualNicRegistryEntry {
    fn reserve_registration(&self) -> bool {
        let mut lifetimes = self.lifetimes.lock().unwrap();
        if !self.is_valid() {
            return false;
        }
        match lifetimes.as_mut() {
            Some(count) => {
                *count = count
                    .checked_add(1)
                    .expect("shared NIC registration count overflow");
                true
            }
            None => false,
        }
    }

    fn new(nic: SharedVirtualNic) -> Self {
        Self {
            managed_routes: nic.managed_routes,
            lifetimes: nic.lifetimes.clone(),
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

    pub(crate) fn in_domain(closing: Arc<AtomicBool>) -> Self {
        Self {
            closing,
            ..Self::default()
        }
    }

    pub(crate) fn take_for_shutdown(&mut self) -> Vec<Arc<Mutex<SharedVirtualNic>>> {
        self.closing.store(true, Ordering::Release);
        std::mem::take(&mut self.nics)
            .into_values()
            .map(|entry| entry.nic)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn get(
        &self,
        dev_name: &str,
        _config: &VirtualNicConfig,
    ) -> Option<Arc<Mutex<SharedVirtualNic>>> {
        let key = SharedVirtualNicRegistryKey::new(dev_name.to_owned(), uuid::Uuid::nil());
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
            .filter(|(key, entry)| {
                matches!(key, SharedVirtualNicRegistryKey::Named(name) if name == dev_name)
                    && entry.is_valid()
            })
            .map(|(_, entry)| entry.nic());
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

    fn get_or_create_entry(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
        member: uuid::Uuid,
    ) -> Result<&SharedVirtualNicRegistryEntry, Error> {
        // Only explicit completion can retire an entry; weak references do not prove teardown.
        self.nics
            .retain(|_, entry| entry.lifetimes.lock().unwrap().is_some());
        let key = SharedVirtualNicRegistryKey::new(dev_name, member);
        if let Some(entry) = self.nics.get(&key).filter(|entry| entry.is_valid()) {
            if entry.managed_routes != config.routes_managed() {
                return Err(anyhow::anyhow!(
                    "cannot mix Legacy and managed routes on the same NIC"
                )
                .into());
            }
        }
        let needs_new_entry = self
            .nics
            .get(&key)
            .is_none_or(|entry| !entry.reserve_registration());
        if needs_new_entry {
            let entry = SharedVirtualNicRegistryEntry::new(SharedVirtualNic::new(config));
            assert!(entry.reserve_registration());
            self.nics.insert(key.clone(), entry);
        }

        Ok(self
            .nics
            .get(&key)
            .expect("shared virtual nic registry entry should exist"))
    }

    pub(crate) fn try_create_member(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
        member_id: SharedVirtualNicMemberId,
        close_notifier: Arc<Notify>,
    ) -> Result<SharedVirtualNicMember, Error> {
        if self.closing.load(Ordering::Acquire) {
            return Err(anyhow::anyhow!("network namespace NIC admission is closed").into());
        }
        let configured_mtu = config.mtu();
        let entry = self.get_or_create_entry(dev_name, config, member_id)?;
        Ok(SharedVirtualNicMember::new(
            member_id,
            configured_mtu,
            entry.nic(),
            close_notifier,
            entry.member_tunnel_table(),
            entry.lifetimes.clone(),
        ))
    }

    #[cfg(test)]
    pub fn create_member(
        &mut self,
        name: String,
        config: VirtualNicConfig,
        member: SharedVirtualNicMemberId,
        closed: Arc<Notify>,
    ) -> SharedVirtualNicMember {
        self.try_create_member(name, config, member, closed)
            .unwrap()
    }
}

// Rust 1.95's LLVM can zero this result when inlined into the async add_ip path.
// Remove this workaround once all build toolchains include LLVM's fix:
// https://github.com/llvm/llvm-project/pull/207229
#[inline(never)]
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
mod tests;

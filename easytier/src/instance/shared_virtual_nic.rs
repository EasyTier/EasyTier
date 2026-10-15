use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, LazyLock,
        atomic::{AtomicBool, Ordering},
    },
};

use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::{
    runtime::{Builder, Runtime},
    sync::{Mutex, Notify},
};

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

// The shared device and its cleanup must outlive every member's executor.
static SHARED_VIRTUAL_NIC_RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    Builder::new_multi_thread()
        .worker_threads(if cfg!(mobile) { 1 } else { 2 })
        .thread_name("easytier-shared-tun")
        .enable_all()
        .build()
        .expect("failed to build shared virtual nic runtime")
});

pub struct SharedVirtualNic {
    nic: Arc<Mutex<VirtualNic>>,
    ifcfg: SharedIfConfig,
    valid: Arc<AtomicBool>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    member_registrations: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberRegistrationId>,
    dispatcher: Option<SharedVirtualNicDispatcher>,
    #[cfg(all(
        target_os = "linux",
        feature = "linux-netlink",
        feature = "tun",
        not(mobile)
    ))]
    route_outlet: super::route::outlet::RouteOutlet,
    #[cfg(all(
        target_os = "linux",
        feature = "linux-netlink",
        feature = "tun",
        not(mobile)
    ))]
    route_writer_active: bool,
    #[cfg(all(
        target_os = "linux",
        feature = "linux-netlink",
        feature = "tun",
        not(mobile)
    ))]
    managed_route_members: BTreeSet<SharedVirtualNicMemberId>,
}

impl SharedVirtualNic {
    pub fn new(config: VirtualNicConfig) -> Self {
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        let route_outlet = super::route::outlet::RouteOutlet::new(
            crate::common::netns::NetNS::new(config.net_ns_name()),
        );
        let nic = VirtualNic::new(config);
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        let nic = nic.with_device_state(route_outlet.devices.clone());
        Self {
            nic: Arc::new(Mutex::new(nic)),
            ifcfg: SharedIfConfig::default(),
            valid: Arc::new(AtomicBool::new(true)),
            member_tunnel_table: SharedVirtualNicMemberTunnelTable::default(),
            member_registrations: BTreeMap::new(),
            dispatcher: None,
            #[cfg(all(
                target_os = "linux",
                feature = "linux-netlink",
                feature = "tun",
                not(mobile)
            ))]
            route_outlet,
            #[cfg(all(
                target_os = "linux",
                feature = "linux-netlink",
                feature = "tun",
                not(mobile)
            ))]
            route_writer_active: false,
            #[cfg(all(
                target_os = "linux",
                feature = "linux-netlink",
                feature = "tun",
                not(mobile)
            ))]
            managed_route_members: BTreeSet::new(),
        }
    }

    pub fn mark_invalid(&self) {
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        self.route_outlet.request_shutdown();
        self.valid.store(false, Ordering::Release);
    }

    pub fn is_valid(&self) -> bool {
        self.valid.load(Ordering::Acquire)
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
        self.apply_member_claims(member_id, claims, !cfg!(mobile))
            .await
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
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        if self.route_writer_active {
            self.route_outlet.invalidate_routes();
        }

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

        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        self.managed_route_members.remove(&member_id);

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
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        if self.route_writer_active {
            self.route_outlet.invalidate_routes();
        }

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
        #[cfg(target_os = "windows")]
        self.nic.lock().await.clear_windows_device();
    }

    async fn apply_ifcfg_update(&self, next_ifcfg: &SharedIfConfig) -> Result<(), Error> {
        let old_effective = self.ifcfg.effective();
        let next_effective = next_ifcfg.effective();
        let delta = SharedIfConfigDelta::between(&old_effective, &next_effective);
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        if self.route_writer_active
            && (!delta.ipv4_addresses.added.is_empty()
                || !delta.ipv4_addresses.removed.is_empty()
                || !delta.ipv6_addresses.added.is_empty()
                || !delta.ipv6_addresses.removed.is_empty())
        {
            self.route_outlet.invalidate_routes();
        }
        let changed_routes: Vec<_> = old_effective
            .ipv4_routes
            .intersection(&next_effective.ipv4_routes)
            .filter(|route| {
                self.ifcfg.ipv4_route_source_hint(route) != next_ifcfg.ipv4_route_source_hint(route)
            })
            .collect();
        let nic = self.nic.lock().await;

        if self.directly_manages_routes() {
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
        if self.directly_manages_routes() {
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
        if self.directly_manages_routes() && !delta.ipv4_addresses.removed.is_empty() {
            for route in &next_effective.ipv4_routes {
                ignore_added_ifcfg_already_exists(
                    add_shared_ipv4_route(&nic, route, next_ifcfg).await,
                )?;
            }
        }

        #[cfg(target_os = "linux")]
        if self.directly_manages_routes() && !delta.ipv6_addresses.removed.is_empty() {
            for route in &next_effective.ipv6_routes {
                ignore_added_ifcfg_already_exists(
                    nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                        .await,
                )?;
            }
        }

        Ok(())
    }

    fn directly_manages_routes(&self) -> bool {
        #[cfg(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        ))]
        {
            !self.route_writer_active
        }
        #[cfg(not(all(
            target_os = "linux",
            feature = "linux-netlink",
            feature = "tun",
            not(mobile)
        )))]
        {
            true
        }
    }

    #[cfg(all(
        target_os = "linux",
        feature = "linux-netlink",
        feature = "tun",
        not(mobile)
    ))]
    pub(crate) async fn project_route_inputs(
        &mut self,
        inputs: &[(
            Arc<super::route::scope::RouteInput>,
            easytier_core::host::route::RouteSet,
        )],
    ) -> Result<super::route::projection::RouteProjection, Error> {
        use easytier_core::host::route::{RouteSet, RouteSpec};
        if let Err(error) = self.ensure_valid() {
            self.route_outlet.request_shutdown();
            return Err(error);
        }
        let mut next = self.ifcfg.clone();
        let present = inputs
            .iter()
            .filter(|(input, _)| {
                self.is_current_member_registration(input.scope.member(), input.member_registration)
            })
            .map(|(input, _)| input.scope.member())
            .collect::<BTreeSet<_>>();
        for member in self.managed_route_members.difference(&present) {
            let mut claims = next.claims_of(*member);
            claims.ipv4_routes.clear();
            claims.ipv6_routes.clear();
            next.apply_member_claims(*member, claims);
        }
        // Fully withdrawn members release their destinations before additions.
        for (input, _) in inputs.iter().filter(|(_, requested)| requested.is_empty()) {
            if self.is_current_member_registration(input.scope.member(), input.member_registration)
            {
                let mut claims = next.claims_of(input.scope.member());
                claims.ipv4_routes.clear();
                claims.ipv6_routes.clear();
                next.apply_member_claims(input.scope.member(), claims);
            }
        }
        let mut pending = Vec::new();
        for (input, requested) in inputs.iter().filter(|(_, requested)| !requested.is_empty()) {
            let member = input.scope.member();
            if !self.is_current_member_registration(member, input.member_registration) {
                continue;
            }
            let mut claims = next.claims_of(member);
            claims.ipv4_routes.clear();
            claims.ipv6_routes.clear();
            for spec in requested {
                match spec.destination {
                    cidr::IpCidr::V4(destination) => {
                        claims.ipv4_routes.insert(SharedIpv4Route::new(
                            destination.first_address(),
                            destination.network_length(),
                            Some(spec.metric.get() as i32),
                        ));
                    }
                    cidr::IpCidr::V6(destination) => {
                        claims.ipv6_routes.insert(SharedIpv6Route::new(
                            destination.first_address(),
                            destination.network_length(),
                            Some(spec.metric.get() as i32),
                        ));
                    }
                }
            }
            pending.push((member, claims));
        }
        // A nonempty replacement can release a prefix wanted by a proposal
        // visited earlier. Reconsider blocked proposals after each progress
        // pass, without requiring an unrelated future notification. A member's
        // replacement remains atomic; conflicts retain its accepted claims.
        loop {
            let before = pending.len();
            pending.retain(|(member, claims)| {
                if next.ensure_disjoint(*member, claims).is_ok() {
                    next.apply_member_claims(*member, claims.clone());
                    false
                } else {
                    true
                }
            });
            if pending.len() == before {
                break;
            }
        }
        for (member, claims) in pending {
            if let Err(error) = next.ensure_disjoint(member, &claims) {
                tracing::warn!(
                    ?member,
                    ?error,
                    "route intent rejected by shared NIC membership policy; retaining accepted claims"
                );
            }
        }
        for member in &self.managed_route_members {
            if self.ifcfg.member_claims.get(member) == next.member_claims.get(member) {
                continue;
            }
            let claims = next.claims_of(*member);
            if let Err(error) = self
                .sync_dispatcher_sources_for_claims(*member, &claims)
                .await
            {
                // A partial dispatcher update must not leave a healthy-looking
                // outlet with claims that were never committed.
                self.invalidate_and_shutdown_dispatcher().await;
                return Err(error);
            }
        }
        self.ifcfg = next;
        let mut projection = super::route::projection::RouteProjection {
            scopes: BTreeMap::new(),
            sources: BTreeMap::new(),
        };
        for (input, _) in inputs {
            let member = input.scope.member();
            if !self.is_current_member_registration(member, input.member_registration) {
                continue;
            }
            let claims = self.ifcfg.claims_of(member);
            let mut routes = RouteSet::new();
            for route in claims.ipv4_routes {
                let metric = route.cost.unwrap_or(65535) as u32;
                if let Some(metric) = std::num::NonZeroU32::new(metric) {
                    let spec = RouteSpec::new(
                        cidr::IpCidr::V4(cidr::Ipv4Cidr::new(route.address, route.prefix).unwrap()),
                        metric,
                    );
                    projection.sources.insert(
                        spec,
                        self.ifcfg
                            .ipv4_route_source_hint(&route)
                            .map(std::net::IpAddr::V4),
                    );
                    routes.insert(spec);
                }
            }
            for route in claims.ipv6_routes {
                if let Some(metric) = std::num::NonZeroU32::new(route.cost.unwrap_or(65535) as u32)
                {
                    routes.insert(RouteSpec::new(
                        cidr::IpCidr::V6(cidr::Ipv6Cidr::new(route.address, route.prefix).unwrap()),
                        metric,
                    ));
                }
            }
            projection.scopes.insert(input.id, routes);
        }
        Ok(projection)
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
}

impl SharedVirtualNicMemberRegistration {
    fn register_tunnel(&self, close_notifier: Arc<Notify>) -> Result<Box<dyn Tunnel>, Error> {
        self.member_tunnel_table
            .register(self.member_id, self.registration_id, close_notifier)
    }
}

impl Drop for SharedVirtualNicMemberRegistration {
    fn drop(&mut self) {
        self.member_tunnel_table
            .unregister(self.member_id, self.registration_id);
        let shared_nic = self.shared_nic.clone();
        let member_id = self.member_id;
        let registration_id = self.registration_id;

        SHARED_VIRTUAL_NIC_RUNTIME.spawn(async move {
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
        SHARED_VIRTUAL_NIC_RUNTIME
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

    #[cfg(all(
        target_os = "linux",
        feature = "linux-netlink",
        feature = "tun",
        not(mobile)
    ))]
    pub(crate) async fn attach_route_scope(
        &self,
        scope: super::route::scope::RouteScope,
    ) -> Result<super::route::scope::RouteScopeLease, Error> {
        let member = self.clone();
        SHARED_VIRTUAL_NIC_RUNTIME
            .spawn(async move {
                let mut nic = member.shared_nic.lock().await;
                nic.attach_member_registration(
                    member.member_id,
                    member.registration.registration_id,
                )
                .await?;
                nic.route_outlet
                    .start(Arc::downgrade(&member.shared_nic))
                    .await?;
                nic.route_writer_active = true;
                nic.managed_route_members.insert(member.member_id);
                Ok(nic
                    .route_outlet
                    .attach(&scope, member.registration.registration_id)?)
            })
            .await
            .map_err(anyhow::Error::from)?
    }

    pub fn shared_nic(&self) -> Arc<Mutex<SharedVirtualNic>> {
        self.shared_nic.clone()
    }

    pub async fn create_dev(&self) -> Result<Box<dyn Tunnel>, Error> {
        let member = self.clone();
        SHARED_VIRTUAL_NIC_RUNTIME
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
                    .await
            })
            .await
            .map_err(anyhow::Error::from)??;
        self.registration
            .register_tunnel(self.close_notifier.clone())
    }

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &self,
        tun_fd: std::os::fd::RawFd,
        replace_tun_fd: bool,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let member = self.clone();
        SHARED_VIRTUAL_NIC_RUNTIME
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
        SHARED_VIRTUAL_NIC_RUNTIME
            .spawn(async move {
                let mut shared_nic = member.shared_nic.lock().await;
                let mut claims = shared_nic.ifcfg.claims_of(member.member_id);
                update(&mut claims);
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
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedVirtualNicRegistryKey {
    net_ns: Option<String>,
    dev_name: String,
    private_owner: Option<SharedVirtualNicMemberId>,
}

impl SharedVirtualNicRegistryKey {
    fn new(dev_name: String, config: &VirtualNicConfig) -> Self {
        Self {
            net_ns: config.net_ns_name(),
            dev_name,
            private_owner: None,
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

    #[cfg(test)]
    pub(crate) fn get(
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

    fn get_or_create_entry(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
        member_id: SharedVirtualNicMemberId,
    ) -> &SharedVirtualNicRegistryEntry {
        let mut key = SharedVirtualNicRegistryKey::new(dev_name, &config);
        if !cfg!(mobile) && key.dev_name.is_empty() {
            key.private_owner = Some(member_id);
        }
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
        let entry = self.get_or_create_entry(dev_name, config, member_id);
        SharedVirtualNicMember::new(
            member_id,
            configured_mtu,
            entry.nic(),
            close_notifier,
            entry.member_tunnel_table(),
        )
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

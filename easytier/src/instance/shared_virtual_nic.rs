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

use crate::{
    common::error::Error,
    tunnel::{Tunnel, ring::create_ring_tunnel_pair},
};

use super::virtual_nic::{VirtualNic, VirtualNicConfig};

#[cfg(not(target_os = "linux"))]
use crate::common::ifcfg::IfConfiger;

mod dispatcher;

use dispatcher::{SharedVirtualNicDispatcher, SharedVirtualNicMemberTunnelTable};

pub type SharedVirtualNicMemberId = uuid::Uuid;
pub(super) type SharedVirtualNicMemberRegistrationId = uuid::Uuid;

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedIfConfigSnapshot {
    pub ipv4_addresses: BTreeMap<Ipv4Inet, BTreeSet<SharedVirtualNicMemberId>>,
    pub ipv6_addresses: BTreeMap<Ipv6Inet, BTreeSet<SharedVirtualNicMemberId>>,
    pub ipv4_routes: BTreeMap<SharedIpv4Route, BTreeSet<SharedVirtualNicMemberId>>,
    pub ipv6_routes: BTreeMap<SharedIpv6Route, BTreeSet<SharedVirtualNicMemberId>>,
    pub effective_mtu: Option<u32>,
}

#[derive(Clone, Debug, Default)]
pub struct SharedIfConfig {
    member_claims: BTreeMap<SharedVirtualNicMemberId, SharedIfConfigClaims>,
    ipv4_address_owners: BTreeMap<Ipv4Inet, BTreeSet<SharedVirtualNicMemberId>>,
    ipv6_address_owners: BTreeMap<Ipv6Inet, BTreeSet<SharedVirtualNicMemberId>>,
    ipv4_route_owners: BTreeMap<SharedIpv4Route, BTreeSet<SharedVirtualNicMemberId>>,
    ipv6_route_owners: BTreeMap<SharedIpv6Route, BTreeSet<SharedVirtualNicMemberId>>,
    member_mtu: BTreeMap<SharedVirtualNicMemberId, u32>,
}

impl SharedIfConfig {
    pub fn apply_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> SharedIfConfigDelta {
        let old_claims = self
            .member_claims
            .get(&member_id)
            .cloned()
            .unwrap_or_default();
        let old_mtu = self.effective_mtu();

        let ipv4_addresses = update_owned_items(
            &mut self.ipv4_address_owners,
            member_id,
            &old_claims.ipv4_addresses,
            &claims.ipv4_addresses,
        );
        let ipv6_addresses = update_owned_items(
            &mut self.ipv6_address_owners,
            member_id,
            &old_claims.ipv6_addresses,
            &claims.ipv6_addresses,
        );
        let ipv4_routes = update_owned_items(
            &mut self.ipv4_route_owners,
            member_id,
            &old_claims.ipv4_routes,
            &claims.ipv4_routes,
        );
        let ipv6_routes = update_owned_items(
            &mut self.ipv6_route_owners,
            member_id,
            &old_claims.ipv6_routes,
            &claims.ipv6_routes,
        );

        update_member_mtu(&mut self.member_mtu, member_id, claims.mtu);
        self.member_claims.insert(member_id, claims);

        SharedIfConfigDelta {
            ipv4_addresses,
            ipv6_addresses,
            ipv4_routes,
            ipv6_routes,
            mtu: mtu_delta(old_mtu, self.effective_mtu()),
        }
    }

    pub fn remove_member(
        &mut self,
        member_id: SharedVirtualNicMemberId,
    ) -> Option<SharedIfConfigDelta> {
        let old_claims = self.member_claims.remove(&member_id)?;
        let old_mtu = self.effective_mtu();

        let ipv4_addresses = remove_owned_items(
            &mut self.ipv4_address_owners,
            member_id,
            &old_claims.ipv4_addresses,
        );
        let ipv6_addresses = remove_owned_items(
            &mut self.ipv6_address_owners,
            member_id,
            &old_claims.ipv6_addresses,
        );
        let ipv4_routes = remove_owned_items(
            &mut self.ipv4_route_owners,
            member_id,
            &old_claims.ipv4_routes,
        );
        let ipv6_routes = remove_owned_items(
            &mut self.ipv6_route_owners,
            member_id,
            &old_claims.ipv6_routes,
        );

        self.member_mtu.remove(&member_id);

        Some(SharedIfConfigDelta {
            ipv4_addresses,
            ipv6_addresses,
            ipv4_routes,
            ipv6_routes,
            mtu: mtu_delta(old_mtu, self.effective_mtu()),
        })
    }

    pub fn effective_mtu(&self) -> Option<u32> {
        self.member_mtu.values().copied().min()
    }

    pub fn owners_of_ipv4_route(
        &self,
        route: &SharedIpv4Route,
    ) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_of(&self.ipv4_route_owners, route)
    }

    pub fn owners_of_ipv6_route(
        &self,
        route: &SharedIpv6Route,
    ) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_of(&self.ipv6_route_owners, route)
    }

    pub fn owners_of_ipv4_address(&self, address: &Ipv4Inet) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_of(&self.ipv4_address_owners, address)
    }

    pub fn owners_of_ipv6_address(&self, address: &Ipv6Inet) -> BTreeSet<SharedVirtualNicMemberId> {
        owners_of(&self.ipv6_address_owners, address)
    }

    pub fn snapshot(&self) -> SharedIfConfigSnapshot {
        SharedIfConfigSnapshot {
            ipv4_addresses: self.ipv4_address_owners.clone(),
            ipv6_addresses: self.ipv6_address_owners.clone(),
            ipv4_routes: self.ipv4_route_owners.clone(),
            ipv6_routes: self.ipv6_route_owners.clone(),
            effective_mtu: self.effective_mtu(),
        }
    }

    fn claims_of(&self, member_id: SharedVirtualNicMemberId) -> SharedIfConfigClaims {
        self.member_claims
            .get(&member_id)
            .cloned()
            .unwrap_or_default()
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

        match self.member_registrations.insert(member_id, registration_id) {
            Some(old_registration_id) if old_registration_id != registration_id => {
                self.remove_member_claims(member_id).await?;
            }
            _ => {}
        }

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

        self.member_registrations.remove(&member_id);
        self.remove_member_claims(member_id).await
    }

    async fn apply_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> Result<(), Error> {
        self.ensure_valid()?;

        let mut next_ifcfg = self.ifcfg.clone();
        let old_claims = self.ifcfg.claims_of(member_id);
        let next_claims = claims.clone();
        let delta = next_ifcfg.apply_member_claims(member_id, claims);
        self.sync_dispatcher_sources_for_ifcfg_update(member_id, &old_claims, &next_claims)
            .await?;

        if let Err(err) = self.apply_ifcfg_delta(&delta).await {
            let _ = self
                .sync_dispatcher_sources_for_member(member_id, &old_claims)
                .await;
            return Err(err);
        }

        self.sync_dispatcher_sources_for_member(member_id, &next_claims)
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

        let mut next_ifcfg = self.ifcfg.clone();
        let next_claims = claims.clone();
        next_ifcfg.apply_member_claims(member_id, claims);

        self.sync_dispatcher_sources_for_member(member_id, &next_claims)
            .await?;
        self.ifcfg = next_ifcfg;

        Ok(())
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
        self.apply_ifcfg_delta(&delta).await?;
        #[cfg(mobile)]
        drop(delta);
        self.remove_dispatcher_sources_for_member(member_id).await?;
        self.ifcfg = next_ifcfg;

        Ok(())
    }

    async fn apply_ifcfg_delta(&self, delta: &SharedIfConfigDelta) -> Result<(), Error> {
        let nic = self.nic.lock().await;

        for route in &delta.ipv4_routes.removed {
            ignore_removed_ifcfg_not_found(nic.remove_route(route.address, route.prefix).await)?;
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
            nic.add_route_with_cost(route.address, route.prefix, route.cost)
                .await?;
        }
        for route in &delta.ipv6_routes.added {
            nic.add_ipv6_route_with_cost(route.address, route.prefix, route.cost)
                .await?;
        }

        if let Some(mtu) = &delta.mtu {
            nic.set_mtu(mtu.new.unwrap_or_else(|| nic.configured_mtu()))
                .await?;
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
            dispatcher.update_mobile_tun_fd(tun_fd);
            self.nic.lock().await.set_mobile_tun_fd_name(tun_fd);
            return Ok(());
        }

        self.nic.lock().await.set_mobile_tun_fd_name(tun_fd);
        let dispatcher = SharedVirtualNicDispatcher::start_for_mobile(
            self.nic.clone(),
            tun_fd,
            self.member_tunnel_table.clone(),
            self.valid.clone(),
        );
        self.sync_dispatcher_sources(&dispatcher).await?;
        self.dispatcher = Some(dispatcher);
        Ok(())
    }

    async fn sync_dispatcher_sources(
        &self,
        dispatcher: &SharedVirtualNicDispatcher,
    ) -> Result<(), Error> {
        for (member_id, claims) in &self.ifcfg.member_claims {
            dispatcher
                .update_sources(*member_id, &claims.ipv4_addresses, &claims.ipv6_addresses)
                .await?;
        }
        Ok(())
    }

    async fn sync_dispatcher_sources_for_ifcfg_update(
        &self,
        member_id: SharedVirtualNicMemberId,
        old_claims: &SharedIfConfigClaims,
        next_claims: &SharedIfConfigClaims,
    ) -> Result<(), Error> {
        let mut active_ipv4_addresses = old_claims.ipv4_addresses.clone();
        active_ipv4_addresses.extend(next_claims.ipv4_addresses.iter().copied());
        let mut active_ipv6_addresses = old_claims.ipv6_addresses.clone();
        active_ipv6_addresses.extend(next_claims.ipv6_addresses.iter().copied());

        self.sync_dispatcher_sources_for_addresses(
            member_id,
            &active_ipv4_addresses,
            &active_ipv6_addresses,
        )
        .await
    }

    async fn sync_dispatcher_sources_for_member(
        &self,
        member_id: SharedVirtualNicMemberId,
        claims: &SharedIfConfigClaims,
    ) -> Result<(), Error> {
        self.sync_dispatcher_sources_for_addresses(
            member_id,
            &claims.ipv4_addresses,
            &claims.ipv6_addresses,
        )
        .await
    }

    async fn sync_dispatcher_sources_for_addresses(
        &self,
        member_id: SharedVirtualNicMemberId,
        ipv4_addresses: &BTreeSet<Ipv4Inet>,
        ipv6_addresses: &BTreeSet<Ipv6Inet>,
    ) -> Result<(), Error> {
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher
                .update_sources(member_id, ipv4_addresses, ipv6_addresses)
                .await?;
        }
        Ok(())
    }

    async fn remove_dispatcher_sources_for_member(
        &self,
        member_id: SharedVirtualNicMemberId,
    ) -> Result<(), Error> {
        if let Some(dispatcher) = &self.dispatcher {
            dispatcher.remove_sources(member_id).await?;
        }
        Ok(())
    }
}

fn ignore_removed_ifcfg_not_found(result: Result<(), Error>) -> Result<(), Error> {
    match result {
        Err(Error::NotFound) => Ok(()),
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
    shared_nic: Arc<Mutex<SharedVirtualNic>>,
    close_notifier: Arc<Notify>,
    registration: Arc<SharedVirtualNicMemberRegistration>,
}

impl SharedVirtualNicMember {
    fn new(
        member_id: SharedVirtualNicMemberId,
        shared_nic: Arc<Mutex<SharedVirtualNic>>,
        close_notifier: Arc<Notify>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    ) -> Self {
        let registration_id = uuid::Uuid::new_v4();
        Self {
            member_id,
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

    pub async fn create_dev(&self) -> Result<Box<dyn Tunnel>, Error> {
        let (member_tunnel, shared_tunnel) = create_ring_tunnel_pair();
        {
            let mut shared_nic = self.shared_nic.lock().await;
            shared_nic
                .attach_member_registration(self.member_id, self.registration.registration_id)
                .await?;
            shared_nic.ensure_dispatcher().await?;
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
        self.update_claims(|claims| match ip {
            Some(ip) => {
                claims.ipv4_addresses.remove(&ip);
            }
            None => {
                claims.ipv4_addresses.clear();
            }
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
    pub async fn add_mobile_source_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let ip = ipv4_inet(ip, cidr)?;
        self.update_claims_for_mobile(|claims| {
            claims.ipv4_addresses.insert(ip);
        })
        .await
    }

    #[cfg(mobile)]
    pub async fn add_mobile_source_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let ip = ipv6_inet(ip, cidr)?;
        self.update_claims_for_mobile(|claims| {
            claims.ipv6_addresses.insert(ip);
        })
        .await
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        self.update_claims(|claims| match ip {
            Some(ip) => {
                claims.ipv6_addresses.remove(&ip);
            }
            None => {
                claims.ipv6_addresses.clear();
            }
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

    #[cfg(mobile)]
    async fn update_claims_for_mobile<F>(&self, update: F) -> Result<(), Error>
    where
        F: FnOnce(&mut SharedIfConfigClaims) + Send,
    {
        let mut shared_nic = self.shared_nic.lock().await;
        let mut claims = shared_nic.ifcfg.claims_of(self.member_id);
        update(&mut claims);
        shared_nic
            .apply_member_claims_for_mobile_registration(
                self.member_id,
                self.registration.registration_id,
                claims,
            )
            .await
    }
}

#[derive(Default)]
pub struct SharedVirtualNicRegistry {
    nics: BTreeMap<String, SharedVirtualNicRegistryEntry>,
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

    pub fn get(&self, dev_name: &str) -> Option<Arc<Mutex<SharedVirtualNic>>> {
        self.nics
            .get(dev_name)
            .filter(|entry| entry.is_valid())
            .map(|entry| entry.nic())
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
        let needs_new_entry = self
            .nics
            .get(&dev_name)
            .is_none_or(|entry| !entry.is_valid());
        if needs_new_entry {
            let entry = SharedVirtualNicRegistryEntry::new(SharedVirtualNic::new(config));
            self.nics.insert(dev_name.clone(), entry);
        }

        self.nics
            .get(&dev_name)
            .expect("shared virtual nic registry entry should exist")
    }

    pub fn create_member(
        &mut self,
        dev_name: String,
        config: VirtualNicConfig,
        member_id: SharedVirtualNicMemberId,
        close_notifier: Arc<Notify>,
    ) -> SharedVirtualNicMember {
        let entry = self.get_or_create_entry(dev_name, config);
        SharedVirtualNicMember::new(
            member_id,
            entry.nic(),
            close_notifier,
            entry.member_tunnel_table(),
        )
    }
}

fn update_owned_items<T>(
    owners: &mut BTreeMap<T, BTreeSet<SharedVirtualNicMemberId>>,
    member_id: SharedVirtualNicMemberId,
    old_items: &BTreeSet<T>,
    new_items: &BTreeSet<T>,
) -> OwnedItemDelta<T>
where
    T: Ord + Clone,
{
    let mut delta = OwnedItemDelta::default();

    for item in old_items.difference(new_items) {
        if remove_item_owner(owners, item, member_id) {
            delta.removed.insert(item.clone());
        }
    }

    for item in new_items.difference(old_items) {
        if add_item_owner(owners, item.clone(), member_id) {
            delta.added.insert(item.clone());
        }
    }

    delta
}

fn remove_owned_items<T>(
    owners: &mut BTreeMap<T, BTreeSet<SharedVirtualNicMemberId>>,
    member_id: SharedVirtualNicMemberId,
    items: &BTreeSet<T>,
) -> OwnedItemDelta<T>
where
    T: Ord + Clone,
{
    let mut delta = OwnedItemDelta::default();

    for item in items {
        if remove_item_owner(owners, item, member_id) {
            delta.removed.insert(item.clone());
        }
    }

    delta
}

fn add_item_owner<T>(
    owners: &mut BTreeMap<T, BTreeSet<SharedVirtualNicMemberId>>,
    item: T,
    member_id: SharedVirtualNicMemberId,
) -> bool
where
    T: Ord,
{
    let entry = owners.entry(item).or_default();
    let is_new_item = entry.is_empty();
    entry.insert(member_id);
    is_new_item
}

fn remove_item_owner<T>(
    owners: &mut BTreeMap<T, BTreeSet<SharedVirtualNicMemberId>>,
    item: &T,
    member_id: SharedVirtualNicMemberId,
) -> bool
where
    T: Ord,
{
    let Some(entry) = owners.get_mut(item) else {
        return false;
    };

    entry.remove(&member_id);
    if !entry.is_empty() {
        return false;
    }

    owners.remove(item);
    true
}

fn update_member_mtu(
    member_mtu: &mut BTreeMap<SharedVirtualNicMemberId, u32>,
    member_id: SharedVirtualNicMemberId,
    mtu: Option<u32>,
) {
    match mtu {
        Some(mtu) => {
            member_mtu.insert(member_id, mtu);
        }
        None => {
            member_mtu.remove(&member_id);
        }
    }
}

fn mtu_delta(old: Option<u32>, new: Option<u32>) -> Option<SharedMtuChange> {
    (old != new).then_some(SharedMtuChange { old, new })
}

fn owners_of<T>(
    owners: &BTreeMap<T, BTreeSet<SharedVirtualNicMemberId>>,
    item: &T,
) -> BTreeSet<SharedVirtualNicMemberId>
where
    T: Ord,
{
    owners.get(item).cloned().unwrap_or_default()
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

    use crate::common::netns::NetNS;
    use tokio::sync::Notify;

    use super::*;

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

    fn virtual_nic_config() -> VirtualNicConfig {
        VirtualNicConfig::new(String::new(), 1500, NetNS::new(None))
    }

    #[test]
    fn duplicate_routes_keep_owner_sets_and_single_os_delta() {
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 10, 0, 0), 24, None);
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
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 20, 0, 0), 24, None);
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

    #[test]
    fn registry_reuses_shared_virtual_nic_for_same_dev_name() {
        let mut registry = SharedVirtualNicRegistry::new();

        let first = registry.get_or_create("et0".to_string(), virtual_nic_config());
        let second = registry.get_or_create("et0".to_string(), virtual_nic_config());

        assert!(Arc::ptr_eq(&first, &second));
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
                .get("et0")
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
        let shared_nic = registry.get("et0").unwrap();

        assert_eq!(member.member_id(), member_id);
        assert!(Arc::ptr_eq(&member.shared_nic(), &shared_nic));
    }
}

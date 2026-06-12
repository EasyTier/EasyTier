use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use cidr::{Ipv4Inet, Ipv6Inet};
use tokio::sync::Mutex;

use crate::common::global_ctx::ArcGlobalCtx;

use super::virtual_nic::VirtualNic;

pub type SharedVirtualNicMemberId = uuid::Uuid;

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
}

pub struct SharedVirtualNic {
    nic: Arc<Mutex<VirtualNic>>,
    ifcfg: SharedIfConfig,
}

impl SharedVirtualNic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            nic: Arc::new(Mutex::new(VirtualNic::new(global_ctx))),
            ifcfg: SharedIfConfig::default(),
        }
    }

    pub fn attach_member(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> SharedIfConfigDelta {
        self.ifcfg.apply_member_claims(member_id, claims)
    }

    pub fn update_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) -> SharedIfConfigDelta {
        self.ifcfg.apply_member_claims(member_id, claims)
    }

    pub fn detach_member(
        &mut self,
        member_id: SharedVirtualNicMemberId,
    ) -> Option<SharedIfConfigDelta> {
        self.ifcfg.remove_member(member_id)
    }

    pub fn ifcfg(&self) -> &SharedIfConfig {
        &self.ifcfg
    }

    pub fn nic(&self) -> Arc<Mutex<VirtualNic>> {
        self.nic.clone()
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

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use crate::common::global_ctx::tests::get_mock_global_ctx;

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

    #[tokio::test]
    async fn shared_virtual_nic_wraps_virtual_nic_and_tracks_ifcfg() {
        let mut shared_nic = SharedVirtualNic::new(get_mock_global_ctx());
        let member = member_id(1);
        let route = SharedIpv4Route::new(Ipv4Addr::new(10, 40, 0, 0), 24, None);

        shared_nic.attach_member(member, claims_with_ipv4_route(route.clone(), None));

        assert_eq!(
            shared_nic.ifcfg().owners_of_ipv4_route(&route),
            BTreeSet::from([member])
        );
        drop(shared_nic.nic());
    }
}

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{Ipv4Addr, Ipv6Addr},
};

use cidr::{Ipv4Cidr, Ipv4Inet, Ipv6Cidr, Ipv6Inet};

use super::SharedVirtualNicMemberId;

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
    fn ipv4_destinations(&self) -> impl Iterator<Item = (Ipv4Cidr, bool)> + '_ {
        self.ipv4_addresses
            .iter()
            .map(|ip| (ip.network(), false))
            .chain(
                self.ipv4_routes
                    .iter()
                    .filter_map(|route| Ipv4Inet::new(route.address, route.prefix).ok())
                    .map(|route| (route.network(), true)),
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
pub(super) struct OwnedItemDelta<T> {
    pub added: BTreeSet<T>,
    pub removed: BTreeSet<T>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SharedIfConfigDelta {
    pub ipv4_addresses: OwnedItemDelta<Ipv4Inet>,
    pub ipv6_addresses: OwnedItemDelta<Ipv6Inet>,
    pub ipv4_routes: OwnedItemDelta<SharedIpv4Route>,
    pub ipv6_routes: OwnedItemDelta<SharedIpv6Route>,
}

impl SharedIfConfigDelta {
    pub(super) fn between(old: &SharedIfConfigClaims, new: &SharedIfConfigClaims) -> Self {
        Self {
            ipv4_addresses: item_delta(&old.ipv4_addresses, &new.ipv4_addresses),
            ipv6_addresses: item_delta(&old.ipv6_addresses, &new.ipv6_addresses),
            ipv4_routes: item_delta(&old.ipv4_routes, &new.ipv4_routes),
            ipv6_routes: item_delta(&old.ipv6_routes, &new.ipv6_routes),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SharedIfConfig {
    pub(super) member_claims: BTreeMap<SharedVirtualNicMemberId, SharedIfConfigClaims>,
}

#[derive(Debug, thiserror::Error)]
#[error(
    "shared virtual NIC destination {requested} overlaps member {member_id} destination {existing}"
)]
pub(crate) struct SharedIfConfigConflict {
    requested: String,
    member_id: SharedVirtualNicMemberId,
    existing: String,
}

impl SharedIfConfig {
    pub(crate) fn ensure_disjoint(
        &self,
        member_id: SharedVirtualNicMemberId,
        claims: &SharedIfConfigClaims,
    ) -> anyhow::Result<()> {
        let magic_dns = Ipv4Cidr::new(crate::instance::dns_server::MAGIC_DNS_FAKE_IP.parse()?, 32)?;
        for (other_id, other) in &self.member_claims {
            if *other_id == member_id {
                continue;
            }
            for (requested, requested_is_route) in claims.ipv4_destinations() {
                if let Some((existing, _)) =
                    other
                        .ipv4_destinations()
                        .find(|(existing, existing_is_route)| {
                            !(requested_is_route
                                && *existing_is_route
                                && requested == magic_dns
                                && *existing == magic_dns)
                                && ipv4_cidrs_overlap(requested, *existing)
                        })
                {
                    return Err(SharedIfConfigConflict {
                        requested: requested.to_string(),
                        member_id: *other_id,
                        existing: existing.to_string(),
                    }
                    .into());
                }
            }
            for requested in claims.ipv6_destinations() {
                if let Some(existing) = other
                    .ipv6_destinations()
                    .find(|existing| ipv6_cidrs_overlap(requested, *existing))
                {
                    return Err(SharedIfConfigConflict {
                        requested: requested.to_string(),
                        member_id: *other_id,
                        existing: existing.to_string(),
                    }
                    .into());
                }
            }
        }
        Ok(())
    }

    pub(crate) fn apply_member_claims(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        claims: SharedIfConfigClaims,
    ) {
        self.member_claims.insert(member_id, claims);
    }

    pub(super) fn remove_member(&mut self, member_id: SharedVirtualNicMemberId) -> bool {
        self.member_claims.remove(&member_id).is_some()
    }

    fn effective_mtu(&self) -> Option<u32> {
        self.member_claims
            .values()
            .filter_map(|claims| claims.mtu)
            .min()
    }

    #[cfg(test)]
    pub(crate) fn owners_of_ipv4_route(
        &self,
        route: &SharedIpv4Route,
    ) -> BTreeSet<SharedVirtualNicMemberId> {
        self.member_claims
            .iter()
            .filter_map(|(member_id, claims)| {
                claims.ipv4_routes.contains(route).then_some(*member_id)
            })
            .collect()
    }

    pub(super) fn effective(&self) -> SharedIfConfigClaims {
        SharedIfConfigClaims {
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
            mtu: self.effective_mtu(),
        }
    }

    pub(super) fn claims_of(&self, member_id: SharedVirtualNicMemberId) -> SharedIfConfigClaims {
        self.member_claims
            .get(&member_id)
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn ipv4_route_source_hint(&self, route: &SharedIpv4Route) -> Option<Ipv4Addr> {
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

fn ipv4_cidrs_overlap(left: Ipv4Cidr, right: Ipv4Cidr) -> bool {
    left.contains(&right.first_address()) || right.contains(&left.first_address())
}

fn ipv6_cidrs_overlap(left: Ipv6Cidr, right: Ipv6Cidr) -> bool {
    left.contains(&right.first_address()) || right.contains(&left.first_address())
}

#[cfg(test)]
mod tests;

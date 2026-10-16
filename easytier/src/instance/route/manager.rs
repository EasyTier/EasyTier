//! Concrete native route indexing and reconciliation state.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    num::NonZeroU32,
};

use cidr::IpCidr;
use easytier_core::host::route::DeviceEpoch;
use uuid::Uuid;

use super::{OsRoute, OsRouteSlotKey};

/// Exact effect parameters with the device evidence outside the backend API.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct RouteKey {
    route: OsRoute,
    nic: Uuid,
    epoch: DeviceEpoch,
}

/// Equal forwarding semantics within one real device generation. Metric is
/// aggregated; different sources, tables and device generations remain distinct.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ForwardKey {
    table: u32,
    destination: IpCidr,
    ifindex: u32,
    preferred_source: Option<IpAddr>,
    nic: Uuid,
    epoch: DeviceEpoch,
}

impl RouteKey {
    fn forward(&self) -> ForwardKey {
        ForwardKey {
            table: self.route.table,
            destination: self.route.destination,
            ifindex: self.route.ifindex,
            preferred_source: self.route.preferred_source,
            nic: self.nic,
            epoch: self.epoch,
        }
    }
}

impl ForwardKey {
    fn route(&self, metric: NonZeroU32) -> RouteKey {
        RouteKey {
            route: OsRoute {
                table: self.table,
                destination: self.destination,
                ifindex: self.ifindex,
                preferred_source: self.preferred_source,
                metric,
            },
            nic: self.nic,
            epoch: self.epoch,
        }
    }
}

#[derive(Default)]
struct ForwardOwners {
    metrics: BTreeMap<NonZeroU32, BTreeSet<Uuid>>,
    // Number of distinct metrics requested by each owner for this forward key.
    // This permits local removal without scanning every other owner's metrics.
    owners: BTreeMap<Uuid, usize>,
}

#[derive(Default)]
struct DesiredIndex {
    sources: BTreeMap<ForwardKey, ForwardOwners>,
    aggregates: BTreeMap<ForwardKey, RouteKey>,
    slots: BTreeMap<OsRouteSlotKey, BTreeMap<RouteKey, BTreeSet<Uuid>>>,
}

impl DesiredIndex {
    /// Old/new values are one instance's accepted resolved cache. This method
    /// changes only affected forwarding groups and returns physical slot changes.
    fn replace(
        &mut self,
        owner: Uuid,
        old: &BTreeSet<RouteKey>,
        next: &BTreeSet<RouteKey>,
    ) -> BTreeSet<OsRouteSlotKey> {
        let mut changed = BTreeSet::new();
        for removed in old.difference(next) {
            let forward = removed.forward();
            let group = self
                .sources
                .get_mut(&forward)
                .expect("accepted route must have a source group");
            let owners = group
                .metrics
                .get_mut(&removed.route.metric)
                .expect("accepted metric must exist");
            assert!(owners.remove(&owner));
            if owners.is_empty() {
                group.metrics.remove(&removed.route.metric);
            }
            let count = group
                .owners
                .get_mut(&owner)
                .expect("accepted owner must exist");
            *count = count
                .checked_sub(1)
                .expect("metric reference count underflow");
            if *count == 0 {
                group.owners.remove(&owner);
            }
            changed.insert(forward);
        }
        for added in next.difference(old) {
            let forward = added.forward();
            let group = self.sources.entry(forward.clone()).or_default();
            assert!(
                group
                    .metrics
                    .entry(added.route.metric)
                    .or_default()
                    .insert(owner)
            );
            let count = group.owners.entry(owner).or_default();
            *count = count
                .checked_add(1)
                .expect("metric reference count overflow");
            changed.insert(forward);
        }
        let mut slots = BTreeSet::new();
        for forward in changed {
            let before = self.aggregates.remove(&forward);
            let group = self.sources.get(&forward).unwrap();
            let after = group
                .metrics
                .first_key_value()
                .map(|(metric, _)| forward.route(*metric));
            if before == after {
                // A higher metric changed without altering the physical route.
                // Update membership only; unchanged membership needs no OS work.
                if let Some(after) = &after {
                    let members = self
                        .slots
                        .get_mut(&after.route.slot())
                        .unwrap()
                        .get_mut(after)
                        .unwrap();
                    let membership_changed = if group.owners.contains_key(&owner) {
                        members.insert(owner)
                    } else {
                        members.remove(&owner)
                    };
                    if membership_changed {
                        slots.insert(after.route.slot());
                    }
                }
            } else {
                if let Some(before) = &before {
                    let slot = before.route.slot();
                    let candidates = self.slots.get_mut(&slot).unwrap();
                    candidates.remove(before);
                    if candidates.is_empty() {
                        self.slots.remove(&slot);
                    }
                    slots.insert(slot);
                }
                if let Some(after) = &after {
                    let slot = after.route.slot();
                    self.slots
                        .entry(slot.clone())
                        .or_default()
                        .insert(after.clone(), group.owners.keys().copied().collect());
                    slots.insert(slot);
                }
            }
            if let Some(after) = after {
                self.aggregates.insert(forward, after);
            } else {
                self.sources.remove(&forward);
            }
        }
        slots
    }

    fn aggregate(&self, requested: &RouteKey) -> Option<&RouteKey> {
        self.aggregates.get(&requested.forward())
    }

    fn candidates(&self, slot: &OsRouteSlotKey) -> Option<&BTreeMap<RouteKey, BTreeSet<Uuid>>> {
        self.slots.get(slot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(index: u32, nic: Uuid, epoch: DeviceEpoch, metric: u32) -> RouteKey {
        RouteKey {
            route: OsRoute {
                table: 254,
                destination: "198.18.0.0/24".parse().unwrap(),
                ifindex: index,
                metric: NonZeroU32::new(metric).unwrap(),
                preferred_source: None,
            },
            nic,
            epoch,
        }
    }

    #[test]
    fn shared_forwarding_uses_lowest_metric_and_updates_only_real_slot_changes() {
        let mut desired = DesiredIndex::default();
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let nic = Uuid::from_u128(3);
        let epoch = DeviceEpoch::new();
        let a_route = route(7, nic, epoch, 200);
        let b_route = route(7, nic, epoch, 100);
        desired.replace(a, &BTreeSet::new(), &BTreeSet::from([a_route.clone()]));
        let changed = desired.replace(b, &BTreeSet::new(), &BTreeSet::from([b_route.clone()]));
        assert_eq!(
            changed,
            BTreeSet::from([a_route.route.slot(), b_route.route.slot()])
        );
        assert_eq!(desired.aggregate(&a_route), Some(&b_route));
        assert_eq!(desired.slots.len(), 1);
        assert_eq!(
            desired.candidates(&b_route.route.slot()).unwrap()[&b_route],
            BTreeSet::from([a, b])
        );
        let higher = route(7, nic, epoch, 300);
        assert!(
            desired
                .replace(
                    a,
                    &BTreeSet::from([a_route]),
                    &BTreeSet::from([higher.clone()])
                )
                .is_empty()
        );
        assert_eq!(desired.aggregate(&higher), Some(&b_route));
        desired.replace(b, &BTreeSet::from([b_route]), &BTreeSet::new());
        assert_eq!(desired.aggregate(&higher), Some(&higher));
        desired.replace(a, &BTreeSet::from([higher]), &BTreeSet::new());
        assert!(desired.sources.is_empty());
        assert!(desired.aggregates.is_empty());
        assert!(desired.slots.is_empty());
    }

    #[test]
    fn one_owner_can_have_multiple_metrics_without_losing_membership() {
        let mut desired = DesiredIndex::default();
        let owner = Uuid::from_u128(1);
        let nic = Uuid::from_u128(3);
        let epoch = DeviceEpoch::new();
        let low = route(7, nic, epoch, 100);
        let high = route(7, nic, epoch, 200);
        let both = BTreeSet::from([low.clone(), high.clone()]);
        desired.replace(owner, &BTreeSet::new(), &both);
        desired.replace(owner, &both, &BTreeSet::from([low.clone()]));
        assert_eq!(
            desired.candidates(&low.route.slot()).unwrap()[&low],
            BTreeSet::from([owner])
        );
        desired.replace(owner, &BTreeSet::from([low]), &BTreeSet::new());
        assert!(desired.slots.is_empty());
        assert!(desired.sources.is_empty());
    }

    #[test]
    fn different_tuns_sources_tables_and_device_epochs_are_never_merged() {
        let mut desired = DesiredIndex::default();
        let nic = Uuid::from_u128(3);
        let first = route(7, nic, DeviceEpoch::new(), 100);
        let mut others = vec![
            route(8, Uuid::from_u128(4), DeviceEpoch::new(), 200),
            route(7, nic, DeviceEpoch::new(), 100),
            first.clone(),
            first.clone(),
        ];
        others[2].route.preferred_source = Some("192.0.2.1".parse().unwrap());
        others[3].route.table = 501;
        desired.replace(
            Uuid::from_u128(10),
            &BTreeSet::new(),
            &BTreeSet::from([first.clone()]),
        );
        for (index, other) in others.iter().enumerate() {
            desired.replace(
                Uuid::from_u128(11 + index as u128),
                &BTreeSet::new(),
                &BTreeSet::from([other.clone()]),
            );
            assert_eq!(desired.aggregate(other), Some(other));
        }
        assert_eq!(desired.aggregates.len(), 5);
        assert_eq!(
            desired.candidates(&first.route.slot()).unwrap().len(),
            3,
            "same Linux slot still needs explicit conflict arbitration"
        );
        let changed = desired.replace(
            Uuid::from_u128(11),
            &BTreeSet::from([others[0].clone()]),
            &BTreeSet::new(),
        );
        assert_eq!(changed, BTreeSet::from([others[0].route.slot()]));
        assert_eq!(desired.aggregate(&first), Some(&first));
    }
}

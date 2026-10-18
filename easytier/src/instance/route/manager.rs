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

#[cfg(feature = "tun")]
#[path = "controller.rs"]
mod controller;
#[cfg(feature = "tun")]
pub(crate) use controller::RouteController;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Add,
    Remove,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EffectPhase {
    Owned,
    External,
    Unknown {
        operation: Mutation,
        reason: std::sync::Arc<str>,
    },
}

#[derive(Clone, Debug)]
struct Effect {
    key: RouteKey,
    phase: EffectPhase,
    owners: BTreeSet<Uuid>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum SlotStatus {
    #[default]
    Pending,
    Ready(RouteKey),
    Conflict,
    Failed(std::sync::Arc<str>),
}

#[derive(Default)]
struct SlotState {
    accepted: Option<RouteKey>,
    effect: Option<Effect>,
    probe: Option<RouteKey>,
    status: SlotStatus,
    retry: Option<(u32, tokio::time::Instant)>,
}

impl SlotState {
    fn retry(&mut self) {
        let attempts = self
            .retry
            .map_or(1, |(attempts, _)| attempts.saturating_add(1));
        let millis = (100_u64 << attempts.saturating_sub(1).min(6)).min(5000);
        self.retry = Some((
            attempts,
            tokio::time::Instant::now() + std::time::Duration::from_millis(millis),
        ));
    }
    fn due(&self, now: tokio::time::Instant) -> bool {
        self.retry.is_none_or(|(_, deadline)| deadline <= now)
    }
}

/// One native writer's private state. All effect records stay in this object
/// across awaits. A supervisor may retain it after the drive future panics.
struct Worker<B> {
    backend: Option<B>,
    desired: DesiredIndex,
    slots: BTreeMap<OsRouteSlotKey, SlotState>,
    pending: BTreeSet<OsRouteSlotKey>,
    inspections: BTreeSet<OsRouteSlotKey>,
    responsibility_index: BTreeMap<Uuid, BTreeSet<OsRouteSlotKey>>,
}

impl<B: super::RouteBackend> Worker<B> {
    fn new(backend: B) -> Self {
        Self {
            backend: Some(backend),
            desired: DesiredIndex::default(),
            slots: BTreeMap::new(),
            pending: BTreeSet::new(),
            inspections: BTreeSet::new(),
            responsibility_index: BTreeMap::new(),
        }
    }

    fn replace_routes(
        &mut self,
        owner: Uuid,
        old: &BTreeSet<RouteKey>,
        next: &BTreeSet<RouteKey>,
    ) -> BTreeSet<OsRouteSlotKey> {
        let changed = self.desired.replace(owner, old, next);
        for key in &changed {
            if self.desired.candidates(key).is_none()
                && self.slots.get(key).is_none_or(|slot| {
                    slot.effect
                        .as_ref()
                        .is_none_or(|effect| matches!(effect.phase, EffectPhase::External))
                })
            {
                // No mutation or observation is required to forget an obsolete
                // External probe. It never granted responsibility to begin with.
                self.slots.remove(key);
                self.pending.remove(key);
                self.inspections.remove(key);
                continue;
            }
            let slot = self.slots.entry(key.clone()).or_default();
            slot.status = SlotStatus::Pending;
            slot.retry = None;
            self.pending.insert(key.clone());
        }
        changed
    }

    fn invalidate(&mut self, key: &OsRouteSlotKey) {
        if let Some(slot) = self.slots.get_mut(key) {
            slot.status = SlotStatus::Pending;
            slot.retry = None;
            self.inspections.insert(key.clone());
        }
    }

    fn lose_ownership(&mut self, key: &OsRouteSlotKey) {
        if let Some(effect) = self
            .slots
            .get_mut(key)
            .and_then(|slot| slot.effect.as_mut())
        {
            if matches!(effect.phase, EffectPhase::Owned) {
                effect.phase = EffectPhase::Unknown {
                    operation: Mutation::Add,
                    reason:
                        "external route mutation or observation loss broke ownership continuity"
                            .into(),
                };
            }
        }
        self.invalidate(key);
    }

    fn next_pending(&self, now: tokio::time::Instant) -> Option<OsRouteSlotKey> {
        self.pending
            .iter()
            .find(|key| {
                !self.inspections.contains(*key)
                    && self.slots.get(*key).is_some_and(|slot| slot.due(now))
            })
            .cloned()
    }

    fn has_due_inspections(&self, now: tokio::time::Instant) -> bool {
        self.inspections
            .iter()
            .any(|key| self.slots.get(key).is_some_and(|slot| slot.due(now)))
    }

    fn effect_owners(&self, key: &OsRouteSlotKey) -> BTreeSet<Uuid> {
        self.slots
            .get(key)
            .and_then(|slot| slot.effect.as_ref())
            .filter(|effect| !matches!(effect.phase, EffectPhase::External))
            .map(|effect| effect.owners.clone())
            .unwrap_or_default()
    }

    fn index_responsibility(&mut self, key: &OsRouteSlotKey, before: &BTreeSet<Uuid>) {
        let after = self.effect_owners(key);
        for owner in before.difference(&after) {
            let slots = self
                .responsibility_index
                .get_mut(owner)
                .expect("effect responsibility must be indexed");
            slots.remove(key);
            if slots.is_empty() {
                self.responsibility_index.remove(owner);
            }
        }
        for owner in after.difference(before) {
            self.responsibility_index
                .entry(*owner)
                .or_default()
                .insert(key.clone());
        }
    }

    fn has_responsibility(&self, owner: Uuid) -> bool {
        self.responsibility_index.contains_key(&owner)
    }

    fn next_retry(&self) -> Option<tokio::time::Instant> {
        self.pending
            .iter()
            .chain(&self.inspections)
            .filter_map(|key| self.slots.get(key)?.retry.map(|(_, deadline)| deadline))
            .min()
    }

    /// One batch is all-or-error; partial family dumps never settle absence.
    async fn inspect(&mut self) -> (BTreeSet<OsRouteSlotKey>, bool) {
        let keys = self
            .inspections
            .iter()
            .filter(|key| {
                self.slots
                    .get(*key)
                    .is_some_and(|slot| slot.due(tokio::time::Instant::now()))
            })
            .map(|key| (key.clone(), self.effect_owners(key)))
            .collect::<BTreeMap<_, _>>();
        let changed = self.inspect_inner(&keys.keys().cloned().collect()).await;
        for (key, before) in keys {
            self.index_responsibility(&key, &before);
        }
        changed
    }

    async fn inspect_inner(
        &mut self,
        selected: &BTreeSet<OsRouteSlotKey>,
    ) -> (BTreeSet<OsRouteSlotKey>, bool) {
        let keys = selected.clone();
        let requested = keys
            .iter()
            .filter_map(|key| {
                let slot = &self.slots[key];
                slot.effect
                    .as_ref()
                    .map(|effect| effect.key.route.clone())
                    .or_else(|| slot.probe.as_ref().map(|key| key.route.clone()))
            })
            .collect::<BTreeSet<_>>();
        let result = if requested.is_empty() {
            Ok(BTreeSet::new())
        } else {
            self.backend
                .as_mut()
                .expect("running route backend")
                .existing(&requested)
                .await
        };
        let complete = result.is_ok();
        for key in &keys {
            let slot = self.slots.get_mut(key).unwrap();
            match &result {
                Err(error) => {
                    slot.status = SlotStatus::Failed(error.to_string().into());
                    slot.retry();
                }
                Ok(existing) => {
                    self.inspections.remove(key);
                    if let Some(effect) = &slot.effect {
                        if !existing.contains(&effect.key.route) {
                            slot.effect = None;
                            slot.retry = None;
                        } else if matches!(effect.phase, EffectPhase::Unknown { .. }) {
                            // Presence cannot tell whether our uncertain add
                            // created this route or an external writer did.
                            slot.retry();
                            slot.status = SlotStatus::Pending;
                            self.inspections.insert(key.clone());
                            continue;
                        }
                    } else if let Some(probe) = slot.probe.take() {
                        if existing.contains(&probe.route) {
                            slot.accepted = Some(probe.clone());
                            let owners = self
                                .desired
                                .candidates(key)
                                .and_then(|candidates| candidates.get(&probe))
                                .cloned()
                                .unwrap_or_default();
                            slot.effect = Some(Effect {
                                key: probe,
                                phase: EffectPhase::External,
                                owners,
                            });
                            slot.retry = None;
                        } else {
                            // EEXIST may have named a different route in this
                            // slot. Reattempt exclusive creation only on a
                            // bounded retry or a fresh OS/input invalidation.
                            slot.status = SlotStatus::Conflict;
                            slot.retry();
                        }
                    } else {
                        slot.retry = None;
                    }
                    self.pending.insert(key.clone());
                }
            }
        }
        (keys, complete)
    }

    /// At most one mutation. The outer controller rechecks dirty/close and
    /// input eligibility between these calls, after the actual result is saved.
    async fn advance(&mut self, key: &OsRouteSlotKey) -> bool {
        let before = self.effect_owners(key);
        let mutated = self.advance_inner(key).await;
        self.index_responsibility(key, &before);
        mutated
    }

    async fn advance_inner(&mut self, key: &OsRouteSlotKey) -> bool {
        use super::RouteError;
        self.pending.remove(key);
        let candidates = self.desired.candidates(key);
        let slot = self.slots.get_mut(key).unwrap();
        // Only a confirmed occupancy establishes priority. A failed first
        // attempt must not reserve this slot against a later competing source.
        if !slot.accepted.as_ref().is_some_and(|accepted| {
            candidates.is_some_and(|candidates| candidates.contains_key(accepted))
        }) {
            slot.accepted = slot
                .effect
                .as_ref()
                .filter(|effect| {
                    matches!(effect.phase, EffectPhase::Owned | EffectPhase::External)
                        && candidates.is_some_and(|candidates| candidates.contains_key(&effect.key))
                })
                .map(|effect| effect.key.clone());
        }
        let selected = slot.accepted.clone().or_else(|| {
            candidates
                .filter(|candidates| candidates.len() == 1)
                .and_then(|candidates| candidates.keys().next().cloned())
        });
        if slot
            .probe
            .as_ref()
            .is_some_and(|probe| Some(probe) != selected.as_ref())
        {
            slot.probe = None;
        }
        if slot.effect.as_ref().is_some_and(|effect| {
            matches!(effect.phase, EffectPhase::External) && Some(&effect.key) != selected.as_ref()
        }) {
            slot.effect = None; // External effects never grant deletion rights.
        }
        if let Some(effect) = &mut slot.effect {
            match &effect.phase {
                EffectPhase::Unknown { .. } => {
                    self.inspections.insert(key.clone());
                    slot.status = SlotStatus::Pending;
                    return false;
                }
                EffectPhase::Owned | EffectPhase::External
                    if Some(&effect.key) == selected.as_ref() =>
                {
                    effect.owners = candidates.unwrap()[&effect.key].clone();
                    slot.status = SlotStatus::Ready(effect.key.clone());
                    slot.retry = None;
                    return false;
                }
                EffectPhase::Owned => {
                    let route = effect.key.route.clone();
                    effect.phase = EffectPhase::Unknown {
                        operation: Mutation::Remove,
                        reason: "request in flight".into(),
                    };
                    slot.status = SlotStatus::Pending;
                    // The record above remains inside the retained worker if
                    // the future panics or is destroyed during this await.
                    match self
                        .backend
                        .as_mut()
                        .expect("running route backend")
                        .remove(&route)
                        .await
                    {
                        Ok(()) => {
                            slot.effect = None;
                            slot.retry = None;
                            self.pending.insert(key.clone());
                        }
                        Err(RouteError::Unknown(error)) => {
                            slot.effect.as_mut().unwrap().phase = EffectPhase::Unknown {
                                operation: Mutation::Remove,
                                reason: error.to_string().into(),
                            };
                            slot.retry();
                            self.inspections.insert(key.clone());
                        }
                        Err(error) => {
                            slot.effect.as_mut().unwrap().phase = EffectPhase::Owned;
                            slot.status = SlotStatus::Failed(error.to_string().into());
                            slot.retry();
                            if error.is_errno(nix::libc::ESRCH) || error.is_errno(nix::libc::ENOENT)
                            {
                                self.inspections.insert(key.clone());
                            } else {
                                self.pending.insert(key.clone());
                            }
                        }
                    }
                    return true;
                }
                EffectPhase::External => unreachable!("obsolete external effect was discarded"),
            }
        }
        if slot.probe.is_some() {
            self.inspections.insert(key.clone());
            return false;
        }
        let Some(accepted) = selected else {
            slot.status = if candidates.is_some_and(|candidates| candidates.len() > 1) {
                SlotStatus::Conflict
            } else {
                SlotStatus::Pending
            };
            if candidates.is_none() {
                self.slots.remove(key);
                self.inspections.remove(key);
            }
            return false;
        };
        let owners = candidates.unwrap()[&accepted].clone();
        slot.effect = Some(Effect {
            key: accepted.clone(),
            phase: EffectPhase::Unknown {
                operation: Mutation::Add,
                reason: "request in flight".into(),
            },
            owners,
        });
        slot.status = SlotStatus::Pending;
        match self
            .backend
            .as_mut()
            .expect("running route backend")
            .add(&accepted.route)
            .await
        {
            Ok(()) => {
                slot.accepted = Some(accepted.clone());
                slot.effect.as_mut().unwrap().phase = EffectPhase::Owned;
                slot.retry = None;
                self.pending.insert(key.clone());
            }
            Err(RouteError::Unknown(error)) => {
                slot.effect.as_mut().unwrap().phase = EffectPhase::Unknown {
                    operation: Mutation::Add,
                    reason: error.to_string().into(),
                };
                slot.retry();
                self.inspections.insert(key.clone());
            }
            Err(error) => {
                slot.effect = None;
                if error.is_errno(nix::libc::EEXIST) {
                    slot.probe = Some(accepted);
                    // An elapsed retry remains eligible for immediate
                    // inspection; retain attempts so a persistent conflict
                    // backs off instead of resetting to 100ms every time.
                    self.inspections.insert(key.clone());
                } else {
                    slot.status = SlotStatus::Failed(error.to_string().into());
                    slot.retry();
                    self.pending.insert(key.clone());
                }
            }
        }
        true
    }

    fn status(&self, requested: &RouteKey) -> SlotStatus {
        let Some(aggregate) = self.desired.aggregate(requested) else {
            return SlotStatus::Pending;
        };
        match self
            .slots
            .get(&aggregate.route.slot())
            .map(|slot| &slot.status)
        {
            Some(SlotStatus::Ready(ready)) if ready == aggregate => {
                SlotStatus::Ready(ready.clone())
            }
            Some(SlotStatus::Ready(_)) => SlotStatus::Conflict,
            Some(other) => other.clone(),
            None => SlotStatus::Pending,
        }
    }

    fn responsible_owners(&self) -> BTreeSet<Uuid> {
        self.slots
            .values()
            .filter_map(|slot| slot.effect.as_ref())
            .filter(|effect| !matches!(effect.phase, EffectPhase::External))
            .flat_map(|effect| effect.owners.iter().copied())
            .collect()
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
    #[derive(Clone, Debug)]
    enum Call {
        Add(OsRoute),
        Remove(OsRoute),
        Inspect,
    }
    enum Directive {
        UnknownApplied,
        PanicAfterApply,
    }
    #[derive(Default)]
    struct MockState {
        routes: BTreeSet<OsRoute>,
        calls: Vec<Call>,
        directives: std::collections::VecDeque<Directive>,
        query_failed: bool,
    }
    #[derive(Clone, Default)]
    struct MockBackend(std::sync::Arc<std::sync::Mutex<MockState>>);

    impl super::super::RouteBackend for MockBackend {
        async fn add(&mut self, route: &OsRoute) -> Result<(), super::super::RouteError> {
            let mut state = self.0.lock().unwrap();
            state.calls.push(Call::Add(route.clone()));
            let directive = state.directives.pop_front();
            if state
                .routes
                .iter()
                .any(|existing| existing.slot() == route.slot())
            {
                return Err(super::super::RouteError::Failed(
                    std::io::Error::from_raw_os_error(nix::libc::EEXIST).into(),
                ));
            }
            state.routes.insert(route.clone());
            match directive {
                Some(Directive::UnknownApplied) => Err(super::super::RouteError::Unknown(
                    anyhow::anyhow!("ACK lost"),
                )),
                Some(Directive::PanicAfterApply) => panic!("backend panic after mutation"),
                None => Ok(()),
            }
        }
        async fn remove(&mut self, route: &OsRoute) -> Result<(), super::super::RouteError> {
            let mut state = self.0.lock().unwrap();
            state.calls.push(Call::Remove(route.clone()));
            let directive = state.directives.pop_front();
            if !state.routes.remove(route) {
                return Err(super::super::RouteError::Failed(
                    std::io::Error::from_raw_os_error(nix::libc::ESRCH).into(),
                ));
            }
            match directive {
                Some(Directive::UnknownApplied) => Err(super::super::RouteError::Unknown(
                    anyhow::anyhow!("delete ACK lost"),
                )),
                Some(Directive::PanicAfterApply) => panic!("backend panic after delete"),
                None => Ok(()),
            }
        }
        async fn existing(
            &mut self,
            routes: &BTreeSet<OsRoute>,
        ) -> Result<BTreeSet<OsRoute>, super::super::RouteError> {
            let mut state = self.0.lock().unwrap();
            state.calls.push(Call::Inspect);
            if state.query_failed {
                return Err(super::super::RouteError::Failed(anyhow::anyhow!(
                    "dump interrupted"
                )));
            }
            Ok(state.routes.intersection(routes).cloned().collect())
        }
    }

    async fn settle(worker: &mut Worker<MockBackend>) {
        for _ in 0..100 {
            let now = tokio::time::Instant::now();
            if worker.has_due_inspections(now) {
                worker.inspect().await;
                continue;
            }
            let Some(key) = worker.next_pending(now) else {
                assert_eq!(
                    worker
                        .responsibility_index
                        .keys()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    worker.responsible_owners()
                );
                return;
            };
            worker.advance(&key).await;
        }
        panic!("worker did not reach a wait point");
    }

    fn single_route() -> (Uuid, RouteKey, BTreeSet<RouteKey>) {
        let owner = Uuid::from_u128(1);
        let key = route(7, Uuid::from_u128(3), DeviceEpoch::new(), 65535);
        (owner, key.clone(), BTreeSet::from([key]))
    }

    #[tokio::test]
    async fn owned_effect_handoffs_without_duplicate_mutation_and_cleans_after_last_owner() {
        let backend = MockBackend::default();
        let mut worker = Worker::new(backend.clone());
        let (a, key, routes) = single_route();
        let b = Uuid::from_u128(2);
        worker.replace_routes(a, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key.clone()));
        worker.replace_routes(b, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        worker.replace_routes(a, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        assert_eq!(worker.responsible_owners(), BTreeSet::from([b]));
        assert!(!worker.has_responsibility(a));
        assert!(worker.has_responsibility(b));
        assert_eq!(
            backend.0.lock().unwrap().calls.len(),
            1,
            "handoff must not rewrite the kernel route"
        );
        worker.replace_routes(b, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        let state = backend.0.lock().unwrap();
        assert!(state.routes.is_empty());
        assert!(
            matches!(&state.calls[..], [Call::Add(added), Call::Remove(removed)] if added == removed)
        );
        assert!(worker.slots.is_empty());
        assert!(worker.responsible_owners().is_empty());
    }

    #[tokio::test]
    async fn fresh_conflicts_have_no_map_order_winner_but_an_incumbent_is_preserved() {
        let (a, key, a_routes) = single_route();
        let b = Uuid::from_u128(2);
        let other = route(8, Uuid::from_u128(4), DeviceEpoch::new(), 65535);
        let b_routes = BTreeSet::from([other.clone()]);
        let backend = MockBackend::default();
        let mut fresh = Worker::new(backend.clone());
        fresh.replace_routes(a, &BTreeSet::new(), &a_routes);
        fresh.replace_routes(b, &BTreeSet::new(), &b_routes);
        settle(&mut fresh).await;
        assert_eq!(fresh.status(&key), SlotStatus::Conflict);
        assert_eq!(fresh.status(&other), SlotStatus::Conflict);
        assert!(backend.0.lock().unwrap().calls.is_empty());
        let mut occupied = Worker::new(backend.clone());
        occupied.replace_routes(a, &BTreeSet::new(), &a_routes);
        settle(&mut occupied).await;
        occupied.replace_routes(b, &BTreeSet::new(), &b_routes);
        settle(&mut occupied).await;
        assert_eq!(occupied.status(&key), SlotStatus::Ready(key.clone()));
        assert_eq!(occupied.status(&other), SlotStatus::Conflict);
        assert_eq!(backend.0.lock().unwrap().calls.len(), 1);
        occupied.replace_routes(a, &a_routes, &BTreeSet::new());
        settle(&mut occupied).await;
        assert_eq!(occupied.status(&other), SlotStatus::Ready(other.clone()));
        assert_eq!(occupied.responsible_owners(), BTreeSet::from([b]));
        assert!(
            matches!(&backend.0.lock().unwrap().calls[..], [Call::Add(_), Call::Remove(removed), Call::Add(added)] if removed == &key.route && added == &other.route)
        );
    }

    #[tokio::test]
    async fn an_unconfirmed_attempt_does_not_reserve_priority_against_a_new_candidate() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        backend.0.lock().unwrap().routes.insert(OsRoute {
            ifindex: 99,
            ..key.route.clone()
        });
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        assert!(worker.slots[&key.route.slot()].accepted.is_none());
        let other = route(8, Uuid::from_u128(4), DeviceEpoch::new(), 65535);
        let writes = backend.0.lock().unwrap().calls.len();
        worker.replace_routes(
            Uuid::from_u128(2),
            &BTreeSet::new(),
            &BTreeSet::from([other.clone()]),
        );
        settle(&mut worker).await;
        assert!(worker.slots[&key.route.slot()].accepted.is_none());
        assert_eq!(worker.status(&key), SlotStatus::Conflict);
        assert_eq!(worker.status(&other), SlotStatus::Conflict);
        assert_eq!(backend.0.lock().unwrap().calls.len(), writes);
    }

    #[tokio::test]
    async fn a_confirmed_occupancy_keeps_priority_during_external_deletion_and_repair() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        let other = route(8, Uuid::from_u128(4), DeviceEpoch::new(), 65535);
        worker.replace_routes(
            Uuid::from_u128(2),
            &BTreeSet::new(),
            &BTreeSet::from([other.clone()]),
        );
        settle(&mut worker).await;
        backend.0.lock().unwrap().routes.clear();
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key.clone()));
        assert_eq!(worker.status(&other), SlotStatus::Conflict);
        assert!(backend.0.lock().unwrap().routes.contains(&key.route));
    }

    #[tokio::test]
    async fn equivalent_external_route_is_ready_without_ever_gaining_delete_rights() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        backend.0.lock().unwrap().routes.insert(key.route.clone());
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key.clone()));
        assert!(worker.responsible_owners().is_empty());
        worker.replace_routes(owner, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        let state = backend.0.lock().unwrap();
        assert!(state.routes.contains(&key.route));
        assert!(
            !state
                .calls
                .iter()
                .any(|call| matches!(call, Call::Remove(_)))
        );
    }

    #[tokio::test]
    async fn a_known_owned_route_loses_delete_rights_after_foreign_identical_replacement() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key.clone()));
        // DELETE followed by an identical external CREATE leaves the same dump.
        worker.lose_ownership(&key.route.slot());
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Pending);
        worker.replace_routes(owner, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        assert!(worker.has_responsibility(owner));
        assert!(
            !backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| matches!(call, Call::Remove(_)))
        );
        backend.0.lock().unwrap().routes.clear();
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert!(!worker.has_responsibility(owner));
    }

    #[tokio::test]
    async fn an_external_route_disappearing_can_only_become_owned_after_a_fresh_ack() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        backend.0.lock().unwrap().routes.insert(key.route.clone());
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        backend.0.lock().unwrap().routes.clear();
        worker.invalidate(&key.route.slot());
        assert_eq!(worker.status(&key), SlotStatus::Pending);
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key.clone()));
        assert_eq!(worker.responsible_owners(), BTreeSet::from([owner]));
        worker.replace_routes(owner, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        assert!(backend.0.lock().unwrap().routes.is_empty());
        assert_eq!(
            backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Add(_)))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn non_equivalent_external_conflict_recovers_without_deleting_the_foreign_route() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        let foreign = OsRoute {
            ifindex: 8,
            ..key.route.clone()
        };
        backend.0.lock().unwrap().routes.insert(foreign.clone());
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Conflict);
        assert!(backend.0.lock().unwrap().routes.contains(&foreign));
        assert!(worker.responsible_owners().is_empty());
        backend.0.lock().unwrap().routes.remove(&foreign);
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key));
        assert!(
            !backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| matches!(call, Call::Remove(_)))
        );
    }

    #[tokio::test]
    async fn persistent_external_conflicts_increase_backoff_instead_of_busy_retrying() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        backend.0.lock().unwrap().routes.insert(OsRoute {
            ifindex: 8,
            ..key.route.clone()
        });
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        let slot = key.route.slot();
        assert_eq!(worker.slots[&slot].retry.unwrap().0, 1);
        assert!(worker.next_pending(tokio::time::Instant::now()).is_none());
        // Advance only this private retry deadline; no scheduling race/sleep.
        worker
            .slots
            .get_mut(&slot)
            .unwrap()
            .retry
            .as_mut()
            .unwrap()
            .1 = tokio::time::Instant::now();
        settle(&mut worker).await;
        assert_eq!(worker.slots[&slot].retry.unwrap().0, 2);
        assert!(worker.next_pending(tokio::time::Instant::now()).is_none());
        assert_eq!(worker.status(&key), SlotStatus::Conflict);
        assert_eq!(
            backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Add(_)))
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn unknown_add_presence_is_neither_owned_nor_ready_and_is_never_deleted() {
        let backend = MockBackend::default();
        backend
            .0
            .lock()
            .unwrap()
            .directives
            .push_back(Directive::UnknownApplied);
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Pending);
        assert!(matches!(
            worker.slots[&key.route.slot()]
                .effect
                .as_ref()
                .unwrap()
                .phase,
            EffectPhase::Unknown {
                operation: Mutation::Add,
                ..
            }
        ));
        worker.replace_routes(owner, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        assert_eq!(worker.responsible_owners(), BTreeSet::from([owner]));
        assert!(
            !backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|call| matches!(call, Call::Remove(_)))
        );
        backend.0.lock().unwrap().routes.clear();
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert!(worker.responsible_owners().is_empty());
        assert!(worker.slots.is_empty());
    }

    #[tokio::test]
    async fn unknown_delete_cannot_delete_an_identical_foreign_replacement() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        backend
            .0
            .lock()
            .unwrap()
            .directives
            .push_back(Directive::UnknownApplied);
        worker.replace_routes(owner, &routes, &BTreeSet::new());
        settle(&mut worker).await;
        assert_eq!(worker.responsible_owners(), BTreeSet::from([owner]));
        backend.0.lock().unwrap().routes.insert(key.route.clone());
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert!(matches!(
            worker.slots[&key.route.slot()]
                .effect
                .as_ref()
                .unwrap()
                .phase,
            EffectPhase::Unknown {
                operation: Mutation::Remove,
                ..
            }
        ));
        assert_eq!(
            backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Remove(_)))
                .count(),
            1
        );
        backend.0.lock().unwrap().routes.clear();
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert!(worker.responsible_owners().is_empty());
    }

    #[tokio::test]
    async fn failed_inspection_never_means_absent_and_never_replays_an_add() {
        let backend = MockBackend::default();
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend.clone());
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        settle(&mut worker).await;
        backend.0.lock().unwrap().query_failed = true;
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert!(matches!(worker.status(&key), SlotStatus::Failed(_)));
        assert_eq!(worker.responsible_owners(), BTreeSet::from([owner]));
        assert_eq!(
            backend
                .0
                .lock()
                .unwrap()
                .calls
                .iter()
                .filter(|call| matches!(call, Call::Add(_)))
                .count(),
            1
        );
        backend.0.lock().unwrap().query_failed = false;
        worker.invalidate(&key.route.slot());
        settle(&mut worker).await;
        assert_eq!(worker.status(&key), SlotStatus::Ready(key));
    }

    #[tokio::test]
    async fn backend_panic_keeps_the_inflight_record_in_the_retained_worker() {
        use futures::FutureExt;
        let backend = MockBackend::default();
        backend
            .0
            .lock()
            .unwrap()
            .directives
            .push_back(Directive::PanicAfterApply);
        let (owner, key, routes) = single_route();
        let mut worker = Worker::new(backend);
        worker.replace_routes(owner, &BTreeSet::new(), &routes);
        let result = std::panic::AssertUnwindSafe(worker.advance(&key.route.slot()))
            .catch_unwind()
            .await;
        assert!(result.is_err());
        let effect = worker.slots[&key.route.slot()].effect.as_ref().unwrap();
        assert_eq!(effect.key, key);
        assert!(matches!(
            effect.phase,
            EffectPhase::Unknown {
                operation: Mutation::Add,
                ..
            }
        ));
        assert_eq!(worker.responsible_owners(), BTreeSet::from([owner]));
    }
}

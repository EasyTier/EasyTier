//! One namespace's native controller, invalidation and input lifetimes.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

use easytier_core::host::route::{
    ClaimRouteStatus, DeviceEpoch, InstanceRouteStatus, InstanceRoutes, RouteClaimId, RouteDemand,
    RouteInputSnapshot, RouteInputs, RouteSet, RouteSpec,
};
use parking_lot::Mutex;
use tokio::{
    runtime::Handle,
    sync::{Mutex as AsyncMutex, Notify, watch},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::super::{
    OsRoute, OsRouteSlotKey, PlatformRouteBackend, RouteBackend,
    device::DeviceState,
    linux::{RouteChanges, RouteObserver},
    validate_tun_spec,
};
use super::{EffectPhase, RouteKey, SlotStatus, Worker};
use crate::{
    common::netns::PlatformNamespace,
    instance::shared_virtual_nic::{
        SharedVirtualNic, SharedVirtualNicMember, SharedVirtualNicRegistryKey,
    },
};

#[derive(Clone, Debug)]
enum Phase {
    Running,
    Stopped,
    Failed(Arc<str>),
}

#[derive(Default)]
struct Dirty {
    instances: BTreeSet<Uuid>,
    order: Vec<Uuid>,
    nics: BTreeSet<Uuid>,
    slots: BTreeSet<OsRouteSlotKey>,
    foreign: BTreeSet<OsRouteSlotKey>,
    verify_all: bool,
}
impl Dirty {
    fn input(&mut self, run: Uuid) {
        if self.instances.insert(run) {
            self.order.push(run);
        }
    }
    fn is_empty(&self) -> bool {
        self.instances.is_empty()
            && self.nics.is_empty()
            && self.slots.is_empty()
            && self.foreign.is_empty()
            && !self.verify_all
    }
}

#[derive(Clone)]
struct MemberBinding {
    nic: Weak<AsyncMutex<SharedVirtualNic>>,
    registration: Uuid,
}

#[derive(Clone)]
struct InputRef {
    inputs: Arc<RouteInputs>,
    nic: Uuid,
    member: Option<MemberBinding>,
    ready: Option<(Uuid, DeviceEpoch)>,
    abandoned: bool,
}

struct NicGroup {
    logical: SharedVirtualNicRegistryKey,
    device: Arc<DeviceState>,
    nic: Weak<AsyncMutex<SharedVirtualNic>>,
    members: BTreeSet<Uuid>,
    ifindices: BTreeSet<u32>,
    failure: Option<Arc<str>>,
}

struct Catalog {
    closing: bool,
    instances: BTreeMap<Uuid, InputRef>,
    groups: BTreeMap<Uuid, NicGroup>,
    logical: BTreeMap<SharedVirtualNicRegistryKey, Uuid>,
    slots: BTreeMap<OsRouteSlotKey, BTreeSet<Uuid>>,
    interfaces: BTreeMap<u32, BTreeSet<Uuid>>,
    observation: u64,
    connected: bool,
}

struct ControllerState {
    catalog: Mutex<Catalog>,
    dirty: Mutex<Dirty>,
    wake: Notify,
    phase: watch::Sender<Phase>,
    shared: Handle,
}

impl ControllerState {
    fn new(shared: Handle) -> Arc<Self> {
        Arc::new(Self {
            catalog: Mutex::new(Catalog {
                closing: false,
                instances: BTreeMap::new(),
                groups: BTreeMap::new(),
                logical: BTreeMap::new(),
                slots: BTreeMap::new(),
                interfaces: BTreeMap::new(),
                observation: 0,
                connected: true,
            }),
            dirty: Mutex::new(Dirty::default()),
            wake: Notify::new(),
            phase: watch::channel(Phase::Running).0,
            shared,
        })
    }

    fn mark_input(&self, run: Uuid) {
        self.dirty.lock().input(run);
        self.wake.notify_one();
    }
    fn mark_nic(&self, nic: Uuid) {
        self.dirty.lock().nics.insert(nic);
        self.wake.notify_one();
    }

    fn open(self: &Arc<Self>, run: Uuid, name: String) -> anyhow::Result<InstanceRoutes> {
        let mut catalog = self.catalog.lock();
        anyhow::ensure!(!catalog.closing, "route controller is closed");
        anyhow::ensure!(
            !catalog.instances.contains_key(&run),
            "instance run is already registered"
        );
        let logical = SharedVirtualNicRegistryKey::new(name, run);
        let nic = if let Some(nic) = catalog.logical.get(&logical) {
            *nic
        } else {
            let nic = Uuid::new_v4();
            let weak = Arc::downgrade(self);
            let device = DeviceState::new(Arc::new(move || {
                if let Some(state) = weak.upgrade() {
                    state.device_changed(nic);
                }
            }));
            catalog.logical.insert(logical.clone(), nic);
            catalog.groups.insert(
                nic,
                NicGroup {
                    logical,
                    device,
                    nic: Weak::new(),
                    members: BTreeSet::new(),
                    ifindices: BTreeSet::new(),
                    failure: None,
                },
            );
            nic
        };
        let weak = Arc::downgrade(self);
        let owner = InstanceRoutes::new(Arc::new(move || {
            if let Some(state) = weak.upgrade() {
                state.mark_input(run);
            }
        }));
        owner.bind_default_nic(nic)?;
        let device = catalog.groups[&nic].device.snapshot().selected;
        owner.inputs().set_default_device(nic, device)?;
        catalog.groups.get_mut(&nic).unwrap().members.insert(run);
        catalog.instances.insert(
            run,
            InputRef {
                inputs: owner.inputs(),
                nic,
                member: None,
                ready: None,
                abandoned: false,
            },
        );
        drop(catalog);
        self.mark_input(run);
        Ok(owner)
    }

    fn device_changed(&self, nic: Uuid) {
        let mut catalog = self.catalog.lock();
        let Some(group) = catalog.groups.get(&nic) else {
            return;
        };
        let facts = group.device.snapshot();
        let old_indices = group.ifindices.clone();
        let indices = facts
            .live
            .values()
            .map(|device| device.ifindex)
            .collect::<BTreeSet<_>>();
        let members = group.members.clone();
        for index in old_indices.difference(&indices) {
            if let Some(groups) = catalog.interfaces.get_mut(index) {
                groups.remove(&nic);
                if groups.is_empty() {
                    catalog.interfaces.remove(index);
                }
            }
        }
        for index in &indices {
            catalog.interfaces.entry(*index).or_default().insert(nic);
        }
        catalog.groups.get_mut(&nic).unwrap().ifindices = indices;
        for run in members {
            let input = &catalog.instances[&run];
            let _ = input.inputs.set_default_device(nic, facts.selected);
            input.inputs.invalidate();
        }
        drop(catalog);
        self.mark_nic(nic);
    }

    fn bind_member(&self, run: Uuid, member: &SharedVirtualNicMember) -> anyhow::Result<()> {
        let strong = member.shared_nic();
        let weak = Arc::downgrade(&strong);
        let registration = member.registration_id();
        let mut catalog = self.catalog.lock();
        anyhow::ensure!(!catalog.closing, "route controller is closed");
        let input = catalog
            .instances
            .get_mut(&run)
            .ok_or_else(|| anyhow::anyhow!("instance run is not registered"))?;
        anyhow::ensure!(!input.inputs.is_closed(), "instance routes are closing");
        let nic = input.nic;
        input.member = Some(MemberBinding {
            nic: weak.clone(),
            registration,
        });
        input.ready = None;
        input.inputs.invalidate();
        let group = catalog.groups.get_mut(&nic).unwrap();
        if !Weak::ptr_eq(&group.nic, &weak) {
            group.failure = None;
        }
        group.nic = weak;
        drop(catalog);
        self.mark_nic(nic);
        Ok(())
    }

    fn member_ready(
        &self,
        run: Uuid,
        registration: Uuid,
        epoch: DeviceEpoch,
    ) -> anyhow::Result<DeviceEpoch> {
        let mut catalog = self.catalog.lock();
        anyhow::ensure!(!catalog.closing, "route controller is closed");
        let input = catalog
            .instances
            .get(&run)
            .ok_or_else(|| anyhow::anyhow!("instance run is not registered"))?;
        anyhow::ensure!(!input.inputs.is_closed(), "instance routes are closing");
        let group = &catalog.groups[&input.nic];
        anyhow::ensure!(group.failure.is_none(), "NIC admission failed");
        anyhow::ensure!(
            input
                .member
                .as_ref()
                .is_some_and(|member| member.registration == registration
                    && Weak::ptr_eq(&member.nic, &group.nic)),
            "NIC member registration changed"
        );
        let nic = input.nic;
        let facts = group.device.snapshot();
        anyhow::ensure!(
            facts.selected == Some(epoch) && facts.ready,
            "physical device generation changed or is not ready"
        );
        let input = catalog.instances.get_mut(&run).unwrap();
        input.ready = Some((registration, epoch));
        input.inputs.invalidate();
        drop(catalog);
        self.mark_nic(nic);
        Ok(epoch)
    }

    fn member_unready(&self, run: Uuid, registration: Uuid) {
        let mut catalog = self.catalog.lock();
        let Some(input) = catalog.instances.get_mut(&run) else {
            return;
        };
        if !input
            .member
            .as_ref()
            .is_some_and(|member| member.registration == registration)
        {
            return;
        }
        let nic = input.nic;
        input.ready = None;
        input.inputs.invalidate();
        drop(catalog);
        self.mark_nic(nic);
    }

    fn observation_changed(&self, connected: bool) {
        let inputs = {
            let mut catalog = self.catalog.lock();
            catalog.observation = catalog
                .observation
                .checked_add(1)
                .expect("observation revision exhausted");
            catalog.connected = connected;
            catalog
                .instances
                .values()
                .map(|input| input.inputs.clone())
                .collect::<Vec<_>>()
        };
        for input in inputs {
            input.invalidate();
        }
        self.dirty.lock().verify_all = true;
        self.wake.notify_one();
    }

    fn os_changed(&self, changes: RouteChanges) {
        let (inputs, slots, nics, foreign) = {
            let catalog = self.catalog.lock();
            let foreign = changes
                .slots
                .into_iter()
                .filter(|slot| catalog.slots.contains_key(slot))
                .collect::<BTreeSet<_>>();
            let nics = changes
                .links
                .iter()
                .filter_map(|index| catalog.interfaces.get(index))
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>();
            let nic_runs = nics
                .iter()
                .filter_map(|nic| catalog.groups.get(nic))
                .flat_map(|group| group.members.iter().copied())
                .collect::<BTreeSet<_>>();
            let mut slots = foreign.clone();
            if !nic_runs.is_empty() {
                slots.extend(
                    catalog
                        .slots
                        .iter()
                        .filter(|(_, owners)| !owners.is_disjoint(&nic_runs))
                        .map(|(slot, _)| slot.clone()),
                );
            }
            let runs = slots
                .iter()
                .filter_map(|slot| catalog.slots.get(slot))
                .flatten()
                .copied()
                .chain(
                    nics.iter()
                        .filter_map(|nic| catalog.groups.get(nic))
                        .flat_map(|group| group.members.iter().copied()),
                )
                .collect::<BTreeSet<_>>();
            (
                runs.into_iter()
                    .filter_map(|run| {
                        catalog
                            .instances
                            .get(&run)
                            .map(|input| input.inputs.clone())
                    })
                    .collect::<Vec<_>>(),
                slots,
                nics,
                foreign,
            )
        };
        for input in inputs {
            input.invalidate();
        }
        let mut dirty = self.dirty.lock();
        dirty.slots.extend(slots);
        dirty.foreign.extend(foreign);
        dirty.nics.extend(nics);
        if !dirty.is_empty() {
            self.wake.notify_one();
        }
    }

    fn request_shutdown(&self) {
        let inputs = {
            let mut catalog = self.catalog.lock();
            catalog.closing = true;
            catalog
                .instances
                .values()
                .map(|input| input.inputs.clone())
                .collect::<Vec<_>>()
        };
        for input in inputs {
            input.close();
        }
        self.wake.notify_one();
    }

    fn abandon(&self, run: Uuid, reason: Arc<str>) {
        let input = {
            let mut catalog = self.catalog.lock();
            let Some(input) = catalog.instances.get_mut(&run) else {
                return;
            };
            input.abandoned = true;
            input.inputs.clone()
        };
        input.close();
        input.fail(reason);
        self.mark_input(run);
    }

    fn fail(&self, reason: Arc<str>) {
        let inputs = {
            let mut catalog = self.catalog.lock();
            catalog.closing = true;
            for group in catalog.groups.values_mut() {
                group.members.clear();
            }
            std::mem::take(&mut catalog.instances)
        };
        for (_, input) in inputs {
            input.inputs.fail(reason.clone());
        }
        self.phase.send_replace(Phase::Failed(reason));
    }

    async fn stopped(&self) -> anyhow::Result<()> {
        let mut phase = self.phase.subscribe();
        loop {
            match &*phase.borrow_and_update() {
                Phase::Stopped => return Ok(()),
                Phase::Failed(reason) => anyhow::bail!("{reason}"),
                Phase::Running => {}
            }
            phase
                .changed()
                .await
                .map_err(|_| anyhow::anyhow!("route controller disappeared"))?;
        }
    }
}

pub(crate) struct RouteController {
    state: Arc<ControllerState>,
    worker: Arc<AsyncMutex<Worker<PlatformRouteBackend>>>,
}

impl RouteController {
    pub(crate) fn new(namespace: PlatformNamespace, shared: Handle) -> anyhow::Result<Self> {
        // Constructors explicitly enter this executor for AsyncFd registration.
        let backend = PlatformRouteBackend::new(&namespace, &shared)?;
        let observer = RouteObserver::new(&namespace, &shared, Some(backend.request_origin()))?;
        let state = ControllerState::new(shared.clone());
        let worker = Arc::new(AsyncMutex::new(Worker::new(backend)));
        spawn_driver(
            state.clone(),
            worker.clone(),
            Some(observer),
            namespace,
            shared,
        );
        Ok(Self { state, worker })
    }
    pub(crate) fn open_instance(&self, run: Uuid, name: String) -> anyhow::Result<InstanceRoutes> {
        self.state.open(run, name)
    }
    pub(crate) fn ensure_instance_open(&self, run: Uuid) -> anyhow::Result<()> {
        let catalog = self.state.catalog.lock();
        anyhow::ensure!(
            !catalog.closing
                && catalog
                    .instances
                    .get(&run)
                    .is_some_and(|input| !input.inputs.is_closed()),
            "instance route capability is closed"
        );
        Ok(())
    }
    pub(crate) fn device(&self, run: Uuid) -> anyhow::Result<(Uuid, Arc<DeviceState>)> {
        let catalog = self.state.catalog.lock();
        let input = catalog
            .instances
            .get(&run)
            .ok_or_else(|| anyhow::anyhow!("instance run is not registered"))?;
        Ok((input.nic, catalog.groups[&input.nic].device.clone()))
    }
    pub(crate) fn bind_member(
        &self,
        run: Uuid,
        member: &SharedVirtualNicMember,
    ) -> anyhow::Result<()> {
        self.state.bind_member(run, member)
    }
    pub(crate) fn set_member_ready(
        &self,
        run: Uuid,
        registration: Uuid,
        epoch: DeviceEpoch,
    ) -> anyhow::Result<DeviceEpoch> {
        self.state.member_ready(run, registration, epoch)
    }
    pub(crate) fn set_member_unready(&self, run: Uuid, registration: Uuid) {
        self.state.member_unready(run, registration);
    }

    pub(crate) fn invalidate_instance_device(&self, run: Uuid) {
        let mut catalog = self.state.catalog.lock();
        let Some(input) = catalog.instances.get_mut(&run) else {
            return;
        };
        input.ready = None;
        input.inputs.invalidate();
        let nic = input.nic;
        drop(catalog);
        self.state.mark_nic(nic);
    }
    pub(crate) fn request_shutdown(&self) {
        self.state.request_shutdown();
    }
    pub(crate) fn abandon_instance(&self, run: Uuid, reason: Arc<str>) {
        self.state.abandon(run, reason);
    }
    pub(crate) async fn wait_stopped(&self) -> anyhow::Result<()> {
        if let Err(error) = self.state.stopped().await {
            let effects = self.unresolved().await;
            if !effects.is_empty() {
                return Err(error.context(format!(
                    "retained route effects (up to 16): {}",
                    effects.join("; ")
                )));
            }
            return Err(error);
        }
        Ok(())
    }
    pub(crate) async fn unresolved(&self) -> Vec<String> {
        let worker = self.worker.lock().await;
        worker
            .slots
            .values()
            .filter_map(|slot| slot.effect.as_ref())
            .filter(|effect| !matches!(effect.phase, EffectPhase::External))
            .take(16)
            .map(|effect| format!("{:?}: {:?}", effect.key, effect.phase))
            .collect()
    }
}

impl Drop for RouteController {
    fn drop(&mut self) {
        self.request_shutdown();
    }
}

struct DriverGuard<B> {
    state: Arc<ControllerState>,
    worker: Arc<AsyncMutex<Worker<B>>>,
    finished: bool,
}
impl<B> DriverGuard<B> {
    fn finish(mut self) {
        self.finished = true;
    }
}
impl<B> Drop for DriverGuard<B> {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(mut worker) = self.worker.try_lock() {
                worker.backend.take();
            }
            self.state
                .fail("route worker disappeared before completion".into());
        }
    }
}

// Caches retain publications and resolved metadata, never RouteInputs or the
// configuration store. The catalog is the only long-lived input owner.
#[derive(Default)]
struct ClaimProgress {
    rejected: Option<Arc<str>>,
    // Only non-ready routes participate in the aggregate; the first one
    // preserves deterministic route-order feedback without rescanning T.
    remaining: BTreeMap<RouteSpec, SlotStatus>,
}

struct CachedInput {
    snapshot: RouteInputSnapshot,
    accepted: RouteSet,
    publications: BTreeMap<easytier_core::host::route::RouteClaimId, Arc<RouteDemand>>,
    resolved: BTreeMap<RouteSpec, RouteKey>,
    indexed: BTreeSet<RouteKey>,
    rejected: Option<Arc<str>>,
    unsupported: BTreeMap<RouteSpec, Arc<str>>,
    fresh: bool,
    eligible: bool,
    withdrawn: bool,
    progress: BTreeMap<RouteClaimId, ClaimProgress>,
    slot_demands: BTreeMap<OsRouteSlotKey, Vec<(RouteClaimId, RouteSpec)>>,
    progress_dirty: bool,
    #[cfg(test)]
    status_reads: usize,
}

impl CachedInput {
    fn new(snapshot: RouteInputSnapshot) -> Self {
        Self {
            snapshot,
            accepted: RouteSet::new(),
            publications: BTreeMap::new(),
            resolved: BTreeMap::new(),
            indexed: BTreeSet::new(),
            rejected: None,
            unsupported: BTreeMap::new(),
            fresh: false,
            eligible: false,
            withdrawn: false,
            progress: BTreeMap::new(),
            slot_demands: BTreeMap::new(),
            progress_dirty: true,
            #[cfg(test)]
            status_reads: 0,
        }
    }
    fn same_source(&self, next: &RouteInputSnapshot) -> bool {
        self.snapshot.closed == next.closed
            && self.snapshot.device == next.device
            && self.snapshot.default_nic == next.default_nic
            && self.snapshot.config.is_some() == next.config.is_some()
            && match (&self.snapshot.config, &next.config) {
                (Some(old), Some(next)) => {
                    Arc::ptr_eq(old, next)
                        || old.services.manual_routes == next.services.manual_routes
                }
                (None, None) => true,
                _ => false,
            }
            && self.snapshot.claims.len() == next.claims.len()
            && self.snapshot.claims.iter().all(|(id, publication)| {
                next.claims
                    .get(id)
                    .is_some_and(|next| Arc::ptr_eq(publication, next))
            })
    }
    fn proposal(&mut self) -> RouteSet {
        self.unsupported.clear();
        if self.snapshot.closed || self.snapshot.config.is_none() {
            return RouteSet::new();
        }
        self.snapshot
            .effective_routes()
            .into_iter()
            .filter(|route| match validate_tun_spec(route) {
                Ok(_) => true,
                Err(error) => {
                    self.unsupported.insert(route.clone(), error.into());
                    false
                }
            })
            .collect()
    }
    fn update_progress<B: RouteBackend>(
        &mut self,
        worker: &Worker<B>,
        affected: &BTreeSet<OsRouteSlotKey>,
    ) {
        let demands = if self.progress_dirty {
            self.progress.clear();
            self.slot_demands.clear();
            self.progress_dirty = false;
            let mut demands = Vec::new();
            for (id, publication) in &self.snapshot.claims {
                self.progress.insert(*id, ClaimProgress::default());
                match publication.as_ref() {
                    RouteDemand::AutoProxy(prefixes) if !self.snapshot.auto_suppressed() => {
                        demands.extend(
                            prefixes
                                .iter()
                                .map(|prefix| (*id, RouteSpec::for_tun((*prefix).into()))),
                        );
                    }
                    RouteDemand::Additional(routes) => {
                        demands.extend(routes.iter().cloned().map(|route| (*id, route)))
                    }
                    _ => {}
                }
            }
            demands
        } else {
            // Remove first, then reinsert according to the current aggregate.
            // Another owner changing the minimum metric can move a dependency
            // to a different slot without changing this claim's publication.
            affected
                .iter()
                .filter_map(|slot| self.slot_demands.remove(slot))
                .flatten()
                .collect()
        };
        for (id, spec) in demands {
            #[cfg(test)]
            {
                self.status_reads += 1;
            }
            let progress = self
                .progress
                .get_mut(&id)
                .expect("claim progress is initialized");
            if let Some(error) = self.unsupported.get(&spec) {
                progress.rejected.get_or_insert_with(|| error.clone());
            }
            let resolved = self.resolved.get(&spec);
            let status = resolved.map_or(SlotStatus::Pending, |route| worker.status(route));
            match status {
                SlotStatus::Ready(_) => {
                    progress.remaining.remove(&spec);
                }
                status => {
                    progress.remaining.insert(spec.clone(), status);
                }
            }
            if let Some(route) = resolved {
                let physical = worker.desired.aggregate(route).unwrap_or(route);
                self.slot_demands
                    .entry(physical.route.slot())
                    .or_default()
                    .push((id, spec));
            }
        }
    }

    fn status(
        &self,
        id: RouteClaimId,
        demand: &Arc<RouteDemand>,
        observed: bool,
    ) -> ClaimRouteStatus {
        if matches!(demand.as_ref(), RouteDemand::AutoProxy(_)) && self.snapshot.auto_suppressed() {
            return ClaimRouteStatus::Suppressed;
        }
        let Some(progress) = self.progress.get(&id) else {
            return ClaimRouteStatus::Pending;
        };
        if let Some(error) = &progress.rejected {
            return ClaimRouteStatus::Rejected(error.clone());
        }
        if self.snapshot.config.is_none() || !self.fresh {
            return ClaimRouteStatus::Pending;
        }
        if matches!(demand.as_ref(), RouteDemand::Additional(routes) if routes.is_empty()) {
            return ClaimRouteStatus::Ready;
        }
        if !self.eligible || !observed {
            return ClaimRouteStatus::Pending;
        }
        if !self
            .publications
            .get(&id)
            .is_some_and(|old| Arc::ptr_eq(old, demand))
        {
            return self
                .rejected
                .clone()
                .map(ClaimRouteStatus::Rejected)
                .unwrap_or(ClaimRouteStatus::Pending);
        }
        match progress
            .remaining
            .first_key_value()
            .map(|(_, status)| status)
        {
            None => ClaimRouteStatus::Ready,
            Some(SlotStatus::Conflict) => ClaimRouteStatus::Rejected(
                "incompatible route occupies the Linux route slot".into(),
            ),
            Some(SlotStatus::Failed(error)) => ClaimRouteStatus::Failed(error.clone()),
            _ => ClaimRouteStatus::Pending,
        }
    }
}

struct GroupView {
    device: Arc<DeviceState>,
    nic: Weak<AsyncMutex<SharedVirtualNic>>,
    members: Vec<(Uuid, InputRef)>,
    failure: Option<Arc<str>>,
}

impl ControllerState {
    fn group(&self, id: Uuid) -> Option<GroupView> {
        let catalog = self.catalog.lock();
        let group = catalog.groups.get(&id)?;
        Some(GroupView {
            device: group.device.clone(),
            nic: group.nic.clone(),
            members: group
                .members
                .iter()
                .filter_map(|run| {
                    catalog
                        .instances
                        .get(run)
                        .cloned()
                        .map(|input| (*run, input))
                })
                .collect(),
            failure: group.failure.clone(),
        })
    }
    fn sync_slots<B: RouteBackend>(&self, worker: &Worker<B>, changed: &BTreeSet<OsRouteSlotKey>) {
        let mut catalog = self.catalog.lock();
        for key in changed {
            let mut owners = worker
                .desired
                .candidates(key)
                .into_iter()
                .flat_map(|candidates| candidates.values())
                .flatten()
                .copied()
                .collect::<BTreeSet<_>>();
            owners.extend(worker.effect_owners(key));
            if owners.is_empty() {
                catalog.slots.remove(key);
            } else {
                catalog.slots.insert(key.clone(), owners);
            }
        }
    }
    fn current(&self, run: Uuid, cache: &CachedInput) -> bool {
        let catalog = self.catalog.lock();
        catalog
            .instances
            .get(&run)
            .is_some_and(|input| input.inputs.is_current(&cache.snapshot))
    }
    fn can_advance<B: RouteBackend>(
        &self,
        worker: &Worker<B>,
        key: &OsRouteSlotKey,
        caches: &BTreeMap<Uuid, CachedInput>,
    ) -> bool {
        let owners = worker
            .desired
            .candidates(key)
            .into_iter()
            .flat_map(|candidates| candidates.values())
            .flatten()
            .copied()
            .chain(worker.effect_owners(key))
            .collect::<BTreeSet<_>>();
        owners.into_iter().all(|run| {
            caches
                .get(&run)
                .is_none_or(|cache| cache.fresh && self.current(run, cache))
        })
    }
    fn retire(&self, run: Uuid) -> Option<Uuid> {
        let input = {
            let mut catalog = self.catalog.lock();
            let Some(input) = catalog.instances.remove(&run) else {
                return None;
            };
            catalog
                .groups
                .get_mut(&input.nic)
                .unwrap()
                .members
                .remove(&run);
            input
        };
        // ConfigStore and its values are released outside the catalog lock.
        let nic = input.nic;
        drop(input);
        let mut dirty = self.dirty.lock();
        dirty.instances.remove(&run);
        dirty.order.retain(|id| *id != run);
        Some(nic)
    }

    fn compact_group<B: RouteBackend>(&self, nic: Uuid, worker: &Worker<B>) {
        let retired = {
            let mut catalog = self.catalog.lock();
            let Some(group) = catalog.groups.get(&nic) else {
                return;
            };
            let pending = worker
                .slots
                .values()
                .filter_map(|slot| slot.effect.as_ref())
                .filter(|effect| {
                    effect.key.nic == nic && !matches!(effect.phase, EffectPhase::External)
                })
                .map(|effect| effect.key.epoch)
                .collect();
            group.device.retain_releases(&pending);
            if !group.members.is_empty()
                || !group.device.snapshot().live.is_empty()
                || worker.slots.values().any(|slot| {
                    slot.effect
                        .as_ref()
                        .is_some_and(|effect| effect.key.nic == nic)
                })
            {
                return;
            }
            if let Some(physical) = group.nic.upgrade() {
                // A valid cached physical entry may still be reused. Weak
                // references or an empty input set do not prove retirement.
                if !physical
                    .try_lock()
                    .is_ok_and(|physical| !physical.is_valid())
                {
                    return;
                }
            }
            let group = catalog.groups.remove(&nic).unwrap();
            catalog.logical.remove(&group.logical);
            for index in &group.ifindices {
                if let Some(groups) = catalog.interfaces.get_mut(index) {
                    groups.remove(&nic);
                    if groups.is_empty() {
                        catalog.interfaces.remove(index);
                    }
                }
            }
            group
        };
        drop(retired);
    }
}

// This operates only on the shared NIC's admission/dispatcher state. The
// temporary NIC strong reference and lock are dropped before backend awaits.
async fn refresh_group(
    state: &Arc<ControllerState>,
    id: Uuid,
    order: &[Uuid],
    caches: &mut BTreeMap<Uuid, CachedInput>,
) -> bool {
    let Some(group) = state.group(id) else {
        return true;
    };
    for (run, input) in &group.members {
        let snapshot = input.inputs.snapshot();
        if let Some(cache) = caches.get_mut(run) {
            cache.snapshot = snapshot;
            cache.fresh = false;
        } else {
            caches.insert(*run, CachedInput::new(snapshot));
        }
    }
    let facts = group.device.snapshot();
    let Some(nic) = group.nic.upgrade() else {
        for (run, _) in &group.members {
            let cache = caches.get_mut(run).unwrap();
            cache.accepted.clear();
            cache.resolved.clear();
            cache.publications.clear();
            cache.eligible = false;
            cache.withdrawn = true;
            cache.fresh = true;
            cache.proposal();
        }
        return true;
    };
    let Ok(mut nic_guard) = nic.try_lock() else {
        return false;
    };
    let valid = nic_guard.is_valid() && group.failure.is_none();
    for (run, input) in &group.members {
        let cache = caches.get_mut(run).unwrap();
        cache.eligible = valid
            && input.member.as_ref().is_some_and(|member| {
                Weak::ptr_eq(&member.nic, &group.nic)
                    && Some(member.registration) == nic_guard.current_registration(*run)
                    && facts.ready
                    && facts
                        .selected
                        .is_some_and(|epoch| input.ready == Some((member.registration, epoch)))
            });
    }
    let mut admission_changed = false;
    let mut processing = group.members.iter().collect::<Vec<_>>();
    // Every withdrawal is applied before new proposals. Within a physical NIC
    // proposals retain input arrival order, rather than UUID/map order.
    processing.sort_by_key(|(run, _)| {
        (
            !caches[run].snapshot.closed
                && caches[run].eligible
                && !caches[run].snapshot.effective_routes().is_empty(),
            order.iter().position(|id| id == run).unwrap_or(usize::MAX),
        )
    });
    for (run, input) in processing {
        let cache = caches.get_mut(run).unwrap();
        let same_entry = input
            .member
            .as_ref()
            .is_some_and(|member| Weak::ptr_eq(&member.nic, &group.nic));
        let registration = input.member.as_ref().map(|member| member.registration);
        let proposal = cache.proposal();
        if !input.inputs.is_current(&cache.snapshot) {
            state.mark_input(*run);
            continue;
        }
        let desired = if cache.eligible && !cache.snapshot.closed {
            proposal
        } else {
            RouteSet::new()
        };
        // Closing the unique run authority may withdraw even if setup replaced
        // its registration immediately before seeing close. Active stale setup
        // is never allowed to mutate a newer registration.
        let actual = if cache.snapshot.closed {
            nic_guard.current_registration(*run)
        } else if same_entry {
            registration
                .filter(|registration| Some(*registration) == nic_guard.current_registration(*run))
        } else {
            None
        };
        if !valid || actual.is_none() {
            cache.accepted.clear();
            cache.publications.clear();
            cache.withdrawn = true;
            cache.rejected = group.failure.clone();
            cache.fresh = true;
            continue;
        }
        if desired == cache.accepted {
            cache.publications = cache.snapshot.claims.clone();
            cache.rejected = None;
            cache.withdrawn = desired.is_empty();
            cache.fresh = true;
            continue;
        }
        let prepared = match nic_guard.prepare_managed_routes(*run, actual.unwrap(), &desired) {
            Ok(prepared) => prepared,
            Err(error) => {
                cache.rejected = Some(error.to_string().into());
                cache.fresh = true;
                continue;
            }
        };
        match tokio::time::timeout(
            std::time::Duration::from_secs(2),
            nic_guard.commit_managed_routes(*run, actual.unwrap(), prepared),
        )
        .await
        {
            Ok(Ok(())) => {
                // Record the actual committed admission before checking whether
                // a publisher changed its input during dispatcher I/O.
                admission_changed = true;
                cache.accepted = desired;
                cache.publications = cache.snapshot.claims.clone();
                cache.rejected = None;
                cache.withdrawn = cache.accepted.is_empty();
                cache.fresh = true;
            }
            result => {
                let reason: Arc<str> = match result {
                    Err(_) => "NIC dispatcher admission timed out".into(),
                    Ok(Err(error)) => error.to_string().into(),
                    Ok(Ok(())) => unreachable!(),
                };
                {
                    let mut catalog = state.catalog.lock();
                    if let Some(current) = catalog.groups.get_mut(&id) {
                        if Weak::ptr_eq(&current.nic, &group.nic) {
                            current.failure = Some(reason.clone());
                            let members = current.members.clone();
                            for run in members {
                                if let Some(input) = catalog.instances.get_mut(&run) {
                                    input.ready = None;
                                    input.inputs.invalidate();
                                }
                            }
                        }
                    }
                }
                nic_guard.mark_invalid();
                let weak = group.nic.clone();
                state.shared.spawn(async move {
                    if let Some(nic) = weak.upgrade() {
                        nic.lock().await.invalidate_and_shutdown_dispatcher().await;
                    }
                });
                state.mark_nic(id);
                return false;
            }
        }
    }
    if admission_changed
        && group
            .members
            .iter()
            .any(|(run, _)| caches[run].rejected.is_some())
    {
        state.mark_nic(id);
    }
    // Admission may change source selection for another member. Resolve against
    // the final effective state, after all proposals in this group are applied.
    for (run, input) in &group.members {
        let cache = caches.get_mut(run).unwrap();
        cache.resolved.clear();
        if cache.eligible && !cache.snapshot.closed {
            if let Some(device) = facts.active() {
                for spec in &cache.accepted {
                    cache.resolved.insert(
                        spec.clone(),
                        RouteKey {
                            route: OsRoute {
                                table: 254,
                                destination: spec.destination,
                                metric: validate_tun_spec(spec)
                                    .expect("accepted route is validated"),
                                ifindex: device.ifindex,
                                preferred_source: spec
                                    .preferred_source
                                    .or_else(|| nic_guard.managed_source_hint(spec)),
                            },
                            nic: id,
                            epoch: device.epoch,
                        },
                    );
                }
            }
        }
        if !input.inputs.is_current(&cache.snapshot) {
            cache.fresh = false;
            state.mark_input(*run);
        }
    }
    true
}

fn spawn_driver(
    state: Arc<ControllerState>,
    worker: Arc<AsyncMutex<Worker<PlatformRouteBackend>>>,
    observer: Option<RouteObserver>,
    namespace: PlatformNamespace,
    shared: Handle,
) {
    use futures::FutureExt;
    // Construct before spawning: an executor may destroy an unpolled future.
    let guard = DriverGuard {
        state: state.clone(),
        worker: worker.clone(),
        finished: false,
    };
    shared.spawn(async move {
        let stop = CancellationToken::new();
        let result = std::panic::AssertUnwindSafe(async {
            let work = async {
                let result = drive(&state, &worker).await;
                stop.cancel();
                result
            };
            let observe = observe(state.clone(), observer, namespace, stop.clone());
            let (result, ()) = tokio::join!(work, observe);
            result
        })
        .catch_unwind()
        .await;
        // Preserve exact unresolved effects, not a live request socket or its
        // Reactor registration, after a terminal stop or worker failure.
        worker.lock().await.backend.take();
        match result {
            Ok(Ok(())) => {
                state.phase.send_replace(Phase::Stopped);
            }
            Ok(Err(error)) => state.fail(error.to_string().into()),
            Err(_) => {
                state.fail("route controller panicked; retained effect ledger is frozen".into())
            }
        }
        guard.finish();
    });
}

async fn observe(
    state: Arc<ControllerState>,
    mut observer: Option<RouteObserver>,
    namespace: PlatformNamespace,
    stop: CancellationToken,
) {
    let origin = observer.as_ref().and_then(|observer| observer.origin());
    let mut attempt = 0u32;
    loop {
        if stop.is_cancelled() {
            return;
        }
        if let Some(socket) = &observer {
            let result =
                tokio::select! { _ = stop.cancelled() => return, result = socket.next() => result };
            match result {
                Ok(changes) => {
                    state.os_changed(changes);
                    attempt = 0;
                    continue;
                }
                Err(error) => {
                    tracing::warn!(?error, "route observation lost; invalidating baseline");
                    state.observation_changed(false);
                    observer = None;
                }
            }
        }
        attempt = attempt.saturating_add(1);
        let delay = std::time::Duration::from_millis(
            (100_u64 << attempt.saturating_sub(1).min(6)).min(5000),
        );
        tokio::select! { _ = stop.cancelled() => return, _ = tokio::time::sleep(delay) => {} }
        match RouteObserver::new(&namespace, &state.shared, origin.clone()) {
            Ok(socket) => {
                observer = Some(socket);
                state.observation_changed(true);
            }
            Err(error) => tracing::warn!(?error, "route observer reconnect failed"),
        }
    }
}

async fn drive<B: RouteBackend>(
    state: &Arc<ControllerState>,
    retained: &Arc<AsyncMutex<Worker<B>>>,
) -> anyhow::Result<()> {
    let mut caches = BTreeMap::<Uuid, CachedInput>::new();
    let mut deferred = BTreeMap::<Uuid, tokio::time::Instant>::new();
    let mut verified = Some(0u64);
    let mut verifying = None;
    let mut unverified = BTreeSet::new();
    let mut closing_since = None;
    let mut least_remaining = None;
    loop {
        let notified = state.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let mut dirty = std::mem::take(&mut *state.dirty.lock());
        let now = tokio::time::Instant::now();
        deferred.retain(|nic, deadline| {
            if *deadline <= now {
                dirty.nics.insert(*nic);
                false
            } else {
                true
            }
        });
        let mut feedback = dirty.instances.clone();
        {
            let catalog = state.catalog.lock();
            if catalog.closing {
                closing_since.get_or_insert(now);
            }
            for run in &dirty.order {
                if let Some(input) = catalog.instances.get(run) {
                    let next = input.inputs.snapshot();
                    if caches
                        .get(run)
                        .is_none_or(|cache| !cache.fresh || !cache.same_source(&next))
                    {
                        dirty.nics.insert(input.nic);
                    }
                    match caches.get_mut(run) {
                        Some(cache) => cache.snapshot = next,
                        None => {
                            caches.insert(*run, CachedInput::new(next));
                        }
                    }
                }
            }
        }
        let mut changed_inputs = BTreeSet::new();
        for nic in &dirty.nics {
            if let Some(group) = state.group(*nic) {
                changed_inputs.extend(group.members.iter().map(|(run, _)| *run));
            }
            if refresh_group(state, *nic, &dirty.order, &mut caches).await {
                deferred.remove(nic);
            } else {
                deferred.insert(*nic, now + std::time::Duration::from_millis(100));
            }
        }
        feedback.extend(&changed_inputs);
        let mut worker = retained.lock().await;
        let mut affected = BTreeSet::new();
        // A bounded failed shutdown releases input/config ownership while the
        // exact effect ledger retains only run IDs. Native registration cleanup
        // belongs to the actual NIC owner and does not need these input stores.
        let abandoned = {
            let catalog = state.catalog.lock();
            dirty
                .instances
                .iter()
                .copied()
                .filter(|run| {
                    catalog
                        .instances
                        .get(run)
                        .is_some_and(|input| input.abandoned)
                })
                .collect::<Vec<_>>()
        };
        for run in abandoned {
            if let Some(cache) = caches.remove(&run) {
                affected.extend(worker.replace_routes(run, &cache.indexed, &BTreeSet::new()));
            }
            changed_inputs.remove(&run);
            if let Some(nic) = state.retire(run) {
                dirty.nics.insert(nic);
            }
        }
        for run in changed_inputs {
            let Some(cache) = caches.get_mut(&run) else {
                continue;
            };
            cache.progress_dirty = true;
            if cache.fresh {
                let next = cache.resolved.values().cloned().collect();
                affected.extend(worker.replace_routes(run, &cache.indexed, &next));
                cache.indexed = next;
            }
        }
        // Subscribe new desired/effect slots before any request is sent. A
        // foreign replacement can race our ACK and must not be filtered out
        // merely because this first slot was not published to the observer yet.
        state.sync_slots(&worker, &affected);
        let observation = {
            let catalog = state.catalog.lock();
            (catalog.observation, catalog.connected)
        };
        if dirty.verify_all {
            verified = None;
            verifying = Some(observation.0);
            unverified = worker.slots.keys().cloned().collect();
            for key in &unverified {
                worker.lose_ownership(key);
            }
        }
        for key in &dirty.foreign {
            worker.lose_ownership(key);
        }
        for key in &dirty.slots {
            worker.invalidate(key);
        }
        if worker.has_due_inspections(tokio::time::Instant::now()) {
            let (inspected, complete) = worker.inspect().await;
            if complete {
                for key in &inspected {
                    unverified.remove(key);
                }
            }
            affected.extend(inspected);
        }
        unverified.retain(|key| worker.slots.contains_key(key));
        if unverified.is_empty() && observation.1 && verifying == Some(observation.0) {
            verified = verifying.take();
        }
        // Never choose a winner until all changes collected in this batch reach
        // the derived index. A busy NIC does not block an independent OS slot.
        let mut made_progress = false;
        if state.dirty.lock().is_empty() {
            let now = tokio::time::Instant::now();
            let next = worker
                .pending
                .iter()
                .find(|key| {
                    !worker.inspections.contains(*key)
                        && worker.slots.get(*key).is_some_and(|slot| slot.due(now))
                        && state.can_advance(&worker, key, &caches)
                })
                .cloned();
            if let Some(key) = next {
                worker.advance(&key).await;
                affected.insert(key.clone());
                made_progress = true;
            }
        }
        // Both old and new owners need feedback, especially the last departing
        // owner whose physical effect has just been handed off or removed.
        {
            let catalog = state.catalog.lock();
            for slot in &affected {
                if let Some(owners) = catalog.slots.get(slot) {
                    feedback.extend(owners);
                }
            }
        }
        state.sync_slots(&worker, &affected);
        let (observed, inputs) = {
            let catalog = state.catalog.lock();
            for slot in &affected {
                if let Some(owners) = catalog.slots.get(slot) {
                    feedback.extend(owners);
                }
            }
            (
                catalog.connected && verified == Some(catalog.observation),
                feedback
                    .into_iter()
                    .filter_map(|run| {
                        catalog
                            .instances
                            .get(&run)
                            .map(|input| (run, input.inputs.clone()))
                    })
                    .collect::<Vec<_>>(),
            )
        };
        let mut retired = Vec::new();
        for (run, input) in &inputs {
            let Some(cache) = caches.get_mut(run) else {
                continue;
            };
            cache.update_progress(&worker, &affected);
            let drained = cache.snapshot.closed
                && cache.fresh
                && cache.withdrawn
                && cache.indexed.is_empty()
                && !worker.has_responsibility(*run);
            let status = if drained {
                InstanceRouteStatus::Drained
            } else if cache.snapshot.closed {
                InstanceRouteStatus::Draining {
                    remaining: Some(
                        worker
                            .responsibility_index
                            .get(run)
                            .map_or(0, BTreeSet::len),
                    ),
                }
            } else {
                InstanceRouteStatus::Active
            };
            let feedback = cache
                .snapshot
                .claims
                .iter()
                .map(|(id, demand)| (*id, cache.status(*id, demand, observed)))
                .collect();
            if input.publish_feedback(&cache.snapshot, status, feedback) {
                if drained {
                    retired.push(*run);
                }
            } else {
                state.mark_input(*run);
            }
        }
        for run in retired {
            if let Some(nic) = state.retire(run) {
                dirty.nics.insert(nic);
            }
            caches.remove(&run);
        }
        for nic in &dirty.nics {
            state.compact_group(*nic, &worker);
        }
        let empty = state.catalog.lock().instances.is_empty();
        if closing_since.is_some() {
            let remaining: usize = worker
                .responsibility_index
                .values()
                .map(BTreeSet::len)
                .sum();
            if least_remaining.is_none_or(|least| remaining < least) {
                least_remaining = Some(remaining);
                closing_since = Some(tokio::time::Instant::now());
            }
        }
        if closing_since.is_some() && empty && worker.responsible_owners().is_empty() {
            return Ok(());
        }
        if closing_since.is_some_and(|since| since.elapsed() >= std::time::Duration::from_secs(30))
        {
            anyhow::bail!(
                "route cleanup made no progress for 30 seconds; {} unresolved effects retained",
                worker
                    .slots
                    .values()
                    .filter(|slot| slot
                        .effect
                        .as_ref()
                        .is_some_and(|effect| !matches!(effect.phase, EffectPhase::External)))
                    .count()
            );
        }
        let now = tokio::time::Instant::now();
        let mut deadline = worker
            .next_retry()
            .into_iter()
            .filter(|deadline| *deadline > now)
            .chain(deferred.values().copied())
            .min();
        if let Some(since) = closing_since {
            let end = since + std::time::Duration::from_secs(30);
            deadline = Some(deadline.map_or(end, |deadline| deadline.min(end)));
        }
        drop(worker);
        drop(inputs);
        if made_progress || !state.dirty.lock().is_empty() {
            tokio::task::yield_now().await;
            continue;
        }
        match deadline {
            Some(deadline) => {
                tokio::select! { _ = &mut notified => {}, _ = tokio::time::sleep_until(deadline) => {} }
            }
            None => notified.await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{
        RouteError,
        device::{DeviceLifetime, DeviceOrigin},
    };
    use super::*;
    use crate::{
        common::netns::NetNS,
        instance::{shared_virtual_nic::SharedVirtualNicRegistry, virtual_nic::VirtualNicConfig},
    };
    use easytier_core::{
        config::{
            peers::PeerRuntimeSnapshot,
            runtime::{CoreRuntimeConfig, CoreRuntimeConfigStore},
        },
        host::route::RouteWaitError,
    };
    use futures::FutureExt;
    use std::time::Duration;

    fn feedback_fixture(
        count: usize,
    ) -> (
        InstanceRoutes,
        easytier_core::host::route::RouteClaim,
        Uuid,
        CachedInput,
        Worker<Backend>,
    ) {
        let owner = InstanceRoutes::new(Arc::new(|| {}));
        owner.bind_config(config()).unwrap();
        let epoch = DeviceEpoch::new();
        let nic = Uuid::new_v4();
        let run = Uuid::new_v4();
        let routes = (0..count)
            .map(|index| {
                RouteSpec::for_tun(
                    cidr::IpCidr::new(
                        std::net::Ipv4Addr::from(0xc6120000u32 + index as u32).into(),
                        32,
                    )
                    .unwrap(),
                )
            })
            .collect::<RouteSet>();
        let claim = owner
            .handle()
            .publish(RouteDemand::Additional(routes.clone()))
            .unwrap();
        let mut cache = CachedInput::new(owner.inputs().snapshot());
        cache.resolved = routes
            .into_iter()
            .map(|spec| {
                let route = OsRoute {
                    table: 254,
                    destination: spec.destination,
                    metric: super::super::super::METRIC_DIRECT,
                    ifindex: 7,
                    preferred_source: None,
                };
                (spec, RouteKey { route, nic, epoch })
            })
            .collect();
        cache.fresh = true;
        cache.eligible = true;
        cache.publications = cache.snapshot.claims.clone();
        let fake = Arc::new(Fake::default());
        let mut worker = Worker::new(Backend(fake));
        let accepted = cache.resolved.values().cloned().collect();
        worker.replace_routes(run, &BTreeSet::new(), &accepted);
        (owner, claim, run, cache, worker)
    }

    async fn measure_feedback_updates(count: usize) -> (usize, std::time::Duration) {
        let (_owner, _claim, _run, mut cache, mut worker) = feedback_fixture(count);
        let started = std::time::Instant::now();
        cache.update_progress(&worker, &BTreeSet::new());
        let keys = worker.slots.keys().cloned().collect::<Vec<_>>();
        for key in keys {
            worker.advance(&key).await;
            cache.update_progress(&worker, &BTreeSet::from([key]));
            let (id, publication) = cache.snapshot.claims.first_key_value().unwrap();
            let _ = cache.status(*id, publication, true);
        }
        let elapsed = started.elapsed();
        let (id, publication) = cache.snapshot.claims.first_key_value().unwrap();
        assert_eq!(
            cache.status(*id, publication, true),
            ClaimRouteStatus::Ready
        );
        (cache.status_reads, elapsed)
    }

    #[tokio::test]
    async fn feedback_updates_touch_each_route_once_per_affected_slot() {
        let (reads, _) = measure_feedback_updates(2048).await;
        assert_eq!(
            reads, 4096,
            "initial build plus one update per ACK; no full-claim scans"
        );
    }

    #[tokio::test]
    async fn feedback_follows_another_owners_minimum_metric_without_republishing() {
        async fn advance(cache: &mut CachedInput, worker: &mut Worker<Backend>) {
            for _ in 0..10 {
                let Some(slot) = worker.next_pending(tokio::time::Instant::now()) else {
                    return;
                };
                worker.advance(&slot).await;
                cache.update_progress(worker, &BTreeSet::from([slot]));
            }
            panic!("unexpected repeated mutation");
        }
        let (_owner, _claim, _run, mut cache, mut worker) = feedback_fixture(1);
        let first = cache.resolved.first_key_value().unwrap().1.clone();
        cache.update_progress(&worker, &BTreeSet::new());
        advance(&mut cache, &mut worker).await;
        let mut lower = first.clone();
        lower.route.metric = super::super::super::METRIC_PUBLIC_IPV6_DEFAULT;
        let other = Uuid::new_v4();
        let routes = BTreeSet::from([lower.clone()]);
        let affected = worker.replace_routes(other, &BTreeSet::new(), &routes);
        cache.update_progress(&worker, &affected);
        advance(&mut cache, &mut worker).await;
        assert!(cache.slot_demands.contains_key(&lower.route.slot()));
        assert!(!cache.slot_demands.contains_key(&first.route.slot()));
        let (id, publication) = cache.snapshot.claims.first_key_value().unwrap();
        assert_eq!(
            cache.status(*id, publication, true),
            ClaimRouteStatus::Ready
        );
        let affected = worker.replace_routes(other, &routes, &BTreeSet::new());
        cache.update_progress(&worker, &affected);
        advance(&mut cache, &mut worker).await;
        assert!(cache.slot_demands.contains_key(&first.route.slot()));
        assert!(!cache.slot_demands.contains_key(&lower.route.slot()));
        let (id, publication) = cache.snapshot.claims.first_key_value().unwrap();
        assert_eq!(
            cache.status(*id, publication, true),
            ClaimRouteStatus::Ready
        );
    }

    #[tokio::test]
    #[ignore = "manual CPU/allocation performance probe, no physical TUN required"]
    async fn benchmark_feedback_scaling() {
        for count in [1000, 10000, 50000] {
            let (reads, elapsed) = measure_feedback_updates(count).await;
            assert_eq!(reads, count * 2);
            println!(
                "route feedback: routes={count}, route_status_reads={reads}, elapsed={elapsed:?}"
            );
        }
    }

    #[derive(Default)]
    struct FakeState {
        routes: BTreeSet<OsRoute>,
        adds: usize,
        removes: usize,
        queries: usize,
        pause_add: bool,
        pause_query: bool,
        unknown_add: bool,
        fail_query: bool,
    }
    #[derive(Default)]
    struct Fake {
        state: Mutex<FakeState>,
        changed: Notify,
        add_ack: Notify,
        query_ack: Notify,
    }
    struct Backend(Arc<Fake>);
    impl RouteBackend for Backend {
        async fn add(&mut self, route: &OsRoute) -> Result<(), RouteError> {
            let ack = self.0.add_ack.notified();
            tokio::pin!(ack);
            ack.as_mut().enable();
            let (pause, unknown) = {
                let mut state = self.0.state.lock();
                state.adds += 1;
                state.routes.insert(route.clone());
                (state.pause_add, state.unknown_add)
            };
            self.0.changed.notify_waiters();
            if pause {
                ack.await;
            }
            if unknown {
                Err(RouteError::Unknown(anyhow::anyhow!("ACK lost")))
            } else {
                Ok(())
            }
        }
        async fn remove(&mut self, route: &OsRoute) -> Result<(), RouteError> {
            {
                let mut state = self.0.state.lock();
                state.removes += 1;
                state.routes.remove(route);
            }
            self.0.changed.notify_waiters();
            Ok(())
        }
        async fn existing(
            &mut self,
            routes: &BTreeSet<OsRoute>,
        ) -> Result<BTreeSet<OsRoute>, RouteError> {
            let ack = self.0.query_ack.notified();
            tokio::pin!(ack);
            ack.as_mut().enable();
            let pause = {
                let mut state = self.0.state.lock();
                state.queries += 1;
                state.pause_query
            };
            self.0.changed.notify_waiters();
            if pause {
                ack.await;
            }
            let state = self.0.state.lock();
            if state.fail_query {
                Err(RouteError::Failed(anyhow::anyhow!("interrupted dump")))
            } else {
                Ok(state.routes.intersection(routes).cloned().collect())
            }
        }
    }
    impl Fake {
        async fn until(&self, predicate: impl Fn(&FakeState) -> bool) {
            tokio::time::timeout(Duration::from_secs(3), async {
                loop {
                    let changed = self.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    if predicate(&self.state.lock()) {
                        return;
                    }
                    changed.await;
                }
            })
            .await
            .expect("backend milestone");
        }
    }

    fn config() -> CoreRuntimeConfigStore {
        CoreRuntimeConfigStore::new(
            CoreRuntimeConfig::default(),
            Arc::new(PeerRuntimeSnapshot::default()),
        )
    }
    fn extra(prefix: &str) -> RouteDemand {
        RouteDemand::Additional(RouteSet::from([RouteSpec::for_tun(
            prefix.parse().unwrap(),
        )]))
    }
    fn start(
        state: &Arc<ControllerState>,
        fake: &Arc<Fake>,
    ) -> (
        Arc<AsyncMutex<Worker<Backend>>>,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        let worker = Arc::new(AsyncMutex::new(Worker::new(Backend(fake.clone()))));
        let owned = worker.clone();
        let state = state.clone();
        let task = tokio::spawn(async move { drive(&state, &owned).await });
        (worker, task)
    }
    async fn finish(
        state: &Arc<ControllerState>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
    ) {
        state.request_shutdown();
        tokio::time::timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    async fn kernel_member(
        namespace: &Arc<NetNS>,
        run: Uuid,
        name: &str,
        index: u32,
    ) -> (
        InstanceRoutes,
        SharedVirtualNicMember,
        Option<DeviceLifetime>,
        DeviceEpoch,
    ) {
        let controller = namespace.route_controller().unwrap();
        let owner = controller.open_instance(run, name.into()).unwrap();
        owner.bind_config(config()).unwrap();
        let (_, device) = controller.device(run).unwrap();
        let lifetime = device
            .snapshot()
            .selected
            .is_none()
            .then(|| device.attach(name.into(), index, DeviceOrigin::Borrowed));
        let epoch = device.snapshot().selected.unwrap();
        assert!(device.mark_ready(epoch));
        let member = namespace
            .nics
            .lock()
            .await
            .try_create_member(
                name.into(),
                VirtualNicConfig::new(name.into(), 1400, namespace.clone())
                    .with_route_device(device),
                run,
                Arc::new(Notify::new()),
            )
            .unwrap();
        member
            .shared_nic()
            .lock()
            .await
            .attach_member_registration(run, member.registration_id())
            .await
            .unwrap();
        controller.bind_member(run, &member).unwrap();
        controller
            .set_member_ready(run, member.registration_id(), epoch)
            .unwrap();
        (owner, member, lifetime, epoch)
    }

    fn kernel_dummy(namespace: &NetNS, name: &str) -> u32 {
        for args in [
            vec!["link", "add", name, "type", "dummy"],
            vec!["link", "set", name, "up"],
        ] {
            assert!(
                namespace
                    .run(|| std::process::Command::new("ip").args(args).status())
                    .unwrap()
                    .unwrap()
                    .success()
            );
        }
        namespace
            .run(|| nix::net::if_::if_nametoindex(name))
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace; uses dummy links, no TUN required"]
    async fn kernel_controller_shares_minimum_metric_then_retires_both_inputs() {
        let namespace = crate::common::netns::isolated_namespace_for_test().unwrap();
        let index = kernel_dummy(&namespace, "et-claims");
        let (a, ma, lifetime, epoch) =
            kernel_member(&namespace, Uuid::new_v4(), "et-claims", index).await;
        let (b, mb, reused, b_epoch) =
            kernel_member(&namespace, Uuid::new_v4(), "et-claims", index).await;
        assert!(reused.is_none());
        assert_eq!(epoch, b_epoch);
        // Shared NIC forwarding admits overlap only for its existing DNS
        // host-route exception. Ordinary overlay destinations remain disjoint.
        let prefix = format!("{}/32", crate::instance::dns_server::MAGIC_DNS_FAKE_IP);
        let a_claim = a.handle().publish(extra(&prefix)).unwrap();
        tokio::time::timeout(Duration::from_secs(5), a_claim.wait_ready(Some(epoch)))
            .await
            .unwrap()
            .unwrap();
        let mut spec = RouteSpec::for_tun(prefix.parse().unwrap());
        spec.metric = 1000;
        let b_claim = b
            .handle()
            .publish(RouteDemand::Additional(BTreeSet::from([spec.clone()])))
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), b_claim.wait_ready(Some(epoch)))
            .await
            .unwrap()
            .unwrap();
        let mut reader =
            PlatformRouteBackend::new(namespace.platform(), &Handle::current()).unwrap();
        let route = OsRoute {
            table: 254,
            destination: spec.destination,
            metric: std::num::NonZeroU32::new(1000).unwrap(),
            ifindex: index,
            preferred_source: None,
        };
        let requested = BTreeSet::from([route.clone()]);
        assert_eq!(reader.existing(&requested).await.unwrap(), requested);
        let weak_a = Arc::downgrade(&a.inputs());
        a.request_close();
        tokio::time::timeout(Duration::from_secs(5), a.wait_drained())
            .await
            .unwrap()
            .unwrap();
        drop((a, a_claim, ma));
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak_a.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(reader.existing(&requested).await.unwrap(), requested);
        b_claim.wait_ready(Some(epoch)).await.unwrap();
        b.request_close();
        tokio::time::timeout(Duration::from_secs(5), b.wait_drained())
            .await
            .unwrap()
            .unwrap();
        let both_metrics = BTreeSet::from([
            route.clone(),
            OsRoute {
                metric: super::super::super::METRIC_DIRECT,
                ..route
            },
        ]);
        assert!(reader.existing(&both_metrics).await.unwrap().is_empty());
        drop((b, b_claim, mb, lifetime));
        namespace.request_service_shutdown();
        tokio::time::timeout(Duration::from_secs(5), namespace.wait_services_stopped())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    #[ignore = "run inside an isolated user+network namespace; uses a dummy link, no TUN required"]
    async fn kernel_controller_never_deletes_an_observed_identical_foreign_replacement() {
        let namespace = crate::common::netns::isolated_namespace_for_test().unwrap();
        let index = kernel_dummy(&namespace, "et-foreign");
        let (owner, member, lifetime, epoch) =
            kernel_member(&namespace, Uuid::new_v4(), "et-foreign", index).await;
        let claim = owner.handle().publish(extra("198.18.81.0/24")).unwrap();
        tokio::time::timeout(Duration::from_secs(5), claim.wait_ready(Some(epoch)))
            .await
            .unwrap()
            .unwrap();
        let controller = namespace.route_controller().unwrap();
        let route = OsRoute {
            table: 254,
            destination: "198.18.81.0/24".parse().unwrap(),
            metric: super::super::super::METRIC_DIRECT,
            ifindex: index,
            preferred_source: None,
        };
        let mut foreign =
            PlatformRouteBackend::new(namespace.platform(), &Handle::current()).unwrap();
        let paused = controller.worker.lock().await;
        foreign.remove(&route).await.unwrap();
        foreign.add(&route).await.unwrap();
        drop(paused);
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let unknown = controller
                    .worker
                    .lock()
                    .await
                    .slots
                    .get(&route.slot())
                    .and_then(|slot| slot.effect.as_ref())
                    .is_some_and(|effect| matches!(effect.phase, EffectPhase::Unknown { .. }));
                if unknown {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(claim.wait_ready(Some(epoch)).now_or_never().is_none());
        owner.request_close();
        assert!(owner.wait_drained().now_or_never().is_none());
        let requested = BTreeSet::from([route.clone()]);
        assert_eq!(foreign.existing(&requested).await.unwrap(), requested);
        foreign.remove(&route).await.unwrap();
        tokio::time::timeout(Duration::from_secs(5), owner.wait_drained())
            .await
            .unwrap()
            .unwrap();
        assert!(controller.unresolved().await.is_empty());
        drop((owner, claim, member, lifetime));
        namespace.request_service_shutdown();
        tokio::time::timeout(Duration::from_secs(5), namespace.wait_services_stopped())
            .await
            .unwrap()
            .unwrap();
    }
    async fn member_with_config(
        state: &Arc<ControllerState>,
        run: Uuid,
        name: &str,
        index: u32,
        store: CoreRuntimeConfigStore,
    ) -> (
        InstanceRoutes,
        SharedVirtualNicMember,
        DeviceLifetime,
        SharedVirtualNicRegistry,
    ) {
        let owner = state.open(run, name.into()).unwrap();
        owner.bind_config(store).unwrap();
        let nic_id = state.catalog.lock().instances[&run].nic;
        let group = state.group(nic_id).unwrap();
        let lifetime = group
            .device
            .attach(name.into(), index, DeviceOrigin::Borrowed);
        assert!(group.device.mark_ready(lifetime.epoch()));
        let mut registry = SharedVirtualNicRegistry::new();
        let config = VirtualNicConfig::new(name.into(), 1500, NetNS::current().unwrap())
            .with_route_device(group.device);
        let member = registry.create_member(name.into(), config, run, Arc::new(Notify::new()));
        member
            .shared_nic()
            .lock()
            .await
            .attach_member_registration(run, member.registration_id())
            .await
            .unwrap();
        state.bind_member(run, &member).unwrap();
        state
            .member_ready(run, member.registration_id(), lifetime.epoch())
            .unwrap();
        (owner, member, lifetime, registry)
    }

    async fn member(
        state: &Arc<ControllerState>,
        run: Uuid,
        name: &str,
        index: u32,
    ) -> (
        InstanceRoutes,
        SharedVirtualNicMember,
        DeviceLifetime,
        SharedVirtualNicRegistry,
    ) {
        member_with_config(state, run, name, index, config()).await
    }

    #[tokio::test]
    async fn empty_claim_needs_no_device_and_retirement_releases_every_input() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let (_, task) = start(&state, &fake);
        for _ in 0..64 {
            let run = Uuid::new_v4();
            let owner = state.open(run, String::new()).unwrap();
            owner.bind_config(config()).unwrap();
            let weak = Arc::downgrade(&owner.inputs());
            let claim = owner
                .handle()
                .publish(RouteDemand::Additional(RouteSet::new()))
                .unwrap();
            tokio::time::timeout(Duration::from_secs(3), claim.wait_ready(None))
                .await
                .unwrap()
                .unwrap();
            owner.request_close();
            tokio::time::timeout(Duration::from_secs(3), owner.wait_drained())
                .await
                .unwrap()
                .unwrap();
            drop(owner);
            drop(claim);
            // The driver drops transient input clones before yielding to wait.
            tokio::task::yield_now().await;
            assert!(weak.upgrade().is_none());
        }
        assert!(state.catalog.lock().instances.is_empty());
        assert!(state.catalog.lock().slots.is_empty());
        assert!(state.catalog.lock().groups.is_empty());
        assert!(state.catalog.lock().logical.is_empty());
        assert_eq!(fake.state.lock().adds, 0);
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn replacement_and_close_during_ack_record_then_remove_actual_effect() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        fake.state.lock().pause_add = true;
        let run = Uuid::new_v4();
        let (owner, _member, lifetime, _registry) = member(&state, run, "controller-ack", 7).await;
        let claim = owner.handle().publish(extra("198.18.1.0/24")).unwrap();
        let (worker, task) = start(&state, &fake);
        fake.until(|fake| fake.adds == 1).await;
        claim.replace(extra("198.18.2.0/24")).unwrap();
        owner.request_close();
        fake.state.lock().pause_add = false;
        fake.add_ack.notify_one();
        tokio::time::timeout(Duration::from_secs(3), owner.wait_drained())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            claim.wait_ready(Some(lifetime.epoch())).await,
            Err(RouteWaitError::Closed)
        ));
        let counts = {
            let data = fake.state.lock();
            (data.adds, data.removes)
        };
        assert_eq!(counts, (1, 1));
        assert!(fake.state.lock().routes.is_empty());
        assert!(worker.lock().await.responsible_owners().is_empty());
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn busy_nic_does_not_block_an_independent_slot() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let (a, ma, ea, _ra) = member(&state, Uuid::new_v4(), "controller-busy", 7).await;
        let (b, _mb, eb, _rb) = member(&state, Uuid::new_v4(), "controller-free", 8).await;
        let ca = a.handle().publish(extra("198.18.1.0/24")).unwrap();
        let cb = b.handle().publish(extra("198.18.2.0/24")).unwrap();
        let nic = ma.shared_nic();
        let held = nic.lock().await;
        let (_, task) = start(&state, &fake);
        tokio::time::timeout(Duration::from_secs(3), cb.wait_ready(Some(eb.epoch())))
            .await
            .unwrap()
            .unwrap();
        assert!(ca.wait_ready(Some(ea.epoch())).now_or_never().is_none());
        assert_eq!(fake.state.lock().adds, 1);
        drop(held);
        tokio::time::timeout(Duration::from_secs(3), ca.wait_ready(Some(ea.epoch())))
            .await
            .unwrap()
            .unwrap();
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn observation_reconnect_needs_absence_before_reacquiring_owned_routes() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let (owner, _member, epoch, _registry) =
            member(&state, Uuid::new_v4(), "controller-observe", 7).await;
        let claim = owner.handle().publish(extra("198.18.1.0/24")).unwrap();
        let (_, task) = start(&state, &fake);
        tokio::time::timeout(
            Duration::from_secs(3),
            claim.wait_ready(Some(epoch.epoch())),
        )
        .await
        .unwrap()
        .unwrap();
        fake.state.lock().pause_query = true;
        state.observation_changed(false);
        state.observation_changed(true);
        fake.until(|fake| fake.queries == 1).await;
        assert!(
            claim
                .wait_ready(Some(epoch.epoch()))
                .now_or_never()
                .is_none()
        );
        fake.state.lock().pause_query = false;
        fake.query_ack.notify_one();
        fake.until(|fake| fake.queries >= 2).await;
        assert!(
            claim
                .wait_ready(Some(epoch.epoch()))
                .now_or_never()
                .is_none()
        );
        assert_eq!(fake.state.lock().removes, 0);
        let slots = {
            let mut fake = fake.state.lock();
            let slots = fake.routes.iter().map(OsRoute::slot).collect();
            fake.routes.clear();
            slots
        };
        state.os_changed(RouteChanges {
            slots,
            links: BTreeSet::new(),
        });
        tokio::time::timeout(
            Duration::from_secs(3),
            claim.wait_ready(Some(epoch.epoch())),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(fake.state.lock().adds, 2);
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn device_epoch_and_member_ready_are_separate_and_late_completion_is_rejected() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let run = Uuid::new_v4();
        let (owner, member, first, _registry) = member(&state, run, "controller-epochs", 7).await;
        let claim = owner.handle().publish(extra("198.18.1.0/24")).unwrap();
        let (_, task) = start(&state, &fake);
        tokio::time::timeout(
            Duration::from_secs(3),
            claim.wait_ready(Some(first.epoch())),
        )
        .await
        .unwrap()
        .unwrap();
        let nic_id = state.catalog.lock().instances[&run].nic;
        let group = state.group(nic_id).unwrap();
        state.member_unready(run, member.registration_id());
        assert_eq!(owner.inputs().snapshot().device, Some(first.epoch()));
        assert!(
            claim
                .wait_ready(Some(first.epoch()))
                .now_or_never()
                .is_none()
        );
        state
            .member_ready(run, member.registration_id(), first.epoch())
            .unwrap();
        let next = group
            .device
            .attach("controller-epochs".into(), 8, DeviceOrigin::Borrowed);
        group.device.mark_ready(next.epoch());
        assert!(
            state
                .member_ready(run, member.registration_id(), first.epoch())
                .is_err()
        );
        assert!(matches!(
            claim.wait_ready(Some(first.epoch())).await,
            Err(RouteWaitError::DeviceChanged)
        ));
        assert!(
            claim
                .wait_ready(Some(next.epoch()))
                .now_or_never()
                .is_none()
        );
        state
            .member_ready(run, member.registration_id(), next.epoch())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), claim.wait_ready(Some(next.epoch())))
            .await
            .unwrap()
            .unwrap();
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn unpolled_driver_drop_fails_inputs_and_releases_catalog_references() {
        let state = ControllerState::new(Handle::current());
        let owner = state.open(Uuid::new_v4(), String::new()).unwrap();
        let guard = DriverGuard {
            state: state.clone(),
            worker: Arc::new(AsyncMutex::new(Worker::new(Backend(Arc::new(
                Fake::default(),
            ))))),
            finished: false,
        };
        let unpolled = async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        };
        drop(unpolled);
        assert!(matches!(
            owner.wait_drained().await,
            Err(RouteWaitError::Failed(_))
        ));
        assert!(state.catalog.lock().instances.is_empty());
    }
    #[tokio::test]
    async fn shared_device_claim_handoff_retires_the_departing_input_without_route_churn() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let run_a = Uuid::new_v4();
        let (a, _ma, epoch, mut registry) = member(&state, run_a, "controller-shared", 7).await;
        let run_b = Uuid::new_v4();
        let b = state.open(run_b, "controller-shared".into()).unwrap();
        b.bind_config(config()).unwrap();
        let nic_id = state.catalog.lock().instances[&run_b].nic;
        let device = state.group(nic_id).unwrap().device;
        let config =
            VirtualNicConfig::new("controller-shared".into(), 1500, NetNS::current().unwrap())
                .with_route_device(device);
        let mb = registry.create_member(
            "controller-shared".into(),
            config,
            run_b,
            Arc::new(Notify::new()),
        );
        mb.shared_nic()
            .lock()
            .await
            .attach_member_registration(run_b, mb.registration_id())
            .await
            .unwrap();
        state.bind_member(run_b, &mb).unwrap();
        state
            .member_ready(run_b, mb.registration_id(), epoch.epoch())
            .unwrap();
        let dns = format!("{}/32", crate::instance::dns_server::MAGIC_DNS_FAKE_IP);
        let ca = a.handle().publish(extra(&dns)).unwrap();
        let cb = b.handle().publish(extra(&dns)).unwrap();
        let (_, task) = start(&state, &fake);
        tokio::time::timeout(Duration::from_secs(3), ca.wait_ready(Some(epoch.epoch())))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(3), cb.wait_ready(Some(epoch.epoch())))
            .await
            .unwrap()
            .unwrap();
        let weak_a = Arc::downgrade(&a.inputs());
        a.request_close();
        tokio::time::timeout(Duration::from_secs(3), a.wait_drained())
            .await
            .unwrap()
            .unwrap();
        drop(a);
        drop(ca);
        tokio::task::yield_now().await;
        assert!(weak_a.upgrade().is_none());
        assert_eq!(fake.state.lock().adds, 1);
        assert_eq!(fake.state.lock().removes, 0);
        cb.wait_ready(Some(epoch.epoch())).await.unwrap();
        b.request_close();
        tokio::time::timeout(Duration::from_secs(3), b.wait_drained())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fake.state.lock().removes, 1);
        finish(&state, task).await;
    }

    #[tokio::test]
    async fn manual_suppression_retains_raw_auto_updates_and_additional_claims() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        let store = config();
        let (owner, _member, epoch, _registry) = member_with_config(
            &state,
            Uuid::new_v4(),
            "controller-manual",
            7,
            store.clone(),
        )
        .await;
        let auto = owner
            .handle()
            .publish(RouteDemand::AutoProxy(BTreeSet::from(["10.50.0.0/24"
                .parse()
                .unwrap()])))
            .unwrap();
        let additional = owner.handle().publish(extra("198.18.1.0/24")).unwrap();
        let (_, task) = start(&state, &fake);
        tokio::time::timeout(Duration::from_secs(3), auto.wait_ready(Some(epoch.epoch())))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(
            Duration::from_secs(3),
            additional.wait_ready(Some(epoch.epoch())),
        )
        .await
        .unwrap()
        .unwrap();
        store.update_services(|services| services.manual_routes = Some(BTreeSet::new()));
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(3), auto.wait_ready(Some(epoch.epoch())))
                .await
                .unwrap(),
            Err(RouteWaitError::Suppressed)
        ));
        fake.until(|fake| fake.removes == 1).await;
        auto.replace(RouteDemand::AutoProxy(BTreeSet::from(["10.51.0.0/24"
            .parse()
            .unwrap()])))
            .unwrap();
        store.update_services(|services| {
            services.manual_routes = Some(BTreeSet::from(["10.52.0.0/24".parse().unwrap()]))
        });
        let manual = "10.52.0.0/24".parse::<cidr::IpCidr>().unwrap();
        fake.until(|fake| fake.routes.iter().any(|route| route.destination == manual))
            .await;
        additional.wait_ready(Some(epoch.epoch())).await.unwrap();
        store.update_services(|services| services.manual_routes = None);
        tokio::time::timeout(Duration::from_secs(3), auto.wait_ready(Some(epoch.epoch())))
            .await
            .unwrap()
            .unwrap();
        // Ready applies to this publication. Independent obsolete routes may
        // finish their separate withdrawals just after the new route is ready.
        fake.until(|fake| !fake.routes.iter().any(|route| route.destination == manual))
            .await;
        let current = "10.51.0.0/24".parse::<cidr::IpCidr>().unwrap();
        {
            let fake = fake.state.lock();
            assert!(fake.routes.iter().any(|route| route.destination == current));
            assert!(!fake.routes.iter().any(|route| route.destination == manual));
            assert_eq!(fake.adds, 4);
            assert_eq!(fake.removes, 2);
        }
        finish(&state, task).await;
    }
    #[tokio::test]
    async fn shared_controller_backend_survives_the_first_instance_executor() {
        use crate::common::native_executor::NativeExecutor;
        let shared = NativeExecutor::shared().unwrap();
        let first = NativeExecutor::new(false, 0).unwrap();
        let platform = PlatformNamespace::current().unwrap();
        let driver = shared.handle();
        // The synchronous lazy constructor is called from the first instance,
        // not from the shared runtime that must own its AsyncFd registrations.
        let controller = first
            .handle()
            .spawn(async move { RouteController::new(platform, driver).unwrap() })
            .await
            .unwrap();
        first.request_shutdown();
        first.wait_stopped().await;
        let query = OsRoute {
            table: 254,
            destination: "198.18.240.1/32".parse().unwrap(),
            metric: std::num::NonZeroU32::new(65535).unwrap(),
            ifindex: 1,
            preferred_source: None,
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            controller
                .worker
                .lock()
                .await
                .backend
                .as_mut()
                .unwrap()
                .existing(&BTreeSet::from([query]))
                .await
                .unwrap();
        })
        .await
        .unwrap();
        controller.request_shutdown();
        tokio::time::timeout(Duration::from_secs(3), controller.wait_stopped())
            .await
            .unwrap()
            .unwrap();
        assert!(controller.worker.lock().await.backend.is_none());
        shared.request_shutdown();
        shared.wait_stopped().await;
    }
    #[tokio::test]
    async fn failed_shutdown_retires_input_but_keeps_unknown_effect_without_delete_rights() {
        let state = ControllerState::new(Handle::current());
        let fake = Arc::new(Fake::default());
        fake.state.lock().unknown_add = true;
        let run = Uuid::new_v4();
        let (owner, _member, _epoch, _registry) =
            member(&state, run, "controller-abandoned", 7).await;
        let weak = Arc::downgrade(&owner.inputs());
        let claim = owner.handle().publish(extra("198.18.1.0/24")).unwrap();
        let (worker, task) = start(&state, &fake);
        fake.until(|fake| fake.adds == 1).await;
        state.abandon(run, "cleanup stalled".into());
        assert!(matches!(
            owner.wait_drained().await,
            Err(RouteWaitError::Failed(_))
        ));
        drop(claim);
        drop(owner);
        tokio::time::timeout(Duration::from_secs(3), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!state.catalog.lock().instances.contains_key(&run));
        let slots = {
            let worker = worker.lock().await;
            assert!(worker.has_responsibility(run));
            assert!(worker.slots.values().any(|slot| {
                slot.effect
                    .as_ref()
                    .is_some_and(|effect| matches!(effect.phase, EffectPhase::Unknown { .. }))
            }));
            worker.slots.keys().cloned().collect()
        };
        assert_eq!(fake.state.lock().removes, 0);
        // A later complete absence observation may settle the orphan receipt.
        fake.state.lock().routes.clear();
        state.os_changed(RouteChanges {
            slots,
            links: BTreeSet::new(),
        });
        finish(&state, task).await;
        assert!(!worker.lock().await.has_responsibility(run));
    }
}

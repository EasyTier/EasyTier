use std::collections::BTreeSet;
use std::sync::{Arc, Weak};

use cidr::IpCidr;
use parking_lot::{Mutex, RwLock};

use crate::utils::dirty::DirtyFlag;

pub type RouteSlot = RwLock<BTreeSet<IpCidr>>;

/// Lightweight, cloneable handle for registering route publishers.
///
/// Different publishers do NOT share routing state with each other.
/// Each registered publisher acquires an independent `RouteLease` backed by its own private `RouteSlot`.
#[derive(Clone, Debug)]
pub struct RouteHandle {
    slots: Arc<Mutex<Vec<Weak<RouteSlot>>>>,
    dirty: Arc<DirtyFlag>,
}

impl RouteHandle {
    pub fn new(slots: Arc<Mutex<Vec<Weak<RouteSlot>>>>, dirty: Arc<DirtyFlag>) -> Self {
        Self { slots, dirty }
    }

    pub fn register(&self) -> RouteLease {
        let slot = Arc::new(RwLock::new(BTreeSet::new()));
        self.slots.lock().push(Arc::downgrade(&slot));
        self.dirty.mark();
        RouteLease {
            slot: Some(slot),
            dirty: self.dirty.clone(),
        }
    }
}

/// RAII route lease held by a publisher.
///
/// When the lease is dropped, its private slot strong reference is dropped
/// and the Manager is notified immediately to withdraw the routes from the kernel.
#[derive(Debug)]
pub struct RouteLease {
    slot: Option<Arc<RouteSlot>>,
    dirty: Arc<DirtyFlag>,
}

impl RouteLease {
    pub fn update(&self, f: impl FnOnce(&mut BTreeSet<IpCidr>)) {
        if let Some(slot) = &self.slot {
            f(&mut slot.write());
            self.dirty.mark();
        }
    }

    pub fn set(&self, cidrs: BTreeSet<IpCidr>) {
        self.update(|s| *s = cidrs);
    }

    pub fn clear(&self) {
        self.update(|s| s.clear());
    }

    pub fn list(&self) -> BTreeSet<IpCidr> {
        self.slot
            .as_ref()
            .map(|s| s.read().clone())
            .unwrap_or_default()
    }
}

impl Drop for RouteLease {
    fn drop(&mut self) {
        drop(self.slot.take());
        self.dirty.mark();
    }
}

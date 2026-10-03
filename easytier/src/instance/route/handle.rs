use std::collections::BTreeSet;
use std::sync::{Arc, Weak};

use cidr::IpCidr;
use guarden::guard;
use guarden::guard::boxed::BoxSyncGuard;
use parking_lot::RwLock;
use tokio::sync::{Notify, mpsc};

pub type RouteSlot = RwLock<BTreeSet<IpCidr>>;

/// Lightweight, cloneable handle for registering route publishers.
///
/// Different publishers do NOT share routing state with each other.
/// Each registered publisher acquires an independent `RouteLease` backed by its own private `RouteSlot`.
#[derive(Clone, Debug)]
pub struct RouteHandle {
    reg: mpsc::UnboundedSender<Weak<RouteSlot>>,
    changed: Arc<Notify>,
}

impl RouteHandle {
    pub fn new(reg: mpsc::UnboundedSender<Weak<RouteSlot>>, changed: Arc<Notify>) -> Self {
        Self { reg, changed }
    }

    pub fn register(&self) -> RouteLease {
        let lease = RouteLease::new(self.changed.clone());
        let _ = self.reg.send(Arc::downgrade(&lease.slot));
        lease
    }
}

/// RAII route lease held by a publisher.
///
/// When the lease is dropped, its private slot strong reference is dropped
/// and the Manager is notified immediately to withdraw the routes from the kernel.
#[derive(Debug)]
pub struct RouteLease {
    slot: Arc<RouteSlot>,
    changed: BoxSyncGuard<Arc<Notify>>,
}

impl RouteLease {
    pub fn new(changed: Arc<Notify>) -> Self {
        Self {
            slot: Arc::new(RwLock::new(BTreeSet::new())),
            changed: guard!([changed] changed.notify_one()).boxed(),
        }
    }

    pub fn update(&self, f: impl FnOnce(&mut BTreeSet<IpCidr>)) {
        f(&mut self.slot.write());
        self.changed.notify_one();
    }

    pub fn set(&self, cidrs: BTreeSet<IpCidr>) {
        self.update(|s| *s = cidrs);
    }

    pub fn clear(&self) {
        self.update(|s| s.clear());
    }

    pub fn list(&self) -> BTreeSet<IpCidr> {
        self.slot.read().clone()
    }
}

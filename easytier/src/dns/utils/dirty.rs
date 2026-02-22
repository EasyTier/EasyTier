use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Debug, Default, Deref, DerefMut)]
pub struct DirtyState<T> {
    #[deref]
    #[deref_mut]
    flags: T,
    pub notify: Notify,
}

#[derive(Derivative, Debug, Deref)]
#[derivative(Default)]
pub struct DirtyFlag {
    #[derivative(Default(value = "AtomicBool::new(true)"))]
    dirty: AtomicBool,
    #[deref]
    notify: Notify,
}

impl DirtyFlag {
    pub fn new(value: bool) -> Self {
        Self {
            dirty: AtomicBool::new(value),
            notify: Notify::new(),
        }
    }

    pub fn mark(&self) {
        self.dirty.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    pub fn peek(&self) -> bool {
        self.dirty.load(Ordering::Acquire)
    }

    pub fn reset(&self) -> bool {
        self.dirty.swap(false, Ordering::Acquire)
    }
}

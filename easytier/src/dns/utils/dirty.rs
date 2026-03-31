use derive_more::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Notify;

#[derive(Debug, Deref)]
pub struct DirtyFlag {
    dirty: AtomicBool,
    #[deref]
    notify: Notify,
}

impl DirtyFlag {
    pub fn new(value: bool) -> Self {
        let notify = Notify::new();

        if value {
            notify.notify_one();
        }

        Self {
            dirty: AtomicBool::new(value),
            notify,
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

impl Default for DirtyFlag {
    fn default() -> Self {
        Self::new(true)
    }
}

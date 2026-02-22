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

#[derive(Derivative, Debug)]
#[derivative(Default)]
pub struct DirtyFlag(#[derivative(Default(value = "AtomicBool::new(true)"))] AtomicBool);

impl DirtyFlag {
    pub fn new(value: bool) -> Self {
        Self(AtomicBool::new(value))
    }

    pub fn mark(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn peek(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }

    pub fn reset(&self) -> bool {
        self.0.swap(false, Ordering::Acquire)
    }
}

//! Device facts contain metadata only. Physical I/O owns the release guard.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Weak},
};

use easytier_core::host::route::DeviceEpoch;
use parking_lot::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceOrigin {
    ControlledNonPersistentTun,
    PersistentOrSharedTun,
    Borrowed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeviceRecord {
    pub epoch: DeviceEpoch,
    pub ifindex: u32,
    pub name: String,
    pub origin: DeviceOrigin,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeviceRelease {
    ControlledTunClosed(DeviceRecord),
    DescriptorClosed(DeviceRecord),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DeviceFacts {
    pub selected: Option<DeviceEpoch>,
    pub ready: bool,
    pub live: BTreeMap<DeviceEpoch, DeviceRecord>,
    pub released: BTreeMap<DeviceEpoch, DeviceRelease>,
}

impl DeviceFacts {
    pub(crate) fn active(&self) -> Option<&DeviceRecord> {
        self.selected.and_then(|epoch| self.live.get(&epoch))
    }
}

pub(crate) struct DeviceState {
    facts: Mutex<DeviceFacts>,
    changed: Arc<dyn Fn() + Send + Sync>,
}

impl DeviceState {
    pub(crate) fn new(changed: Arc<dyn Fn() + Send + Sync>) -> Arc<Self> {
        Arc::new(Self {
            facts: Mutex::new(DeviceFacts::default()),
            changed,
        })
    }

    pub(crate) fn snapshot(&self) -> DeviceFacts {
        self.facts.lock().clone()
    }

    pub(crate) fn attach(
        self: &Arc<Self>,
        name: String,
        ifindex: u32,
        origin: DeviceOrigin,
    ) -> DeviceLifetime {
        assert_ne!(ifindex, 0);
        let epoch = DeviceEpoch::new();
        {
            let mut facts = self.facts.lock();
            facts.live.insert(
                epoch,
                DeviceRecord {
                    epoch,
                    name,
                    ifindex,
                    origin,
                },
            );
            facts.selected = Some(epoch);
            facts.ready = false;
        }
        (self.changed)();
        DeviceLifetime {
            state: Arc::downgrade(self),
            epoch,
        }
    }

    pub(crate) fn mark_ready(&self, expected: DeviceEpoch) -> bool {
        {
            let mut facts = self.facts.lock();
            if facts.selected != Some(expected) || !facts.live.contains_key(&expected) {
                return false;
            }
            if facts.ready {
                return true;
            }
            facts.ready = true;
        }
        (self.changed)();
        true
    }

    pub(crate) fn mark_unready(&self, expected: DeviceEpoch) {
        {
            let mut facts = self.facts.lock();
            if facts.selected != Some(expected) || !facts.ready {
                return;
            }
            facts.ready = false;
        }
        (self.changed)();
    }

    // The controller keeps evidence only while an effect still depends on it.
    pub(crate) fn retain_releases(&self, pending: &BTreeSet<DeviceEpoch>) {
        self.facts
            .lock()
            .released
            .retain(|epoch, _| pending.contains(epoch));
    }
}

pub(crate) struct DeviceLifetime {
    state: Weak<DeviceState>,
    epoch: DeviceEpoch,
}

impl DeviceLifetime {
    pub(crate) fn epoch(&self) -> DeviceEpoch {
        self.epoch
    }
}

impl Drop for DeviceLifetime {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        {
            let mut facts = state.facts.lock();
            let Some(record) = facts.live.remove(&self.epoch) else {
                return;
            };
            if facts.selected == Some(self.epoch) {
                facts.selected = None;
                facts.ready = false;
            }
            let release = match record.origin {
                DeviceOrigin::ControlledNonPersistentTun => {
                    DeviceRelease::ControlledTunClosed(record)
                }
                _ => DeviceRelease::DescriptorClosed(record),
            };
            facts.released.insert(self.epoch, release);
        }
        (state.changed)();
    }
}

// Field order closes the real fd before publishing its release. BiLock owns
// this whole wrapper across split I/O; no separate cloneable lifetime exists.
pub(crate) struct DeviceResource<T> {
    resource: T,
    _lifetime: Option<DeviceLifetime>,
}

impl<T> DeviceResource<T> {
    pub(crate) fn untracked(resource: T) -> Self {
        Self {
            resource,
            _lifetime: None,
        }
    }
    pub(crate) fn new(resource: T, lifetime: DeviceLifetime) -> Self {
        Self {
            resource,
            _lifetime: Some(lifetime),
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for DeviceResource<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().resource).poll_read(cx, buf)
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for DeviceResource<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().resource).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().resource).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().resource).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn selection_ready_and_real_resource_release_are_independent() {
        let state = DeviceState::new(Arc::new(|| {}));
        let first = state.attach("tun0".into(), 7, DeviceOrigin::ControlledNonPersistentTun);
        let first_epoch = first.epoch();
        assert!(state.mark_ready(first_epoch));
        state.mark_unready(first_epoch);
        assert!(state.snapshot().live.contains_key(&first_epoch));
        let next = state.attach("tun0".into(), 7, DeviceOrigin::ControlledNonPersistentTun);
        assert_ne!(next.epoch(), first_epoch);
        assert!(!state.mark_ready(first_epoch));
        assert!(state.mark_ready(next.epoch()));
        drop(first);
        let facts = state.snapshot();
        assert_eq!(facts.active().unwrap().epoch, next.epoch());
        assert!(facts.ready);
        assert!(matches!(
            facts.released[&first_epoch],
            DeviceRelease::ControlledTunClosed(_)
        ));
        state.retain_releases(&BTreeSet::new());
        assert!(state.snapshot().released.is_empty());
    }

    #[test]
    fn split_io_and_drop_order_do_not_publish_premature_release() {
        use futures::lock::BiLock;
        struct Resource {
            closed: Arc<AtomicBool>,
        }
        impl Drop for Resource {
            fn drop(&mut self) {
                self.closed.store(true, Ordering::Release);
            }
        }
        let closed = Arc::new(AtomicBool::new(false));
        let observe_closed = closed.clone();
        let armed = Arc::new(AtomicBool::new(false));
        let observe_armed = armed.clone();
        let released = Arc::new(AtomicBool::new(false));
        let observe_released = released.clone();
        let state = DeviceState::new(Arc::new(move || {
            if observe_armed.load(Ordering::Acquire) {
                assert!(
                    observe_closed.load(Ordering::Acquire),
                    "release must follow the real resource destructor"
                );
                observe_released.store(true, Ordering::Release);
            }
        }));
        let lifetime = state.attach("tun0".into(), 7, DeviceOrigin::ControlledNonPersistentTun);
        let epoch = lifetime.epoch();
        let (reader, writer) = BiLock::new(DeviceResource::new(
            Resource {
                closed: closed.clone(),
            },
            lifetime,
        ));
        armed.store(true, Ordering::Release);
        drop(reader);
        assert!(!closed.load(Ordering::Acquire));
        assert!(state.snapshot().live.contains_key(&epoch));
        drop(writer);
        assert!(released.load(Ordering::Acquire));
        assert!(closed.load(Ordering::Acquire));
        assert!(!state.snapshot().live.contains_key(&epoch));
        assert!(state.snapshot().released.contains_key(&epoch));
    }

    #[test]
    fn borrowed_and_persistent_descriptors_do_not_prove_device_destruction() {
        let state = DeviceState::new(Arc::new(|| {}));
        for origin in [DeviceOrigin::Borrowed, DeviceOrigin::PersistentOrSharedTun] {
            let lifetime = state.attach("tun0".into(), 7, origin);
            let epoch = lifetime.epoch();
            drop(lifetime);
            assert!(matches!(
                state.snapshot().released[&epoch],
                DeviceRelease::DescriptorClosed(_)
            ));
        }
    }
}

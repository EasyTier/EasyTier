use std::{
    collections::BTreeMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::watch;

use super::DeviceId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ActiveDevice {
    pub id: DeviceId,
    pub registration: u64,
    pub name: String,
    pub ready: bool,
}

/// Host facts, not route state. Selecting a new device does not prove that
/// an older device was destroyed; every live fd owner remains in `live`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DeviceFacts {
    pub active: Option<ActiveDevice>,
    pub live: BTreeMap<u64, DeviceId>,
}

impl DeviceFacts {
    pub fn destroyed(&self, device: &DeviceId) -> bool {
        device.host_instance.is_some() && !self.live.values().any(|live| live == device)
    }
}

pub(crate) struct TunDeviceState {
    changes: watch::Sender<DeviceFacts>,
    legacy_name: Arc<Mutex<Option<String>>>,
    next_instance: AtomicU64,
}

impl TunDeviceState {
    pub fn new(legacy_name: Arc<Mutex<Option<String>>>) -> Arc<Self> {
        Arc::new(Self {
            changes: watch::channel(DeviceFacts::default()).0,
            legacy_name,
            next_instance: AtomicU64::new(0),
        })
    }

    pub fn subscribe(&self) -> watch::Receiver<DeviceFacts> {
        self.changes.subscribe()
    }

    pub fn snapshot(&self) -> DeviceFacts {
        self.changes.borrow().clone()
    }

    /// The returned lifetime must be stored after the actual fd resource, so
    /// it is dropped only once that resource has closed.
    pub fn attach(self: &Arc<Self>, name: String, ifindex: u32) -> TunDeviceLifetime {
        self.attach_with_ownership(name, ifindex, true)
    }

    pub fn attach_external(self: &Arc<Self>, name: String, ifindex: u32) -> TunDeviceLifetime {
        self.attach_with_ownership(name, ifindex, false)
    }

    fn attach_with_ownership(
        self: &Arc<Self>,
        name: String,
        ifindex: u32,
        owned: bool,
    ) -> TunDeviceLifetime {
        let instance = self
            .next_instance
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .expect("TUN instance identity exhausted")
            + 1;
        let id = DeviceId::new(ifindex, owned.then_some(instance));
        self.changes.send_modify(|facts| {
            facts.live.insert(instance, id.clone());
            facts.active = Some(ActiveDevice {
                id: id.clone(),
                registration: instance,
                name,
                ready: false,
            });
            *self.legacy_name.lock().unwrap() = None;
        });
        TunDeviceLifetime {
            state: Arc::downgrade(self),
            id,
            registration: instance,
        }
    }

    pub fn mark_ready(&self, registration: u64) -> Option<String> {
        let mut name = None;
        self.changes.send_if_modified(|facts| {
            let Some(active) = facts
                .active
                .as_mut()
                .filter(|active| active.registration == registration)
            else {
                return false;
            };
            name = Some(active.name.clone());
            if active.ready {
                return false;
            }
            active.ready = true;
            *self.legacy_name.lock().unwrap() = name.clone();
            true
        });
        name
    }

    pub fn mark_unready(&self) {
        self.changes.send_if_modified(|facts| {
            let Some(active) = facts.active.as_mut() else {
                return false;
            };
            if !active.ready {
                return false;
            }
            active.ready = false;
            true
        });
    }

    #[cfg(test)]
    pub fn set_for_test(self: &Arc<Self>, ifindex: Option<u32>) {
        let name = ifindex.map(|index| format!("test-{index}"));
        let lifetime = ifindex.map(|index| self.attach(name.unwrap(), index));
        if let Some(lifetime) = lifetime {
            self.mark_ready(lifetime.registration());
            // Test setters explicitly replace and retire their synthetic
            // device facts; they do not own a real fd.
            self.changes.send_modify(|facts| {
                facts.live = BTreeMap::from([(lifetime.registration, lifetime.id.clone())]);
            });
            let mut lifetime = lifetime;
            lifetime.state = Weak::new();
        } else {
            self.changes.send_modify(|facts| {
                facts.active = None;
                facts.live.clear();
            });
            *self.legacy_name.lock().unwrap() = None;
        }
    }
}

/// Metadata ownership carried by the actual TUN fd, without keeping the Host
/// or a device alive. An old lifetime cannot erase a newer active device.
pub(crate) struct TunDeviceLifetime {
    state: Weak<TunDeviceState>,
    id: DeviceId,
    registration: u64,
}

impl TunDeviceLifetime {
    pub fn registration(&self) -> u64 {
        self.registration
    }

    #[cfg(test)]
    pub fn id(&self) -> &DeviceId {
        &self.id
    }
}

impl Drop for TunDeviceLifetime {
    fn drop(&mut self) {
        let Some(state) = self.state.upgrade() else {
            return;
        };
        state.changes.send_if_modified(|facts| {
            if facts.live.remove(&self.registration).as_ref() != Some(&self.id) {
                return false;
            }
            if facts
                .active
                .as_ref()
                .is_some_and(|active| active.registration == self.registration)
            {
                facts.active = None;
                *state.legacy_name.lock().unwrap() = None;
            }
            true
        });
    }
}

/// Field order is intentional: close the actual resource before its lifetime
/// publishes destruction. Splitting I/O may share this wrapper, never its guard.
pub(crate) struct DeviceResource<T> {
    resource: T,
    _lifetime: Option<TunDeviceLifetime>,
}

impl<T> DeviceResource<T> {
    /// Shared or borrowed devices retain their existing lifetime authority.
    pub fn untracked(resource: T) -> Self {
        Self { resource, _lifetime: None }
    }

    pub fn new(resource: T, lifetime: TunDeviceLifetime) -> Self {
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
    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().resource).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.resource.is_write_vectored()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_readiness_and_liveness_are_independent() {
        let name = Arc::new(Mutex::new(None));
        let state = TunDeviceState::new(name.clone());
        let old = state.attach("old".into(), 7);
        state.mark_ready(old.registration());
        let new = state.attach("new".into(), 8);
        assert_eq!(state.snapshot().live.len(), 2);
        assert!(!state.snapshot().active.as_ref().unwrap().ready);
        assert!(!state.snapshot().destroyed(old.id()));
        assert!(name.lock().unwrap().is_none());
        state.mark_ready(new.registration());
        assert_eq!(state.mark_ready(old.registration()), None);
        assert_eq!(*name.lock().unwrap(), Some("new".into()));
        drop(old);
        assert_eq!(
            state.snapshot().live,
            BTreeMap::from([(new.registration, new.id.clone())])
        );
        assert_eq!(*name.lock().unwrap(), Some("new".into()));
        drop(new);
        assert!(state.snapshot().active.is_none());
        assert!(name.lock().unwrap().is_none());
    }

    #[test]
    fn same_index_recreation_is_visible_even_if_notifications_coalesce() {
        let state = TunDeviceState::new(Arc::new(Mutex::new(None)));
        let mut changed = state.subscribe();
        let old = state.attach("et".into(), 7);
        let old_id = old.id.clone();
        state.mark_ready(old.registration());
        changed.mark_unchanged();
        drop(old);
        let new = state.attach("et".into(), 7);
        state.mark_ready(new.registration());
        assert!(changed.has_changed().unwrap());
        assert_ne!(&old_id, new.id());
        assert!(state.snapshot().destroyed(&old_id));
        assert!(!state.snapshot().destroyed(new.id()));
    }

    #[test]
    fn external_device_claims_do_not_assert_kernel_destruction() {
        let state = TunDeviceState::new(Arc::new(Mutex::new(None)));
        let old = state.attach_external("et".into(), 7);
        let new = state.attach_external("et".into(), 7);
        assert_eq!(old.id(), new.id());
        assert_ne!(old.registration(), new.registration());
        state.mark_ready(new.registration());
        assert_eq!(state.mark_ready(old.registration()), None);
        let id = new.id.clone();
        drop(old);
        assert_eq!(
            state.snapshot().active.unwrap().registration,
            new.registration()
        );
        drop(new);
        assert!(state.snapshot().active.is_none());
        assert!(!state.snapshot().destroyed(&id));
    }

    #[cfg(unix)]
    #[test]
    fn split_resource_publishes_destruction_after_the_last_fd_closes() {
        use std::os::fd::OwnedFd;
        struct FdProbe {
            _fd: OwnedFd,
            state: Arc<TunDeviceState>,
            id: DeviceId,
        }
        impl Drop for FdProbe {
            fn drop(&mut self) {
                assert!(!self.state.snapshot().destroyed(&self.id));
            }
        }
        let state = TunDeviceState::new(Arc::new(Mutex::new(None)));
        let lifetime = state.attach("et".into(), 7);
        let id = lifetime.id.clone();
        let (read, write) = nix::unistd::pipe().unwrap();
        let resource = DeviceResource::new(
            FdProbe {
                _fd: read,
                state: state.clone(),
                id: id.clone(),
            },
            lifetime,
        );
        let (read_half, write_half) = futures::lock::BiLock::new(resource);
        drop(read_half);
        assert!(!state.snapshot().destroyed(&id));
        drop(write_half);
        assert!(state.snapshot().destroyed(&id));
        assert_eq!(
            nix::unistd::write(&write, b"closed").unwrap_err(),
            nix::errno::Errno::EPIPE
        );
    }
}

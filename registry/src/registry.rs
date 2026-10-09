use educe::Educe;
use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::{fmt, mem};
use tokio::sync::watch;

/// Table-internal entry identity.
///
/// Ids are allocated in increasing order and never reused, so an operation that
/// still refers to an old id can never address a newer entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct EntryId(u64);

impl EntryId {
    fn next() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        Self(
            NEXT.try_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
                .unwrap(),
        )
    }
}

#[derive(Debug)]
struct Shared<T> {
    /// `Some(entries)` while the registry is open; `None` once it is closed.
    entries: Mutex<Option<BTreeMap<EntryId, Arc<T>>>>,
    signal: watch::Sender<()>,
}

impl<T> Shared<T> {
    fn new(signal: watch::Sender<()>) -> Self {
        Self {
            entries: Mutex::new(Some(BTreeMap::new())),
            signal,
        }
    }

    fn entries(&self) -> Option<MappedMutexGuard<'_, BTreeMap<EntryId, Arc<T>>>> {
        MutexGuard::try_map(self.entries.lock(), Option::as_mut).ok()
    }
}

/// Lifetime-bound, observable registry of live state claims.
///
/// Cloning a `Registry` shares the same entries and change signal. Registries
/// carry no lifecycle authority: the registry does not close when the last
/// clone is dropped, and a temporary `Weak::upgrade` can keep the shared state
/// alive past the last clone. A host that needs a stop boundary calls
/// [`Registry::close`].
#[derive(Educe, Debug)]
#[educe(Clone(bound = ""))]
pub struct Registry<T> {
    shared: Arc<Shared<T>>,
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        let (signal, _) = watch::channel(());
        Self::new(signal)
    }
}

impl<T> Registry<T> {
    fn entries(&self) -> Option<MappedMutexGuard<'_, BTreeMap<EntryId, Arc<T>>>> {
        self.shared.entries()
    }

    /// Creates a registry that publishes its changes through `signal`.
    ///
    /// `watch::Sender` is cloneable, so the registry can share one signal with
    /// other registries or with producers that commit external facts; a
    /// notification from any of them wakes consumers of this registry.
    pub fn new(signal: watch::Sender<()>) -> Self {
        Self {
            shared: Arc::new(Shared::new(signal)),
        }
    }

    /// Subscribes a consumer to this registry's invalidation notifications.
    ///
    /// The returned receiver starts with the current value marked as seen:
    /// consumers follow `mark_unchanged` → `snapshot` → work → `changed`.
    pub fn subscribe(&self) -> watch::Receiver<()> {
        self.shared.signal.subscribe()
    }

    /// Registers `value` and returns the claim that keeps it live.
    ///
    /// Returns `None` once the registry is closed. The payload is destroyed
    /// outside the lock either way.
    pub fn register(&self, value: T) -> Option<Registration<T>> {
        // Do not hold the lock when T::Drop is triggered
        self.entries()
            .map(|mut entries| {
                let id = EntryId::next();
                entries.insert(id, Arc::new(value));
                id
            })
            // guard dropped here
            .map(|id| {
                self.shared.signal.send_replace(());
                Registration {
                    shared: Arc::downgrade(&self.shared),
                    id,
                }
            })
    }

    /// Returns the live values in registration order.
    ///
    /// Only the `Arc` handles are cloned; `T` is never copied, compared or
    /// formatted. The result is a point-in-time snapshot: later modifications
    /// do not change it, and holding it does not keep an entry in later reads.
    pub fn snapshot(&self) -> Vec<Arc<T>> {
        self.entries()
            .map(|entries| entries.values().cloned().collect())
            .unwrap_or_default()
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.entries().map_or(0, |entries| entries.len())
    }

    /// Returns `true` when there are no live entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Closes the registry: withdraws every entry and rejects later writes.
    ///
    /// Returns `true` for the first close and `false` for repeated calls.
    /// Closing is irreversible and does not destroy the change signal: senders
    /// shared with other producers keep notifying, so consumers must use their
    /// own stop condition rather than relying on `changed()` to fail.
    pub fn close(&self) -> bool {
        // The taken map is bound before the lock guard is released by the end
        // of this statement, so payload destructors run outside the lock.
        let entries = self.shared.entries.lock().take();

        entries
            .map(|_| self.shared.signal.send_replace(()))
            .is_some()
    }
}

/// One publisher's ownership-bound claim inside a [`Registry`].
///
/// A `Registration` is not `Clone`; to share one registration between owners,
/// wrap it in an `Arc` at the call site. Dropping it withdraws its entry
/// synchronously.
pub struct Registration<T> {
    shared: Weak<Shared<T>>,
    id: EntryId,
}

impl<T> Registration<T> {
    /// Returns the currently registered value.
    ///
    /// `None` after the entry is withdrawn, after the registry is closed, or
    /// after the shared state is destroyed.
    pub fn get(&self) -> Option<Arc<T>> {
        let shared = self.shared.upgrade()?;

        shared.entries()?.get(&self.id).cloned()
    }

    /// Replaces the registered value, keeping this entry's position.
    ///
    /// Returns `None` after the registry is closed or once the shared state is
    /// destroyed. The retired value is destroyed outside the lock.
    pub fn replace(&self, value: T) -> Option<()> {
        let shared = self.shared.upgrade()?;

        shared
            .entries()
            .and_then(|mut entries| Some(mem::replace(entries.get_mut(&self.id)?, Arc::new(value))))
            .map(|_| shared.signal.send_replace(()))
    }
}

impl<T> Drop for Registration<T> {
    fn drop(&mut self) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };

        if shared
            .entries()
            .and_then(|mut entries| entries.remove(&self.id))
            .is_some()
        {
            shared.signal.send_replace(())
        }
    }
}

impl<T: Debug> Debug for Registration<T> {
    /// Reports the entry id and whether the claim is still live; the payload is
    /// never formatted.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registration")
            .field("shared", &self.shared.upgrade())
            .field("id", &self.id)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn values(registry: &Registry<u32>) -> Vec<u32> {
        registry.snapshot().iter().map(|value| **value).collect()
    }

    #[test]
    fn snapshot_preserves_order_and_sources_are_independent() {
        let registry = Registry::default();
        let a = registry.register(1).unwrap();
        let b = registry.register(2).unwrap();
        let c = registry.register(3).unwrap();
        assert_eq!(values(&registry), vec![1, 2, 3]);

        // replace keeps the entry's position in registration order
        b.replace(20).unwrap();
        assert_eq!(values(&registry), vec![1, 20, 3]);

        // one registration never observes another one's writes
        a.replace(10).unwrap();
        assert_eq!(*c.get().unwrap(), 3);
        assert_eq!(values(&registry), vec![10, 20, 3]);

        drop(b);
        assert_eq!(values(&registry), vec![10, 3]);
    }

    #[test]
    fn ids_are_monotonic_and_never_reused() {
        let registry = Registry::default();
        let first = registry.register(1).unwrap();
        let first_id = first.id;
        drop(first);

        let second = registry.register(2).unwrap();
        assert!(second.id > first_id, "the id counter must not rewind");
    }

    #[test]
    fn a_withdrawn_entry_does_not_shadow_a_new_registration() {
        let registry = Registry::default();
        let lease = registry.register(1).unwrap();
        let old = registry.snapshot().pop().unwrap();
        drop(lease);

        let new_lease = registry.register(2).unwrap();
        assert_eq!(values(&registry), vec![2]);
        assert_eq!(*new_lease.get().unwrap(), 2);
        // The historical handle still reads the old payload, but grants nothing.
        assert_eq!(*old, 1);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn historical_snapshots_do_not_keep_entries_alive() {
        let registry = Registry::default();
        let lease = registry.register(1).unwrap();
        let old = registry.snapshot().pop().unwrap();

        lease.replace(2).unwrap();
        let new = registry.snapshot().pop().unwrap();
        assert_eq!(*old, 1);
        assert_eq!(*new, 2);
        assert!(!Arc::ptr_eq(&old, &new));

        drop(lease);
        assert!(registry.snapshot().is_empty());
        assert_eq!(*old, 1, "the old Arc keeps the payload, not the claim");
    }

    #[test]
    fn registration_storm_leaves_no_entries() {
        let registry = Registry::default();
        for i in 0..10_000u32 {
            let lease = registry.register(i).unwrap();
            if i % 3 == 0 {
                lease.replace(i).unwrap();
            }
            drop(lease);
        }
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.snapshot().is_empty());
    }

    #[test]
    fn commit_notifies_after_the_state_is_readable() {
        let registry = Registry::default();
        let mut rx = registry.subscribe();

        rx.mark_unchanged();
        let lease = registry.register(7u32).unwrap();
        assert_eq!(values(&registry), vec![7]);
        assert!(rx.has_changed().unwrap());

        rx.mark_unchanged();
        lease.replace(8).unwrap();
        assert_eq!(values(&registry), vec![8]);
        assert!(rx.has_changed().unwrap());

        rx.mark_unchanged();
        drop(lease);
        assert!(registry.is_empty());
        assert!(rx.has_changed().unwrap());

        let _lease = registry.register(9).unwrap();
        rx.mark_unchanged();
        assert!(registry.close());
        assert!(registry.is_empty());
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn rejected_and_repeated_operations_do_not_notify() {
        let registry = Registry::<u32>::default();
        let lease = registry.register(1).unwrap();
        assert!(registry.close());

        // A subscriber created after close starts from the current value.
        let rx = registry.subscribe();
        assert!(!rx.has_changed().unwrap());

        assert!(!registry.close(), "repeated close");
        assert!(registry.register(2).is_none(), "rejected register");
        assert!(lease.replace(3).is_none(), "rejected replace");
        drop(lease);
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn modifications_without_receivers_succeed() {
        let registry = Registry::<u32>::default();
        let lease = registry.register(1).unwrap();
        lease.replace(2).unwrap();
        drop(lease);
        assert!(registry.register(3).is_some());
        assert!(registry.close());

        // Notifications are not replayed to subscribers that did not exist.
        let rx = registry.subscribe();
        assert!(!rx.has_changed().unwrap());
    }

    #[test]
    fn subscribers_track_changes_independently() {
        let registry = Registry::<u32>::default();
        let mut rx1 = registry.subscribe();
        let mut rx2 = registry.subscribe();
        rx1.mark_unchanged();
        rx2.mark_unchanged();

        // Several modifications may coalesce into one unseen change.
        registry.register(1).unwrap();
        registry.register(2).unwrap();
        assert!(rx1.has_changed().unwrap());
        assert!(rx2.has_changed().unwrap());

        rx1.mark_unchanged();
        assert!(!rx1.has_changed().unwrap());
        assert!(rx2.has_changed().unwrap(), "one consumer's ack is its own");
    }

    #[test]
    fn registries_can_share_one_signal() {
        let (signal, _keep_alive) = watch::channel(());
        let a = Registry::<u32>::new(signal.clone());
        let b = Registry::<u32>::new(signal.clone());

        let mut rx = a.subscribe();
        rx.mark_unchanged();
        b.register(1).unwrap();
        assert!(rx.has_changed().unwrap());

        rx.mark_unchanged();
        signal.send_replace(());
        assert!(rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn close_revokes_writes_but_keeps_the_signal_alive() {
        let (signal, _keep_alive) = watch::channel(());
        let registry = Registry::<u32>::new(signal.clone());
        let lease = registry.register(1).unwrap();
        let mut rx = registry.subscribe();
        rx.mark_unchanged();

        assert!(registry.close());
        assert!(rx.has_changed().unwrap());
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        assert!(registry.snapshot().is_empty());
        assert!(lease.get().is_none());
        assert!(registry.register(2).is_none());
        assert!(lease.replace(3).is_none());

        // close is not a channel disconnect: an external sender still notifies.
        rx.mark_unchanged();
        signal.send_replace(());
        assert!(rx.has_changed().unwrap());

        // and changed() does not report disconnection while a sender lives
        rx.mark_unchanged();
        assert!(
            tokio::time::timeout(Duration::from_millis(50), rx.changed())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn registrations_go_inert_after_the_shared_state_is_destroyed() {
        let registry = Registry::<u32>::default();
        let lease = registry.register(1).unwrap();
        let mut rx = registry.subscribe();
        drop(registry);

        assert!(lease.get().is_none());
        assert!(lease.replace(2).is_none());
        drop(lease); // late drop is a no-op

        // Only after the pending change is consumed do all senders being gone
        // surface as Err.
        let drained = tokio::time::timeout(Duration::from_secs(5), async {
            while rx.changed().await.is_ok() {}
        })
        .await;
        assert!(drained.is_ok(), "changed() never reported disconnection");
    }

    #[test]
    fn payloads_need_neither_clone_nor_debug() {
        struct Opaque(#[allow(dead_code)] u32);

        let registry = Registry::<Opaque>::default();
        let lease = registry.register(Opaque(1)).unwrap();
        lease.replace(Opaque(2)).unwrap();
        assert_eq!(registry.snapshot().len(), 1);
        assert_eq!(lease.get().unwrap().0, 2);
        drop(lease);
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_and_registration_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        struct Opaque;
        assert_send_sync::<Registry<Opaque>>();
        assert_send_sync::<Registration<Opaque>>();
    }

    /// Shared state of the re-entrancy probe: the same registry is reached from
    /// inside a payload destructor.
    struct ProbeShared {
        registry: Arc<Registry<DropProbe>>,
        snapshots: AtomicUsize,
        registered: AtomicUsize,
        rejected: AtomicUsize,
    }

    /// Payload whose destructor calls back into the registry.
    ///
    /// `shared: None` marks a callback-free probe used for the re-entrant
    /// registration, so a rejected payload cannot cascade.
    struct DropProbe {
        shared: Option<Arc<ProbeShared>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            let Some(shared) = self.shared.take() else {
                return;
            };
            // Both calls would deadlock if the library dropped payloads while
            // holding its state lock.
            let _ = shared.registry.snapshot();
            shared.snapshots.fetch_add(1, Ordering::SeqCst);
            match shared.registry.register(DropProbe { shared: None }) {
                Some(lease) => {
                    shared.registered.fetch_add(1, Ordering::SeqCst);
                    std::mem::forget(lease);
                }
                None => {
                    shared.rejected.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
    }

    fn probe(shared: &Arc<ProbeShared>) -> DropProbe {
        DropProbe {
            shared: Some(Arc::clone(shared)),
        }
    }

    /// Runs `f` on another thread, returns its value, and fails if it does not
    /// finish in time. Returning the value keeps anything the caller still owns
    /// (such as a lease) out of the worker thread's implicit drops.
    fn run_off_thread<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> R {
        let (result_tx, result_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = f();
            let _ = result_tx.send(result);
        });
        let result = result_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("payload destructor deadlocked on the registry lock");
        worker.join().unwrap();
        result
    }

    fn probe_registry() -> (Arc<Registry<DropProbe>>, Arc<ProbeShared>) {
        let registry = Arc::new(Registry::default());
        let shared = Arc::new(ProbeShared {
            registry: Arc::clone(&registry),
            snapshots: AtomicUsize::new(0),
            registered: AtomicUsize::new(0),
            rejected: AtomicUsize::new(0),
        });
        (registry, shared)
    }

    #[test]
    fn replace_drops_the_retired_payload_outside_the_lock() {
        let (registry, shared) = probe_registry();
        let lease = registry.register(probe(&shared)).unwrap();

        let worker_shared = Arc::clone(&shared);
        // The worker returns the lease so that the main thread, not the
        // worker's implicit drops, decides when the entry is withdrawn.
        let _lease = run_off_thread(move || {
            lease.replace(probe(&worker_shared)).unwrap();
            lease
        });

        assert_eq!(shared.snapshots.load(Ordering::SeqCst), 1);
        assert_eq!(shared.registered.load(Ordering::SeqCst), 1);
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 0);

        // The re-entrant probe is still registered; closing destroys it (and
        // the replaced one) after the registry is marked closed.
        registry.close();
        assert_eq!(shared.registered.load(Ordering::SeqCst), 1);
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn registration_drop_runs_outside_the_lock() {
        let (registry, shared) = probe_registry();
        let lease = registry.register(probe(&shared)).unwrap();

        run_off_thread(move || drop(lease));

        assert_eq!(shared.snapshots.load(Ordering::SeqCst), 1);
        assert_eq!(shared.registered.load(Ordering::SeqCst), 1);
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 0);

        registry.close();
        assert!(registry.is_empty());
    }

    #[test]
    fn close_drops_payloads_outside_the_lock() {
        let (registry, shared) = probe_registry();
        let _lease = registry.register(probe(&shared)).unwrap();

        // The payload destructor must observe the closed registry: it re-enters
        // after the entries are taken and must not deadlock on the state lock.
        let registry_holder = Arc::clone(&registry);
        run_off_thread(move || {
            registry_holder.close();
        });

        assert_eq!(shared.snapshots.load(Ordering::SeqCst), 1);
        assert_eq!(shared.registered.load(Ordering::SeqCst), 0);
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 1);
        assert!(registry.is_empty());
    }

    #[test]
    fn rejected_writes_drop_payloads_outside_the_lock() {
        let (registry, shared) = probe_registry();
        let lease = registry.register(probe(&shared)).unwrap();
        assert!(registry.close());
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 1);

        // Rejected register: the new payload is destroyed outside the lock and
        // observes the closed registry.
        let registry_holder = Arc::clone(&registry);
        let worker_shared = Arc::clone(&shared);
        run_off_thread(move || {
            assert!(registry_holder.register(probe(&worker_shared)).is_none());
        });
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 2);

        // Rejected replace: same for the value that never gets committed.
        let worker_shared = Arc::clone(&shared);
        let _lease = run_off_thread(move || {
            assert!(lease.replace(probe(&worker_shared)).is_none());
            lease
        });
        assert_eq!(shared.rejected.load(Ordering::SeqCst), 3);
        assert_eq!(shared.snapshots.load(Ordering::SeqCst), 3);
    }
}

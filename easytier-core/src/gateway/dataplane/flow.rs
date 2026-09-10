//! Shared data-plane flow registration and ownership.

use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use atomic_shim::AtomicU64;
use dashmap::{DashMap, mapref::entry::Entry};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum FlowKind {
    Udp = 1,
    Tcp = 2,
    TcpListen = 3,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub kind: FlowKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowCountChange {
    pub previous: usize,
    pub current: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowInsert {
    pub replaced: bool,
    pub count: FlowCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowRemoval {
    pub removed: bool,
    pub count: FlowCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FlowRetain {
    pub removed: usize,
    pub count: FlowCountChange,
}

pub(crate) struct FlowTable<V> {
    entries: DashMap<FlowKey, RegisteredFlow<V>>,
    count: AtomicUsize,
    next_registration: AtomicU64,
}

struct RegisteredFlow<V> {
    registration: u64,
    value: V,
}

pub(crate) struct FlowLease<V> {
    table: Arc<FlowTable<V>>,
    entry: FlowKey,
    registration: u64,
    active: bool,
}

impl<V> FlowLease<V> {
    pub fn register(table: Arc<FlowTable<V>>, entry: FlowKey, value: V) -> (Self, FlowInsert) {
        let (registration, insert) = table.insert_registered(entry.clone(), value);
        (
            Self {
                table,
                entry,
                registration,
                active: true,
            },
            insert,
        )
    }

    pub fn try_register(table: Arc<FlowTable<V>>, entry: FlowKey, value: V) -> Option<Self> {
        let registration = table.try_insert_registered(entry.clone(), value)?;
        Some(Self {
            table,
            entry,
            registration,
            active: true,
        })
    }
}

impl<V> Drop for FlowLease<V> {
    fn drop(&mut self) {
        if self.active {
            self.table
                .remove_registration(&self.entry, self.registration);
        }
    }
}

impl<V> Default for FlowTable<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            count: AtomicUsize::new(0),
            next_registration: AtomicU64::new(1),
        }
    }
}

impl<V> FlowTable<V> {
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Returns whether no flow is visible or being published.
    ///
    /// New entries reserve their count before they become visible, while
    /// removals release their count after the entry is gone. Consequently a
    /// zero observed here is a safe fast-path signal without inspecting every
    /// DashMap shard.
    pub fn is_idle(&self) -> bool {
        self.count.load(Ordering::Acquire) == 0
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, entry: &FlowKey) -> bool {
        self.entries.contains_key(entry)
    }

    pub fn contains_destination_ip(&self, destination: IpAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key().dst.ip() == destination)
    }

    #[cfg(test)]
    pub fn with_entry<R>(&self, entry: &FlowKey, f: impl FnOnce(&V) -> R) -> Option<R> {
        self.entries.get(entry).map(|value| f(&value.value().value))
    }

    #[cfg(test)]
    pub fn insert(&self, entry: FlowKey, value: V) -> FlowInsert {
        self.insert_registered(entry, value).1
    }

    fn insert_registered(&self, entry: FlowKey, value: V) -> (u64, FlowInsert) {
        let registration = self.next_registration();
        match self.entries.entry(entry) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(RegisteredFlow {
                    registration,
                    value,
                });
                let count = self.count();
                (
                    registration,
                    FlowInsert {
                        replaced: true,
                        count: FlowCountChange {
                            previous: count,
                            current: count,
                        },
                    },
                )
            }
            Entry::Vacant(vacant) => {
                // Reserve the count while holding the shard lock so retain cannot
                // observe the entry before its count is accounted for.
                let count = self.increment_count();
                vacant.insert(RegisteredFlow {
                    registration,
                    value,
                });
                (
                    registration,
                    FlowInsert {
                        replaced: false,
                        count,
                    },
                )
            }
        }
    }

    #[cfg(test)]
    pub fn try_insert(&self, entry: FlowKey, value: V) -> bool {
        self.try_insert_registered(entry, value).is_some()
    }

    fn try_insert_registered(&self, entry: FlowKey, value: V) -> Option<u64> {
        match self.entries.entry(entry) {
            Entry::Occupied(_) => None,
            Entry::Vacant(vacant) => {
                let registration = self.next_registration();
                self.increment_count();
                vacant.insert(RegisteredFlow {
                    registration,
                    value,
                });
                Some(registration)
            }
        }
    }

    #[cfg(test)]
    pub fn remove(&self, entry: &FlowKey) -> FlowRemoval {
        let removed = self.entries.remove(entry).is_some();
        let count = if removed {
            self.decrement_count_by(1)
        } else {
            let count = self.count();
            FlowCountChange {
                previous: count,
                current: count,
            }
        };
        FlowRemoval { removed, count }
    }

    pub fn retain(&self, mut f: impl FnMut(&FlowKey, &mut V) -> bool) -> FlowRetain {
        let mut removed = 0;
        self.entries.retain(|entry, value| {
            let keep = f(entry, &mut value.value);
            if !keep {
                removed += 1;
            }
            keep
        });
        FlowRetain {
            removed,
            count: self.decrement_count_by(removed),
        }
    }

    pub fn clear(&self) -> FlowRetain {
        self.retain(|_, _| false)
    }

    fn increment_count(&self) -> FlowCountChange {
        let previous = self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_add(1)
            })
            .expect("flow count overflow");
        FlowCountChange {
            previous,
            current: previous + 1,
        }
    }

    fn next_registration(&self) -> u64 {
        self.next_registration.fetch_add(1, Ordering::Relaxed)
    }

    fn remove_registration(&self, entry: &FlowKey, registration: u64) -> FlowRemoval {
        let removed = self
            .entries
            .remove_if(entry, |_, flow| flow.registration == registration)
            .is_some();
        let count = if removed {
            self.decrement_count_by(1)
        } else {
            let count = self.count();
            FlowCountChange {
                previous: count,
                current: count,
            }
        };
        FlowRemoval { removed, count }
    }

    fn decrement_count_by(&self, delta: usize) -> FlowCountChange {
        if delta == 0 {
            let count = self.count();
            return FlowCountChange {
                previous: count,
                current: count,
            };
        }

        let previous = self
            .count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(delta)
            })
            .expect("flow count underflow");
        FlowCountChange {
            previous,
            current: previous - delta,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FlowKey, FlowKind, FlowLease, FlowTable};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    impl<V> FlowLease<V> {
        fn remove(mut self) -> super::FlowRemoval {
            self.active = false;
            self.table
                .remove_registration(&self.entry, self.registration)
        }
    }

    #[test]
    fn entry_kind_values_preserve_native_table_identity() {
        assert_eq!(FlowKind::Udp as u8, 1);
        assert_eq!(FlowKind::Tcp as u8, 2);
        assert_eq!(FlowKind::TcpListen as u8, 3);
    }

    fn table_entry(port: u16) -> FlowKey {
        FlowKey {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            kind: FlowKind::Tcp,
        }
    }

    #[test]
    fn flow_table_tracks_insert_replace_and_remove() {
        let table = FlowTable::default();
        let entry = table_entry(40000);

        let inserted = table.insert(entry.clone(), "first");
        assert!(!inserted.replaced);
        assert_eq!(inserted.count.previous, 0);
        assert_eq!(inserted.count.current, 1);
        assert!(!table.is_idle());
        assert_eq!(table.with_entry(&entry, |value| *value), Some("first"));

        let replaced = table.insert(entry.clone(), "second");
        assert!(replaced.replaced);
        assert_eq!(replaced.count.previous, 1);
        assert_eq!(replaced.count.current, 1);
        assert_eq!(table.with_entry(&entry, |value| *value), Some("second"));

        let removed = table.remove(&entry);
        assert!(removed.removed);
        assert_eq!(removed.count.previous, 1);
        assert_eq!(removed.count.current, 0);
        assert!(table.is_idle());

        let missing = table.remove(&entry);
        assert!(!missing.removed);
        assert_eq!(missing.count.previous, 0);
        assert_eq!(missing.count.current, 0);
    }

    #[test]
    fn flow_table_try_insert_and_retain_keep_count_consistent() {
        let table = FlowTable::default();
        let first = table_entry(40000);
        let second = table_entry(40001);

        assert!(table.try_insert(first.clone(), 1));
        assert!(!table.try_insert(first.clone(), 2));
        assert!(table.try_insert(second.clone(), 3));
        assert_eq!(table.count(), 2);
        assert!(table.contains_destination_ip(first.dst.ip()));

        let retained = table.retain(|entry, _| entry == &second);
        assert_eq!(retained.removed, 1);
        assert_eq!(retained.count.previous, 2);
        assert_eq!(retained.count.current, 1);
        assert!(!table.contains_key(&first));
        assert!(table.contains_key(&second));

        let cleared = table.clear();
        assert_eq!(cleared.removed, 1);
        assert_eq!(cleared.count.current, 0);
        assert!(table.is_empty());
    }

    #[test]
    fn entry_guard_owns_registration_lifetime() {
        let table = Arc::new(FlowTable::default());
        let entry = table_entry(40000);

        let (guard, insert) = FlowLease::register(table.clone(), entry.clone(), "first");
        assert!(!insert.replaced);
        assert!(table.contains_key(&entry));
        assert!(FlowLease::try_register(table.clone(), entry.clone(), "second").is_none());
        assert_eq!(table.with_entry(&entry, |value| *value), Some("first"));

        drop(guard);
        assert!(!table.contains_key(&entry));

        let guard = FlowLease::try_register(table.clone(), entry.clone(), "third").unwrap();
        let removal = guard.remove();
        assert!(removal.removed);
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn replaced_lease_cannot_remove_new_registration() {
        let table = Arc::new(FlowTable::default());
        let entry = table_entry(40000);
        let (old, _) = FlowLease::register(table.clone(), entry.clone(), "old");
        let (new, replaced) = FlowLease::register(table.clone(), entry.clone(), "new");
        assert!(replaced.replaced);

        drop(old);
        assert_eq!(table.with_entry(&entry, |value| *value), Some("new"));

        drop(new);
        assert!(!table.contains_key(&entry));
    }
}

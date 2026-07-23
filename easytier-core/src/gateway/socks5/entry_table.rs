use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::{DashMap, mapref::entry::Entry};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(crate) enum Socks5EntryKind {
    Udp = 1,
    Tcp = 2,
    TcpListen = 3,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(crate) struct Socks5Entry {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub kind: Socks5EntryKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socks5EntryCountChange {
    pub previous: usize,
    pub current: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socks5EntryInsert {
    pub replaced: bool,
    pub count: Socks5EntryCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socks5EntryRemoval {
    pub removed: bool,
    pub count: Socks5EntryCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Socks5EntryRetain {
    pub removed: usize,
    pub count: Socks5EntryCountChange,
}

pub(crate) struct Socks5EntryTable<V> {
    entries: DashMap<Socks5Entry, V>,
    count: AtomicUsize,
}

pub(crate) struct Socks5EntryGuard<V> {
    table: Arc<Socks5EntryTable<V>>,
    entry: Socks5Entry,
    active: bool,
}

impl<V> Socks5EntryGuard<V> {
    pub fn register(
        table: Arc<Socks5EntryTable<V>>,
        entry: Socks5Entry,
        value: V,
    ) -> (Self, Socks5EntryInsert) {
        let insert = table.insert(entry.clone(), value);
        (
            Self {
                table,
                entry,
                active: true,
            },
            insert,
        )
    }

    pub fn try_register(
        table: Arc<Socks5EntryTable<V>>,
        entry: Socks5Entry,
        value: V,
    ) -> Option<Self> {
        if !table.try_insert(entry.clone(), value) {
            return None;
        }
        Some(Self {
            table,
            entry,
            active: true,
        })
    }
}

impl<V> Drop for Socks5EntryGuard<V> {
    fn drop(&mut self) {
        if self.active {
            self.table.remove(&self.entry);
        }
    }
}

impl<V> Default for Socks5EntryTable<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            count: AtomicUsize::new(0),
        }
    }
}

impl<V> Socks5EntryTable<V> {
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, entry: &Socks5Entry) -> bool {
        self.entries.contains_key(entry)
    }

    pub fn contains_destination_ip(&self, destination: IpAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key().dst.ip() == destination)
    }

    pub fn with_entry<R>(&self, entry: &Socks5Entry, f: impl FnOnce(&V) -> R) -> Option<R> {
        self.entries.get(entry).map(|value| f(value.value()))
    }

    pub fn insert(&self, entry: Socks5Entry, value: V) -> Socks5EntryInsert {
        match self.entries.entry(entry) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(value);
                let count = self.count();
                Socks5EntryInsert {
                    replaced: true,
                    count: Socks5EntryCountChange {
                        previous: count,
                        current: count,
                    },
                }
            }
            Entry::Vacant(vacant) => {
                // Reserve the count while holding the shard lock so retain cannot
                // observe the entry before its count is accounted for.
                let count = self.increment_count();
                vacant.insert(value);
                Socks5EntryInsert {
                    replaced: false,
                    count,
                }
            }
        }
    }

    pub fn try_insert(&self, entry: Socks5Entry, value: V) -> bool {
        match self.entries.entry(entry) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                self.increment_count();
                vacant.insert(value);
                true
            }
        }
    }

    pub fn remove(&self, entry: &Socks5Entry) -> Socks5EntryRemoval {
        let removed = self.entries.remove(entry).is_some();
        let count = if removed {
            self.decrement_count_by(1)
        } else {
            let count = self.count();
            Socks5EntryCountChange {
                previous: count,
                current: count,
            }
        };
        Socks5EntryRemoval { removed, count }
    }

    pub fn retain(&self, mut f: impl FnMut(&Socks5Entry, &mut V) -> bool) -> Socks5EntryRetain {
        let mut removed = 0;
        self.entries.retain(|entry, value| {
            let keep = f(entry, value);
            if !keep {
                removed += 1;
            }
            keep
        });
        Socks5EntryRetain {
            removed,
            count: self.decrement_count_by(removed),
        }
    }

    pub fn clear(&self) -> Socks5EntryRetain {
        self.retain(|_, _| false)
    }

    pub fn shrink_to_fit(&self) {
        self.entries.shrink_to_fit();
    }

    fn increment_count(&self) -> Socks5EntryCountChange {
        let previous = self
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .unwrap_or_else(|count| count);
        Socks5EntryCountChange {
            previous,
            current: previous.saturating_add(1),
        }
    }

    fn decrement_count_by(&self, delta: usize) -> Socks5EntryCountChange {
        if delta == 0 {
            let count = self.count();
            return Socks5EntryCountChange {
                previous: count,
                current: count,
            };
        }

        let previous = self
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(delta))
            })
            .unwrap_or_else(|count| count);
        Socks5EntryCountChange {
            previous,
            current: previous.saturating_sub(delta),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Socks5Entry, Socks5EntryGuard, Socks5EntryKind, Socks5EntryTable};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    impl<V> Socks5EntryGuard<V> {
        fn remove(mut self) -> super::Socks5EntryRemoval {
            self.active = false;
            self.table.remove(&self.entry)
        }
    }

    #[test]
    fn entry_kind_values_preserve_native_table_identity() {
        assert_eq!(Socks5EntryKind::Udp as u8, 1);
        assert_eq!(Socks5EntryKind::Tcp as u8, 2);
        assert_eq!(Socks5EntryKind::TcpListen as u8, 3);
    }

    fn table_entry(port: u16) -> Socks5Entry {
        Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            kind: Socks5EntryKind::Tcp,
        }
    }

    #[test]
    fn entry_table_tracks_insert_replace_and_remove() {
        let table = Socks5EntryTable::default();
        let entry = table_entry(40000);

        let inserted = table.insert(entry.clone(), "first");
        assert!(!inserted.replaced);
        assert_eq!(inserted.count.previous, 0);
        assert_eq!(inserted.count.current, 1);
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

        let missing = table.remove(&entry);
        assert!(!missing.removed);
        assert_eq!(missing.count.previous, 0);
        assert_eq!(missing.count.current, 0);
    }

    #[test]
    fn entry_table_try_insert_and_retain_keep_count_consistent() {
        let table = Socks5EntryTable::default();
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
        let table = Arc::new(Socks5EntryTable::default());
        let entry = table_entry(40000);

        let (guard, insert) = Socks5EntryGuard::register(table.clone(), entry.clone(), "first");
        assert!(!insert.replaced);
        assert!(table.contains_key(&entry));
        assert!(Socks5EntryGuard::try_register(table.clone(), entry.clone(), "second").is_none());
        assert_eq!(table.with_entry(&entry, |value| *value), Some("first"));

        drop(guard);
        assert!(!table.contains_key(&entry));

        let guard = Socks5EntryGuard::try_register(table.clone(), entry.clone(), "third").unwrap();
        let removal = guard.remove();
        assert!(removal.removed);
        assert_eq!(table.count(), 0);
    }
}

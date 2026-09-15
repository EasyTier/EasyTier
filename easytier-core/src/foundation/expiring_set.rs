use std::{hash::Hash, time::Duration, time::Instant};

use dashmap::DashMap;

/// A thread-safe set whose entries expire after a per-insert TTL.
///
/// `contains` lazily removes expired entries, so periodic `cleanup` calls
/// are only needed to reclaim memory for keys that stop being read.
#[derive(Debug, Clone)]
pub struct ExpiringSet<K>
where
    K: Eq + Hash,
{
    entries: DashMap<K, Instant>,
}

impl<K> Default for ExpiringSet<K>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<K> ExpiringSet<K>
where
    K: Eq + Hash + Clone,
{
    pub fn insert(&self, key: K, ttl: Duration) {
        self.entries.insert(key, Instant::now() + ttl);
    }

    pub fn contains(&self, key: &K) -> bool {
        match self
            .entries
            .remove_if(key, |_, expires_at| *expires_at <= Instant::now())
        {
            // Existed and expired: removed while holding the shard lock, so a
            // concurrent insert of the same key cannot be dropped by us.
            Some(_) => false,
            // Not removed: either absent, or still fresh.
            None => self.entries.contains_key(key),
        }
    }

    pub fn cleanup(&self) {
        let now = Instant::now();
        self.entries.retain(|_, expires_at| *expires_at > now);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn expired_entries_are_reported_absent() {
        let set: ExpiringSet<u32> = ExpiringSet::default();
        set.insert(1, Duration::ZERO);
        set.insert(2, Duration::from_secs(3600));
        assert!(!set.contains(&1));
        assert!(set.contains(&2));
        set.cleanup();
        assert!(!set.entries.contains_key(&1));
    }
}

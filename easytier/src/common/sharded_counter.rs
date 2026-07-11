use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

const PUBLISH_INTERVAL: u64 = 256;

/// Counter optimized for long-lived worker threads.
///
/// Pending values below `PUBLISH_INTERVAL` live in `ThreadLocal` shards. The
/// shards are retained until this counter is dropped, so this is intended for
/// tokio workers or similarly long-lived threads rather than high-churn threads.
pub struct ShardedCounter {
    published: AtomicU64,
    locals: thread_local::ThreadLocal<AtomicU64>,
}

impl ShardedCounter {
    pub fn new() -> Self {
        Self {
            published: AtomicU64::new(0),
            locals: thread_local::ThreadLocal::new(),
        }
    }

    #[inline]
    #[cfg_attr(feature = "hotpath", hotpath::measure(impl_type = "ShardedCounter"))]
    pub fn add(&self, delta: u64) {
        let local = self.locals.get_or(|| AtomicU64::new(0));
        let v = local.load(Relaxed).saturating_add(delta);
        local.store(v, Relaxed);
        if v >= PUBLISH_INTERVAL {
            let pending = local.swap(0, Relaxed);
            if pending > 0 {
                self.published.fetch_add(pending, Relaxed);
            }
        }
    }

    #[inline]
    pub fn inc(&self) {
        self.add(1);
    }

    pub fn get(&self) -> u64 {
        self.locals
            .iter()
            .fold(self.published.load(Relaxed), |total, local| {
                total.saturating_add(local.load(Relaxed))
            })
    }

    pub fn reset(&self) {
        self.published.store(0, Relaxed);
        for local in self.locals.iter() {
            local.store(0, Relaxed);
        }
    }
}

impl Default for ShardedCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ShardedCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShardedCounter")
            .field("value", &self.get())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    #[test]
    fn sharded_counter_get_includes_other_thread_locals() {
        let counter = Arc::new(ShardedCounter::new());
        let thread_counter = Arc::clone(&counter);

        thread::spawn(move || {
            for _ in 0..10 {
                thread_counter.inc();
            }
        })
        .join()
        .unwrap();

        assert_eq!(counter.get(), 10);
    }

    #[test]
    fn sharded_counter_reset_clears_other_thread_locals() {
        let counter = Arc::new(ShardedCounter::new());
        let thread_counter = Arc::clone(&counter);

        thread::spawn(move || {
            for _ in 0..10 {
                thread_counter.inc();
            }
        })
        .join()
        .unwrap();

        counter.reset();

        assert_eq!(counter.get(), 0);
    }
}

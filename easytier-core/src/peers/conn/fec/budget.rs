use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub(super) const CONNECTION_LIMIT: usize = 4 * 1024 * 1024;

/// Shared by all FEC connections belonging to one instance, including foreign peers.
#[derive(Debug)]
pub struct FecInstanceBudget {
    limit: usize,
    used: AtomicUsize,
}

impl Default for FecInstanceBudget {
    fn default() -> Self {
        Self::new(64 * 1024 * 1024)
    }
}

impl FecInstanceBudget {
    pub fn new(limit_bytes: usize) -> Self {
        Self {
            limit: limit_bytes,
            used: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub fn used_bytes(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }
}

fn claim(counter: &AtomicUsize, limit: usize, bytes: usize) -> bool {
    counter
        .try_update(Ordering::AcqRel, Ordering::Relaxed, |used| {
            used.checked_add(bytes).filter(|&next| next <= limit)
        })
        .is_ok()
}

pub(super) struct Account {
    pub instance: Arc<FecInstanceBudget>,
    used: AtomicUsize,
    peak: AtomicUsize,
}

impl Account {
    pub fn new(instance: Arc<FecInstanceBudget>) -> Arc<Self> {
        Arc::new(Self {
            instance,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
        })
    }

    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        if !claim(&self.used, CONNECTION_LIMIT, bytes) {
            return None;
        }
        if !claim(&self.instance.used, self.instance.limit, bytes) {
            self.used.fetch_sub(bytes, Ordering::AcqRel);
            return None;
        }
        self.peak.fetch_max(self.used(), Ordering::Relaxed);
        Some(Reservation {
            account: self.clone(),
            bytes,
        })
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Relaxed)
    }

    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }
}

pub(super) struct Reservation {
    account: Arc<Account>,
    bytes: usize,
}

impl Reservation {
    pub fn grow(&mut self, bytes: usize) -> bool {
        let Some(mut extra) = self.account.reserve(bytes) else {
            return false;
        };
        self.bytes += bytes;
        extra.bytes = 0;
        true
    }

    pub fn split(&mut self, bytes: usize) -> Self {
        assert!(bytes <= self.bytes);
        self.bytes -= bytes;
        Self {
            account: self.account.clone(),
            bytes,
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.account.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.account
            .instance
            .used
            .fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

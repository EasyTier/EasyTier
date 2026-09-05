use std::{collections::VecDeque, sync::Mutex};

use tokio::sync::Notify;

struct HostListenerQueueState<T> {
    closed: bool,
    listeners: usize,
    pending: VecDeque<T>,
}

/// Bounded handoff from a synchronous Host callback to async listeners.
pub(crate) struct HostListenerQueue<T> {
    capacity: usize,
    state: Mutex<HostListenerQueueState<T>>,
    changed: Notify,
}

impl<T> HostListenerQueue<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            capacity,
            state: Mutex::new(HostListenerQueueState {
                closed: false,
                listeners: 0,
                pending: VecDeque::new(),
            }),
            changed: Notify::new(),
        }
    }

    pub(crate) fn register_listener(&self) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return false;
        }
        state.listeners += 1;
        true
    }

    pub(crate) fn unregister_listener(&self) {
        let pending = {
            let mut state = self.state.lock().unwrap();
            debug_assert!(state.listeners > 0);
            state.listeners -= 1;
            if state.listeners != 0 {
                return;
            }
            state.closed = true;
            std::mem::take(&mut state.pending)
        };
        drop(pending);
        self.changed.notify_waiters();
    }

    /// Constructs `T` only after the queue accepts Host-to-guest ownership.
    pub(crate) fn enqueue_with(&self, create: impl FnOnce() -> T) -> anyhow::Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if state.closed || state.listeners == 0 {
                anyhow::bail!("Host listener queue is closed");
            }
            if state.pending.len() >= self.capacity {
                anyhow::bail!("Host listener admission queue is full");
            }
            state.pending.push_back(create());
        }
        self.changed.notify_one();
        Ok(())
    }

    pub(crate) async fn accept(&self) -> Option<T> {
        loop {
            let changed = self.changed.notified();
            {
                let mut state = self.state.lock().unwrap();
                if let Some(item) = state.pending.pop_front() {
                    return Some(item);
                }
                if state.closed {
                    return None;
                }
            }
            changed.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use super::HostListenerQueue;

    struct DropCounter(Arc<AtomicUsize>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn constructs_only_after_listener_accepts_ownership() {
        let queue = HostListenerQueue::new(1);
        let constructed = AtomicUsize::new(0);

        assert!(
            queue
                .enqueue_with(|| {
                    constructed.fetch_add(1, Ordering::Relaxed);
                })
                .is_err()
        );
        assert_eq!(constructed.load(Ordering::Relaxed), 0);

        assert!(queue.register_listener());
        queue
            .enqueue_with(|| {
                constructed.fetch_add(1, Ordering::Relaxed);
            })
            .unwrap();
        assert!(
            queue
                .enqueue_with(|| {
                    constructed.fetch_add(1, Ordering::Relaxed);
                })
                .is_err()
        );
        assert_eq!(constructed.load(Ordering::Relaxed), 1);
        queue.accept().await.unwrap();
        queue.unregister_listener();
    }

    #[test]
    fn last_listener_closes_and_drains_pending_items() {
        let queue = HostListenerQueue::new(1);
        let drops = Arc::new(AtomicUsize::new(0));
        assert!(queue.register_listener());
        queue.enqueue_with(|| DropCounter(drops.clone())).unwrap();

        queue.unregister_listener();

        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(!queue.register_listener());
    }
}

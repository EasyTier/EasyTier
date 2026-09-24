//! Shared lifetime and close guards held by data-plane resources.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use crossbeam::atomic::AtomicCell;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use super::{DataPlaneError, DataPlaneErrorKind, DataPlaneResult};

pub(super) struct DataPlaneLease {
    consumers: Arc<DataPlaneConsumers>,
}

pub(super) struct DataPlaneConsumers {
    refs: Mutex<usize>,
    notifier: Notify,
}

pub(crate) struct DataPlaneConsumerLease {
    _lease: DataPlaneLease,
}

impl DataPlaneConsumerLease {
    pub(super) fn new(lease: DataPlaneLease) -> Self {
        Self { _lease: lease }
    }
}

impl DataPlaneLease {
    pub(super) fn acquire(consumers: Arc<DataPlaneConsumers>) -> Self {
        consumers.acquire();
        Self { consumers }
    }
}

impl Clone for DataPlaneLease {
    fn clone(&self) -> Self {
        self.consumers.clone_ref();
        Self {
            consumers: self.consumers.clone(),
        }
    }
}

impl Drop for DataPlaneLease {
    fn drop(&mut self) {
        self.consumers.release();
    }
}

impl DataPlaneConsumers {
    pub(super) fn new() -> Self {
        Self {
            refs: Mutex::new(0),
            notifier: Notify::new(),
        }
    }

    pub(super) fn has_consumers(&self) -> bool {
        *self.refs.lock().unwrap() != 0
    }

    pub(super) async fn changed(&self) {
        self.notifier.notified().await;
    }

    fn acquire(&self) {
        let mut refs = self.refs.lock().unwrap();
        *refs = refs
            .checked_add(1)
            .expect("data-plane consumer reference count overflow");
        drop(refs);
        self.notifier.notify_one();
    }

    fn clone_ref(&self) {
        let mut refs = self.refs.lock().unwrap();
        *refs = refs
            .checked_add(1)
            .expect("data-plane consumer reference count overflow");
    }

    fn release(&self) {
        let mut refs = self.refs.lock().unwrap();
        debug_assert_ne!(*refs, 0);
        *refs -= 1;
        let final_ref = *refs == 0;
        drop(refs);
        if final_ref {
            self.notifier.notify_one();
        }
    }
}

#[derive(Clone)]
pub(super) struct DataPlaneIoGuard {
    closed: CancellationToken,
    close_kind: Arc<AtomicCell<Option<DataPlaneErrorKind>>>,
}

impl DataPlaneIoGuard {
    pub(super) fn new() -> Self {
        Self {
            closed: CancellationToken::new(),
            close_kind: Arc::new(AtomicCell::new(None)),
        }
    }

    pub(super) fn ensure_open(&self) -> DataPlaneResult<()> {
        if self.closed.is_cancelled() {
            return Err(self.closed_error());
        }
        Ok(())
    }

    pub(super) fn is_closed(&self) -> bool {
        self.closed.is_cancelled()
    }

    pub(super) async fn closed(&self) {
        self.closed.cancelled().await;
    }

    pub(super) async fn while_open<T>(
        &self,
        future: impl Future<Output = DataPlaneResult<T>>,
    ) -> DataPlaneResult<T> {
        self.ensure_open()?;
        tokio::select! {
            biased;
            _ = self.closed() => Err(self.closed_error()),
            result = future => result,
        }
    }

    pub(super) fn closed_future(&self) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let closed = self.closed.clone();
        Box::pin(async move {
            closed.cancelled().await;
        })
    }

    pub(super) fn close(&self, kind: DataPlaneErrorKind) {
        if self.close_kind.compare_exchange(None, Some(kind)).is_ok() {
            self.closed.cancel();
        }
    }

    pub(super) fn closed_error(&self) -> DataPlaneError {
        let kind = self
            .close_kind
            .load()
            .unwrap_or(DataPlaneErrorKind::HandleClosed);
        DataPlaneError::new(kind, "data-plane I/O resource closed")
    }

    pub(super) fn closed_io_error(&self) -> std::io::Error {
        self.closed_error().into_io_error()
    }
}

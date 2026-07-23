//! Bounded current-thread Tokio turns for externally driven runtimes.

use std::{
    future::{Future, poll_fn},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Poll, Waker},
    time::Duration,
};

use tokio::runtime::Runtime;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RuntimeDriveOutcome {
    Quiescent,
    BudgetExhausted,
}

#[derive(Clone, Default)]
pub(super) struct RuntimeDriver {
    state: Arc<RuntimeDriverState>,
}

#[derive(Default)]
struct RuntimeDriverState {
    active: AtomicBool,
    quiescent: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl RuntimeDriver {
    pub(super) fn on_thread_park(&self) {
        if !self.state.active.load(Ordering::SeqCst) {
            return;
        }
        self.state.quiescent.store(true, Ordering::SeqCst);
        if let Some(waker) = self.state.waker.lock().unwrap().take() {
            waker.wake();
        }
    }

    pub(super) fn drive(&self, runtime: &Runtime) -> RuntimeDriveOutcome {
        // First give the timer driver a non-blocking turn. The quiescence hook
        // stays disabled here so an expired timer can wake its task.
        runtime.block_on(async {
            tokio::time::sleep(Duration::ZERO).await;
        });

        let _active = RuntimeDriverGuard::activate(self.state.as_ref());
        runtime.block_on(async {
            let budget = tokio::time::sleep(Duration::ZERO);
            tokio::pin!(budget);
            poll_fn(|context| {
                if self.state.poll_quiescent(context.waker()) {
                    return Poll::Ready(RuntimeDriveOutcome::Quiescent);
                }
                if budget.as_mut().poll(context).is_ready() {
                    return Poll::Ready(RuntimeDriveOutcome::BudgetExhausted);
                }
                Poll::Pending
            })
            .await
        })
    }
}

impl RuntimeDriverState {
    fn poll_quiescent(&self, waker: &Waker) -> bool {
        if self.quiescent.load(Ordering::SeqCst) {
            return true;
        }
        *self.waker.lock().unwrap() = Some(waker.clone());
        self.quiescent.load(Ordering::SeqCst)
    }
}

struct RuntimeDriverGuard<'a> {
    state: &'a RuntimeDriverState,
}

impl<'a> RuntimeDriverGuard<'a> {
    fn activate(state: &'a RuntimeDriverState) -> Self {
        state.quiescent.store(false, Ordering::SeqCst);
        *state.waker.lock().unwrap() = None;
        state.active.store(true, Ordering::SeqCst);
        Self { state }
    }
}

impl Drop for RuntimeDriverGuard<'_> {
    fn drop(&mut self) {
        self.state.active.store(false, Ordering::SeqCst);
        self.state.quiescent.store(false, Ordering::SeqCst);
        *self.state.waker.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use std::{future::poll_fn, sync::Arc, task::Poll};

    use tokio::{runtime::Builder, sync::Notify};

    use super::{RuntimeDriveOutcome, RuntimeDriver};

    fn runtime(driver: &RuntimeDriver) -> tokio::runtime::Runtime {
        let park_driver = driver.clone();
        Builder::new_current_thread()
            .enable_time()
            .event_interval(3)
            .on_thread_park(move || park_driver.on_thread_park())
            .build()
            .unwrap()
    }

    #[test]
    fn reports_budget_exhaustion_for_a_continuously_runnable_task() {
        let driver = RuntimeDriver::default();
        let runtime = runtime(&driver);
        let task = runtime.spawn(poll_fn(|context| {
            context.waker().wake_by_ref();
            Poll::<()>::Pending
        }));

        assert_eq!(driver.drive(&runtime), RuntimeDriveOutcome::BudgetExhausted);

        task.abort();
        while driver.drive(&runtime) == RuntimeDriveOutcome::BudgetExhausted {}
        assert!(task.is_finished());
    }

    #[test]
    fn reports_quiescence_while_waiting_for_an_external_wake() {
        let driver = RuntimeDriver::default();
        let runtime = runtime(&driver);
        let notify = Arc::new(Notify::new());
        let task_notify = notify.clone();
        let task = runtime.spawn(async move {
            task_notify.notified().await;
        });

        assert_eq!(driver.drive(&runtime), RuntimeDriveOutcome::Quiescent);
        assert!(!task.is_finished());

        notify.notify_one();
        while driver.drive(&runtime) == RuntimeDriveOutcome::BudgetExhausted {}
        assert!(task.is_finished());
    }
}

use std::sync::mpsc;

use anyhow::Context as _;
use tokio::{
    runtime::{Builder, Handle},
    sync::oneshot,
};

/// Keeps an instance's executor alive without dropping a Tokio runtime on one
/// of its workers. A borrowed executor remains owned by the embedding caller.
pub(crate) struct NativeInstanceExecutor {
    handle: Handle,
    shutdown: Option<oneshot::Sender<()>>,
}

impl NativeInstanceExecutor {
    pub(crate) fn owned(multi_thread: bool, worker_threads: usize) -> anyhow::Result<Self> {
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        std::thread::Builder::new()
            .name("easytier-runtime-owner".to_owned())
            .spawn(move || {
                let mut builder = if multi_thread {
                    let mut builder = Builder::new_multi_thread();
                    builder.worker_threads(worker_threads.max(2));
                    builder
                } else {
                    Builder::new_current_thread()
                };
                let runtime = match builder.enable_all().thread_name("easytier-worker").build() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };

                if ready_tx.send(Ok(runtime.handle().clone())).is_err() {
                    return;
                }

                // A current-thread runtime must stay inside block_on for its
                // spawned tasks, socket reactor, and timers to make progress.
                runtime.block_on(async {
                    let _ = shutdown_rx.await;
                });
                // Runtime shutdown can block, so it belongs on this owner
                // thread even when the last instance reference was a task.
            })
            .context("failed to start the instance runtime owner")?;

        let handle = ready_rx
            .recv()
            .context("instance runtime owner exited before initialization")?
            .context("failed to build the instance runtime")?;
        Ok(Self {
            handle,
            shutdown: Some(shutdown_tx),
        })
    }

    pub(crate) fn external(handle: Handle) -> Self {
        Self {
            handle,
            shutdown: None,
        }
    }

    pub(crate) fn handle(&self) -> Handle {
        self.handle.clone()
    }
}

impl Drop for NativeInstanceExecutor {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::runtime::RuntimeFlavor;

    use super::*;

    #[test]
    fn owned_multi_thread_runtime_honors_worker_count_and_minimum() {
        for (requested, expected) in [(0, 2), (1, 2), (3, 3)] {
            let executor = NativeInstanceExecutor::owned(true, requested).unwrap();
            let handle = executor.handle();
            assert_eq!(handle.runtime_flavor(), RuntimeFlavor::MultiThread);
            assert_eq!(handle.metrics().num_workers(), expected);
        }
    }

    #[test]
    fn owned_current_thread_runtime_drives_tasks_and_timers() {
        let executor = NativeInstanceExecutor::owned(false, 8).unwrap();
        let handle = executor.handle();
        assert_eq!(handle.runtime_flavor(), RuntimeFlavor::CurrentThread);
        assert_eq!(handle.metrics().num_workers(), 1);

        let (finished_tx, finished_rx) = mpsc::channel();
        handle.spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            finished_tx.send(()).unwrap();
        });
        finished_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the owned current-thread runtime must keep driving timers");
    }

    #[test]
    fn owned_runtime_can_be_released_by_its_own_task() {
        for multi_thread in [false, true] {
            let executor = NativeInstanceExecutor::owned(multi_thread, 2).unwrap();
            let handle = executor.handle();
            let (pending_tx, pending_rx) = mpsc::channel::<()>();
            handle.spawn(async move {
                let _pending = pending_tx;
                std::future::pending::<()>().await;
            });
            let (finished_tx, finished_rx) = mpsc::channel();
            handle.spawn(async move {
                drop(executor);
                finished_tx.send(()).unwrap();
            });
            finished_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("dropping the executor from its task must neither panic nor block");
            assert_eq!(
                pending_rx.recv_timeout(Duration::from_secs(5)),
                Err(mpsc::RecvTimeoutError::Disconnected),
                "releasing the owned runtime must also cancel its outstanding tasks"
            );
        }
    }

    #[test]
    fn dropping_external_executor_preserves_the_callers_runtime() {
        let runtime = Builder::new_current_thread().enable_all().build().unwrap();
        let executor = NativeInstanceExecutor::external(runtime.handle().clone());
        drop(executor);

        runtime.block_on(async {
            tokio::spawn(async {
                tokio::time::sleep(Duration::from_millis(10)).await;
            })
            .await
            .expect("dropping a borrowed executor must not shut down its runtime");
        });
    }
}

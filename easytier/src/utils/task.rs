use crate::utils::guard::ContextGuard;
use std::future::Future;
use std::io;
use std::ops::DerefMut;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

// region CancellableTask

#[derive(Debug)]
pub struct CancellableTask<Output> {
    handle: AbortOnDropHandle<Output>,
    token: CancellationToken,
}

impl<Output> CancellableTask<Output> {
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    pub fn with_handle(token: CancellationToken, handle: JoinHandle<Output>) -> Self {
        Self {
            handle: AbortOnDropHandle::new(handle),
            token,
        }
    }

    pub async fn stop(mut self, timeout: Option<Duration>) -> io::Result<Output> {
        self.token.cancel();

        match timeout {
            Some(timeout) => tokio::time::timeout(timeout, &mut self.handle)
                .await
                .map_err(|e| {
                    tracing::warn!("task stop timeout after {:?}, aborted", timeout);
                    io::Error::new(io::ErrorKind::TimedOut, e)
                })?,
            None => self.handle.await,
        }
        .map_err(Into::into)
    }
}

impl<Output: Send + 'static> CancellableTask<Output> {
    pub fn new<F>(token: CancellationToken, future: F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        Self::with_handle(token, tokio::spawn(future))
    }

    pub fn spawn<F>(factory: impl FnOnce(CancellationToken) -> F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        let token = CancellationToken::new();
        Self::new(token.clone(), factory(token))
    }

    pub fn child<F>(&self, factory: impl FnOnce(CancellationToken) -> F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        let token = self.token.clone();
        Self::new(token.clone(), factory(token))
    }
}

impl<Output> Future for CancellableTask<Output> {
    type Output = io::Result<Output>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle)
            .poll(cx)
            .map(|result| result.map_err(Into::into))
    }
}

// endregion

// region DetachableTask

type BoxTask<Task> = Pin<Box<Task>>;

struct DetachableTaskContext<Spawner, Task> {
    spawner: Spawner,
    task: Option<BoxTask<Task>>,
}
type DetachableTaskGuardHelper<Context> = ContextGuard<false, Context, fn(Context)>;
type DetachableTaskGuard<Spawner, Task> =
    DetachableTaskGuardHelper<DetachableTaskContext<Spawner, Task>>;

pub struct DetachableTask<Spawner, Task> {
    guard: DetachableTaskGuard<Spawner, Task>,
}

impl<Spawner, Task> DetachableTask<Spawner, Task> {
    pub fn detach(self) {
        self.guard.trigger()
    }

    pub fn reclaim(self) -> BoxTask<Task> {
        self.guard.defuse().task.unwrap()
    }
}

pub type TaskSpawner<Task, R = JoinHandle<<Task as Future>::Output>> = fn(BoxTask<Task>) -> R;

impl DetachableTask<fn(()), ()> {
    pub fn with_spawner<Spawner, _R, Task>(
        spawner: Spawner,
        task: Task,
    ) -> DetachableTask<Spawner, Task>
    where
        Spawner: FnOnce(BoxTask<Task>) -> _R,
    {
        let context = DetachableTaskContext {
            spawner,
            task: Some(Box::pin(task)),
        };
        DetachableTask {
            guard: crate::guard!([context] if let Some(task) = context.task {
                (context.spawner)(task);
            }),
        }
    }

    pub fn new<Task>(task: Task) -> DetachableTask<TaskSpawner<Task>, Task>
    where
        Task: Future + Send + 'static,
        <Task as Future>::Output: Send + 'static,
    {
        Self::with_spawner(|task| tokio::runtime::Handle::current().spawn(task), task)
    }
}

impl<Spawner: FnOnce(BoxTask<Task>) -> _R, _R, Task> IntoFuture for DetachableTask<Spawner, Task>
where
    Task: Future,
{
    type Output = Task::Output;
    type IntoFuture = DetachableTaskFuture<Spawner, Task>;

    fn into_future(self) -> Self::IntoFuture {
        DetachableTaskFuture { guard: self.guard }
    }
}

pub struct DetachableTaskFuture<Spawner, Task> {
    guard: DetachableTaskGuard<Spawner, Task>,
}

impl<Spawner: FnOnce(BoxTask<Task>) -> _R, _R, Task> Future for DetachableTaskFuture<Spawner, Task>
where
    Task: Future,
{
    type Output = Task::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };
        let context = this.guard.deref_mut();
        let mut task = context.task.take().expect("polled after completion");
        let poll = task.as_mut().poll(cx);
        if poll.is_pending() {
            context.task = Some(task);
        }
        poll
    }
}

// endregion

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{mpsc, oneshot};

    #[tokio::test]
    async fn spawn_when_dropped() {
        let spawned = Arc::new(AtomicBool::new(false));
        {
            let spawned = spawned.clone();
            let _task = DetachableTask::new(async move {
                spawned.store(true, Ordering::SeqCst);
            });
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while !spawned.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("task should be spawned on drop");
    }

    #[tokio::test]
    async fn await_completed_task_does_not_detach() {
        let spawn_count = Arc::new(AtomicUsize::new(0));
        let result = {
            let spawn_count = spawn_count.clone();
            DetachableTask::with_spawner(
                move |_| {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                },
                async { 7usize },
            )
            .await
        };

        assert_eq!(result, 7);
        assert_eq!(spawn_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn drop_without_await_and_runs_once() {
        let spawn_count = Arc::new(AtomicUsize::new(0));
        let (done_tx, done_rx) = oneshot::channel();

        {
            let spawn_count = spawn_count.clone();
            let _task = DetachableTask::with_spawner(
                move |f| {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let result = f.await;
                        let _ = done_tx.send(result);
                    });
                },
                async { 42usize },
            );
        }

        let detached_result = tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("detached task should finish")
            .expect("detached task should send result");

        assert_eq!(detached_result, 42);
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drop_after_await_still_detaches() {
        let spawn_count = Arc::new(AtomicUsize::new(0));
        let (value_tx, mut value_rx) = mpsc::channel(4);
        let (done_tx, done_rx) = oneshot::channel();

        let handle = {
            let future = async move {
                let mut sum = 0;
                while let Some(value) = value_rx.recv().await {
                    sum += value;
                }
                sum
            };

            let spawn_count = spawn_count.clone();
            let task = DetachableTask::with_spawner(
                move |f| {
                    spawn_count.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let result = f.await;
                        let _ = done_tx.send(result);
                    });
                },
                future,
            );

            tokio::spawn(task.into_future())
        };

        value_tx
            .send(10)
            .await
            .expect("value receiver should still exist");
        handle.abort();
        value_tx
            .send(11)
            .await
            .expect("value receiver should still exist");
        drop(value_tx);

        let detached_result = tokio::time::timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("detached polled task should finish")
            .expect("detached polled task should send result");

        assert_eq!(detached_result, 21);
        assert_eq!(spawn_count.load(Ordering::SeqCst), 1);
    }
}

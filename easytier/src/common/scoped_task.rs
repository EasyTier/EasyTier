//! This crate provides a wrapper type of Tokio's JoinHandle: `ScopedTask`, which aborts the task when it's dropped.
//! `ScopedTask` can still be awaited to join the child-task, and abort-on-drop will still trigger while it is being awaited.
//!
//! For example, if task A spawned task B but is doing something else, and task B is waiting for task C to join,
//! aborting A will also abort both B and C.

use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::task::JoinHandle;

#[derive(Debug)]
pub struct ScopedTask<T> {
    inner: JoinHandle<T>,
}

impl<T> Drop for ScopedTask<T> {
    fn drop(&mut self) {
        self.inner.abort()
    }
}

impl<T> Future for ScopedTask<T> {
    type Output = <JoinHandle<T> as Future>::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.inner).poll(cx)
    }
}

impl<T> From<JoinHandle<T>> for ScopedTask<T> {
    fn from(inner: JoinHandle<T>) -> Self {
        Self { inner }
    }
}

impl<T> Deref for ScopedTask<T> {
    type Target = JoinHandle<T>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::ScopedTask;
    use futures_util::future::pending;
    use std::sync::{Arc, RwLock};
    use tokio::task::yield_now;

    struct Sentry(Arc<RwLock<bool>>);
    impl Drop for Sentry {
        fn drop(&mut self) {
            *self.0.write().unwrap() = true
        }
    }

    #[tokio::test]
    async fn drop_while_not_waiting_for_join() {
        let dropped = Arc::new(RwLock::new(false));
        let sentry = Sentry(dropped.clone());
        let task = ScopedTask::from(tokio::spawn(async move {
            let _sentry = sentry;
            pending::<()>().await
        }));
        yield_now().await;
        assert!(!*dropped.read().unwrap());
        drop(task);
        yield_now().await;
        assert!(*dropped.read().unwrap());
    }

    #[tokio::test]
    async fn drop_while_waiting_for_join() {
        let dropped = Arc::new(RwLock::new(false));
        let sentry = Sentry(dropped.clone());
        let handle = tokio::spawn(async move {
            ScopedTask::from(tokio::spawn(async move {
                let _sentry = sentry;
                pending::<()>().await
            }))
            .await
            .unwrap()
        });
        yield_now().await;
        assert!(!*dropped.read().unwrap());
        handle.abort();
        yield_now().await;
        assert!(*dropped.read().unwrap());
    }

    #[tokio::test]
    async fn no_drop_only_join() {
        assert_eq!(
            ScopedTask::from(tokio::spawn(async {
                yield_now().await;
                5
            }))
            .await
            .unwrap(),
            5
        )
    }

    #[tokio::test]
    async fn manually_abort_before_drop() {
        let dropped = Arc::new(RwLock::new(false));
        let sentry = Sentry(dropped.clone());
        let task = ScopedTask::from(tokio::spawn(async move {
            let _sentry = sentry;
            pending::<()>().await
        }));
        yield_now().await;
        assert!(!*dropped.read().unwrap());
        task.abort();
        yield_now().await;
        assert!(*dropped.read().unwrap());
    }

    #[tokio::test]
    async fn manually_abort_then_join() {
        let dropped = Arc::new(RwLock::new(false));
        let sentry = Sentry(dropped.clone());
        let task = ScopedTask::from(tokio::spawn(async move {
            let _sentry = sentry;
            pending::<()>().await
        }));
        yield_now().await;
        assert!(!*dropped.read().unwrap());
        task.abort();
        yield_now().await;
        assert!(task.await.is_err());
    }
}

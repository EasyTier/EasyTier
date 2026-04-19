use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task::JoinError;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

#[derive(Debug)]
pub struct CancellableTask<Output: Send + 'static = ()> {
    handle: AbortOnDropHandle<Output>,
    token: CancellationToken,
}

impl<Output: Send + 'static> CancellableTask<Output> {
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    pub fn new<F>(
        token: Option<CancellationToken>,
        factory: impl FnOnce(CancellationToken) -> F,
    ) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        let token = token.unwrap_or_default();
        Self {
            handle: AbortOnDropHandle::new(tokio::spawn(factory(token.clone()))),
            token,
        }
    }

    pub fn spawn<F>(f: impl FnOnce(CancellationToken) -> F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        Self::new(None, f)
    }

    pub fn child<F>(&self, f: impl FnOnce(CancellationToken) -> F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        Self::new(Some(self.token.clone()), f)
    }

    pub fn with_token<F>(token: CancellationToken, future: F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        Self::new(Some(token), |_| future)
    }

    pub async fn stop(mut self, timeout: Option<Duration>) -> Result<Output, JoinError> {
        self.token.cancel();
        if let Some(timeout) = timeout {
            if let Ok(result) = tokio::time::timeout(timeout, &mut self.handle).await {
                return result;
            } else {
                self.handle.abort();
                tracing::warn!("task stop timeout after {:?}, aborted", timeout);
            }
        }
        self.handle.await
    }
}

impl<Output: Send + 'static> Future for CancellableTask<Output> {
    type Output = <AbortOnDropHandle<Output> as Future>::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}

use std::future::Future;
use std::io;
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

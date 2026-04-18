use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tokio_util::task::AbortOnDropHandle;

#[derive(Debug)]
pub struct CancellableTask<Output> {
    handle: AbortOnDropHandle<Output>,
    token: CancellationToken,
}

impl<Output> Future for CancellableTask<Output> {
    type Output = <AbortOnDropHandle<Output> as Future>::Output;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}

impl<Output> CancellableTask<Output> {
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }

    pub fn with_spawner<S, F>(spawner: S, token: CancellationToken, future: F) -> Self
    where
        S: FnOnce(F) -> JoinHandle<Output>,
        F: Future<Output = Output>,
    {
        Self {
            handle: AbortOnDropHandle::new(spawner(future)),
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
    fn new<F>(token: CancellationToken, future: F) -> Self
    where
        F: Future<Output = Output> + Send + 'static,
    {
        Self::with_spawner(tokio::spawn, token, future)
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

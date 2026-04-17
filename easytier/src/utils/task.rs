use crate::common::scoped_task::ScopedTask;
use derivative::Derivative;
use derive_more::{Deref, DerefMut};
use parking_lot::Mutex;
use std::future::Future;
use std::mem::take;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tokio::task::{AbortHandle, JoinError};
use tokio_util::sync::CancellationToken;

#[derive(Derivative, Debug)]
#[derivative(Default(bound = ""))]
enum AsyncRuntimeState<R: Send + 'static> {
    #[derivative(Default)]
    Idle,
    Running {
        id: tokio::task::Id,
        task: ScopedTask<R>,
        token: CancellationToken,
    },
    Stopping(AbortHandle),
}

#[derive(Derivative, Debug)]
#[derivative(Default(bound = ""))]
pub struct AsyncRuntimeInner<R: Send + 'static = ()> {
    state: Mutex<AsyncRuntimeState<R>>,
    idle: Notify,
}

#[derive(Derivative, Deref, DerefMut)]
#[derivative(Debug = "transparent", Default(bound = ""), Clone(bound = ""))]
pub struct AsyncRuntime<R: Send + 'static = ()>(Arc<AsyncRuntimeInner<R>>);

impl<R: Send + 'static> AsyncRuntime<R> {
    pub fn token(&self) -> Option<CancellationToken> {
        if let AsyncRuntimeState::Running { token, .. } = &*self.state.lock() {
            Some(token.clone())
        } else {
            None
        }
    }

    pub fn start<F, Fut>(&self, token: Option<CancellationToken>, factory: F) -> anyhow::Result<()>
    where
        F: FnOnce(CancellationToken) -> Fut,
        Fut: Future<Output = R> + Send + 'static,
    {
        let mut state = self.state.lock();
        if !matches!(*state, AsyncRuntimeState::Idle) {
            return Err(anyhow::anyhow!("task is already running/stopping"));
        }

        let token = token.unwrap_or_default();

        let task = {
            let f = factory(token.clone());
            let this = (*self).clone();
            tokio::spawn(async move {
                let result = f.await;
                let mut state = this.state.lock();
                if let AsyncRuntimeState::Running { id, .. } = &*state
                    && *id == tokio::task::id()
                {
                    take(&mut *state);
                }
                result
            })
        };

        *state = AsyncRuntimeState::Running {
            id: task.id(),
            task: task.into(),
            token,
        };

        Ok(())
    }

    pub async fn stop(&self, timeout: Option<Duration>) -> Option<Result<R, JoinError>> {
        let state = {
            let mut state = self.state.lock();
            match &*state {
                AsyncRuntimeState::Running { .. } => {
                    let AsyncRuntimeState::Running { task, token, .. } = take(&mut *state) else {
                        unreachable!()
                    };
                    *state = AsyncRuntimeState::Stopping(task.abort_handle());
                    Ok((task, token))
                }
                AsyncRuntimeState::Stopping(_) => Err(self.idle.notified()),
                AsyncRuntimeState::Idle => return None,
            }
        };

        let (mut task, token) = match state {
            Ok(running) => running,
            Err(stopping) => {
                stopping.await;
                return None;
            }
        };

        token.cancel();
        let result = match timeout {
            Some(duration) => {
                if let Ok(result) = tokio::time::timeout(duration, &mut task).await {
                    result
                } else {
                    task.abort();
                    tracing::warn!("task stop timeout after {:?}, aborted", duration);
                    task.await
                }
            }
            None => task.await,
        };

        {
            let mut state = self.state.lock();
            if matches!(*state, AsyncRuntimeState::Stopping(_)) {
                *state = AsyncRuntimeState::Idle;
                drop(state);
                self.idle.notify_waiters();
            }
        }

        Some(result)
    }

    pub fn abort(&self) {
        let mut state = self.state.lock();
        match &*state {
            AsyncRuntimeState::Running { task, .. } => {
                task.abort();
                *state = AsyncRuntimeState::Idle;
                drop(state);
                self.idle.notify_waiters();
            }
            AsyncRuntimeState::Stopping(handle) => handle.abort(),
            _ => {}
        }
    }
}

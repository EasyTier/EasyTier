//! Deadlines for data-plane control operations and persistent I/O resources.

use std::{future::Future, sync::Mutex, time::Duration};

use quanta::Instant;
use tokio::{sync::watch, task::JoinHandle};
use tokio_util::sync::CancellationToken;

use crate::foundation::time;

use super::{DataPlaneError, DataPlaneResult};

#[derive(Clone, Copy, Debug)]
pub(super) struct DataPlaneDeadline(Option<Instant>);

impl DataPlaneDeadline {
    pub(super) fn from_timeout(timeout: Duration) -> Self {
        Self(Instant::now().checked_add(timeout))
    }

    pub(super) fn from_optional_timeout(timeout: Option<Duration>) -> Self {
        match timeout {
            Some(timeout) => Self::from_timeout(timeout),
            None => Self(None),
        }
    }

    pub(super) fn remaining(self) -> DataPlaneResult<Option<Duration>> {
        let Some(deadline) = self.0 else {
            return Ok(None);
        };
        let now = Instant::now();
        if now >= deadline {
            return Err(DataPlaneError::deadline_exceeded());
        }
        Ok(Some(deadline - now))
    }

    pub(super) async fn run<T, E>(
        self,
        future: impl Future<Output = Result<T, E>>,
    ) -> DataPlaneResult<T>
    where
        E: Into<DataPlaneError>,
    {
        match self.remaining()? {
            Some(remaining) => time::timeout(remaining, future)
                .await
                .map_err(|_| DataPlaneError::deadline_exceeded())?
                .map_err(Into::into),
            None => future.await.map_err(Into::into),
        }
    }
}

pub(super) struct DataPlaneIoDeadline {
    generation: watch::Sender<CancellationToken>,
    timer: Mutex<Option<JoinHandle<()>>>,
}

impl Default for DataPlaneIoDeadline {
    fn default() -> Self {
        Self {
            generation: watch::channel(CancellationToken::new()).0,
            timer: Mutex::new(None),
        }
    }
}

impl DataPlaneIoDeadline {
    pub(super) fn set_timeout(&self, timeout: Option<Duration>) {
        let mut timer = self.timer.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(timer) = timer.take() {
            timer.abort();
        }

        let expired = CancellationToken::new();
        if let Some(timeout) = timeout {
            if timeout.is_zero() {
                expired.cancel();
            } else {
                if let Some(deadline) = time::Instant::now().checked_add(timeout) {
                    let sleep = time::sleep_until(deadline);
                    let expiration = expired.clone();
                    *timer = Some(tokio::spawn(async move {
                        sleep.await;
                        expiration.cancel();
                    }));
                }
            }
        }
        self.generation.send_replace(expired);
    }

    pub(super) async fn run<T, E>(
        &self,
        cancel: CancellationToken,
        future: impl Future<Output = Result<T, E>>,
    ) -> DataPlaneResult<T>
    where
        E: Into<DataPlaneError>,
    {
        let mut deadline = self.generation.subscribe();
        tokio::pin!(future);
        loop {
            let expired = deadline.borrow_and_update().clone();
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {
                    return Err(DataPlaneError::new(
                        super::DataPlaneErrorKind::Cancelled,
                        "data-plane operation cancelled",
                    ));
                }
                changed = deadline.changed() => {
                    if changed.is_err() {
                        return Err(DataPlaneError::new(
                            super::DataPlaneErrorKind::HandleClosed,
                            "data-plane resource is closed",
                        ));
                    }
                }
                _ = expired.cancelled() => {
                    return Err(DataPlaneError::deadline_exceeded());
                }
                result = &mut future => return result.map_err(Into::into),
            }
        }
    }
}

impl Drop for DataPlaneIoDeadline {
    fn drop(&mut self) {
        if let Some(timer) = self
            .timer
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            timer.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{future, sync::Arc};

    use super::*;

    #[tokio::test]
    async fn io_deadline_updates_an_active_operation() {
        let deadline = Arc::new(DataPlaneIoDeadline::default());
        let operation = {
            let deadline = deadline.clone();
            tokio::spawn(async move {
                deadline
                    .run(
                        CancellationToken::new(),
                        future::pending::<Result<(), DataPlaneError>>(),
                    )
                    .await
            })
        };
        tokio::task::yield_now().await;

        deadline.set_timeout(Some(Duration::ZERO));

        assert_eq!(
            operation.await.unwrap().unwrap_err().kind(),
            super::super::DataPlaneErrorKind::DeadlineExceeded
        );
    }

    #[tokio::test]
    async fn io_deadline_expires_future_operations_until_cleared() {
        let deadline = DataPlaneIoDeadline::default();
        deadline.set_timeout(Some(Duration::ZERO));

        assert_eq!(
            deadline
                .run(
                    CancellationToken::new(),
                    future::ready(Ok::<_, DataPlaneError>(())),
                )
                .await
                .unwrap_err()
                .kind(),
            super::super::DataPlaneErrorKind::DeadlineExceeded
        );

        deadline.set_timeout(None);
        deadline
            .run(
                CancellationToken::new(),
                future::ready(Ok::<_, DataPlaneError>(())),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn io_deadline_treats_unrepresentable_timeout_as_unbounded() {
        let deadline = DataPlaneIoDeadline::default();
        deadline.set_timeout(Some(Duration::from_millis(u64::MAX - 1)));

        deadline
            .run(
                CancellationToken::new(),
                future::ready(Ok::<_, DataPlaneError>(())),
            )
            .await
            .unwrap();
    }
}

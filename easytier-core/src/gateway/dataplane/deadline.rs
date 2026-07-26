//! One absolute deadline shared by every stage of a data-plane operation.

use std::{future::Future, time::Duration};

use quanta::Instant;

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

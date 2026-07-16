use crate::utils::error::ErrorCollection;
use futures::StreamExt;
use futures::stream::FuturesUnordered;
use std::future::Future;
use std::time::Duration;
use tokio::time::sleep;

// region HedgeExt

pub(crate) trait HedgeExt: Iterator + Sized {
    async fn hedge<T, E>(self, delay: Duration) -> Result<T, ErrorCollection<E>>
    where
        Self::Item: Future<Output = Result<T, E>>;
}

impl<I> HedgeExt for I
where
    I: Iterator,
{
    async fn hedge<T, E>(mut self, delay: Duration) -> Result<T, ErrorCollection<E>>
    where
        Self::Item: Future<Output = Result<T, E>>,
    {
        let mut tasks = FuturesUnordered::new();
        let mut errors = ErrorCollection::new();
        let mut exhausted = false;

        macro_rules! spawn {
            () => {
                if let Some(fut) = self.next() {
                    tasks.push(fut);
                } else {
                    exhausted = true;
                }
            };
        }

        spawn!();

        while !tasks.is_empty() {
            tokio::select! {
                res = tasks.next() => {
                    match res {
                        Some(Ok(v)) => return Ok(v),
                        Some(Err(e)) => errors.push(e),
                        None => unreachable!(),
                    }

                    if !exhausted {
                        spawn!();
                    }
                }

                _ = sleep(delay), if !exhausted => {
                    spawn!();
                }
            }
        }

        Err(errors)
    }
}

// endregion

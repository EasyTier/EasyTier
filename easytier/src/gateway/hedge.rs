use std::{
    fmt::{self, Display},
    future::Future,
    time::Duration,
};

use futures::{StreamExt, stream::FuturesUnordered};
use tokio::time::sleep;

#[derive(Debug)]
pub(super) struct ErrorCollection<E> {
    errors: Vec<E>,
}

impl<E> ErrorCollection<E> {
    fn new() -> Self {
        Self { errors: Vec::new() }
    }

    fn push(&mut self, error: E) {
        self.errors.push(error);
    }
}

impl<E: Display> Display for ErrorCollection<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.errors.is_empty() {
            return write!(f, "No errors");
        }

        write!(f, "{} error(s) occurred:", self.errors.len())?;
        for (i, err) in self.errors.iter().enumerate() {
            writeln!(f)?;
            write!(f, "  {}. {}", i + 1, err)?;
        }

        Ok(())
    }
}

impl<E: fmt::Debug + Display> std::error::Error for ErrorCollection<E> {}

pub(super) trait HedgeExt: Iterator + Sized {
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

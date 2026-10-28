//! Retry runtime listener failures until the owning task is cancelled.

use super::SocketListener;

pub async fn wait() {
    crate::foundation::time::sleep(std::time::Duration::from_millis(100)).await;
}

/// For owners whose listener can be restarted in place after an accept error.
/// The first listen remains fallible so startup errors reach the caller.
pub async fn accept_with_rebind<L: SocketListener + ?Sized>(listener: &mut L) -> L::Accepted {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            Err(error) => {
                tracing::warn!(target: "CORE", url = %listener.local_url(), error = %format_args!("{error:#}"), "listener failed; rebinding");
            }
        }
        loop {
            wait().await;
            match listener.listen().await {
                Ok(()) => break,
                Err(error) => {
                    tracing::warn!(target: "CORE", url = %listener.local_url(), error = %format_args!("{error:#}"), "listener bind failed; retrying");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, io};

    #[derive(Debug, Default)]
    struct Listener {
        accepts: VecDeque<io::Result<usize>>,
        binds: VecDeque<io::Result<()>>,
    }
    #[async_trait::async_trait]
    impl SocketListener for Listener {
        type Accepted = usize;
        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(self.binds.pop_front().unwrap_or(Ok(()))?)
        }
        async fn accept(&mut self) -> anyhow::Result<usize> {
            Ok(self.accepts.pop_front().expect("unexpected retry")?)
        }
        fn local_url(&self) -> url::Url {
            "tcp://127.0.0.1:22020".parse().unwrap()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unknown_accept_and_repeated_bind_failures_do_not_stop_recovery() {
        let mut listener = Listener {
            accepts: VecDeque::from([Err(io::Error::other("unknown failure")), Ok(7)]),
            binds: (0..10)
                .map(|_| Err(io::ErrorKind::PermissionDenied.into()))
                .collect(),
        };
        let start = tokio::time::Instant::now();
        assert_eq!(accept_with_rebind(&mut listener).await, 7);
        assert_eq!(start.elapsed(), std::time::Duration::from_millis(1100));
    }

    #[tokio::test(start_paused = true)]
    async fn rebind_wait_is_cancelled_with_its_owner() {
        let mut listener = Listener {
            accepts: VecDeque::from([Err(io::ErrorKind::BrokenPipe.into()), Ok(7)]),
            binds: VecDeque::from([Err(io::ErrorKind::AddrInUse.into()), Ok(())]),
        };
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(150),
                accept_with_rebind(&mut listener)
            )
            .await
            .is_err()
        );
        assert_eq!(listener.binds.len(), 1);
        assert_eq!(listener.accepts.len(), 1);
    }
}

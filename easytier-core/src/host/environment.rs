//! Async host-operation bridge for connector environment services.

use std::{io, net::SocketAddr, sync::Arc, task::Poll};

use async_trait::async_trait;

use crate::socket::SocketContext;

use super::socket::{HostOperationId, HostSocketRuntime};

/// Slow or socket-specific system operations below connector policy.
#[async_trait]
pub trait HostConnectorEnvironmentServices: Send + Sync + 'static {
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr>;
}

/// Mechanical asynchronous environment operations below connector policy.
///
/// Submit calls must take ownership of their complete input before returning
/// and must leave no operation state when they return an error. A `Pending`
/// take retains the operation; a `Ready` take consumes both successful and
/// failed results. Cancellation must remove pending and completed-but-unread
/// state and is idempotent for an already-absent operation.
pub trait HostConnectorEnvironmentIo: Send + Sync + 'static {
    fn submit_local_addr_for_remote(
        &self,
        operation: HostOperationId,
        remote_addr: SocketAddr,
        context: &SocketContext,
    ) -> io::Result<()>;

    fn take_local_addr_for_remote(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<SocketAddr>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;
}

/// Tokio-facing environment services backed by host operation IDs.
pub struct HostConnectorEnvironmentServiceAdapter<I>
where
    I: HostConnectorEnvironmentIo,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
}

impl<I> HostConnectorEnvironmentServiceAdapter<I>
where
    I: HostConnectorEnvironmentIo,
{
    pub fn new(runtime: HostSocketRuntime, io: Arc<I>) -> Self {
        Self { runtime, io }
    }
}

#[async_trait]
impl<I> HostConnectorEnvironmentServices for HostConnectorEnvironmentServiceAdapter<I>
where
    I: HostConnectorEnvironmentIo,
{
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr> {
        Ok(self
            .runtime
            .run_operation(
                self.io.clone(),
                |io, operation| io.submit_local_addr_for_remote(operation, remote_addr, &context),
                HostConnectorEnvironmentIo::take_local_addr_for_remote,
                |io, operation| io.cancel_operation(operation),
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Request {
        Local(SocketAddr, SocketContext),
    }

    #[derive(Debug, Clone, Copy)]
    enum Completion {
        Ok(SocketAddr),
        Err(io::ErrorKind),
    }

    #[derive(Default)]
    struct TestIo {
        requests: Mutex<HashMap<HostOperationId, (Request, Option<Completion>)>>,
        cancelled: Mutex<Vec<HostOperationId>>,
    }

    impl TestIo {
        fn submit(&self, operation: HostOperationId, request: Request) -> io::Result<()> {
            let replaced = self
                .requests
                .lock()
                .unwrap()
                .insert(operation, (request, None));
            if replaced.is_some() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            Ok(())
        }

        fn take(&self, operation: HostOperationId) -> Poll<io::Result<SocketAddr>> {
            let mut requests = self.requests.lock().unwrap();
            let Some((_, result)) = requests.get(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = *result else {
                return Poll::Pending;
            };
            requests.remove(&operation);
            Poll::Ready(match result {
                Completion::Ok(address) => Ok(address),
                Completion::Err(kind) => Err(kind.into()),
            })
        }

        fn operation_for(&self, request: Request) -> HostOperationId {
            self.requests
                .lock()
                .unwrap()
                .iter()
                .find_map(|(operation, (candidate, _))| {
                    (*candidate == request).then_some(*operation)
                })
                .expect("submitted host environment operation")
        }

        fn complete(&self, operation: HostOperationId, result: Completion) {
            self.requests.lock().unwrap().get_mut(&operation).unwrap().1 = Some(result);
        }
    }

    impl HostConnectorEnvironmentIo for TestIo {
        fn submit_local_addr_for_remote(
            &self,
            operation: HostOperationId,
            remote_addr: SocketAddr,
            context: &SocketContext,
        ) -> io::Result<()> {
            self.submit(operation, Request::Local(remote_addr, context.clone()))
        }

        fn take_local_addr_for_remote(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<SocketAddr>> {
            self.take(operation)
        }

        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            self.requests.lock().unwrap().remove(&operation);
            self.cancelled.lock().unwrap().push(operation);
            Ok(())
        }
    }

    #[tokio::test]
    async fn wakes_completed_operations_and_cancels_dropped_futures() {
        let runtime = HostSocketRuntime::new();
        let io = Arc::new(TestIo::default());
        let services = Arc::new(HostConnectorEnvironmentServiceAdapter::new(
            runtime.clone(),
            io.clone(),
        ));
        let remote = "203.0.113.1:11010".parse().unwrap();
        let context = SocketContext::default().with_socket_mark(Some(7));
        let task = tokio::spawn({
            let services = services.clone();
            let context = context.clone();
            async move { services.local_addr_for_remote(remote, context).await }
        });
        tokio::task::yield_now().await;

        let operation = io.operation_for(Request::Local(remote, context));
        io.complete(
            operation,
            Completion::Ok("192.0.2.1:40100".parse().unwrap()),
        );
        runtime.notify_completions();
        assert_eq!(
            task.await.unwrap().unwrap(),
            "192.0.2.1:40100".parse().unwrap()
        );

        let pending_remote = "203.0.113.2:11010".parse().unwrap();
        let pending = tokio::spawn({
            let services = services.clone();
            async move {
                services
                    .local_addr_for_remote(pending_remote, SocketContext::default())
                    .await
            }
        });
        tokio::task::yield_now().await;
        let cancelled = io.operation_for(Request::Local(pending_remote, SocketContext::default()));
        pending.abort();
        let _ = pending.await;
        assert_eq!(*io.cancelled.lock().unwrap(), vec![cancelled]);
        assert!(!io.requests.lock().unwrap().contains_key(&cancelled));

        let failed_remote = "203.0.113.3:11010".parse().unwrap();
        let failed = tokio::spawn({
            let services = services.clone();
            async move {
                services
                    .local_addr_for_remote(failed_remote, SocketContext::default())
                    .await
            }
        });
        tokio::task::yield_now().await;
        let failed_operation =
            io.operation_for(Request::Local(failed_remote, SocketContext::default()));
        io.complete(
            failed_operation,
            Completion::Err(io::ErrorKind::AddrNotAvailable),
        );
        runtime.notify_completions();
        assert_eq!(
            failed
                .await
                .unwrap()
                .unwrap_err()
                .downcast_ref::<io::Error>()
                .unwrap()
                .kind(),
            io::ErrorKind::AddrNotAvailable
        );
        assert!(!io.requests.lock().unwrap().contains_key(&failed_operation));

        let unread_remote = "203.0.113.4:11010".parse().unwrap();
        let unread = tokio::spawn({
            let services = services.clone();
            async move {
                services
                    .local_addr_for_remote(unread_remote, SocketContext::default())
                    .await
            }
        });
        tokio::task::yield_now().await;
        let unread_operation =
            io.operation_for(Request::Local(unread_remote, SocketContext::default()));
        io.complete(
            unread_operation,
            Completion::Ok("198.51.100.1:44000".parse().unwrap()),
        );
        runtime.notify_completions();
        unread.abort();
        let _ = unread.await;
        assert!(io.cancelled.lock().unwrap().contains(&unread_operation));
        assert!(!io.requests.lock().unwrap().contains_key(&unread_operation));
    }
}

//! Async host-operation bridge for connector environment services.

use std::{io, net::SocketAddr, sync::Arc, task::Poll};

use async_trait::async_trait;
use futures::future::poll_fn;

use crate::connectivity::host::environment::HostConnectorEnvironmentServices;

use super::{HostOperationId, HostSocketHandle, HostSocketRuntime, udp::HostUdpSocket};

/// Mechanical asynchronous environment operations below connector policy.
pub trait HostConnectorEnvironmentIo: Send + Sync + 'static {
    fn submit_local_addr_for_remote(
        &self,
        operation: HostOperationId,
        remote_addr: SocketAddr,
    ) -> io::Result<()>;

    fn take_local_addr_for_remote(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<SocketAddr>>;

    fn submit_udp_port_mapping(
        &self,
        operation: HostOperationId,
        socket: HostSocketHandle,
    ) -> io::Result<()>;

    fn take_udp_port_mapping(&self, operation: HostOperationId) -> Poll<io::Result<SocketAddr>>;

    fn submit_tcp_port_mapping(
        &self,
        operation: HostOperationId,
        local_port: u16,
    ) -> io::Result<()>;

    fn take_tcp_port_mapping(&self, operation: HostOperationId) -> Poll<io::Result<SocketAddr>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;
}

struct PendingEnvironmentOperation<I>
where
    I: HostConnectorEnvironmentIo,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
    operation: HostOperationId,
    completed: bool,
}

impl<I> PendingEnvironmentOperation<I>
where
    I: HostConnectorEnvironmentIo,
{
    fn new(runtime: HostSocketRuntime, io: Arc<I>, operation: HostOperationId) -> Self {
        Self {
            runtime,
            io,
            operation,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.runtime.inner.wakers.remove(self.operation);
        self.completed = true;
    }
}

impl<I> Drop for PendingEnvironmentOperation<I>
where
    I: HostConnectorEnvironmentIo,
{
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.runtime.inner.wakers.remove(self.operation);
        let _ = self.io.cancel_operation(self.operation);
    }
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

    async fn run_operation(
        &self,
        submit: impl FnOnce(&I, HostOperationId) -> io::Result<()>,
        take: impl Fn(&I, HostOperationId) -> Poll<io::Result<SocketAddr>>,
    ) -> io::Result<SocketAddr> {
        let operation = self.runtime.next_operation();
        submit(&self.io, operation)?;
        let mut pending =
            PendingEnvironmentOperation::new(self.runtime.clone(), self.io.clone(), operation);
        poll_fn(|context| {
            let epoch = self
                .runtime
                .inner
                .completion_epoch
                .load(std::sync::atomic::Ordering::SeqCst);
            match take(&self.io, operation) {
                Poll::Pending => {
                    self.runtime.register_pending(operation, epoch, context);
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    pending.complete();
                    Poll::Ready(result)
                }
            }
        })
        .await
    }
}

#[async_trait]
impl<I> HostConnectorEnvironmentServices for HostConnectorEnvironmentServiceAdapter<I>
where
    I: HostConnectorEnvironmentIo,
{
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr> {
        Ok(self
            .run_operation(
                |io, operation| io.submit_local_addr_for_remote(operation, remote_addr),
                HostConnectorEnvironmentIo::take_local_addr_for_remote,
            )
            .await?)
    }

    async fn udp_port_mapping(&self, socket: Arc<HostUdpSocket>) -> anyhow::Result<SocketAddr> {
        let handle = socket.host_handle();
        let result = self
            .run_operation(
                |io, operation| io.submit_udp_port_mapping(operation, handle),
                HostConnectorEnvironmentIo::take_udp_port_mapping,
            )
            .await;
        drop(socket);
        Ok(result?)
    }

    async fn tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        Ok(self
            .run_operation(
                |io, operation| io.submit_tcp_port_mapping(operation, local_port),
                HostConnectorEnvironmentIo::take_tcp_port_mapping,
            )
            .await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Request {
        Local(SocketAddr),
        Udp(HostSocketHandle),
        Tcp(u16),
    }

    #[derive(Default)]
    struct TestIo {
        requests: Mutex<HashMap<HostOperationId, (Request, Option<SocketAddr>)>>,
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
            Poll::Ready(Ok(result))
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

        fn complete(&self, operation: HostOperationId, result: SocketAddr) {
            self.requests.lock().unwrap().get_mut(&operation).unwrap().1 = Some(result);
        }
    }

    impl HostConnectorEnvironmentIo for TestIo {
        fn submit_local_addr_for_remote(
            &self,
            operation: HostOperationId,
            remote_addr: SocketAddr,
        ) -> io::Result<()> {
            self.submit(operation, Request::Local(remote_addr))
        }

        fn take_local_addr_for_remote(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<SocketAddr>> {
            self.take(operation)
        }

        fn submit_udp_port_mapping(
            &self,
            operation: HostOperationId,
            socket: HostSocketHandle,
        ) -> io::Result<()> {
            self.submit(operation, Request::Udp(socket))
        }

        fn take_udp_port_mapping(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<SocketAddr>> {
            self.take(operation)
        }

        fn submit_tcp_port_mapping(
            &self,
            operation: HostOperationId,
            local_port: u16,
        ) -> io::Result<()> {
            self.submit(operation, Request::Tcp(local_port))
        }

        fn take_tcp_port_mapping(
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
        let task = tokio::spawn({
            let services = services.clone();
            async move { services.local_addr_for_remote(remote).await }
        });
        tokio::task::yield_now().await;

        let operation = io.operation_for(Request::Local(remote));
        io.complete(operation, "192.0.2.1:40100".parse().unwrap());
        runtime.notify_completions();
        assert_eq!(
            task.await.unwrap().unwrap(),
            "192.0.2.1:40100".parse().unwrap()
        );

        let pending = tokio::spawn({
            let services = services.clone();
            async move { services.tcp_port_mapping(42000).await }
        });
        tokio::task::yield_now().await;
        let cancelled = io.operation_for(Request::Tcp(42000));
        pending.abort();
        let _ = pending.await;
        assert_eq!(*io.cancelled.lock().unwrap(), vec![cancelled]);
        assert!(!io.requests.lock().unwrap().contains_key(&cancelled));
    }
}

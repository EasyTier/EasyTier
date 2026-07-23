use std::{io, net::SocketAddr, sync::Arc, task::Poll};

use crate::socket::tcp::{TcpListenOptions, VirtualTcpListener, VirtualTcpListenerFactory};
use async_trait::async_trait;

use super::{
    HostOperationId, HostSocketHandle, HostSocketIo, HostSocketRuntime, HostTcpIo, HostTcpStream,
    factory::HostTcpConnectResult,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTcpBindResult {
    pub handle: HostSocketHandle,
    pub local_addr: SocketAddr,
}

/// Mechanical TCP listener creation and accept readiness.
///
/// Bind cancellation must close a completed but unobserved listener. Accepted
/// connections stay in a host-owned listener queue until `take_tcp_accept` is
/// called from a guest poll; canceling an accept waiter must not remove one.
pub trait HostTcpListenerIo: HostSocketIo {
    fn submit_tcp_bind(
        &self,
        operation: HostOperationId,
        options: &TcpListenOptions,
    ) -> io::Result<()>;

    fn take_tcp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostTcpBindResult>>;

    fn submit_tcp_accept(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
    ) -> io::Result<()>;

    fn take_tcp_accept(&self, operation: HostOperationId)
    -> Poll<io::Result<HostTcpConnectResult>>;
}

pub trait HostTcpListenerBackend: HostTcpListenerIo + HostTcpIo {}

impl<T> HostTcpListenerBackend for T where T: HostTcpListenerIo + HostTcpIo {}

pub struct HostTcpListenerFactory<B>
where
    B: HostTcpListenerBackend,
{
    runtime: HostSocketRuntime,
    backend: Arc<B>,
}

impl<B> Clone for HostTcpListenerFactory<B>
where
    B: HostTcpListenerBackend,
{
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            backend: self.backend.clone(),
        }
    }
}

impl<B> HostTcpListenerFactory<B>
where
    B: HostTcpListenerBackend,
{
    pub fn new(runtime: HostSocketRuntime, backend: Arc<B>) -> Self {
        Self { runtime, backend }
    }

    async fn bind(&self, options: TcpListenOptions) -> io::Result<Arc<HostTcpListener<B>>> {
        let result = self
            .runtime
            .run_operation(
                self.backend.clone(),
                |backend, operation| backend.submit_tcp_bind(operation, &options),
                |backend, operation| backend.take_tcp_bind(operation),
                |backend, operation| backend.cancel_operation(operation),
            )
            .await?;
        Ok(Arc::new(HostTcpListener {
            runtime: self.runtime.clone(),
            backend: self.backend.clone(),
            handle: result.handle,
            local_addr: result.local_addr,
        }))
    }
}

#[async_trait]
impl<B> VirtualTcpListenerFactory for HostTcpListenerFactory<B>
where
    B: HostTcpListenerBackend,
{
    type Listener = HostTcpListener<B>;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        Ok(self.bind(options).await?)
    }
}

pub struct HostTcpListener<B>
where
    B: HostTcpListenerBackend,
{
    runtime: HostSocketRuntime,
    backend: Arc<B>,
    handle: HostSocketHandle,
    local_addr: SocketAddr,
}

impl<B> std::fmt::Debug for HostTcpListener<B>
where
    B: HostTcpListenerBackend,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostTcpListener")
            .field("handle", &self.handle)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl<B> VirtualTcpListener for HostTcpListener<B>
where
    B: HostTcpListenerBackend,
{
    type Socket = HostTcpStream;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
        let result = self
            .runtime
            .run_operation(
                self.backend.clone(),
                |backend, operation| backend.submit_tcp_accept(self.handle, operation),
                |backend, operation| backend.take_tcp_accept(operation),
                |backend, operation| backend.cancel_operation(operation),
            )
            .await?;
        let peer_addr = result.peer_addr;
        Ok((
            self.runtime.tcp_stream(
                self.backend.clone(),
                result.handle,
                result.local_addr,
                peer_addr,
                result.transport_label,
            ),
            peer_addr,
        ))
    }
}

impl<B> Drop for HostTcpListener<B>
where
    B: HostTcpListenerBackend,
{
    fn drop(&mut self) {
        let _ = self.backend.close(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        sync::Mutex,
    };

    use crate::socket::tcp::{TcpBindOptions, TcpListenPurpose, VirtualTcpSocket};

    use super::*;

    enum TestOperation {
        Bind {
            options: TcpListenOptions,
            result: Option<io::Result<HostTcpBindResult>>,
        },
        Accept {
            handle: HostSocketHandle,
        },
    }

    #[derive(Default)]
    struct TestHostIo {
        operations: Mutex<HashMap<HostOperationId, TestOperation>>,
        accepted: Mutex<HashMap<HostSocketHandle, VecDeque<HostTcpConnectResult>>>,
        cancelled: Mutex<Vec<HostOperationId>>,
        closed: Mutex<HashSet<HostSocketHandle>>,
    }

    impl TestHostIo {
        fn bind_operation(&self) -> HostOperationId {
            self.operation(|operation| matches!(operation, TestOperation::Bind { .. }))
        }

        fn accept_operation(&self) -> HostOperationId {
            self.operation(|operation| matches!(operation, TestOperation::Accept { .. }))
        }

        fn operation(&self, predicate: impl Fn(&TestOperation) -> bool) -> HostOperationId {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(operation, value)| predicate(value).then_some(*operation))
                .unwrap()
        }

        fn complete_bind(&self, operation: HostOperationId, result: HostTcpBindResult) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Bind {
                result: completion, ..
            } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not bind");
            };
            *completion = Some(Ok(result));
        }

        fn queue_accept(&self, operation: HostOperationId, result: HostTcpConnectResult) {
            let operations = self.operations.lock().unwrap();
            let TestOperation::Accept { handle } = operations.get(&operation).unwrap() else {
                panic!("operation is not accept");
            };
            self.accepted
                .lock()
                .unwrap()
                .entry(*handle)
                .or_default()
                .push_back(result);
        }
    }

    impl HostSocketIo for TestHostIo {
        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            if let Some(TestOperation::Bind {
                result: Some(Ok(result)),
                ..
            }) = self.operations.lock().unwrap().remove(&operation)
            {
                self.closed.lock().unwrap().insert(result.handle);
            }
            self.cancelled.lock().unwrap().push(operation);
            Ok(())
        }

        fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
            self.closed.lock().unwrap().insert(handle);
            Ok(())
        }
    }

    impl HostTcpListenerIo for TestHostIo {
        fn submit_tcp_bind(
            &self,
            operation: HostOperationId,
            options: &TcpListenOptions,
        ) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestOperation::Bind {
                    options: options.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_tcp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostTcpBindResult>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Bind { result, .. }) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }

        fn submit_tcp_accept(
            &self,
            handle: HostSocketHandle,
            operation: HostOperationId,
        ) -> io::Result<()> {
            self.operations
                .lock()
                .unwrap()
                .insert(operation, TestOperation::Accept { handle });
            Ok(())
        }

        fn take_tcp_accept(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<HostTcpConnectResult>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Accept { handle }) = operations.get(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let handle = *handle;
            let Some(result) = self
                .accepted
                .lock()
                .unwrap()
                .entry(handle)
                .or_default()
                .pop_front()
            else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(Ok(result))
        }
    }

    impl HostTcpIo for TestHostIo {
        fn submit_read(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn take_read(&self, _operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn submit_write(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _source: &[u8],
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn take_write(&self, _operation: HostOperationId) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    fn listener(
        runtime: &HostSocketRuntime,
        io: Arc<TestHostIo>,
        handle: HostSocketHandle,
    ) -> HostTcpListener<TestHostIo> {
        HostTcpListener {
            runtime: runtime.clone(),
            backend: io,
            handle,
            local_addr: "192.0.2.1:11013".parse().unwrap(),
        }
    }

    #[tokio::test]
    async fn forwards_bind_options_and_wraps_accepted_stream() {
        let io = Arc::new(TestHostIo::default());
        let runtime = HostSocketRuntime::new();
        let factory = HostTcpListenerFactory::new(runtime.clone(), io.clone());
        let options = TcpListenOptions {
            bind: TcpBindOptions::default()
                .with_local_addr(Some("192.0.2.1:0".parse().unwrap()))
                .with_socket_mark(Some(7))
                .with_bind_device(Some("host-device".to_owned()))
                .with_reuse_port(true),
            purpose: TcpListenPurpose::ManualConnect,
        };
        let bind_task = tokio::spawn({
            let factory = factory.clone();
            let options = options.clone();
            async move { factory.bind_tcp(options).await }
        });
        tokio::task::yield_now().await;
        let bind_operation = io.bind_operation();
        {
            let operations = io.operations.lock().unwrap();
            let TestOperation::Bind {
                options: submitted, ..
            } = operations.get(&bind_operation).unwrap()
            else {
                panic!("operation is not bind");
            };
            assert_eq!(submitted, &options);
        }
        io.complete_bind(
            bind_operation,
            HostTcpBindResult {
                handle: HostSocketHandle(51),
                local_addr: "192.0.2.1:11013".parse().unwrap(),
            },
        );
        runtime.notify_completions();
        let listener = bind_task.await.unwrap().unwrap();

        let accept_task = tokio::spawn({
            let listener = listener.clone();
            async move { listener.accept().await }
        });
        tokio::task::yield_now().await;
        let accept_operation = io.accept_operation();
        io.queue_accept(
            accept_operation,
            HostTcpConnectResult {
                handle: HostSocketHandle(52),
                local_addr: "192.0.2.1:11013".parse().unwrap(),
                peer_addr: "192.0.2.2:40100".parse().unwrap(),
                transport_label: Some("host-accepted".to_owned()),
            },
        );
        runtime.notify_completions();
        let (stream, peer_addr) = accept_task.await.unwrap().unwrap();
        assert_eq!(peer_addr, "192.0.2.2:40100".parse().unwrap());
        assert_eq!(stream.transport_label(), Some("host-accepted"));
        drop(stream);
        drop(listener);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(51)));
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(52)));
    }

    #[tokio::test]
    async fn cancelling_ready_accept_preserves_connection_for_next_poll() {
        let io = Arc::new(TestHostIo::default());
        let runtime = HostSocketRuntime::new();
        let listener = listener(&runtime, io.clone(), HostSocketHandle(53));
        let peer_addr = "192.0.2.2:40101".parse().unwrap();
        let operation = {
            let mut accept = Box::pin(listener.accept());
            assert!(futures::poll!(&mut accept).is_pending());
            let operation = io.accept_operation();
            io.queue_accept(
                operation,
                HostTcpConnectResult {
                    handle: HostSocketHandle(54),
                    local_addr: "192.0.2.1:11013".parse().unwrap(),
                    peer_addr,
                    transport_label: None,
                },
            );
            runtime.notify_completions();
            drop(accept);
            operation
        };
        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);

        let (stream, accepted_peer) = listener.accept().await.unwrap();
        assert_eq!(accepted_peer, peer_addr);
        drop(stream);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(54)));
    }
}

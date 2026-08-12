use std::{io, net::SocketAddr, sync::Arc, task::Poll};

use crate::socket::{
    tcp::{TcpConnectOptions, VirtualTcpSocketFactory},
    udp::{UdpBindOptions, VirtualUdpSocketFactory},
};
use async_trait::async_trait;

use super::{
    HostOperationId, HostSocketHandle, HostSocketIo, HostSocketRuntime, HostTcpIo, HostTcpStream,
    udp::{HostUdpIo, HostUdpSocket},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostTcpConnectResult {
    pub handle: HostSocketHandle,
    pub local_addr: SocketAddr,
    pub peer_addr: SocketAddr,
    pub transport_label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUdpBindResult {
    pub handle: HostSocketHandle,
    pub local_addr: SocketAddr,
}

/// Mechanical creation of host-owned socket resources.
///
/// Submit methods start work without blocking the guest. Completion results own
/// their handles and address metadata. Canceling an operation must atomically
/// stop pending creation or close and discard a resource that completed before
/// core observed it, so dropping a factory future cannot leak a host socket.
pub trait HostSocketFactoryIo: HostSocketIo {
    fn submit_tcp_connect(
        &self,
        operation: HostOperationId,
        options: &TcpConnectOptions,
    ) -> io::Result<()>;

    fn take_tcp_connect(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<HostTcpConnectResult>>;

    fn submit_udp_bind(
        &self,
        operation: HostOperationId,
        options: &UdpBindOptions,
    ) -> io::Result<()>;

    fn take_udp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpBindResult>>;
}

pub trait HostSocketBackend: HostSocketFactoryIo + HostTcpIo + HostUdpIo {}

impl<T> HostSocketBackend for T where T: HostSocketFactoryIo + HostTcpIo + HostUdpIo {}

pub struct HostSocketFactory<B>
where
    B: HostSocketBackend,
{
    runtime: HostSocketRuntime,
    backend: Arc<B>,
}

impl<B> Clone for HostSocketFactory<B>
where
    B: HostSocketBackend,
{
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            backend: self.backend.clone(),
        }
    }
}

impl<B> HostSocketFactory<B>
where
    B: HostSocketBackend,
{
    pub fn new(runtime: HostSocketRuntime, backend: Arc<B>) -> Self {
        Self { runtime, backend }
    }

    async fn connect_tcp(&self, options: TcpConnectOptions) -> io::Result<HostTcpStream> {
        let result = self
            .runtime
            .run_operation(
                self.backend.clone(),
                |backend, operation| backend.submit_tcp_connect(operation, &options),
                |backend, operation| backend.take_tcp_connect(operation),
                |backend, operation| backend.cancel_operation(operation),
            )
            .await?;
        Ok(self.runtime.tcp_stream(
            self.backend.clone(),
            result.handle,
            result.local_addr,
            result.peer_addr,
            result.transport_label,
        ))
    }

    async fn bind_udp(&self, options: UdpBindOptions) -> io::Result<Arc<HostUdpSocket>> {
        let context = options.context.clone();
        let result = self
            .runtime
            .run_operation(
                self.backend.clone(),
                |backend, operation| backend.submit_udp_bind(operation, &options),
                |backend, operation| backend.take_udp_bind(operation),
                |backend, operation| backend.cancel_operation(operation),
            )
            .await?;
        Ok(Arc::new(self.runtime.udp_socket_with_context(
            self.backend.clone(),
            result.handle,
            result.local_addr,
            context,
        )))
    }
}

#[async_trait]
impl<B> VirtualTcpSocketFactory for HostSocketFactory<B>
where
    B: HostSocketBackend,
{
    type Socket = HostTcpStream;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        Ok(self.connect_tcp(options).await?)
    }
}

#[async_trait]
impl<B> VirtualUdpSocketFactory for HostSocketFactory<B>
where
    B: HostSocketBackend,
{
    type Socket = HostUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        Ok(self.bind_udp(options).await?)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        sync::Mutex,
    };

    use crate::socket::{
        tcp::{TcpBindOptions, TcpSocketPurpose, VirtualTcpSocket},
        udp::{UdpSocketPurpose, UdpSocketSendMeta, VirtualUdpSocket},
    };

    use super::*;

    enum TestCreate {
        Tcp {
            options: TcpConnectOptions,
            result: Option<io::Result<HostTcpConnectResult>>,
        },
        Udp {
            options: UdpBindOptions,
            result: Option<io::Result<HostUdpBindResult>>,
        },
    }

    #[derive(Default)]
    struct TestHostIo {
        creates: Mutex<HashMap<HostOperationId, TestCreate>>,
        cancelled: Mutex<Vec<HostOperationId>>,
        closed: Mutex<HashSet<HostSocketHandle>>,
    }

    impl TestHostIo {
        fn operation(&self, tcp: bool) -> HostOperationId {
            self.creates
                .lock()
                .unwrap()
                .iter()
                .find_map(|(operation, create)| match (tcp, create) {
                    (true, TestCreate::Tcp { .. }) | (false, TestCreate::Udp { .. }) => {
                        Some(*operation)
                    }
                    _ => None,
                })
                .unwrap()
        }

        fn complete_tcp(&self, operation: HostOperationId, result: HostTcpConnectResult) {
            let mut creates = self.creates.lock().unwrap();
            let TestCreate::Tcp {
                result: completion, ..
            } = creates.get_mut(&operation).unwrap()
            else {
                panic!("operation is not TCP connect");
            };
            *completion = Some(Ok(result));
        }

        fn complete_udp(&self, operation: HostOperationId, result: HostUdpBindResult) {
            let mut creates = self.creates.lock().unwrap();
            let TestCreate::Udp {
                result: completion, ..
            } = creates.get_mut(&operation).unwrap()
            else {
                panic!("operation is not UDP bind");
            };
            *completion = Some(Ok(result));
        }
    }

    impl HostSocketIo for TestHostIo {
        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            if let Some(create) = self.creates.lock().unwrap().remove(&operation) {
                let handle = match create {
                    TestCreate::Tcp {
                        result: Some(Ok(result)),
                        ..
                    } => Some(result.handle),
                    TestCreate::Udp {
                        result: Some(Ok(result)),
                        ..
                    } => Some(result.handle),
                    _ => None,
                };
                if let Some(handle) = handle {
                    self.closed.lock().unwrap().insert(handle);
                }
            }
            self.cancelled.lock().unwrap().push(operation);
            Ok(())
        }

        fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
            self.closed.lock().unwrap().insert(handle);
            Ok(())
        }
    }

    impl HostSocketFactoryIo for TestHostIo {
        fn submit_tcp_connect(
            &self,
            operation: HostOperationId,
            options: &TcpConnectOptions,
        ) -> io::Result<()> {
            self.creates.lock().unwrap().insert(
                operation,
                TestCreate::Tcp {
                    options: options.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_tcp_connect(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<HostTcpConnectResult>> {
            let mut creates = self.creates.lock().unwrap();
            let Some(TestCreate::Tcp { result, .. }) = creates.get_mut(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            creates.remove(&operation);
            Poll::Ready(result)
        }

        fn submit_udp_bind(
            &self,
            operation: HostOperationId,
            options: &UdpBindOptions,
        ) -> io::Result<()> {
            self.creates.lock().unwrap().insert(
                operation,
                TestCreate::Udp {
                    options: options.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_udp_bind(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpBindResult>> {
            let mut creates = self.creates.lock().unwrap();
            let Some(TestCreate::Udp { result, .. }) = creates.get_mut(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            creates.remove(&operation);
            Poll::Ready(result)
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

    impl HostUdpIo for TestHostIo {
        fn submit_recv(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn take_recv(
            &self,
            _operation: HostOperationId,
        ) -> Poll<io::Result<crate::host::socket::udp::HostUdpDatagram>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }

        fn try_send(
            &self,
            _handle: HostSocketHandle,
            _source: &[u8],
            _peer_addr: SocketAddr,
            _meta: UdpSocketSendMeta,
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn submit_send_ready(
            &self,
            _handle: HostSocketHandle,
            _operation: HostOperationId,
        ) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn take_send_ready(&self, _operation: HostOperationId) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
    }

    fn test_factory(io: Arc<TestHostIo>) -> (HostSocketRuntime, HostSocketFactory<TestHostIo>) {
        let runtime = HostSocketRuntime::new();
        let factory = HostSocketFactory::new(runtime.clone(), io);
        (runtime, factory)
    }

    #[tokio::test]
    async fn forwards_tcp_connect_options_and_wraps_completed_handle() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, factory) = test_factory(io.clone());
        let options = TcpConnectOptions {
            remote_addr: "192.0.2.2:11013".parse().unwrap(),
            bind: TcpBindOptions::default()
                .with_local_addr(Some("192.0.2.1:0".parse().unwrap()))
                .with_socket_mark(Some(7))
                .with_bind_device(Some("host-device".to_owned()))
                .with_reuse_port(true),
            purpose: TcpSocketPurpose::ManualConnect,
        };
        let task = tokio::spawn({
            let factory = factory.clone();
            let options = options.clone();
            async move { VirtualTcpSocketFactory::connect_tcp(&factory, options).await }
        });
        tokio::task::yield_now().await;
        let operation = io.operation(true);
        {
            let creates = io.creates.lock().unwrap();
            let TestCreate::Tcp {
                options: submitted, ..
            } = creates.get(&operation).unwrap()
            else {
                panic!("operation is not TCP connect");
            };
            assert_eq!(submitted, &options);
        }

        io.complete_tcp(
            operation,
            HostTcpConnectResult {
                handle: HostSocketHandle(41),
                local_addr: "192.0.2.1:40100".parse().unwrap(),
                peer_addr: options.remote_addr,
                transport_label: Some("host-tcp".to_owned()),
            },
        );
        runtime.notify_completions();
        let stream = task.await.unwrap().unwrap();
        assert_eq!(
            stream.local_addr().unwrap(),
            "192.0.2.1:40100".parse().unwrap()
        );
        assert_eq!(stream.peer_addr().unwrap(), options.remote_addr);
        assert_eq!(stream.transport_label(), Some("host-tcp"));
        drop(stream);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(41)));
    }

    #[tokio::test]
    async fn forwards_udp_bind_options_and_wraps_completed_handle() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, factory) = test_factory(io.clone());
        let options = UdpBindOptions {
            context: crate::socket::SocketContext::default().with_socket_mark(Some(9)),
            local_addr: Some("[::]:11013".parse().unwrap()),
            bind_device: Some("host-device".to_owned()),
            reuse_addr: true,
            reuse_port: true,
            only_v6: true,
            purpose: UdpSocketPurpose::PortBoundListener,
        };
        let task = tokio::spawn({
            let factory = factory.clone();
            let options = options.clone();
            async move { VirtualUdpSocketFactory::bind_udp(&factory, options).await }
        });
        tokio::task::yield_now().await;
        let operation = io.operation(false);
        {
            let creates = io.creates.lock().unwrap();
            let TestCreate::Udp {
                options: submitted, ..
            } = creates.get(&operation).unwrap()
            else {
                panic!("operation is not UDP bind");
            };
            assert_eq!(submitted, &options);
        }

        io.complete_udp(
            operation,
            HostUdpBindResult {
                handle: HostSocketHandle(42),
                local_addr: "[::]:11013".parse().unwrap(),
            },
        );
        runtime.notify_completions();
        let socket = task.await.unwrap().unwrap();
        assert_eq!(socket.local_addr().unwrap(), "[::]:11013".parse().unwrap());
        drop(socket);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(42)));
    }

    #[tokio::test]
    async fn cancelling_completed_create_closes_unobserved_handle() {
        let io = Arc::new(TestHostIo::default());
        let (_runtime, factory) = test_factory(io.clone());
        let options = TcpConnectOptions::direct_connect("192.0.2.2:11013".parse().unwrap());
        let mut connect = Box::pin(VirtualTcpSocketFactory::connect_tcp(
            &factory,
            options.clone(),
        ));
        assert!(futures::poll!(&mut connect).is_pending());
        let operation = io.operation(true);
        io.complete_tcp(
            operation,
            HostTcpConnectResult {
                handle: HostSocketHandle(43),
                local_addr: "192.0.2.1:40101".parse().unwrap(),
                peer_addr: options.remote_addr,
                transport_label: None,
            },
        );
        drop(connect);

        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(43)));
    }
}

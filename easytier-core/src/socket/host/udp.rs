use std::{fmt, future::poll_fn, io, net::SocketAddr, sync::Arc, task::Poll};

use async_trait::async_trait;

use crate::socket::udp::{UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket};

use super::{HostOperationId, HostSocketHandle, HostSocketIo, HostSocketRuntime};

/// One host-owned UDP receive completion.
#[derive(Debug)]
pub struct HostUdpDatagram {
    pub data: Vec<u8>,
    pub peer_addr: SocketAddr,
    pub meta: UdpSocketRecvMeta,
}

/// Mechanical host UDP I/O below core's datagram scheduling seam.
///
/// Submit methods must return without waiting for I/O. `submit_send` must copy
/// or otherwise own the complete datagram before returning. A successful send
/// completion means the complete datagram was sent atomically. Receive
/// completions own their payload and are consumed by `take_recv`.
pub trait HostUdpIo: HostSocketIo {
    fn submit_recv(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>>;

    fn submit_send(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
        peer_addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<()>;

    fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>>;
}

struct PendingHostUdpOperation {
    runtime: HostSocketRuntime,
    io: Arc<dyn HostUdpIo>,
    operation: HostOperationId,
    completed: bool,
}

impl PendingHostUdpOperation {
    fn new(runtime: HostSocketRuntime, io: Arc<dyn HostUdpIo>, operation: HostOperationId) -> Self {
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

impl Drop for PendingHostUdpOperation {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.runtime.inner.wakers.remove(self.operation);
        let _ = self.io.cancel_operation(self.operation);
    }
}

pub struct HostUdpSocket {
    runtime: HostSocketRuntime,
    io: Arc<dyn HostUdpIo>,
    handle: HostSocketHandle,
    local_addr: SocketAddr,
}

impl HostSocketRuntime {
    pub fn udp_socket(
        &self,
        io: Arc<dyn HostUdpIo>,
        handle: HostSocketHandle,
        local_addr: SocketAddr,
    ) -> HostUdpSocket {
        HostUdpSocket {
            runtime: self.clone(),
            io,
            handle,
            local_addr,
        }
    }
}

impl HostUdpSocket {
    async fn send(
        &self,
        data: &[u8],
        peer_addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<usize> {
        let operation = self.runtime.next_operation();
        self.io
            .submit_send(self.handle, operation, data, peer_addr, meta)?;
        let mut pending =
            PendingHostUdpOperation::new(self.runtime.clone(), self.io.clone(), operation);
        poll_fn(|context| {
            let epoch = self
                .runtime
                .inner
                .completion_epoch
                .load(std::sync::atomic::Ordering::SeqCst);
            match self.io.take_send(operation) {
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
        .await?;
        Ok(data.len())
    }

    async fn receive(&self, buffer: &mut [u8]) -> io::Result<HostUdpDatagram> {
        let operation = self.runtime.next_operation();
        self.io.submit_recv(self.handle, operation, buffer.len())?;
        let mut pending =
            PendingHostUdpOperation::new(self.runtime.clone(), self.io.clone(), operation);
        let datagram = poll_fn(|context| {
            let epoch = self
                .runtime
                .inner
                .completion_epoch
                .load(std::sync::atomic::Ordering::SeqCst);
            match self.io.take_recv(operation) {
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
        .await?;

        if datagram.data.len() > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host UDP receive completion exceeds the submitted capacity",
            ));
        }
        buffer[..datagram.data.len()].copy_from_slice(&datagram.data);
        Ok(datagram)
    }
}

impl fmt::Debug for HostUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostUdpSocket")
            .field("handle", &self.handle)
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl VirtualUdpSocket for HostUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.send(data, addr, UdpSocketSendMeta::default()).await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let datagram = self.receive(buffer).await?;
        Ok((datagram.data.len(), datagram.peer_addr))
    }

    async fn send_to_with_meta(
        &self,
        data: &[u8],
        addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<usize> {
        self.send(data, addr, meta).await
    }

    async fn recv_from_with_meta(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, UdpSocketRecvMeta)> {
        let datagram = self.receive(buffer).await?;
        Ok((datagram.data.len(), datagram.peer_addr, datagram.meta))
    }
}

impl Drop for HostUdpSocket {
    fn drop(&mut self) {
        let _ = self.io.close(self.handle);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr},
        sync::Mutex,
    };

    use super::*;

    enum TestOperation {
        Receive(Option<io::Result<HostUdpDatagram>>),
        Send {
            source: Vec<u8>,
            peer_addr: SocketAddr,
            meta: UdpSocketSendMeta,
            result: Option<io::Result<()>>,
        },
    }

    #[derive(Default)]
    struct TestHostUdpIo {
        operations: Mutex<HashMap<HostOperationId, TestOperation>>,
        cancelled: Mutex<Vec<HostOperationId>>,
        closed: Mutex<HashSet<HostSocketHandle>>,
    }

    impl TestHostUdpIo {
        fn operation(&self, receive: bool) -> HostOperationId {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, operation)| match (receive, operation) {
                    (true, TestOperation::Receive(_)) | (false, TestOperation::Send { .. }) => {
                        Some(*id)
                    }
                    _ => None,
                })
                .expect("operation was not submitted")
        }

        fn complete_recv(&self, operation: HostOperationId, datagram: HostUdpDatagram) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Receive(result) = operations.get_mut(&operation).unwrap() else {
                panic!("operation is not a receive");
            };
            *result = Some(Ok(datagram));
        }

        fn complete_send(&self, operation: HostOperationId) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Send { result, .. } = operations.get_mut(&operation).unwrap() else {
                panic!("operation is not a send");
            };
            *result = Some(Ok(()));
        }
    }

    impl HostSocketIo for TestHostUdpIo {
        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            self.operations.lock().unwrap().remove(&operation);
            self.cancelled.lock().unwrap().push(operation);
            Ok(())
        }

        fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
            self.closed.lock().unwrap().insert(handle);
            Ok(())
        }
    }

    impl HostUdpIo for TestHostUdpIo {
        fn submit_recv(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            self.operations
                .lock()
                .unwrap()
                .insert(operation, TestOperation::Receive(None));
            Ok(())
        }

        fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Receive(result)) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "receive operation is missing",
                )));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }

        fn submit_send(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            source: &[u8],
            peer_addr: SocketAddr,
            meta: UdpSocketSendMeta,
        ) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestOperation::Send {
                    source: source.to_vec(),
                    peer_addr,
                    meta,
                    result: None,
                },
            );
            Ok(())
        }

        fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Send { result, .. }) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "send operation is missing",
                )));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }
    }

    fn test_socket(io: Arc<TestHostUdpIo>) -> (HostSocketRuntime, HostUdpSocket) {
        let runtime = HostSocketRuntime::new();
        let socket =
            runtime.udp_socket(io, HostSocketHandle(9), "192.0.2.1:11013".parse().unwrap());
        (runtime, socket)
    }

    #[tokio::test]
    async fn send_owns_datagram_and_waits_for_atomic_completion() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let socket = Arc::new(socket);
        let peer_addr = "192.0.2.2:22026".parse().unwrap();
        let source_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let task = tokio::spawn({
            let socket = socket.clone();
            async move {
                socket
                    .send_to_with_meta(
                        b"udp",
                        peer_addr,
                        UdpSocketSendMeta {
                            src_ip: Some(source_ip),
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;

        let operation = io.operation(false);
        {
            let operations = io.operations.lock().unwrap();
            let TestOperation::Send {
                source,
                peer_addr: submitted_peer,
                meta,
                ..
            } = operations.get(&operation).unwrap()
            else {
                panic!("operation is not a send");
            };
            assert_eq!(source, b"udp");
            assert_eq!(*submitted_peer, peer_addr);
            assert_eq!(meta.src_ip, Some(source_ip));
        }

        io.complete_send(operation);
        runtime.notify_completions();
        assert_eq!(task.await.unwrap().unwrap(), 3);
        drop(socket);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(9)));
    }

    #[tokio::test]
    async fn receive_returns_owned_payload_peer_and_destination_metadata() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let socket = Arc::new(socket);
        let peer_addr = "192.0.2.2:22026".parse().unwrap();
        let destination_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        let task = tokio::spawn({
            let socket = socket.clone();
            async move {
                let mut buffer = [0_u8; 4];
                let result = socket.recv_from_with_meta(&mut buffer).await;
                (result, buffer)
            }
        });
        tokio::task::yield_now().await;

        let operation = io.operation(true);
        io.complete_recv(
            operation,
            HostUdpDatagram {
                data: b"data".to_vec(),
                peer_addr,
                meta: UdpSocketRecvMeta {
                    dst_ip: Some(destination_ip),
                },
            },
        );
        runtime.notify_completions();

        let (result, buffer) = task.await.unwrap();
        let (length, received_peer, meta) = result.unwrap();
        assert_eq!(length, 4);
        assert_eq!(&buffer, b"data");
        assert_eq!(received_peer, peer_addr);
        assert_eq!(meta.dst_ip, Some(destination_ip));
    }

    #[tokio::test]
    async fn cancelling_receive_removes_waker_and_cancels_host_operation() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let operation = {
            let mut buffer = [0_u8; 1];
            let mut receive = Box::pin(socket.recv_from(&mut buffer));
            assert!(futures::poll!(&mut receive).is_pending());
            let operation = io.operation(true);
            assert_eq!(runtime.inner.wakers.len(), 1);
            drop(receive);
            operation
        };

        assert_eq!(runtime.inner.wakers.len(), 0);
        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        drop(socket);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(9)));
    }
}

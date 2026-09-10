use std::{fmt, io, net::SocketAddr, sync::Arc, task::Poll};

use async_trait::async_trait;

use crate::socket::{
    SocketContext,
    udp::{UdpSocketRecvMeta, UdpSocketSendMeta, VirtualUdpSocket},
};

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
/// Submit methods register readiness without performing the datagram I/O.
/// Receive datagrams stay in a host-owned socket queue until `take_recv` is
/// called from a guest poll, so canceling a waiter cannot consume a datagram.
/// `try_send` must synchronously copy one complete datagram into a bounded host
/// queue or return `WouldBlock`; it must never retain guest-memory borrows.
pub trait HostUdpIo: HostSocketIo {
    fn submit_recv(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>>;

    fn try_send(
        &self,
        handle: HostSocketHandle,
        source: &[u8],
        peer_addr: SocketAddr,
        meta: UdpSocketSendMeta,
    ) -> io::Result<()>;

    fn submit_send_ready(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
    ) -> io::Result<()>;

    fn take_send_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>>;
}

pub struct HostUdpSocket {
    runtime: HostSocketRuntime,
    io: Arc<dyn HostUdpIo>,
    handle: HostSocketHandle,
    local_addr: SocketAddr,
    context: SocketContext,
}

impl HostSocketRuntime {
    pub fn udp_socket(
        &self,
        io: Arc<dyn HostUdpIo>,
        handle: HostSocketHandle,
        local_addr: SocketAddr,
    ) -> HostUdpSocket {
        self.udp_socket_with_context(io, handle, local_addr, SocketContext::default())
    }

    pub fn udp_socket_with_context(
        &self,
        io: Arc<dyn HostUdpIo>,
        handle: HostSocketHandle,
        local_addr: SocketAddr,
        context: SocketContext,
    ) -> HostUdpSocket {
        HostUdpSocket {
            runtime: self.clone(),
            io,
            handle,
            local_addr,
            context,
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
        loop {
            match self.io.try_send(self.handle, data, peer_addr, meta) {
                Ok(()) => return Ok(data.len()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }

            self.runtime
                .run_operation(
                    self.io.clone(),
                    |io, operation| io.submit_send_ready(self.handle, operation),
                    |io, operation| io.take_send_ready(operation),
                    |io, operation| io.cancel_operation(operation),
                )
                .await?;
        }
    }

    async fn receive(&self, buffer: &mut [u8]) -> io::Result<HostUdpDatagram> {
        let datagram = self
            .runtime
            .run_operation(
                self.io.clone(),
                |io, operation| io.submit_recv(self.handle, operation, buffer.len()),
                |io, operation| io.take_recv(operation),
                |io, operation| io.cancel_operation(operation),
            )
            .await?;

        let copy_len = datagram.data.len().min(buffer.len());
        buffer[..copy_len].copy_from_slice(&datagram.data[..copy_len]);
        let mut datagram = datagram;
        datagram.data.truncate(copy_len);
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

    fn socket_context(&self) -> SocketContext {
        self.context.clone()
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
        collections::{HashMap, HashSet, VecDeque},
        net::{IpAddr, Ipv4Addr},
        sync::{
            Mutex,
            atomic::{AtomicBool, Ordering},
        },
    };

    use super::*;

    enum TestOperation {
        Receive,
        SendReady(Option<io::Result<()>>),
    }

    #[derive(Default)]
    struct TestHostUdpIo {
        operations: Mutex<HashMap<HostOperationId, TestOperation>>,
        received: Mutex<VecDeque<HostUdpDatagram>>,
        sent: Mutex<Vec<(Vec<u8>, SocketAddr, UdpSocketSendMeta)>>,
        writable: AtomicBool,
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
                    (true, TestOperation::Receive) | (false, TestOperation::SendReady(_)) => {
                        Some(*id)
                    }
                    _ => None,
                })
                .expect("operation was not submitted")
        }

        fn complete_recv(&self, operation: HostOperationId, datagram: HostUdpDatagram) {
            let operations = self.operations.lock().unwrap();
            let TestOperation::Receive = operations.get(&operation).unwrap() else {
                panic!("operation is not a receive");
            };
            self.received.lock().unwrap().push_back(datagram);
        }

        fn complete_send(&self, operation: HostOperationId) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::SendReady(result) = operations.get_mut(&operation).unwrap() else {
                panic!("operation is not a send");
            };
            *result = Some(Ok(()));
            self.writable.store(true, Ordering::SeqCst);
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
                .insert(operation, TestOperation::Receive);
            Ok(())
        }

        fn take_recv(&self, operation: HostOperationId) -> Poll<io::Result<HostUdpDatagram>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Receive) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "receive operation is missing",
                )));
            };
            let Some(datagram) = self.received.lock().unwrap().pop_front() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(Ok(datagram))
        }

        fn try_send(
            &self,
            _handle: HostSocketHandle,
            source: &[u8],
            peer_addr: SocketAddr,
            meta: UdpSocketSendMeta,
        ) -> io::Result<()> {
            if !self.writable.swap(false, Ordering::SeqCst) {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.sent
                .lock()
                .unwrap()
                .push((source.to_vec(), peer_addr, meta));
            Ok(())
        }

        fn submit_send_ready(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
        ) -> io::Result<()> {
            self.operations
                .lock()
                .unwrap()
                .insert(operation, TestOperation::SendReady(None));
            Ok(())
        }

        fn take_send_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::SendReady(result)) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "send readiness operation is missing",
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
    async fn send_waits_for_readiness_then_enqueues_atomically() {
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
                            src_ifindex: None,
                        },
                    )
                    .await
            }
        });
        tokio::task::yield_now().await;

        let operation = io.operation(false);
        assert!(io.sent.lock().unwrap().is_empty());

        io.complete_send(operation);
        runtime.notify_completions();
        assert_eq!(task.await.unwrap().unwrap(), 3);
        assert_eq!(
            *io.sent.lock().unwrap(),
            vec![(
                b"udp".to_vec(),
                peer_addr,
                UdpSocketSendMeta {
                    src_ip: Some(source_ip),
                    src_ifindex: None,
                }
            )]
        );
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
    async fn cancelling_completed_receive_preserves_datagram_for_next_poll() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let peer_addr = "192.0.2.2:22026".parse().unwrap();
        let operation = {
            let mut buffer = [0_u8; 1];
            let mut receive = Box::pin(socket.recv_from(&mut buffer));
            assert!(futures::poll!(&mut receive).is_pending());
            let operation = io.operation(true);
            assert_eq!(runtime.inner.wakers.len(), 1);
            io.complete_recv(
                operation,
                HostUdpDatagram {
                    data: b"kept".to_vec(),
                    peer_addr,
                    meta: UdpSocketRecvMeta::default(),
                },
            );
            runtime.notify_completions();
            drop(receive);
            operation
        };

        assert_eq!(runtime.inner.wakers.len(), 0);
        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        let mut recovered = [0_u8; 4];
        assert_eq!(
            socket.recv_from(&mut recovered).await.unwrap(),
            (4, peer_addr)
        );
        assert_eq!(&recovered, b"kept");
        drop(socket);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(9)));
    }

    #[tokio::test]
    async fn cancelling_send_readiness_never_enqueues_datagram() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let peer_addr = "192.0.2.2:22026".parse().unwrap();
        let operation = {
            let mut send = Box::pin(socket.send_to(b"cancelled", peer_addr));
            assert!(futures::poll!(&mut send).is_pending());
            let operation = io.operation(false);
            io.complete_send(operation);
            runtime.notify_completions();
            drop(send);
            operation
        };

        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        assert!(io.sent.lock().unwrap().is_empty());
    }

    async fn receive_payload<const N: usize>(
        runtime: &HostSocketRuntime,
        io: &Arc<TestHostUdpIo>,
        socket: Arc<HostUdpSocket>,
        payload: Vec<u8>,
    ) -> (usize, [u8; N]) {
        let peer_addr = "192.0.2.2:22026".parse().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0_u8; N];
            let (length, _) = socket.recv_from(&mut buffer).await.unwrap();
            (length, buffer)
        });
        tokio::task::yield_now().await;
        let operation = io.operation(true);
        io.complete_recv(
            operation,
            HostUdpDatagram {
                data: payload,
                peer_addr,
                meta: UdpSocketRecvMeta::default(),
            },
        );
        runtime.notify_completions();
        task.await.unwrap()
    }

    #[tokio::test]
    async fn receive_truncates_and_distinguishes_empty_buffers_from_datagrams() {
        let io = Arc::new(TestHostUdpIo::default());
        let (runtime, socket) = test_socket(io.clone());
        let socket = Arc::new(socket);

        let (length, buffer) =
            receive_payload(&runtime, &io, socket.clone(), b"long".to_vec()).await;
        assert_eq!((length, buffer), (2, *b"lo"));

        let (length, buffer) =
            receive_payload::<0>(&runtime, &io, socket.clone(), b"consumed".to_vec()).await;
        assert_eq!((length, buffer), (0, []));

        let (length, buffer) = receive_payload(&runtime, &io, socket, Vec::new()).await;
        assert_eq!((length, buffer), (0, [0]));
    }
}

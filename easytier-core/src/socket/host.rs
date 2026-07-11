use std::{
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tcp::VirtualTcpSocket;

#[cfg(target_os = "wasi")]
pub mod wasi;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostSocketHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostOperationId(pub u64);

/// Mechanical host I/O below core's socket scheduling seam.
///
/// Submit methods must return without waiting for I/O. `submit_write` must take
/// ownership of the submitted bytes before returning; it may not retain the
/// borrowed slice. Completion methods may copy completed data into guest memory
/// only during the call.
pub trait HostTcpIo: Send + Sync + 'static {
    fn submit_read(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_read(
        &self,
        operation: HostOperationId,
        destination: &mut [u8],
    ) -> Poll<io::Result<usize>>;

    fn submit_write(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()>;

    fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<usize>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;

    /// Close must be idempotent.
    fn close(&self, handle: HostSocketHandle) -> io::Result<()>;
}

#[derive(Default)]
struct WakerRegistry {
    wakers: Mutex<Vec<Waker>>,
}

impl WakerRegistry {
    fn register(&self, waker: &Waker) {
        let mut wakers = self.wakers.lock().expect("host waker registry poisoned");
        if !wakers.iter().any(|registered| registered.will_wake(waker)) {
            wakers.push(waker.clone());
        }
    }

    fn wake_all(&self) {
        let wakers = {
            let mut registered = self.wakers.lock().expect("host waker registry poisoned");
            std::mem::take(&mut *registered)
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

struct HostSocketRuntimeInner {
    io: Arc<dyn HostTcpIo>,
    next_operation: AtomicU64,
    wakers: WakerRegistry,
}

#[derive(Clone)]
pub struct HostSocketRuntime {
    inner: Arc<HostSocketRuntimeInner>,
}

impl HostSocketRuntime {
    pub fn new(io: Arc<dyn HostTcpIo>) -> Self {
        Self {
            inner: Arc::new(HostSocketRuntimeInner {
                io,
                next_operation: AtomicU64::new(1),
                wakers: WakerRegistry::default(),
            }),
        }
    }

    pub fn tcp_stream(
        &self,
        handle: HostSocketHandle,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        transport_label: Option<String>,
    ) -> HostTcpStream {
        HostTcpStream {
            runtime: self.clone(),
            handle,
            local_addr,
            peer_addr,
            transport_label,
            read_operation: None,
            write_operation: None,
            closed: false,
        }
    }

    /// Wake socket tasks after the host reports one or more completions.
    pub fn notify_completions(&self) {
        self.inner.wakers.wake_all();
    }

    fn next_operation(&self) -> HostOperationId {
        HostOperationId(self.inner.next_operation.fetch_add(1, Ordering::Relaxed))
    }
}

pub struct HostTcpStream {
    runtime: HostSocketRuntime,
    handle: HostSocketHandle,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    transport_label: Option<String>,
    read_operation: Option<HostOperationId>,
    write_operation: Option<PendingWrite>,
    closed: bool,
}

struct PendingWrite {
    operation: HostOperationId,
    data: Vec<u8>,
    offset: usize,
}

impl HostTcpStream {
    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        let mut first_error = None;
        if let Some(operation) = self.read_operation.take()
            && let Err(error) = self.runtime.inner.io.cancel_operation(operation)
        {
            first_error = Some(error);
        }
        if let Some(pending) = self.write_operation.take()
            && let Err(error) = self.runtime.inner.io.cancel_operation(pending.operation)
            && first_error.is_none()
        {
            first_error = Some(error);
        }
        if let Err(error) = self.runtime.inner.io.close(self.handle)
            && first_error.is_none()
        {
            first_error = Some(error);
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn submit_write(&mut self, data: Vec<u8>) -> io::Result<()> {
        let operation = self.runtime.next_operation();
        self.runtime
            .inner
            .io
            .submit_write(self.handle, operation, &data)?;
        self.write_operation = Some(PendingWrite {
            operation,
            data,
            offset: 0,
        });
        Ok(())
    }

    fn poll_pending_write(&mut self, context: &mut Context<'_>) -> Poll<io::Result<usize>> {
        loop {
            let Some(pending) = &self.write_operation else {
                return Poll::Ready(Ok(0));
            };
            let operation = pending.operation;
            let remaining_len = pending.data.len() - pending.offset;
            match self.runtime.inner.io.take_write(operation) {
                Poll::Pending => {
                    self.runtime.inner.wakers.register(context.waker());
                    return Poll::Pending;
                }
                Poll::Ready(Err(error)) => {
                    self.write_operation = None;
                    return Poll::Ready(Err(error));
                }
                Poll::Ready(Ok(0)) => {
                    self.write_operation = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "host write operation made no progress",
                    )));
                }
                Poll::Ready(Ok(length)) if length > remaining_len => {
                    self.write_operation = None;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host write completion exceeds the submitted buffer",
                    )));
                }
                Poll::Ready(Ok(length)) => {
                    let pending = self.write_operation.as_mut().unwrap();
                    pending.offset += length;
                    if pending.offset == pending.data.len() {
                        let completed_len = pending.data.len();
                        self.write_operation = None;
                        return Poll::Ready(Ok(completed_len));
                    }

                    let operation = self.runtime.next_operation();
                    let pending = self.write_operation.as_mut().unwrap();
                    if let Err(error) = self.runtime.inner.io.submit_write(
                        self.handle,
                        operation,
                        &pending.data[pending.offset..],
                    ) {
                        self.write_operation = None;
                        return Poll::Ready(Err(error));
                    }
                    pending.operation = operation;
                }
            }
        }
    }
}

impl fmt::Debug for HostTcpStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostTcpStream")
            .field("handle", &self.handle)
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .field("transport_label", &self.transport_label)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for HostTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed || buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let operation = match self.read_operation {
            Some(operation) => operation,
            None => {
                let operation = self.runtime.next_operation();
                if let Err(error) =
                    self.runtime
                        .inner
                        .io
                        .submit_read(self.handle, operation, buffer.remaining())
                {
                    return Poll::Ready(Err(error));
                }
                self.read_operation = Some(operation);
                operation
            }
        };

        let destination = buffer.initialize_unfilled();
        match self.runtime.inner.io.take_read(operation, destination) {
            Poll::Pending => {
                self.runtime.inner.wakers.register(context.waker());
                Poll::Pending
            }
            Poll::Ready(result) => {
                self.read_operation = None;
                match result {
                    Ok(length) if length <= destination.len() => {
                        buffer.advance(length);
                        Poll::Ready(Ok(()))
                    }
                    Ok(_) => Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host read completion exceeds the guest buffer",
                    ))),
                    Err(error) => Poll::Ready(Err(error)),
                }
            }
        }
    }
}

impl AsyncWrite for HostTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "host TCP stream is closed",
            )));
        }
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }

        loop {
            if let Some(pending) = &self.write_operation {
                let same_write = pending.data.as_slice() == buffer;
                match self.poll_pending_write(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Ready(Ok(length)) if same_write => return Poll::Ready(Ok(length)),
                    Poll::Ready(Ok(_)) => continue,
                }
            }

            if let Err(error) = self.submit_write(buffer.to_vec()) {
                return Poll::Ready(Err(error));
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending_write(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => Poll::Ready(result.map(|_| ())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.write_operation.is_some() {
            match self.poll_pending_write(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Poll::Ready(self.close())
    }
}

impl VirtualTcpSocket for HostTcpStream {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }

    fn transport_label(&self) -> Option<&str> {
        self.transport_label.as_deref()
    }
}

impl Drop for HostTcpStream {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    enum TestOperation {
        Read(Option<Vec<u8>>),
        Write {
            source: Vec<u8>,
            result: Option<usize>,
        },
    }

    #[derive(Default)]
    struct TestHostIo {
        operations: Mutex<HashMap<HostOperationId, TestOperation>>,
        cancelled: Mutex<Vec<HostOperationId>>,
        closed: Mutex<HashSet<HostSocketHandle>>,
    }

    impl TestHostIo {
        fn read_operation(&self) -> HostOperationId {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, operation)| {
                    matches!(operation, TestOperation::Read(_)).then_some(*id)
                })
                .expect("read operation was not submitted")
        }

        fn write_operation(&self) -> (HostOperationId, Vec<u8>) {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, operation)| match operation {
                    TestOperation::Write { source, .. } => Some((*id, source.clone())),
                    TestOperation::Read(_) => None,
                })
                .expect("write operation was not submitted")
        }

        fn complete_read(&self, operation: HostOperationId, data: Vec<u8>) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Read(result) = operations.get_mut(&operation).unwrap() else {
                panic!("operation is not a read");
            };
            *result = Some(data);
        }

        fn complete_write(&self, operation: HostOperationId, length: usize) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Write { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not a write");
            };
            *result = Some(length);
        }
    }

    impl HostTcpIo for TestHostIo {
        fn submit_read(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            self.operations
                .lock()
                .unwrap()
                .insert(operation, TestOperation::Read(None));
            Ok(())
        }

        fn take_read(
            &self,
            operation: HostOperationId,
            destination: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Read(Some(data))) = operations.get(&operation) else {
                return Poll::Pending;
            };
            if data.len() > destination.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "destination is too small",
                )));
            }
            destination[..data.len()].copy_from_slice(data);
            let length = data.len();
            operations.remove(&operation);
            Poll::Ready(Ok(length))
        }

        fn submit_write(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            source: &[u8],
        ) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestOperation::Write {
                    source: source.to_vec(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<usize>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Write {
                result: Some(length),
                ..
            }) = operations.get(&operation)
            else {
                return Poll::Pending;
            };
            let length = *length;
            operations.remove(&operation);
            Poll::Ready(Ok(length))
        }

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

    fn test_stream(io: Arc<TestHostIo>) -> (HostSocketRuntime, HostTcpStream) {
        let runtime = HostSocketRuntime::new(io);
        let stream = runtime.tcp_stream(
            HostSocketHandle(7),
            "192.0.2.1:10000".parse().unwrap(),
            "192.0.2.2:11013".parse().unwrap(),
            Some("host-test".to_owned()),
        );
        (runtime, stream)
    }

    #[tokio::test]
    async fn pending_completions_wake_read_and_write_tasks() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, stream) = test_stream(io.clone());
        assert_eq!(stream.transport_label(), Some("host-test"));
        let (mut reader, mut writer) = tokio::io::split(stream);

        let read_task = tokio::spawn(async move {
            let mut data = [0_u8; 3];
            reader.read_exact(&mut data).await.unwrap();
            data
        });
        tokio::task::yield_now().await;
        let read_operation = io.read_operation();
        io.complete_read(read_operation, b"abc".to_vec());
        runtime.notify_completions();
        assert_eq!(read_task.await.unwrap(), *b"abc");

        let write_task = tokio::spawn(async move {
            writer.write_all(b"xyz").await.unwrap();
            writer.shutdown().await.unwrap();
        });
        tokio::task::yield_now().await;
        let (write_operation, source) = io.write_operation();
        assert_eq!(source, b"xyz");
        io.complete_write(write_operation, 1);
        runtime.notify_completions();
        tokio::task::yield_now().await;
        let (write_operation, source) = io.write_operation();
        assert_eq!(source, b"yz");
        io.complete_write(write_operation, source.len());
        runtime.notify_completions();
        write_task.await.unwrap();

        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }

    #[tokio::test]
    async fn empty_read_completion_reports_eof() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, mut stream) = test_stream(io.clone());
        let read_task = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            stream.read(&mut byte).await.unwrap()
        });
        tokio::task::yield_now().await;
        let operation = io.read_operation();
        io.complete_read(operation, Vec::new());
        runtime.notify_completions();

        assert_eq!(read_task.await.unwrap(), 0);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }

    #[tokio::test]
    async fn dropping_pending_stream_cancels_operation_and_closes_handle() {
        let io = Arc::new(TestHostIo::default());
        let (_runtime, mut stream) = test_stream(io.clone());
        let read_task = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        tokio::task::yield_now().await;
        let operation = io.read_operation();
        read_task.abort();
        let _ = read_task.await;

        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }
}

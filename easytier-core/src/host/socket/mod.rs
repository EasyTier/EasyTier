//! Host-backed socket seams.
//!
//! This module holds the socket-flavoured Host capability seams. Core owns
//! socket I/O scheduling, backpressure, and protocol state; the host Adapter
//! behind these traits owns the mechanical endpoint operations (see
//! CONTEXT.md, "Socket"). [`HostSocketIo`] and [`HostTcpIo`] are the base
//! operation traits keyed by [`HostSocketHandle`] and [`HostOperationId`];
//! [`HostSocketRuntime`] schedules host completions; [`HostTcpStream`]
//! bridges host TCP I/O into core's socket traits. Socket creation lives in
//! [`factory`], TCP listener bind/accept in [`listener`], and the UDP
//! datagram bridge in [`udp`]. Concrete WASI adapters behind these seams live
//! in [`crate::wasi`].

use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, atomic::Ordering},
    task::{Context, Poll, Waker},
};

use atomic_shim::AtomicU64;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::socket::tcp::VirtualTcpSocket;

pub mod factory;
pub mod listener;
pub mod udp;

static NEXT_HOST_OPERATION: LazyLock<AtomicU64> = LazyLock::new(|| AtomicU64::new(1));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostSocketHandle(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostOperationId(pub u64);

/// Mechanical host I/O below core's socket scheduling seam.
pub trait HostSocketIo: Send + Sync + 'static {
    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;

    /// Close must be idempotent.
    fn close(&self, handle: HostSocketHandle) -> io::Result<()>;
}

/// Mechanical host TCP I/O below core's socket scheduling seam.
///
/// Submit methods must return without waiting for I/O. `submit_write` must take
/// ownership of the complete source before returning and complete only after
/// all accepted bytes are written or an error occurs. Completion methods return
/// host-owned results; they never retain guest-memory borrows.
pub trait HostTcpIo: HostSocketIo {
    fn submit_read(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_read(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>>;

    fn submit_write(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()>;

    fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<()>>;
}

#[derive(Default)]
pub(in crate::host) struct WakerRegistry {
    wakers: Mutex<HashMap<HostOperationId, Waker>>,
}

impl WakerRegistry {
    fn register(&self, operation: HostOperationId, waker: &Waker) {
        let mut wakers = self.wakers.lock().expect("host waker registry poisoned");
        match wakers.get_mut(&operation) {
            Some(registered) if registered.will_wake(waker) => {}
            Some(registered) => *registered = waker.clone(),
            None => {
                wakers.insert(operation, waker.clone());
            }
        }
    }

    pub(in crate::host) fn remove(&self, operation: HostOperationId) {
        self.wakers
            .lock()
            .expect("host waker registry poisoned")
            .remove(&operation);
    }

    fn wake_all(&self) {
        let wakers = {
            let mut registered = self.wakers.lock().expect("host waker registry poisoned");
            std::mem::take(&mut *registered)
        };
        for waker in wakers.into_values() {
            waker.wake();
        }
    }
}

pub(in crate::host) struct HostSocketRuntimeInner {
    pub(in crate::host) completion_epoch: AtomicU64,
    pub(in crate::host) wakers: WakerRegistry,
}

#[derive(Clone)]
pub struct HostSocketRuntime {
    pub(in crate::host) inner: Arc<HostSocketRuntimeInner>,
}

impl Default for HostSocketRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl HostSocketRuntime {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(HostSocketRuntimeInner {
                completion_epoch: AtomicU64::new(0),
                wakers: WakerRegistry::default(),
            }),
        }
    }

    pub fn tcp_stream(
        &self,
        io: Arc<dyn HostTcpIo>,
        handle: HostSocketHandle,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        transport_label: Option<String>,
    ) -> HostTcpStream {
        HostTcpStream {
            runtime: self.clone(),
            io,
            handle,
            local_addr,
            peer_addr,
            transport_label,
            read_operation: None,
            read_buffer: None,
            read_eof: false,
            write_operation: None,
            closed: false,
        }
    }

    /// Wake socket tasks after the host reports one or more completions.
    pub fn notify_completions(&self) {
        self.inner.completion_epoch.fetch_add(1, Ordering::SeqCst);
        self.inner.wakers.wake_all();
    }

    pub(in crate::host) fn next_operation(&self) -> HostOperationId {
        loop {
            let operation = NEXT_HOST_OPERATION.fetch_add(1, Ordering::Relaxed);
            if operation != 0 {
                return HostOperationId(operation);
            }
        }
    }

    pub(in crate::host) fn register_pending(
        &self,
        operation: HostOperationId,
        observed_epoch: u64,
        context: &Context<'_>,
    ) {
        self.inner.wakers.register(operation, context.waker());
        if self.inner.completion_epoch.load(Ordering::SeqCst) != observed_epoch {
            self.inner.wakers.remove(operation);
            context.waker().wake_by_ref();
        }
    }

    pub(in crate::host) async fn run_operation<I, T>(
        &self,
        io: Arc<I>,
        submit: impl FnOnce(&I, HostOperationId) -> io::Result<()>,
        take: impl Fn(&I, HostOperationId) -> Poll<io::Result<T>>,
        cancel: fn(&I, HostOperationId) -> io::Result<()>,
    ) -> io::Result<T>
    where
        I: ?Sized + Send + Sync + 'static,
    {
        let operation = self.next_operation();
        submit(io.as_ref(), operation)?;
        let mut pending = PendingHostOperation::new(self.clone(), io, operation, cancel);
        futures::future::poll_fn(|context| {
            pending.poll(context, |io, operation| take(io, operation))
        })
        .await
    }
}

pub(in crate::host) struct PendingHostOperation<I>
where
    I: ?Sized,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
    operation: HostOperationId,
    cancel: fn(&I, HostOperationId) -> io::Result<()>,
    completed: bool,
}

impl<I> PendingHostOperation<I>
where
    I: ?Sized,
{
    pub(in crate::host) fn new(
        runtime: HostSocketRuntime,
        io: Arc<I>,
        operation: HostOperationId,
        cancel: fn(&I, HostOperationId) -> io::Result<()>,
    ) -> Self {
        Self {
            runtime,
            io,
            operation,
            cancel,
            completed: false,
        }
    }

    fn poll<T>(
        &mut self,
        context: &Context<'_>,
        take: impl FnOnce(&I, HostOperationId) -> Poll<T>,
    ) -> Poll<T> {
        let epoch = self.runtime.inner.completion_epoch.load(Ordering::SeqCst);
        match take(self.io.as_ref(), self.operation) {
            Poll::Pending => {
                self.runtime
                    .register_pending(self.operation, epoch, context);
                Poll::Pending
            }
            Poll::Ready(result) => {
                self.complete();
                Poll::Ready(result)
            }
        }
    }

    fn complete(&mut self) {
        self.runtime.inner.wakers.remove(self.operation);
        self.completed = true;
    }

    fn cancel(mut self) -> io::Result<()> {
        self.runtime.inner.wakers.remove(self.operation);
        self.completed = true;
        (self.cancel)(self.io.as_ref(), self.operation)
    }
}

impl<I> Drop for PendingHostOperation<I>
where
    I: ?Sized,
{
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.runtime.inner.wakers.remove(self.operation);
        let _ = (self.cancel)(self.io.as_ref(), self.operation);
    }
}

struct ReadBuffer {
    data: Vec<u8>,
    offset: usize,
}

pub struct HostTcpStream {
    runtime: HostSocketRuntime,
    io: Arc<dyn HostTcpIo>,
    handle: HostSocketHandle,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    transport_label: Option<String>,
    read_operation: Option<PendingHostOperation<dyn HostTcpIo>>,
    read_buffer: Option<ReadBuffer>,
    read_eof: bool,
    write_operation: Option<PendingHostOperation<dyn HostTcpIo>>,
    closed: bool,
}

impl HostTcpStream {
    fn close(&mut self) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }

        let mut first_error = None;
        for pending in [self.read_operation.take(), self.write_operation.take()]
            .into_iter()
            .flatten()
        {
            if let Err(error) = pending.cancel()
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }

        match self.io.close(self.handle) {
            Ok(()) => self.closed = true,
            Err(error) if first_error.is_none() => first_error = Some(error),
            Err(_) => {}
        }

        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn copy_buffered_read(&mut self, buffer: &mut ReadBuf<'_>) -> bool {
        let Some(pending) = &mut self.read_buffer else {
            return false;
        };
        let remaining = &pending.data[pending.offset..];
        let copy_len = remaining.len().min(buffer.remaining());
        buffer.put_slice(&remaining[..copy_len]);
        pending.offset += copy_len;
        if pending.offset == pending.data.len() {
            self.read_buffer = None;
        }
        true
    }

    fn poll_write_completion(&mut self, context: &Context<'_>) -> Poll<io::Result<()>> {
        let Some(pending) = &mut self.write_operation else {
            return Poll::Ready(Ok(()));
        };
        match pending.poll(context, |io, operation| io.take_write(operation)) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.write_operation = None;
                Poll::Ready(result)
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
        if buffer.remaining() == 0 || self.closed || self.read_eof {
            return Poll::Ready(Ok(()));
        }
        if self.copy_buffered_read(buffer) {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.read_operation.is_none() {
                let operation = self.runtime.next_operation();
                if let Err(error) = self
                    .io
                    .submit_read(self.handle, operation, buffer.remaining())
                {
                    return Poll::Ready(Err(error));
                }
                self.read_operation = Some(PendingHostOperation::new(
                    self.runtime.clone(),
                    self.io.clone(),
                    operation,
                    |io, operation| io.cancel_operation(operation),
                ));
            }

            let completion = self
                .read_operation
                .as_mut()
                .expect("read operation was just installed")
                .poll(context, |io, operation| io.take_read(operation));
            match completion {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => {
                    self.read_operation = None;
                    match result {
                        Ok(data) if data.is_empty() => {
                            self.read_eof = true;
                            return Poll::Ready(Ok(()));
                        }
                        Ok(data) => {
                            self.read_buffer = Some(ReadBuffer { data, offset: 0 });
                            if self.copy_buffered_read(buffer) {
                                return Poll::Ready(Ok(()));
                            }
                        }
                        Err(error) => return Poll::Ready(Err(error)),
                    }
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

        match self.poll_write_completion(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {}
        }

        let operation = self.runtime.next_operation();
        if let Err(error) = self.io.submit_write(self.handle, operation, buffer) {
            return Poll::Ready(Err(error));
        }
        self.write_operation = Some(PendingHostOperation::new(
            self.runtime.clone(),
            self.io.clone(),
            operation,
            |io, operation| io.cancel_operation(operation),
        ));
        Poll::Ready(Ok(buffer.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write_completion(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let flush_error = match self.poll_write_completion(context) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Ok(())) => None,
            Poll::Ready(Err(error)) => Some(error),
        };
        let close_result = self.close();
        match (flush_error, close_result) {
            (Some(error), _) => Poll::Ready(Err(error)),
            (None, result) => Poll::Ready(result),
        }
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
    use std::{collections::HashSet, sync::atomic::AtomicBool};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    impl WakerRegistry {
        pub(crate) fn len(&self) -> usize {
            self.wakers.lock().unwrap().len()
        }
    }

    enum TestOperation {
        Read(Option<io::Result<Vec<u8>>>),
        Write {
            source: Vec<u8>,
            result: Option<io::Result<()>>,
        },
    }

    #[derive(Default)]
    struct TestHostIo {
        operations: Mutex<HashMap<HostOperationId, TestOperation>>,
        cancelled: Mutex<Vec<HostOperationId>>,
        closed: Mutex<HashSet<HostSocketHandle>>,
        notify_during_take: AtomicBool,
        runtime: Mutex<Option<HostSocketRuntime>>,
    }

    impl TestHostIo {
        fn operation(&self, read: bool) -> HostOperationId {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(id, operation)| match (read, operation) {
                    (true, TestOperation::Read(_)) | (false, TestOperation::Write { .. }) => {
                        Some(*id)
                    }
                    _ => None,
                })
                .expect("operation was not submitted")
        }

        fn write_source(&self, operation: HostOperationId) -> Vec<u8> {
            let operations = self.operations.lock().unwrap();
            let TestOperation::Write { source, .. } = operations.get(&operation).unwrap() else {
                panic!("operation is not a write");
            };
            source.clone()
        }

        fn complete_read(&self, operation: HostOperationId, data: Vec<u8>) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Read(result) = operations.get_mut(&operation).unwrap() else {
                panic!("operation is not a read");
            };
            *result = Some(Ok(data));
        }

        fn complete_write(&self, operation: HostOperationId) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Write { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not a write");
            };
            *result = Some(Ok(()));
        }

        fn fail_write(&self, operation: HostOperationId) {
            let mut operations = self.operations.lock().unwrap();
            let TestOperation::Write { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not a write");
            };
            *result = Some(Err(io::Error::other("write failed")));
        }
    }

    impl HostSocketIo for TestHostIo {
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

        fn take_read(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
            if self.notify_during_take.swap(false, Ordering::SeqCst) {
                self.runtime
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .notify_completions();
                return Poll::Pending;
            }
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Read(result)) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "read operation is missing",
                )));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
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

        fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestOperation::Write { result, .. }) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "write operation is missing",
                )));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }
    }

    fn test_stream(io: Arc<TestHostIo>) -> (HostSocketRuntime, HostTcpStream) {
        let runtime = HostSocketRuntime::new();
        *io.runtime.lock().unwrap() = Some(runtime.clone());
        let stream = runtime.tcp_stream(
            io,
            HostSocketHandle(7),
            "192.0.2.1:10000".parse().unwrap(),
            "192.0.2.2:11013".parse().unwrap(),
            Some("host-test".to_owned()),
        );
        (runtime, stream)
    }

    #[tokio::test]
    async fn pending_completions_wake_reads_and_apply_write_backpressure() {
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
        let read_operation = io.operation(true);
        io.complete_read(read_operation, b"abc".to_vec());
        runtime.notify_completions();
        assert_eq!(read_task.await.unwrap(), *b"abc");

        let write_task = tokio::spawn(async move {
            writer.write_all(b"one").await.unwrap();
            writer.write_all(b"two").await.unwrap();
            writer.shutdown().await.unwrap();
        });
        tokio::task::yield_now().await;
        let first_write = io.operation(false);
        assert_eq!(io.write_source(first_write), b"one");
        io.complete_write(first_write);
        runtime.notify_completions();
        tokio::task::yield_now().await;
        let second_write = io.operation(false);
        assert_ne!(second_write, first_write);
        assert_eq!(io.write_source(second_write), b"two");
        io.complete_write(second_write);
        runtime.notify_completions();
        write_task.await.unwrap();

        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }

    #[tokio::test]
    async fn cancelled_read_keeps_owned_completion_remainder() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, mut stream) = test_stream(io.clone());
        let mut large = [0_u8; 4];
        let mut first_read = Box::pin(stream.read(&mut large));
        assert!(futures::poll!(&mut first_read).is_pending());
        drop(first_read);

        let operation = io.operation(true);
        io.complete_read(operation, b"abcd".to_vec());
        runtime.notify_completions();
        let mut first = [0_u8; 1];
        stream.read_exact(&mut first).await.unwrap();
        assert_eq!(&first, b"a");
        let mut remainder = [0_u8; 3];
        stream.read_exact(&mut remainder).await.unwrap();
        assert_eq!(&remainder, b"bcd");
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
        let operation = io.operation(true);
        io.complete_read(operation, Vec::new());
        runtime.notify_completions();

        assert_eq!(read_task.await.unwrap(), 0);
    }

    #[tokio::test]
    async fn shutdown_closes_handle_after_buffered_write_error() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, mut stream) = test_stream(io.clone());
        stream.write_all(b"data").await.unwrap();
        let operation = io.operation(false);
        io.fail_write(operation);
        runtime.notify_completions();

        let error = stream.shutdown().await.unwrap_err();
        assert_eq!(error.to_string(), "write failed");
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }

    #[tokio::test]
    async fn completion_between_poll_and_registration_is_not_lost() {
        let io = Arc::new(TestHostIo::default());
        let (_runtime, mut stream) = test_stream(io.clone());
        let operation = {
            let mut byte = [0_u8; 1];
            let mut read = Box::pin(stream.read(&mut byte));
            assert!(futures::poll!(&mut read).is_pending());
            io.operation(true)
        };
        io.complete_read(operation, b"x".to_vec());
        io.notify_during_take.store(true, Ordering::SeqCst);

        let mut byte = [0_u8; 1];
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            stream.read_exact(&mut byte),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&byte, b"x");
    }

    #[tokio::test]
    async fn dropping_pending_stream_removes_waker_cancels_and_closes() {
        let io = Arc::new(TestHostIo::default());
        let (runtime, mut stream) = test_stream(io.clone());
        let read_task = tokio::spawn(async move {
            let mut byte = [0_u8; 1];
            let _ = stream.read(&mut byte).await;
        });
        tokio::task::yield_now().await;
        let operation = io.operation(true);
        assert_eq!(runtime.inner.wakers.len(), 1);
        read_task.abort();
        let _ = read_task.await;

        assert_eq!(runtime.inner.wakers.len(), 0);
        assert_eq!(*io.cancelled.lock().unwrap(), vec![operation]);
        assert!(io.closed.lock().unwrap().contains(&HostSocketHandle(7)));
    }

    #[test]
    fn shared_host_io_receives_unique_operation_ids() {
        let runtime_a = HostSocketRuntime::new();
        let runtime_b = HostSocketRuntime::new();
        assert_ne!(runtime_a.next_operation(), runtime_b.next_operation());
    }
}

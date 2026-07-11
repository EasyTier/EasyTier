use std::{io, sync::Arc, task::Poll};

use async_trait::async_trait;
use futures::future::poll_fn;

use crate::instance::PacketSink;

use super::{HostOperationId, HostSocketRuntime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostPacketSinkHandle(pub u64);

/// Mechanical packet egress below core's packet scheduling seam.
///
/// A successful `try_write_packet` owns a complete packet copy before it
/// returns. `WouldBlock` has no side effects. Readiness operations only report
/// that another admission attempt may succeed; they never accept a packet.
pub trait HostPacketIo: Send + Sync + 'static {
    fn try_write_packet(&self, handle: HostPacketSinkHandle, packet: &[u8]) -> io::Result<()>;

    fn submit_write_ready(
        &self,
        handle: HostPacketSinkHandle,
        operation: HostOperationId,
    ) -> io::Result<()>;

    fn take_write_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;
}

struct PendingPacketReady<I>
where
    I: HostPacketIo,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
    operation: HostOperationId,
    completed: bool,
}

impl<I> PendingPacketReady<I>
where
    I: HostPacketIo,
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

impl<I> Drop for PendingPacketReady<I>
where
    I: HostPacketIo,
{
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.runtime.inner.wakers.remove(self.operation);
        let _ = self.io.cancel_operation(self.operation);
    }
}

pub struct HostPacketSink<I>
where
    I: HostPacketIo,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
    handle: HostPacketSinkHandle,
}

impl<I> Clone for HostPacketSink<I>
where
    I: HostPacketIo,
{
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            io: self.io.clone(),
            handle: self.handle,
        }
    }
}

impl<I> HostPacketSink<I>
where
    I: HostPacketIo,
{
    pub fn new(runtime: HostSocketRuntime, io: Arc<I>, handle: HostPacketSinkHandle) -> Self {
        Self {
            runtime,
            io,
            handle,
        }
    }

    async fn wait_writable(&self) -> io::Result<()> {
        let operation = self.runtime.next_operation();
        self.io.submit_write_ready(self.handle, operation)?;
        let mut pending = PendingPacketReady::new(self.runtime.clone(), self.io.clone(), operation);
        poll_fn(|context| {
            let epoch = self
                .runtime
                .inner
                .completion_epoch
                .load(std::sync::atomic::Ordering::SeqCst);
            match self.io.take_write_ready(operation) {
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
impl<I> PacketSink for HostPacketSink<I>
where
    I: HostPacketIo,
{
    async fn write_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        loop {
            match self.io.try_write_packet(self.handle, &packet) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_writable().await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

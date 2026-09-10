use std::{fmt, io, sync::Arc, task::Poll};

use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::packet::{ZCPacket, ZCPacketType};

use super::socket::{HostOperationId, HostSocketRuntime};

/// An owned raw IP packet crossing the Host packet seam.
///
/// The backing allocation and any core-private headroom stay opaque. Native
/// adapters can move the packet without copying its payload, while ABI adapters
/// can borrow [`Self::payload`] at the point where a copy is unavoidable.
pub struct HostPacket {
    inner: ZCPacket,
}

pub(crate) type HostPacketSender = mpsc::Sender<HostPacket>;

/// The single bounded receive side for packets leaving a core instance.
///
/// Hosts own this receiver for the instance lifetime. Keeping the channel
/// opaque prevents platform adapters from depending on core packet headers or
/// replacing the bounded backpressure contract.
pub struct HostPacketReceiver {
    receiver: mpsc::Receiver<HostPacket>,
}

impl HostPacketReceiver {
    /// Wraps a Host-owned bounded packet channel.
    ///
    /// This is intended for native adapters that already receive owned
    /// [`HostPacket`] values from an in-process packet sink.
    pub fn new(receiver: mpsc::Receiver<HostPacket>) -> Self {
        Self { receiver }
    }

    pub async fn recv(&mut self) -> Option<HostPacket> {
        self.receiver.recv().await
    }
}

pub(crate) fn host_packet_channel() -> (HostPacketSender, HostPacketReceiver) {
    let (sender, receiver) = mpsc::channel(128);
    (sender, HostPacketReceiver::new(receiver))
}

impl HostPacket {
    /// Copies raw IP bytes into core-owned packet storage.
    ///
    /// Native packet devices should use [`Self::from_tun_packet`] instead.
    pub fn copy_from_payload(payload: &[u8]) -> Self {
        Self {
            inner: ZCPacket::new_with_payload(payload),
        }
    }

    /// Moves a packet read from a native TUN adapter into the Host seam.
    pub fn from_tun_packet(packet: ZCPacket) -> Self {
        debug_assert_eq!(packet.packet_type(), ZCPacketType::NIC);
        Self { inner: packet }
    }

    pub fn payload(&self) -> &[u8] {
        self.inner.payload()
    }

    pub fn len(&self) -> usize {
        self.inner.payload_len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.payload().is_empty()
    }

    /// Moves a packet into a native TUN adapter without copying its payload.
    ///
    /// Core-private headers are cleared before the backing allocation crosses
    /// the seam. The returned packet retains its original payload offset so the
    /// native writer can reuse the existing headroom for packet-info framing.
    pub fn into_tun_packet(mut self) -> ZCPacket {
        let payload_offset = self.inner.payload_offset();
        self.inner.mut_inner()[..payload_offset].fill(0);
        self.inner
    }

    pub(crate) fn from_core_packet(packet: ZCPacket) -> Self {
        Self { inner: packet }
    }

    pub(crate) fn into_core_packet(self) -> ZCPacket {
        self.inner
    }
}

impl fmt::Debug for HostPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostPacket")
            .field("len", &self.len())
            .finish()
    }
}

/// Receives owned IP packets leaving the EasyTier peer graph.
///
/// The host decides whether packets go to a TUN device, a Go callback, or a
/// different packet backend. Core's internal packet headers remain hidden, and
/// core never performs platform I/O directly.
#[async_trait]
pub trait PacketSink: Send + Sync + 'static {
    async fn write_packet(&self, packet: HostPacket) -> anyhow::Result<()>;
}

#[async_trait]
impl PacketSink for mpsc::Sender<Vec<u8>> {
    async fn write_packet(&self, packet: HostPacket) -> anyhow::Result<()> {
        self.send(packet.payload().to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("packet sink channel is closed"))
    }
}

/// Ownership-preserving in-process adapter for native packet runtimes.
pub struct HostPacketChannelSink {
    sender: mpsc::Sender<HostPacket>,
}

impl HostPacketChannelSink {
    pub fn new(sender: mpsc::Sender<HostPacket>) -> Self {
        Self { sender }
    }
}

#[async_trait]
impl PacketSink for HostPacketChannelSink {
    async fn write_packet(&self, packet: HostPacket) -> anyhow::Result<()> {
        self.sender
            .send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("packet sink channel is closed"))
    }
}

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
        self.runtime
            .run_operation(
                self.io.clone(),
                |io, operation| io.submit_write_ready(self.handle, operation),
                |io, operation| io.take_write_ready(operation),
                |io, operation| io.cancel_operation(operation),
            )
            .await
    }
}

#[async_trait]
impl<I> PacketSink for HostPacketSink<I>
where
    I: HostPacketIo,
{
    async fn write_packet(&self, packet: HostPacket) -> anyhow::Result<()> {
        loop {
            match self.io.try_write_packet(self.handle, packet.payload()) {
                Ok(()) => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    self.wait_writable().await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use super::*;

    #[derive(Default)]
    struct TestPacketState {
        writable: bool,
        packets: Vec<(HostPacketSinkHandle, Vec<u8>)>,
        waiters: HashMap<HostOperationId, bool>,
        cancelled: Vec<HostOperationId>,
    }

    #[derive(Default)]
    struct TestPacketIo {
        state: Mutex<TestPacketState>,
    }

    impl TestPacketIo {
        fn set_writable(&self) {
            let mut state = self.state.lock().unwrap();
            state.writable = true;
            for ready in state.waiters.values_mut() {
                *ready = true;
            }
        }

        fn waiter(&self) -> HostOperationId {
            *self.state.lock().unwrap().waiters.keys().next().unwrap()
        }
    }

    impl HostPacketIo for TestPacketIo {
        fn try_write_packet(&self, handle: HostPacketSinkHandle, packet: &[u8]) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            if !state.writable {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            state.writable = false;
            state.packets.push((handle, packet.to_vec()));
            Ok(())
        }

        fn submit_write_ready(
            &self,
            _handle: HostPacketSinkHandle,
            operation: HostOperationId,
        ) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            let ready = state.writable;
            state.waiters.insert(operation, ready);
            Ok(())
        }

        fn take_write_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
            let mut state = self.state.lock().unwrap();
            match state.waiters.get(&operation) {
                Some(true) => {
                    state.waiters.remove(&operation);
                    Poll::Ready(Ok(()))
                }
                Some(false) => Poll::Pending,
                None => Poll::Ready(Err(io::ErrorKind::NotFound.into())),
            }
        }

        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.waiters.remove(&operation);
            state.cancelled.push(operation);
            Ok(())
        }
    }

    fn test_sink(
        writable: bool,
    ) -> (
        HostSocketRuntime,
        Arc<TestPacketIo>,
        HostPacketSink<TestPacketIo>,
    ) {
        let runtime = HostSocketRuntime::new();
        let io = Arc::new(TestPacketIo::default());
        io.state.lock().unwrap().writable = writable;
        let sink = HostPacketSink::new(runtime.clone(), io.clone(), HostPacketSinkHandle(41));
        (runtime, io, sink)
    }

    #[tokio::test]
    async fn admits_complete_packet_without_readiness_wait() {
        let (_runtime, io, sink) = test_sink(true);
        sink.write_packet(HostPacket::copy_from_payload(&[1, 2, 3, 4]))
            .await
            .unwrap();

        let state = io.state.lock().unwrap();
        assert_eq!(
            state.packets,
            vec![(HostPacketSinkHandle(41), vec![1, 2, 3, 4])]
        );
        assert!(state.waiters.is_empty());
    }

    #[tokio::test]
    async fn waits_for_capacity_then_admits_packet_once() {
        let (runtime, io, sink) = test_sink(false);
        let task = tokio::spawn(async move {
            sink.write_packet(HostPacket::copy_from_payload(&[5, 6, 7]))
                .await
        });
        tokio::task::yield_now().await;
        assert!(io.state.lock().unwrap().packets.is_empty());
        assert_eq!(runtime.inner.wakers.len(), 1);

        io.set_writable();
        runtime.notify_completions();
        task.await.unwrap().unwrap();

        let state = io.state.lock().unwrap();
        assert_eq!(
            state.packets,
            vec![(HostPacketSinkHandle(41), vec![5, 6, 7])]
        );
        assert!(state.waiters.is_empty());
        assert!(state.cancelled.is_empty());
        assert_eq!(runtime.inner.wakers.len(), 0);
    }

    #[tokio::test]
    async fn dropping_pending_waiter_removes_waker_and_host_state() {
        let (runtime, io, sink) = test_sink(false);
        let operation = {
            let mut write = Box::pin(sink.write_packet(HostPacket::copy_from_payload(&[7, 8])));
            assert!(futures::poll!(&mut write).is_pending());
            assert_eq!(runtime.inner.wakers.len(), 1);
            let operation = io.waiter();
            drop(write);
            operation
        };

        let state = io.state.lock().unwrap();
        assert!(state.packets.is_empty());
        assert!(state.waiters.is_empty());
        assert_eq!(state.cancelled, vec![operation]);
        assert_eq!(runtime.inner.wakers.len(), 0);
    }

    #[tokio::test]
    async fn dropping_ready_waiter_does_not_admit_packet() {
        let (runtime, io, sink) = test_sink(false);
        let operation = {
            let mut write = Box::pin(sink.write_packet(HostPacket::copy_from_payload(&[8, 9])));
            assert!(futures::poll!(&mut write).is_pending());
            let operation = io.waiter();
            io.set_writable();
            runtime.notify_completions();
            drop(write);
            operation
        };

        {
            let state = io.state.lock().unwrap();
            assert!(state.packets.is_empty());
            assert!(state.waiters.is_empty());
            assert_eq!(state.cancelled, vec![operation]);
        }
        sink.write_packet(HostPacket::copy_from_payload(&[8, 9]))
            .await
            .unwrap();
        assert_eq!(
            io.state.lock().unwrap().packets,
            vec![(HostPacketSinkHandle(41), vec![8, 9])]
        );
    }

    #[test]
    fn native_packet_round_trip_preserves_allocation_and_hides_headers() {
        let mut core_packet = ZCPacket::new_with_payload(b"owned payload");
        let payload_offset = core_packet.payload_offset();
        core_packet.mut_inner()[..payload_offset].fill(0xa5);
        let payload_pointer = core_packet.payload().as_ptr();

        let host_packet = HostPacket::from_core_packet(core_packet);
        assert_eq!(host_packet.payload().as_ptr(), payload_pointer);
        assert_eq!(host_packet.payload(), b"owned payload");

        let tun_packet = host_packet.into_tun_packet();
        assert_eq!(tun_packet.payload().as_ptr(), payload_pointer);
        assert_eq!(tun_packet.payload(), b"owned payload");
        assert!(
            tun_packet.inner()[..payload_offset]
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[test]
    fn tun_packet_moves_into_core_without_copying_payload() {
        let tun_packet = ZCPacket::new_with_payload(b"from tun");
        let payload_pointer = tun_packet.payload().as_ptr();

        let host_packet = HostPacket::from_tun_packet(tun_packet);
        assert_eq!(host_packet.payload().as_ptr(), payload_pointer);
        let core_packet = host_packet.into_core_packet();

        assert_eq!(core_packet.payload().as_ptr(), payload_pointer);
        assert_eq!(core_packet.payload(), b"from tun");
    }
}

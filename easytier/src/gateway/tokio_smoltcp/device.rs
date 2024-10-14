use futures::{Sink, Stream};
pub use smoltcp::phy::DeviceCapabilities;
use smoltcp::{
    phy::{Device, RxToken, TxToken},
    time::Instant,
};
use std::{collections::VecDeque, io};

/// Default value of `max_burst_size`.
pub const DEFAULT_MAX_BURST_SIZE: usize = 100;

/// A packet used in `AsyncDevice`.
pub type Packet = Vec<u8>;

/// A device that send and receive packets asynchronously.
pub trait AsyncDevice:
    Stream<Item = io::Result<Packet>> + Sink<Packet, Error = io::Error> + Send + Unpin
{
    /// Returns the device capabilities.
    fn capabilities(&self) -> &DeviceCapabilities;
}

impl<T> AsyncDevice for Box<T>
where
    T: AsyncDevice,
{
    fn capabilities(&self) -> &DeviceCapabilities {
        (**self).capabilities()
    }
}

/// A device that send and receive packets synchronously.
pub struct BufferDevice {
    caps: DeviceCapabilities,
    max_burst_size: usize,
    recv_queue: VecDeque<Packet>,
    send_queue: VecDeque<Packet>,
}

/// RxToken for `BufferDevice`.
pub struct BufferRxToken(Packet);

impl RxToken for BufferRxToken {
    fn consume<R, F>(mut self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let p = &mut self.0;
        let result = f(p);
        result
    }
}

/// TxToken for `BufferDevice`.
pub struct BufferTxToken<'a>(&'a mut BufferDevice);

impl<'d> TxToken for BufferTxToken<'d> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);

        self.0.send_queue.push_back(buffer);

        result
    }
}

impl Device for BufferDevice {
    type RxToken<'a>
        = BufferRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = BufferTxToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.recv_queue.pop_front() {
            Some(p) => Some((BufferRxToken(p), BufferTxToken(self))),
            None => None,
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.send_queue.len() < self.max_burst_size {
            Some(BufferTxToken(self))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.caps.clone()
    }
}

impl BufferDevice {
    pub(crate) fn new(caps: DeviceCapabilities) -> BufferDevice {
        let max_burst_size = caps.max_burst_size.unwrap_or(DEFAULT_MAX_BURST_SIZE);
        BufferDevice {
            caps,
            max_burst_size,
            recv_queue: VecDeque::with_capacity(max_burst_size),
            send_queue: VecDeque::with_capacity(max_burst_size),
        }
    }
    pub(crate) fn take_send_queue(&mut self) -> VecDeque<Packet> {
        std::mem::replace(
            &mut self.send_queue,
            VecDeque::with_capacity(self.max_burst_size),
        )
    }
    pub(crate) fn push_recv_queue(&mut self, p: impl Iterator<Item = Packet>) {
        self.recv_queue.extend(p.take(self.avaliable_recv_queue()));
    }
    pub(crate) fn avaliable_recv_queue(&self) -> usize {
        self.max_burst_size - self.recv_queue.len()
    }
    pub(crate) fn need_wait(&self) -> bool {
        self.recv_queue.is_empty()
    }
}

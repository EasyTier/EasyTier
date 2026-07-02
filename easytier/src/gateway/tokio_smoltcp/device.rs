use bytes::BytesMut;
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
pub type Packet = BytesMut;

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
    tx_headroom: usize,
    recv_queue: VecDeque<Packet>,
    send_queue: VecDeque<Packet>,
}

/// RxToken for `BufferDevice`.
pub struct BufferRxToken(Packet);

impl RxToken for BufferRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0[..])
    }
}

/// TxToken for `BufferDevice`.
pub struct BufferTxToken<'a>(&'a mut BufferDevice);

impl<'d> TxToken for BufferTxToken<'d> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let tx_headroom = self.0.tx_headroom;
        let mut buffer = BytesMut::with_capacity(tx_headroom + len);
        buffer.resize(tx_headroom + len, 0);
        let result = f(&mut buffer[tx_headroom..]);

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
        self.recv_queue
            .pop_front()
            .map(|p| (BufferRxToken(p), BufferTxToken(self)))
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
    pub(crate) fn new(caps: DeviceCapabilities, tx_headroom: usize) -> BufferDevice {
        let max_burst_size = caps.max_burst_size.unwrap_or(DEFAULT_MAX_BURST_SIZE);
        BufferDevice {
            caps,
            max_burst_size,
            tx_headroom,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_device_reserves_tx_headroom() {
        let mut caps = DeviceCapabilities::default();
        caps.max_burst_size = Some(1);
        let mut device = BufferDevice::new(caps, 16);

        let token = device.transmit(Instant::now()).unwrap();
        token.consume(4, |buf| {
            assert_eq!(buf.len(), 4);
            buf.copy_from_slice(&[1, 2, 3, 4]);
        });

        let mut queue = device.take_send_queue();
        let packet = queue.pop_front().unwrap();
        assert_eq!(packet.len(), 20);
        assert_eq!(&packet[..16], &[0; 16]);
        assert_eq!(&packet[16..], &[1, 2, 3, 4]);
    }
}

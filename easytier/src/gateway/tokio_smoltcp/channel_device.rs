use futures::{Sink, Stream};
use smoltcp::phy::DeviceCapabilities;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::sync::{PollSendError, PollSender};

use super::device::AsyncDevice;

/// A device that send and receive packets using a channel.
pub struct ChannelDevice {
    recv: Receiver<io::Result<Vec<u8>>>,
    send: PollSender<Vec<u8>>,
    caps: DeviceCapabilities,
}

pub type ChannelDeviceNewRet = (
    ChannelDevice,
    Sender<io::Result<Vec<u8>>>,
    Receiver<Vec<u8>>,
);

impl ChannelDevice {
    /// Make a new `ChannelDevice` with the given `recv` and `send` channels.
    ///
    /// The `caps` is used to determine the device capabilities. `DeviceCapabilities::max_transmission_unit` must be set.
    pub fn new(caps: DeviceCapabilities) -> ChannelDeviceNewRet {
        let (tx1, rx1) = channel(1000);
        let (tx2, rx2) = channel(1000);
        (
            ChannelDevice {
                send: PollSender::new(tx1),
                recv: rx2,
                caps,
            },
            tx2,
            rx1,
        )
    }
}

impl Stream for ChannelDevice {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.recv.poll_recv(cx)
    }
}

fn map_err(e: PollSendError<Vec<u8>>) -> io::Error {
    io::Error::other(e)
}

impl Sink<Vec<u8>> for ChannelDevice {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.send.send_item(item).map_err(map_err)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.send.poll_reserve(cx).map_err(map_err)
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for ChannelDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}

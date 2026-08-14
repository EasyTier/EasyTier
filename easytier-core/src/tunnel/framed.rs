use std::{
    any::Any,
    collections::VecDeque,
    io::IoSlice,
    pin::Pin,
    task::{Poll, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use crate::{
    packet::{
        PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, TCPTunnelHeader, ZCPacket, ZCPacketType,
    },
    tunnel::{SinkError, SinkItem, StreamItem, TunnelError},
};

pub const TCP_MTU_BYTES: usize = 2000;

pub fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() < min_size {
        buf.reserve(max_size);
    }
}

pin_project! {
    pub struct FramedReader<R> {
        #[pin]
        reader: R,
        buf: BytesMut,
        max_packet_size: usize,
        _associate_data: Option<Box<dyn Any + Send + 'static>>,
        error: Option<TunnelError>,
    }
}

impl<R> FramedReader<R> {
    pub fn new(reader: R, max_packet_size: usize) -> Self {
        Self::new_with_associate_data(reader, max_packet_size, None)
    }

    pub fn new_with_associate_data(
        reader: R,
        max_packet_size: usize,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        Self {
            reader,
            buf: BytesMut::with_capacity(max_packet_size),
            max_packet_size,
            _associate_data: associate_data,
            error: None,
        }
    }

    pub fn extract_one_packet(
        buf: &mut BytesMut,
        max_packet_size: usize,
    ) -> Option<Result<ZCPacket, TunnelError>> {
        if buf.len() < TCP_TUNNEL_HEADER_SIZE {
            return None;
        }

        let header = TCPTunnelHeader::ref_from_prefix(&buf[..]).unwrap();
        let body_len = header.len.get() as usize;
        if body_len > max_packet_size {
            return Some(Err(TunnelError::InvalidPacket("body too long".to_owned())));
        }

        if body_len < PEER_MANAGER_HEADER_SIZE {
            return Some(Err(TunnelError::InvalidPacket("body too short".to_owned())));
        }

        if buf.len() < TCP_TUNNEL_HEADER_SIZE + body_len {
            return None;
        }

        let packet_buf = buf.split_to(TCP_TUNNEL_HEADER_SIZE + body_len);
        Some(Ok(ZCPacket::new_from_buf(packet_buf, ZCPacketType::TCP)))
    }
}

impl<R> Stream for FramedReader<R>
where
    R: AsyncRead + Send + 'static + Unpin,
{
    type Item = StreamItem;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        loop {
            if let Some(error) = this.error.as_ref() {
                tracing::warn!("poll_next on a failed FramedReader, {:?}", error);
                return Poll::Ready(None);
            }

            if let Some(packet) = Self::extract_one_packet(this.buf, *this.max_packet_size) {
                if let Err(TunnelError::InvalidPacket(msg)) = packet.as_ref() {
                    this.error.replace(TunnelError::InvalidPacket(msg.clone()));
                }
                return Poll::Ready(Some(packet));
            }

            reserve_buf(this.buf, *this.max_packet_size, *this.max_packet_size * 2);

            let cap = this.buf.capacity() - this.buf.len();
            let buf = this.buf.chunk_mut().as_mut_ptr();
            let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
            let mut buf = ReadBuf::new(buf);

            let ret = ready!(this.reader.as_mut().poll_read(cx, &mut buf));
            let len = buf.filled().len();
            unsafe { this.buf.advance_mut(len) };

            match ret {
                Ok(_) if len == 0 => return Poll::Ready(None),
                Ok(_) => {}
                Err(error) => return Poll::Ready(Some(Err(TunnelError::IOError(error)))),
            }
        }
    }
}

pub trait ZCPacketToBytes {
    fn zcpacket_into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, TunnelError>;
}

pub struct TcpZCPacketToBytes;

impl ZCPacketToBytes for TcpZCPacketToBytes {
    fn zcpacket_into_bytes(&self, item: ZCPacket) -> Result<Bytes, TunnelError> {
        let mut item = item.convert_type(ZCPacketType::TCP);

        let tcp_len = PEER_MANAGER_HEADER_SIZE + item.payload_len();
        let Some(header) = item.mut_tcp_tunnel_header() else {
            return Err(TunnelError::InvalidPacket("packet too short".to_owned()));
        };
        header.len.set(tcp_len.try_into().unwrap());

        Ok(item.into_bytes())
    }
}

struct SendBufs {
    bufs: VecDeque<Bytes>,
}

impl SendBufs {
    fn new() -> Self {
        Self {
            bufs: VecDeque::new(),
        }
    }

    fn len(&self) -> usize {
        self.bufs.len()
    }

    fn push(&mut self, buf: Bytes) {
        debug_assert!(buf.has_remaining());
        self.bufs.push_back(buf);
    }
}

impl Buf for SendBufs {
    fn remaining(&self) -> usize {
        self.bufs.iter().map(Buf::remaining).sum()
    }

    fn chunk(&self) -> &[u8] {
        self.bufs.front().map(Buf::chunk).unwrap_or_default()
    }

    fn advance(&mut self, mut cnt: usize) {
        while cnt > 0 {
            let Some(front) = self.bufs.front_mut() else {
                return;
            };
            let rem = front.remaining();
            if rem > cnt {
                front.advance(cnt);
                return;
            }
            front.advance(rem);
            cnt -= rem;
            self.bufs.pop_front();
        }
    }

    fn chunks_vectored<'a>(&'a self, dst: &mut [IoSlice<'a>]) -> usize {
        if dst.is_empty() {
            return 0;
        }

        let mut count = 0;
        for buf in &self.bufs {
            count += buf.chunks_vectored(&mut dst[count..]);
            if count == dst.len() {
                break;
            }
        }
        count
    }

    fn copy_to_bytes(&mut self, len: usize) -> Bytes {
        match self.bufs.front_mut() {
            Some(front) if front.remaining() == len => {
                let bytes = front.copy_to_bytes(len);
                self.bufs.pop_front();
                bytes
            }
            Some(front) if front.remaining() > len => front.copy_to_bytes(len),
            _ => {
                assert!(len <= self.remaining(), "len greater than remaining");
                let mut bytes = BytesMut::with_capacity(len);
                bytes.put(self.take(len));
                bytes.freeze()
            }
        }
    }
}

pin_project! {
    pub struct FramedWriter<W, C> {
        #[pin]
        writer: W,
        sending_bufs: SendBufs,
        _associate_data: Option<Box<dyn Any + Send + 'static>>,
        converter: C,
    }
}

impl<W, C> FramedWriter<W, C> {
    fn max_buffer_count(&self) -> usize {
        64
    }
}

impl<W> FramedWriter<W, TcpZCPacketToBytes> {
    pub fn new(writer: W) -> Self {
        Self::new_with_associate_data(writer, None)
    }

    pub fn new_with_associate_data(
        writer: W,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        Self {
            writer,
            sending_bufs: SendBufs::new(),
            _associate_data: associate_data,
            converter: TcpZCPacketToBytes,
        }
    }
}

impl<W, C: ZCPacketToBytes + Send + 'static> FramedWriter<W, C> {
    pub fn new_with_converter(writer: W, converter: C) -> Self {
        Self::new_with_converter_and_associate_data(writer, converter, None)
    }

    pub fn new_with_converter_and_associate_data(
        writer: W,
        converter: C,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        Self {
            writer,
            sending_bufs: SendBufs::new(),
            _associate_data: associate_data,
            converter,
        }
    }
}

impl<W, C> Sink<SinkItem> for FramedWriter<W, C>
where
    W: AsyncWrite + Send + 'static,
    C: ZCPacketToBytes + Send + 'static,
{
    type Error = SinkError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let max_buffer_count = self.max_buffer_count();
        if self.sending_bufs.len() >= max_buffer_count {
            self.as_mut().poll_flush(cx)
        } else {
            tracing::trace!(bufs_cnt = self.sending_bufs.len(), "ready to send");
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let this = self.project();
        this.sending_bufs
            .push(this.converter.zcpacket_into_bytes(item)?);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let mut this = self.project();
        let mut remaining = this.sending_bufs.remaining();
        while remaining != 0 {
            let n = ready!(poll_write_buf(this.writer.as_mut(), cx, this.sending_bufs))?;
            if n == 0 {
                return Poll::Ready(Err(TunnelError::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                ))));
            }
            remaining -= n;
        }

        tracing::trace!(?remaining, "flushed");
        ready!(this.writer.poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(self.project().writer.poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framed_reader_rejects_short_peer_manager_body() {
        let mut buf = BytesMut::new();
        buf.put_u32_le((PEER_MANAGER_HEADER_SIZE - 1) as u32);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE - 1, 0);

        let ret = FramedReader::<tokio::io::Empty>::extract_one_packet(&mut buf, 2000);

        assert!(matches!(
            ret,
            Some(Err(TunnelError::InvalidPacket(msg))) if msg == "body too short"
        ));
    }

    #[test]
    fn send_bufs_exposes_all_queued_buffers_for_vectored_write() {
        let mut bufs = SendBufs::new();
        bufs.push(Bytes::from_static(b"abc"));
        bufs.push(Bytes::from_static(b"defg"));

        let mut slices = [IoSlice::new(&[]); 4];
        let count = bufs.chunks_vectored(&mut slices);

        assert_eq!(count, 2);
        assert_eq!(&*slices[0], b"abc");
        assert_eq!(&*slices[1], b"defg");
    }
}

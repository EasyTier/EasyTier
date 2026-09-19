use std::pin::Pin;
use std::task::{Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use futures::Sink;
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio_util::codec::Decoder;
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use crate::{
    packet::{
        PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, TCPTunnelHeader, ZCPacket, ZCPacketType,
    },
    tunnel::{SinkError, SinkItem, TunnelError, buf::BufList},
};

pub const TCP_MTU_BYTES: usize = 2000;

#[derive(Copy, Clone, Debug)]
pub struct TunnelCodec {
    pub max_packet_size: usize,
}

impl Decoder for TunnelCodec {
    type Item = ZCPacket;
    type Error = TunnelError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(header) = TCPTunnelHeader::ref_from_prefix(src) else {
            return Ok(None);
        };

        let len = {
            let len = header.len.get() as usize;
            if len > self.max_packet_size {
                return Err(TunnelError::InvalidPacket("body too long".to_string()));
            }
            if len < PEER_MANAGER_HEADER_SIZE {
                return Err(TunnelError::InvalidPacket("body too short".to_string()));
            }

            TCP_TUNNEL_HEADER_SIZE + len
        };

        if src.len() < len {
            if src.capacity() < len {
                src.reserve((len - src.len()).max(self.max_packet_size << 4));
            }
            return Ok(None);
        }

        let packet_buf = src.split_to(len);
        Ok(Some(ZCPacket::new_from_buf(packet_buf, ZCPacketType::TCP)))
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

pin_project! {
    pub struct FramedWriter<W, C> {
        #[pin]
        writer: W,
        sending_bufs: BufList<Bytes>,
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
        Self {
            writer,
            sending_bufs: BufList::new(),
            converter: TcpZCPacketToBytes,
        }
    }
}

impl<W, C: ZCPacketToBytes + Send + 'static> FramedWriter<W, C> {
    pub fn with_converter(writer: W, converter: C) -> Self {
        Self {
            writer,
            sending_bufs: BufList::new(),
            converter,
        }
    }

    pub fn new_with_converter(writer: W, converter: C) -> Self {
        Self::with_converter(writer, converter)
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
        let mut pinned = self.project();
        while pinned.sending_bufs.has_remaining() {
            let n = ready!(poll_write_buf(
                pinned.writer.as_mut(),
                cx,
                pinned.sending_bufs
            ))?;
            if n == 0 {
                return Poll::Ready(Err(TunnelError::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                ))));
            }
        }

        ready!(pinned.writer.poll_flush(cx))?;
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

pub fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() - buf.len() < min_size {
        buf.reserve(max_size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BufMut;
    use std::io::IoSlice;

    #[test]
    fn framed_reader_rejects_short_peer_manager_body() {
        use tokio_util::codec::Decoder;

        let mut buf = BytesMut::new();
        buf.put_u32_le((PEER_MANAGER_HEADER_SIZE - 1) as u32);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE - 1, 0);

        let ret = TunnelCodec {
            max_packet_size: 2000,
        }
        .decode(&mut buf);

        assert!(matches!(
            ret,
            Err(TunnelError::InvalidPacket(msg)) if msg == "body too short"
        ));
    }

    #[test]
    fn send_bufs_exposes_all_queued_buffers_for_vectored_write() {
        let mut bufs = BufList::new();
        bufs.push(Bytes::from_static(b"abc"));
        bufs.push(Bytes::from_static(b"defg"));

        let mut slices = [IoSlice::new(&[]); 4];
        let count = bufs.chunks_vectored(&mut slices);

        assert_eq!(count, 2);
        assert_eq!(&*slices[0], b"abc");
        assert_eq!(&*slices[1], b"defg");
    }
}

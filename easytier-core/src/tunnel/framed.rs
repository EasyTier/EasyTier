use std::pin::Pin;
use std::task::{Poll, ready};

use bytes::{Buf, Bytes, BytesMut};
use futures::Sink;
use pin_project_lite::pin_project;
use tokio::io::AsyncWrite;
use tokio_util::codec::Decoder;
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use crate::packet::TAIL_RESERVED_SIZE;
use crate::{
    packet::{
        PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, TCPTunnelHeader, ZCPacket, ZCPacketType,
    },
    tunnel::{SinkError, SinkItem, TunnelError, buf::BufList},
};

pub const MAX_PACKET_SIZE: usize = 1 << 16;
pub const DEFAULT_TUNNEL_MTU: usize = 1420;

#[derive(Copy, Clone, Debug)]
pub struct TunnelCodec {
    pub mtu: usize,
    pub gso: bool,
}

impl TunnelCodec {
    pub fn new(mtu: usize) -> Self {
        Self {
            mtu: if mtu > 0 { mtu } else { DEFAULT_TUNNEL_MTU },
            gso: false,
        }
    }
}

impl Decoder for TunnelCodec {
    type Item = ZCPacket;
    type Error = TunnelError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let packet_len = self.mtu.max(DEFAULT_TUNNEL_MTU)
            + TCP_TUNNEL_HEADER_SIZE
            + PEER_MANAGER_HEADER_SIZE
            + TAIL_RESERVED_SIZE;
        let reserved_len = packet_len * 4;

        if src.is_empty() {
            if src.capacity() > reserved_len {
                *src = BytesMut::with_capacity(reserved_len);
            }
            return Ok(None);
        }

        let Some(header) = TCPTunnelHeader::ref_from_prefix(src) else {
            return Ok(None);
        };

        let len = {
            let len = header.len.get() as usize;
            if len > MAX_PACKET_SIZE {
                return Err(TunnelError::InvalidPacket("body too long".to_string()));
            }
            if len < PEER_MANAGER_HEADER_SIZE {
                return Err(TunnelError::InvalidPacket("body too short".to_string()));
            }

            TCP_TUNNEL_HEADER_SIZE + len
        };

        if len > packet_len + 32 {
            self.gso = true;
        }

        if src.len() < len {
            if src.capacity() < len {
                let reserve = if self.gso {
                    (len - src.len()).max(MAX_PACKET_SIZE * 2)
                } else {
                    (len - src.len()).max(reserved_len)
                };
                src.reserve(reserve);
            }
            return Ok(None);
        }

        Ok(Some(ZCPacket::new_from_buf(
            src.split_to(len),
            ZCPacketType::TCP,
        )))
    }
}

pin_project! {
    pub struct FramedWriter<W> {
        #[pin]
        writer: W,
        sending_bufs: BufList<Bytes>,
    }
}

impl<W> FramedWriter<W> {
    fn max_buffer_count(&self) -> usize {
        64
    }

    pub fn new(writer: W) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
        }
    }
}

impl<W> Sink<SinkItem> for FramedWriter<W>
where
    W: AsyncWrite + Send + 'static,
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

        let mut packet = item.convert_type(ZCPacketType::TCP);
        let payload_len = packet.payload_len();
        let Some(header) = packet.mut_tcp_tunnel_header() else {
            return Err(TunnelError::InvalidPacket("packet too short".to_string()));
        };
        header
            .len
            .set((PEER_MANAGER_HEADER_SIZE + payload_len).try_into().unwrap());

        this.sending_bufs.push(packet.into_bytes());

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

        let ret = TunnelCodec::new(DEFAULT_TUNNEL_MTU).decode(&mut buf);

        assert!(matches!(
            ret,
            Err(TunnelError::InvalidPacket(msg)) if msg == "body too short"
        ));
    }

    #[test]
    fn test_tunnel_codec_gso_promotion_and_idle_shrink() {
        use tokio_util::codec::Decoder;

        let mut codec = TunnelCodec::new(1500);
        assert!(!codec.gso);

        // 1. Small packet (1000 bytes body)
        let mut buf = BytesMut::new();
        buf.put_u32_le(1000);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + 1000, 0);

        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
        assert!(!codec.gso);

        // 2. Large packet exceeding MTU (e.g. 5000 bytes body)
        let mut buf = BytesMut::new();
        buf.put_u32_le(5000);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + 5000, 0);

        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
        assert!(codec.gso);

        // 3. Subsequent small packet keeps GSO flag (one-way promotion)
        let mut buf = BytesMut::new();
        buf.put_u32_le(100);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + 100, 0);

        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_some());
        assert!(codec.gso);

        // 4. Idle shrink: when empty and capacity > small_reserve, capacity shrinks back
        let small_reserve =
            (1500 + TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE + TAIL_RESERVED_SIZE) * 4;
        buf.reserve(MAX_PACKET_SIZE * 2);
        assert!(buf.capacity() > small_reserve);
        let decoded = codec.decode(&mut buf).unwrap();
        assert!(decoded.is_none());
        assert_eq!(buf.capacity(), small_reserve);
        assert!(codec.gso); // GSO flag preserved!
    }

    #[test]
    fn test_tunnel_codec_rejects_oversized_packet() {
        use tokio_util::codec::Decoder;

        let mut buf = BytesMut::new();
        buf.put_u32_le((MAX_PACKET_SIZE + 1) as u32);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + 10, 0);

        let ret = TunnelCodec::new(1500).decode(&mut buf);
        assert!(matches!(
            ret,
            Err(TunnelError::InvalidPacket(msg)) if msg == "body too long"
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

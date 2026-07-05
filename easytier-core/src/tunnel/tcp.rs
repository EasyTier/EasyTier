use std::{
    collections::VecDeque,
    pin::Pin,
    sync::Mutex as StdMutex,
    task::{Context, Poll, ready},
};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use crate::{
    packet::{
        PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE, TCPTunnelHeader, ZCPacket, ZCPacketType,
    },
    proto::common::TunnelInfo,
    socket::tcp::VirtualTcpSocket,
    tunnel::{SinkError, SinkItem, SplitTunnel, StreamItem, Tunnel, TunnelError},
};

const TCP_MTU_BYTES: usize = 2000;

fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() < min_size {
        buf.reserve(max_size);
    }
}

struct TcpTunnelStream<R> {
    reader: R,
    buf: BytesMut,
    max_packet_size: usize,
    error: Option<TunnelError>,
}

impl<R> TcpTunnelStream<R> {
    fn new(reader: R, max_packet_size: usize) -> Self {
        Self {
            reader,
            buf: BytesMut::with_capacity(max_packet_size),
            max_packet_size,
            error: None,
        }
    }

    fn extract_one_packet(
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

impl<R> Stream for TcpTunnelStream<R>
where
    R: AsyncRead + Send + 'static + Unpin,
{
    type Item = StreamItem;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;

        loop {
            if let Some(error) = this.error.as_ref() {
                tracing::warn!("poll_next on a failed TcpTunnelStream, {:?}", error);
                return Poll::Ready(None);
            }

            if let Some(packet) = Self::extract_one_packet(&mut this.buf, this.max_packet_size) {
                if let Err(TunnelError::InvalidPacket(msg)) = packet.as_ref() {
                    this.error.replace(TunnelError::InvalidPacket(msg.clone()));
                }
                return Poll::Ready(Some(packet));
            }

            reserve_buf(
                &mut this.buf,
                this.max_packet_size,
                this.max_packet_size * 2,
            );

            let cap = this.buf.capacity() - this.buf.len();
            let buf = this.buf.chunk_mut().as_mut_ptr();
            let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
            let mut buf = ReadBuf::new(buf);

            let ret = ready!(Pin::new(&mut this.reader).poll_read(cx, &mut buf));
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

    fn push_back(&mut self, buf: Bytes) {
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
}

struct TcpTunnelSink<W> {
    writer: W,
    sending_bufs: SendBufs,
}

impl<W> TcpTunnelSink<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            sending_bufs: SendBufs::new(),
        }
    }

    fn max_buffer_count(&self) -> usize {
        64
    }
}

impl<W> Sink<SinkItem> for TcpTunnelSink<W>
where
    W: AsyncWrite + Send + 'static + Unpin,
{
    type Error = SinkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let max_buffer_count = self.max_buffer_count();
        if self.sending_bufs.len() >= max_buffer_count {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let mut item = item.convert_type(ZCPacketType::TCP);
        let tcp_len = PEER_MANAGER_HEADER_SIZE + item.payload_len();
        let Some(header) = item.mut_tcp_tunnel_header() else {
            return Err(TunnelError::InvalidPacket("packet too short".to_owned()));
        };
        header.len.set(tcp_len.try_into().unwrap());
        this.sending_bufs.push_back(item.into_bytes());
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let mut remaining = this.sending_bufs.remaining();
        while remaining != 0 {
            let n = ready!(poll_write_buf(
                Pin::new(&mut this.writer),
                cx,
                &mut this.sending_bufs
            ))?;
            if n == 0 {
                return Poll::Ready(Err(TunnelError::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                ))));
            }
            remaining -= n;
        }

        ready!(Pin::new(&mut this.writer).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(Pin::new(&mut self.get_mut().writer).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

pub struct TcpTunnel<S> {
    info: Option<TunnelInfo>,
    socket: StdMutex<Option<S>>,
}

impl<S> TcpTunnel<S> {
    fn new(socket: S, tunnel_info: TunnelInfo) -> Self {
        Self {
            info: Some(tunnel_info),
            socket: StdMutex::new(Some(socket)),
        }
    }
}

impl<S> Tunnel for TcpTunnel<S>
where
    S: VirtualTcpSocket,
{
    fn split(&self) -> SplitTunnel {
        let socket = self
            .socket
            .lock()
            .unwrap()
            .take()
            .expect("TcpTunnel can only be split once");
        let (reader, writer) = tokio::io::split(socket);
        (
            Box::pin(TcpTunnelStream::new(reader, TCP_MTU_BYTES)),
            Box::pin(TcpTunnelSink::new(writer)),
        )
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub struct TcpTunnelUpgrader {
    tunnel_info: TunnelInfo,
}

impl TcpTunnelUpgrader {
    pub fn new(tunnel_info: TunnelInfo) -> Self {
        Self { tunnel_info }
    }

    pub fn upgrade<S>(self, socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        S: VirtualTcpSocket,
    {
        Ok(Box::new(TcpTunnel::new(socket, self.tunnel_info)))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        task::{Context, Poll},
    };

    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl MockTcpSocket {
        fn new(stream: DuplexStream, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
            Self {
                stream,
                local_addr,
                peer_addr,
            }
        }
    }

    impl AsyncRead for MockTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockTcpSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for MockTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }
    }

    fn set_tcp_tunnel_len(packet: &mut ZCPacket) {
        let tcp_len = PEER_MANAGER_HEADER_SIZE + packet.payload_len();
        packet
            .mut_tcp_tunnel_header()
            .unwrap()
            .len
            .set(tcp_len.try_into().unwrap());
    }

    #[tokio::test]
    async fn tcp_tunnel_upgrader_preserves_metadata_and_framing() {
        let (socket_stream, mut peer_stream) = tokio::io::duplex(65536);
        let socket = MockTcpSocket::new(
            socket_stream,
            "127.0.0.1:1000".parse().unwrap(),
            "127.0.0.1:2000".parse().unwrap(),
        );
        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        };
        let tunnel = TcpTunnelUpgrader::new(info.clone())
            .upgrade(socket)
            .unwrap();
        assert_eq!(tunnel.info(), Some(info));

        let (mut stream, mut sink) = tunnel.split();
        let outbound = ZCPacket::new_with_payload(b"outbound");
        let mut expected = outbound.clone().convert_type(ZCPacketType::TCP);
        set_tcp_tunnel_len(&mut expected);
        let expected_raw = expected.into_bytes();
        let read_peer = tokio::spawn(async move {
            let mut raw = vec![0; expected_raw.len()];
            peer_stream.read_exact(&mut raw).await.unwrap();
            assert_eq!(raw, expected_raw);

            let mut inbound =
                ZCPacket::new_with_payload(b"inbound").convert_type(ZCPacketType::TCP);
            set_tcp_tunnel_len(&mut inbound);
            peer_stream.write_all(&inbound.into_bytes()).await.unwrap();
        });
        sink.send(outbound).await.unwrap();
        sink.flush().await.unwrap();

        let packet = stream.next().await.unwrap().unwrap();
        assert_eq!(packet.payload(), b"inbound");
        read_peer.await.unwrap();
    }
}

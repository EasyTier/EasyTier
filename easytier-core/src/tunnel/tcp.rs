use std::sync::Mutex as StdMutex;

use crate::{
    proto::common::TunnelInfo,
    socket::tcp::VirtualTcpSocket,
    tunnel::framed::{FramedReader, FramedWriter, TCP_MTU_BYTES},
    tunnel::{SplitTunnel, Tunnel, TunnelError},
};

pub struct TcpTunnel<S> {
    info: Option<TunnelInfo>,
    socket: StdMutex<Option<S>>,
    max_packet_size: usize,
}

impl<S> TcpTunnel<S> {
    fn new(socket: S, tunnel_info: TunnelInfo, max_packet_size: usize) -> Self {
        Self {
            info: Some(tunnel_info),
            socket: StdMutex::new(Some(socket)),
            max_packet_size,
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
            Box::pin(FramedReader::new(reader, self.max_packet_size)),
            Box::pin(FramedWriter::new(writer)),
        )
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub struct TcpTunnelUpgrader {
    tunnel_info: TunnelInfo,
    max_packet_size: usize,
}

impl TcpTunnelUpgrader {
    pub fn new(tunnel_info: TunnelInfo) -> Self {
        Self {
            tunnel_info,
            max_packet_size: TCP_MTU_BYTES,
        }
    }

    pub(crate) fn with_max_packet_size(mut self, max_packet_size: usize) -> Self {
        self.max_packet_size = max_packet_size;
        self
    }

    pub fn upgrade<S>(self, socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        S: VirtualTcpSocket,
    {
        Ok(Box::new(TcpTunnel::new(
            socket,
            self.tunnel_info,
            self.max_packet_size,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use crate::packet::{PEER_MANAGER_HEADER_SIZE, ZCPacket, ZCPacketType};
    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

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

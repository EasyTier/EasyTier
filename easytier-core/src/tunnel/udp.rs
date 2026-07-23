use std::{
    pin::Pin,
    sync::{Arc, Mutex as StdMutex},
    task::{Context, Poll},
};

use bytes::BytesMut;
use futures::{Sink, Stream};
use tokio::sync::{oneshot, watch};

use crate::{
    packet::{UDP_TUNNEL_HEADER_SIZE, UdpPacketType, ZCPacket, ZCPacketType},
    proto::common::TunnelInfo,
    socket::{
        ring::{RingSocketError, RingSocketReceiver, RingSocketSendError, RingSocketSender},
        udp::{
            UdpSession, UdpSessionCleanup, UdpSessionCodec, UdpSessionDatagram, UdpSessionOutbound,
            UdpSessionTunnelParts,
        },
    },
    tunnel::{SinkError, SinkItem, SplitTunnel, StreamItem, Tunnel, TunnelError},
};

fn zcpacket_from_udp_session_payload(payload: &[u8]) -> Result<ZCPacket, TunnelError> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| TunnelError::ExceedMaxPacketSize(u16::MAX as usize, payload.len()))?;
    let mut buf = BytesMut::new();
    buf.resize(UDP_TUNNEL_HEADER_SIZE + payload.len(), 0);
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(payload);

    let mut packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = packet.mut_udp_tunnel_header().unwrap();
    header.msg_type = UdpPacketType::Data as u8;
    header.len.set(payload_len);
    Ok(packet)
}

fn ring_socket_error_to_tunnel(error: RingSocketError) -> TunnelError {
    match error {
        RingSocketError::Closed => TunnelError::Shutdown,
        RingSocketError::Full => TunnelError::BufferFull,
        RingSocketError::AlreadySplit => {
            TunnelError::InternalError("udp session ring already split".to_owned())
        }
    }
}

fn ring_send_error_to_tunnel<T>(error: RingSocketSendError<T>) -> TunnelError {
    match error {
        RingSocketSendError::Closed(_) => TunnelError::Shutdown,
        RingSocketSendError::Full(_) => TunnelError::BufferFull,
    }
}

struct UdpTunnelSessionGuard {
    cleanup: StdMutex<Option<UdpSessionCleanup>>,
    _layer_guard: Option<Box<dyn Send + Sync>>,
}

impl UdpTunnelSessionGuard {
    fn close_session(&self) {
        drop(self.cleanup.lock().unwrap().take());
    }
}

struct UdpTunnelStream {
    session_recv_rx: RingSocketReceiver<UdpSessionDatagram>,
    session_guard: Arc<UdpTunnelSessionGuard>,
}

impl Stream for UdpTunnelStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let ret = std::task::ready!(Pin::new(&mut self.get_mut().session_recv_rx).poll_next(cx));
        Poll::Ready(ret.map(|payload| {
            payload
                .map_err(ring_socket_error_to_tunnel)
                .and_then(|datagram| zcpacket_from_udp_session_payload(&datagram.payload))
        }))
    }
}

impl Drop for UdpTunnelStream {
    fn drop(&mut self) {
        self.session_guard.close_session();
    }
}

struct UdpTunnelSink {
    codec: UdpSessionCodec,
    session_send_tx: RingSocketSender<UdpSessionOutbound>,
    closed: watch::Receiver<bool>,
    session_guard: Arc<UdpTunnelSessionGuard>,
}

impl Sink<SinkItem> for UdpTunnelSink {
    type Error = SinkError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if *this.closed.borrow() {
            return Poll::Ready(Err(TunnelError::Shutdown));
        }
        Pin::new(&mut this.session_send_tx)
            .poll_ready(cx)
            .map_err(ring_socket_error_to_tunnel)
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        let this = self.get_mut();
        if *this.closed.borrow() {
            return Err(TunnelError::Shutdown);
        }

        let packet = item.convert_type(ZCPacketType::UDP);
        let payload = BytesMut::from(packet.udp_payload());
        this.codec
            .validate_payload(&payload)
            .map_err(TunnelError::IOError)?;
        let (completion, _sent) = oneshot::channel();
        let outbound = UdpSessionOutbound {
            payload,
            completion,
        };
        this.session_send_tx
            .force_send(outbound)
            .map_err(ring_send_error_to_tunnel)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().session_send_tx)
            .poll_flush(cx)
            .map_err(ring_socket_error_to_tunnel)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.session_send_tx)
            .poll_close(cx)
            .map_err(ring_socket_error_to_tunnel);
        if result.is_ready() {
            this.session_guard.close_session();
        }
        result
    }
}

impl Drop for UdpTunnelSink {
    fn drop(&mut self) {
        self.session_guard.close_session();
    }
}

struct UdpTunnelParts {
    codec: UdpSessionCodec,
    session_recv_rx: RingSocketReceiver<UdpSessionDatagram>,
    session_send_tx: RingSocketSender<UdpSessionOutbound>,
    closed: watch::Receiver<bool>,
    cleanup: UdpSessionCleanup,
    keep_alive: Option<Box<dyn Send + Sync>>,
}

pub struct UdpTunnel {
    info: Option<TunnelInfo>,
    parts: StdMutex<Option<UdpTunnelParts>>,
}

impl UdpTunnel {
    fn new(
        tunnel_info: TunnelInfo,
        session_parts: UdpSessionTunnelParts,
        keep_alive: Option<Box<dyn Send + Sync>>,
    ) -> Self {
        let UdpSessionTunnelParts {
            local_addr,
            peer_addr,
            kind,
            codec,
            session_recv_rx,
            session_send_tx,
            closed,
            cleanup,
        } = session_parts;
        tracing::debug!(
            ?local_addr,
            ?peer_addr,
            ?kind,
            "udp build tunnel from session"
        );
        Self {
            info: Some(tunnel_info),
            parts: StdMutex::new(Some(UdpTunnelParts {
                codec,
                session_recv_rx,
                session_send_tx,
                closed,
                cleanup,
                keep_alive,
            })),
        }
    }
}

impl Tunnel for UdpTunnel {
    fn split(&self) -> SplitTunnel {
        let parts = self
            .parts
            .lock()
            .unwrap()
            .take()
            .expect("UdpTunnel can only be split once");
        let session_guard = Arc::new(UdpTunnelSessionGuard {
            cleanup: StdMutex::new(Some(parts.cleanup)),
            _layer_guard: parts.keep_alive,
        });
        (
            Box::pin(UdpTunnelStream {
                session_recv_rx: parts.session_recv_rx,
                session_guard: session_guard.clone(),
            }),
            Box::pin(UdpTunnelSink {
                codec: parts.codec,
                session_send_tx: parts.session_send_tx,
                closed: parts.closed,
                session_guard,
            }),
        )
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub struct UdpTunnelUpgrader {
    tunnel_info: TunnelInfo,
    keep_alive: Option<Box<dyn Send + Sync>>,
}

impl UdpTunnelUpgrader {
    pub fn new(tunnel_info: TunnelInfo) -> Self {
        Self {
            tunnel_info,
            keep_alive: None,
        }
    }

    pub fn with_keep_alive<T>(tunnel_info: TunnelInfo, keep_alive: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        Self {
            tunnel_info,
            keep_alive: Some(Box::new(keep_alive)),
        }
    }

    pub fn upgrade(self, session: UdpSession) -> Result<Box<dyn Tunnel>, TunnelError> {
        let Self {
            tunnel_info,
            keep_alive,
        } = self;
        Ok(Box::new(UdpTunnel::new(
            tunnel_info,
            session.into_tunnel_parts(),
            keep_alive,
        )))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        sync::{Arc, Mutex as StdMutex},
        time::Duration,
    };

    use async_trait::async_trait;
    use futures::{SinkExt, StreamExt};
    use tokio::{
        sync::mpsc::{Receiver, channel},
        time::{sleep, timeout},
    };

    use crate::socket::udp::{UdpSessionKind, VirtualUdpSocket};

    use super::*;

    struct MockVirtualUdpSocket {
        local_addr: SocketAddr,
        inbound: tokio::sync::Mutex<Receiver<(Vec<u8>, SocketAddr)>>,
        sent: StdMutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockVirtualUdpSocket {
        fn new(local_addr: SocketAddr, inbound: Receiver<(Vec<u8>, SocketAddr)>) -> Self {
            Self {
                local_addr,
                inbound: tokio::sync::Mutex::new(inbound),
                sent: StdMutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockVirtualUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let mut inbound = self.inbound.lock().await;
            let Some((data, addr)) = inbound.recv().await else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mock socket closed",
                ));
            };
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok((len, addr))
        }
    }

    async fn wait_until<F>(mut condition: F)
    where
        F: FnMut() -> bool,
    {
        timeout(Duration::from_secs(1), async {
            loop {
                if condition() {
                    return;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn udp_tunnel_upgrader_consumes_udp_session_rings() {
        let local_addr = "127.0.0.1:1".parse().unwrap();
        let peer_addr = "127.0.0.1:2".parse().unwrap();
        let (network_sender, network_recv) = channel(8);
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, network_recv));
        let session =
            UdpSession::identity_standalone(socket.clone(), peer_addr, UdpSessionKind::Quic)
                .unwrap();
        let tunnel = UdpTunnelUpgrader::new(TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        })
        .upgrade(session)
        .unwrap();
        let (mut stream, mut sink) = tunnel.split();

        let outbound_packet = ZCPacket::new_with_payload(b"outbound");
        let expected_session_payload = outbound_packet
            .clone()
            .convert_type(ZCPacketType::UDP)
            .udp_payload()
            .to_vec();
        sink.send(outbound_packet).await.unwrap();
        wait_until(|| !socket.sent().is_empty()).await;
        assert_eq!(socket.sent(), vec![(expected_session_payload, peer_addr)]);

        network_sender
            .send((b"inbound".to_vec(), peer_addr))
            .await
            .unwrap();
        let packet = timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(packet.udp_payload(), b"inbound");
    }

    #[tokio::test]
    async fn udp_tunnel_sink_close_closes_session() {
        let local_addr = "127.0.0.1:1".parse().unwrap();
        let peer_addr = "127.0.0.1:2".parse().unwrap();
        let (_network_sender, network_recv) = channel(8);
        let socket = Arc::new(MockVirtualUdpSocket::new(local_addr, network_recv));
        let session =
            UdpSession::identity_standalone(socket, peer_addr, UdpSessionKind::Quic).unwrap();
        let tunnel = UdpTunnelUpgrader::new(TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        })
        .upgrade(session)
        .unwrap();
        let (mut stream, mut sink) = tunnel.split();

        sink.close().await.unwrap();
        let item = timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap();
        assert!(
            item.is_none() || matches!(item, Some(Err(TunnelError::Shutdown))),
            "session stream must close after sink close"
        );
    }
}

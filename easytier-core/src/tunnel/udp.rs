use std::sync::Arc;

use bytes::BytesMut;
use futures::StreamExt;
use tracing::Instrument;

use crate::{
    packet::{UDP_TUNNEL_HEADER_SIZE, UdpPacketType, ZCPacket, ZCPacketType},
    proto::common::TunnelInfo,
    socket::udp::UdpSessionSocket,
    tunnel::{
        Tunnel, TunnelError,
        ring::{
            RingSink, RingSinkSendError, RingStream, RingTunnel, create_ring_socket_pair,
            split_ring_socket,
        },
    },
};

const UDP_TUNNEL_BRIDGE_RING_CAPACITY: usize = 128;

async fn forward_from_ring_to_udp_session(
    mut ring_recv: RingStream,
    session: Arc<dyn UdpSessionSocket>,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from ring to udp session");
    loop {
        let buf = ring_recv.next().await?;
        let packet = match buf {
            Ok(v) => v,
            Err(e) => return Some(e),
        };

        let packet = packet.convert_type(ZCPacketType::UDP);
        let payload = BytesMut::from(packet.udp_payload());
        match session.send(&payload).await {
            Ok(0) => return None,
            Ok(_) => {}
            Err(err) => return Some(TunnelError::IOError(err)),
        }
    }
}

async fn forward_from_udp_session_to_ring(
    session: Arc<dyn UdpSessionSocket>,
    mut ring_sender: RingSink,
) -> Option<TunnelError> {
    tracing::debug!("udp forward from udp session to ring");
    let mut buf = vec![0u8; u16::MAX as usize];
    loop {
        let len = match session.recv(&mut buf).await {
            Ok(0) => return None,
            Ok(len) => len,
            Err(err) => return Some(TunnelError::IOError(err)),
        };

        let zc_packet = match zcpacket_from_udp_session_payload(&buf[..len]) {
            Ok(packet) => packet,
            Err(err) => return Some(err),
        };
        if let Some(err) = send_zcpacket_to_ring(&mut ring_sender, zc_packet) {
            if matches!(err, TunnelError::BufferFull) {
                tracing::trace!(?err, "udp session bridge ring send failed");
                continue;
            }
            return Some(err);
        }
    }
}

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

fn send_zcpacket_to_ring(ring_sender: &mut RingSink, zc_packet: ZCPacket) -> Option<TunnelError> {
    if zc_packet.is_lossy() {
        if let Err(err) = ring_sender.try_send(zc_packet) {
            match err {
                RingSinkSendError::Full(packet) => {
                    tracing::trace!(?packet, "ring sender full, drop lossy packet");
                }
                RingSinkSendError::Closed(_) => return Some(TunnelError::Shutdown),
            }
        }
    } else if let Err(err) = ring_sender.force_send(zc_packet) {
        return match err {
            RingSinkSendError::Full(_) => {
                tracing::trace!("ring sender full, reject non-lossy packet");
                Some(TunnelError::BufferFull)
            }
            RingSinkSendError::Closed(_) => Some(TunnelError::Shutdown),
        };
    }

    None
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

    pub fn upgrade(
        self,
        session: Arc<dyn UdpSessionSocket>,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let Self {
            tunnel_info,
            keep_alive,
        } = self;
        let (tunnel_ring, udp_ring) = create_ring_socket_pair(UDP_TUNNEL_BRIDGE_RING_CAPACITY);
        tracing::debug!(?tunnel_ring, ?udp_ring, "udp build tunnel from session");

        let (ring_recv, ring_sender) = split_ring_socket(udp_ring);
        let send_session = session.clone();
        let recv_session = session.clone();
        let dst_addr = session.peer_addr()?;
        tokio::spawn(
            async move {
                let _keep_alive = keep_alive;
                tokio::select! {
                    err = forward_from_ring_to_udp_session(ring_recv, send_session) => {
                        tracing::debug!(?err, "udp ring-to-session task done");
                    }
                    err = forward_from_udp_session_to_ring(recv_session, ring_sender) => {
                        tracing::debug!(?err, "udp session-to-ring task done");
                    }
                }
            }
            .instrument(tracing::info_span!(
                "udp forward between session and ring",
                ?dst_addr,
            )),
        );

        Ok(Box::new(RingTunnel::new(tunnel_ring, Some(tunnel_info))))
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

    use crate::{
        packet::{PacketType, UdpPacketType, ZCPacket, ZCPacketType},
        socket::udp::{UdpSessionKind, UdpSessionSocket},
    };

    use super::*;

    fn new_udp_data_packet(conn_id: u32, packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(b"udp-data").convert_type(ZCPacketType::UDP);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        let udp_payload_len = packet.udp_payload().len();
        let header = packet.mut_udp_tunnel_header().unwrap();
        header.conn_id.set(conn_id);
        header.msg_type = UdpPacketType::Data as u8;
        header.len.set(udp_payload_len as u16);
        packet
    }

    struct MockUdpSessionSocket {
        recv: tokio::sync::Mutex<Receiver<Vec<u8>>>,
        sent: StdMutex<Vec<Vec<u8>>>,
    }

    impl MockUdpSessionSocket {
        fn new(recv: Receiver<Vec<u8>>) -> Self {
            Self {
                recv: tokio::sync::Mutex::new(recv),
                sent: StdMutex::new(Vec::new()),
            }
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl UdpSessionSocket for MockUdpSessionSocket {
        fn kind(&self) -> UdpSessionKind {
            UdpSessionKind::EasyTierMux
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2".parse().unwrap())
        }

        async fn send(&self, data: &[u8]) -> io::Result<usize> {
            self.sent.lock().unwrap().push(data.to_vec());
            Ok(data.len())
        }

        async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            let mut recv = self.recv.lock().await;
            let Some(data) = recv.recv().await else {
                return Ok(0);
            };
            let len = data.len().min(buf.len());
            buf[..len].copy_from_slice(&data[..len]);
            Ok(len)
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

    #[test]
    fn udp_session_bridge_keeps_lossy_ring_delivery_policy() {
        let (_tunnel_ring, udp_ring) = create_ring_socket_pair(8);
        let (_udp_recv, mut udp_sender) = split_ring_socket(udp_ring);

        for _ in 0..16 {
            assert!(
                send_zcpacket_to_ring(&mut udp_sender, new_udp_data_packet(0, PacketType::Data))
                    .is_none()
            );
        }

        let mut got_buffer_full = false;
        for _ in 0..16 {
            match send_zcpacket_to_ring(&mut udp_sender, new_udp_data_packet(0, PacketType::Ping)) {
                None => {}
                Some(TunnelError::BufferFull) => {
                    got_buffer_full = true;
                    break;
                }
                Some(err) => panic!("unexpected error: {err:?}"),
            }
        }
        assert!(got_buffer_full);
    }

    #[tokio::test]
    async fn udp_tunnel_upgrader_consumes_udp_session_socket() {
        let (payload_sender, payload_recv) = channel(8);
        let session = Arc::new(MockUdpSessionSocket::new(payload_recv));
        let tunnel = UdpTunnelUpgrader::new(TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: None,
            remote_addr: None,
            resolved_remote_addr: None,
        })
        .upgrade(session.clone())
        .unwrap();
        let (mut stream, mut sink) = tunnel.split();

        let outbound_packet = ZCPacket::new_with_payload(b"outbound");
        let expected_session_payload = outbound_packet
            .clone()
            .convert_type(ZCPacketType::UDP)
            .udp_payload()
            .to_vec();
        sink.send(outbound_packet).await.unwrap();
        wait_until(|| !session.sent().is_empty()).await;
        assert_eq!(session.sent(), vec![expected_session_payload]);

        payload_sender.send(b"inbound".to_vec()).await.unwrap();
        let packet = timeout(Duration::from_secs(1), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        assert_eq!(packet.udp_payload(), b"inbound");
    }

    #[tokio::test]
    async fn udp_session_bridge_keeps_running_after_non_lossy_ring_full() {
        let (payload_sender, payload_recv) = channel(32);
        let session = Arc::new(MockUdpSessionSocket::new(payload_recv));
        let (tunnel_ring, udp_ring) = create_ring_socket_pair(8);
        let (_tunnel_recv, _tunnel_sender) = split_ring_socket(tunnel_ring);
        let (_udp_recv, udp_sender) = split_ring_socket(udp_ring);
        let payload = new_udp_data_packet(0, PacketType::Ping)
            .udp_payload()
            .to_vec();

        let mut bridge_task = tokio::spawn(forward_from_udp_session_to_ring(session, udp_sender));
        for _ in 0..16 {
            payload_sender.send(payload.clone()).await.unwrap();
        }

        assert!(
            timeout(Duration::from_millis(100), &mut bridge_task)
                .await
                .is_err(),
            "bridge task must keep running after transient non-lossy BufferFull"
        );
        bridge_task.abort();
    }
}

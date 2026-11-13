use std::{
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use easytier_core::{
    gateway::proxy::icmp_host::{IcmpProxyHost, IcmpProxySocket, ProxyRuntimeError},
    socket::SocketContext,
};
use socket2::Socket;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::common::netns::NetNS;

#[derive(Debug, Default)]
pub(crate) struct RuntimeIcmpProxyHost;

impl RuntimeIcmpProxyHost {
    fn create_raw_socket(context: &SocketContext) -> Result<Socket, std::io::Error> {
        let _guard = NetNS::from_socket_context(context).guard();
        let socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        socket.set_nonblocking(true)?;
        Ok(socket)
    }
}

#[derive(Debug)]
struct RuntimeIcmpSocket {
    socket: UdpSocket,
    cancel: CancellationToken,
}

#[async_trait::async_trait]
impl IcmpProxySocket for RuntimeIcmpSocket {
    async fn send(&self, destination: Ipv4Addr, packet: &[u8]) -> Result<(), ProxyRuntimeError> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into()),
            result = self.socket.send_to(packet, SocketAddrV4::new(destination, 0)) => { result?; }
        }
        Ok(())
    }

    async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError> {
        let mut buffer = vec![0_u8; 8192];
        let (length, peer) = tokio::select! {
            biased;
            // The proxy receive loop terminates on an empty packet. A permanent
            // error would be retried immediately and could prevent task abortion.
            _ = self.cancel.cancelled() => return Ok((IpAddr::V4(Ipv4Addr::UNSPECIFIED), Vec::new())),
            result = self.socket.recv_from(&mut buffer) => result?,
        };
        buffer.truncate(length);
        Ok((peer.ip(), buffer))
    }

    fn close(&self) {
        self.cancel.cancel();
    }
}

#[async_trait::async_trait]
impl IcmpProxyHost for RuntimeIcmpProxyHost {
    async fn open_icmp_v4(
        &self,
        context: SocketContext,
    ) -> Result<Arc<dyn IcmpProxySocket>, ProxyRuntimeError> {
        let socket = Self::create_raw_socket(&context).inspect_err(|error| {
            tracing::warn!(?error, "create ICMP socket failed");
        })?;
        // Tokio only supplies readiness and recvfrom/sendto here; the underlying
        // socket remains raw ICMP, including the IPv4 header on received packets.
        Ok(Arc::new(RuntimeIcmpSocket {
            socket: UdpSocket::from_std(socket.into())?,
            cancel: CancellationToken::new(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn close_ends_receivers_and_rejects_further_sends() {
        let socket = RuntimeIcmpSocket {
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
            cancel: CancellationToken::new(),
        };
        let mut first = Box::pin(socket.recv());
        let mut second = Box::pin(socket.recv());
        assert!(futures::poll!(&mut first).is_pending());
        assert!(futures::poll!(&mut second).is_pending());

        socket.close();
        socket.close();
        tokio::time::timeout(Duration::from_secs(1), async {
            assert!(first.await.unwrap().1.is_empty());
            assert!(second.await.unwrap().1.is_empty());
            assert!(socket.recv().await.unwrap().1.is_empty());
            assert!(socket.send(Ipv4Addr::LOCALHOST, &[0; 8]).await.is_err());
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelled_receive_does_not_consume_the_next_packet() {
        let socket = RuntimeIcmpSocket {
            socket: UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap(),
            cancel: CancellationToken::new(),
        };
        let mut receive = Box::pin(socket.recv());
        assert!(futures::poll!(&mut receive).is_pending());
        drop(receive);

        let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        sender
            .send_to(b"after cancellation", socket.socket.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, packet) = tokio::time::timeout(Duration::from_secs(1), socket.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(packet, b"after cancellation");
    }

    // Raw ICMP requires CAP_NET_RAW; run this test in the privileged test container.
    #[test]
    #[cfg(target_os = "linux")]
    fn raw_echo_fanout_does_not_start_blocking_threads() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let threads = Arc::new(AtomicUsize::new(0));
        let started = threads.clone();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .on_thread_start(move || {
                started.fetch_add(1, Ordering::Relaxed);
            })
            .build()
            .unwrap();
        let result = runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                let mut sockets = Vec::new();
                for _ in 0..30 {
                    sockets.push(
                        RuntimeIcmpProxyHost
                            .open_icmp_v4(SocketContext::default())
                            .await
                            .unwrap(),
                    );
                }
                let identifier = rand::random::<u16>().to_be_bytes();
                for sequence in 0..16 {
                    let mut request = vec![8, 0, 0, 0, identifier[0], identifier[1], 0, sequence];
                    request.extend_from_slice(b"async ICMP");
                    let mut checksum: u32 = request
                        .chunks_exact(2)
                        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
                        .sum();
                    while checksum >> 16 != 0 {
                        checksum = (checksum & 0xffff) + (checksum >> 16);
                    }
                    request[2..4].copy_from_slice(&(!(checksum as u16)).to_be_bytes());
                    let receivers = futures::future::join_all(sockets.iter().map(|socket| async {
                        loop {
                            let (peer, packet) = socket.recv().await.unwrap();
                            let header_len = usize::from(packet[0] & 0x0f) * 4;
                            let Some(reply) = packet.get(header_len..) else {
                                continue;
                            };
                            if reply.len() == request.len()
                                && reply[0] == 0
                                && reply[4..] == request[4..]
                            {
                                assert_eq!(peer, IpAddr::V4(Ipv4Addr::LOCALHOST));
                                break;
                            }
                        }
                    }));
                    tokio::join!(receivers, async {
                        sockets[0]
                            .send(Ipv4Addr::LOCALHOST, &request)
                            .await
                            .unwrap();
                    });
                }
                for socket in sockets {
                    socket.close();
                }
            })
            .await
        });
        runtime.shutdown_timeout(Duration::from_secs(1));
        result.unwrap();
        assert_eq!(threads.load(Ordering::Relaxed), 0);
    }
}

use async_trait::async_trait;
use url::Url;

use crate::{socket::tcp::VirtualTcpSocket, tunnel::Tunnel};

use super::transport::ConnectedTransport;

pub mod raw;

#[async_trait]
pub trait ClientProtocolUpgrader<TcpSocket>: Send + Sync + 'static {
    fn supports_scheme(&self, scheme: &str) -> bool;

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>>;
}

/// Core's built-in TCP and UDP tunnel framing.
///
/// Hosts only need to provide a different upgrader when they enable an
/// optional protocol whose implementation has not moved into core yet.
#[derive(Debug, Default)]
pub struct RawClientProtocolUpgrader;

#[async_trait]
impl<TcpSocket> ClientProtocolUpgrader<TcpSocket> for RawClientProtocolUpgrader
where
    TcpSocket: VirtualTcpSocket,
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        matches!(scheme, "tcp" | "udp" | "ring" | "unix")
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        match (requested_url.scheme(), connected) {
            ("tcp", ConnectedTransport::Tcp(socket)) => {
                Ok(raw::upgrade_connected_tcp(socket, requested_url)?)
            }
            ("udp", ConnectedTransport::Udp(session)) => {
                Ok(raw::upgrade_connected_udp(session, requested_url)?)
            }
            ("ring" | "unix", ConnectedTransport::ByteStream(stream)) => {
                Ok(raw::upgrade_connected_byte_stream(stream)?)
            }
            ("tcp", ConnectedTransport::Udp(_) | ConnectedTransport::ByteStream(_)) => {
                anyhow::bail!("TCP protocol requires a TCP transport")
            }
            ("udp", ConnectedTransport::Tcp(_) | ConnectedTransport::ByteStream(_)) => {
                anyhow::bail!("UDP protocol requires a UDP session")
            }
            ("ring" | "unix", _) => {
                anyhow::bail!("external byte-stream protocol requires a byte stream")
            }
            (scheme, _) => anyhow::bail!("unsupported client protocol upgrader: {scheme}"),
        }
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

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    struct MockTcpSocket;

    impl AsyncRead for MockTcpSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for MockTcpSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<Result<usize, io::Error>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), io::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    impl VirtualTcpSocket for MockTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:1000".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:2000".parse().unwrap())
        }
    }

    #[tokio::test]
    async fn raw_upgrader_rejects_non_raw_and_mismatched_protocols() {
        let upgrader = RawClientProtocolUpgrader;

        let supports = |scheme| {
            <RawClientProtocolUpgrader as ClientProtocolUpgrader<MockTcpSocket>>::supports_scheme(
                &upgrader, scheme,
            )
        };
        assert!(supports("ring"));
        assert!(supports("unix"));

        let unsupported = upgrader
            .upgrade_client(
                ConnectedTransport::Tcp(MockTcpSocket),
                "ws://127.0.0.1:2000".parse().unwrap(),
            )
            .await;
        assert!(unsupported.is_err());

        let mismatched = upgrader
            .upgrade_client(
                ConnectedTransport::Tcp(MockTcpSocket),
                "udp://127.0.0.1:2000".parse().unwrap(),
            )
            .await;
        assert!(mismatched.is_err());
    }
}

use std::sync::Arc;

use async_trait::async_trait;
use url::Url;

use crate::{socket::tcp::VirtualTcpSocket, tunnel::Tunnel};

use super::transport::ConnectedTransport;

pub mod faketcp;
pub mod insecure_tls;
pub mod raw;
pub mod websocket;
pub mod wireguard;

#[async_trait]
pub trait ClientProtocolUpgrader<TcpSocket>: Send + Sync + 'static {
    fn supports_scheme(&self, scheme: &str) -> bool;

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CoreClientProtocolConfig {
    pub unix: bool,
    pub faketcp: bool,
}

/// Owns portable client protocol dispatch and delegates only protocol engines
/// that are not yet available in core.
pub struct CoreClientProtocolUpgrader<TcpSocket> {
    config: CoreClientProtocolConfig,
    external: Option<Arc<dyn ClientProtocolUpgrader<TcpSocket>>>,
}

impl<TcpSocket> CoreClientProtocolUpgrader<TcpSocket> {
    pub fn new(config: CoreClientProtocolConfig) -> Self {
        Self {
            config,
            external: None,
        }
    }

    pub fn with_external(
        config: CoreClientProtocolConfig,
        external: Arc<dyn ClientProtocolUpgrader<TcpSocket>>,
    ) -> Self {
        Self {
            config,
            external: Some(external),
        }
    }
}

#[async_trait]
impl<TcpSocket> ClientProtocolUpgrader<TcpSocket> for CoreClientProtocolUpgrader<TcpSocket>
where
    TcpSocket: VirtualTcpSocket,
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        match scheme {
            "tcp" | "udp" | "ring" => true,
            "unix" => self.config.unix,
            "faketcp" => self.config.faketcp,
            _ => self
                .external
                .as_ref()
                .is_some_and(|external| external.supports_scheme(scheme)),
        }
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        match requested_url.scheme() {
            "tcp" | "udp" => Ok(raw::upgrade_connected(connected, requested_url)?),
            "ring" => upgrade_byte_stream(connected),
            "unix" if self.config.unix => upgrade_byte_stream(connected),
            "faketcp" if self.config.faketcp => match connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(faketcp::upgrade_connected(socket, requested_url)?)
                }
                ConnectedTransport::Udp(_) | ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("FakeTCP protocol requires a TCP transport")
                }
            },
            "unix" | "faketcp" => anyhow::bail!(
                "unsupported client protocol upgrader: {}",
                requested_url.scheme()
            ),
            scheme => {
                let Some(external) = &self.external else {
                    anyhow::bail!("unsupported client protocol upgrader: {scheme}");
                };
                if !external.supports_scheme(scheme) {
                    anyhow::bail!("unsupported client protocol upgrader: {scheme}");
                }
                external.upgrade_client(connected, requested_url).await
            }
        }
    }
}

fn upgrade_byte_stream<TcpSocket>(
    connected: ConnectedTransport<TcpSocket>,
) -> anyhow::Result<Box<dyn Tunnel>>
where
    TcpSocket: VirtualTcpSocket,
{
    match connected {
        ConnectedTransport::ByteStream(stream) => Ok(raw::upgrade_connected_byte_stream(stream)?),
        ConnectedTransport::Tcp(_) | ConnectedTransport::Udp(_) => {
            anyhow::bail!("external protocol requires a host-created byte stream")
        }
    }
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

    struct MockExternalUpgrader;

    #[async_trait]
    impl ClientProtocolUpgrader<MockTcpSocket> for MockExternalUpgrader {
        fn supports_scheme(&self, _scheme: &str) -> bool {
            true
        }

        async fn upgrade_client(
            &self,
            _connected: ConnectedTransport<MockTcpSocket>,
            _requested_url: Url,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            anyhow::bail!("external protocol invoked")
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

    #[tokio::test]
    async fn core_upgrader_owns_builtin_capabilities_and_delegates_external_protocols() {
        let upgrader = CoreClientProtocolUpgrader::with_external(
            CoreClientProtocolConfig {
                unix: false,
                faketcp: false,
            },
            Arc::new(MockExternalUpgrader),
        );

        assert!(upgrader.supports_scheme("tcp"));
        assert!(upgrader.supports_scheme("ring"));
        assert!(upgrader.supports_scheme("ws"));
        assert!(!upgrader.supports_scheme("unix"));
        assert!(!upgrader.supports_scheme("faketcp"));

        let external = upgrader
            .upgrade_client(
                ConnectedTransport::Tcp(MockTcpSocket),
                "ws://127.0.0.1:2000".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(external.to_string(), "external protocol invoked");

        let disabled_builtin = upgrader
            .upgrade_client(
                ConnectedTransport::Tcp(MockTcpSocket),
                "faketcp://127.0.0.1:2000".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert!(
            disabled_builtin
                .to_string()
                .contains("unsupported client protocol upgrader")
        );
    }
}

use std::{marker::PhantomData, num::NonZeroUsize, sync::Arc, time::Duration};

use async_trait::async_trait;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::{
    socket::{tcp::VirtualTcpSocket, udp::UdpSession},
    tunnel::Tunnel,
};

use super::transport::ConnectedTransport;

pub mod raw;

#[async_trait]
pub trait ClientProtocolUpgrader<TcpSocket>: Send + Sync + 'static {
    fn supports_scheme(&self, scheme: &str) -> bool;

    fn connect_timeout(&self, _scheme: &str) -> Option<Duration> {
        None
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>>;
}

#[async_trait]
pub trait ServerTunnelAcceptor: Send + 'static {
    async fn accept(&mut self) -> anyhow::Result<Box<dyn Tunnel>>;
}

pub enum ServerProtocolUpgrade {
    Tunnel(Box<dyn Tunnel>),
    Acceptor(Box<dyn ServerTunnelAcceptor>),
}

pub struct ServerProtocolAdmission {
    active_session: OwnedSemaphorePermit,
    handshake_slots: Arc<Semaphore>,
}

impl ServerProtocolAdmission {
    pub fn into_parts(self) -> (OwnedSemaphorePermit, Arc<Semaphore>) {
        (self.active_session, self.handshake_slots)
    }
}

pub struct ServerProtocolAdmissionController {
    active_sessions: Arc<Semaphore>,
    handshake_slots: Arc<Semaphore>,
}

impl ServerProtocolAdmissionController {
    pub fn new(max_active_sessions: usize, max_in_flight_handshakes: usize) -> Self {
        Self {
            active_sessions: Arc::new(Semaphore::new(max_active_sessions)),
            handshake_slots: Arc::new(Semaphore::new(max_in_flight_handshakes)),
        }
    }

    pub fn try_admit(&self) -> Option<ServerProtocolAdmission> {
        Some(ServerProtocolAdmission {
            active_session: self.active_sessions.clone().try_acquire_owned().ok()?,
            handshake_slots: self.handshake_slots.clone(),
        })
    }

    pub fn quic() -> Self {
        Self::new(1024, 128)
    }
}

#[async_trait]
pub trait ServerProtocolUpgrader<TcpSocket>: Send + Sync + 'static {
    fn supports_scheme(&self, scheme: &str) -> bool;

    fn max_pending_tcp_upgrades(&self, _scheme: &str) -> Option<NonZeroUsize> {
        None
    }

    async fn upgrade_tcp(
        &self,
        socket: TcpSocket,
        local_url: Url,
    ) -> anyhow::Result<ServerProtocolUpgrade>;

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        local_url: Url,
        admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade>;

    async fn upgrade_byte_stream(
        &self,
        socket: TcpSocket,
        local_url: Url,
        remote_url: Option<Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade>;
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

    fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
        self.external
            .as_ref()
            .filter(|external| external.supports_scheme(scheme))
            .and_then(|external| external.connect_timeout(scheme))
    }

    async fn upgrade_client(
        &self,
        connected: ConnectedTransport<TcpSocket>,
        requested_url: Url,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        match requested_url.scheme() {
            "tcp" => match connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(raw::upgrade_connected_tcp(socket, requested_url)?)
                }
                ConnectedTransport::Udp(_) | ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("TCP protocol requires a TCP transport")
                }
            },
            "udp" => match connected {
                ConnectedTransport::Udp(session) => {
                    Ok(raw::upgrade_connected_udp(session, requested_url)?)
                }
                ConnectedTransport::Tcp(_) | ConnectedTransport::ByteStream(_) => {
                    anyhow::bail!("UDP protocol requires a UDP session")
                }
            },
            "ring" => upgrade_byte_stream(connected),
            "unix" if self.config.unix => upgrade_byte_stream(connected),
            "faketcp" if self.config.faketcp => match connected {
                ConnectedTransport::Tcp(socket) => {
                    Ok(raw::upgrade_connected_tcp(socket, requested_url)?)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreServerProtocolConfig {
    pub unix: bool,
    pub faketcp: bool,
}

impl Default for CoreServerProtocolConfig {
    fn default() -> Self {
        Self {
            unix: false,
            faketcp: false,
        }
    }
}

/// Owns portable server protocol dispatch and delegates only protocol engines
/// that are not available in core.
pub struct CoreServerProtocolUpgrader<TcpSocket> {
    config: CoreServerProtocolConfig,
    external: Option<Arc<dyn ServerProtocolUpgrader<TcpSocket>>>,
    tcp_socket: PhantomData<fn() -> TcpSocket>,
}

impl<TcpSocket: 'static> CoreServerProtocolUpgrader<TcpSocket> {
    pub fn new(config: CoreServerProtocolConfig) -> Self {
        Self {
            config,
            external: None,
            tcp_socket: PhantomData,
        }
    }

    pub fn with_external(
        config: CoreServerProtocolConfig,
        external: Arc<dyn ServerProtocolUpgrader<TcpSocket>>,
    ) -> Self {
        Self {
            config,
            external: Some(external),
            tcp_socket: PhantomData,
        }
    }

    fn supports_core_scheme(&self, scheme: &str) -> Option<bool> {
        match scheme {
            "tcp" | "udp" | "ring" => Some(true),
            "unix" => Some(self.config.unix),
            "faketcp" => Some(self.config.faketcp),
            _ => None,
        }
    }

    fn external(&self, scheme: &str) -> anyhow::Result<&dyn ServerProtocolUpgrader<TcpSocket>> {
        let external = self
            .external
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("unsupported server protocol upgrader: {scheme}"))?;
        if !external.supports_scheme(scheme) {
            anyhow::bail!("unsupported server protocol upgrader: {scheme}");
        }
        Ok(external)
    }
}

#[async_trait]
impl<TcpSocket> ServerProtocolUpgrader<TcpSocket> for CoreServerProtocolUpgrader<TcpSocket>
where
    TcpSocket: VirtualTcpSocket,
{
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.supports_core_scheme(scheme).unwrap_or_else(|| {
            self.external
                .as_ref()
                .is_some_and(|external| external.supports_scheme(scheme))
        })
    }

    fn max_pending_tcp_upgrades(&self, scheme: &str) -> Option<NonZeroUsize> {
        self.external
            .as_ref()
            .filter(|external| external.supports_scheme(scheme))
            .and_then(|external| external.max_pending_tcp_upgrades(scheme))
    }

    async fn upgrade_tcp(
        &self,
        socket: TcpSocket,
        local_url: Url,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            "tcp" | "faketcp" => Ok(ServerProtocolUpgrade::Tunnel(
                upgrade_accepted_tcp(socket, local_url, self.config).await?,
            )),
            "udp" | "wg" | "quic" => {
                anyhow::bail!("{} protocol requires a UDP session", local_url.scheme())
            }
            "ring" | "unix" => {
                anyhow::bail!("{} protocol requires a byte stream", local_url.scheme())
            }
            scheme => self.external(scheme)?.upgrade_tcp(socket, local_url).await,
        }
    }

    async fn upgrade_udp(
        &self,
        session: UdpSession,
        local_url: Url,
        admission: Option<ServerProtocolAdmission>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            "udp" => Ok(ServerProtocolUpgrade::Tunnel(upgrade_accepted_udp(
                session, &local_url,
            )?)),
            "tcp" | "faketcp" => {
                anyhow::bail!("{} protocol requires a TCP transport", local_url.scheme())
            }
            "ring" | "unix" => {
                anyhow::bail!("{} protocol requires a byte stream", local_url.scheme())
            }
            scheme => {
                self.external(scheme)?
                    .upgrade_udp(session, local_url, admission)
                    .await
            }
        }
    }

    async fn upgrade_byte_stream(
        &self,
        socket: TcpSocket,
        local_url: Url,
        remote_url: Option<Url>,
    ) -> anyhow::Result<ServerProtocolUpgrade> {
        match local_url.scheme() {
            "ring" => Ok(ServerProtocolUpgrade::Tunnel(
                raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
            )),
            "unix" if self.config.unix => Ok(ServerProtocolUpgrade::Tunnel(
                raw::upgrade_accepted_byte_stream(socket, local_url, remote_url)?,
            )),
            "tcp" | "faketcp" => {
                anyhow::bail!("{} protocol requires a TCP transport", local_url.scheme())
            }
            "udp" | "wg" | "quic" => {
                anyhow::bail!("{} protocol requires a UDP session", local_url.scheme())
            }
            "unix" => anyhow::bail!("unsupported server protocol upgrader: unix"),
            scheme => {
                self.external(scheme)?
                    .upgrade_byte_stream(socket, local_url, remote_url)
                    .await
            }
        }
    }
}

pub async fn upgrade_accepted_tcp<TcpSocket>(
    socket: TcpSocket,
    local_url: Url,
    config: CoreServerProtocolConfig,
) -> anyhow::Result<Box<dyn Tunnel>>
where
    TcpSocket: VirtualTcpSocket,
{
    match local_url.scheme() {
        "tcp" => Ok(raw::upgrade_accepted_tcp_with_local_url(socket, local_url)?),
        "faketcp" if config.faketcp => {
            Ok(raw::upgrade_accepted_tcp_with_local_url(socket, local_url)?)
        }
        scheme => anyhow::bail!("unsupported TCP listener protocol: {scheme}"),
    }
}

pub fn upgrade_accepted_udp(
    session: UdpSession,
    local_url: &Url,
) -> anyhow::Result<Box<dyn Tunnel>> {
    match local_url.scheme() {
        "udp" => Ok(raw::upgrade_accepted_udp_with_local_url(
            session,
            local_url.clone(),
        )?),
        scheme => anyhow::bail!("unsupported UDP listener protocol: {scheme}"),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;
    use crate::socket::udp::{UdpSessionKind, VirtualUdpSocket};

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

    struct MockUdpSocket {
        local_addr: SocketAddr,
    }

    #[async_trait]
    impl VirtualUdpSocket for MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
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

    #[async_trait]
    impl ServerProtocolUpgrader<MockTcpSocket> for MockExternalUpgrader {
        fn supports_scheme(&self, scheme: &str) -> bool {
            matches!(scheme, "external" | "ring" | "unix")
        }

        async fn upgrade_tcp(
            &self,
            _socket: MockTcpSocket,
            _local_url: Url,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("external server protocol invoked")
        }

        async fn upgrade_udp(
            &self,
            _session: UdpSession,
            _local_url: Url,
            _admission: Option<ServerProtocolAdmission>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("external server UDP protocol invoked")
        }

        async fn upgrade_byte_stream(
            &self,
            _socket: MockTcpSocket,
            _local_url: Url,
            _remote_url: Option<Url>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("external server byte-stream protocol invoked")
        }
    }

    #[tokio::test]
    async fn default_core_upgrader_rejects_external_and_mismatched_protocols() {
        let upgrader =
            CoreClientProtocolUpgrader::<MockTcpSocket>::new(CoreClientProtocolConfig::default());

        assert!(upgrader.supports_scheme("ring"));
        assert!(!upgrader.supports_scheme("unix"));

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

        let mismatched_udp = upgrader
            .upgrade_client(
                ConnectedTransport::Tcp(MockTcpSocket),
                "udp://127.0.0.1:2000".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            mismatched_udp.to_string(),
            "UDP protocol requires a UDP session"
        );

        let mismatched_tcp = upgrader
            .upgrade_client(
                ConnectedTransport::ByteStream(super::super::transport::ConnectedByteStream::new(
                    MockTcpSocket,
                    None,
                    "ring://remote".parse().unwrap(),
                    None,
                )),
                "tcp://127.0.0.1:2000".parse().unwrap(),
            )
            .await
            .unwrap_err();
        assert_eq!(
            mismatched_tcp.to_string(),
            "TCP protocol requires a TCP transport"
        );
    }

    #[tokio::test]
    async fn core_server_dispatches_raw_tcp_and_enforces_host_capabilities() {
        let tunnel = upgrade_accepted_tcp(
            MockTcpSocket,
            "tcp://0.0.0.0:2000".parse().unwrap(),
            CoreServerProtocolConfig::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            tunnel.info().unwrap().local_addr.unwrap().url,
            "tcp://0.0.0.0:2000"
        );

        let disabled = upgrade_accepted_tcp(
            MockTcpSocket,
            "ws://0.0.0.0:2000".parse().unwrap(),
            CoreServerProtocolConfig::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(
            disabled.to_string(),
            "unsupported TCP listener protocol: ws"
        );
    }

    #[tokio::test]
    async fn core_server_raw_udp_preserves_explicit_listener_url() {
        let local_url: Url = "udp://listener.example:1000/path?bind_device=eth0"
            .parse()
            .unwrap();
        let session = UdpSession::identity_standalone(
            Arc::new(MockUdpSocket {
                local_addr: "127.0.0.1:1000".parse().unwrap(),
            }),
            "127.0.0.1:2000".parse().unwrap(),
            UdpSessionKind::EasyTierMux,
        )
        .unwrap();

        let tunnel = upgrade_accepted_udp(session, &local_url).unwrap();

        assert_eq!(
            tunnel.info().unwrap().local_addr.unwrap().url,
            local_url.as_str()
        );
    }

    #[tokio::test]
    async fn core_server_upgrader_owns_builtin_dispatch_and_delegates_external_protocols() {
        let upgrader = CoreServerProtocolUpgrader::with_external(
            CoreServerProtocolConfig::default(),
            Arc::new(MockExternalUpgrader),
        );

        assert!(upgrader.supports_scheme("tcp"));
        assert!(upgrader.supports_scheme("udp"));
        assert!(!upgrader.supports_scheme("ws"));
        assert!(!upgrader.supports_scheme("quic"));
        assert!(upgrader.supports_scheme("ring"));
        assert!(!upgrader.supports_scheme("unix"));
        assert!(upgrader.supports_scheme("external"));

        let external = upgrader
            .upgrade_tcp(MockTcpSocket, "external://0.0.0.0:2000".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(external.to_string(), "external server protocol invoked");

        let mismatched = upgrader
            .upgrade_tcp(MockTcpSocket, "quic://0.0.0.0:2000".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(
            mismatched.to_string(),
            "quic protocol requires a UDP session"
        );

        let wrong_ring_transport = upgrader
            .upgrade_tcp(MockTcpSocket, "ring://local".parse().unwrap())
            .await
            .err()
            .unwrap();
        assert_eq!(
            wrong_ring_transport.to_string(),
            "ring protocol requires a byte stream"
        );

        let disabled_unix = upgrader
            .upgrade_byte_stream(
                MockTcpSocket,
                "unix:///tmp/easytier.sock".parse().unwrap(),
                None,
            )
            .await
            .err()
            .unwrap();
        assert_eq!(
            disabled_unix.to_string(),
            "unsupported server protocol upgrader: unix"
        );
    }

    #[test]
    fn server_protocol_admission_is_scoped_to_its_controller() {
        let controller = ServerProtocolAdmissionController::new(1, 2);
        let admission = controller.try_admit().unwrap();
        assert!(controller.try_admit().is_none());

        let (active_session, handshake_slots) = admission.into_parts();
        assert_eq!(handshake_slots.available_permits(), 2);
        drop(active_session);
        assert!(controller.try_admit().is_some());

        let other = ServerProtocolAdmissionController::new(1, 1);
        assert!(other.try_admit().is_some());
    }
}

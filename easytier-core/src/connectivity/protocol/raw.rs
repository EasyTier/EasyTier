use std::{fmt, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use rand::seq::SliceRandom as _;
use url::Url;

use crate::{
    connectivity::{
        manual::resolve_url_addrs,
        transport::{self, ConnectedByteStream, ConnectedUdpSession, UdpSessionMode},
    },
    host::dns::DnsResolver,
    proto::common::TunnelInfo,
    socket::{
        IpVersion, ListenerConnectionCounter, SocketListener,
        tcp::{
            TcpBindOptions, TcpListenOptions, TcpSocketListener, TcpSocketPurpose,
            VirtualTcpListenerFactory, VirtualTcpSocket, VirtualTcpSocketFactory,
        },
        udp::{
            UdpBindOptions, UdpSession, UdpSessionAcceptKind, UdpSessionListenRequest,
            UdpSessionSocket, UdpSessionSocketListener, VirtualUdpSocketFactory,
        },
    },
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader, udp::UdpTunnelUpgrader},
};

use super::protocol_default_port;

const BYTE_STREAM_MAX_PACKET_SIZE: usize = 4096;
const TCP_DEFAULT_PORT: u16 = protocol_default_port("tcp").expect("tcp must have a default port");
const UDP_DEFAULT_PORT: u16 = protocol_default_port("udp").expect("udp must have a default port");

#[async_trait]
#[auto_impl::auto_impl(Box, Arc)]
pub trait TunnelDialer: Send + Sync + 'static {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>>;

    fn remote_url(&self) -> Url;
}

/// Core-owned raw TCP Tunnel connector over an injected socket factory.
pub struct TcpTunnelDialer<F>
where
    F: VirtualTcpSocketFactory,
{
    remote_url: Url,
    factory: Arc<F>,
    dns: Arc<dyn DnsResolver>,
    ip_version: IpVersion,
    bind: TcpBindOptions,
}

impl<F> TcpTunnelDialer<F>
where
    F: VirtualTcpSocketFactory,
{
    pub fn new(remote_url: Url, factory: Arc<F>, dns: Arc<dyn DnsResolver>) -> Self {
        Self {
            remote_url,
            factory,
            dns,
            ip_version: IpVersion::Both,
            bind: TcpBindOptions::default(),
        }
    }

    pub fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.ip_version = ip_version;
        self
    }

    pub fn with_bind(mut self, bind: TcpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[async_trait]
impl<F> TunnelDialer for TcpTunnelDialer<F>
where
    F: VirtualTcpSocketFactory,
{
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        if self.remote_url.scheme() != "tcp" {
            anyhow::bail!("raw TCP dialer requires tcp URL: {}", self.remote_url);
        }
        let remote_addr = resolve_url_addrs(
            &self.remote_url,
            TCP_DEFAULT_PORT,
            self.bind.context.clone().with_ip_version(self.ip_version),
            self.dns.as_ref(),
        )
        .await?
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or(TunnelError::NoDnsRecordFound(self.ip_version))?;
        let socket = transport::connect_tcp(
            self.factory.clone(),
            remote_addr,
            Vec::new(),
            self.bind.clone(),
            TcpSocketPurpose::ManualConnect,
        )
        .await?;
        Ok(upgrade_connected_tcp(socket, self.remote_url.clone())?)
    }

    fn remote_url(&self) -> Url {
        self.remote_url.clone()
    }
}

/// Core-owned raw TCP Tunnel listener over an injected listener factory.
pub struct TcpTunnelListener<F>
where
    F: VirtualTcpListenerFactory,
{
    inner: TcpSocketListener<F>,
}

impl<F> TcpTunnelListener<F>
where
    F: VirtualTcpListenerFactory,
{
    pub fn new(local_addr: SocketAddr, factory: Arc<F>) -> Self {
        let bind = TcpBindOptions::default()
            .with_local_addr(Some(local_addr))
            .with_only_v6(true);
        Self::new_with_bind(local_addr, bind, factory)
    }

    pub fn new_with_bind(local_addr: SocketAddr, bind: TcpBindOptions, factory: Arc<F>) -> Self {
        Self {
            inner: TcpSocketListener::new_with_options(
                socket_url("tcp", local_addr),
                TcpListenOptions::manual_connect(local_addr).with_bind(bind),
                factory,
            ),
        }
    }
}

impl<F> fmt::Debug for TcpTunnelListener<F>
where
    F: VirtualTcpListenerFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TcpTunnelListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<F> SocketListener for TcpTunnelListener<F>
where
    F: VirtualTcpListenerFactory,
{
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = self.inner.local_url();
        let socket = self.inner.accept().await?;
        Ok(upgrade_accepted_tcp_with_local_url(socket, local_url)?)
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }
}

/// Core-owned raw UDP Tunnel connector over an injected socket factory.
pub struct UdpTunnelDialer<H>
where
    H: VirtualUdpSocketFactory,
{
    remote_url: Url,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    ip_version: IpVersion,
    bind_addrs: Vec<SocketAddr>,
    bind: UdpBindOptions,
}

impl<H> UdpTunnelDialer<H>
where
    H: VirtualUdpSocketFactory,
{
    pub fn new(remote_url: Url, host: Arc<H>, dns: Arc<dyn DnsResolver>) -> Self {
        Self {
            remote_url,
            host,
            dns,
            ip_version: IpVersion::Both,
            bind_addrs: Vec::new(),
            bind: UdpBindOptions::direct_connect(),
        }
    }

    pub fn with_ip_version(mut self, ip_version: IpVersion) -> Self {
        self.ip_version = ip_version;
        self
    }

    pub fn with_bind_addrs(mut self, bind_addrs: Vec<SocketAddr>) -> Self {
        self.bind_addrs = bind_addrs;
        self
    }

    pub fn with_bind(mut self, bind: UdpBindOptions) -> Self {
        self.bind = bind;
        self
    }
}

#[async_trait]
impl<H> TunnelDialer for UdpTunnelDialer<H>
where
    H: VirtualUdpSocketFactory,
{
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        if self.remote_url.scheme() != "udp" {
            anyhow::bail!("raw UDP dialer requires udp URL: {}", self.remote_url);
        }
        let remote_addr = resolve_url_addrs(
            &self.remote_url,
            UDP_DEFAULT_PORT,
            self.bind.context.clone().with_ip_version(self.ip_version),
            self.dns.as_ref(),
        )
        .await?
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or(TunnelError::NoDnsRecordFound(self.ip_version))?;
        let bind_addrs = udp_bind_addrs_for_remote(remote_addr, &self.bind_addrs);
        let connected = transport::connect_udp(
            self.host.clone(),
            remote_addr,
            bind_addrs,
            self.bind.clone(),
            UdpSessionMode::EasyTierMux,
        )
        .await?;
        Ok(upgrade_connected_udp(connected, self.remote_url.clone())?)
    }

    fn remote_url(&self) -> Url {
        self.remote_url.clone()
    }
}

/// Core-owned raw UDP Tunnel listener over an injected socket factory.
pub struct UdpTunnelListener<H>
where
    H: VirtualUdpSocketFactory,
{
    inner: UdpSessionSocketListener<H>,
}

impl<H> UdpTunnelListener<H>
where
    H: VirtualUdpSocketFactory,
{
    pub fn new(local_url: Url, local_addr: SocketAddr, host: Arc<H>) -> Self {
        Self {
            inner: UdpSessionSocketListener::new(local_url, local_addr, host),
        }
    }

    pub fn new_with_request(
        local_url: Url,
        request: UdpSessionListenRequest,
        host: Arc<H>,
    ) -> Self {
        Self {
            inner: UdpSessionSocketListener::new_with_request(
                local_url,
                request,
                UdpSessionAcceptKind::EasyTierMux,
                host,
            ),
        }
    }
}

impl<H> fmt::Debug for UdpTunnelListener<H>
where
    H: VirtualUdpSocketFactory,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UdpTunnelListener")
            .field("inner", &self.inner)
            .finish()
    }
}

#[async_trait]
impl<H> SocketListener for UdpTunnelListener<H>
where
    H: VirtualUdpSocketFactory,
{
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        let local_url = self.inner.local_url();
        if local_url.scheme() != "udp" {
            anyhow::bail!("raw UDP listener requires udp URL: {local_url}");
        }
        self.inner.listen().await
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let local_url = self.inner.local_url();
        Ok(upgrade_accepted_udp_with_local_url(
            self.inner.accept().await?,
            local_url,
        )?)
    }

    fn local_url(&self) -> Url {
        self.inner.local_url()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        self.inner.connection_counter()
    }
}

pub(crate) fn upgrade_connected_byte_stream<S>(
    connected: ConnectedByteStream<S>,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let (socket, local_url, remote_url, resolved_remote_url) = connected.into_parts();
    let info = TunnelInfo {
        tunnel_type: remote_url.scheme().to_owned(),
        local_addr: local_url.map(Into::into),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(resolved_remote_url.unwrap_or(remote_url).into()),
    };
    TcpTunnelUpgrader::new(info)
        .with_max_packet_size(BYTE_STREAM_MAX_PACKET_SIZE)
        .upgrade(socket)
}

pub(crate) fn upgrade_connected_tcp<S>(
    socket: S,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let resolved_remote_addr = socket.peer_addr()?;
    let scheme = requested_remote_addr.scheme().to_owned();
    let tunnel_type = tcp_tunnel_type(&socket, &scheme)?;
    let info = connected_tunnel_info(
        &scheme,
        &tunnel_type,
        local_addr,
        resolved_remote_addr,
        requested_remote_addr,
    );
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub(crate) fn upgrade_connected_udp(
    connected: ConnectedUdpSession,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let (session, layer) = connected.into_parts();
    let info = connected_tunnel_info(
        "udp",
        "udp",
        session.local_addr()?,
        session.peer_addr()?,
        requested_remote_addr,
    );
    UdpTunnelUpgrader::with_keep_alive(info, layer).upgrade(session)
}

pub(crate) fn upgrade_accepted_tcp_with_local_url<S>(
    socket: S,
    local_url: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let remote_addr = socket.peer_addr()?;
    let scheme = local_url.scheme().to_owned();
    let remote_url = socket_url(&scheme, remote_addr);
    let info = TunnelInfo {
        tunnel_type: tcp_tunnel_type(&socket, &scheme)?,
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub(crate) fn upgrade_accepted_byte_stream<S>(
    socket: S,
    local_url: Url,
    remote_url: Option<Url>,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let info = TunnelInfo {
        tunnel_type: local_url.scheme().to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: remote_url.clone().map(Into::into),
        resolved_remote_addr: remote_url.map(Into::into),
    };
    TcpTunnelUpgrader::new(info)
        .with_max_packet_size(BYTE_STREAM_MAX_PACKET_SIZE)
        .upgrade(socket)
}

pub(crate) fn upgrade_accepted_udp_with_local_url(
    session: UdpSession,
    local_url: Url,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    if local_url.scheme() != "udp" {
        return Err(TunnelError::InvalidProtocol(format!(
            "raw UDP listener requires udp URL: {local_url}"
        )));
    }
    let remote_url = socket_url("udp", session.peer_addr()?);
    let info = TunnelInfo {
        tunnel_type: "udp".to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    UdpTunnelUpgrader::new(info).upgrade(session)
}

fn udp_bind_addrs_for_remote(
    remote_addr: SocketAddr,
    configured: &[SocketAddr],
) -> Vec<SocketAddr> {
    if remote_addr.is_ipv6() {
        Vec::new()
    } else {
        configured.to_vec()
    }
}

fn connected_tunnel_info(
    scheme: &str,
    tunnel_type: &str,
    local_addr: SocketAddr,
    resolved_remote_addr: SocketAddr,
    requested_remote_addr: Url,
) -> TunnelInfo {
    TunnelInfo {
        tunnel_type: tunnel_type.to_owned(),
        local_addr: Some(socket_url(scheme, local_addr).into()),
        remote_addr: Some(requested_remote_addr.into()),
        resolved_remote_addr: Some(socket_url(scheme, resolved_remote_addr).into()),
    }
}

fn tcp_tunnel_type(socket: &impl VirtualTcpSocket, scheme: &str) -> Result<String, TunnelError> {
    match socket.transport_label() {
        Some(label) => Ok(label.to_owned()),
        None if scheme == "faketcp" => Err(TunnelError::InternalError(
            "FakeTCP upgrader received a socket without a FakeTCP transport label".to_owned(),
        )),
        None => Ok(scheme.to_owned()),
    }
}

fn socket_url(scheme: &str, addr: SocketAddr) -> Url {
    let mut url =
        Url::parse(&format!("{scheme}://0.0.0.0")).expect("static transport URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("transport URL should accept a port");
    url
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use futures::{SinkExt, StreamExt};
    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use crate::{
        packet::ZCPacket,
        socket::udp::{UdpSessionKind, VirtualUdpSocket},
    };

    use super::*;

    pub(crate) fn upgrade_accepted_tcp<S>(socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
    where
        S: VirtualTcpSocket,
    {
        let local_addr = socket.local_addr()?;
        upgrade_accepted_tcp_with_local_url(socket, socket_url("tcp", local_addr))
    }

    pub(crate) fn upgrade_accepted_udp(
        session: UdpSession,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let local_url = socket_url("udp", session.local_addr()?);
        upgrade_accepted_udp_with_local_url(session, local_url)
    }

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        transport_label: Option<&'static str>,
    }

    impl MockTcpSocket {
        fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
            let (stream, _) = tokio::io::duplex(64);
            Self::from_stream(stream, local_addr, peer_addr)
        }

        fn from_stream(
            stream: DuplexStream,
            local_addr: SocketAddr,
            peer_addr: SocketAddr,
        ) -> Self {
            Self {
                stream,
                local_addr,
                peer_addr,
                transport_label: None,
            }
        }

        fn with_transport_label(mut self, transport_label: &'static str) -> Self {
            self.transport_label = Some(transport_label);
            self
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

        fn transport_label(&self) -> Option<&str> {
            self.transport_label
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

    #[test]
    fn raw_upgrader_preserves_requested_and_resolved_addresses() {
        let local_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let requested_url: Url = "tcp://example.com:2000".parse().unwrap();

        let connected = upgrade_connected_tcp(
            MockTcpSocket::new(local_addr, peer_addr),
            requested_url.clone(),
        )
        .unwrap();
        let connected_info = connected.info().unwrap();
        assert_eq!(
            connected_info.remote_addr.unwrap().url,
            requested_url.as_str()
        );
        let resolved: Url = connected_info.resolved_remote_addr.unwrap().into();
        assert_eq!(resolved.host_str(), Some("127.0.0.1"));
        assert_eq!(resolved.port(), Some(2000));

        let accepted = upgrade_accepted_tcp(MockTcpSocket::new(local_addr, peer_addr)).unwrap();
        let accepted_info = accepted.info().unwrap();
        assert_eq!(
            accepted_info.remote_addr,
            accepted_info.resolved_remote_addr
        );

        let requested_local_url: Url = "tcp://0.0.0.0:1000".parse().unwrap();
        let accepted = upgrade_accepted_tcp_with_local_url(
            MockTcpSocket::new(local_addr, peer_addr),
            requested_local_url.clone(),
        )
        .unwrap();
        assert_eq!(
            accepted.info().unwrap().local_addr.unwrap().url,
            requested_local_url.as_str()
        );
    }

    #[test]
    fn raw_tcp_upgrader_preserves_host_transport_label() {
        let local_addr: SocketAddr = "192.0.2.1:10000".parse().unwrap();
        let peer_addr: SocketAddr = "192.0.2.2:11013".parse().unwrap();
        let requested_url: Url = "faketcp://peer.example:11013".parse().unwrap();

        let connected = upgrade_connected_tcp(
            MockTcpSocket::new(local_addr, peer_addr).with_transport_label("faketcp_test-driver"),
            requested_url.clone(),
        )
        .unwrap();
        let connected_info = connected.info().unwrap();
        assert_eq!(connected_info.tunnel_type, "faketcp_test-driver");
        assert_eq!(
            connected_info.resolved_remote_addr.unwrap().url,
            "faketcp://192.0.2.2:11013"
        );

        let accepted = upgrade_accepted_tcp_with_local_url(
            MockTcpSocket::new(local_addr, peer_addr).with_transport_label("faketcp_test-driver"),
            "faketcp://0.0.0.0:11013".parse().unwrap(),
        )
        .unwrap();
        let accepted_info = accepted.info().unwrap();
        assert_eq!(accepted_info.tunnel_type, "faketcp_test-driver");
        assert_eq!(
            accepted_info.remote_addr,
            accepted_info.resolved_remote_addr
        );
    }

    #[test]
    fn faketcp_upgrader_rejects_socket_without_host_transport_label() {
        let local_addr: SocketAddr = "192.0.2.1:10000".parse().unwrap();
        let peer_addr: SocketAddr = "192.0.2.2:11013".parse().unwrap();

        let connected_error = upgrade_connected_tcp(
            MockTcpSocket::new(local_addr, peer_addr),
            "faketcp://peer.example:11013".parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(connected_error, TunnelError::InternalError(_)));

        let accepted_error = upgrade_accepted_tcp_with_local_url(
            MockTcpSocket::new(local_addr, peer_addr),
            "faketcp://0.0.0.0:11013".parse().unwrap(),
        )
        .unwrap_err();
        assert!(matches!(accepted_error, TunnelError::InternalError(_)));
    }

    #[test]
    fn raw_udp_uses_default_bind_for_ipv6_remote() {
        let configured = vec!["192.0.2.1:0".parse().unwrap()];

        assert_eq!(
            udp_bind_addrs_for_remote("198.51.100.1:11010".parse().unwrap(), &configured),
            configured
        );
        assert!(
            udp_bind_addrs_for_remote("[2001:db8::1]:11010".parse().unwrap(), &configured)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn accepted_udp_uses_explicit_listener_url() {
        let local_addr = "127.0.0.1:1000".parse().unwrap();
        let peer_addr = "127.0.0.1:2000".parse().unwrap();
        let local_url: Url = "udp://listener.example:1000?bind_device=eth0"
            .parse()
            .unwrap();
        let session = UdpSession::identity_standalone(
            Arc::new(MockUdpSocket { local_addr }),
            peer_addr,
            UdpSessionKind::EasyTierMux,
        )
        .unwrap();

        let tunnel = upgrade_accepted_udp_with_local_url(session, local_url.clone()).unwrap();
        let info = tunnel.info().unwrap();

        assert_eq!(info.local_addr.unwrap().url, local_url.as_str());
        assert_eq!(info.remote_addr, info.resolved_remote_addr);
    }

    #[tokio::test]
    async fn accepted_udp_rejects_non_udp_listener_url() {
        let local_addr = "127.0.0.1:1000".parse().unwrap();
        let session = UdpSession::identity_standalone(
            Arc::new(MockUdpSocket { local_addr }),
            "127.0.0.1:2000".parse().unwrap(),
            UdpSessionKind::EasyTierMux,
        )
        .unwrap();

        let error =
            upgrade_accepted_udp_with_local_url(session, "quic://127.0.0.1:1000".parse().unwrap())
                .unwrap_err();

        assert!(matches!(error, TunnelError::InvalidProtocol(_)));
    }

    #[test]
    fn byte_stream_upgrader_uses_host_endpoint_metadata() {
        let local_url: Url = "ring://local".parse().unwrap();
        let remote_url: Url = "ring://remote".parse().unwrap();
        let tunnel = upgrade_connected_byte_stream(ConnectedByteStream::new(
            MockTcpSocket::new(
                "127.0.0.1:1000".parse().unwrap(),
                "127.0.0.1:2000".parse().unwrap(),
            ),
            Some(local_url.clone()),
            remote_url.clone(),
            None,
        ))
        .unwrap();
        let info = tunnel.info().unwrap();

        assert_eq!(info.tunnel_type, "ring");
        assert_eq!(info.local_addr.unwrap().url, local_url.as_str());
        assert_eq!(info.remote_addr.unwrap().url, remote_url.as_str());
        assert_eq!(info.resolved_remote_addr.unwrap().url, remote_url.as_str());
    }

    #[test]
    fn accepted_byte_stream_uses_explicit_endpoint_metadata() {
        let local_url: Url = "ring://local".parse().unwrap();
        let remote_url: Url = "ring://remote".parse().unwrap();
        let tunnel = upgrade_accepted_byte_stream(
            MockTcpSocket::new(
                "127.0.0.1:1000".parse().unwrap(),
                "127.0.0.1:2000".parse().unwrap(),
            ),
            local_url.clone(),
            Some(remote_url.clone()),
        )
        .unwrap();
        let info = tunnel.info().unwrap();

        assert_eq!(info.tunnel_type, "ring");
        assert_eq!(info.local_addr.unwrap().url, local_url.as_str());
        assert_eq!(info.remote_addr.unwrap().url, remote_url.as_str());
        assert_eq!(info.resolved_remote_addr.unwrap().url, remote_url.as_str());
    }

    #[test]
    fn accepted_byte_stream_allows_unnamed_remote_endpoint() {
        let tunnel = upgrade_accepted_byte_stream(
            MockTcpSocket::new(
                "127.0.0.1:1000".parse().unwrap(),
                "127.0.0.1:2000".parse().unwrap(),
            ),
            "unix:///tmp/easytier.sock".parse().unwrap(),
            None,
        )
        .unwrap();
        let info = tunnel.info().unwrap();

        assert_eq!(info.tunnel_type, "unix");
        assert!(info.remote_addr.is_none());
        assert!(info.resolved_remote_addr.is_none());
    }

    #[tokio::test]
    async fn byte_stream_upgrader_preserves_legacy_unix_packet_limit() {
        let (client_stream, server_stream) = tokio::io::duplex(8192);
        let client = upgrade_connected_byte_stream(ConnectedByteStream::new(
            MockTcpSocket::from_stream(
                client_stream,
                "127.0.0.1:1000".parse().unwrap(),
                "127.0.0.1:2000".parse().unwrap(),
            ),
            None,
            "unix:///tmp/easytier.sock".parse().unwrap(),
            None,
        ))
        .unwrap();
        let server = upgrade_accepted_byte_stream(
            MockTcpSocket::from_stream(
                server_stream,
                "127.0.0.1:2000".parse().unwrap(),
                "127.0.0.1:1000".parse().unwrap(),
            ),
            "unix:///tmp/easytier.sock".parse().unwrap(),
            Some("unix://anonymous/peer".parse().unwrap()),
        )
        .unwrap();

        let (mut client_stream, mut client_sink) = client.split();
        let (mut server_stream, mut server_sink) = server.split();
        let payload = vec![0x5a; 3000];
        client_sink
            .send(ZCPacket::new_with_payload(&payload))
            .await
            .unwrap();

        let packet = server_stream.next().await.unwrap().unwrap();
        assert_eq!(packet.payload(), payload);

        let response_payload = vec![0xa5; 3000];
        server_sink
            .send(ZCPacket::new_with_payload(&response_payload))
            .await
            .unwrap();

        let packet = client_stream.next().await.unwrap().unwrap();
        assert_eq!(packet.payload(), response_payload);
    }
}

use std::{io, net::SocketAddr, pin::Pin, sync::Arc, task::Context, task::Poll, time::Duration};

use crate::proto::common::TunnelInfo;
use easytier_core::{
    socket::tcp::VirtualTcpSocket,
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader},
};
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub(crate) const SERVER_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn init_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn get_insecure_tls_client_config() -> rustls::ClientConfig {
    init_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider.clone()))
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config
}

fn get_insecure_tls_cert<'a>() -> (
    Vec<rustls::pki_types::CertificateDer<'a>>,
    rustls::pki_types::PrivateKeyDer<'a>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.cert.der().clone();
    let private_key = cert.signing_key.serialize_der();
    let private_key = rustls::pki_types::PrivatePkcs8KeyDer::from(private_key);
    (vec![cert_der], private_key.into())
}

pin_project! {
    struct TlsTcpSocket<S> {
        #[pin]
        inner: S,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }
}

impl<S> TlsTcpSocket<S> {
    fn new(inner: S, local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
        Self {
            inner,
            local_addr,
            peer_addr,
        }
    }
}

impl<S> AsyncRead for TlsTcpSocket<S>
where
    S: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl<S> AsyncWrite for TlsTcpSocket<S>
where
    S: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl<S> VirtualTcpSocket for TlsTcpSocket<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer_addr)
    }
}

fn is_tls(url: &url::Url) -> Result<bool, TunnelError> {
    match url.scheme() {
        "tls" => Ok(true),
        scheme => Err(TunnelError::InvalidProtocol(scheme.to_owned())),
    }
}

fn socket_url(scheme: &str, addr: SocketAddr) -> url::Url {
    let mut url =
        url::Url::parse(&format!("{scheme}://0.0.0.0")).expect("TLS transport scheme should be valid");
    url.set_ip_host(addr.ip()).unwrap();
    url.set_port(Some(addr.port())).unwrap();
    url
}

pub(crate) async fn upgrade_connected_tls<S>(
    stream: S,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    if !is_tls(&remote_url)? {
        return Err(TunnelError::InvalidProtocol(remote_url.scheme().to_owned()));
    }

    init_crypto_provider();
    let local_addr = stream.local_addr()?;
    let resolved_remote_addr = stream.peer_addr()?;
    let scheme = remote_url.scheme().to_owned();

    let tls = tokio_rustls::TlsConnector::from(Arc::new(get_insecure_tls_client_config()));
    let sni = remote_url.domain().unwrap_or("localhost").to_owned();
    let server_name = rustls::pki_types::ServerName::try_from(sni)
        .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
    let stream = tls.connect(server_name, stream).await?;

    let socket = TlsTcpSocket::new(stream, local_addr, resolved_remote_addr);
    let info = TunnelInfo {
        tunnel_type: scheme.clone(),
        local_addr: Some(socket_url(&scheme, local_addr).into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(socket_url(&scheme, resolved_remote_addr).into()),
    };
    Ok(TcpTunnelUpgrader::new(info).upgrade(socket)?)
}

pub(crate) async fn upgrade_accepted_tls<S>(
    stream: S,
    local_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    if !is_tls(&local_url)? {
        return Err(TunnelError::InvalidProtocol(local_url.scheme().to_owned()));
    }

    init_crypto_provider();
    let local_addr = stream.local_addr()?;
    let peer_addr = stream.peer_addr()?;
    let scheme = local_url.scheme().to_owned();

    let (certificates, private_key) = get_insecure_tls_cert();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, private_key)
        .map_err(|error| TunnelError::ProtocolError(format!("TLS server config error: {error}")))?;
    let stream = tokio_rustls::TlsAcceptor::from(Arc::new(config))
        .accept(stream)
        .await?;

    let socket = TlsTcpSocket::new(stream, local_addr, peer_addr);
    let remote_url = socket_url(&scheme, peer_addr);
    let info = TunnelInfo {
        tunnel_type: scheme.clone(),
        local_addr: Some(local_url.clone().into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    Ok(TcpTunnelUpgrader::new(info).upgrade(socket)?)
}
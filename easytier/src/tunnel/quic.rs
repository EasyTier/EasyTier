//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use std::{error::Error, net::SocketAddr, sync::Arc};

use crate::{
    rpc::TunnelInfo,
    tunnel::common::{setup_sokcet2, FramedReader, FramedWriter, TunnelWrapper},
};
use anyhow::Context;
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
use tokio::io::AsyncWriteExt;

use super::{
    check_scheme_and_get_socket_addr, Tunnel, TunnelConnector, TunnelError, TunnelListener,
};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, Vec<u8>), Box<dyn Error>> {
    let (server_config, server_cert) = configure_server()?;
    let endpoint = Endpoint::server(server_config, bind_addr)?;
    Ok((endpoint, server_cert))
}

/// Returns default server configuration along with its certificate.
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn Error>> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(10_u8.into());
    transport_config.max_concurrent_bidi_streams(10_u8.into());

    Ok((server_config, cert_der))
}

#[allow(unused)]
pub const ALPN_QUIC_HTTP: &[&[u8]] = &[b"hq-29"];

/// Runs a QUIC server bound to given address.

struct ConnWrapper {
    conn: Connection,
}

impl Drop for ConnWrapper {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

pub struct QUICTunnelListener {
    addr: url::Url,
    endpoint: Option<Endpoint>,
    server_cert: Option<Vec<u8>>,
}

impl QUICTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        QUICTunnelListener {
            addr,
            endpoint: None,
            server_cert: None,
        }
    }
}

#[async_trait::async_trait]
impl TunnelListener for QUICTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic")?;
        let (endpoint, server_cert) = make_server_endpoint(addr).unwrap();
        self.endpoint = Some(endpoint);
        self.server_cert = Some(server_cert);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        // accept a single connection
        let incoming_conn = self.endpoint.as_ref().unwrap().accept().await.unwrap();
        let conn = incoming_conn.await.unwrap();
        println!(
            "[server] connection accepted: addr={}",
            conn.remote_address()
        );
        let remote_addr = conn.remote_address();
        let (w, r) = conn.accept_bi().await.with_context(|| "accept_bi failed")?;

        let arc_conn = Arc::new(ConnWrapper { conn });

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: self.local_url().into(),
            remote_addr: super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
        };

        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 4500, Box::new(arc_conn.clone())),
            FramedWriter::new_with_associate_data(w, Box::new(arc_conn)),
            Some(info),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct QUICTunnelConnector {
    addr: url::Url,
    endpoint: Option<Endpoint>,
}

impl QUICTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        QUICTunnelConnector {
            addr,
            endpoint: None,
        }
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QUICTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic")?;

        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap())?;
        endpoint.set_default_client_config(configure_client());

        // connect to server
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        println!("[client] connected: addr={}", connection.remote_address());

        let local_addr = endpoint.local_addr().unwrap();

        self.endpoint = Some(endpoint);

        let (w, r) = connection
            .open_bi()
            .await
            .with_context(|| "open_bi failed")?;

        let info = TunnelInfo {
            tunnel_type: "quic".to_owned(),
            local_addr: super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into(),
            remote_addr: self.addr.to_string(),
        };

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            FramedReader::new(r, 4500),
            FramedWriter::new(w),
            Some(info),
            Box::new(connection),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong, enable_log};

    use super::*;

    #[tokio::test]
    async fn quic_pingpong() {
        enable_log();
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21011".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn quic_bench() {
        enable_log();
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21012".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }
}

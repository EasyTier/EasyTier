//! This example demonstrates how to make a QUIC connection that ignores the server certificate.
//!
//! Checkout the `README.md` for guidance.

use std::{error::Error, net::SocketAddr, sync::Arc};

use crate::tunnel::{
    check_scheme_and_get_socket_addr_ext,
    common::{FramedReader, FramedWriter, TunnelWrapper},
    TunnelInfo,
};
use anyhow::Context;
use quinn::{crypto::rustls::QuicClientConfig, ClientConfig, Connection, Endpoint, ServerConfig};

use super::{
    check_scheme_and_get_socket_addr,
    insecure_tls::{get_insecure_tls_cert, get_insecure_tls_client_config},
    IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelListener,
};

fn configure_client() -> ClientConfig {
    ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(get_insecure_tls_client_config()).unwrap(),
    ))
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
    let (certs, key) = get_insecure_tls_cert();

    let mut server_config = ServerConfig::with_single_cert(certs.clone(), key.into())?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(10_u8.into());
    transport_config.max_concurrent_bidi_streams(10_u8.into());

    Ok((server_config, certs[0].to_vec()))
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
        let addr =
            check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "quic", IpVersion::Both)?;
        let (endpoint, server_cert) = make_server_endpoint(addr).unwrap();
        self.endpoint = Some(endpoint);
        self.server_cert = Some(server_cert);

        self.addr
            .set_port(Some(self.endpoint.as_ref().unwrap().local_addr()?.port()))
            .unwrap();

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
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(&remote_addr.to_string(), "quic").into(),
            ),
        };

        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 2000, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
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
    ip_version: IpVersion,
}

impl QUICTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        QUICTunnelConnector {
            addr,
            endpoint: None,
            ip_version: IpVersion::Both,
        }
    }
}

#[async_trait::async_trait]
impl TunnelConnector for QUICTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr = check_scheme_and_get_socket_addr_ext::<SocketAddr>(
            &self.addr,
            "quic",
            self.ip_version,
        )?;
        let local_addr = if addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };

        let mut endpoint = Endpoint::client(local_addr.parse().unwrap())?;
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
            local_addr: Some(
                super::build_url_from_socket_addr(&local_addr.to_string(), "quic").into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
        };

        let arc_conn = Arc::new(ConnWrapper { conn: connection });
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new_with_associate_data(r, 4500, Some(Box::new(arc_conn.clone()))),
            FramedWriter::new_with_associate_data(w, Some(Box::new(arc_conn))),
            Some(info),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{
        common::tests::{_tunnel_bench, _tunnel_pingpong},
        IpVersion,
    };

    use super::*;

    #[tokio::test]
    async fn quic_pingpong() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21011".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:21011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn quic_bench() {
        let listener = QUICTunnelListener::new("quic://0.0.0.0:21012".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://127.0.0.1:21012".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = QUICTunnelListener::new("quic://[::1]:31015".parse().unwrap());
        let connector = QUICTunnelConnector::new("quic://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = QUICTunnelListener::new("quic://[::1]:31016".parse().unwrap());
        let mut connector =
            QUICTunnelConnector::new("quic://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = QUICTunnelListener::new("quic://127.0.0.1:31016".parse().unwrap());
        let mut connector =
            QUICTunnelConnector::new("quic://test.easytier.top:31016".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = QUICTunnelListener::new("quic://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = QUICTunnelListener::new("quic://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}

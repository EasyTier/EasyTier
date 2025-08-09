use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use bytes::BytesMut;
use futures::{stream::FuturesUnordered, SinkExt, StreamExt};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tokio_websockets::{ClientBuilder, Limits, MaybeTlsStream, Message};
use zerocopy::AsBytes;

use super::TunnelInfo;
use crate::tunnel::insecure_tls::get_insecure_tls_client_config;

use super::{
    common::{setup_sokcet2, wait_for_connect_futures, TunnelWrapper},
    insecure_tls::{get_insecure_tls_cert, init_crypto_provider},
    packet_def::{ZCPacket, ZCPacketType},
    FromUrl, IpVersion, Tunnel, TunnelConnector, TunnelError, TunnelListener,
};

fn is_wss(addr: &url::Url) -> Result<bool, TunnelError> {
    match addr.scheme() {
        "ws" => Ok(false),
        "wss" => Ok(true),
        _ => Err(TunnelError::InvalidProtocol(addr.scheme().to_string())),
    }
}

async fn sink_from_zc_packet<E>(msg: ZCPacket) -> Result<Message, E> {
    Ok(Message::binary(msg.tunnel_payload_bytes().freeze()))
}

async fn map_from_ws_message(
    msg: Result<Message, tokio_websockets::Error>,
) -> Option<Result<ZCPacket, TunnelError>> {
    if let Err(e) = msg {
        tracing::error!(?e, "recv from websocket error");
        return Some(Err(TunnelError::WebSocketError(e)));
    }

    let msg = msg.unwrap();
    if msg.is_close() {
        tracing::warn!("recv close message from websocket");
        return None;
    }

    if !msg.is_binary() {
        let msg = format!("{:?}", msg);
        tracing::error!(?msg, "Invalid packet");
        return Some(Err(TunnelError::InvalidPacket(msg)));
    }

    Some(Ok(ZCPacket::new_from_buf(
        BytesMut::from(msg.into_payload().as_bytes()),
        ZCPacketType::DummyTunnel,
    )))
}

#[derive(Debug)]
pub struct WSTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
}

impl WSTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        WSTunnelListener {
            addr,
            listener: None,
        }
    }

    async fn try_accept(&mut self, stream: TcpStream) -> Result<Box<dyn Tunnel>, TunnelError> {
        let info = TunnelInfo {
            tunnel_type: self.addr.scheme().to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(
                    &stream.peer_addr()?.to_string(),
                    self.addr.scheme().to_string().as_str(),
                )
                .into(),
            ),
        };

        let server_bulder = tokio_websockets::ServerBuilder::new().limits(Limits::unlimited());

        let ret: Box<dyn Tunnel> = if is_wss(&self.addr)? {
            init_crypto_provider();
            let (certs, key) = get_insecure_tls_cert();
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .with_context(|| "Failed to create server config")?;
            let acceptor = TlsAcceptor::from(Arc::new(config));

            let stream = acceptor.accept(stream).await?;
            let (write, read) = server_bulder.accept(stream).await?.split();

            Box::new(TunnelWrapper::new(
                read.filter_map(map_from_ws_message),
                write.with(sink_from_zc_packet),
                Some(info),
            ))
        } else {
            let (write, read) = server_bulder.accept(stream).await?.split();
            Box::new(TunnelWrapper::new(
                read.filter_map(map_from_ws_message),
                write.with(sink_from_zc_packet),
                Some(info),
            ))
        };

        Ok(ret)
    }
}

#[async_trait::async_trait]
impl TunnelListener for WSTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        setup_sokcet2(&socket2_socket, &addr)?;
        let socket = TcpSocket::from_std_stream(socket2_socket.into());

        self.addr
            .set_port(Some(socket.local_addr()?.port()))
            .unwrap();

        self.listener = Some(socket.listen(1024)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        loop {
            let listener = self.listener.as_ref().unwrap();
            // only fail on tcp accept error
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true).unwrap();
            match timeout(Duration::from_secs(3), self.try_accept(stream)).await {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                e => {
                    tracing::error!(?e, ?self, "Failed to accept ws/wss tunnel");
                    continue;
                }
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct WSTunnelConnector {
    addr: url::Url,
    ip_version: IpVersion,

    bind_addrs: Vec<SocketAddr>,
}

impl WSTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        WSTunnelConnector {
            addr,
            ip_version: IpVersion::Both,

            bind_addrs: vec![],
        }
    }

    async fn connect_with(
        addr: url::Url,
        ip_version: IpVersion,
        tcp_socket: TcpSocket,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let is_wss = is_wss(&addr)?;
        let socket_addr = SocketAddr::from_url(addr.clone(), ip_version).await?;
        let stream = tcp_socket.connect(socket_addr).await?;

        let info = TunnelInfo {
            tunnel_type: addr.scheme().to_owned(),
            local_addr: Some(
                super::build_url_from_socket_addr(
                    &stream.local_addr()?.to_string(),
                    addr.scheme().to_string().as_str(),
                )
                .into(),
            ),
            remote_addr: Some(addr.clone().into()),
        };

        let c = ClientBuilder::from_uri(http::Uri::try_from(addr.to_string()).unwrap());
        let stream: MaybeTlsStream<TcpStream> = if is_wss {
            init_crypto_provider();
            let tls_conn =
                tokio_rustls::TlsConnector::from(Arc::new(get_insecure_tls_client_config()));
            // Modify SNI logic: use "localhost" as SNI for url without domain to avoid IP blocking.
            let sni = match addr.domain() {
                None => "localhost".to_string(),
                Some(domain) => domain.to_string(),
            };
            let server_name = rustls::pki_types::ServerName::try_from(sni)
                .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_string()))?;
            let stream = tls_conn.connect(server_name, stream).await?;
            MaybeTlsStream::Rustls(stream)
        } else {
            MaybeTlsStream::Plain(stream)
        };

        let (client, _) = c.connect_on(stream).await?;
        let (write, read) = client.split();
        let read = read.filter_map(map_from_ws_message);
        let write = write.with(sink_from_zc_packet);
        Ok(Box::new(TunnelWrapper::new(read, write, Some(info))))
    }

    async fn connect_with_default_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        Self::connect_with(self.addr.clone(), self.ip_version, socket).await
    }

    async fn connect_with_custom_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(bind_addr = ?bind_addr, ?addr, "bind addr");

            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;

            if let Err(e) = setup_sokcet2(&socket2_socket, bind_addr) {
                tracing::error!(bind_addr = ?bind_addr, ?addr, "bind addr fail: {:?}", e);
                continue;
            }

            let socket = TcpSocket::from_std_stream(socket2_socket.into());
            futures.push(Self::connect_with(
                self.addr.clone(),
                self.ip_version,
                socket,
            ))
        }

        wait_for_connect_futures(futures).await
    }
}

#[async_trait::async_trait]
impl TunnelConnector for WSTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr = SocketAddr::from_url(self.addr.clone(), self.ip_version).await?;
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }
}

#[cfg(test)]
pub mod tests {
    use crate::tunnel::common::tests::_tunnel_pingpong;
    use crate::tunnel::websocket::{WSTunnelConnector, WSTunnelListener};
    use crate::tunnel::{TunnelConnector, TunnelListener};

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong(#[values("ws", "wss")] proto: &str) {
        let listener = WSTunnelListener::new(format!("{}://0.0.0.0:25556", proto).parse().unwrap());
        let connector =
            WSTunnelConnector::new(format!("{}://127.0.0.1:25556", proto).parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong_bind(#[values("ws", "wss")] proto: &str) {
        let listener = WSTunnelListener::new(format!("{}://0.0.0.0:25557", proto).parse().unwrap());
        let mut connector =
            WSTunnelConnector::new(format!("{}://127.0.0.1:25557", proto).parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    // TODO: tokio-websockets cannot correctly handle close, benchmark case is disabled
    // #[rstest::rstest]
    // #[tokio::test]
    // #[serial_test::serial]
    // async fn ws_bench(#[values("ws", "wss")] proto: &str) {
    //     enable_log();
    //     let listener = WSTunnelListener::new(format!("{}://0.0.0.0:25557", proto).parse().unwrap());
    //     let connector =
    //         WSTunnelConnector::new(format!("{}://127.0.0.1:25557", proto).parse().unwrap());
    //     _tunnel_bench(listener, connector).await
    // }

    #[tokio::test]
    async fn ws_accept_wss() {
        let mut listener = WSTunnelListener::new("wss://0.0.0.0:25558".parse().unwrap());
        listener.listen().await.unwrap();
        let j = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let mut connector = WSTunnelConnector::new("ws://127.0.0.1:25558".parse().unwrap());
        connector.connect().await.unwrap_err();

        let mut connector = WSTunnelConnector::new("wss://127.0.0.1:25558".parse().unwrap());
        connector.connect().await.unwrap();

        j.abort();
    }
}

use super::{FromUrl, common::wait_for_connect_futures};
use crate::tunnel::common::bind;
use crate::{proto::common::TunnelInfo, socket::tcp::RuntimeTcpSocket};
use easytier_core::{
    connectivity::protocol::{
        insecure_tls::{get_insecure_tls_client_config, init_crypto_provider},
        websocket::{is_wss, map_from_ws_message, sink_from_zc_packet, upgrade_accepted},
    },
    socket::tcp::VirtualTcpSocket,
    tunnel::{IpVersion, Tunnel, TunnelError, wrapper::TunnelWrapper},
};
use futures::{SinkExt, StreamExt, stream::FuturesUnordered};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::{TcpListener, TcpSocket},
    time::timeout,
};
use tokio_websockets::{ClientBuilder, MaybeTlsStream};

#[derive(Debug)]
pub struct WsTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
    socket_mark: Option<u32>,
}

impl WsTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelListener {
            addr,
            listener: None,
            socket_mark: None,
        }
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        self.listener = None;

        let addr = SocketAddr::from_url(self.addr.clone(), IpVersion::Both).await?;
        let listener = bind::<TcpListener>()
            .addr(addr)
            .only_v6(true)
            .maybe_socket_mark(self.socket_mark)
            .call()?;

        self.addr
            .set_port(Some(listener.local_addr()?.port()))
            .unwrap();
        self.listener = Some(listener);

        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        loop {
            let listener = self.listener.as_ref().unwrap();
            // only fail on tcp accept error
            let (stream, _) = listener.accept().await?;
            stream.set_nodelay(true).unwrap();
            match timeout(
                Duration::from_secs(3),
                upgrade_accepted(RuntimeTcpSocket::new(stream), self.addr.clone()),
            )
            .await
            {
                Ok(Ok(tunnel)) => return Ok(tunnel),
                e => {
                    tracing::error!(?e, ?self, "Failed to accept ws/wss tunnel");
                    continue;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl easytier_core::listener::SocketListener for WsTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel().await?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct WsTunnelConnector {
    addr: url::Url,
    ip_version: IpVersion,
    resolved_addr: Option<SocketAddr>,

    bind_addrs: Vec<SocketAddr>,
    socket_mark: Option<u32>,
}

impl WsTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        WsTunnelConnector {
            addr,
            ip_version: IpVersion::Both,
            resolved_addr: None,

            bind_addrs: vec![],
            socket_mark: None,
        }
    }

    pub fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }

    pub fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    pub fn set_resolved_addr(&mut self, addr: SocketAddr) {
        self.resolved_addr = Some(addr);
    }

    pub fn set_socket_mark(&mut self, socket_mark: Option<u32>) {
        self.socket_mark = socket_mark;
    }

    async fn connect_with(
        addr: url::Url,
        socket_addr: SocketAddr,
        tcp_socket: TcpSocket,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        is_wss(&addr)?;
        let stream = tcp_socket.connect(socket_addr).await?;
        if let Err(error) = stream.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay fail in ws connect");
        }
        upgrade_connected(RuntimeTcpSocket::new(stream), addr).await
    }

    async fn connect_with_default_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        crate::tunnel::common::apply_socket_mark(
            &socket2::SockRef::from(&socket),
            self.socket_mark,
        )?;
        Self::connect_with(self.addr.clone(), addr, socket).await
    }

    async fn connect_with_custom_bind(
        &self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(?bind_addr, ?addr, "bind addr");
            match bind()
                .addr(*bind_addr)
                .only_v6(true)
                .maybe_socket_mark(self.socket_mark)
                .call()
            {
                Ok(socket) => futures.push(Self::connect_with(self.addr.clone(), addr, socket)),
                Err(error) => {
                    tracing::error!(?bind_addr, ?addr, ?error, "bind addr fail");
                    continue;
                }
            }
        }

        wait_for_connect_futures(futures).await
    }

    async fn connect_tunnel(&self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = match self.resolved_addr {
            Some(addr) => addr,
            None => SocketAddr::from_url(self.addr.clone(), self.ip_version).await?,
        };
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }
}

pub(crate) async fn upgrade_connected<S>(
    stream: S,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let is_wss = is_wss(&remote_url)?;
    let local_addr = stream.local_addr()?;
    let resolved_remote_addr = stream.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type: remote_url.scheme().to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&local_addr.to_string(), remote_url.scheme()).into(),
        ),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(
            super::build_url_from_socket_addr(
                &resolved_remote_addr.to_string(),
                remote_url.scheme(),
            )
            .into(),
        ),
    };

    let client = ClientBuilder::from_uri(http::Uri::try_from(remote_url.to_string()).unwrap())
        .max_headers(128);
    let stream: MaybeTlsStream<S> = if is_wss {
        init_crypto_provider();
        let tls = tokio_rustls::TlsConnector::from(Arc::new(get_insecure_tls_client_config()));
        let sni = remote_url.domain().unwrap_or("localhost").to_owned();
        let server_name = rustls::pki_types::ServerName::try_from(sni)
            .map_err(|_| TunnelError::InvalidProtocol("Invalid SNI".to_owned()))?;
        MaybeTlsStream::Rustls(tls.connect(server_name, stream).await?)
    } else {
        MaybeTlsStream::Plain(stream)
    };

    let (client, _) = client
        .connect_on(stream)
        .await
        .map_err(TunnelError::websocket_error)?;
    let (write, read) = client.split();
    Ok(Box::new(TunnelWrapper::new(
        read.filter_map(map_from_ws_message),
        write
            .sink_map_err(TunnelError::websocket_error)
            .with(sink_from_zc_packet::<TunnelError>),
        Some(info),
    )))
}

#[async_trait::async_trait]
impl easytier_core::connectivity::protocol::raw::TunnelDialer for WsTunnelConnector {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(self.connect_tunnel().await?)
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::tunnel::common::tests::_tunnel_pingpong;
    use easytier_core::{connectivity::protocol::raw::TunnelDialer, listener::SocketListener};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong(#[values("ws", "wss")] proto: &str) {
        let listener = WsTunnelListener::new(format!("{}://0.0.0.0:25556", proto).parse().unwrap());
        let connector =
            WsTunnelConnector::new(format!("{}://127.0.0.1:25556", proto).parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[rstest::rstest]
    #[tokio::test]
    #[serial_test::serial]
    async fn ws_pingpong_bind(#[values("ws", "wss")] proto: &str) {
        let listener = WsTunnelListener::new(format!("{}://0.0.0.0:25557", proto).parse().unwrap());
        let mut connector =
            WsTunnelConnector::new(format!("{}://127.0.0.1:25557", proto).parse().unwrap());
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
        let mut listener = WsTunnelListener::new("wss://0.0.0.0:25558".parse().unwrap());
        listener.listen().await.unwrap();
        let j = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let connector = WsTunnelConnector::new("ws://127.0.0.1:25558".parse().unwrap());
        connector.connect().await.unwrap_err();

        let connector = WsTunnelConnector::new("wss://127.0.0.1:25558".parse().unwrap());
        connector.connect().await.unwrap();

        j.abort();
    }

    #[tokio::test]
    async fn ws_forwarded() {
        let mut listener = WsTunnelListener::new("ws://127.0.0.1:25559".parse().unwrap());
        listener.listen().await.unwrap();

        let server_task = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();

            let remote_addr = tunnel
                .info()
                .unwrap()
                .remote_addr
                .unwrap()
                .url
                .parse::<url::Url>()
                .unwrap();

            assert_eq!(remote_addr.host_str().unwrap(), "203.0.113.5");
            let proxy_addr = remote_addr
                .query_pairs()
                .find(|(k, _)| k == "proxy")
                .map(|(_, v)| v.into_owned())
                .unwrap();
            assert_eq!(proxy_addr, "127.0.0.1:25560");

            tunnel
        });

        let socket = TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.1:25560".parse().unwrap()).unwrap();
        let mut stream = socket
            .connect("127.0.0.1:25559".parse().unwrap())
            .await
            .unwrap();

        let handshake = "GET / HTTP/1.1\r\n\
                         Host: 127.0.0.1:25559\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                         Sec-WebSocket-Version: 13\r\n\
                         X-Forwarded-For: 203.0.113.5, 192.168.1.1\r\n\
                         \r\n";

        stream.write_all(handshake.as_bytes()).await.unwrap();

        let mut buf = [0u8; 1024];
        let bytes_read = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..bytes_read]);

        assert!(response.contains("101 Switching Protocols"));

        let _tunnel = server_task.await.unwrap();
    }
}

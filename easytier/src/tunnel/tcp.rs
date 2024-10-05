use std::net::SocketAddr;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use tokio::net::{TcpListener, TcpSocket, TcpStream};

use super::TunnelInfo;
use crate::tunnel::common::setup_sokcet2;

use super::{
    check_scheme_and_get_socket_addr, check_scheme_and_get_socket_addr_ext,
    common::{wait_for_connect_futures, FramedReader, FramedWriter, TunnelWrapper},
    IpVersion, Tunnel, TunnelError, TunnelListener,
};

const TCP_MTU_BYTES: usize = 2000;

#[derive(Debug)]
pub struct TcpTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
}

impl TcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelListener {
            addr,
            listener: None,
        }
    }
}

#[async_trait]
impl TunnelListener for TcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;

        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        setup_sokcet2(&socket2_socket, &addr)?;
        let socket = TcpSocket::from_std_stream(socket2_socket.into());

        if let Err(e) = socket.set_nodelay(true) {
            tracing::warn!(?e, "set_nodelay fail in listen");
        }

        self.addr
            .set_port(Some(socket.local_addr()?.port()))
            .unwrap();

        self.listener = Some(socket.listen(1024)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await?;

        if let Err(e) = stream.set_nodelay(true) {
            tracing::warn!(?e, "set_nodelay fail in accept");
        }

        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                super::build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "tcp").into(),
            ),
        };

        let (r, w) = stream.into_split();
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, TCP_MTU_BYTES),
            FramedWriter::new(w),
            Some(info),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

fn get_tunnel_with_tcp_stream(
    stream: TcpStream,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, super::TunnelError> {
    if let Err(e) = stream.set_nodelay(true) {
        tracing::warn!(?e, "set_nodelay fail in get_tunnel_with_tcp_stream");
    }

    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(
            super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "tcp").into(),
        ),
        remote_addr: Some(remote_url.into()),
    };

    let (r, w) = stream.into_split();
    Ok(Box::new(TunnelWrapper::new(
        FramedReader::new(r, TCP_MTU_BYTES),
        FramedWriter::new(w),
        Some(info),
    )))
}

#[derive(Debug)]
pub struct TcpTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
    ip_version: IpVersion,
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
            ip_version: IpVersion::Both,
        }
    }

    async fn connect_with_default_bind(
        &mut self,
        addr: SocketAddr,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(addr = ?self.addr, "connect tcp start");
        let stream = TcpStream::connect(addr).await?;
        tracing::info!(addr = ?self.addr, "connect tcp succ");
        return get_tunnel_with_tcp_stream(stream, self.addr.clone().into());
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
            futures.push(socket.connect(addr.clone()));
        }

        let ret = wait_for_connect_futures(futures).await;
        return get_tunnel_with_tcp_stream(ret?, self.addr.clone().into());
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let addr =
            check_scheme_and_get_socket_addr_ext::<SocketAddr>(&self.addr, "tcp", self.ip_version)?;
        if self.bind_addrs.is_empty() || addr.is_ipv6() {
            self.connect_with_default_bind(addr).await
        } else {
            self.connect_with_custom_bind(addr).await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }

    fn set_ip_version(&mut self, ip_version: IpVersion) {
        self.ip_version = ip_version;
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::{
        common::tests::{_tunnel_bench, _tunnel_pingpong},
        TunnelConnector,
    };

    use super::*;

    #[tokio::test]
    async fn tcp_pingpong() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:31011".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:31011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:31012".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:31012".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench_with_bind() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11013".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11013".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn tcp_bench_with_bind_fail() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn bind_same_port() {
        let mut listener = TcpTunnelListener::new("tcp://[::]:31014".parse().unwrap());
        let mut listener2 = TcpTunnelListener::new("tcp://0.0.0.0:31014".parse().unwrap());
        listener.listen().await.unwrap();
        listener2.listen().await.unwrap();
    }

    #[tokio::test]
    async fn ipv6_pingpong() {
        let listener = TcpTunnelListener::new("tcp://[::1]:31015".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://[::1]:31015".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn ipv6_domain_pingpong() {
        let listener = TcpTunnelListener::new("tcp://[::1]:31015".parse().unwrap());
        let mut connector =
            TcpTunnelConnector::new("tcp://test.kkrainbow.top:31015".parse().unwrap());
        connector.set_ip_version(IpVersion::V6);
        _tunnel_pingpong(listener, connector).await;

        let listener = TcpTunnelListener::new("tcp://127.0.0.1:31015".parse().unwrap());
        let mut connector =
            TcpTunnelConnector::new("tcp://test.kkrainbow.top:31015".parse().unwrap());
        connector.set_ip_version(IpVersion::V4);
        _tunnel_pingpong(listener, connector).await;
    }

    #[tokio::test]
    async fn test_alloc_port() {
        // v4
        let mut listener = TcpTunnelListener::new("tcp://0.0.0.0:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);

        // v6
        let mut listener = TcpTunnelListener::new("tcp://[::]:0".parse().unwrap());
        listener.listen().await.unwrap();
        let port = listener.local_url().port().unwrap();
        assert!(port > 0);
    }
}

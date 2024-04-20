use std::net::SocketAddr;

use async_trait::async_trait;
use futures::stream::FuturesUnordered;
use tokio::{
    io::{AsyncReadExt, AsyncWrite},
    net::{TcpListener, TcpSocket, TcpStream},
};

use crate::{rpc::TunnelInfo, tunnel::common::setup_sokcet2};

use super::{
    check_scheme_and_get_socket_addr,
    common::{wait_for_connect_futures, FramedReader, FramedWriter, TunnelWrapper},
    Tunnel, TunnelError, TunnelListener,
};

const TCP_MTU_BYTES: usize = 64 * 1024;

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

        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_reuseaddr(true)?;
        // #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        // socket.set_reuseport(true)?;
        socket.bind(addr)?;

        self.listener = Some(socket.listen(1024)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).unwrap();
        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: self.local_url().into(),
            remote_addr: super::build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "tcp")
                .into(),
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
    stream.set_nodelay(true).unwrap();

    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "tcp")
            .into(),
        remote_addr: remote_url.into(),
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
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
        }
    }

    async fn connect_with_default_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(addr = ?self.addr, "connect tcp start");
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;
        let stream = TcpStream::connect(addr).await?;
        tracing::info!(addr = ?self.addr, "connect tcp succ");
        return get_tunnel_with_tcp_stream(stream, self.addr.clone().into());
    }

    async fn connect_with_custom_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();
        let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(bind_addr = ?bind_addr, ?dst_addr, "bind addr");

            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(dst_addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            setup_sokcet2(&socket2_socket, bind_addr)?;

            let socket = TcpSocket::from_std_stream(socket2_socket.into());
            futures.push(socket.connect(dst_addr.clone()));
        }

        let ret = wait_for_connect_futures(futures).await;
        return get_tunnel_with_tcp_stream(ret?, self.addr.clone().into());
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        if self.bind_addrs.is_empty() {
            self.connect_with_default_bind().await
        } else {
            self.connect_with_custom_bind().await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};

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
}

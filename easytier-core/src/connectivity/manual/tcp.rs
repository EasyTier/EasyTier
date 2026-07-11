use std::{net::SocketAddr, sync::Arc};

use futures::stream::FuturesUnordered;
use url::Url;

use crate::{
    proto::common::TunnelInfo,
    socket::tcp::{TcpBindOptions, TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory},
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader},
};

use super::first_success;

pub(super) async fn connect_and_upgrade<H>(
    host: Arc<H>,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
    default_bind: TcpBindOptions,
    requested_remote_addr: Url,
) -> anyhow::Result<Box<dyn Tunnel>>
where
    H: VirtualTcpSocketFactory,
{
    let futures = FuturesUnordered::new();
    if bind_addrs.is_empty() {
        futures.push(
            host.connect_tcp(
                TcpConnectOptions::direct_connect(remote_addr).with_bind(default_bind),
            ),
        );
    } else {
        for bind_addr in bind_addrs {
            let bind = default_bind
                .clone()
                .with_local_addr(Some(bind_addr))
                .with_only_v6(true);
            futures.push(
                host.connect_tcp(TcpConnectOptions::direct_connect(remote_addr).with_bind(bind)),
            );
        }
    }
    let socket = first_success(futures).await?;
    upgrade_connected_socket(socket, requested_remote_addr).map_err(Into::into)
}

fn upgrade_connected_socket<S>(
    socket: S,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let resolved_remote_addr = socket.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(tcp_url(local_addr).into()),
        remote_addr: Some(requested_remote_addr.into()),
        resolved_remote_addr: Some(tcp_url(resolved_remote_addr).into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub fn upgrade_accepted_socket<S>(socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let remote_addr = socket.peer_addr()?;
    let remote_url = tcp_url(remote_addr);
    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(tcp_url(local_addr).into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

fn tcp_url(addr: SocketAddr) -> Url {
    let mut url = Url::parse("tcp://0.0.0.0").expect("static TCP URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("TCP URL should accept a port");
    url
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use super::*;

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl MockTcpSocket {
        fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
            let (stream, _) = tokio::io::duplex(64);
            Self {
                stream,
                local_addr,
                peer_addr,
            }
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
    }

    #[test]
    fn tcp_socket_upgrades_preserve_requested_and_resolved_addresses() {
        let local_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let requested_url: Url = "tcp://example.com:2000".parse().unwrap();

        let connected = upgrade_connected_socket(
            MockTcpSocket::new(local_addr, peer_addr),
            requested_url.clone(),
        )
        .unwrap();
        let connected_info = connected.info().unwrap();
        assert_eq!(
            connected_info.remote_addr.unwrap().url,
            requested_url.as_str()
        );
        let connected_resolved: Url = connected_info.resolved_remote_addr.unwrap().into();
        assert_eq!(connected_resolved.host_str(), Some("127.0.0.1"));
        assert_eq!(connected_resolved.port(), Some(2000));

        let accepted = upgrade_accepted_socket(MockTcpSocket::new(local_addr, peer_addr)).unwrap();
        let accepted_info = accepted.info().unwrap();
        assert_eq!(
            accepted_info.remote_addr,
            accepted_info.resolved_remote_addr
        );
    }
}

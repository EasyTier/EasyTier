use std::net::SocketAddr;

use url::Url;

use crate::{
    connectivity::transport::{ConnectedTransport, ConnectedUdpSession},
    proto::common::TunnelInfo,
    socket::{
        tcp::VirtualTcpSocket,
        udp::{UdpSession, UdpSessionSocket},
    },
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader, udp::UdpTunnelUpgrader},
};

pub fn upgrade_connected<S>(
    connected: ConnectedTransport<S>,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    match connected {
        ConnectedTransport::Tcp(socket) => upgrade_connected_tcp(socket, requested_remote_addr),
        ConnectedTransport::Udp(session) => upgrade_connected_udp(session, requested_remote_addr),
    }
}

pub fn upgrade_connected_tcp<S>(
    socket: S,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let resolved_remote_addr = socket.peer_addr()?;
    let info = connected_tunnel_info(
        "tcp",
        local_addr,
        resolved_remote_addr,
        requested_remote_addr,
    );
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub fn upgrade_connected_udp(
    connected: ConnectedUdpSession,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let (session, layer) = connected.into_parts();
    let info = connected_tunnel_info(
        "udp",
        session.local_addr()?,
        session.peer_addr()?,
        requested_remote_addr,
    );
    UdpTunnelUpgrader::with_keep_alive(info, layer).upgrade(session)
}

pub fn upgrade_accepted_tcp<S>(socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let remote_addr = socket.peer_addr()?;
    let info = accepted_tunnel_info("tcp", local_addr, remote_addr);
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub fn upgrade_accepted_udp(session: UdpSession) -> Result<Box<dyn Tunnel>, TunnelError> {
    let info = accepted_tunnel_info("udp", session.local_addr()?, session.peer_addr()?);
    UdpTunnelUpgrader::new(info).upgrade(session)
}

fn connected_tunnel_info(
    scheme: &str,
    local_addr: SocketAddr,
    resolved_remote_addr: SocketAddr,
    requested_remote_addr: Url,
) -> TunnelInfo {
    TunnelInfo {
        tunnel_type: scheme.to_owned(),
        local_addr: Some(socket_url(scheme, local_addr).into()),
        remote_addr: Some(requested_remote_addr.into()),
        resolved_remote_addr: Some(socket_url(scheme, resolved_remote_addr).into()),
    }
}

fn accepted_tunnel_info(
    scheme: &str,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
) -> TunnelInfo {
    let remote_url = socket_url(scheme, remote_addr);
    TunnelInfo {
        tunnel_type: scheme.to_owned(),
        local_addr: Some(socket_url(scheme, local_addr).into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
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
    }
}

use url::Url;

use crate::{
    proto::common::TunnelInfo,
    socket::tcp::VirtualTcpSocket,
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader},
};

pub fn upgrade_connected<S>(socket: S, requested_url: Url) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let tunnel_type = transport_label(&socket)?;
    let local_addr = socket.local_addr()?;
    let remote_addr = socket.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type,
        local_addr: Some(socket_url(local_addr).into()),
        remote_addr: Some(requested_url.into()),
        resolved_remote_addr: Some(socket_url(remote_addr).into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub fn upgrade_accepted<S>(socket: S, local_url: Url) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let tunnel_type = transport_label(&socket)?;
    let remote_url = socket_url(socket.peer_addr()?);
    let info = TunnelInfo {
        tunnel_type,
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

fn socket_url(addr: std::net::SocketAddr) -> Url {
    let mut url = Url::parse("faketcp://0.0.0.0").unwrap();
    url.set_ip_host(addr.ip()).unwrap();
    url.set_port(Some(addr.port())).unwrap();
    url
}

fn transport_label(socket: &impl VirtualTcpSocket) -> Result<String, TunnelError> {
    socket.transport_label().map(str::to_owned).ok_or_else(|| {
        TunnelError::InternalError(
            "FakeTCP upgrader received a socket without a FakeTCP transport label".to_owned(),
        )
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::SocketAddr,
        pin::Pin,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use super::*;

    struct TestSocket {
        transport_label: Option<&'static str>,
    }

    impl AsyncRead for TestSocket {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Pending
        }
    }

    impl AsyncWrite for TestSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Pending
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl VirtualTcpSocket for TestSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("192.0.2.1:10000".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("192.0.2.2:11013".parse().unwrap())
        }

        fn transport_label(&self) -> Option<&str> {
            self.transport_label
        }
    }

    fn labelled_socket() -> TestSocket {
        TestSocket {
            transport_label: Some("faketcp_test-driver"),
        }
    }

    #[test]
    fn upgrades_preserve_host_transport_label_and_addresses() {
        let connected = upgrade_connected(
            labelled_socket(),
            "faketcp://peer.example:11013".parse().unwrap(),
        )
        .unwrap();
        let connected_info = connected.info().unwrap();
        assert_eq!(connected_info.tunnel_type, "faketcp_test-driver");
        assert_eq!(
            connected_info.resolved_remote_addr.unwrap().url,
            "faketcp://192.0.2.2:11013"
        );

        let accepted = upgrade_accepted(
            labelled_socket(),
            "faketcp://0.0.0.0:11013".parse().unwrap(),
        )
        .unwrap();
        let accepted_info = accepted.info().unwrap();
        assert_eq!(accepted_info.tunnel_type, "faketcp_test-driver");
        assert_eq!(
            accepted_info.remote_addr.unwrap(),
            accepted_info.resolved_remote_addr.unwrap()
        );
    }

    #[test]
    fn rejects_socket_without_host_transport_label() {
        let error = upgrade_connected(
            TestSocket {
                transport_label: None,
            },
            "faketcp://peer.example:11013".parse().unwrap(),
        )
        .unwrap_err();

        assert!(matches!(error, TunnelError::InternalError(_)));
    }
}

use std::path::Path;

use async_trait::async_trait;
use easytier_core::tunnel::{
    Tunnel, TunnelError,
    framed::{FramedReader, FramedWriter},
    wrapper::TunnelWrapper,
};
use tokio::net::{UnixListener, UnixStream, unix::SocketAddr};

use crate::proto::common::TunnelInfo;

const MAX_PACKET_SIZE: usize = 4096;

pub(crate) fn url_from_unix_socket_addr(addr: SocketAddr) -> Option<url::Url> {
    addr.as_pathname()
        .and_then(|p| p.to_str())
        .and_then(|s| format!("unix://{}", s).parse().ok())
}

#[derive(Debug)]
pub struct UnixSocketTunnelListener {
    addr: url::Url,
    listener: Option<UnixListener>,
    unlink_on_drop: bool,
}

impl UnixSocketTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        UnixSocketTunnelListener {
            addr,
            listener: None,
            unlink_on_drop: true,
        }
    }

    async fn do_accept(&self) -> Result<Box<dyn Tunnel>, std::io::Error> {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await?;

        let remote_addr = stream.peer_addr().ok().and_then(url_from_unix_socket_addr);

        let info = TunnelInfo {
            tunnel_type: "unix".to_owned(),
            local_addr: Some(self.addr.clone().into()),
            remote_addr: remote_addr.clone().map(Into::into),
            resolved_remote_addr: remote_addr.map(Into::into),
        };

        let (r, w) = stream.into_split();
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, MAX_PACKET_SIZE),
            FramedWriter::new(w),
            Some(info),
        )))
    }

    fn set_unlink_on_drop(&mut self, unlink: bool) {
        self.unlink_on_drop = unlink;
    }

    fn listen_tunnel(&mut self) -> Result<(), TunnelError> {
        self.listener = None;
        let path_str = self.addr.path();
        let path = Path::new(path_str);

        let listener = UnixListener::bind(path)?;
        self.listener = Some(listener);
        Ok(())
    }

    async fn accept_tunnel(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        loop {
            match self.do_accept().await {
                Ok(ret) => return Ok(ret),
                Err(e) => {
                    use std::io::ErrorKind::*;
                    if matches!(
                        e.kind(),
                        NotConnected | ConnectionAborted | ConnectionRefused | ConnectionReset
                    ) {
                        tracing::warn!(?e, "accept fail with retryable error: {:?}", e);
                        continue;
                    }
                    tracing::warn!(?e, "accept fail");
                    return Err(e.into());
                }
            }
        }
    }
}

#[async_trait]
impl easytier_core::listener::SocketListener for UnixSocketTunnelListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        Ok(self.listen_tunnel()?)
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        Ok(self.accept_tunnel().await?)
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

#[derive(Debug)]
pub struct UnixSocketTunnelConnector {
    addr: url::Url,
}

impl UnixSocketTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        UnixSocketTunnelConnector { addr }
    }

    async fn connect_tunnel(&self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let path_str = self.addr.path();
        let path = Path::new(path_str);
        tracing::info!(url = ?self.addr, "connect unix socket start");
        let stream = UnixStream::connect(path).await?;
        tracing::info!(url = ?self.addr, "connect unix socket succ");

        let local_addr = stream.local_addr().ok().and_then(url_from_unix_socket_addr);

        let info = TunnelInfo {
            tunnel_type: "unix".to_owned(),
            local_addr: local_addr.map(Into::into),
            remote_addr: Some(self.addr.clone().into()),
            resolved_remote_addr: Some(self.addr.clone().into()),
        };

        let (r, w) = stream.into_split();
        Ok(Box::new(TunnelWrapper::new(
            FramedReader::new(r, MAX_PACKET_SIZE),
            FramedWriter::new(w),
            Some(info),
        )))
    }
}

#[async_trait]
impl easytier_core::connectivity::protocol::raw::TunnelDialer for UnixSocketTunnelConnector {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        Ok(self.connect_tunnel().await?)
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

impl Drop for UnixSocketTunnelListener {
    fn drop(&mut self) {
        if self.unlink_on_drop {
            let _ = std::fs::remove_file(self.addr.path());
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::{_tunnel_bench, _tunnel_pingpong};
    use easytier_core::listener::SocketListener;

    use super::*;

    #[tokio::test]
    async fn unix_socket_pingpong() {
        let listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test.sock".parse().unwrap());
        let connector =
            UnixSocketTunnelConnector::new("unix:///tmp/easytier-test.sock".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn unix_socket_bench() {
        let listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test-bench.sock".parse().unwrap());
        let connector =
            UnixSocketTunnelConnector::new("unix:///tmp/easytier-test-bench.sock".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn unlink_on_drop() {
        let listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test-exists.sock".parse().unwrap());
        let connector = UnixSocketTunnelConnector::new(
            "unix:///tmp/easytier-test-exists.sock".parse().unwrap(),
        );
        _tunnel_pingpong(listener, connector).await;

        let mut listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test-exists.sock".parse().unwrap());
        listener.set_unlink_on_drop(false);
        let connector = UnixSocketTunnelConnector::new(
            "unix:///tmp/easytier-test-exists.sock".parse().unwrap(),
        );
        _tunnel_pingpong(listener, connector).await;

        let mut listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test-exists.sock".parse().unwrap());
        let result = listener.listen().await;
        assert!(matches!(
            result.unwrap_err().downcast_ref::<TunnelError>(),
            Some(TunnelError::IOError(err)) if err.kind() == std::io::ErrorKind::AddrInUse
        ))
    }

    #[tokio::test]
    async fn bind_file_exists() {
        use std::fs;

        let path = "/tmp/easytier-test-exists.sock";
        fs::File::create(path).unwrap();
        let mut listener =
            UnixSocketTunnelListener::new("unix:///tmp/easytier-test-exists.sock".parse().unwrap());
        let result = listener.listen().await;

        fs::remove_file(path).unwrap();
        assert!(matches!(
            result.unwrap_err().downcast_ref::<TunnelError>(),
            Some(TunnelError::IOError(err)) if err.kind() == std::io::ErrorKind::AddrInUse
        ))
    }
}

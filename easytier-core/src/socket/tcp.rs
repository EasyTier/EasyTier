use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

/// A core-visible TCP stream endpoint.
///
/// Implementations are runtime adapters over concrete TCP stream types. This
/// trait deliberately stays below tunnel framing: it only exposes stream I/O and
/// socket addresses.
pub trait VirtualTcpSocket: AsyncRead + AsyncWrite + Unpin + Send + 'static {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    fn peer_addr(&self) -> io::Result<SocketAddr>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpSocketPurpose {
    DirectConnect,
    HolePunch,
    ManualConnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpConnectOptions {
    pub remote_addr: SocketAddr,
    pub local_addr: Option<SocketAddr>,
    pub purpose: TcpSocketPurpose,
}

impl TcpConnectOptions {
    pub fn direct_connect(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            local_addr: None,
            purpose: TcpSocketPurpose::DirectConnect,
        }
    }

    pub fn hole_punch(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            local_addr,
            purpose: TcpSocketPurpose::HolePunch,
        }
    }

    pub fn manual_connect(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            local_addr,
            purpose: TcpSocketPurpose::ManualConnect,
        }
    }
}

#[async_trait]
pub trait VirtualTcpSocketFactory: Send + Sync + 'static {
    type Socket: VirtualTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket>;
}

#[async_trait]
pub trait VirtualTcpListener: Send + Sync + 'static {
    type Socket: VirtualTcpSocket;

    fn local_addr(&self) -> io::Result<SocketAddr>;

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpListenPurpose {
    DirectConnect,
    HolePunch,
    ManualConnect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpListenOptions {
    pub local_addr: SocketAddr,
    pub purpose: TcpListenPurpose,
}

impl TcpListenOptions {
    pub fn direct_connect(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            purpose: TcpListenPurpose::DirectConnect,
        }
    }

    pub fn hole_punch(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            purpose: TcpListenPurpose::HolePunch,
        }
    }

    pub fn manual_connect(local_addr: SocketAddr) -> Self {
        Self {
            local_addr,
            purpose: TcpListenPurpose::ManualConnect,
        }
    }
}

#[async_trait]
pub trait VirtualTcpListenerFactory: Send + Sync + 'static {
    type Listener: VirtualTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_connect_options_preserve_socket_purpose() {
        let remote_addr = SocketAddr::from(([127, 0, 0, 1], 11010));
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));

        assert_eq!(
            TcpConnectOptions::direct_connect(remote_addr),
            TcpConnectOptions {
                remote_addr,
                local_addr: None,
                purpose: TcpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpConnectOptions::hole_punch(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                local_addr: Some(local_addr),
                purpose: TcpSocketPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpConnectOptions::manual_connect(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                local_addr: Some(local_addr),
                purpose: TcpSocketPurpose::ManualConnect,
            }
        );
    }

    #[test]
    fn tcp_listen_options_preserve_socket_purpose() {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 11010));

        assert_eq!(
            TcpListenOptions::direct_connect(local_addr),
            TcpListenOptions {
                local_addr,
                purpose: TcpListenPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpListenOptions::hole_punch(local_addr),
            TcpListenOptions {
                local_addr,
                purpose: TcpListenPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpListenOptions::manual_connect(local_addr),
            TcpListenOptions {
                local_addr,
                purpose: TcpListenPurpose::ManualConnect,
            }
        );
    }
}

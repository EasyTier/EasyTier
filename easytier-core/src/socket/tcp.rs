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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpBindOptions {
    pub local_addr: Option<SocketAddr>,
    pub socket_mark: Option<u32>,
    pub bind_device: Option<String>,
    pub reuse_addr: bool,
    pub reuse_port: bool,
    pub only_v6: bool,
}

impl TcpBindOptions {
    pub fn new() -> Self {
        Self {
            local_addr: None,
            socket_mark: None,
            bind_device: None,
            reuse_addr: !cfg!(target_os = "windows"),
            reuse_port: false,
            only_v6: false,
        }
    }

    pub fn with_local_addr(mut self, local_addr: Option<SocketAddr>) -> Self {
        self.local_addr = local_addr;
        self
    }

    pub fn with_socket_mark(mut self, socket_mark: Option<u32>) -> Self {
        self.socket_mark = socket_mark;
        self
    }

    pub fn with_bind_device(mut self, bind_device: Option<String>) -> Self {
        self.bind_device = bind_device;
        self
    }

    pub fn with_reuse_addr(mut self, reuse_addr: bool) -> Self {
        self.reuse_addr = reuse_addr;
        self
    }

    pub fn with_reuse_port(mut self, reuse_port: bool) -> Self {
        self.reuse_port = reuse_port;
        self
    }

    pub fn with_only_v6(mut self, only_v6: bool) -> Self {
        self.only_v6 = only_v6;
        self
    }
}

impl Default for TcpBindOptions {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpConnectOptions {
    pub remote_addr: SocketAddr,
    pub bind: TcpBindOptions,
    pub purpose: TcpSocketPurpose,
}

impl TcpConnectOptions {
    pub fn direct_connect(remote_addr: SocketAddr) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default(),
            purpose: TcpSocketPurpose::DirectConnect,
        }
    }

    pub fn hole_punch(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default().with_local_addr(local_addr),
            purpose: TcpSocketPurpose::HolePunch,
        }
    }

    pub fn manual_connect(remote_addr: SocketAddr, local_addr: Option<SocketAddr>) -> Self {
        Self {
            remote_addr,
            bind: TcpBindOptions::default().with_local_addr(local_addr),
            purpose: TcpSocketPurpose::ManualConnect,
        }
    }

    pub fn with_bind(mut self, bind: TcpBindOptions) -> Self {
        self.bind = bind;
        self
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpListenOptions {
    pub bind: TcpBindOptions,
    pub purpose: TcpListenPurpose,
}

impl TcpListenOptions {
    pub fn direct_connect(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::DirectConnect,
        }
    }

    pub fn hole_punch(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::HolePunch,
        }
    }

    pub fn manual_connect(local_addr: SocketAddr) -> Self {
        Self {
            bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
            purpose: TcpListenPurpose::ManualConnect,
        }
    }

    pub fn with_bind(mut self, bind: TcpBindOptions) -> Self {
        self.bind = bind;
        self
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
                bind: TcpBindOptions::default(),
                purpose: TcpSocketPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpConnectOptions::hole_punch(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpSocketPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpConnectOptions::manual_connect(remote_addr, Some(local_addr)),
            TcpConnectOptions {
                remote_addr,
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
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
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::DirectConnect,
            }
        );
        assert_eq!(
            TcpListenOptions::hole_punch(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::HolePunch,
            }
        );
        assert_eq!(
            TcpListenOptions::manual_connect(local_addr),
            TcpListenOptions {
                bind: TcpBindOptions::default().with_local_addr(Some(local_addr)),
                purpose: TcpListenPurpose::ManualConnect,
            }
        );
    }

    #[test]
    fn tcp_bind_options_preserve_socket_configuration() {
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let options = TcpBindOptions::default()
            .with_local_addr(Some(local_addr))
            .with_socket_mark(Some(7))
            .with_bind_device(Some("eth0".to_owned()))
            .with_reuse_addr(true)
            .with_reuse_port(true)
            .with_only_v6(true);

        assert_eq!(
            options,
            TcpBindOptions {
                local_addr: Some(local_addr),
                socket_mark: Some(7),
                bind_device: Some("eth0".to_owned()),
                reuse_addr: true,
                reuse_port: true,
                only_v6: true,
            }
        );
    }
}

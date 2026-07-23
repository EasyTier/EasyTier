//! Shared virtual-socket and DNS fakes for core unit tests.
//!
//! `gateway` and `instance` tests drive the same portable host seams; both use
//! this kit instead of keeping parallel copies. The fakes are inert by
//! default: TCP connects only succeed for proxy-NAT purposes, listeners never
//! accept, UDP sockets never receive, and DNS answers only literal IP hosts.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};
use crate::socket::{
    tcp::{
        TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose,
        VirtualTcpListener, VirtualTcpListenerFactory, VirtualTcpSocket, VirtualTcpSocketFactory,
    },
    udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
};

pub struct TestTcpSocket(pub tokio::io::DuplexStream);

impl AsyncRead for TestTcpSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(_cx, buf)
    }
}

impl AsyncWrite for TestTcpSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(_cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl VirtualTcpSocket for TestTcpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:20000".parse().unwrap())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:20001".parse().unwrap())
    }
}

pub struct TestTcpListener(pub SocketAddr);

#[async_trait::async_trait]
impl VirtualTcpListener for TestTcpListener {
    type Socket = TestTcpSocket;

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0)
    }

    async fn accept(&self) -> io::Result<(Self::Socket, SocketAddr)> {
        std::future::pending().await
    }
}

pub struct TestUdpSocket(pub SocketAddr);

#[async_trait::async_trait]
impl VirtualUdpSocket for TestUdpSocket {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0)
    }

    async fn send_to(&self, data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        Ok(data.len())
    }

    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }
}

#[derive(Default)]
pub struct TestHost {
    pub tcp_binds: AtomicUsize,
    pub proxy_nat_connections:
        Option<tokio::sync::mpsc::UnboundedSender<(SocketAddr, tokio::io::DuplexStream)>>,
    pub reject_socks5_listener: bool,
}

#[async_trait::async_trait]
impl VirtualTcpSocketFactory for TestHost {
    type Socket = TestTcpSocket;

    async fn connect_tcp(&self, options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
        if options.purpose != TcpSocketPurpose::ProxyNat {
            anyhow::bail!("test host does not connect non-proxy TCP sockets");
        }
        let connections = self
            .proxy_nat_connections
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("test host proxy NAT is disabled"))?;
        let (socket, peer) = tokio::io::duplex(1024);
        connections
            .send((options.remote_addr, peer))
            .map_err(|_| anyhow::anyhow!("test host proxy NAT receiver is closed"))?;
        Ok(TestTcpSocket(socket))
    }
}

#[async_trait::async_trait]
impl VirtualTcpListenerFactory for TestHost {
    type Listener = TestTcpListener;

    async fn bind_tcp(&self, options: TcpListenOptions) -> anyhow::Result<Arc<Self::Listener>> {
        self.tcp_binds.fetch_add(1, Ordering::Relaxed);
        if self.reject_socks5_listener && options.purpose == TcpListenPurpose::Socks5 {
            anyhow::bail!("test host rejected SOCKS5 listener");
        }
        let address = options
            .bind
            .local_addr
            .unwrap_or_else(|| "127.0.0.1:20000".parse().unwrap());
        // Ephemeral binds still report a fixed nonzero port: the gateway
        // smoltcp connector feeds `local_addr().port()` into the virtual
        // stack, which rejects source port 0 as unaddressable.
        let address = if address.port() == 0 {
            SocketAddr::new(address.ip(), 20000)
        } else {
            address
        };
        Ok(Arc::new(TestTcpListener(address)))
    }
}

#[async_trait::async_trait]
impl VirtualUdpSocketFactory for TestHost {
    type Socket = TestUdpSocket;

    async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
        let address = options
            .local_addr
            .unwrap_or_else(|| "127.0.0.1:20002".parse().unwrap());
        Ok(Arc::new(TestUdpSocket(address)))
    }
}

pub struct TestDns;

#[async_trait::async_trait]
impl DnsResolver for TestDns {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        Ok(query.host.parse().into_iter().collect())
    }
}

#[async_trait::async_trait]
impl DnsRecordResolver for TestDns {
    async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
        anyhow::bail!("test DNS has no TXT records")
    }

    async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        Ok(Vec::new())
    }
}

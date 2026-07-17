//! Data-plane access built on top of the core gateway smoltcp stack.
//!
//! This module exposes TCP streams and UDP sockets (mainly for FFI callers that
//! send traffic through EasyTier without creating OS-level proxy listeners).
//!
//! Typical usage:
//!
//! ```ignore
//! let instance = CoreInstance::new(...);
//! instance.start().await?;
//!
//! let socket = instance.data_plane_udp_bind(local_port, timeout).await?;
//! socket.send_to(buf, peer_addr).await?;
//! ```

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use anyhow::Context as _;
use quanta::Instant;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{
    gateway::{
        socks5::{Socks5Entry, Socks5EntryGuard, protocol::server::AsyncTcpConnector},
        tokio_smoltcp::{Net, TcpListener},
    },
    socket::{
        tcp::{TcpSocketPurpose, VirtualTcpListenerFactory, VirtualTcpSocketFactory},
        udp::VirtualUdpSocketFactory,
    },
};

use super::{
    GatewayEntryData, GatewayEntrySet, GatewayModule, GatewayTcpStream, GatewayUdpSocket,
    Socks5AutoConnector, TCP_ENTRY, TCP_LISTEN_ENTRY, UDP_ENTRY, UdpClientKey,
};

struct DataPlaneRef {
    refs: Arc<AtomicUsize>,
    notifier: Arc<tokio::sync::Notify>,
}

/// Tracks how an established data-plane TCP stream keeps its inbound route alive.
///
/// The two variants capture the intrinsic asymmetry between the connect and
/// accept paths. An outbound stream reserved a source port through the
/// [`Socks5AutoConnector`], which owns the matching route entry and clears it on
/// drop. An accepted stream instead inherits its port and peer from the
/// listener, so it carries merely a [`Socks5EntryGuard`].
enum DataPlaneTcpStreamRoute {
    Outbound {
        _connector: Box<dyn std::any::Any + Send>,
    },
    Accepted {
        _entry: Socks5EntryGuard<GatewayEntryData>,
    },
}

/// A TCP stream created by the data plane API.
/// Can be either an actively requested outbound connection or an outbound request accepted from a TCP listener.
pub struct DataPlaneTcpStream {
    stream: GatewayTcpStream,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
    _route: DataPlaneTcpStreamRoute,
}

/// A TCP listener created by the data plane API.
/// It accepts inbound connections and produces [`DataPlaneTcpStream`]s.
pub struct DataPlaneTcpListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    entries: GatewayEntrySet,
    _listen_route: Socks5EntryGuard<GatewayEntryData>,
    _data_plane_ref: DataPlaneRef,
}

pub struct DataPlaneUdpSocket {
    socket: Arc<GatewayUdpSocket>,
    entries: GatewayEntrySet,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
}

impl Drop for DataPlaneRef {
    fn drop(&mut self) {
        if self.refs.fetch_sub(1, Ordering::Relaxed) == 1 {
            self.notifier.notify_one();
        }
    }
}

impl DataPlaneTcpStream {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl DataPlaneTcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept(&mut self) -> Result<(DataPlaneTcpStream, SocketAddr), std::io::Error> {
        let (stream, peer_addr) = self.listener.accept().await?;
        let local_addr = stream.local_addr()?;
        let (route, _) = Socks5EntryGuard::register(
            self.entries.clone(),
            Socks5Entry {
                src: local_addr,
                dst: peer_addr,
                kind: TCP_ENTRY,
            },
            GatewayEntryData::DataPlaneRoute,
        );
        let accepted = DataPlaneTcpStream {
            stream: Box::new(stream),
            local_addr,
            _data_plane_ref: self._data_plane_ref.clone(),
            _route: DataPlaneTcpStreamRoute::Accepted { _entry: route },
        };
        Ok((accepted, peer_addr))
    }
}

impl AsyncRead for DataPlaneTcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DataPlaneTcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl DataPlaneUdpSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, std::io::Error> {
        let key = Socks5Entry {
            src: self.local_addr,
            dst: addr,
            kind: UDP_ENTRY,
        };
        self.entries.try_insert(
            key,
            GatewayEntryData::Udp((
                self.socket.clone(),
                UdpClientKey {
                    client_addr: self.local_addr,
                    dst_addr: addr,
                },
            )),
        );
        self.socket.send_to(buf, addr).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.socket.recv_from(buf).await
    }
}

impl Drop for DataPlaneUdpSocket {
    fn drop(&mut self) {
        self.entries.retain(|_, data| match data {
            GatewayEntryData::Udp((socket, _)) if Arc::ptr_eq(socket, &self.socket) => false,
            _ => true,
        });
    }
}

impl Clone for DataPlaneRef {
    fn clone(&self) -> Self {
        self.refs.fetch_add(1, Ordering::Relaxed);
        Self {
            refs: self.refs.clone(),
            notifier: self.notifier.clone(),
        }
    }
}

impl<H> GatewayModule<H>
where
    H: VirtualTcpSocketFactory + VirtualTcpListenerFactory + VirtualUdpSocketFactory,
{
    fn acquire_data_plane_ref(&self) -> DataPlaneRef {
        self.data_plane_refs.fetch_add(1, Ordering::Relaxed);
        self.port_forward_list_change_notifier.notify_one();
        DataPlaneRef {
            refs: self.data_plane_refs.clone(),
            notifier: self.port_forward_list_change_notifier.clone(),
        }
    }

    async fn wait_data_plane_net(
        &self,
        deadline: Instant,
    ) -> anyhow::Result<(cidr::Ipv4Inet, Arc<Net>)> {
        let mut ready = self.data_plane_net_ready.subscribe();
        loop {
            if let Some(net) = self
                .net
                .lock()
                .await
                .as_ref()
                .map(|net| (net.ipv4_addr, net.smoltcp_net.clone()))
            {
                return Ok(net);
            }

            let now = Instant::now();
            if now >= deadline {
                return Err(anyhow::anyhow!("data plane net is not ready"));
            }
            let _ = tokio::time::timeout(deadline - now, ready.wait_for(|ready| *ready)).await;
        }
    }

    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpStream> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        // FIXME: This is the data-plane source address reserved for route
        // matching. `Socks5AutoConnector` may fall back to direct TCP for
        // non-virtual destinations, so this is not always the OS socket's
        // local address.
        let local_port = smoltcp_net.get_port();
        let local_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let connector = Socks5AutoConnector {
            transport_proxy: self.transport_proxy.clone(),
            peer_mgr: self.peer_manager.clone(),
            entries: self.entries.clone(),
            smoltcp_net: Some(smoltcp_net),
            src_addr: local_addr,
            host: self.host.clone(),
            socket_context: self.socket_context.clone(),
            kernel_purpose: TcpSocketPurpose::DataPlane,
            inner_connector: parking_lot::Mutex::new(None),
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        let inner_timeout_s = remaining.as_secs().saturating_add(1);
        let stream =
            tokio::time::timeout(remaining, connector.tcp_connect(dst_addr, inner_timeout_s))
                .await
                .with_context(|| "data plane tcp connect timeout")?
                .map_err(anyhow::Error::from)?;
        Ok(DataPlaneTcpStream {
            stream,
            local_addr,
            _data_plane_ref: data_plane_ref,
            _route: DataPlaneTcpStreamRoute::Outbound {
                _connector: Box::new(connector),
            },
        })
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpListener> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let listener = smoltcp_net.tcp_bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let listen_route = Socks5EntryGuard::try_register(
            self.entries.clone(),
            Socks5Entry {
                src: local_addr,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: TCP_LISTEN_ENTRY,
            },
            GatewayEntryData::DataPlaneRoute,
        )
        .ok_or_else(|| anyhow::anyhow!("data plane tcp listener already exists"))?;

        Ok(DataPlaneTcpListener {
            listener,
            local_addr,
            entries: self.entries.clone(),
            _listen_route: listen_route,
            _data_plane_ref: data_plane_ref,
        })
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneUdpSocket> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let smol = smoltcp_net.udp_bind(bind_addr).await?;
        let local_addr = smol.local_addr()?;
        let socket = Arc::new(GatewayUdpSocket::SmolUdpSocket(smol));

        Ok(DataPlaneUdpSocket {
            socket,
            entries: self.entries.clone(),
            local_addr,
            _data_plane_ref: data_plane_ref,
        })
    }
}

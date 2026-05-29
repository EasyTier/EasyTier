//! Data-plane access built on top of the `Socks5Server` smoltcp stack.
//!
//! This module exposes TCP streams and UDP sockets (mainly for FFI callers that
//! send traffic through EasyTier without creating OS-level proxy listeners).
//!
//! Typical usage:
//!
//! ```ignore
//! let instance = Instance::new(cfg);
//! instance.run().await?;
//! let socks5_server = instance.get_socks5_server();
//!
//! let socket = socks5_server.data_plane_udp_bind(local_port, timeout).await?;
//! socket.send_to(buf, peer_addr).await?;
//! ```

use std::{
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use anyhow::Context as _;
use dashmap::mapref::entry::Entry;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{common::error::Error, gateway::fast_socks5::server::AsyncTcpConnector};

use super::{
    Socks5AutoConnector, Socks5Entry, Socks5EntryData, Socks5EntrySet, Socks5Server,
    SocksTcpStream, SocksUdpSocket, UDP_ENTRY, UdpClientKey,
};
use crate::gateway::tokio_smoltcp::Net;

struct DataPlaneRef {
    refs: Arc<AtomicUsize>,
    notifier: Arc<tokio::sync::Notify>,
}

type DataPlaneRouteGuard = Socks5AutoConnector;

pub struct DataPlaneTcpStream {
    stream: SocksTcpStream,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
    _route_guard: DataPlaneRouteGuard,
}

pub struct DataPlaneUdpSocket {
    socket: Arc<SocksUdpSocket>,
    entries: Socks5EntrySet,
    entry_count: Arc<AtomicUsize>,
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
            entry_type: UDP_ENTRY,
        };
        if let Entry::Vacant(entry) = self.entries.entry(key) {
            entry.insert(Socks5EntryData::Udp((
                self.socket.clone(),
                UdpClientKey {
                    client_addr: self.local_addr,
                    dst_addr: addr,
                },
            )));
            self.entry_count.fetch_add(1, Ordering::Relaxed);
        }
        self.socket.send_to(buf, addr).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), std::io::Error> {
        self.socket.recv_from(buf).await
    }
}

impl Drop for DataPlaneUdpSocket {
    fn drop(&mut self) {
        self.entries.retain(|_, data| match data {
            Socks5EntryData::Udp((socket, _)) if Arc::ptr_eq(socket, &self.socket) => {
                self.entry_count.fetch_sub(1, Ordering::Relaxed);
                false
            }
            _ => true,
        });
    }
}

impl Socks5Server {
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
    ) -> Result<(cidr::Ipv4Inet, Arc<Net>), Error> {
        let notifier = self.port_forward_list_change_notifier.clone();
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
                return Err(anyhow::anyhow!("data plane net is not ready").into());
            }
            let _ = tokio::time::timeout(deadline - now, notifier.notified()).await;
        }
    }

    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> Result<DataPlaneTcpStream, Error> {
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
            #[cfg(feature = "kcp")]
            kcp_endpoint: self.kcp_endpoint.lock().await.clone(),
            peer_mgr: self.peer_manager.clone(),
            entries: self.entries.clone(),
            smoltcp_net: Some(smoltcp_net),
            src_addr: local_addr,
            entry_count: self.entry_count.clone(),
            inner_connector: parking_lot::Mutex::new(None),
        };

        let remaining = deadline.saturating_duration_since(Instant::now());
        let inner_timeout_s = remaining.as_secs().saturating_add(1);
        let stream = tokio::time::timeout(
            remaining,
            connector.tcp_connect(dst_addr, inner_timeout_s),
        )
        .await
        .with_context(|| "data plane tcp connect timeout")?
        .map_err(anyhow::Error::from)?;
        Ok(DataPlaneTcpStream {
            stream,
            local_addr,
            _data_plane_ref: data_plane_ref,
            _route_guard: connector,
        })
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> Result<DataPlaneUdpSocket, Error> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let smol = smoltcp_net.udp_bind(bind_addr).await?;
        let local_addr = smol.local_addr()?;
        let socket = Arc::new(SocksUdpSocket::SmolUdpSocket(smol));

        Ok(DataPlaneUdpSocket {
            socket,
            entries: self.entries.clone(),
            entry_count: self.entry_count.clone(),
            local_addr,
            _data_plane_ref: data_plane_ref,
        })
    }
}

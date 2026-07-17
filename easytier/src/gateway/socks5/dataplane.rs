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

use crate::{common::error::Error, gateway::fast_socks5::server::AsyncTcpConnector};

use super::{
    Socks5AutoConnector, Socks5Entry, Socks5EntryData, Socks5EntrySet, Socks5Server,
    SocksTcpStream, SocksUdpSocket, TCP_ENTRY, TCP_LISTEN_ENTRY, UDP_ENTRY, UdpClientKey,
    decrement_entry_count, insert_entry_and_increment_count, try_insert_entry_and_increment_count,
};
use crate::gateway::tokio_smoltcp::{Net, TcpListener};

struct DataPlaneRef {
    refs: Arc<AtomicUsize>,
    notifier: Arc<tokio::sync::Notify>,
}

/// A route-table entry whose lifetime is tied to this value: constructing it
/// reserves the route and bumps the active-entry count, dropping it removes the
/// route and drops the count back.
struct OwnedRouteEntry {
    entries: Socks5EntrySet,
    entry_count: Arc<AtomicUsize>,
    entry: Socks5Entry,
}

impl OwnedRouteEntry {
    /// Inserts the route, replacing any existing entry for the same key.
    fn register(
        entries: Socks5EntrySet,
        entry_count: Arc<AtomicUsize>,
        entry: Socks5Entry,
    ) -> Self {
        insert_entry_and_increment_count(
            &entries,
            &entry_count,
            entry.clone(),
            Socks5EntryData::DataPlaneRoute,
        );
        Self {
            entries,
            entry_count,
            entry,
        }
    }

    /// Inserts the route only if the key is free, returning `None` on conflict.
    fn try_register(
        entries: Socks5EntrySet,
        entry_count: Arc<AtomicUsize>,
        entry: Socks5Entry,
    ) -> Option<Self> {
        if !try_insert_entry_and_increment_count(
            &entries,
            &entry_count,
            entry.clone(),
            Socks5EntryData::DataPlaneRoute,
        ) {
            return None;
        }
        Some(Self {
            entries,
            entry_count,
            entry,
        })
    }
}

impl Drop for OwnedRouteEntry {
    fn drop(&mut self) {
        if self.entries.remove(&self.entry).is_some() {
            decrement_entry_count(&self.entry_count);
        }
    }
}

/// Tracks how an established data-plane TCP stream keeps its inbound route alive.
///
/// The two variants capture the intrinsic asymmetry between the connect and
/// accept paths. An outbound stream reserved a source port through the
/// [`Socks5AutoConnector`], which owns the matching route entry and clears it on
/// drop. An accepted stream instead inherits its port and peer from the
/// listener, so it carries merely an [`OwnedRouteEntry`].
enum DataPlaneTcpStreamRoute {
    Outbound(Socks5AutoConnector),
    Accepted(OwnedRouteEntry),
}

/// A TCP stream created by the data plane API.
/// Can be either an actively requested outbound connection or an outbound request accepted from a TCP listener.
pub struct DataPlaneTcpStream {
    stream: SocksTcpStream,
    local_addr: SocketAddr,
    _data_plane_ref: DataPlaneRef,
    _route: DataPlaneTcpStreamRoute,
}

/// A TCP listener created by the data plane API.
/// It accepts inbound connections and produces [`DataPlaneTcpStream`]s.
pub struct DataPlaneTcpListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    entries: Socks5EntrySet,
    entry_count: Arc<AtomicUsize>,
    _listen_route: OwnedRouteEntry,
    _data_plane_ref: DataPlaneRef,
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

impl DataPlaneTcpListener {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn accept(&mut self) -> Result<(DataPlaneTcpStream, SocketAddr), std::io::Error> {
        let (stream, peer_addr) = self.listener.accept().await?;
        let local_addr = stream.local_addr()?;
        let route = OwnedRouteEntry::register(
            self.entries.clone(),
            self.entry_count.clone(),
            Socks5Entry {
                src: local_addr,
                dst: peer_addr,
                entry_type: TCP_ENTRY,
            },
        );
        let accepted = DataPlaneTcpStream {
            stream: SocksTcpStream::SmolTcp(stream),
            local_addr,
            _data_plane_ref: self._data_plane_ref.clone(),
            _route: DataPlaneTcpStreamRoute::Accepted(route),
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
            entry_type: UDP_ENTRY,
        };
        try_insert_entry_and_increment_count(
            &self.entries,
            &self.entry_count,
            key,
            Socks5EntryData::Udp((
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
        let mut removed_entries = 0;
        self.entries.retain(|_, data| match data {
            Socks5EntryData::Udp((socket, _)) if Arc::ptr_eq(socket, &self.socket) => {
                removed_entries += 1;
                false
            }
            _ => true,
        });
        super::decrement_entry_count_by(&self.entry_count, removed_entries);
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
                return Err(anyhow::anyhow!("data plane net is not ready").into());
            }
            let _ = tokio::time::timeout(deadline - now, ready.wait_for(|ready| *ready)).await;
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
        let stream =
            tokio::time::timeout(remaining, connector.tcp_connect(dst_addr, inner_timeout_s))
                .await
                .with_context(|| "data plane tcp connect timeout")?
                .map_err(anyhow::Error::from)?;
        Ok(DataPlaneTcpStream {
            stream,
            local_addr,
            _data_plane_ref: data_plane_ref,
            _route: DataPlaneTcpStreamRoute::Outbound(connector),
        })
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> Result<DataPlaneTcpListener, Error> {
        let data_plane_ref = self.acquire_data_plane_ref();
        let deadline = Instant::now() + timeout;
        let (ipv4_addr, smoltcp_net) = self.wait_data_plane_net(deadline).await?;
        let bind_addr = SocketAddr::new(IpAddr::V4(ipv4_addr.address()), local_port);
        let listener = smoltcp_net.tcp_bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let listen_route = OwnedRouteEntry::try_register(
            self.entries.clone(),
            self.entry_count.clone(),
            Socks5Entry {
                src: local_addr,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                entry_type: TCP_LISTEN_ENTRY,
            },
        )
        .ok_or_else(|| anyhow::anyhow!("data plane tcp listener already exists"))?;

        Ok(DataPlaneTcpListener {
            listener,
            local_addr,
            entries: self.entries.clone(),
            entry_count: self.entry_count.clone(),
            _listen_route: listen_route,
            _data_plane_ref: data_plane_ref,
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::Socks5Server;
    use crate::peers::peer_manager::PeerManager;
    use crate::peers::tests::{connect_peer_manager, create_mock_peer_manager};
    use crate::tunnel::common::tests::wait_for_condition;

    /// A peer and its data-plane server. `Socks5Server` only holds a `Weak`
    /// reference to the `PeerManager`, so the manager must be kept alive by the
    /// test for the server's smoltcp <-> peer routing to work.
    struct Endpoint {
        _peer: std::sync::Arc<PeerManager>,
        server: std::sync::Arc<Socks5Server>,
        ip: cidr::Ipv4Inet,
    }

    /// Brings up two peers connected by a ring tunnel, each with a virtual IPv4
    /// and a running `Socks5Server`, and waits until the route to `b`'s IPv4 is
    /// visible from `a`. `run(None)` leaves the kcp endpoint unset, so the
    /// connect path goes through smoltcp, matching the listener side under test.
    async fn setup_pair() -> (Endpoint, Endpoint) {
        let a = create_mock_peer_manager().await;
        let b = create_mock_peer_manager().await;
        connect_peer_manager(a.clone(), b.clone()).await;

        let a_ip: cidr::Ipv4Inet = "10.126.126.1/24".parse().unwrap();
        let b_ip: cidr::Ipv4Inet = "10.126.126.2/24".parse().unwrap();
        a.get_global_ctx().set_ipv4(Some(a_ip));
        b.get_global_ctx().set_ipv4(Some(b_ip));

        let server_a = Socks5Server::new(a.get_global_ctx(), a.clone(), None);
        let server_b = Socks5Server::new(b.get_global_ctx(), b.clone(), None);
        server_a.run(None).await.unwrap();
        server_b.run(None).await.unwrap();

        wait_for_condition(
            || async {
                a.get_route()
                    .get_peer_id_by_ipv4(&b_ip.address())
                    .await
                    .is_some()
            },
            Duration::from_secs(10),
        )
        .await;

        (
            Endpoint {
                _peer: a,
                server: server_a,
                ip: a_ip,
            },
            Endpoint {
                _peer: b,
                server: server_b,
                ip: b_ip,
            },
        )
    }

    #[tokio::test]
    async fn data_plane_tcp_pingpong() {
        let (ep_a, ep_b) = setup_pair().await;
        let (server_a, server_b, b_ip) = (ep_a.server, ep_b.server, ep_b.ip);
        let timeout = Duration::from_secs(10);

        let mut listener = server_b.data_plane_tcp_bind(0, timeout).await.unwrap();
        let listen_addr =
            std::net::SocketAddr::new(b_ip.address().into(), listener.local_addr().port());

        let accept = tokio::spawn(async move {
            let (mut stream, _peer) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            // Hold the listener and stream until the client has read the reply.
            tokio::time::sleep(Duration::from_secs(1)).await;
        });

        let mut client = server_a
            .data_plane_tcp_connect(listen_addr, timeout)
            .await
            .unwrap();
        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        accept.await.unwrap();
    }

    #[tokio::test]
    async fn data_plane_udp_pingpong() {
        let (ep_a, ep_b) = setup_pair().await;
        let (server_a, a_ip, server_b, b_ip) = (ep_a.server, ep_a.ip, ep_b.server, ep_b.ip);
        let timeout = Duration::from_secs(10);

        let sock_a = server_a.data_plane_udp_bind(0, timeout).await.unwrap();
        let sock_b = server_b.data_plane_udp_bind(0, timeout).await.unwrap();
        let addr_a = std::net::SocketAddr::new(a_ip.address().into(), sock_a.local_addr().port());
        let addr_b = std::net::SocketAddr::new(b_ip.address().into(), sock_b.local_addr().port());

        // UDP data-plane routes are connected-style: a socket only accepts
        // inbound datagrams from a peer it has already sent to, because the
        // route entry is registered by `send_to`. Prime b's route toward a so
        // the upcoming ping is routed instead of dropped at b's packet filter.
        // This datagram is dropped at a (a has no route yet) and is not awaited.
        sock_b.send_to(b"warmup", addr_a).await.unwrap();

        sock_a.send_to(b"ping", addr_b).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = tokio::time::timeout(timeout, sock_b.recv_from(&mut buf))
            .await
            .expect("recv ping timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(from, addr_a);

        sock_b.send_to(b"pong", addr_a).await.unwrap();
        // a may also receive the stray warmup datagram (it arrives once a has
        // registered its route by sending the ping above), so skip anything
        // that is not the reply.
        loop {
            let (n, from) = tokio::time::timeout(timeout, sock_a.recv_from(&mut buf))
                .await
                .expect("recv pong timed out")
                .unwrap();
            if &buf[..n] == b"pong" {
                assert_eq!(from, addr_b);
                break;
            }
        }
    }
}

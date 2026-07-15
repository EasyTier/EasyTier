use bon::builder;
use futures::{Future, stream::FuturesUnordered};
use network_interface::NetworkInterfaceConfig as _;
use std::net::{IpAddr, SocketAddr};

use super::TunnelError;
use crate::common::netns::NetNS;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio_stream::StreamExt;

pub(crate) fn get_interface_name_by_ip(local_ip: &IpAddr) -> Option<String> {
    if local_ip.is_unspecified() || local_ip.is_multicast() {
        return None;
    }
    let ifaces = network_interface::NetworkInterface::show().ok()?;
    for iface in ifaces {
        for addr in iface.addr {
            if addr.ip() == *local_ip {
                return Some(iface.name);
            }
        }
    }

    tracing::error!(?local_ip, "can not find interface name by ip");
    None
}

pub(crate) async fn wait_for_connect_futures<Fut, Ret, E>(
    mut futures: FuturesUnordered<Fut>,
) -> Result<Ret, TunnelError>
where
    Fut: Future<Output = Result<Ret, E>> + Send,
    E: std::error::Error + Into<TunnelError> + Send + 'static,
{
    // return last error
    let mut last_err = None;

    while let Some(ret) = futures.next().await {
        if let Err(e) = ret {
            last_err = Some(e.into());
        } else {
            return ret.map_err(|e| e.into());
        }
    }

    Err(last_err.unwrap_or(TunnelError::Shutdown))
}

// region bind

pub trait Bindable: Sized {
    const TYPE: socket2::Type;
    const PROTOCOL: Option<socket2::Protocol>;

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError>;
}

impl Bindable for TcpSocket {
    const TYPE: socket2::Type = socket2::Type::STREAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::TCP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        let socket = TcpSocket::from_std_stream(socket.into());

        if let Err(error) = socket.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay failed for tcp socket");
        }

        Ok(socket)
    }
}

impl Bindable for TcpListener {
    const TYPE: socket2::Type = socket2::Type::STREAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::TCP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        Ok(TcpSocket::finalize(socket)?.listen(1024)?)
    }
}

impl Bindable for UdpSocket {
    const TYPE: socket2::Type = socket2::Type::DGRAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::UDP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        Ok(UdpSocket::from_std(socket.into())?)
    }
}

fn setup_socket2_ext(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
    #[allow(unused_variables)] bind_dev: Option<String>,
    only_v6: bool,
    reuse_addr: bool,
    reuse_port: bool,
    socket_mark: Option<u32>,
) -> Result<(), TunnelError> {
    #[cfg(target_os = "windows")]
    {
        let is_udp = matches!(socket2_socket.r#type()?, socket2::Type::DGRAM);
        crate::arch::windows::setup_socket_for_win(socket2_socket, bind_addr, bind_dev, is_udp)?;
    }

    if bind_addr.is_ipv6() {
        socket2_socket.set_only_v6(only_v6)?;
    }

    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(reuse_addr)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if reuse_port {
        socket2_socket.set_reuse_port(true)?;
    }
    #[cfg(not(all(unix, not(target_os = "solaris"), not(target_os = "illumos"))))]
    {
        let _ = reuse_port;
    }

    // SO_MARK must be set before bind() so the kernel applies the mark to
    // any source-address selection bind() triggers on unspecified binds.
    // Accepted child sockets inherit the mark from the listener on Linux.
    apply_socket_mark(socket2_socket, socket_mark)?;

    if let Err(e) = socket2_socket.bind(&socket2::SockAddr::from(*bind_addr)) {
        if bind_addr.is_ipv4() {
            return Err(e.into());
        } else {
            tracing::warn!(?e, "bind failed, do not return error for ipv6");
        }
    }

    // linux/mac does not use interface of bind_addr to send packet, so we need to bind device
    // win can handle this with bind correctly
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Some(dev_name) = bind_dev {
        // use IP_BOUND_IF to bind device
        let c_dev_name = std::ffi::CString::new(dev_name.clone()).map_err(|err| {
            TunnelError::InvalidAddr(format!("invalid interface name {dev_name}: {err}"))
        })?;
        let dev_idx = unsafe { nix::libc::if_nametoindex(c_dev_name.as_ptr()) };
        let Some(dev_idx) = std::num::NonZeroU32::new(dev_idx) else {
            return Err(TunnelError::InvalidAddr(format!(
                "network interface not found: {dev_name}"
            )));
        };
        tracing::warn!(?dev_idx, ?dev_name, "bind device");
        if bind_addr.is_ipv4() {
            socket2_socket.bind_device_by_index_v4(Some(dev_idx))?;
        } else {
            socket2_socket.bind_device_by_index_v6(Some(dev_idx))?;
        }
        tracing::warn!(?dev_idx, ?dev_name, "bind device done");
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_env = "ohos"
    ))]
    if let Some(dev_name) = bind_dev {
        tracing::trace!(dev_name = ?dev_name, "bind device");
        socket2_socket.bind_device(Some(dev_name.as_bytes()))?;
    }

    Ok(())
}

/// Apply Linux SO_MARK (a.k.a. fwmark) to a `socket2::Socket`. `None` leaves
/// SO_MARK untouched (kernel default 0); `Some(mark)` applies that exact value
/// — including `Some(0)`, which is a legitimate mark. On non-Linux platforms
/// this is unconditionally a no-op.
///
/// Exposed so transports that bypass [`bind`] (currently the WebSocket
/// default-bind path and FakeTCP) can apply the same mark.
pub fn apply_socket_mark(
    socket: &socket2::Socket,
    socket_mark: Option<u32>,
) -> Result<(), TunnelError> {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(mark) = socket_mark {
        tracing::trace!(socket_mark = mark, "set SO_MARK on socket");
        socket.set_mark(mark)?;
    }
    #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
    {
        let _ = (socket, socket_mark);
    }
    Ok(())
}

#[derive(Debug, Default, Clone)]
pub enum BindDev {
    #[default]
    Auto,
    Disabled,
    Custom(String),
}

impl From<String> for BindDev {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::Disabled
        } else {
            Self::Custom(value)
        }
    }
}

impl From<&str> for BindDev {
    fn from(value: &str) -> Self {
        value.to_string().into()
    }
}

/// Binds a socket to a specific address and optionally a network interface.
///
/// This function creates a new socket, applies specific configurations (such as
/// binding to a device or setting IPv6-only flags), and finalizes it into the
/// requested [`Bindable`] type.
///
/// # Arguments
///
/// * `addr` - The `SocketAddr` to bind the socket to.
/// * `dev` - The name of the network interface to bind to:
///   * **(default) `BindDev::Auto`**: Enables **auto-discovery**. The function will attempt to automatically
///     resolve the interface name associated with the provided `addr.ip()`.
///   * **empty string or `BindDev::Disabled`**: **Disables** auto-discovery and
///     explicitly chooses **not** to bind to any specific device. The routing will be
///     left entirely to the OS.
///   * **non-empty string or `BindDev::Custom(..)`**: Skips auto-discovery and explicitly binds to
///     the specified interface.
/// * `net_ns` - An optional network namespace to switch into before creating the socket.
/// * `only_v6` - If `true`, sets the `IPV6_V6ONLY` flag on the socket.
///
/// # Errors
///
/// Returns a [`TunnelError`] if socket creation, configuration, or finalization fails.
#[builder]
pub fn bind<B: Bindable>(
    addr: SocketAddr,
    #[builder(default, into)] dev: BindDev,
    net_ns: Option<NetNS>,
    #[builder(default)] only_v6: bool,
    #[builder(default = !cfg!(target_os = "windows"))] reuse_addr: bool,
    #[builder(default)] reuse_port: bool,
    /// Linux SO_MARK (fwmark) to apply to the socket. `None` leaves SO_MARK
    /// untouched; `Some(mark)` applies that exact value, including `Some(0)`.
    socket_mark: Option<u32>,
) -> Result<B, TunnelError> {
    let _g = net_ns.map(|n| n.guard());
    let dev = match dev {
        BindDev::Auto => get_interface_name_by_ip(&addr.ip()),
        BindDev::Disabled => None,
        BindDev::Custom(s) => Some(s),
    };
    let socket = socket2::Socket::new(socket2::Domain::for_address(addr), B::TYPE, B::PROTOCOL)?;
    setup_socket2_ext(
        &socket,
        &addr,
        dev,
        only_v6,
        reuse_addr,
        reuse_port,
        socket_mark,
    )?;
    B::finalize(socket)
}

// endregion

pub mod tests {
    use atomic_shim::AtomicU64;
    use std::{sync::Arc, time::Instant};

    use futures::{Future, SinkExt, StreamExt};
    use tokio_util::bytes::{BufMut, Bytes, BytesMut};

    use easytier_core::{
        connectivity::protocol::raw::TunnelDialer, listener::SocketListener, packet::ZCPacket,
        tunnel::Tunnel,
    };

    use crate::common::netns::NetNS;

    #[cfg(test)]
    use crate::tunnel::TunnelError;
    #[cfg(test)]
    use easytier_core::packet::{PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE};
    #[cfg(test)]
    use easytier_core::tunnel::framed::FramedReader;

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[test]
    fn apply_socket_mark_none_is_noop_and_does_not_error() {
        // The contract for `None` is "no syscall is made and no error is
        // returned" — must not require CAP_NET_ADMIN to call.
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        super::apply_socket_mark(&socket, None).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_NET_ADMIN; run as root or with sudo -E cargo test"]
    fn apply_socket_mark_sets_so_mark_when_capable() {
        use nix::libc;
        use std::os::fd::AsRawFd;

        fn read_so_mark(s: &socket2::Socket) -> u32 {
            let mut value: libc::c_int = 0;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let r = unsafe {
                libc::getsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mut value as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(r, 0, "getsockopt(SO_MARK) failed");
            value as u32
        }

        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        super::apply_socket_mark(&socket, Some(0x1234))
            .expect("set_mark failed; need CAP_NET_ADMIN");
        assert_eq!(read_so_mark(&socket), 0x1234);

        // Some(0) is a legitimate value: it must reach setsockopt and clear
        // the mark, distinct from None which makes no syscall.
        super::apply_socket_mark(&socket, Some(0)).expect("set_mark(0) failed");
        assert_eq!(read_so_mark(&socket), 0);
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_env = "ohos"
    ))]
    #[test]
    fn bind_custom_device_is_applied_for_unspecified_addr() {
        use std::net::SocketAddr;
        use tokio::net::UdpSocket;

        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let _err = super::bind::<UdpSocket>()
            .addr(addr)
            .dev("et/invalid-device-name")
            .call()
            .expect_err("custom device must not be skipped for unspecified bind addr");
    }

    #[test]
    fn framed_reader_rejects_short_peer_manager_body() {
        let mut buf = BytesMut::new();
        buf.put_u32_le((PEER_MANAGER_HEADER_SIZE - 1) as u32);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE - 1, 0);

        let ret = FramedReader::<tokio::io::Empty>::extract_one_packet(&mut buf, 2000);

        assert!(matches!(
            ret,
            Some(Err(TunnelError::InvalidPacket(msg))) if msg == "body too short"
        ));
    }

    pub async fn _tunnel_echo_server(tunnel: Box<dyn Tunnel>, once: bool) {
        let (mut recv, mut send) = tunnel.split();

        if !once {
            while let Some(item) = recv.next().await {
                let Ok(msg) = item else {
                    continue;
                };
                tracing::debug!(?msg, "recv a msg, try echo back");
                if send.send(msg).await.is_err() {
                    break;
                }
            }
        } else {
            let Some(ret) = recv.next().await else {
                panic!("recv error");
            };

            if ret.is_err() {
                tracing::debug!(?ret, "recv error");
                return;
            }

            let res = ret.unwrap();
            tracing::debug!(?res, "recv a msg, try echo back");
            send.send(res).await.unwrap();
        }
        let _ = send.flush().await;
        let _ = send.close().await;

        tracing::warn!("echo server exit...");
    }

    pub(crate) async fn _tunnel_pingpong<L, C>(listener: L, connector: C)
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        _tunnel_pingpong_netns_with_timeout(
            listener,
            connector,
            NetNS::new(None),
            NetNS::new(None),
            "12345678abcdefg".as_bytes().to_vec(),
            // only used by tunnel test, so set a long timeout
            tokio::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
    }

    async fn _tunnel_pingpong_netns<L, C>(
        mut listener: L,
        connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
    ) where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        l_netns
            .run_async(|| async {
                listener.listen().await.unwrap();
            })
            .await;

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            println!("accept: {:?}", ret.info());
            assert_eq!(
                url::Url::from(ret.info().unwrap().local_addr.unwrap()),
                listener.local_url()
            );
            _tunnel_echo_server(ret, false).await
        });

        let tunnel = c_netns.run_async(|| connector.connect()).await.unwrap();
        println!("connect: {:?}", tunnel.info());

        if connector.remote_url().scheme() == "faketcp" {
            // listener need some time to start capturing packet
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }

        assert_eq!(
            url::Url::from(tunnel.info().unwrap().remote_addr.unwrap()),
            connector.remote_url(),
        );

        let (mut recv, mut send) = tunnel.split();

        send.send(ZCPacket::new_with_payload(buf.as_slice()))
            .await
            .unwrap();

        let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        println!("echo back: {:?}", ret);
        assert_eq!(ret.payload(), Bytes::from(buf));

        send.close().await.unwrap();

        if ["udp", "wg"].contains(&connector.remote_url().scheme()) {
            lis.abort();
        } else {
            // lis should finish in 1 second
            let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), lis).await;
            assert!(ret.is_ok());
        }
    }

    pub(crate) async fn _tunnel_pingpong_netns_with_timeout<L, C>(
        listener: L,
        connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
        timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error>
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        let handle = tokio::spawn(async move {
            _tunnel_pingpong_netns(listener, connector, l_netns, c_netns, buf).await;
        });

        match tokio::time::timeout(timeout, handle).await {
            Ok(join_res) => match join_res {
                Ok(_) => Ok(()),
                Err(join_err) => {
                    if join_err.is_panic() {
                        let payload = join_err.into_panic();
                        let msg = match payload.downcast::<String>() {
                            Ok(s) => *s,
                            Err(payload) => match payload.downcast::<&str>() {
                                Ok(s) => (*s).to_string(),
                                Err(_) => "non-string panic payload".to_string(),
                            },
                        };
                        Err(anyhow::anyhow!("task panicked: {}", msg))
                    } else {
                        Err(anyhow::anyhow!("task cancelled"))
                    }
                }
            },
            Err(elapsed) => Err(elapsed.into()),
        }
    }

    pub(crate) async fn _tunnel_bench<L, C>(listener: L, connector: C)
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        _tunnel_bench_netns(listener, connector, NetNS::new(None), NetNS::new(None)).await;
    }

    pub(crate) async fn _tunnel_bench_netns<L, C>(
        mut listener: L,
        connector: C,
        netns_l: NetNS,
        netns_c: NetNS,
    ) -> usize
    where
        L: SocketListener<Accepted = Box<dyn Tunnel>> + Sync + 'static,
        C: TunnelDialer,
    {
        {
            let _g = netns_l.guard();
            listener.listen().await.unwrap();
        }

        let bps = Arc::new(AtomicU64::new(0));
        let bps_clone = bps.clone();

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            // _tunnel_echo_server(ret, false).await
            let (mut r, _s) = ret.split();
            let now = Instant::now();
            let mut count = 0;
            while let Some(Ok(p)) = r.next().await {
                count += p.payload_len();
                let elapsed_sec = now.elapsed().as_secs();
                if elapsed_sec > 0 {
                    bps_clone.store(
                        count as u64 / now.elapsed().as_secs(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        });

        let tunnel = {
            let _g = netns_c.guard();
            connector.connect().await.unwrap()
        };

        let (_recv, mut send) = tunnel.split();

        // prepare a 4k buffer with random data
        let mut send_buf = BytesMut::new();
        for _ in 0..64 {
            send_buf.put_i128(rand::random::<i128>());
        }

        let now = Instant::now();
        while now.elapsed().as_secs() < 10 {
            // send.feed(item)
            let item = ZCPacket::new_with_payload(send_buf.as_ref());
            send.feed(item).await.unwrap();
        }

        send.close().await.unwrap();
        drop(send);
        drop(connector);
        drop(tunnel);

        tracing::warn!("wait for recv to finish...");
        let bps = bps.load(std::sync::atomic::Ordering::Acquire);
        println!("bps: {}", bps);

        lis.abort();
        bps as usize
    }

    pub async fn wait_for_condition<F, FRet>(mut condition: F, timeout: std::time::Duration)
    where
        F: FnMut() -> FRet + Send,
        FRet: Future<Output = bool>,
    {
        let now = std::time::Instant::now();
        while now.elapsed() < timeout {
            if condition().await {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(condition().await, "Timeout")
    }
}

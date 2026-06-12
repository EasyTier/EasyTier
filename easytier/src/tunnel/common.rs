use bon::builder;
use bytes::{Buf, Bytes, BytesMut};
use futures::{Future, Sink, stream::FuturesUnordered};
use network_interface::NetworkInterfaceConfig as _;
use pin_project_lite::pin_project;
use std::{
    any::Any,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Poll, ready},
};
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};
use tokio_stream::StreamExt;
use tokio_util::codec::Decoder;
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use super::TunnelInfo;
use super::{
    SinkItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
    packet_def::{TCP_TUNNEL_HEADER_SIZE, TCPTunnelHeader, ZCPacketType},
};
use crate::common::netns::NetNS;
use crate::tunnel::packet_def::{PEER_MANAGER_HEADER_SIZE, ZCPacket};
use crate::utils::buf::BufList;

pub struct TunnelWrapper<R, W> {
    reader: Arc<Mutex<Option<R>>>,
    writer: Arc<Mutex<Option<W>>>,
    info: Option<TunnelInfo>,
    associate_data: Option<Box<dyn Any + Send + 'static>>,
}

impl<R, W> TunnelWrapper<R, W> {
    pub fn new(reader: R, writer: W, info: Option<TunnelInfo>) -> Self {
        Self::new_with_associate_data(reader, writer, info, None)
    }

    pub fn new_with_associate_data(
        reader: R,
        writer: W,
        info: Option<TunnelInfo>,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        TunnelWrapper {
            reader: Arc::new(Mutex::new(Some(reader))),
            writer: Arc::new(Mutex::new(Some(writer))),
            info,
            associate_data,
        }
    }
}

impl<R, W> Tunnel for TunnelWrapper<R, W>
where
    R: ZCPacketStream + Send + 'static,
    W: ZCPacketSink + Send + 'static,
{
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>) {
        let reader = self.reader.lock().unwrap().take().unwrap();
        let writer = self.writer.lock().unwrap().take().unwrap();
        (Box::pin(reader), Box::pin(writer))
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

pub struct TunnelCodec {
    pub max_packet_size: usize,
}

impl Decoder for TunnelCodec {
    type Item = ZCPacket;
    type Error = TunnelError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let Some(header) = TCPTunnelHeader::ref_from_prefix(src) else {
            return Ok(None);
        };

        let len = {
            let len = header.len.get() as usize;
            if len > self.max_packet_size {
                return Err(TunnelError::InvalidPacket("body too long".to_string()));
            }
            if len < PEER_MANAGER_HEADER_SIZE {
                return Err(TunnelError::InvalidPacket("body too short".to_string()));
            }

            TCP_TUNNEL_HEADER_SIZE + len
        };

        if src.len() < len {
            if src.capacity() < len {
                src.reserve((len - src.len()).max(self.max_packet_size << 4));
            }
            return Ok(None);
        }

        let packet_buf = src.split_to(len);
        Ok(Some(ZCPacket::new_from_buf(packet_buf, ZCPacketType::TCP)))
    }
}

pin_project! {
    pub struct FramedWriter<W> {
        #[pin]
        writer: W,
        sending_bufs: BufList<Bytes>,
    }
}

impl<W> FramedWriter<W> {
    fn max_buffer_count(&self) -> usize {
        64
    }
}

impl<W> FramedWriter<W> {
    pub fn new(writer: W) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
        }
    }
}

impl<W> Sink<SinkItem> for FramedWriter<W>
where
    W: AsyncWrite + Send + 'static,
{
    type Error = TunnelError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let max_buffer_count = self.max_buffer_count();
        if self.sending_bufs.len() >= max_buffer_count {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: ZCPacket) -> Result<(), Self::Error> {
        let this = self.project();

        let mut packet = item.convert_type(ZCPacketType::TCP);
        let payload_len = packet.payload_len();
        let Some(header) = packet.mut_tcp_tunnel_header() else {
            return Err(TunnelError::InvalidPacket("packet too short".to_string()));
        };
        header
            .len
            .set((PEER_MANAGER_HEADER_SIZE + payload_len).try_into().unwrap());

        this.sending_bufs.push(packet.into_bytes());

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let mut pinned = self.project();
        while pinned.sending_bufs.has_remaining() {
            let n = ready!(poll_write_buf(
                pinned.writer.as_mut(),
                cx,
                pinned.sending_bufs
            ))?;
            if n == 0 {
                return Poll::Ready(Err(TunnelError::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write frame to transport",
                ))));
            }
        }

        ready!(pinned.writer.poll_flush(cx))?;

        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        ready!(self.as_mut().poll_flush(cx))?;
        ready!(self.project().writer.poll_shutdown(cx))?;

        Poll::Ready(Ok(()))
    }
}

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
    socket2_socket.set_reuse_address(!cfg!(target_os = "windows"))?;

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

    // #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    // socket2_socket.set_reuse_port(true)?;

    if bind_addr.ip().is_unspecified() {
        return Ok(());
    }

    // linux/mac does not use interface of bind_addr to send packet, so we need to bind device
    // win can handle this with bind correctly
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Some(dev_name) = bind_dev {
        // use IP_BOUND_IF to bind device
        unsafe {
            let dev_idx = nix::libc::if_nametoindex(dev_name.as_str().as_ptr() as *const i8);
            tracing::warn!(?dev_idx, ?dev_name, "bind device");
            if bind_addr.is_ipv4() {
                socket2_socket.bind_device_by_index_v4(std::num::NonZeroU32::new(dev_idx))?;
            } else {
                socket2_socket.bind_device_by_index_v6(std::num::NonZeroU32::new(dev_idx))?;
            }
            tracing::warn!(?dev_idx, ?dev_name, "bind device doen");
        }
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
    setup_socket2_ext(&socket, &addr, dev, only_v6, socket_mark)?;
    B::finalize(socket)
}

// endregion

pub fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() < min_size {
        buf.reserve(max_size);
    }
}

pub mod tests {
    use atomic_shim::AtomicU64;
    use futures::{Future, SinkExt, StreamExt};
    use std::{sync::Arc, time::Instant};
    use tokio_util::bytes::{BufMut, Bytes, BytesMut};

    #[cfg(test)]
    use crate::tunnel::{
        TunnelError,
        packet_def::{PEER_MANAGER_HEADER_SIZE, TCP_TUNNEL_HEADER_SIZE},
    };
    use crate::{
        common::netns::NetNS,
        tunnel::{TunnelConnector, TunnelListener, packet_def::ZCPacket},
    };

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

    #[test]
    fn framed_reader_rejects_short_peer_manager_body() {
        use crate::tunnel::common::TunnelCodec;
        use tokio_util::codec::Decoder;

        let mut buf = BytesMut::new();
        buf.put_u32_le((PEER_MANAGER_HEADER_SIZE - 1) as u32);
        buf.resize(TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE - 1, 0);

        let ret = TunnelCodec {
            max_packet_size: 2000,
        }
        .decode(&mut buf);

        assert!(matches!(
            ret,
            Err(TunnelError::InvalidPacket(msg)) if msg == "body too short"
        ));
    }

    pub async fn _tunnel_echo_server(tunnel: Box<dyn super::Tunnel>, once: bool) {
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
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
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
        mut connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
        buf: Vec<u8>,
    ) where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
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
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
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
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        _tunnel_bench_netns(listener, connector, NetNS::new(None), NetNS::new(None)).await;
    }

    pub(crate) async fn _tunnel_bench_netns<L, C>(
        mut listener: L,
        mut connector: C,
        netns_l: NetNS,
        netns_c: NetNS,
    ) -> usize
    where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
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

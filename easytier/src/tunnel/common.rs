use std::{
    any::Any,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    task::{ready, Poll},
};

use futures::{stream::FuturesUnordered, Future, Sink, Stream};
use network_interface::NetworkInterfaceConfig as _;
use pin_project_lite::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tokio_stream::StreamExt;
use tokio_util::io::poll_write_buf;
use zerocopy::FromBytes as _;

use super::TunnelInfo;

use crate::tunnel::packet_def::{ZCPacket, PEER_MANAGER_HEADER_SIZE};

use super::{
    buf::BufList,
    packet_def::{TCPTunnelHeader, ZCPacketType, TCP_TUNNEL_HEADER_SIZE},
    SinkItem, StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
};

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

// a length delimited codec for async reader
pin_project! {
    pub struct FramedReader<R> {
        #[pin]
        reader: R,
        buf: BytesMut,
        max_packet_size: usize,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
        error: Option<TunnelError>,
    }
}

impl<R> FramedReader<R> {
    pub fn new(reader: R, max_packet_size: usize) -> Self {
        Self::new_with_associate_data(reader, max_packet_size, None)
    }

    pub fn new_with_associate_data(
        reader: R,
        max_packet_size: usize,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedReader {
            reader,
            buf: BytesMut::with_capacity(max_packet_size),
            max_packet_size,
            associate_data,
            error: None,
        }
    }

    fn extract_one_packet(
        buf: &mut BytesMut,
        max_packet_size: usize,
    ) -> Option<Result<ZCPacket, TunnelError>> {
        if buf.len() < TCP_TUNNEL_HEADER_SIZE {
            // header is not complete
            return None;
        }

        let header = TCPTunnelHeader::ref_from_prefix(&buf[..]).unwrap();
        let body_len = header.len.get() as usize;
        if body_len > max_packet_size {
            // body is too long
            return Some(Err(TunnelError::InvalidPacket("body too long".to_string())));
        }

        if buf.len() < TCP_TUNNEL_HEADER_SIZE + body_len {
            // body is not complete
            return None;
        }

        // extract one packet
        let packet_buf = buf.split_to(TCP_TUNNEL_HEADER_SIZE + body_len);
        Some(Ok(ZCPacket::new_from_buf(packet_buf, ZCPacketType::TCP)))
    }
}

impl<R> Stream for FramedReader<R>
where
    R: AsyncRead + Send + 'static + Unpin,
{
    type Item = StreamItem;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let mut self_mut = self.project();

        loop {
            if let Some(e) = self_mut.error.as_ref() {
                tracing::warn!("poll_next on a failed FramedReader, {:?}", e);
                return Poll::Ready(None);
            }

            while let Some(packet) =
                Self::extract_one_packet(self_mut.buf, *self_mut.max_packet_size)
            {
                if let Err(TunnelError::InvalidPacket(msg)) = packet.as_ref() {
                    self_mut
                        .error
                        .replace(TunnelError::InvalidPacket(msg.clone()));
                }
                return Poll::Ready(Some(packet));
            }

            reserve_buf(
                &mut self_mut.buf,
                *self_mut.max_packet_size,
                *self_mut.max_packet_size * 2,
            );

            let cap = self_mut.buf.capacity() - self_mut.buf.len();
            let buf = self_mut.buf.chunk_mut().as_mut_ptr();
            let buf = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
            let mut buf = ReadBuf::new(buf);

            let ret = ready!(self_mut.reader.as_mut().poll_read(cx, &mut buf));
            let len = buf.filled().len();
            unsafe { self_mut.buf.advance_mut(len) };

            match ret {
                Ok(_) => {
                    if len == 0 {
                        return Poll::Ready(None);
                    }
                }
                Err(e) => {
                    return Poll::Ready(Some(Err(TunnelError::IOError(e))));
                }
            }
        }
    }
}

pub trait ZCPacketToBytes {
    fn into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, TunnelError>;
}

pub struct TcpZCPacketToBytes;
impl ZCPacketToBytes for TcpZCPacketToBytes {
    fn into_bytes(&self, item: ZCPacket) -> Result<Bytes, TunnelError> {
        let mut item = item.convert_type(ZCPacketType::TCP);

        let tcp_len = PEER_MANAGER_HEADER_SIZE + item.payload_len();
        let Some(header) = item.mut_tcp_tunnel_header() else {
            return Err(TunnelError::InvalidPacket("packet too short".to_string()));
        };
        header.len.set(tcp_len.try_into().unwrap());

        Ok(item.into_bytes())
    }
}

pin_project! {
    pub struct FramedWriter<W, C> {
        #[pin]
        writer: W,
        sending_bufs: BufList<Bytes>,
        associate_data: Option<Box<dyn Any + Send + 'static>>,

        converter: C,
    }
}

impl<W, C> FramedWriter<W, C> {
    fn max_buffer_count(&self) -> usize {
        64
    }
}

impl<W> FramedWriter<W, TcpZCPacketToBytes> {
    pub fn new(writer: W) -> Self {
        Self::new_with_associate_data(writer, None)
    }

    pub fn new_with_associate_data(
        writer: W,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
            associate_data,
            converter: TcpZCPacketToBytes {},
        }
    }
}

impl<W, C: ZCPacketToBytes + Send + 'static> FramedWriter<W, C> {
    pub fn new_with_converter(writer: W, converter: C) -> Self {
        Self::new_with_converter_and_associate_data(writer, converter, None)
    }

    pub fn new_with_converter_and_associate_data(
        writer: W,
        converter: C,
        associate_data: Option<Box<dyn Any + Send + 'static>>,
    ) -> Self {
        FramedWriter {
            writer,
            sending_bufs: BufList::new(),
            associate_data,
            converter,
        }
    }
}

impl<W, C> Sink<SinkItem> for FramedWriter<W, C>
where
    W: AsyncWrite + Send + 'static,
    C: ZCPacketToBytes + Send + 'static,
{
    type Error = TunnelError;

    fn poll_ready(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        let max_buffer_count = self.max_buffer_count();
        if self.sending_bufs.bufs_cnt() >= max_buffer_count {
            self.as_mut().poll_flush(cx)
        } else {
            tracing::trace!(bufs_cnt = self.sending_bufs.bufs_cnt(), "ready to send");
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: ZCPacket) -> Result<(), Self::Error> {
        let pinned = self.project();
        pinned.sending_bufs.push(pinned.converter.into_bytes(item)?);

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let mut pinned = self.project();
        let mut remaining = pinned.sending_bufs.remaining();
        while remaining != 0 {
            let n = ready!(poll_write_buf(
                pinned.writer.as_mut(),
                cx,
                pinned.sending_bufs
            ))?;
            if n == 0 {
                return Poll::Ready(Err(TunnelError::IOError(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to \
                     write frame to transport",
                ))));
            }
            remaining -= n;
        }

        tracing::trace!(?remaining, "flushed");

        // Try flushing the underlying IO
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

pub(crate) fn setup_sokcet2_ext(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
    #[allow(unused_variables)] bind_dev: Option<String>,
) -> Result<(), TunnelError> {
    #[cfg(target_os = "windows")]
    {
        let is_udp = matches!(socket2_socket.r#type()?, socket2::Type::DGRAM);
        crate::arch::windows::setup_socket_for_win(socket2_socket, bind_addr, bind_dev, is_udp)?;
    }

    if bind_addr.is_ipv6() {
        socket2_socket.set_only_v6(true)?;
    }

    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(true)?;
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
            socket2_socket.bind_device_by_index_v4(std::num::NonZeroU32::new(dev_idx))?;
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

pub(crate) fn setup_sokcet2(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
) -> Result<(), TunnelError> {
    setup_sokcet2_ext(
        socket2_socket,
        bind_addr,
        super::common::get_interface_name_by_ip(&bind_addr.ip()),
    )
}

pub fn reserve_buf(buf: &mut BytesMut, min_size: usize, max_size: usize) {
    if buf.capacity() < min_size {
        buf.reserve(max_size);
    }
}

pub mod tests {
    use atomic_shim::AtomicU64;
    use std::{sync::Arc, time::Instant};

    use futures::{Future, SinkExt, StreamExt};
    use tokio_util::bytes::{BufMut, Bytes, BytesMut};

    use crate::{
        common::netns::NetNS,
        tunnel::{packet_def::ZCPacket, TunnelConnector, TunnelListener},
    };

    pub async fn _tunnel_echo_server(tunnel: Box<dyn super::Tunnel>, once: bool) {
        let (mut recv, mut send) = tunnel.split();

        if !once {
            while let Some(item) = recv.next().await {
                let Ok(msg) = item else {
                    continue;
                };
                tracing::debug!(?msg, "recv a msg, try echo back");
                if let Err(_) = send.send(msg).await {
                    break;
                }
            }
        } else {
            let Some(ret) = recv.next().await else {
                assert!(false, "recv error");
                return;
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
        _tunnel_pingpong_netns(
            listener,
            connector,
            NetNS::new(None),
            NetNS::new(None),
            "12345678abcdefg".as_bytes().to_vec(),
        )
        .await;
    }

    pub(crate) async fn _tunnel_pingpong_netns<L, C>(
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
                        count as u64 / now.elapsed().as_secs() as u64,
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
            let _ = send.feed(item).await.unwrap();
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

    pub fn enable_log() {
        let filter = tracing_subscriber::EnvFilter::builder()
            .with_default_directive(tracing::level_filters::LevelFilter::TRACE.into())
            .from_env()
            .unwrap()
            .add_directive("tarpc=error".parse().unwrap());
        tracing_subscriber::fmt::fmt()
            .pretty()
            .with_env_filter(filter)
            .init();
    }

    pub async fn wait_for_condition<F, FRet>(mut condition: F, timeout: std::time::Duration) -> ()
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

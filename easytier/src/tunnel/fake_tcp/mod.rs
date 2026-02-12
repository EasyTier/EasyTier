mod netfilter;
mod packet;
mod stack;

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::{net::SocketAddr, pin::Pin};

use bytes::BytesMut;
use pnet::datalink;
use pnet::util::MacAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::common::scoped_task::ScopedTask;
use crate::tunnel::fake_tcp::netfilter::create_tun;
use crate::tunnel::{common::TunnelWrapper, Tunnel, TunnelError, TunnelInfo, TunnelListener};

use futures::Future;

use dashmap::DashMap;

struct IpToIfNameCache {
    ip_to_ifname: DashMap<IpAddr, (String, Option<MacAddr>)>,
}

impl IpToIfNameCache {
    fn new() -> Self {
        Self {
            ip_to_ifname: DashMap::new(),
        }
    }

    fn reload_ip_to_ifname(&self) {
        self.ip_to_ifname.clear();
        let interfaces = datalink::interfaces();
        for iface in interfaces {
            for ip in iface.ips.iter() {
                self.ip_to_ifname
                    .insert(ip.ip(), (iface.name.clone(), iface.mac));
            }
        }
    }

    fn get_ifname(&self, ip: &IpAddr) -> Option<(String, Option<MacAddr>)> {
        if let Some(ifname) = self.ip_to_ifname.get(ip) {
            Some(ifname.clone())
        } else {
            self.reload_ip_to_ifname();
            self.ip_to_ifname.get(ip).map(|s| s.clone())
        }
    }
}

fn get_faketcp_tunnel_type_str(driver_type: &str) -> String {
    format!("faketcp_{}", driver_type)
}

pub struct FakeTcpTunnelListener {
    addr: url::Url,
    os_listener: Option<tokio::net::TcpListener>,
    // interface_name -> fake tcp stack
    stack_map: DashMap<String, Arc<Mutex<stack::Stack>>>,
    // a cache from ip addr to interface name
    ip_to_ifname: IpToIfNameCache,
}

impl FakeTcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        // Define filter: Capture all packets (or refine this if needed)
        // For FakeTCP, we probably want to capture packets destined to us?
        // But `stack::Stack` handles IP/TCP logic.
        // Maybe we just capture everything for now as a raw tunnel?
        // Or better, filter based on some criteria?
        // The user said "satisfy filter function".
        // Let's create a filter that accepts everything for now, or maybe only IP packets?
        FakeTcpTunnelListener {
            addr,
            os_listener: None,
            stack_map: DashMap::new(),
            ip_to_ifname: IpToIfNameCache::new(),
        }
    }

    async fn do_accept(&mut self) -> Result<AcceptResult, TunnelError> {
        loop {
            match self.os_listener.as_mut().unwrap().accept().await {
                Ok((s, remote_addr)) => {
                    let Ok(local_addr) = s.local_addr() else {
                        tracing::warn!("accept fail with local_addr error");
                        continue;
                    };
                    let Some((interface_name, mac)) =
                        self.ip_to_ifname.get_ifname(&local_addr.ip())
                    else {
                        tracing::warn!("accept fail with interface_name error");
                        continue;
                    };
                    return Ok(AcceptResult {
                        socket: s,
                        local_addr,
                        remote_addr,
                        interface_name,
                        mac,
                    });
                }
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

    async fn get_stack(
        &self,
        accept_result: &AcceptResult,
    ) -> Result<Arc<Mutex<stack::Stack>>, TunnelError> {
        let local_socket_addr = accept_result.local_addr;

        let interface_name = &accept_result.interface_name;

        let (local_ip, local_ip6) = match local_socket_addr.ip() {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        let ret = match self.stack_map.entry(interface_name.to_string()) {
            dashmap::Entry::Occupied(entry) => entry.get().clone(),
            dashmap::Entry::Vacant(entry) => {
                let tun = create_tun(interface_name, None, local_socket_addr)?;
                tracing::info!(
                    ?local_socket_addr,
                    "create new stack with interface_name: {:?}",
                    interface_name
                );
                let stack = Arc::new(Mutex::new(stack::Stack::new(
                    tun,
                    local_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    local_ip6,
                    accept_result.mac,
                )));
                entry.insert(stack.clone());
                stack
            }
        };

        Ok(ret)
    }
}

fn build_os_socket_reader_task(mut socket: TcpStream) -> ScopedTask<()> {
    let os_socket_reader_task: ScopedTask<()> = tokio::spawn(async move {
        // read the os socket until it's closed
        let mut buf = [0u8; 1024];
        while let Ok(size) = socket.read(&mut buf).await {
            tracing::trace!("read {} bytes from os socket", size);
            if size == 0 {
                break;
            }
        }
        tracing::info!("FakeTcpTunnelListener os socket closed");
    })
    .into();
    os_socket_reader_task
}

#[derive(Debug)]
struct AcceptResult {
    socket: TcpStream,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    interface_name: String,
    mac: Option<MacAddr>,
}

#[async_trait::async_trait]
impl TunnelListener for FakeTcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let port = self.addr.port().unwrap_or(0);
        let bind_addr = crate::tunnel::check_scheme_and_get_socket_addr::<SocketAddr>(
            &self.addr,
            "faketcp",
            crate::tunnel::IpVersion::Both,
        )
        .await?;
        let os_listener = tokio::net::TcpListener::bind(bind_addr).await?;
        tracing::info!(port, "FakeTcpTunnelListener listening");
        self.os_listener = Some(os_listener);
        // self.stack.lock().await.listen(port);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::debug!("FakeTcpTunnelListener waiting for accept");
        let res = self.do_accept().await?;
        let stack = self.get_stack(&res).await?;
        let socket = stack
            .lock()
            .await
            .alloc_established_socket(res.local_addr, res.remote_addr, stack::State::Established)
            .await;

        tracing::info!(
            ?res,
            remote = socket.remote_addr().to_string(),
            "FakeTcpTunnelListener accepted connection"
        );

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(stack.lock().await.driver_type()),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
        };

        // We treat the fake tcp socket as a datagram tunnel directly
        // The reader/writer will interface with the socket using recv_bytes/send
        // We need to adapt the socket to ZCPacketStream and ZCPacketSink

        // Since FakeTcpTunnel is a datagram tunnel, we don't need FramedReader/Writer (which are for stream based tunnels like TCP)
        // We should wrap the socket into something that produces/consumes ZCPacket directly.

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(Box::new(build_os_socket_reader_task(res.socket))),
        )))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct FakeTcpTunnelConnector {
    addr: url::Url,
    ip_to_if_name: IpToIfNameCache,
}

impl FakeTcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        FakeTcpTunnelConnector {
            addr,
            ip_to_if_name: IpToIfNameCache::new(),
        }
    }
}

fn get_local_ip_for_destination(destination: IpAddr) -> Option<IpAddr> {
    // 使用一个不可路由的、私有的、或回环地址创建一个临时的 socket，让内核自动选择源接口。
    // 对于 IPv4，使用 0.0.0.0; 对于 IPv6，使用 ::
    let bind_addr = if destination.is_ipv4() {
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
    };

    // 绑定到一个临时端口 (0)
    let socket = UdpSocket::bind((bind_addr, 0)).ok()?;

    // 尝试连接到目标地址。这不会真正发送数据包，只是让内核确定路由。
    socket.connect((destination, 80)).ok()?; // 使用一个常见的端口，例如 80

    // 获取 socket 的本地地址信息
    socket.local_addr().map(|addr| addr.ip()).ok()
}

#[async_trait::async_trait]
impl crate::tunnel::TunnelConnector for FakeTcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let remote_addr = crate::tunnel::check_scheme_and_get_socket_addr::<SocketAddr>(
            &self.addr,
            "faketcp",
            crate::tunnel::IpVersion::Both,
        )
        .await?;
        let local_ip = get_local_ip_for_destination(remote_addr.ip())
            .ok_or(TunnelError::InternalError("Failed to get local ip".into()))?;

        let os_socket = tokio::net::TcpSocket::new_v4()?;
        os_socket.bind("0.0.0.0:0".parse().unwrap())?;
        let local_port = os_socket.local_addr()?.port();
        let local_addr = SocketAddr::new(local_ip, local_port);

        let (interface_name, mac) =
            self.ip_to_if_name
                .get_ifname(&local_ip)
                .ok_or(TunnelError::InternalError(
                    "Failed to get interface name".into(),
                ))?;

        let (local_ip, local_ip6) = match local_ip {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        let tun = create_tun(&interface_name, Some(remote_addr), local_addr)?;
        let local_ip = local_ip.unwrap_or("0.0.0.0".parse().unwrap());
        let mut stack = stack::Stack::new(tun, local_ip, local_ip6, mac);
        let driver_type = stack.driver_type();

        let socket = stack
            .alloc_established_socket(local_addr, remote_addr, stack::State::SynSent)
            .await;

        let os_stream = os_socket.connect(remote_addr).await?;

        tracing::info!(?remote_addr, "FakeTcpTunnelConnector connecting");

        let mut buf = BytesMut::new();
        socket
            .recv(&mut buf)
            .await
            .ok_or(TunnelError::InternalError(
                "Failed to recv bytes to establish connection".into(),
            ))?;

        tracing::info!(local_addr = ?socket.local_addr(), "FakeTcpTunnelConnector connected");

        let info = TunnelInfo {
            tunnel_type: get_faketcp_tunnel_type_str(driver_type),
            local_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.local_addr().to_string(),
                    "faketcp",
                )
                .into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
        };

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        Ok(Box::new(TunnelWrapper::new_with_associate_data(
            reader,
            writer,
            Some(info),
            Some(Box::new((build_os_socket_reader_task(os_stream), stack))),
        )))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

use crate::tunnel::packet_def::{ZCPacket, ZCPacketType};
use crate::tunnel::{SinkError, SinkItem, StreamItem};
use futures::{Sink, Stream};
use std::task::{Context as TaskContext, Poll};

type RecvFut = Pin<Box<dyn Future<Output = Option<(BytesMut, usize)>> + Send + Sync>>;

enum FakeTcpStreamState {
    ConsumingBuf(BytesMut),
    PollFuture(RecvFut),
    Closed,
}

struct FakeTcpStream {
    socket: Arc<stack::Socket>,
    state: FakeTcpStreamState,
}

impl FakeTcpStream {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self {
            socket,
            state: FakeTcpStreamState::ConsumingBuf(BytesMut::new()),
        }
    }
}

impl Stream for FakeTcpStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        loop {
            let state = std::mem::replace(&mut s.state, FakeTcpStreamState::Closed);
            match state {
                FakeTcpStreamState::ConsumingBuf(buf) => {
                    let buf_len = buf.len();
                    // check peer manager header and split buf out
                    let packet = ZCPacket::new_from_buf(buf, ZCPacketType::TCP);
                    if let Some(tcp_hdr) = packet.tcp_tunnel_header() {
                        let expected_payload_len = tcp_hdr.len.get() as usize;
                        if expected_payload_len <= buf_len && expected_payload_len != 0 {
                            let mut buf = packet.inner();
                            let new_inner = buf.split_to(expected_payload_len);
                            s.state = FakeTcpStreamState::ConsumingBuf(buf);
                            return Poll::Ready(Some(Ok(ZCPacket::new_from_buf(
                                new_inner,
                                ZCPacketType::TCP,
                            ))));
                        }
                    }

                    let mut buf = packet.inner();
                    buf.truncate(0);

                    let socket = s.socket.clone();
                    s.state = FakeTcpStreamState::PollFuture(Box::pin(async move {
                        let ret = socket.recv(&mut buf).await;
                        ret.map(|s| (buf, s))
                    }));
                }
                FakeTcpStreamState::PollFuture(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Ready(Some((buf, _sz))) => {
                        s.state = FakeTcpStreamState::ConsumingBuf(buf);
                    }
                    Poll::Ready(None) => {
                        s.state = FakeTcpStreamState::Closed;
                    }
                    Poll::Pending => {
                        s.state = FakeTcpStreamState::PollFuture(fut);
                        return Poll::Pending;
                    }
                },
                FakeTcpStreamState::Closed => {
                    return Poll::Ready(None);
                }
            }
        }
    }
}

struct FakeTcpSink {
    socket: Arc<stack::Socket>,
}

impl FakeTcpSink {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self { socket }
    }
}

impl Sink<SinkItem> for FakeTcpSink {
    type Error = SinkError;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
        // We need to send the packet as bytes
        // The item is ZCPacket, which has into_bytes() method
        let mut packet = item.convert_type(ZCPacketType::TCP);
        let len = packet.buf_len();
        packet.mut_tcp_tunnel_header().unwrap().len.set(len as u32);
        self.socket.try_send(&packet.into_bytes());

        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.socket.close();
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::tunnel::common::tests::_tunnel_pingpong;

    use super::*;

    #[tokio::test]
    async fn faketcp_pingpong() {
        #[cfg(target_family = "unix")]
        {
            if unsafe { nix::libc::geteuid() } != 0 {
                return;
            }
        }

        let listener = FakeTcpTunnelListener::new("faketcp://0.0.0.0:31011".parse().unwrap());
        let connector = FakeTcpTunnelConnector::new("faketcp://127.0.0.1:31011".parse().unwrap());

        _tunnel_pingpong(listener, connector).await
    }
}

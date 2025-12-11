mod packet;
mod stack;

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;
use std::{net::SocketAddr, pin::Pin};

use bytes::{Bytes, BytesMut};
use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::util::MacAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::Mutex;

use crate::common::scoped_task::ScopedTask;
use crate::tunnel::{common::TunnelWrapper, Tunnel, TunnelError, TunnelInfo, TunnelListener};

use futures::Future;

use dashmap::DashMap;
use once_cell::sync::Lazy;
use pnet::datalink::{self, Channel::Ethernet, NetworkInterface};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Weak;

// A simple packet filter function type
type PacketFilter = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

struct Subscriber {
    filter: PacketFilter,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

struct InterfaceWorker {
    tx: Mutex<Box<dyn DataLinkSender>>,
    subscribers: Arc<DashMap<u32, Subscriber>>,
}

impl InterfaceWorker {
    fn new(interface: NetworkInterface) -> Arc<Self> {
        let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the datalink channel: {}",
                e
            ),
        };

        let subscribers = Arc::new(DashMap::<u32, Subscriber>::new());
        let subscribers_clone = subscribers.clone();

        std::thread::spawn(move || {
            loop {
                match rx.next() {
                    Ok(packet) => {
                        // Iterate over subscribers and send packet if filter matches
                        // Note: DashMap iteration might be slow if many subscribers, but usually few per interface.
                        // For high performance we might need a better structure or read-copy-update.
                        for r in subscribers_clone.iter() {
                            let subscriber = r.value();
                            if (subscriber.filter)(packet) {
                                tracing::trace!(
                                    ?packet,
                                    "InterfaceWorker packet matched filter, dispatching"
                                );
                                // Try send, ignore errors (best effort)
                                let _ = subscriber.sender.try_send(packet.to_vec());
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("InterfaceWorker read error: {}", e);
                        // If interface goes down, we might need to handle it.
                        // For now just break and maybe the worker is dead.
                        break;
                    }
                }
            }
        });

        Arc::new(Self {
            tx: Mutex::new(tx),
            subscribers,
        })
    }

    fn subscribe(&self, filter: PacketFilter, sender: tokio::sync::mpsc::Sender<Vec<u8>>) -> u32 {
        static ID_GEN: AtomicU32 = AtomicU32::new(0);
        let id = ID_GEN.fetch_add(1, Ordering::Relaxed);
        self.subscribers.insert(id, Subscriber { filter, sender });
        id
    }

    fn unsubscribe(&self, id: u32) {
        self.subscribers.remove(&id);
    }
}

static INTERFACE_MANAGERS: Lazy<DashMap<String, Weak<InterfaceWorker>>> = Lazy::new(DashMap::new);

fn get_or_create_worker(interface_name: &str) -> Arc<InterfaceWorker> {
    // Check if we have an active worker
    if let Some(worker) = INTERFACE_MANAGERS
        .get(interface_name)
        .and_then(|w| w.upgrade())
    {
        return worker;
    }

    // Need to create new worker.
    // Lock effectively by using entry API? DashMap entry API might not be enough for complex init.
    // Let's use a double-check locking style or just accept race condition (creating two workers and one wins).
    // DashMap doesn't support easy "compute_if_absent" with async or heavy logic without blocking the map shard.

    // But creation is rare.
    // Let's find interface first.
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Network interface not found");

    let worker = InterfaceWorker::new(interface);
    INTERFACE_MANAGERS.insert(interface_name.to_string(), Arc::downgrade(&worker));
    worker
}

struct PnetTun {
    worker: Arc<InterfaceWorker>,
    subscription_id: u32,
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl PnetTun {
    pub fn new(interface_name: &str, filter: PacketFilter) -> Self {
        tracing::debug!(interface_name, "Creating new PnetTun");
        let worker = get_or_create_worker(interface_name);
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let id = worker.subscribe(filter, tx);

        Self {
            worker,
            subscription_id: id,
            recv_queue: Mutex::new(rx),
        }
    }
}

impl Drop for PnetTun {
    fn drop(&mut self) {
        tracing::debug!(subscription_id = self.subscription_id, "Dropping PnetTun");
        self.worker.unsubscribe(self.subscription_id);
    }
}

#[async_trait::async_trait]
impl stack::Tun for PnetTun {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                tracing::trace!(?data, "PnetTun received packet");
                packet.extend_from_slice(&data);
                Ok(data.len())
            }
            None => {
                tracing::warn!("PnetTun recv channel closed");
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "PnetTun channel closed",
                ))
            }
        }
    }

    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        tracing::trace!(len = packet.len(), "PnetTun try_sending packet");
        // We need async lock for tx.
        // try_send is sync. We can use try_lock if available or blocking lock.
        // tokio::sync::Mutex::try_lock is available.
        if let Ok(mut tx) = self.worker.tx.try_lock() {
            tx.send_to(packet, None)
                .ok_or(std::io::Error::other("send_to failed"))?
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "PnetTun tx lock busy",
            ))
        }
    }
}

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

pub struct FakeTcpTunnelListener {
    addr: url::Url,
    os_listener: Option<tokio::net::TcpListener>,
    // interface_name -> fake tcp stack
    stack_map: DashMap<String, Arc<Mutex<stack::Stack>>>,
    // a cache from ip addr to interface name
    ip_to_ifname: IpToIfNameCache,
}

fn filter_tcp_packet(
    packet: &[u8],
    src_addr: Option<&SocketAddr>,
    dst_addr: Option<&SocketAddr>,
) -> bool {
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    let ethernet = if let Some(ethernet) = EthernetPacket::new(packet) {
        ethernet
    } else {
        return false;
    };

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let ipv4 = if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                ipv4
            } else {
                return false;
            };

            if ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                return false;
            }

            let tcp = if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                tcp
            } else {
                return false;
            };

            if let Some(src_addr) = src_addr {
                if IpAddr::V4(ipv4.get_source()) != src_addr.ip() {
                    return false;
                }
                if tcp.get_source() != src_addr.port() {
                    return false;
                }
            }

            if let Some(dst_addr) = dst_addr {
                if IpAddr::V4(ipv4.get_destination()) != dst_addr.ip() {
                    return false;
                }
                if tcp.get_destination() != dst_addr.port() {
                    return false;
                }
            }

            tracing::trace!(
                ?tcp,
                "FakeTcpTunnelListener packet matched filter, dispatching, src_addr: {:?}, dst_addr: {:?}, packet_src_ip: {:?}, packet_dst_ip: {:?}, packet_src_port: {:?}, packet_dst_port: {:?}",
                src_addr,
                dst_addr,
                ipv4.get_source(),
                ipv4.get_destination(),
                tcp.get_source(),
                tcp.get_destination(),
            );
        }
        EtherTypes::Ipv6 => {
            let ipv6 = if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                ipv6
            } else {
                return false;
            };

            if ipv6.get_next_header() != IpNextHeaderProtocols::Tcp {
                return false;
            }

            let tcp = if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                tcp
            } else {
                return false;
            };

            if let Some(src_addr) = src_addr {
                if IpAddr::V6(ipv6.get_source()) != src_addr.ip() {
                    return false;
                }
                if tcp.get_source() != src_addr.port() {
                    return false;
                }
            }

            if let Some(dst_addr) = dst_addr {
                if IpAddr::V6(ipv6.get_destination()) != dst_addr.ip() {
                    return false;
                }
                if tcp.get_destination() != dst_addr.port() {
                    return false;
                }
            }

            tracing::trace!(
                ?tcp,
                "FakeTcpTunnelListener packet matched filter, dispatching"
            );
        }
        _ => return false,
    }

    true
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
        let filter: PacketFilter = Box::new(move |packet: &[u8]| -> bool {
            filter_tcp_packet(packet, None, Some(&local_socket_addr))
        });

        let interface_name = &accept_result.interface_name;

        let (local_ip, local_ip6) = match local_socket_addr.ip() {
            IpAddr::V4(ip) => (Some(ip), None),
            IpAddr::V6(ip) => (None, Some(ip)),
        };

        let ret = self
            .stack_map
            .entry(interface_name.to_string())
            .or_insert_with(|| {
                let tun =
                    vec![Arc::new(PnetTun::new(interface_name, filter)) as Arc<dyn stack::Tun>];
                tracing::info!(
                    ?local_socket_addr,
                    "create new stack with interface_name: {:?}",
                    interface_name
                );
                // TODO: Get local MAC address of the interface
                Arc::new(Mutex::new(stack::Stack::new(
                    tun,
                    local_ip.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    local_ip6,
                    accept_result.mac,
                )))
            })
            .clone();

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
            tunnel_type: "faketcp".to_owned(),
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
    stack: Arc<Mutex<Option<stack::Stack>>>,
    ip_to_if_name: IpToIfNameCache,
}

impl FakeTcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        FakeTcpTunnelConnector {
            addr,
            stack: Arc::new(Mutex::new(None)),
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

        // Similar filter logic as listener
        let filter: PacketFilter = Box::new(move |packet: &[u8]| -> bool {
            filter_tcp_packet(packet, Some(&remote_addr), Some(&local_addr))
        });

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

        let tun = vec![Arc::new(PnetTun::new(&interface_name, filter)) as Arc<dyn stack::Tun>];
        let local_ip = local_ip.unwrap_or("0.0.0.0".parse().unwrap());
        let stack = stack::Stack::new(tun, local_ip, local_ip6, mac);

        *self.stack.lock().await = Some(stack);

        let socket = self
            .stack
            .lock()
            .await
            .as_mut()
            .unwrap()
            .alloc_established_socket(local_addr, remote_addr, stack::State::SynSent)
            .await;

        let os_stream = os_socket.connect(remote_addr).await?;

        tracing::info!(?remote_addr, "FakeTcpTunnelConnector connecting");

        socket.recv_bytes().await.ok_or(TunnelError::InternalError(
            "Failed to recv bytes to establish connection".into(),
        ))?;

        tracing::info!(local_addr = ?socket.local_addr(), "FakeTcpTunnelConnector connected");

        let info = TunnelInfo {
            tunnel_type: "faketcp".to_owned(),
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
            Some(Box::new(build_os_socket_reader_task(os_stream))),
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

struct FakeTcpStream {
    socket: Arc<stack::Socket>,
    #[allow(clippy::type_complexity)]
    recv_fut: Option<Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + Sync>>>,
}

impl FakeTcpStream {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self {
            socket,
            recv_fut: None,
        }
    }
}

impl Stream for FakeTcpStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let s = self.get_mut();
        if s.recv_fut.is_none() {
            let socket = s.socket.clone();
            s.recv_fut = Some(Box::pin(async move { socket.recv_bytes().await }));
        }

        match s.recv_fut.as_mut().unwrap().as_mut().poll(cx) {
            Poll::Ready(Some(data)) => {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&data);
                let packet = ZCPacket::new_from_buf(buf, ZCPacketType::DummyTunnel);

                s.recv_fut = None;

                Poll::Ready(Some(Ok(packet)))
            }
            Poll::Ready(None) => {
                // 连接关闭
                s.recv_fut = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
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
        let bytes = item.convert_type(ZCPacketType::DummyTunnel).into_bytes();

        // Let's just spawn for now as a simple implementation, noting the limitation.
        self.socket.try_send(&bytes);

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
        let listener = FakeTcpTunnelListener::new("faketcp://0.0.0.0:31011".parse().unwrap());
        let connector = FakeTcpTunnelConnector::new("faketcp://127.0.0.1:31011".parse().unwrap());

        _tunnel_pingpong(listener, connector).await
    }
}

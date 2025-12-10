mod packet;
mod stack;

use std::sync::Arc;
use std::{net::SocketAddr, pin::Pin};

use bytes::{Bytes, BytesMut};
use pnet::datalink::DataLinkSender;
use tokio::sync::Mutex;

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
                        tracing::trace!(?packet, "InterfaceWorker received packet");
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
    async fn send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        tracing::trace!(len = packet.len(), "PnetTun sending packet");
        let mut tx = self.worker.tx.lock().await;
        let _ = tx
            .send_to(packet, None)
            .ok_or(std::io::Error::other("send_to failed"))?;
        Ok(())
    }

    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                tracing::trace!(len = data.len(), "PnetTun received packet");
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
            let _ = tx
                .send_to(packet, None)
                .ok_or(std::io::Error::other("send_to failed"))?;
            Ok(())
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "PnetTun tx lock busy",
            ))
        }
    }
}

pub struct FakeTcpTunnelListener {
    addr: url::Url,
    stack: Arc<Mutex<stack::Stack>>,
}

fn filter_tcp_packet(packet: &[u8], port: Option<u16>) -> bool {
    use pnet::packet::ethernet::EthernetPacket;
    use pnet::packet::ipv4::Ipv4Packet;
    use pnet::packet::tcp::TcpPacket;
    use pnet::packet::Packet;

    let ethernet = if let Some(ethernet) = EthernetPacket::new(packet) {
        ethernet
    } else {
        return false;
    };

    let ipv4 = if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
        ipv4
    } else {
        return false;
    };

    let tcp = if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
        tcp
    } else {
        return false;
    };

    if let Some(port) = port {
        if tcp.get_destination() != port && tcp.get_source() != port {
            return false;
        }
    }

    tracing::trace!(
        ?tcp,
        "FakeTcpTunnelListener packet matched filter, dispatching"
    );

    true
}

impl FakeTcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        // Find network interface
        let query_pairs: std::collections::HashMap<_, _> =
            addr.query_pairs().into_owned().collect();
        let interface_name = query_pairs
            .get("bind_dev")
            .map(|s| s.as_str())
            .unwrap_or("eth0");
        let port = addr.port().unwrap_or(0);

        // Define filter: Capture all packets (or refine this if needed)
        // For FakeTCP, we probably want to capture packets destined to us?
        // But `stack::Stack` handles IP/TCP logic.
        // Maybe we just capture everything for now as a raw tunnel?
        // Or better, filter based on some criteria?
        // The user said "satisfy filter function".
        // Let's create a filter that accepts everything for now, or maybe only IP packets?
        let filter: PacketFilter =
            Box::new(move |packet: &[u8]| -> bool { filter_tcp_packet(packet, Some(port)) });

        let tun = vec![Arc::new(PnetTun::new(&interface_name, filter)) as Arc<dyn stack::Tun>];
        let local_ip = "0.0.0.0".parse().unwrap();
        let stack = Arc::new(Mutex::new(stack::Stack::new(tun, local_ip, None)));

        FakeTcpTunnelListener { addr, stack }
    }
}

#[async_trait::async_trait]
impl TunnelListener for FakeTcpTunnelListener {
    async fn listen(&mut self) -> Result<(), TunnelError> {
        let port = self.addr.port().unwrap_or(0);
        tracing::info!(port, "FakeTcpTunnelListener listening");
        self.stack.lock().await.listen(port);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        tracing::debug!("FakeTcpTunnelListener waiting for accept");
        let socket = self.stack.lock().await.accept().await;
        tracing::info!(remote_addr = ?socket.remote_addr(), "FakeTcpTunnelListener accepted connection");

        let info = TunnelInfo {
            tunnel_type: "fake_tcp".to_owned(),
            local_addr: Some(self.local_url().into()),
            remote_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.remote_addr().to_string(),
                    "fake_tcp",
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

        Ok(Box::new(TunnelWrapper::new(reader, writer, Some(info))))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

pub struct FakeTcpTunnelConnector {
    addr: url::Url,
    stack: Arc<Mutex<stack::Stack>>,
}

impl FakeTcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        // Find network interface, assuming it's specified in the query param or we pick a default?
        // For connector, the addr is the remote address. We need to know which local interface to bind.
        // Usually we bind to 0.0.0.0 or a specific interface.
        // Let's assume we can pass interface name in query param "bind_dev"
        let query_pairs: std::collections::HashMap<_, _> =
            addr.query_pairs().into_owned().collect();
        let interface_name = query_pairs
            .get("bind_dev")
            .map(|s| s.as_str())
            .unwrap_or("eth0");

        // Similar filter logic as listener
        let filter: PacketFilter =
            Box::new(move |packet: &[u8]| -> bool { filter_tcp_packet(packet, None) });

        let tun = vec![Arc::new(PnetTun::new(interface_name, filter)) as Arc<dyn stack::Tun>];
        let local_ip = "0.0.0.0".parse().unwrap();
        let stack = Arc::new(Mutex::new(stack::Stack::new(tun, local_ip, None)));

        FakeTcpTunnelConnector { addr, stack }
    }
}

#[async_trait::async_trait]
impl crate::tunnel::TunnelConnector for FakeTcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError> {
        let addr = crate::tunnel::check_scheme_and_get_socket_addr::<SocketAddr>(
            &self.addr,
            "tcp",
            crate::tunnel::IpVersion::Both,
        )
        .await?;

        tracing::info!(?addr, "FakeTcpTunnelConnector connecting");

        let socket = self
            .stack
            .lock()
            .await
            .connect(addr)
            .await
            .ok_or(TunnelError::InternalError("Failed to connect".into()))?;

        tracing::info!(local_addr = ?socket.local_addr(), "FakeTcpTunnelConnector connected");

        let info = TunnelInfo {
            tunnel_type: "fake_tcp".to_owned(),
            local_addr: Some(
                crate::tunnel::build_url_from_socket_addr(
                    &socket.local_addr().to_string(),
                    "fake_tcp",
                )
                .into(),
            ),
            remote_addr: Some(self.addr.clone().into()),
        };

        let socket = Arc::new(socket);
        let reader = FakeTcpStream::new(socket.clone());
        let writer = FakeTcpSink::new(socket);

        Ok(Box::new(TunnelWrapper::new(reader, writer, Some(info))))
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
}

use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::{SinkError, SinkItem, StreamItem};
use futures::{Sink, Stream};
use std::task::{Context as TaskContext, Poll};

struct FakeTcpStream {
    socket: Arc<stack::Socket>,
}

impl FakeTcpStream {
    fn new(socket: Arc<stack::Socket>) -> Self {
        Self { socket }
    }
}

impl Stream for FakeTcpStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Option<Self::Item>> {
        let fut = self.socket.recv_bytes();
        tokio::pin!(fut);
        match fut.poll(cx) {
            Poll::Ready(Some(data)) => {
                let mut buf = BytesMut::new();
                buf.extend_from_slice(&data);
                let packet =
                    ZCPacket::new_from_buf(buf, crate::tunnel::packet_def::ZCPacketType::TCP);
                Poll::Ready(Some(Ok(packet)))
            }
            Poll::Ready(None) => Poll::Ready(None),
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
        let bytes = item.into_bytes();

        // Let's just spawn for now as a simple implementation, noting the limitation.
        let socket = self.socket.clone();
        tokio::spawn(async move {
            socket.send(&bytes).await;
        });

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
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::enable_log;

    use super::*;

    #[tokio::test]
    async fn test_fake_tcp_listener() {
        // This test requires root privileges to run because of pnet.
        // We skip it if not running as root or if environment variable is not set.
        // if std::env::var("EASYTIER_TEST_ROOT").is_err() {
        //     println!("Skipping test_fake_tcp_listener because EASYTIER_TEST_ROOT is not set");
        //     return;
        // }
        enable_log();

        let addr = "tcp://0.0.0.0:12345".parse().unwrap();
        let mut listener = FakeTcpTunnelListener::new(addr);

        listener.listen().await.unwrap();

        // accept a connection
        let ret = listener.accept().await.unwrap();

        println!("Listener started, sleeping for 5 seconds...");
        tokio::time::sleep(tokio::time::Duration::from_secs(50000)).await;
    }
}

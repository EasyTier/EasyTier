use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Weak,
    },
};

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use pnet::{
    datalink::{self, DataLinkSender, NetworkInterface},
    packet::{ethernet::EtherTypes, ip::IpNextHeaderProtocols, ipv6::Ipv6Packet},
};
use tokio::sync::Mutex;

use crate::tunnel::fake_tcp::stack;

type PacketFilter = Box<dyn Fn(&[u8]) -> bool + Send + Sync>;

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

pub fn create_packet_filter(src_addr: Option<SocketAddr>, dst_addr: SocketAddr) -> PacketFilter {
    Box::new(move |packet: &[u8]| -> bool {
        filter_tcp_packet(packet, src_addr.as_ref(), Some(&dst_addr))
    })
}

struct Subscriber {
    filter: PacketFilter,
    sender: tokio::sync::mpsc::Sender<Vec<u8>>,
}

struct InterfaceWorker {
    tx: Mutex<Box<dyn DataLinkSender>>,
    subscribers: Arc<DashMap<u32, Subscriber>>,
}

impl InterfaceWorker {
    fn new(interface: NetworkInterface) -> io::Result<Arc<Self>> {
        let (tx, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(pnet::datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(io::Error::other("Unhandled channel type")),
            Err(e) => return Err(io::Error::other(e)),
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

        Ok(Arc::new(Self {
            tx: Mutex::new(tx),
            subscribers,
        }))
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

fn get_or_create_worker(interface_name: &str) -> io::Result<Arc<InterfaceWorker>> {
    // Check if we have an active worker
    if let Some(worker) = INTERFACE_MANAGERS
        .get(interface_name)
        .and_then(|w| w.upgrade())
    {
        return Ok(worker);
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
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("Network interface '{}' not found", interface_name),
            )
        })?;

    let worker = InterfaceWorker::new(interface)?;
    INTERFACE_MANAGERS.insert(interface_name.to_string(), Arc::downgrade(&worker));
    Ok(worker)
}

pub struct PnetTun {
    worker: Arc<InterfaceWorker>,
    subscription_id: u32,
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl PnetTun {
    pub fn new(interface_name: &str, filter: PacketFilter) -> io::Result<Self> {
        tracing::debug!(interface_name, "Creating new PnetTun");
        let worker = get_or_create_worker(interface_name)?;
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let id = worker.subscribe(filter, tx);

        Ok(Self {
            worker,
            subscription_id: id,
            recv_queue: Mutex::new(rx),
        })
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

    fn driver_type(&self) -> &'static str {
        "pnet"
    }
}

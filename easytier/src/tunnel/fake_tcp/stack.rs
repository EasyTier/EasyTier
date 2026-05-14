//! A minimum, userspace TCP based datagram stack
//!
//! # Overview
//!
//! `fake-tcp` is a reusable library that implements a minimum TCP stack in
//! user space using the Tun interface. It allows programs to send datagrams
//! as if they are part of a TCP connection. `fake-tcp` has been tested to
//! be able to pass through a variety of NAT and stateful firewalls while
//! fully preserves certain desirable behavior such as out of order delivery
//! and no congestion/flow controls.
//!
//! # Core Concepts
//!
//! The core of the `fake-tcp` crate compose of two structures. [`Stack`] and
//! [`Socket`].
//!
//! ## [`Stack`]
//!
//! [`Stack`] represents a virtual TCP stack that operates at
//! Layer 3. It is responsible for:
//!
//! * TCP active and passive open and handshake
//! * `RST` handling
//! * Interact with the Tun interface at Layer 3
//! * Distribute incoming datagrams to corresponding [`Socket`]
//!
//! ## [`Socket`]
//!
//! [`Socket`] represents a TCP connection. It registers the identifying
//! tuple `(src_ip, src_port, dest_ip, dest_port)` inside the [`Stack`] so
//! so that incoming packets can be distributed to the right [`Socket`] with
//! using a channel. It is also what the client should use for
//! sending/receiving datagrams.
//!
//! # Examples
//!
//! Please see [`client.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/client.rs)
//! and [`server.rs`](https://github.com/dndx/phantun/blob/main/phantun/src/bin/server.rs) files
//! from the `phantun` crate for how to use this library in client/server mode, respectively.

use super::packet::*;
use bytes::{Bytes, BytesMut};
use crossbeam::atomic::AtomicCell;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::{Packet, tcp};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;
use tracing::{info, trace, warn};

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const RETRIES: usize = 6;
const MPMC_BUFFER_LEN: usize = 512;
const MAX_UNACKED_LEN: u32 = 128 * 1024 * 1024; // 128MB

#[async_trait::async_trait]
pub trait Tun: Send + Sync + 'static {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error>;
    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error>;
    fn driver_type(&self) -> &'static str;
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AddrTuple {
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl AddrTuple {
    fn new(local_addr: SocketAddr, remote_addr: SocketAddr) -> AddrTuple {
        AddrTuple {
            local_addr,
            remote_addr,
        }
    }
}

struct Shared {
    tuples: RwLock<HashMap<AddrTuple, flume::Sender<Bytes>>>,
    initial_tcp_state: RwLock<HashMap<AddrTuple, TcpInitialState>>,
    listening: RwLock<HashSet<u16>>,
    tun: Arc<dyn Tun>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

#[derive(Clone, Copy, Debug, Default)]
struct TcpInitialState {
    // Captured from kernel handshake packets before the fake socket is accepted.
    seq: Option<u32>,
    ack: Option<u32>,
}

fn record_initial_tcp_state(
    initial_tcp_state: &RwLock<HashMap<AddrTuple, TcpInitialState>>,
    tuple: AddrTuple,
    tcp_packet: &tcp::TcpPacket<'_>,
) {
    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
        return;
    }

    let is_syn = (tcp_packet.get_flags() & tcp::TcpFlags::SYN) != 0;
    let is_ack_only =
        (tcp_packet.get_flags() & tcp::TcpFlags::ACK) != 0 && tcp_packet.payload().is_empty();

    if !is_syn && !is_ack_only {
        return;
    }

    let mut initial_tcp_state = initial_tcp_state.write().unwrap();
    let state = initial_tcp_state.entry(tuple).or_default();
    if is_syn {
        // Header ACK tracks the peer kernel ISN, not fake payload progress.
        state.ack = Some(tcp_packet.get_sequence().wrapping_add(1));
    }
    if is_ack_only {
        state.seq = Some(tcp_packet.get_acknowledgement());
    }
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    local_mac: MacAddr,
    reader_task: AbortOnDropHandle<()>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Idle,
    SynSent,
    SynReceived,
    Established,
}

pub struct Socket {
    shared: Arc<Shared>,
    tun: Arc<dyn Tun>,
    incoming: flume::Receiver<Bytes>,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    local_mac: MacAddr,
    remote_mac: AtomicCell<Option<MacAddr>>,
    seq: AtomicU32,
    ack: AtomicU32,
    last_ack: AtomicU32,
    state: AtomicCell<State>,
}

/// A socket that represents a unique TCP connection between a server and client.
///
/// The `Socket` object itself satisfies `Sync` and `Send`, which means it can
/// be safely called within an async future.
///
/// To close a TCP connection that is no longer needed, simply drop this object
/// out of scope.
impl Socket {
    #[allow(clippy::too_many_arguments)]
    fn new(
        shared: Arc<Shared>,
        tun: Arc<dyn Tun>,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        local_mac: MacAddr,
        remote_mac: Option<MacAddr>,
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>) {
        let (incoming_tx, incoming_rx) = flume::bounded(MPMC_BUFFER_LEN);

        (
            Socket {
                shared,
                tun,
                incoming: incoming_rx,
                local_addr,
                remote_addr,
                local_mac,
                remote_mac: AtomicCell::new(remote_mac),
                seq: AtomicU32::new(0),
                ack: AtomicU32::new(ack.unwrap_or(0)),
                last_ack: AtomicU32::new(ack.unwrap_or(0)),
                state: AtomicCell::new(state),
            },
            incoming_tx,
        )
    }

    fn build_tcp_packet(&self, flags: u8, payload: Option<&[u8]>) -> Bytes {
        let ack = self.ack.load(Ordering::Relaxed);
        self.last_ack.store(ack, Ordering::Relaxed);

        build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or(MacAddr::zero()),
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            ack,
            flags,
            payload,
        )
    }

    /// Sends a datagram to the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the Tun socket returned an error
    /// and this socket must be closed.
    pub fn try_send(&self, payload: &[u8]) -> Option<()> {
        match self.state.load() {
            State::Established => {
                let buf = self.build_tcp_packet(tcp::TcpFlags::ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.tun.try_send(&buf).ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    pub fn close(&self) {
        if self.state.load() != State::Idle {
            let buf = self.build_tcp_packet(tcp::TcpFlags::RST, None);
            let _ = self.tun.try_send(&buf);
            self.state.store(State::Idle);
        }
    }

    /// Attempt to receive a datagram from the other end.
    ///
    /// This method takes `&self`, and it can be called safely by multiple threads
    /// at the same time.
    ///
    /// A return of `None` means the TCP connection is broken
    /// and this socket must be closed.
    pub async fn recv(&self, buf: &mut BytesMut) -> Option<usize> {
        tracing::trace!(
            "Socket recv called, local_addr: {:?}, remote_addr: {:?}",
            self.local_addr,
            self.remote_addr
        );
        loop {
            match self.state.load() {
                State::Established => {
                    let Ok(raw_buf) = self.incoming.recv_async().await else {
                        info!("Connection {} recv error", self);
                        return None;
                    };

                    let Some((src_mac, dst_mac, _v4_packet, tcp_packet)) =
                        parse_ip_packet(&raw_buf)
                    else {
                        trace!("Dropping malformed fake tcp packet for established socket");
                        continue;
                    };

                    tracing::trace!(
                        "Socket received TCP packet from {}({:?}) to {}({:?}): {:?}",
                        self.remote_addr,
                        src_mac,
                        self.local_addr,
                        dst_mac,
                        tcp_packet
                    );

                    self.remote_mac.store(Some(src_mac));

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    if (tcp_packet.get_flags() & tcp::TcpFlags::ACK) != 0
                        && tcp_packet.payload().is_empty()
                    {
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                    }

                    let payload = tcp_packet.payload();

                    for opt in tcp_packet.get_options_iter() {
                        if opt.get_number() == TcpOptionNumbers::SACK {
                            // SACK 选项类型为 5
                            let payload = opt.payload();
                            for chunk in payload.chunks(8) {
                                if chunk.len() != 8 {
                                    continue;
                                }
                                let left = tcp_packet.get_acknowledgement();
                                let right = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
                                let len = right.wrapping_sub(left);

                                let sack_end = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
                                if len == 0 || sack_end <= left {
                                    continue;
                                }

                                let send_len = std::cmp::min(len, 1400) as usize;
                                let data = vec![0u8; send_len];

                                let buf = build_tcp_packet(
                                    self.local_mac,
                                    self.remote_mac.load().unwrap_or(MacAddr::zero()),
                                    self.local_addr,
                                    self.remote_addr,
                                    left,
                                    self.ack.load(Ordering::Relaxed),
                                    tcp::TcpFlags::ACK,
                                    Some(&data),
                                );

                                if let Err(e) = self.tun.try_send(&buf) {
                                    tracing::error!("Failed to send SACK response: {}", e);
                                }
                                break;
                            }
                        }
                    }

                    if payload.is_empty() {
                        continue;
                    }

                    // Zero-fill packets only pacify the TCP stack.
                    if payload.iter().all(|&b| b == 0) {
                        continue;
                    }

                    buf.extend_from_slice(payload);

                    return Some(payload.len());
                }
                State::SynSent => {
                    let Ok(Ok(buf)) = time::timeout(TIMEOUT, self.incoming.recv_async()).await
                    else {
                        info!("Waiting for client SYN + ACK timed out");
                        return None;
                    };
                    let Some((src_mac, _dst_mac, _v4_packet, tcp_packet)) = parse_ip_packet(&buf)
                    else {
                        trace!("Dropping malformed fake tcp packet during handshake");
                        continue;
                    };

                    if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                        tracing::trace!("Connection {} reset by peer", self);
                        return None;
                    }

                    let expected_flag = tcp::TcpFlags::SYN | tcp::TcpFlags::ACK;
                    if (tcp_packet.get_flags() & expected_flag) == expected_flag {
                        // found our SYN + ACK
                        self.seq
                            .store(tcp_packet.get_acknowledgement(), Ordering::Relaxed);
                        self.ack
                            .store(tcp_packet.get_sequence().wrapping_add(1), Ordering::Relaxed);
                        self.remote_mac.store(Some(src_mac));
                        self.state.store(State::Established);
                        return Some(0);
                    }
                }

                _ => unreachable!(),
            }
        }
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

impl Drop for Socket {
    /// Drop the socket and close the TCP connection
    fn drop(&mut self) {
        let tuple = AddrTuple::new(self.local_addr, self.remote_addr);
        // dissociates ourself from the dispatch map
        assert!(self.shared.tuples.write().unwrap().remove(&tuple).is_some());
        // purge cache
        let _ = self.shared.tuples_purge.send(tuple);

        let buf = build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or(MacAddr::zero()),
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            tcp::TcpFlags::RST,
            None,
        );
        if let Err(e) = self.tun.try_send(&buf) {
            warn!("Unable to send RST to remote end: {}", e);
        }

        info!("Fake TCP connection to {} closed", self);
    }
}

impl fmt::Display for Socket {
    /// User-friendly string representation of the socket
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "(Fake TCP connection from {} to {})",
            self.local_addr, self.remote_addr
        )
    }
}

/// A userspace TCP state machine
impl Stack {
    /// Create a new stack, `tun` is an array of [`Tun`](tokio_tun::Tun).
    /// When more than one [`Tun`](tokio_tun::Tun) object is passed in, same amount
    /// of reader will be spawned later. This allows user to utilize the performance
    /// benefit of Multiqueue Tun support on machines with SMP.
    pub fn new(
        tun: Arc<dyn Tun>,
        local_ip: Ipv4Addr,
        local_ip6: Option<Ipv6Addr>,
        local_mac: Option<MacAddr>,
    ) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            initial_tcp_state: RwLock::new(HashMap::new()),
            tun: tun.clone(),
            listening: RwLock::new(HashSet::new()),
            tuples_purge: tuples_purge_tx.clone(),
        });

        let t = tokio::spawn(Stack::reader_task(
            tun,
            shared.clone(),
            tuples_purge_tx.subscribe(),
        ));

        Stack {
            shared,
            local_ip,
            local_ip6,
            local_mac: local_mac.unwrap_or(MacAddr::zero()),
            reader_task: AbortOnDropHandle::new(t),
        }
    }

    /// Returns the driver type of the stack.
    pub fn driver_type(&self) -> &'static str {
        self.shared.tun.driver_type()
    }

    /// Listens for incoming connections on the given `port`.
    pub fn listen(&mut self, port: u16) {
        assert!(self.shared.listening.write().unwrap().insert(port));
    }

    pub async fn alloc_established_socket(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: State,
    ) -> Socket {
        let tuple = AddrTuple::new(local_addr, remote_addr);
        let initial_tcp_state = if state == State::Established {
            self.shared
                .initial_tcp_state
                .write()
                .unwrap()
                .remove(&tuple)
        } else {
            None
        };
        let mut tuples = self.shared.tuples.write().unwrap();
        let (sock, incoming) = Socket::new(
            self.shared.clone(),
            // self.shared.tun.choose(&mut rng).unwrap().clone(),
            self.shared.tun.clone(), // Simplification: just use the first tun
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            initial_tcp_state.and_then(|state| state.ack),
            state,
        );
        if let Some(initial_seq) = initial_tcp_state.and_then(|state| state.seq) {
            sock.seq.store(initial_seq, Ordering::Relaxed);
        }
        assert!(tuples.insert(tuple, incoming).is_none());
        sock
    }

    async fn reader_task(
        tun: Arc<dyn Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();

        loop {
            let mut buf = BytesMut::new();

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = size.unwrap();
                    tracing::trace!(len = size, ?buf, "PnetTun received packet");
                    let buf = buf.split().freeze();

                    match parse_ip_packet(&buf) {
                        Some((_src_mac, _dst_mac, ip_packet, tcp_packet)) => {
                            let local_addr = SocketAddr::new(
                                ip_packet.get_destination(),
                                tcp_packet.get_destination(),
                            );
                            let remote_addr = SocketAddr::new(
                                ip_packet.get_source(),
                                tcp_packet.get_source(),
                            );

                            let tuple = AddrTuple::new(local_addr, remote_addr);
                            if let Some(c) = tuples.get(&tuple) {
                                if c.send_async(buf).await.is_err() {
                                    trace!("Cache hit, but receiver already closed, dropping packet");
                                }

                                continue;

                                // If not Ok, receiver has been closed and just fall through to the slow
                                // path below
                            } else {
                                trace!("Cache miss, checking the shared tuples table for connection");
                                let sender = {
                                    let tuples = shared.tuples.read().unwrap();
                                    tuples.get(&tuple).cloned()
                                };

                                if let Some(c) = sender {
                                    trace!("Storing connection information into local tuples");
                                    tuples.insert(tuple, c.clone());
                                    if let Err(e) = c.send_async(buf).await {
                                        trace!("Error sending packet to connection: {:?}", e);
                                    }
                                    continue;
                                }
                            }

                            record_initial_tcp_state(
                                &shared.initial_tcp_state,
                                tuple.clone(),
                                &tcp_packet,
                            );

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                trace!(?tcp_packet, "Received SYN packet for port {}, ignoring", tcp_packet.get_destination());
                                continue;
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) != 0 {
                                info!("Unknown RST TCP packet from {}, ignoring", remote_addr);
                                continue;
                            } else {
                                trace!("Unknown TCP packet from {}, ignoring", remote_addr);
                                continue;
                            }
                        }
                        None => {
                            trace!("Dropping packet with no IP/TCP header");
                            continue;
                        }
                    }
                },
                tuple = tuples_purge.recv() => {
                    let tuple = tuple.unwrap();
                    tuples.remove(&tuple);
                    shared.initial_tcp_state.write().unwrap().remove(&tuple);
                    trace!("Removed cached tuple: {:?}", tuple);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pnet::packet::ipv4;
    use std::sync::Mutex;

    struct MockTun {
        sent: Mutex<Vec<Bytes>>,
    }

    impl MockTun {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent_packets(&self) -> Vec<Bytes> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl Tun for MockTun {
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, std::io::Error> {
            std::future::pending::<Result<usize, std::io::Error>>().await
        }

        fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
            self.sent.lock().unwrap().push(packet.clone());
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "mock"
        }
    }

    fn test_mac(id: u8) -> MacAddr {
        MacAddr::new(0, 1, 2, 3, 4, id)
    }

    fn socket_with_state(
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>, Arc<MockTun>) {
        let tun = Arc::new(MockTun::new());
        let tun_trait: Arc<dyn Tun> = tun.clone();
        let (tuples_purge, _) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            tuples: RwLock::new(HashMap::new()),
            initial_tcp_state: RwLock::new(HashMap::new()),
            listening: RwLock::new(HashSet::new()),
            tun: tun_trait.clone(),
            tuples_purge,
        });
        let local_addr = "10.0.0.1:10000".parse().unwrap();
        let remote_addr = "10.0.0.2:20000".parse().unwrap();
        let (socket, incoming) = Socket::new(
            shared.clone(),
            tun_trait,
            local_addr,
            remote_addr,
            test_mac(1),
            Some(test_mac(2)),
            ack,
            state,
        );
        shared
            .tuples
            .write()
            .unwrap()
            .insert(AddrTuple::new(local_addr, remote_addr), incoming.clone());

        (socket, incoming, tun)
    }

    fn inbound_packet(
        socket: &Socket,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Option<&[u8]>,
    ) -> Bytes {
        build_tcp_packet(
            test_mac(2),
            test_mac(1),
            socket.remote_addr,
            socket.local_addr,
            seq,
            ack,
            flags,
            payload,
        )
    }

    fn inbound_sack_packet(
        socket: &Socket,
        seq: u32,
        ack: u32,
        first_sack_left: u32,
        first_sack_right: u32,
        payload: &[u8],
    ) -> Bytes {
        const ETH_HEADER_LEN: usize = 14;
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 20;

        let base = inbound_packet(socket, seq, ack, tcp::TcpFlags::ACK, Some(payload));
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let payload_start = tcp_start + TCP_HEADER_LEN;
        let mut options = [0u8; 12];
        options[0] = 5;
        options[1] = 10;
        options[2..6].copy_from_slice(&first_sack_left.to_be_bytes());
        options[6..10].copy_from_slice(&first_sack_right.to_be_bytes());
        options[10] = 1;
        options[11] = 1;

        let mut packet = Vec::with_capacity(base.len() + options.len());
        packet.extend_from_slice(&base[..payload_start]);
        packet.extend_from_slice(&options);
        packet.extend_from_slice(&base[payload_start..]);

        let total_len = (IPV4_HEADER_LEN + TCP_HEADER_LEN + options.len() + payload.len()) as u16;
        packet[ETH_HEADER_LEN + 2..ETH_HEADER_LEN + 4].copy_from_slice(&total_len.to_be_bytes());
        let tcp_header_words = ((TCP_HEADER_LEN + options.len()) / 4) as u8;
        packet[tcp_start + 12] = tcp_header_words << 4;

        {
            let mut ipv4_packet =
                ipv4::MutableIpv4Packet::new(&mut packet[ETH_HEADER_LEN..]).unwrap();
            ipv4_packet.set_checksum(0);
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }

        {
            let mut tcp_packet = tcp::MutableTcpPacket::new(&mut packet[tcp_start..]).unwrap();
            tcp_packet.set_checksum(0);
            let (src, dst) = match (socket.remote_addr, socket.local_addr) {
                (SocketAddr::V4(src), SocketAddr::V4(dst)) => (*src.ip(), *dst.ip()),
                _ => unreachable!(),
            };
            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src, &dst);
            tcp_packet.set_checksum(checksum);
        }

        Bytes::from(packet)
    }

    #[tokio::test]
    async fn fake_payload_does_not_advance_header_ack() {
        let (socket, incoming, tun) = socket_with_state(Some(777), State::Established);

        incoming
            .send(inbound_packet(
                &socket,
                1001,
                0,
                tcp::TcpFlags::ACK,
                Some(b"data"),
            ))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"data");
        assert_eq!(socket.ack.load(Ordering::Relaxed), 777);

        socket.try_send(b"reply").unwrap();
        let sent = tun.sent_packets();
        assert_eq!(sent.len(), 1);
        let (_, _, _, tcp_packet) = parse_ip_packet(&sent[0]).unwrap();
        assert_eq!(tcp_packet.get_acknowledgement(), 777);
        assert_eq!(tcp_packet.payload(), b"reply");
    }

    #[tokio::test]
    async fn server_established_socket_initializes_seq_from_recorded_syn_ack() {
        let tun = Arc::new(MockTun::new());
        let tun_trait: Arc<dyn Tun> = tun.clone();
        let mut stack = Stack::new(
            tun_trait,
            "10.0.0.1".parse().unwrap(),
            None,
            Some(test_mac(1)),
        );
        let local_addr: SocketAddr = "10.0.0.1:10000".parse().unwrap();
        let remote_addr: SocketAddr = "10.0.0.2:20000".parse().unwrap();
        let tuple = AddrTuple::new(local_addr, remote_addr);

        let syn = build_tcp_packet(
            test_mac(2),
            test_mac(1),
            remote_addr,
            local_addr,
            1000,
            0,
            tcp::TcpFlags::SYN,
            None,
        );
        let (_, _, _, syn_packet) = parse_ip_packet(&syn).unwrap();
        record_initial_tcp_state(&stack.shared.initial_tcp_state, tuple.clone(), &syn_packet);

        let final_ack = build_tcp_packet(
            test_mac(2),
            test_mac(1),
            remote_addr,
            local_addr,
            1001,
            6000,
            tcp::TcpFlags::ACK,
            None,
        );
        let (_, _, _, ack_packet) = parse_ip_packet(&final_ack).unwrap();
        record_initial_tcp_state(&stack.shared.initial_tcp_state, tuple.clone(), &ack_packet);

        let socket = stack
            .alloc_established_socket(local_addr, remote_addr, State::Established)
            .await;

        assert_eq!(socket.seq.load(Ordering::Relaxed), 6000);
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1001);
        assert!(
            !stack
                .shared
                .initial_tcp_state
                .read()
                .unwrap()
                .contains_key(&tuple)
        );

        socket.try_send(b"first").unwrap();
        let sent = tun.sent_packets();
        assert_eq!(sent.len(), 1);
        let (_, _, _, tcp_packet) = parse_ip_packet(&sent[0]).unwrap();
        assert_eq!(tcp_packet.get_sequence(), 6000);
        assert_eq!(tcp_packet.get_acknowledgement(), 1001);
        assert_eq!(tcp_packet.payload(), b"first");
    }

    #[tokio::test]
    async fn sack_zero_fill_still_sends_filler() {
        let (socket, incoming, tun) = socket_with_state(Some(1001), State::Established);

        incoming
            .send(inbound_sack_packet(
                &socket, 1001, 5000, 5120, 5300, b"data",
            ))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"data");
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1001);

        let sent = tun.sent_packets();
        assert_eq!(sent.len(), 1);
        let (_, _, _, tcp_packet) = parse_ip_packet(&sent[0]).unwrap();
        assert_eq!(tcp_packet.get_sequence(), 5000);
        assert_eq!(tcp_packet.get_acknowledgement(), 1001);
        assert_eq!(tcp_packet.get_flags(), tcp::TcpFlags::ACK);
        assert_eq!(tcp_packet.payload().len(), 120);
        assert!(tcp_packet.payload().iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn zero_filler_payload_is_dropped_before_upper_layer() {
        let (socket, incoming, _tun) = socket_with_state(Some(1001), State::Established);

        incoming
            .send(inbound_packet(
                &socket,
                4000,
                0,
                tcp::TcpFlags::ACK,
                Some(&[0, 0, 0, 0]),
            ))
            .unwrap();
        incoming
            .send(inbound_packet(
                &socket,
                1001,
                0,
                tcp::TcpFlags::ACK,
                Some(b"real"),
            ))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"real");
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1001);
    }
}

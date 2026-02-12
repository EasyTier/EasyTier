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

use crate::common::scoped_task::ScopedTask;

use super::packet::*;
use bytes::{Bytes, BytesMut};
use crossbeam::atomic::AtomicCell;
use pnet::packet::tcp::TcpOptionNumbers;
use pnet::packet::{tcp, Packet};
use pnet::util::MacAddr;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, RwLock,
};
use tokio::sync::broadcast;
use tokio::time;
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
    listening: RwLock<HashSet<u16>>,
    tun: Arc<dyn Tun>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

pub struct Stack {
    shared: Arc<Shared>,
    local_ip: Ipv4Addr,
    local_ip6: Option<Ipv6Addr>,
    local_mac: MacAddr,
    reader_task: ScopedTask<()>,
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

                    let (src_mac, dst_mac, _v4_packet, tcp_packet) =
                        parse_ip_packet(&raw_buf).unwrap();

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

                    let new_ack = tcp_packet.get_sequence().wrapping_add(payload.len() as u32);
                    self.ack.store(new_ack, Ordering::Relaxed);

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

                    buf.extend_from_slice(payload);

                    return Some(payload.len());
                }
                State::SynSent => {
                    let Ok(Ok(buf)) = time::timeout(TIMEOUT, self.incoming.recv_async()).await
                    else {
                        info!("Waiting for client SYN + ACK timed out");
                        return None;
                    };
                    let (src_mac, _dst_mac, _v4_packet, tcp_packet) =
                        parse_ip_packet(&buf).unwrap();

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
                            .store(tcp_packet.get_sequence() + 1, Ordering::Relaxed);
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
            reader_task: t.into(),
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
        let mut tuples = self.shared.tuples.write().unwrap();
        let (sock, incoming) = Socket::new(
            self.shared.clone(),
            // self.shared.tun.choose(&mut rng).unwrap().clone(),
            self.shared.tun.clone(), // Simplification: just use the first tun
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            Some(0), // Initial ACK
            state,
        );
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

                            if tcp_packet.get_flags() == tcp::TcpFlags::SYN
                                && shared
                                    .listening
                                    .read()
                                    .unwrap()
                                    .contains(&tcp_packet.get_destination())
                            {
                                trace!(?tcp_packet, "Received SYN packet for port {}, ignoring", tcp_packet.get_destination());
                                continue;
                            } else if (tcp_packet.get_flags() & tcp::TcpFlags::RST) == 0 {
                                info!("Unknown RST TCP packet from {}, ignoring", remote_addr);
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
                    trace!("Removed cached tuple: {:?}", tuple);
                }
            }
        }
    }
}

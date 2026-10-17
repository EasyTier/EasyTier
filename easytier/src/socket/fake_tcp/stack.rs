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
use std::collections::HashMap;
use std::fmt;
#[cfg(test)]
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicU32, Ordering},
};
use tokio::sync::broadcast;
use tokio::time;
use tokio_util::task::AbortOnDropHandle;
use tracing::{error, info, trace, warn};

const TIMEOUT: time::Duration = time::Duration::from_secs(1);
const INITIAL_TCP_STATE_TTL: time::Duration = time::Duration::from_secs(60);
const INITIAL_TCP_STATE_CLEANUP_INTERVAL: time::Duration = time::Duration::from_secs(10);
const MPMC_BUFFER_LEN: usize = 512;
const TCP_OPTION_END: u8 = 0;
const TCP_OPTION_NOP: u8 = 1;
const TCP_OPTION_SACK: u8 = 5;

fn tcp_seq_forward_distance(from: u32, to: u32) -> Option<u32> {
    let distance = to.wrapping_sub(from);
    (distance != 0 && distance < (1 << 31)).then_some(distance)
}

struct TcpOptionIter<'a> {
    remaining: &'a [u8],
}

impl<'a> TcpOptionIter<'a> {
    fn new(options: &'a [u8]) -> Self {
        Self { remaining: options }
    }
}

impl<'a> Iterator for TcpOptionIter<'a> {
    type Item = (u8, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let kind = *self.remaining.first()?;
        if kind == TCP_OPTION_END {
            self.remaining = &[];
            return None;
        }
        if kind == TCP_OPTION_NOP {
            self.remaining = &self.remaining[1..];
            return Some((kind, &[]));
        }
        let Some(&length) = self.remaining.get(1) else {
            self.remaining = &[];
            return None;
        };
        let length = usize::from(length);
        if length < 2 || length > self.remaining.len() {
            self.remaining = &[];
            return None;
        }
        let payload = &self.remaining[2..length];
        self.remaining = &self.remaining[length..];
        Some((kind, payload))
    }
}

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

#[derive(Default)]
struct StackState {
    tuples: HashMap<AddrTuple, flume::Sender<Bytes>>,
    initial_tcp_state: HashMap<AddrTuple, TcpInitialState>,
    closed: bool,
}

struct Shared {
    state: RwLock<StackState>,
    tun: Arc<dyn Tun>,
    tuples_purge: broadcast::Sender<AddrTuple>,
}

impl Shared {
    fn is_closed(&self) -> bool {
        self.state.read().unwrap().closed
    }

    fn mark_closed_and_clear_tuples(&self) -> usize {
        let mut state = self.state.write().unwrap();
        state.closed = true;
        let len = state.tuples.len();
        state.tuples.clear();
        state.initial_tcp_state.clear();
        len
    }
}

#[derive(Clone, Copy, Debug)]
struct TcpInitialState {
    // Captured from kernel handshake packets before the fake socket is accepted.
    seq: Option<u32>,
    ack: u32,
    created_at: time::Instant,
}

fn record_initial_tcp_state(
    state: &RwLock<StackState>,
    tuple: AddrTuple,
    tcp_packet: &smoltcp::wire::TcpPacket<&[u8]>,
    now: time::Instant,
) {
    if tcp_packet.rst() {
        state.write().unwrap().initial_tcp_state.remove(&tuple);
        return;
    }

    if tcp_packet.syn() && !tcp_packet.ack() {
        let ack = (tcp_packet.seq_number().0 as u32).wrapping_add(1);
        let mut state = state.write().unwrap();
        let should_replace = match state.initial_tcp_state.get_mut(&tuple) {
            Some(initial) if initial.ack == ack && initial_tcp_state_is_fresh(initial, now) => {
                // A retransmitted SYN refreshes the pending handshake without
                // discarding a final ACK that may already have been captured.
                initial.created_at = now;
                false
            }
            _ => true,
        };
        if should_replace {
            state.initial_tcp_state.insert(
                tuple,
                TcpInitialState {
                    seq: None,
                    ack,
                    created_at: now,
                },
            );
        }
        return;
    }

    if tcp_packet.ack() && !tcp_packet.syn() && tcp_packet.payload().is_empty() {
        let mut state = state.write().unwrap();
        let Some(initial) = state.initial_tcp_state.get_mut(&tuple) else {
            return;
        };
        if !initial_tcp_state_is_fresh(initial, now) {
            state.initial_tcp_state.remove(&tuple);
            return;
        }

        // A final handshake ACK must use the sequence immediately after the
        // peer SYN. Ignore unrelated or stale ACK-only packets for this tuple.
        if initial.seq.is_none() && tcp_packet.seq_number().0 as u32 == initial.ack {
            initial.seq = Some(tcp_packet.ack_number().0 as u32);
        }
    }
}

fn initial_tcp_state_is_fresh(initial: &TcpInitialState, now: time::Instant) -> bool {
    now.saturating_duration_since(initial.created_at) < INITIAL_TCP_STATE_TTL
}

fn prune_expired_initial_tcp_state(state: &RwLock<StackState>, now: time::Instant) -> usize {
    let mut state = state.write().unwrap();
    let before = state.initial_tcp_state.len();
    state
        .initial_tcp_state
        .retain(|_, initial| initial_tcp_state_is_fresh(initial, now));
    before - state.initial_tcp_state.len()
}

pub struct Stack {
    shared: Arc<Shared>,
    local_mac: MacAddr,
    reader_task: AbortOnDropHandle<()>,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Idle,
    SynSent,
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
            self.remote_mac.load().unwrap_or_default(),
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
                let buf = self.build_tcp_packet(TCP_FLAG_ACK, Some(payload));
                self.seq.fetch_add(payload.len() as u32, Ordering::Relaxed);
                self.tun.try_send(&buf).ok().and(Some(()))
            }
            _ => unreachable!(),
        }
    }

    pub fn close(&self) {
        if self.state.load() != State::Idle {
            let buf = self.build_tcp_packet(TCP_FLAG_RST, None);
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

                    if tcp_packet.rst() {
                        info!("Connection {} reset by peer", self);
                        return None;
                    }

                    if tcp_packet.ack() && tcp_packet.payload().is_empty() {
                        self.seq
                            .store(tcp_packet.ack_number().0 as u32, Ordering::Relaxed);
                    }

                    let payload = tcp_packet.payload();

                    for (kind, option_payload) in TcpOptionIter::new(tcp_packet.options()) {
                        if kind == TCP_OPTION_SACK {
                            // SACK 选项类型为 5
                            for chunk in option_payload.chunks(8) {
                                if chunk.len() != 8 {
                                    continue;
                                }
                                let left = tcp_packet.ack_number().0 as u32;
                                let sack_start =
                                    u32::from_be_bytes(chunk[0..4].try_into().unwrap());
                                let sack_end = u32::from_be_bytes(chunk[4..8].try_into().unwrap());
                                let Some(len) = tcp_seq_forward_distance(left, sack_start) else {
                                    continue;
                                };
                                if tcp_seq_forward_distance(sack_start, sack_end).is_none() {
                                    continue;
                                }

                                let send_len = std::cmp::min(len, 1400) as usize;
                                let data = vec![0u8; send_len];

                                let buf = build_tcp_packet(
                                    self.local_mac,
                                    self.remote_mac.load().unwrap_or_default(),
                                    self.local_addr,
                                    self.remote_addr,
                                    left,
                                    self.ack.load(Ordering::Relaxed),
                                    TCP_FLAG_ACK,
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

                    // Zero-fill packets only pacify the TCP stack. Production
                    // data contains a complete framed EasyTier packet, whose
                    // length and protocol headers make it non-zero.
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

                    if tcp_packet.rst() {
                        tracing::trace!("Connection {} reset by peer", self);
                        return None;
                    }

                    if tcp_packet.syn() && tcp_packet.ack() {
                        // found our SYN + ACK
                        self.seq
                            .store(tcp_packet.ack_number().0 as u32, Ordering::Relaxed);
                        self.ack.store(
                            (tcp_packet.seq_number().0 as u32).wrapping_add(1),
                            Ordering::Relaxed,
                        );
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
        let (removed, closed) = {
            let mut state = self.shared.state.write().unwrap();
            (state.tuples.remove(&tuple).is_some(), state.closed)
        };
        if !removed {
            if closed {
                trace!(?tuple, "Fake TCP tuple already removed after stack closed");
            } else {
                warn!(?tuple, "Fake TCP tuple missing while dropping socket");
            }
        }
        // purge cache
        let _ = self.shared.tuples_purge.send(tuple);

        let buf = build_tcp_packet(
            self.local_mac,
            self.remote_mac.load().unwrap_or_default(),
            self.local_addr,
            self.remote_addr,
            self.seq.load(Ordering::Relaxed),
            0,
            TCP_FLAG_RST,
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
    pub fn new(tun: Arc<dyn Tun>, local_mac: Option<MacAddr>) -> Stack {
        let (tuples_purge_tx, _tuples_purge_rx) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            state: RwLock::new(StackState::default()),
            tun: tun.clone(),
            tuples_purge: tuples_purge_tx.clone(),
        });

        let t = tokio::spawn(Stack::reader_task(
            tun,
            shared.clone(),
            tuples_purge_tx.subscribe(),
        ));

        Stack {
            shared,
            local_mac: local_mac.unwrap_or_default(),
            reader_task: AbortOnDropHandle::new(t),
        }
    }

    /// Returns the driver type of the stack.
    pub fn driver_type(&self) -> &'static str {
        self.shared.tun.driver_type()
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed() || self.reader_task.is_finished()
    }

    pub fn try_alloc_established_socket(
        &self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        state: State,
    ) -> Option<Socket> {
        let tuple = AddrTuple::new(local_addr, remote_addr);
        let mut stack_state = self.shared.state.write().unwrap();
        if stack_state.closed || self.reader_task.is_finished() {
            stack_state.closed = true;
            warn!(
                ?tuple,
                "fake_tcp stack is closed, refusing to allocate socket"
            );
            return None;
        }
        let initial_tcp_state = if state == State::Established {
            stack_state
                .initial_tcp_state
                .remove(&tuple)
                .filter(|initial| initial_tcp_state_is_fresh(initial, time::Instant::now()))
        } else {
            None
        };
        let (sock, incoming) = Socket::new(
            self.shared.clone(),
            // self.shared.tun.choose(&mut rng).unwrap().clone(),
            self.shared.tun.clone(), // Simplification: just use the first tun
            local_addr,
            remote_addr,
            self.local_mac,
            None,
            initial_tcp_state.map(|state| state.ack),
            state,
        );
        if let Some(initial_seq) = initial_tcp_state.and_then(|state| state.seq) {
            sock.seq.store(initial_seq, Ordering::Relaxed);
        }
        assert!(stack_state.tuples.insert(tuple, incoming).is_none());
        Some(sock)
    }

    async fn reader_task(
        tun: Arc<dyn Tun>,
        shared: Arc<Shared>,
        mut tuples_purge: broadcast::Receiver<AddrTuple>,
    ) {
        let mut tuples: HashMap<AddrTuple, flume::Sender<Bytes>> = HashMap::new();
        let mut initial_state_cleanup = time::interval(INITIAL_TCP_STATE_CLEANUP_INTERVAL);
        initial_state_cleanup.set_missed_tick_behavior(time::MissedTickBehavior::Skip);

        loop {
            let mut buf = BytesMut::new();

            tokio::select! {
                size = tun.recv(&mut buf) => {
                    let size = match size {
                        Ok(size) => size,
                        Err(e) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            error!(
                                ?e,
                                driver_type = tun.driver_type(),
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tun recv failed, reader_task exiting"
                            );
                            break;
                        }
                    };
                    tracing::trace!(len = size, ?buf, "PnetTun received packet");
                    let buf = buf.split().freeze();

                    match parse_ip_packet(&buf) {
                        Some((_src_mac, _dst_mac, ip_packet, tcp_packet)) => {
                            let local_addr = SocketAddr::new(
                                ip_packet.get_destination(),
                                tcp_packet.dst_port(),
                            );
                            let remote_addr = SocketAddr::new(
                                ip_packet.get_source(),
                                tcp_packet.src_port(),
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
                                    let state = shared.state.read().unwrap();
                                    state.tuples.get(&tuple).cloned()
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
                                &shared.state,
                                tuple.clone(),
                                &tcp_packet,
                                time::Instant::now(),
                            );

                            if tcp_packet.rst() {
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
                    match tuple {
                        Ok(tuple) => {
                            tuples.remove(&tuple);
                            shared
                                .state
                                .write()
                                .unwrap()
                                .initial_tcp_state
                                .remove(&tuple);
                            trace!("Removed cached tuple: {:?}", tuple);
                        }
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                skipped,
                                cached_tuple_count,
                                "fake_tcp tuples purge receiver lagged, cleared local cache"
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            let shared_tuple_count = shared.mark_closed_and_clear_tuples();
                            let cached_tuple_count = tuples.len();
                            tuples.clear();
                            warn!(
                                shared_tuple_count,
                                cached_tuple_count,
                                "fake_tcp tuples purge channel closed, reader_task exiting"
                            );
                            break;
                        }
                    }
                },
                _ = initial_state_cleanup.tick() => {
                    let removed = prune_expired_initial_tcp_state(
                        &shared.state,
                        time::Instant::now(),
                    );
                    if removed != 0 {
                        trace!(removed, "Removed expired fake TCP handshake state");
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::Mutex;
    use tokio::{
        sync::Notify,
        time::{Duration, timeout},
    };

    #[test]
    fn tcp_option_iterator_preserves_all_sack_blocks() {
        for block_count in 1..=4_u32 {
            let mut options = vec![TCP_OPTION_NOP, TCP_OPTION_SACK, (2 + block_count * 8) as u8];
            for block in 0..block_count {
                options.extend_from_slice(&(100 + block * 10).to_be_bytes());
                options.extend_from_slice(&(110 + block * 10).to_be_bytes());
            }
            options.push(TCP_OPTION_END);

            let parsed = TcpOptionIter::new(&options).collect::<Vec<_>>();
            assert_eq!(parsed[0], (TCP_OPTION_NOP, &[][..]));
            assert_eq!(parsed[1].0, TCP_OPTION_SACK);
            assert_eq!(parsed[1].1.len(), block_count as usize * 8);
            let last = parsed[1].1.len() - 8;
            assert_eq!(
                u32::from_be_bytes(parsed[1].1[last..last + 4].try_into().unwrap()),
                100 + (block_count - 1) * 10
            );
            assert_eq!(
                u32::from_be_bytes(parsed[1].1[last + 4..last + 8].try_into().unwrap()),
                110 + (block_count - 1) * 10
            );
        }
    }

    #[test]
    fn tcp_option_iterator_stops_at_end_or_malformed_length() {
        assert_eq!(
            TcpOptionIter::new(&[TCP_OPTION_END, TCP_OPTION_SACK, 2]).count(),
            0
        );
        assert_eq!(TcpOptionIter::new(&[TCP_OPTION_SACK]).count(), 0);
        assert_eq!(TcpOptionIter::new(&[TCP_OPTION_SACK, 1]).count(), 0);
        assert_eq!(TcpOptionIter::new(&[TCP_OPTION_SACK, 10, 0, 0]).count(), 0);
    }

    #[test]
    fn tcp_sequence_forward_distance_handles_wraparound() {
        assert_eq!(tcp_seq_forward_distance(u32::MAX - 15, 16), Some(32));
        assert_eq!(tcp_seq_forward_distance(100, 101), Some(1));
        assert_eq!(tcp_seq_forward_distance(100, 100), None);
        assert_eq!(tcp_seq_forward_distance(101, 100), None);
        assert_eq!(tcp_seq_forward_distance(0, 1 << 31), None);
    }

    #[derive(Default)]
    struct FailingTun {
        fail: Notify,
    }

    impl FailingTun {
        fn fail(&self) {
            self.fail.notify_one();
        }
    }

    #[async_trait::async_trait]
    impl Tun for FailingTun {
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
            self.fail.notified().await;
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "test tun closed"))
        }

        fn try_send(&self, _packet: &Bytes) -> Result<(), io::Error> {
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "test"
        }
    }

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
        async fn recv(&self, _packet: &mut BytesMut) -> Result<usize, io::Error> {
            std::future::pending::<Result<usize, io::Error>>().await
        }

        fn try_send(&self, packet: &Bytes) -> Result<(), io::Error> {
            self.sent.lock().unwrap().push(packet.clone());
            Ok(())
        }

        fn driver_type(&self) -> &'static str {
            "mock"
        }
    }

    fn test_mac(id: u8) -> MacAddr {
        MacAddr::from_bytes(&[0, 1, 2, 3, 4, id])
    }

    fn socket_with_state(
        ack: Option<u32>,
        state: State,
    ) -> (Socket, flume::Sender<Bytes>, Arc<MockTun>) {
        let tun = Arc::new(MockTun::new());
        let tun_trait: Arc<dyn Tun> = tun.clone();
        let (tuples_purge, _) = broadcast::channel(16);
        let shared = Arc::new(Shared {
            state: RwLock::new(StackState::default()),
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
            .state
            .write()
            .unwrap()
            .tuples
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

    fn packet_for_tuple(
        tuple: &AddrTuple,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Option<&[u8]>,
    ) -> Bytes {
        build_tcp_packet(
            test_mac(2),
            test_mac(1),
            tuple.remote_addr,
            tuple.local_addr,
            seq,
            ack,
            flags,
            payload,
        )
    }

    fn record_packet(
        state: &RwLock<StackState>,
        tuple: AddrTuple,
        packet: &Bytes,
        now: time::Instant,
    ) {
        let (_, _, _, tcp_packet) = parse_ip_packet(packet).unwrap();
        record_initial_tcp_state(state, tuple, &tcp_packet, now);
    }

    fn inbound_sack_packet(
        socket: &Socket,
        seq: u32,
        ack: u32,
        first_sack_left: u32,
        first_sack_right: u32,
        payload: &[u8],
    ) -> Bytes {
        use smoltcp::wire::{ETHERNET_HEADER_LEN, IPV4_HEADER_LEN, TCP_HEADER_LEN};

        let mut tcp_payload = vec![0u8; 12];
        tcp_payload[0] = TCP_OPTION_SACK;
        tcp_payload[1] = 10;
        tcp_payload[2..6].copy_from_slice(&first_sack_left.to_be_bytes());
        tcp_payload[6..10].copy_from_slice(&first_sack_right.to_be_bytes());
        tcp_payload[10] = TCP_OPTION_NOP;
        tcp_payload[11] = TCP_OPTION_NOP;
        tcp_payload.extend_from_slice(payload);

        let mut packet =
            inbound_packet(socket, seq, ack, TCP_FLAG_ACK, Some(&tcp_payload)).to_vec();
        let tcp_start = ETHERNET_HEADER_LEN + IPV4_HEADER_LEN;
        packet[tcp_start + 12] = (((TCP_HEADER_LEN + 12) / 4) as u8) << 4;
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
                TCP_FLAG_ACK,
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
        assert_eq!(tcp_packet.ack_number().0 as u32, 777);
        assert_eq!(tcp_packet.payload(), b"reply");
    }

    #[test]
    fn orphan_ack_does_not_create_initial_tcp_state() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let ack = packet_for_tuple(&tuple, 1001, 6000, TCP_FLAG_ACK, None);

        record_packet(&state, tuple, &ack, time::Instant::now());

        assert!(state.read().unwrap().initial_tcp_state.is_empty());
    }

    #[test]
    fn final_ack_must_match_recorded_syn_sequence() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let now = time::Instant::now();
        let syn = packet_for_tuple(&tuple, 1000, 0, TCP_FLAG_SYN, None);
        let wrong_ack = packet_for_tuple(&tuple, 1002, 6000, TCP_FLAG_ACK, None);
        let final_ack = packet_for_tuple(&tuple, 1001, 6000, TCP_FLAG_ACK, None);

        record_packet(&state, tuple.clone(), &syn, now);
        record_packet(&state, tuple.clone(), &wrong_ack, now);
        assert_eq!(
            state
                .read()
                .unwrap()
                .initial_tcp_state
                .get(&tuple)
                .unwrap()
                .seq,
            None
        );

        record_packet(&state, tuple.clone(), &final_ack, now);
        assert_eq!(
            state
                .read()
                .unwrap()
                .initial_tcp_state
                .get(&tuple)
                .unwrap()
                .seq,
            Some(6000)
        );

        let later_ack = packet_for_tuple(&tuple, 1001, 7000, TCP_FLAG_ACK, None);
        record_packet(&state, tuple.clone(), &later_ack, now);
        assert_eq!(
            state
                .read()
                .unwrap()
                .initial_tcp_state
                .get(&tuple)
                .unwrap()
                .seq,
            Some(6000)
        );
    }

    #[test]
    fn retransmitted_syn_preserves_recorded_final_ack() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let now = time::Instant::now();
        let syn = packet_for_tuple(&tuple, 1000, 0, TCP_FLAG_SYN, None);
        let final_ack = packet_for_tuple(&tuple, 1001, 6000, TCP_FLAG_ACK, None);

        record_packet(&state, tuple.clone(), &syn, now);
        record_packet(&state, tuple.clone(), &final_ack, now);
        record_packet(
            &state,
            tuple.clone(),
            &syn,
            now + time::Duration::from_secs(1),
        );

        let state = state.read().unwrap();
        let initial = state.initial_tcp_state.get(&tuple).unwrap();
        assert_eq!(initial.seq, Some(6000));
        assert_eq!(initial.created_at, now + time::Duration::from_secs(1));
    }

    #[test]
    fn syn_replaces_expired_initial_tcp_state() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let now = time::Instant::now();
        let syn = packet_for_tuple(&tuple, 1000, 0, TCP_FLAG_SYN, None);
        let final_ack = packet_for_tuple(&tuple, 1001, 6000, TCP_FLAG_ACK, None);

        record_packet(&state, tuple.clone(), &syn, now - INITIAL_TCP_STATE_TTL);
        record_packet(
            &state,
            tuple.clone(),
            &final_ack,
            now - INITIAL_TCP_STATE_TTL,
        );
        record_packet(&state, tuple.clone(), &syn, now);

        let state = state.read().unwrap();
        let initial = state.initial_tcp_state.get(&tuple).unwrap();
        assert_eq!(initial.seq, None);
        assert_eq!(initial.created_at, now);
    }

    #[test]
    fn rst_removes_initial_tcp_state() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let now = time::Instant::now();
        let syn = packet_for_tuple(&tuple, 1000, 0, TCP_FLAG_SYN, None);
        let rst = packet_for_tuple(&tuple, 1001, 0, TCP_FLAG_RST, None);

        record_packet(&state, tuple.clone(), &syn, now);
        assert!(state.read().unwrap().initial_tcp_state.contains_key(&tuple));

        record_packet(&state, tuple, &rst, now);
        assert!(state.read().unwrap().initial_tcp_state.is_empty());
    }

    #[test]
    fn expired_initial_tcp_state_is_pruned() {
        let state = RwLock::new(StackState::default());
        let expired_tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let fresh_tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20001".parse().unwrap(),
        );
        let now = time::Instant::now();
        let expired_syn = packet_for_tuple(&expired_tuple, 1000, 0, TCP_FLAG_SYN, None);
        let fresh_syn = packet_for_tuple(&fresh_tuple, 2000, 0, TCP_FLAG_SYN, None);

        record_packet(
            &state,
            expired_tuple.clone(),
            &expired_syn,
            now - INITIAL_TCP_STATE_TTL,
        );
        record_packet(&state, fresh_tuple.clone(), &fresh_syn, now);

        assert_eq!(prune_expired_initial_tcp_state(&state, now), 1);
        let state = state.read().unwrap();
        assert!(!state.initial_tcp_state.contains_key(&expired_tuple));
        assert!(state.initial_tcp_state.contains_key(&fresh_tuple));
    }

    #[test]
    fn expired_initial_tcp_state_ignores_final_ack() {
        let state = RwLock::new(StackState::default());
        let tuple = AddrTuple::new(
            "10.0.0.1:10000".parse().unwrap(),
            "10.0.0.2:20000".parse().unwrap(),
        );
        let now = time::Instant::now();
        let syn = packet_for_tuple(&tuple, 1000, 0, TCP_FLAG_SYN, None);
        let final_ack = packet_for_tuple(&tuple, 1001, 6000, TCP_FLAG_ACK, None);

        record_packet(&state, tuple.clone(), &syn, now - INITIAL_TCP_STATE_TTL);
        record_packet(&state, tuple, &final_ack, now);

        assert!(state.read().unwrap().initial_tcp_state.is_empty());
    }

    #[tokio::test]
    async fn server_established_socket_initializes_seq_from_recorded_syn_ack() {
        let tun = Arc::new(MockTun::new());
        let tun_trait: Arc<dyn Tun> = tun.clone();
        let stack = Stack::new(tun_trait, Some(test_mac(1)));
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
            TCP_FLAG_SYN,
            None,
        );
        let (_, _, _, syn_packet) = parse_ip_packet(&syn).unwrap();
        record_initial_tcp_state(
            &stack.shared.state,
            tuple.clone(),
            &syn_packet,
            time::Instant::now(),
        );

        let final_ack = build_tcp_packet(
            test_mac(2),
            test_mac(1),
            remote_addr,
            local_addr,
            1001,
            6000,
            TCP_FLAG_ACK,
            None,
        );
        let (_, _, _, ack_packet) = parse_ip_packet(&final_ack).unwrap();
        record_initial_tcp_state(
            &stack.shared.state,
            tuple.clone(),
            &ack_packet,
            time::Instant::now(),
        );

        let socket = stack
            .try_alloc_established_socket(local_addr, remote_addr, State::Established)
            .unwrap();

        assert_eq!(socket.seq.load(Ordering::Relaxed), 6000);
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1001);
        assert!(
            !stack
                .shared
                .state
                .read()
                .unwrap()
                .initial_tcp_state
                .contains_key(&tuple)
        );

        socket.try_send(b"first").unwrap();
        let sent = tun.sent_packets();
        assert_eq!(sent.len(), 1);
        let (_, _, _, tcp_packet) = parse_ip_packet(&sent[0]).unwrap();
        assert_eq!(tcp_packet.seq_number().0 as u32, 6000);
        assert_eq!(tcp_packet.ack_number().0 as u32, 1001);
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
        assert_eq!(tcp_packet.seq_number().0 as u32, 5000);
        assert_eq!(tcp_packet.ack_number().0 as u32, 1001);
        assert_eq!(tcp_flags(&tcp_packet), TCP_FLAG_ACK);
        assert_eq!(tcp_packet.payload().len(), 120);
        assert!(tcp_packet.payload().iter().all(|&b| b == 0));
    }

    #[tokio::test]
    async fn sack_zero_fill_handles_sequence_wraparound() {
        let (socket, incoming, tun) = socket_with_state(Some(1001), State::Established);
        let ack = u32::MAX - 15;

        incoming
            .send(inbound_sack_packet(&socket, 1001, ack, 16, 32, b"data"))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));

        let sent = tun.sent_packets();
        assert_eq!(sent.len(), 1);
        let (_, _, _, tcp_packet) = parse_ip_packet(&sent[0]).unwrap();
        assert_eq!(tcp_packet.seq_number().0 as u32, ack);
        assert_eq!(tcp_packet.payload().len(), 32);
    }

    #[tokio::test]
    async fn sack_zero_fill_rejects_backward_block() {
        let (socket, incoming, tun) = socket_with_state(Some(1001), State::Established);

        incoming
            .send(inbound_sack_packet(
                &socket, 1001, 5000, 4900, 5100, b"data",
            ))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert!(tun.sent_packets().is_empty());
    }

    #[tokio::test]
    async fn zero_filler_payload_is_dropped_before_upper_layer() {
        let (socket, incoming, _tun) = socket_with_state(Some(1001), State::Established);

        incoming
            .send(inbound_packet(
                &socket,
                4000,
                0,
                TCP_FLAG_ACK,
                Some(&[0, 0, 0, 0]),
            ))
            .unwrap();
        incoming
            .send(inbound_packet(
                &socket,
                1001,
                0,
                TCP_FLAG_ACK,
                Some(b"real"),
            ))
            .unwrap();

        let mut buf = BytesMut::new();
        assert_eq!(socket.recv(&mut buf).await, Some(4));
        assert_eq!(&buf[..], b"real");
        assert_eq!(socket.ack.load(Ordering::Relaxed), 1001);
    }

    #[tokio::test]
    async fn reader_task_closes_sockets_on_tun_recv_error() {
        let tun = Arc::new(FailingTun::default());
        let mut stack = Stack::new(tun.clone(), None);
        let socket = stack
            .try_alloc_established_socket(
                SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_000),
                SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_000),
                State::Established,
            )
            .expect("socket allocation should succeed before tun failure");

        tun.fail();

        let join_result = timeout(Duration::from_secs(1), &mut stack.reader_task)
            .await
            .expect("reader task should exit after tun recv error");
        assert!(join_result.is_ok());
        assert!(stack.is_closed());

        let mut buf = BytesMut::new();
        let recv_result = timeout(Duration::from_secs(1), socket.recv(&mut buf))
            .await
            .expect("socket recv should not hang after reader task exits");
        assert_eq!(recv_result, None);

        let new_socket = stack.try_alloc_established_socket(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 10_001),
            SocketAddr::new(Ipv4Addr::new(192, 0, 2, 1).into(), 20_001),
            State::Established,
        );
        assert!(new_socket.is_none());

        drop(socket);
    }
}

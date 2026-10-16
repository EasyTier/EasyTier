use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    ops::Bound::{Excluded, Included, Unbounded},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use cidr::{Inet, Ipv4Inet, Ipv6Inet};
use futures::{Sink, SinkExt, Stream, StreamExt, future::poll_fn, task::noop_waker_ref};
use smoltcp::wire::{
    Icmpv4Message, Icmpv4Packet, Icmpv6Message, Icmpv6Packet, IpAddress, IpProtocol, Ipv4Packet,
    Ipv6Packet, TcpPacket, UdpPacket,
};
#[cfg(any(mobile, all(test, unix)))]
use tokio::sync::Mutex;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

use crate::common::error::Error;
#[cfg(any(mobile, all(test, unix)))]
use crate::instance::virtual_nic::VirtualNic;
use easytier_core::{
    packet::ZCPacket,
    tunnel::{
        Tunnel, ZCPacketSink, ZCPacketStream,
        ring::{RingSink, RingStream, RingTunnel, create_ring_socket_pair, split_ring_socket},
    },
};

use super::{
    SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route, SharedVirtualNicMemberId,
    SharedVirtualNicMemberRegistrationId, shared_virtual_nic_runtime,
};

const MEMBER_TUNNEL_BUFFER_SIZE: usize = 1024;
const FLOW_OWNER_LIMIT: usize = 4096;
// Match the core UDP proxy's idle lifetime; reclaim lazily under table pressure.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const DISPATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const DISPATCHER_TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

#[cfg(any(mobile, all(test, unix)))]
struct SharedVirtualNicMobileTunUpdate {
    tun_fd: std::os::fd::RawFd,
    ack: oneshot::Sender<Result<(), Error>>,
}

enum SharedVirtualNicControl {
    #[cfg(any(mobile, all(test, unix)))]
    UpdateMobileTun(SharedVirtualNicMobileTunUpdate),
    Register {
        member_id: SharedVirtualNicMemberId,
        entry: SharedVirtualNicMemberTunnelEntry,
    },
    Unregister {
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    },
    UpdateSources {
        member_id: SharedVirtualNicMemberId,
        sources: SharedVirtualNicMemberSources,
        ack: oneshot::Sender<()>,
    },
    Shutdown {
        invalidate: bool,
        ack: oneshot::Sender<()>,
    },
}

#[derive(Clone, Default)]
pub(super) struct SharedVirtualNicMemberTunnelTable {
    control_sender: Arc<StdMutex<Option<mpsc::UnboundedSender<SharedVirtualNicControl>>>>,
}

struct SharedVirtualNicMemberTunnelEntry {
    registration_id: SharedVirtualNicMemberRegistrationId,
    stream: RingStream,
    sink: RingSink,
    close_notifier: Arc<Notify>,
}

impl SharedVirtualNicMemberTunnelTable {
    fn attach_dispatcher(&self, control_sender: mpsc::UnboundedSender<SharedVirtualNicControl>) {
        *self.control_sender.lock().unwrap() = Some(control_sender);
    }

    pub(super) fn detach_dispatcher(&self) {
        self.control_sender.lock().unwrap().take();
    }

    pub(super) fn register(
        &self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        close_notifier: Arc<Notify>,
    ) -> Result<Box<dyn Tunnel>, Error> {
        let control_sender = self
            .control_sender()
            .ok_or_else(|| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        let (member_socket, dispatcher_socket) = create_ring_socket_pair(MEMBER_TUNNEL_BUFFER_SIZE);
        let (stream, sink) = split_ring_socket(dispatcher_socket);
        let entry = SharedVirtualNicMemberTunnelEntry {
            registration_id,
            stream,
            sink,
            close_notifier,
        };
        control_sender
            .send(SharedVirtualNicControl::Register { member_id, entry })
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        Ok(Box::new(RingTunnel::new(member_socket, None)))
    }

    pub(super) fn unregister(
        &self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) {
        if let Some(control_sender) = self.control_sender() {
            let _ = control_sender.send(SharedVirtualNicControl::Unregister {
                member_id,
                registration_id,
            });
        }
    }

    fn control_sender(&self) -> Option<mpsc::UnboundedSender<SharedVirtualNicControl>> {
        self.control_sender.lock().unwrap().clone()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum SharedVirtualNicFlowAddr {
    V4(u32),
    V6([u8; 16]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SharedVirtualNicTransportPorts {
    src: u16,
    dst: u16,
}

impl SharedVirtualNicTransportPorts {
    fn reversed(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SharedVirtualNicFlowKey {
    src: SharedVirtualNicFlowAddr,
    dst: SharedVirtualNicFlowAddr,
    protocol: u8,
    ports: Option<SharedVirtualNicTransportPorts>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SharedVirtualNicMemberSources {
    ipv4_addresses: BTreeSet<Ipv4Inet>,
    ipv6_addresses: BTreeSet<Ipv6Inet>,
    ipv4_routes: BTreeSet<Ipv4Inet>,
    ipv6_routes: BTreeSet<Ipv6Inet>,
}

impl SharedVirtualNicMemberSources {
    fn from_claims(claims: &SharedIfConfigClaims) -> Self {
        let ipv4_addresses = claims
            .ipv4_addresses
            .iter()
            .filter(|addr| !addr.address().is_unspecified())
            .copied()
            .collect::<BTreeSet<_>>();
        let ipv6_addresses = claims
            .ipv6_addresses
            .iter()
            .filter(|addr| !addr.address().is_unspecified())
            .copied()
            .collect::<BTreeSet<_>>();
        let ipv4_routes = claims
            .ipv4_routes
            .iter()
            .filter_map(ipv4_route_to_inet)
            .collect::<BTreeSet<_>>();
        let ipv6_routes = claims
            .ipv6_routes
            .iter()
            .filter_map(ipv6_route_to_inet)
            .collect::<BTreeSet<_>>();

        Self {
            ipv4_addresses,
            ipv6_addresses,
            ipv4_routes,
            ipv6_routes,
        }
    }

    fn is_empty(&self) -> bool {
        self.ipv4_addresses.is_empty()
            && self.ipv6_addresses.is_empty()
            && self.ipv4_routes.is_empty()
            && self.ipv6_routes.is_empty()
    }

    fn owns_source(&self, source: SharedVirtualNicFlowAddr) -> bool {
        match source {
            SharedVirtualNicFlowAddr::V4(source) => self
                .ipv4_addresses
                .iter()
                .any(|address| u32::from(address.address()) == source),
            SharedVirtualNicFlowAddr::V6(source) => self
                .ipv6_addresses
                .iter()
                .any(|address| address.address().octets() == source),
        }
    }
}

fn ipv4_route_to_inet(route: &SharedIpv4Route) -> Option<Ipv4Inet> {
    Ipv4Inet::new(route.address, route.prefix).ok()
}

fn ipv6_route_to_inet(route: &SharedIpv6Route) -> Option<Ipv6Inet> {
    Ipv6Inet::new(route.address, route.prefix).ok()
}

impl From<std::net::Ipv4Addr> for SharedVirtualNicFlowAddr {
    fn from(addr: std::net::Ipv4Addr) -> Self {
        Self::V4(u32::from_be_bytes(addr.octets()))
    }
}

impl From<std::net::Ipv6Addr> for SharedVirtualNicFlowAddr {
    fn from(addr: std::net::Ipv6Addr) -> Self {
        Self::V6(addr.octets())
    }
}

impl SharedVirtualNicFlowAddr {
    fn as_ipv4(self) -> Option<std::net::Ipv4Addr> {
        match self {
            Self::V4(addr) => Some(std::net::Ipv4Addr::from(addr)),
            Self::V6(_) => None,
        }
    }

    fn as_ipv6(self) -> Option<std::net::Ipv6Addr> {
        match self {
            Self::V4(_) => None,
            Self::V6(addr) => Some(std::net::Ipv6Addr::from(addr)),
        }
    }
    fn packet_addrs(packet: &ZCPacket) -> Option<(Self, Self)> {
        let payload = packet.payload();
        match payload.first()? >> 4 {
            4 => {
                let ipv4 = Ipv4Packet::new_checked(payload).ok()?;
                Some((ipv4.src_addr().into(), ipv4.dst_addr().into()))
            }
            6 => {
                let ipv6 = Ipv6Packet::new_checked(payload).ok()?;
                Some((ipv6.src_addr().into(), ipv6.dst_addr().into()))
            }
            _ => None,
        }
    }
}

impl SharedVirtualNicFlowKey {
    fn from_packet(packet: &ZCPacket) -> Option<Self> {
        let payload = packet.payload();
        let version = payload.first()? >> 4;
        match version {
            4 => Self::from_ipv4_payload(payload),
            6 => Self::from_ipv6_payload(payload),
            _ => None,
        }
    }

    fn from_ipv4_payload(payload: &[u8]) -> Option<Self> {
        let ipv4 = Ipv4Packet::new_checked(payload).ok()?;
        if ipv4.version() != 4 {
            return None;
        }

        let protocol = ipv4.next_header().into();
        Some(Self {
            src: ipv4.src_addr().into(),
            dst: ipv4.dst_addr().into(),
            protocol,
            ports: if ipv4.frag_offset() == 0 {
                transport_ports(protocol, ipv4.payload())
            } else {
                None
            },
        })
    }

    fn from_ipv6_payload(payload: &[u8]) -> Option<Self> {
        let ipv6 = Ipv6Packet::new_checked(payload).ok()?;
        if ipv6.version() != 6 {
            return None;
        }

        let protocol = ipv6.next_header().into();
        Some(Self {
            src: ipv6.src_addr().into(),
            dst: ipv6.dst_addr().into(),
            protocol,
            ports: transport_ports(protocol, ipv6.payload()),
        })
    }

    fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
            ports: self.ports.map(|ports| {
                if matches!(
                    IpProtocol::from(self.protocol),
                    IpProtocol::Icmp | IpProtocol::Icmpv6
                ) {
                    ports
                } else {
                    ports.reversed()
                }
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedVirtualNicNatEntry {
    original: SharedVirtualNicFlowKey,
    wire: SharedVirtualNicFlowKey,
    source_owner: Option<SharedVirtualNicMemberId>,
    incoming: bool,
    last_active: Instant,
}

#[derive(Default)]
struct SharedVirtualNicNatTable {
    entries: HashMap<(SharedVirtualNicMemberId, SharedVirtualNicFlowKey), SharedVirtualNicNatEntry>,
    replies: HashMap<(SharedVirtualNicMemberId, SharedVirtualNicFlowKey), SharedVirtualNicFlowKey>,
}

impl SharedVirtualNicNatTable {
    fn prepare_packet(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        source_owner: Option<SharedVirtualNicMemberId>,
        original: SharedVirtualNicFlowKey,
        packet: &mut ZCPacket,
        translated_src: SharedVirtualNicFlowAddr,
    ) -> bool {
        if original.ports.is_none() {
            return original.src == translated_src;
        }
        let now = Instant::now();
        if let Some(entry) = self.entries.get_mut(&(member_id, original)) {
            entry.last_active = now;
            return rewrite_packet_flow(packet, original, entry.wire, RewriteIpAddr::Source);
        }
        let mut wire = original;
        wire.src = translated_src;
        // Wildcard UDP sockets may reply with another member's source address.
        // Prefer an incoming reservation after source correction, preserving its
        // service port and incoming destination. Exact outgoing mappings win above;
        // packet tuples cannot distinguish a new client with the same endpoints.
        if IpProtocol::from(original.protocol) == IpProtocol::Udp
            && let Some(entry) = self.entries.get_mut(&(member_id, wire))
            && entry.incoming
        {
            entry.last_active = now;
            return rewrite_packet_flow(packet, original, entry.wire, RewriteIpAddr::Source);
        }
        if !self.ensure_capacity(now) {
            return false;
        }

        while self.replies.contains_key(&(member_id, wire.reversed())) {
            let Some(ports) = wire.ports.as_mut() else {
                return false;
            };
            ports.src = ports.src.wrapping_add(1).max(1);
            if Some(*ports) == original.ports {
                return false;
            }
        }
        if !rewrite_packet_flow(packet, original, wire, RewriteIpAddr::Source) {
            return false;
        }
        self.entries.insert(
            (member_id, original),
            SharedVirtualNicNatEntry {
                original,
                wire,
                source_owner,
                incoming: false,
                last_active: now,
            },
        );
        self.replies.insert((member_id, wire.reversed()), original);
        true
    }

    fn reserve_reply(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        reply: SharedVirtualNicFlowKey,
    ) -> bool {
        if reply.ports.is_none() || self.replies.contains_key(&(member_id, reply)) {
            return true;
        }
        let original = reply.reversed();
        // An outgoing native flow may already have been assigned a different port.
        if self.entries.contains_key(&(member_id, original)) {
            return false;
        }
        let now = Instant::now();
        if !self.ensure_capacity(now) {
            return false;
        }
        self.entries.insert(
            (member_id, original),
            SharedVirtualNicNatEntry {
                original,
                wire: original,
                source_owner: Some(member_id),
                incoming: true,
                last_active: now,
            },
        );
        self.replies.insert((member_id, reply), original);
        true
    }

    fn ensure_capacity(&mut self, now: Instant) -> bool {
        // Reuse only idle reservations, never an active flow's wire tuple.
        if self.entries.len() >= FLOW_OWNER_LIMIT {
            self.retain(|_, entry| now.duration_since(entry.last_active) < FLOW_IDLE_TIMEOUT);
        }
        self.entries.len() < FLOW_OWNER_LIMIT
    }

    fn translate_reply(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        packet: &mut ZCPacket,
    ) -> bool {
        let Some(key) = SharedVirtualNicFlowKey::from_packet(packet) else {
            return false;
        };
        let Some(original) = self.replies.get(&(member_id, key)) else {
            return false;
        };
        self.entries
            .get_mut(&(member_id, *original))
            .unwrap()
            .last_active = Instant::now();
        rewrite_packet_flow(packet, key, original.reversed(), RewriteIpAddr::Destination)
    }

    fn remove_member(&mut self, member_id: SharedVirtualNicMemberId) {
        self.retain(|owner, entry| owner != member_id && entry.source_owner != Some(member_id));
    }

    fn remove_changed_addresses(
        &mut self,
        previous: &SharedVirtualNicMemberSources,
        current: &SharedVirtualNicMemberSources,
    ) {
        self.retain(|_, entry| {
            [entry.original.src, entry.wire.src]
                .into_iter()
                .all(|addr| !previous.owns_source(addr) || current.owns_source(addr))
        });
    }

    fn retain(
        &mut self,
        keep: impl Fn(SharedVirtualNicMemberId, &SharedVirtualNicNatEntry) -> bool,
    ) {
        self.entries.retain(|(member_id, _), entry| {
            if keep(*member_id, entry) {
                true
            } else {
                self.replies.remove(&(*member_id, entry.wire.reversed()));
                false
            }
        });
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.replies.clear();
    }
}

pub(super) struct SharedVirtualNicDispatcher {
    task: AbortOnDropHandle<()>,
    control_sender: mpsc::UnboundedSender<SharedVirtualNicControl>,
}

impl SharedVirtualNicDispatcher {
    pub(super) fn start(
        tunnel: Box<dyn Tunnel>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Self {
        let (tun_stream, tun_sink) = tunnel.split();
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        member_tunnel_table.attach_dispatcher(control_sender.clone());

        let task = SharedVirtualNicDispatcherTask {
            tun_stream: Some(tun_stream),
            tun_sink: Some(tun_sink),
            #[cfg(any(mobile, all(test, unix)))]
            mobile: None,
            control_receiver,
            member_tunnel_table,
            valid,
            state: SharedVirtualNicDispatcherState::default(),
        };

        Self {
            task: AbortOnDropHandle::new(shared_virtual_nic_runtime().spawn(task.run())),
            control_sender,
        }
    }

    #[cfg(mobile)]
    pub(super) async fn start_for_mobile(
        nic: Arc<Mutex<VirtualNic>>,
        tun_fd: std::os::fd::RawFd,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        let (first_open_sender, first_open_receiver) = oneshot::channel();
        let task_member_tunnel_table = member_tunnel_table.clone();
        member_tunnel_table.attach_dispatcher(control_sender.clone());

        let task = SharedVirtualNicDispatcherTask {
            tun_stream: None,
            tun_sink: None,
            mobile: Some(SharedVirtualNicMobileTun { nic, tun_fd }),
            control_receiver,
            member_tunnel_table: task_member_tunnel_table,
            valid,
            state: SharedVirtualNicDispatcherState {
                translate_unknown_sources: true,
                ..Default::default()
            },
        };
        let task = shared_virtual_nic_runtime().spawn(task.run_for_mobile(first_open_sender));

        let dispatcher = Self {
            task: AbortOnDropHandle::new(task),
            control_sender,
        };
        await_mobile_open(first_open_receiver)
            .await
            .map(|()| dispatcher)
    }

    #[cfg(mobile)]
    pub(super) async fn update_mobile_tun_fd(
        &self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<(), Error> {
        let (ack, receiver) = oneshot::channel();
        self.control_sender
            .send(SharedVirtualNicControl::UpdateMobileTun(
                SharedVirtualNicMobileTunUpdate { tun_fd, ack },
            ))
            .map_err(|_| {
                Error::from(anyhow::anyhow!(
                    "shared virtual nic mobile dispatcher is not running"
                ))
            })?;
        await_mobile_open(receiver).await
    }

    pub(super) async fn update_sources(
        &self,
        member_id: SharedVirtualNicMemberId,
        claims: &SharedIfConfigClaims,
    ) -> Result<(), Error> {
        self.send_source_update(
            member_id,
            SharedVirtualNicMemberSources::from_claims(claims),
        )
        .await
    }

    pub(super) async fn remove_sources(
        &self,
        member_id: SharedVirtualNicMemberId,
    ) -> Result<(), Error> {
        self.send_source_update(member_id, SharedVirtualNicMemberSources::default())
            .await
    }

    async fn send_source_update(
        &self,
        member_id: SharedVirtualNicMemberId,
        sources: SharedVirtualNicMemberSources,
    ) -> Result<(), Error> {
        let (ack, rx) = oneshot::channel();
        self.control_sender
            .send(SharedVirtualNicControl::UpdateSources {
                member_id,
                sources,
                ack,
            })
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running").into())
    }

    pub(super) async fn shutdown_without_invalidation(self) {
        let (ack, rx) = oneshot::channel();
        let sent = self
            .control_sender
            .send(SharedVirtualNicControl::Shutdown {
                invalidate: false,
                ack,
            })
            .is_ok();

        if sent
            && tokio::time::timeout(DISPATCHER_SHUTDOWN_TIMEOUT, rx)
                .await
                .is_err()
        {
            tracing::warn!("timed out shutting down shared virtual nic dispatcher");
        }
        // Even on send failure or timeout, wait for the task's TUN halves to
        // be dropped before releasing the device name for another owner.
        self.task.abort();
        let _ = self.task.await;
    }
}

struct SharedVirtualNicDispatcherTask {
    tun_stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    tun_sink: Option<Pin<Box<dyn ZCPacketSink>>>,
    #[cfg(any(mobile, all(test, unix)))]
    mobile: Option<SharedVirtualNicMobileTun>,
    control_receiver: mpsc::UnboundedReceiver<SharedVirtualNicControl>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    valid: Arc<AtomicBool>,
    state: SharedVirtualNicDispatcherState,
}

#[cfg(any(mobile, all(test, unix)))]
struct SharedVirtualNicMobileTun {
    nic: Arc<Mutex<VirtualNic>>,
    tun_fd: std::os::fd::RawFd,
}

impl SharedVirtualNicDispatcherTask {
    async fn run(mut self) {
        loop {
            // Ring polling is synchronous, including packets dropped before TUN I/O.
            tokio::task::consume_budget().await;
            tokio::select! {
                control = self.control_receiver.recv() => {
                    match control {
                        Some(SharedVirtualNicControl::Shutdown { invalidate, ack }) => {
                            self.cleanup(invalidate);
                            let _ = ack.send(());
                            return;
                        }
                        #[cfg(any(mobile, all(test, unix)))]
                        Some(SharedVirtualNicControl::UpdateMobileTun(update)) => {
                            if !self.apply_tun_update(update).await {
                                return;
                            }
                        }
                        Some(control) => self.state.handle_control(control),
                        None => break,
                    }
                }
                (member_id, packet) = self.state.next_member_packet() => {
                    let Some(packet) = packet else {
                        self.state.close_member(member_id);
                        continue;
                    };
                    let Some(packet) = self.state.prepare_member_packet_to_tun(member_id, packet) else {
                        continue;
                    };
                    let Some(sink) = self.tun_sink.as_mut() else {
                        break;
                    };
                    if let Err(err) = async {
                        tokio::time::timeout(DISPATCHER_TUN_WRITE_TIMEOUT, sink.send(packet)).await??;
                        Ok::<(), Error>(())
                    }.await {
                        tracing::error!(?err, "shared virtual nic write to tun failed");
                        break;
                    }
                }
                packet = async {
                    match self.tun_stream.as_mut() {
                        Some(stream) => stream.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match packet {
                        Some(Ok(packet)) => self.state.forward_tun_packet_to_member(packet),
                        Some(Err(err)) => {
                            tracing::error!(?err, "shared virtual nic read from tun failed");
                            break;
                        }
                        None => break,
                    }
                }

            }
        }
        self.cleanup(true);
    }

    #[cfg(mobile)]
    async fn run_for_mobile(mut self, first_open_sender: oneshot::Sender<Result<(), Error>>) {
        match self.open_tun().await {
            Ok(()) => {
                if first_open_sender.send(Ok(())).is_err() {
                    self.cleanup(false);
                    return;
                }
            }
            Err(err) => {
                self.cleanup(false);
                let _ = first_open_sender.send(Err(err));
                return;
            }
        }
        self.run().await;
    }

    #[cfg(any(mobile, all(test, unix)))]
    async fn open_tun(&mut self) -> Result<(), Error> {
        let mobile = self.mobile.as_ref().unwrap();
        let tun_fd = mobile.tun_fd;
        let tunnel = mobile
            .nic
            .lock()
            .await
            .create_dev_for_mobile(tun_fd)
            .await?;
        let (tun_stream, tun_sink) = tunnel.split();
        self.tun_stream = Some(tun_stream);
        self.tun_sink = Some(tun_sink);
        tracing::info!(fd = tun_fd, "opened shared virtual nic mobile tun");
        Ok(())
    }

    #[cfg(any(mobile, all(test, unix)))]
    async fn apply_tun_update(&mut self, update: SharedVirtualNicMobileTunUpdate) -> bool {
        let Some(mobile) = self.mobile.as_mut() else {
            let _ = update.ack.send(Err(anyhow::anyhow!(
                "shared virtual nic mobile dispatcher is not running"
            )
            .into()));
            return true;
        };
        mobile.tun_fd = update.tun_fd;
        self.tun_stream.take();
        self.tun_sink.take();
        match self.open_tun().await {
            Ok(()) => {
                let _ = update.ack.send(Ok(()));
                true
            }
            Err(err) => {
                tracing::error!(fd = update.tun_fd, ?err, "failed to replace mobile tun");
                self.cleanup(true);
                let _ = update.ack.send(Err(err));
                false
            }
        }
    }

    fn cleanup(&mut self, invalidate: bool) {
        self.tun_stream.take();
        self.tun_sink.take();
        if invalidate {
            self.valid.store(false, Ordering::Release);
        }
        self.member_tunnel_table.detach_dispatcher();
        self.state.close_all();
    }
}

#[cfg(any(mobile, test))]
async fn await_mobile_open(receiver: oneshot::Receiver<Result<(), Error>>) -> Result<(), Error> {
    receiver.await.map_err(|_| {
        Error::from(anyhow::anyhow!(
            "shared virtual nic mobile dispatcher stopped before opening TUN"
        ))
    })?
}

#[derive(Default)]
struct SharedVirtualNicDispatcherState {
    members: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    last_polled_member: SharedVirtualNicMemberId,
    nat_table: SharedVirtualNicNatTable,
    source_table: SharedVirtualNicSourceTable,
    // Mobile VPNs can supply synthetic sources, unlike desktop subnet forwarding.
    translate_unknown_sources: bool,
}

impl SharedVirtualNicDispatcherState {
    fn handle_control(&mut self, control: SharedVirtualNicControl) {
        match control {
            SharedVirtualNicControl::Register { member_id, entry } => {
                self.register(member_id, entry);
            }
            SharedVirtualNicControl::Unregister {
                member_id,
                registration_id,
            } => {
                self.unregister(member_id, registration_id);
            }
            SharedVirtualNicControl::UpdateSources {
                member_id,
                sources,
                ack,
            } => {
                if let Some(previous) = self.source_table.member_sources.get(&member_id) {
                    self.nat_table.remove_changed_addresses(previous, &sources);
                }
                self.source_table.update_member_sources(member_id, sources);
                let _ = ack.send(());
            }
            #[cfg(any(mobile, all(test, unix)))]
            SharedVirtualNicControl::UpdateMobileTun(_) => {
                unreachable!("mobile updates are handled by the dispatcher task")
            }
            SharedVirtualNicControl::Shutdown { .. } => {
                unreachable!("dispatcher shutdown is handled by the dispatcher task")
            }
        }
    }

    fn register(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        entry: SharedVirtualNicMemberTunnelEntry,
    ) {
        let old_entry = self.members.insert(member_id, entry);
        if old_entry.is_some() {
            self.nat_table.remove_member(member_id);
        }
        drop(old_entry);
    }

    fn unregister(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) {
        if self
            .members
            .get(&member_id)
            .map(|entry| entry.registration_id)
            != Some(registration_id)
        {
            return;
        }

        let entry = self.members.remove(&member_id);
        drop(entry);
        self.nat_table.remove_member(member_id);
        self.source_table.remove_owner(member_id);
    }

    fn close_member(&mut self, member_id: SharedVirtualNicMemberId) {
        if let Some(entry) = self.members.get(&member_id) {
            entry.close_notifier.notify_one();
            self.unregister(member_id, entry.registration_id);
        }
    }

    async fn next_member_packet(&mut self) -> (SharedVirtualNicMemberId, Option<ZCPacket>) {
        poll_fn(|cx| {
            // Resume after the last ready member, wrapping once to keep busy members fair.
            let last = self.last_polled_member;
            for (member_id, entry) in self.members.range_mut((Excluded(last), Unbounded)) {
                if let Poll::Ready(packet) = Pin::new(&mut entry.stream).poll_next(cx) {
                    self.last_polled_member = *member_id;
                    return Poll::Ready((*member_id, packet.and_then(Result::ok)));
                }
            }
            for (member_id, entry) in self.members.range_mut((Unbounded, Included(last))) {
                if let Poll::Ready(packet) = Pin::new(&mut entry.stream).poll_next(cx) {
                    self.last_polled_member = *member_id;
                    return Poll::Ready((*member_id, packet.and_then(Result::ok)));
                }
            }
            Poll::Pending
        })
        .await
    }

    fn close_all(&mut self) {
        let members = std::mem::take(&mut self.members);
        self.nat_table.clear();
        self.source_table.clear();

        for entry in members.into_values() {
            entry.close_notifier.notify_one();
        }
    }

    fn prepare_member_packet_to_tun(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        mut packet: ZCPacket,
    ) -> Option<ZCPacket> {
        // A local socket can receive before it ever sends. Reserve its reverse
        // tuple before delivering the packet, so later translations cannot take it.
        if let Some(key) = SharedVirtualNicFlowKey::from_packet(&packet)
            && self
                .source_table
                .member_sources
                .get(&member_id)
                .is_some_and(|sources| sources.owns_source(key.dst))
            && !self.nat_table.reserve_reply(member_id, key)
        {
            return None;
        }
        self.nat_table.translate_reply(member_id, &mut packet);
        Some(packet)
    }

    fn forward_tun_packet_to_member(&mut self, packet: ZCPacket) {
        if !self.send_packet(packet) {
            tracing::trace!("shared virtual nic dropped packet without active member");
        }
    }

    fn send_packet(&mut self, packet: ZCPacket) -> bool {
        let source_owner = self.source_table.owner_of_source(&packet, &self.members);
        if self.members.len() == 1 {
            let member_id = *self.members.keys().next().unwrap();
            // Keep native flow reservations for later members, without creating
            // translations while this member has exclusive use of the TUN.
            let source_owner = source_owner
                .active_member()
                .or_else(|| self.translate_unknown_sources.then_some(member_id));
            return self.send_packet_to_member_with_translation(
                member_id,
                source_owner,
                packet,
                false,
            );
        }
        let preferred_destination_owner = source_owner.active_member();
        let destination_owner = self.source_table.owner_of_destination(
            &packet,
            &self.members,
            preferred_destination_owner,
        );
        if let Some(member_id) = destination_owner {
            let translate_source = should_translate_source_for_member(
                source_owner,
                member_id,
                self.translate_unknown_sources,
            );
            return self.send_packet_to_member_with_translation(
                member_id,
                source_owner.active_member(),
                packet,
                translate_source,
            );
        }

        match source_owner {
            SourceOwner::Active(member_id) => {
                return self.send_packet_to_member_with_translation(
                    member_id,
                    Some(member_id),
                    packet,
                    false,
                );
            }
            SourceOwner::Inactive => return false,
            SourceOwner::None => {}
        }

        false
    }

    fn send_packet_to_member_with_translation(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        source_owner: Option<SharedVirtualNicMemberId>,
        mut packet: ZCPacket,
        translate_source: bool,
    ) -> bool {
        let Some(entry) = self.members.get_mut(&member_id) else {
            return false;
        };
        // Check queue capacity before allocating a flow, and never await a slow member.
        match Pin::new(&mut entry.sink).poll_ready(&mut Context::from_waker(noop_waker_ref())) {
            Poll::Pending => return false,
            Poll::Ready(Err(_)) => {
                self.close_member(member_id);
                return false;
            }
            Poll::Ready(Ok(())) => {}
        }
        let key = SharedVirtualNicFlowKey::from_packet(&packet);
        // Forwarded subnet sources cannot collide with a member's translated address.
        // Keep applying an existing translation after other members leave.
        if !translate_source
            && source_owner.is_none()
            && !key.is_some_and(|key| self.nat_table.entries.contains_key(&(member_id, key)))
        {
            return self.send_to_member(member_id, packet);
        }
        let Some(key) = key else {
            return false;
        };
        let translated_src = if translate_source {
            self.source_table
                .source_for_member_destination(member_id, key.dst)
                .unwrap_or(key.src)
        } else {
            key.src
        };
        // Native flows need reservations too, regardless of which flow arrives first.
        if !self
            .nat_table
            .prepare_packet(member_id, source_owner, key, &mut packet, translated_src)
        {
            return false;
        }
        self.send_to_member(member_id, packet)
    }

    fn send_to_member(&mut self, member_id: SharedVirtualNicMemberId, packet: ZCPacket) -> bool {
        // This is the Ring's only producer, with no await since poll_ready. A consumer
        // can only free capacity; if it closes, unregister also removes the new flow.
        if let Err(err) =
            Pin::new(&mut self.members.get_mut(&member_id).unwrap().sink).start_send(packet)
        {
            self.close_member(member_id);
            tracing::trace!(?err, "shared member tunnel write failed");
            return false;
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SourceOwner {
    Active(SharedVirtualNicMemberId),
    Inactive,
    None,
}

impl SourceOwner {
    fn active_member(self) -> Option<SharedVirtualNicMemberId> {
        match self {
            Self::Active(member_id) => Some(member_id),
            Self::Inactive | Self::None => None,
        }
    }
}

fn should_translate_source_for_member(
    source_owner: SourceOwner,
    member_id: SharedVirtualNicMemberId,
    translate_unknown_sources: bool,
) -> bool {
    match source_owner {
        SourceOwner::Active(source) => source != member_id,
        SourceOwner::Inactive => true,
        SourceOwner::None => translate_unknown_sources,
    }
}

#[cfg(test)]
fn rewrite_packet_source(
    packet: &mut ZCPacket,
    expected_source: SharedVirtualNicFlowAddr,
    new_source: SharedVirtualNicFlowAddr,
) -> bool {
    rewrite_ip_addr(
        packet,
        expected_source,
        new_source,
        RewriteIpAddr::Source,
        None,
    )
}

fn rewrite_packet_flow(
    packet: &mut ZCPacket,
    original: SharedVirtualNicFlowKey,
    translated: SharedVirtualNicFlowKey,
    rewrite: RewriteIpAddr,
) -> bool {
    if original == translated {
        return true;
    }
    let new_port = (original.ports != translated.ports).then(|| {
        let ports = translated.ports.unwrap();
        match (rewrite, IpProtocol::from(translated.protocol)) {
            (_, IpProtocol::Icmp | IpProtocol::Icmpv6) | (RewriteIpAddr::Source, _) => ports.src,
            (RewriteIpAddr::Destination, _) => ports.dst,
        }
    });
    let (old_addr, new_addr) = match rewrite {
        RewriteIpAddr::Source => (original.src, translated.src),
        RewriteIpAddr::Destination => (original.dst, translated.dst),
    };
    rewrite_ip_addr(packet, old_addr, new_addr, rewrite, new_port)
}

#[derive(Clone, Copy)]
enum RewriteIpAddr {
    Source,
    Destination,
}

fn rewrite_ip_addr(
    packet: &mut ZCPacket,
    expected_addr: SharedVirtualNicFlowAddr,
    new_addr: SharedVirtualNicFlowAddr,
    rewrite: RewriteIpAddr,
    new_port: Option<u16>,
) -> bool {
    match (expected_addr, new_addr) {
        (SharedVirtualNicFlowAddr::V4(_), SharedVirtualNicFlowAddr::V4(_)) => {
            rewrite_ipv4_addr(packet, expected_addr, new_addr, rewrite, new_port)
        }
        (SharedVirtualNicFlowAddr::V6(_), SharedVirtualNicFlowAddr::V6(_)) => {
            rewrite_ipv6_addr(packet, expected_addr, new_addr, rewrite, new_port)
        }
        _ => false,
    }
}

fn rewrite_ipv4_addr(
    packet: &mut ZCPacket,
    expected_addr: SharedVirtualNicFlowAddr,
    new_addr: SharedVirtualNicFlowAddr,
    rewrite: RewriteIpAddr,
    new_port: Option<u16>,
) -> bool {
    let Some(expected_addr) = expected_addr.as_ipv4() else {
        return false;
    };
    let Some(new_addr) = new_addr.as_ipv4() else {
        return false;
    };

    let payload = packet.mut_payload();
    let Ok(mut ipv4_packet) = Ipv4Packet::new_checked(payload) else {
        return false;
    };

    if ipv4_packet.version() != 4 || ipv4_packet.frag_offset() != 0 || ipv4_packet.more_frags() {
        return false;
    }

    let valid_transport = match ipv4_packet.next_header() {
        IpProtocol::Tcp => TcpPacket::new_checked(ipv4_packet.payload_mut()).is_ok(),
        IpProtocol::Udp => UdpPacket::new_checked(ipv4_packet.payload_mut()).is_ok(),
        IpProtocol::Icmp => Icmpv4Packet::new_checked(ipv4_packet.payload_mut()).is_ok(),
        _ => true,
    };
    if !valid_transport {
        return false;
    }

    match rewrite {
        RewriteIpAddr::Source if ipv4_packet.src_addr() == expected_addr => {
            ipv4_packet.set_src_addr(new_addr);
        }
        RewriteIpAddr::Destination if ipv4_packet.dst_addr() == expected_addr => {
            ipv4_packet.set_dst_addr(new_addr);
        }
        _ => return false,
    }

    if let Some(port) = new_port {
        rewrite_transport_port(
            ipv4_packet.next_header(),
            ipv4_packet.payload_mut(),
            port,
            rewrite,
        );
    }
    update_ipv4_transport_checksum(&mut ipv4_packet);
    ipv4_packet.fill_checksum();
    true
}

fn rewrite_ipv6_addr(
    packet: &mut ZCPacket,
    expected_addr: SharedVirtualNicFlowAddr,
    new_addr: SharedVirtualNicFlowAddr,
    rewrite: RewriteIpAddr,
    new_port: Option<u16>,
) -> bool {
    let Some(expected_addr) = expected_addr.as_ipv6() else {
        return false;
    };
    let Some(new_addr) = new_addr.as_ipv6() else {
        return false;
    };

    let payload = packet.mut_payload();
    let Ok(mut ipv6_packet) = Ipv6Packet::new_checked(payload) else {
        return false;
    };
    if ipv6_packet.version() != 6 {
        return false;
    }
    let protocol = ipv6_packet.next_header();
    let valid_transport = match protocol {
        IpProtocol::Tcp => TcpPacket::new_checked(ipv6_packet.payload_mut()).is_ok(),
        IpProtocol::Udp => UdpPacket::new_checked(ipv6_packet.payload_mut()).is_ok(),
        IpProtocol::Icmpv6 => Icmpv6Packet::new_checked(ipv6_packet.payload_mut()).is_ok(),
        _ => false,
    };
    if !valid_transport {
        return false;
    }

    match rewrite {
        RewriteIpAddr::Source if ipv6_packet.src_addr() == expected_addr => {
            ipv6_packet.set_src_addr(new_addr);
        }
        RewriteIpAddr::Destination if ipv6_packet.dst_addr() == expected_addr => {
            ipv6_packet.set_dst_addr(new_addr);
        }
        _ => return false,
    }

    if let Some(port) = new_port {
        rewrite_transport_port(protocol, ipv6_packet.payload_mut(), port, rewrite);
    }
    let source = ipv6_packet.src_addr();
    let destination = ipv6_packet.dst_addr();
    match protocol {
        IpProtocol::Tcp => TcpPacket::new_checked(ipv6_packet.payload_mut())
            .unwrap()
            .fill_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination)),
        IpProtocol::Udp => UdpPacket::new_checked(ipv6_packet.payload_mut())
            .unwrap()
            .fill_checksum(&IpAddress::Ipv6(source), &IpAddress::Ipv6(destination)),
        IpProtocol::Icmpv6 => Icmpv6Packet::new_checked(ipv6_packet.payload_mut())
            .unwrap()
            .fill_checksum(&source, &destination),
        _ => unreachable!(),
    }
    true
}

// Callers have already checked the transport header before changing the address.
fn rewrite_transport_port(
    protocol: IpProtocol,
    payload: &mut [u8],
    port: u16,
    rewrite: RewriteIpAddr,
) {
    match protocol {
        IpProtocol::Tcp => {
            let mut packet = TcpPacket::new_unchecked(payload);
            match rewrite {
                RewriteIpAddr::Source => packet.set_src_port(port),
                RewriteIpAddr::Destination => packet.set_dst_port(port),
            }
        }
        IpProtocol::Udp => {
            let mut packet = UdpPacket::new_unchecked(payload);
            match rewrite {
                RewriteIpAddr::Source => packet.set_src_port(port),
                RewriteIpAddr::Destination => packet.set_dst_port(port),
            }
        }
        IpProtocol::Icmp => Icmpv4Packet::new_unchecked(payload).set_echo_ident(port),
        IpProtocol::Icmpv6 => Icmpv6Packet::new_unchecked(payload).set_echo_ident(port),
        _ => unreachable!(),
    }
}

fn update_ipv4_transport_checksum(ipv4_packet: &mut Ipv4Packet<&mut [u8]>) {
    let source = IpAddress::Ipv4(ipv4_packet.src_addr());
    let destination = IpAddress::Ipv4(ipv4_packet.dst_addr());
    let protocol = ipv4_packet.next_header();
    let transport_payload = ipv4_packet.payload_mut();

    match protocol {
        IpProtocol::Tcp => {
            TcpPacket::new_checked(transport_payload)
                .unwrap()
                .fill_checksum(&source, &destination);
        }
        IpProtocol::Udp => {
            let mut udp_packet = UdpPacket::new_checked(transport_payload).unwrap();
            if udp_packet.checksum() == 0 {
                return;
            }
            udp_packet.fill_checksum(&source, &destination);
        }
        IpProtocol::Icmp => {
            Icmpv4Packet::new_checked(transport_payload)
                .unwrap()
                .fill_checksum();
        }
        _ => {}
    }
}

#[derive(Default)]
struct SharedVirtualNicSourceTable {
    member_sources: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberSources>,
}

impl SharedVirtualNicSourceTable {
    fn update_member_sources(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        sources: SharedVirtualNicMemberSources,
    ) {
        if sources.is_empty() {
            self.member_sources.remove(&member_id);
        } else {
            self.member_sources.insert(member_id, sources);
        }
    }

    fn remove_owner(&mut self, member_id: SharedVirtualNicMemberId) {
        self.member_sources.remove(&member_id);
    }

    fn clear(&mut self) {
        self.member_sources.clear();
    }

    fn owner_of_source(
        &self,
        packet: &ZCPacket,
        active_members: &BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    ) -> SourceOwner {
        let Some((source, _)) = SharedVirtualNicFlowAddr::packet_addrs(packet) else {
            return SourceOwner::None;
        };
        let mut found = false;
        for (member_id, sources) in &self.member_sources {
            if sources.owns_source(source) {
                found = true;
                if active_members.contains_key(member_id) {
                    return SourceOwner::Active(*member_id);
                }
            }
        }
        if found {
            SourceOwner::Inactive
        } else {
            SourceOwner::None
        }
    }

    fn owner_of_destination(
        &self,
        packet: &ZCPacket,
        active_members: &BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
        preferred_member: Option<SharedVirtualNicMemberId>,
    ) -> Option<SharedVirtualNicMemberId> {
        let (_, dst) = SharedVirtualNicFlowAddr::packet_addrs(packet)?;

        let mut first = None;
        for (member_id, sources) in &self.member_sources {
            if !active_members.contains_key(member_id) || !sources.has_destination(dst) {
                continue;
            }
            if Some(*member_id) == preferred_member {
                return Some(*member_id);
            }
            first.get_or_insert(*member_id);
        }
        first
    }

    fn source_for_member_destination(
        &self,
        member_id: SharedVirtualNicMemberId,
        dst: SharedVirtualNicFlowAddr,
    ) -> Option<SharedVirtualNicFlowAddr> {
        let sources = self.member_sources.get(&member_id)?;
        match dst {
            SharedVirtualNicFlowAddr::V4(dst) => source_for_destination(
                &sources.ipv4_addresses,
                &sources.ipv4_routes,
                std::net::Ipv4Addr::from(dst),
            )
            .map(SharedVirtualNicFlowAddr::from),
            SharedVirtualNicFlowAddr::V6(dst) => source_for_destination(
                &sources.ipv6_addresses,
                &sources.ipv6_routes,
                std::net::Ipv6Addr::from(dst),
            )
            .map(SharedVirtualNicFlowAddr::from),
        }
    }
}

impl SharedVirtualNicMemberSources {
    fn has_destination(&self, dst: SharedVirtualNicFlowAddr) -> bool {
        match dst {
            SharedVirtualNicFlowAddr::V4(dst) => {
                let dst = std::net::Ipv4Addr::from(dst);
                self.ipv4_addresses.iter().any(|addr| addr.contains(&dst))
                    || self.ipv4_routes.iter().any(|route| route.contains(&dst))
            }
            SharedVirtualNicFlowAddr::V6(dst) => {
                let dst = std::net::Ipv6Addr::from(dst);
                self.ipv6_addresses.iter().any(|addr| addr.contains(&dst))
                    || self.ipv6_routes.iter().any(|route| route.contains(&dst))
            }
        }
    }
}

fn source_for_destination<T: Inet + Ord>(
    addresses: &BTreeSet<T>,
    routes: &BTreeSet<T>,
    dst: T::Address,
) -> Option<T::Address> {
    let mut best = None;
    for addr in addresses {
        if addr.contains(&dst) {
            update_best_source(&mut best, addr.network_length(), addr.address());
        }
    }
    for route in routes {
        if route.contains(&dst) {
            let source = addresses
                .iter()
                .find(|addr| route.contains(&addr.address()))
                .or_else(|| addresses.first());
            if let Some(source) = source {
                update_best_source(&mut best, route.network_length(), source.address());
            }
        }
    }
    best.map(|(_, source)| source)
}

fn update_best_source<T: Copy>(best: &mut Option<(u8, T)>, prefix: u8, source: T) {
    if best
        .map(|(best_prefix, _)| prefix > best_prefix)
        .unwrap_or(true)
    {
        *best = Some((prefix, source));
    }
}

// ICMP Echo sessions use only the identifier; sequence numbers stay in the packet.
fn transport_ports(protocol: u8, payload: &[u8]) -> Option<SharedVirtualNicTransportPorts> {
    let (src, dst) = match IpProtocol::from(protocol) {
        IpProtocol::Tcp => {
            let tcp = TcpPacket::new_checked(payload).ok()?;
            (tcp.src_port(), tcp.dst_port())
        }
        IpProtocol::Udp => {
            let udp = UdpPacket::new_checked(payload).ok()?;
            (udp.src_port(), udp.dst_port())
        }
        IpProtocol::Icmp => {
            let icmp = Icmpv4Packet::new_checked(payload).ok()?;
            if !matches!(
                icmp.msg_type(),
                Icmpv4Message::EchoRequest | Icmpv4Message::EchoReply
            ) {
                return None;
            }
            (icmp.echo_ident(), 0)
        }
        IpProtocol::Icmpv6 => {
            let icmp = Icmpv6Packet::new_checked(payload).ok()?;
            if !matches!(
                icmp.msg_type(),
                Icmpv6Message::EchoRequest | Icmpv6Message::EchoReply
            ) {
                return None;
            }
            (icmp.echo_ident(), 0)
        }
        _ => return None,
    };
    Some(SharedVirtualNicTransportPorts { src, dst })
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::SharedVirtualNicFlowAddr as FlowAddr;
    use super::*;
    use easytier_core::tunnel::{
        TunnelError, ring::create_ring_tunnel_pair, wrapper::TunnelWrapper,
    };
    use futures::FutureExt;
    const IPV4_HEADER_MIN_LEN: usize = 20;
    const IPV6_HEADER_LEN: usize = 40;
    const TCP_HEADER_MIN_LEN: usize = 20;
    const UDP_HEADER_LEN: usize = 8;
    const ICMP_ECHO_HEADER_LEN: usize = 8;

    #[tokio::test]
    async fn mobile_open_handshake_waits_for_dispatcher_result() {
        let (sender, receiver) = oneshot::channel();
        let waiter = tokio::spawn(await_mobile_open(receiver));

        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        sender.send(Ok(())).unwrap();
        waiter.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn mobile_open_handshake_preserves_original_error() {
        let (sender, receiver) = oneshot::channel();
        let waiter = tokio::spawn(await_mobile_open(receiver));
        let errno = 9;

        sender
            .send(Err(std::io::Error::from_raw_os_error(errno).into()))
            .unwrap();
        let err = waiter.await.unwrap().unwrap_err();
        assert!(matches!(err, Error::IOError(ref io_err) if io_err.raw_os_error() == Some(errno)));
    }

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> ZCPacket {
        let mut payload = vec![0; IPV6_HEADER_LEN];
        let mut ipv6 = Ipv6Packet::new_unchecked(&mut payload);
        ipv6.set_version(6);
        ipv6.set_next_header(IpProtocol::Icmpv6);
        ipv6.set_src_addr(src);
        ipv6.set_dst_addr(dst);
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        transport_packet(src, dst, IpProtocol::Udp, 1234, 5678)
    }

    fn ipv4_icmp_echo_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        echo_packet(src, dst, false, 0, 0)
    }

    fn ip_packet(src: FlowAddr, dst: FlowAddr, protocol: IpProtocol, payload: &[u8]) -> ZCPacket {
        let header = if matches!(src, FlowAddr::V4(_)) {
            IPV4_HEADER_MIN_LEN
        } else {
            IPV6_HEADER_LEN
        };
        let mut bytes = vec![0; header + payload.len()];
        bytes[header..].copy_from_slice(payload);
        let len = bytes.len() as u16;
        match (src, dst) {
            (FlowAddr::V4(src), FlowAddr::V4(dst)) => {
                let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
                ip.set_version(4);
                ip.set_header_len(header as u8);
                ip.set_total_len(len);
                ip.set_hop_limit(64);
                ip.set_next_header(protocol);
                ip.set_src_addr(src.into());
                ip.set_dst_addr(dst.into());
                ip.fill_checksum();
            }
            (FlowAddr::V6(src), FlowAddr::V6(dst)) => {
                let mut ip = Ipv6Packet::new_unchecked(&mut bytes);
                ip.set_version(6);
                ip.set_payload_len(payload.len() as u16);
                ip.set_hop_limit(64);
                ip.set_next_header(protocol);
                ip.set_src_addr(src.into());
                ip.set_dst_addr(dst.into());
            }
            _ => unreachable!(),
        }
        ZCPacket::new_with_payload(&bytes)
    }

    fn test_addresses(ipv6: bool) -> [FlowAddr; 4] {
        if ipv6 {
            [
                "2001:db8:1::1",
                "2001:db8:2::1",
                "2001:db8:3::1",
                "2001:db8:3::2",
            ]
            .map(|ip| ip.parse::<Ipv6Addr>().unwrap().into())
        } else {
            [
                Ipv4Addr::new(10, 231, 1, 1),
                Ipv4Addr::new(10, 231, 2, 1),
                Ipv4Addr::new(10, 231, 3, 1),
                Ipv4Addr::new(10, 231, 3, 2),
            ]
            .map(Into::into)
        }
    }

    fn address_sources(address: FlowAddr) -> SharedVirtualNicMemberSources {
        let mut sources = SharedVirtualNicMemberSources::default();
        match address {
            FlowAddr::V4(ip) => {
                sources
                    .ipv4_addresses
                    .insert(Ipv4Inet::new(ip.into(), 24).unwrap());
            }
            FlowAddr::V6(ip) => {
                sources
                    .ipv6_addresses
                    .insert(Ipv6Inet::new(ip.into(), 64).unwrap());
            }
        }
        sources
    }

    fn transport_packet<A: Into<FlowAddr>>(
        src: A,
        dst: A,
        protocol: IpProtocol,
        src_port: u16,
        dst_port: u16,
    ) -> ZCPacket {
        let (src, dst) = (src.into(), dst.into());
        let (src_ip, dst_ip) = match (src, dst) {
            (FlowAddr::V4(src), FlowAddr::V4(dst)) => {
                (IpAddress::Ipv4(src.into()), IpAddress::Ipv4(dst.into()))
            }
            (FlowAddr::V6(src), FlowAddr::V6(dst)) => {
                (IpAddress::Ipv6(src.into()), IpAddress::Ipv6(dst.into()))
            }
            _ => unreachable!(),
        };
        let mut payload = vec![
            0;
            if protocol == IpProtocol::Tcp {
                TCP_HEADER_MIN_LEN
            } else {
                UDP_HEADER_LEN
            }
        ];
        match protocol {
            IpProtocol::Tcp => {
                let mut tcp = TcpPacket::new_unchecked(&mut payload);
                tcp.set_header_len(TCP_HEADER_MIN_LEN as u8);
                tcp.set_src_port(src_port);
                tcp.set_dst_port(dst_port);
                tcp.fill_checksum(&src_ip, &dst_ip);
            }
            IpProtocol::Udp => {
                let mut udp = UdpPacket::new_unchecked(&mut payload);
                udp.set_len(UDP_HEADER_LEN as u16);
                udp.set_src_port(src_port);
                udp.set_dst_port(dst_port);
                udp.fill_checksum(&src_ip, &dst_ip);
            }
            _ => unreachable!(),
        }
        ip_packet(src, dst, protocol, &payload)
    }

    fn echo_packet<A: Into<FlowAddr>>(
        src: A,
        dst: A,
        reply: bool,
        identifier: u16,
        sequence: u16,
    ) -> ZCPacket {
        let (src, dst) = (src.into(), dst.into());
        let mut payload = vec![0; ICMP_ECHO_HEADER_LEN];
        let protocol = match (src, dst) {
            (FlowAddr::V4(_), FlowAddr::V4(_)) => {
                let mut icmp = Icmpv4Packet::new_unchecked(&mut payload);
                icmp.set_msg_type(if reply {
                    Icmpv4Message::EchoReply
                } else {
                    Icmpv4Message::EchoRequest
                });
                icmp.set_echo_ident(identifier);
                icmp.set_echo_seq_no(sequence);
                icmp.fill_checksum();
                IpProtocol::Icmp
            }
            (FlowAddr::V6(src), FlowAddr::V6(dst)) => {
                let mut icmp = Icmpv6Packet::new_unchecked(&mut payload);
                icmp.set_msg_type(if reply {
                    Icmpv6Message::EchoReply
                } else {
                    Icmpv6Message::EchoRequest
                });
                icmp.set_echo_ident(identifier);
                icmp.set_echo_seq_no(sequence);
                icmp.fill_checksum(&src.into(), &dst.into());
                IpProtocol::Icmpv6
            }
            _ => unreachable!(),
        };
        ip_packet(src, dst, protocol, &payload)
    }

    fn assert_checksums(packet: &ZCPacket) {
        let (src, dst, protocol, payload) = match packet.payload()[0] >> 4 {
            4 => {
                let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
                assert!(ip.verify_checksum());
                (
                    IpAddress::Ipv4(ip.src_addr()),
                    IpAddress::Ipv4(ip.dst_addr()),
                    ip.next_header(),
                    &packet.payload()[ip.header_len() as usize..],
                )
            }
            6 => {
                let ip = Ipv6Packet::new_checked(packet.payload()).unwrap();
                (
                    IpAddress::Ipv6(ip.src_addr()),
                    IpAddress::Ipv6(ip.dst_addr()),
                    ip.next_header(),
                    &packet.payload()[IPV6_HEADER_LEN..],
                )
            }
            _ => unreachable!(),
        };
        match protocol {
            IpProtocol::Tcp => assert!(
                TcpPacket::new_checked(payload)
                    .unwrap()
                    .verify_checksum(&src, &dst)
            ),
            IpProtocol::Udp => {
                let udp = UdpPacket::new_checked(payload).unwrap();
                assert_ne!(udp.checksum(), 0);
                assert!(udp.verify_checksum(&src, &dst));
            }
            IpProtocol::Icmp => assert!(
                Icmpv4Packet::new_checked(payload)
                    .unwrap()
                    .verify_checksum()
            ),
            IpProtocol::Icmpv6 => {
                let (IpAddress::Ipv6(src), IpAddress::Ipv6(dst)) = (src, dst) else {
                    unreachable!()
                };
                assert!(
                    Icmpv6Packet::new_checked(payload)
                        .unwrap()
                        .verify_checksum(&src, &dst)
                );
            }
            _ => unreachable!(),
        }
    }

    fn member_sources(ipv4: &[&str]) -> SharedVirtualNicMemberSources {
        SharedVirtualNicMemberSources::from_claims(&member_claims(ipv4, &[], &[], &[]))
    }

    fn member_sources_with_ipv4_routes(
        ipv4: &[&str],
        ipv4_routes: &[&str],
    ) -> SharedVirtualNicMemberSources {
        SharedVirtualNicMemberSources::from_claims(&member_claims(ipv4, &[], ipv4_routes, &[]))
    }

    fn member_sources_with_ipv6(ipv6: &[&str]) -> SharedVirtualNicMemberSources {
        SharedVirtualNicMemberSources::from_claims(&member_claims(&[], ipv6, &[], &[]))
    }

    fn member_sources_with_ipv6_routes(
        ipv6: &[&str],
        ipv6_routes: &[&str],
    ) -> SharedVirtualNicMemberSources {
        SharedVirtualNicMemberSources::from_claims(&member_claims(&[], ipv6, &[], ipv6_routes))
    }

    fn member_claims(
        ipv4: &[&str],
        ipv6: &[&str],
        ipv4_routes: &[&str],
        ipv6_routes: &[&str],
    ) -> SharedIfConfigClaims {
        SharedIfConfigClaims {
            ipv4_addresses: ipv4.iter().map(|addr| addr.parse().unwrap()).collect(),
            ipv6_addresses: ipv6.iter().map(|addr| addr.parse().unwrap()).collect(),
            ipv4_routes: ipv4_routes
                .iter()
                .map(|route| {
                    let inet = route.parse::<Ipv4Inet>().unwrap();
                    SharedIpv4Route::new(inet.address(), inet.network_length(), None)
                })
                .collect(),
            ipv6_routes: ipv6_routes
                .iter()
                .map(|route| {
                    let inet = route.parse::<Ipv6Inet>().unwrap();
                    SharedIpv6Route::new(inet.address(), inet.network_length(), None)
                })
                .collect(),
            mtu: None,
        }
    }

    struct TestMember {
        stream: RingStream,
        _sink: RingSink,
    }

    impl TestMember {
        fn try_recv(&mut self) -> Result<ZCPacket, ()> {
            self.stream
                .next()
                .now_or_never()
                .flatten()
                .ok_or(())?
                .map_err(|_| ())
        }
    }

    fn member_channel(capacity: usize) -> (SharedVirtualNicMemberTunnelEntry, TestMember) {
        let (member, dispatcher) = create_ring_socket_pair(capacity);
        let (stream, sink) = split_ring_socket(dispatcher);
        let (member_stream, member_sink) = split_ring_socket(member);
        (
            SharedVirtualNicMemberTunnelEntry {
                registration_id: uuid::Uuid::from_u128(1),
                stream,
                sink,
                close_notifier: Arc::new(Notify::new()),
            },
            TestMember {
                stream: member_stream,
                _sink: member_sink,
            },
        )
    }

    fn test_state<const N: usize>(
        members: [(SharedVirtualNicMemberId, SharedVirtualNicMemberSources); N],
    ) -> (SharedVirtualNicDispatcherState, [TestMember; N]) {
        let mut state = SharedVirtualNicDispatcherState::default();
        let endpoints = members.map(|(id, sources)| {
            let (entry, member) = member_channel(8);
            state.register(id, entry);
            state.source_table.update_member_sources(id, sources);
            member
        });
        (state, endpoints)
    }

    #[tokio::test]
    async fn member_ring_polling_is_fair_and_wakes_after_pending() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let (mut state, [mut a, mut b]) = test_state([
            (first, SharedVirtualNicMemberSources::default()),
            (second, SharedVirtualNicMemberSources::default()),
        ]);
        let receive = tokio::time::timeout(Duration::from_secs(1), state.next_member_packet());
        let send = async {
            tokio::task::yield_now().await;
            a._sink
                .send(ipv4_udp_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
        };
        let (received, ()) = tokio::join!(receive, send);
        assert_eq!(received.unwrap().0, first);
        for _ in 0..2 {
            a._sink
                .send(ipv4_udp_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
            b._sink
                .send(ipv4_udp_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST))
                .await
                .unwrap();
        }
        for expected in [second, first, second, first] {
            let (id, packet) = state.next_member_packet().await;
            assert_eq!(id, expected);
            assert!(packet.is_some());
        }
        let closed = state.members[&first].close_notifier.clone();
        drop(a);
        let (id, packet) = state.next_member_packet().await;
        assert_eq!(id, first);
        assert!(packet.is_none());
        state.close_member(id);
        closed.notified().await;
        b._sink
            .send(ipv4_udp_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST))
            .await
            .unwrap();
        assert_eq!(state.next_member_packet().await.0, second);
    }

    #[tokio::test]
    async fn full_flow_table_drops_yield_to_other_runtime_tasks() {
        let id = uuid::Uuid::from_u128(1);
        let local = Ipv4Addr::new(10, 231, 1, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        let (entry, mut member) = member_channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let mut state = SharedVirtualNicDispatcherState::default();
        state.register(id, entry);
        state
            .source_table
            .update_member_sources(id, address_sources(local.into()));
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            let packet = transport_packet(remote, local, IpProtocol::Udp, 5678, port);
            assert!(
                state
                    .nat_table
                    .reserve_reply(id, SharedVirtualNicFlowKey::from_packet(&packet).unwrap())
            );
        }
        let packet = transport_packet(remote, local, IpProtocol::Udp, 5678, 5000);
        for _ in 0..MEMBER_TUNNEL_BUFFER_SIZE {
            member
                ._sink
                .force_send(ZCPacket::new_with_payload(packet.payload()))
                .unwrap();
        }
        let (_tun, tunnel) = create_ring_tunnel_pair();
        let (tun_stream, tun_sink) = tunnel.split();
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        let task = SharedVirtualNicDispatcherTask {
            tun_stream: Some(tun_stream),
            tun_sink: Some(tun_sink),
            #[cfg(any(mobile, all(test, unix)))]
            mobile: None,
            control_receiver,
            member_tunnel_table: SharedVirtualNicMemberTunnelTable::default(),
            valid: Arc::new(AtomicBool::new(true)),
            state,
        };
        let handle = tokio::spawn(task.run());
        tokio::task::yield_now().await;
        // Refill freed slots to measure whether the dispatcher yielded before
        // draining the whole Ring. No timer or unbounded producer is needed.
        let mut consumed = 0;
        while member
            ._sink
            .force_send(ZCPacket::new_with_payload(packet.payload()))
            .is_ok()
        {
            consumed += 1;
        }
        let (ack, rx) = oneshot::channel();
        control_sender
            .send(SharedVirtualNicControl::Shutdown {
                invalidate: false,
                ack,
            })
            .unwrap();
        rx.await.unwrap();
        handle.await.unwrap();
        assert!(
            consumed > 0 && consumed < MEMBER_TUNNEL_BUFFER_SIZE,
            "drained {consumed} packets before yielding"
        );
    }

    #[cfg(unix)]
    fn start_mobile_dispatcher_for_test(
        tunnel: Box<dyn Tunnel>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> (
        SharedVirtualNicDispatcher,
        mpsc::UnboundedSender<SharedVirtualNicControl>,
    ) {
        use crate::{common::netns::NetNS, instance::virtual_nic::VirtualNicConfig};

        let (tun_stream, tun_sink) = tunnel.split();
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        member_tunnel_table.attach_dispatcher(control_sender.clone());
        let task = SharedVirtualNicDispatcherTask {
            mobile: Some(SharedVirtualNicMobileTun {
                nic: Arc::new(Mutex::new(VirtualNic::new(VirtualNicConfig::new(
                    String::new(),
                    1300,
                    NetNS::new(None),
                )))),
                tun_fd: -1,
            }),
            tun_stream: Some(tun_stream),
            tun_sink: Some(tun_sink),
            control_receiver,
            member_tunnel_table,
            valid,
            state: SharedVirtualNicDispatcherState {
                translate_unknown_sources: true,
                ..Default::default()
            },
        };
        let dispatcher = SharedVirtualNicDispatcher {
            task: AbortOnDropHandle::new(tokio::spawn(task.run())),
            control_sender: control_sender.clone(),
        };
        (dispatcher, control_sender)
    }

    async fn register_dispatcher_test_members(
        dispatcher: &SharedVirtualNicDispatcher,
        member_tunnel_table: &SharedVirtualNicMemberTunnelTable,
    ) -> (Vec<Box<dyn Tunnel>>, Vec<Arc<Notify>>) {
        let mut tunnels = Vec::new();
        let mut close_notifiers = Vec::new();
        for id in 1..=2 {
            let member_id = uuid::Uuid::from_u128(id);
            let close_notifier = Arc::new(Notify::new());
            let member_tunnel = member_tunnel_table
                .register(member_id, uuid::Uuid::new_v4(), close_notifier.clone())
                .unwrap();
            dispatcher
                .update_sources(member_id, &SharedIfConfigClaims::default())
                .await
                .unwrap();
            tunnels.push(member_tunnel);
            close_notifiers.push(close_notifier);
        }
        (tunnels, close_notifiers)
    }

    fn stalled_tun_for_test() -> (Box<dyn Tunnel>, Arc<Notify>) {
        let writing = Arc::new(Notify::new());
        let sink_writing = writing.clone();
        let tun_sink = futures::sink::unfold((), move |(), _packet: ZCPacket| {
            let writing = sink_writing.clone();
            async move {
                writing.notify_one();
                std::future::pending::<Result<(), TunnelError>>().await
            }
        });
        let tun_stream = futures::stream::pending::<Result<ZCPacket, TunnelError>>();
        (
            Box::new(TunnelWrapper::new(tun_stream, tun_sink, None)),
            writing,
        )
    }

    async fn check_dispatcher_tun_write_timeout(
        dispatcher: SharedVirtualNicDispatcher,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
        writing: Arc<Notify>,
    ) {
        let (members, close_notifiers) =
            register_dispatcher_test_members(&dispatcher, &member_tunnel_table).await;
        let (_, mut member_sink) = members[0].split();
        member_sink
            .send(ipv4_udp_packet(
                Ipv4Addr::new(10, 231, 1, 1),
                Ipv4Addr::new(203, 0, 113, 1),
            ))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), writing.notified())
            .await
            .unwrap();

        let result = tokio::time::timeout(
            DISPATCHER_TUN_WRITE_TIMEOUT + Duration::from_secs(1),
            dispatcher.remove_sources(uuid::Uuid::from_u128(1)),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        for close_notifier in close_notifiers {
            tokio::time::timeout(Duration::from_secs(1), close_notifier.notified())
                .await
                .unwrap();
        }
        assert!(!valid.load(Ordering::Acquire));
        assert!(member_tunnel_table.control_sender().is_none());
        tokio::time::timeout(Duration::from_secs(1), dispatcher.task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn dispatcher_tun_write_timeout_closes_members_and_source_updates() {
        let (tunnel, writing) = stalled_tun_for_test();
        let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
        let valid = Arc::new(AtomicBool::new(true));
        let dispatcher =
            SharedVirtualNicDispatcher::start(tunnel, member_tunnel_table.clone(), valid.clone());

        check_dispatcher_tun_write_timeout(dispatcher, member_tunnel_table, valid, writing).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mobile_dispatcher_tun_write_timeout_closes_members_and_source_updates() {
        let (tunnel, writing) = stalled_tun_for_test();
        let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
        let valid = Arc::new(AtomicBool::new(true));
        let (dispatcher, _updates) =
            start_mobile_dispatcher_for_test(tunnel, member_tunnel_table.clone(), valid.clone());

        check_dispatcher_tun_write_timeout(dispatcher, member_tunnel_table, valid, writing).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mobile_dispatcher_invalidates_shared_nic_when_tun_replacement_fails() {
        let (_tun, tunnel) = create_ring_tunnel_pair();
        let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
        let valid = Arc::new(AtomicBool::new(true));
        let (dispatcher, updates) =
            start_mobile_dispatcher_for_test(tunnel, member_tunnel_table.clone(), valid.clone());
        let (_members, close_notifiers) =
            register_dispatcher_test_members(&dispatcher, &member_tunnel_table).await;
        let (ack, receiver) = oneshot::channel();

        updates
            .send(SharedVirtualNicControl::UpdateMobileTun(
                SharedVirtualNicMobileTunUpdate { tun_fd: -1, ack },
            ))
            .unwrap();

        assert!(
            tokio::time::timeout(Duration::from_secs(1), await_mobile_open(receiver))
                .await
                .unwrap()
                .is_err()
        );
        for close_notifier in close_notifiers {
            tokio::time::timeout(Duration::from_secs(1), close_notifier.notified())
                .await
                .unwrap();
        }
        assert!(!valid.load(Ordering::Acquire));
        assert!(member_tunnel_table.control_sender().is_none());
        assert!(
            dispatcher
                .remove_sources(uuid::Uuid::from_u128(1))
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), dispatcher.task)
            .await
            .unwrap()
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn mobile_dispatcher_invalidates_shared_nic_when_tun_read_closes() {
        for read_error in [false, true] {
            let (tun_tx, tun_rx) = mpsc::unbounded_channel();
            let tun_stream = futures::stream::unfold(tun_rx, |mut receiver| async move {
                receiver.recv().await.map(|packet| (packet, receiver))
            });
            let tun_sink = futures::sink::unfold((), |(), _packet: ZCPacket| async {
                Ok::<(), TunnelError>(())
            });
            let tunnel = Box::new(TunnelWrapper::new(tun_stream, tun_sink, None));
            let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
            let valid = Arc::new(AtomicBool::new(true));
            let (dispatcher, _updates) = start_mobile_dispatcher_for_test(
                tunnel,
                member_tunnel_table.clone(),
                valid.clone(),
            );
            let (_members, close_notifiers) =
                register_dispatcher_test_members(&dispatcher, &member_tunnel_table).await;

            if read_error {
                tun_tx.send(Err(TunnelError::Shutdown)).unwrap();
            }
            drop(tun_tx);

            for close_notifier in close_notifiers {
                tokio::time::timeout(Duration::from_secs(1), close_notifier.notified())
                    .await
                    .unwrap();
            }
            assert!(!valid.load(Ordering::Acquire));
            assert!(member_tunnel_table.control_sender().is_none());
            tokio::time::timeout(Duration::from_secs(1), dispatcher.task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[test]
    fn source_table_selects_ipv6_source_owner() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let second_addr = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let mut table = SharedVirtualNicSourceTable::default();
        let (first_sender, _first_receiver) = member_channel(8);
        let (second_sender, _second_receiver) = member_channel(8);
        let mut members = BTreeMap::new();
        members.insert(first, first_sender);
        members.insert(second, second_sender);

        table.update_member_sources(first, member_sources_with_ipv6(&["2001:db8::1/64"]));
        table.update_member_sources(second, member_sources_with_ipv6(&["2001:db8::2/64"]));

        assert_eq!(
            table.owner_of_source(&ipv6_packet(second_addr, dst), &members),
            SourceOwner::Active(second)
        );

        table.remove_owner(second);
        assert_eq!(
            table.owner_of_source(&ipv6_packet(second_addr, dst), &members),
            SourceOwner::None
        );
    }

    #[test]
    fn source_table_selects_ipv4_destination_owner_from_route_claim() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let src = Ipv4Addr::new(100, 64, 0, 1);
        let dst = Ipv4Addr::new(10, 99, 0, 2);
        let mut table = SharedVirtualNicSourceTable::default();
        let (first_sender, _first_receiver) = member_channel(8);
        let (second_sender, _second_receiver) = member_channel(8);
        let mut members = BTreeMap::new();
        members.insert(first, first_sender);
        members.insert(second, second_sender);

        table.update_member_sources(first, member_sources(&["10.231.1.1/24"]));
        table.update_member_sources(
            second,
            member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["10.99.0.0/24"]),
        );

        assert_eq!(
            table.owner_of_destination(&ipv4_udp_packet(src, dst), &members, None),
            Some(second)
        );
    }

    #[test]
    fn dispatcher_prefers_source_owner_for_shared_magic_dns() {
        let first = uuid::Uuid::from_u128(1);
        let source_owner = uuid::Uuid::from_u128(2);
        let first_ip = Ipv4Addr::new(10, 231, 1, 1);
        let source_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(100, 100, 100, 101);
        let (mut state, [mut first_receiver, mut source_receiver]) = test_state([
            (
                first,
                member_sources_with_ipv4_routes(&["10.231.1.1/24"], &["100.100.100.101/32"]),
            ),
            (
                source_owner,
                member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["100.100.100.101/32"]),
            ),
        ]);

        state.forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip));

        assert!(first_receiver.try_recv().is_err());
        let packet = source_receiver.try_recv().unwrap();
        let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), source_owner_ip);
        assert_ne!(ipv4.src_addr(), first_ip);
        assert_eq!(ipv4.dst_addr(), remote_ip);
    }

    #[test]
    fn rewrite_ipv4_source_rejects_fragments_without_changing_packet() {
        let src = Ipv4Addr::new(10, 231, 1, 1);
        let dst = Ipv4Addr::new(10, 231, 2, 2);
        for (more_frags, offset) in [(true, 0), (false, 8)] {
            let mut packet = ipv4_udp_packet(src, dst);
            let mut ipv4 = Ipv4Packet::new_checked(packet.mut_payload()).unwrap();
            ipv4.set_more_frags(more_frags);
            ipv4.set_frag_offset(offset);
            let original = packet.payload().to_vec();

            assert!(!rewrite_packet_source(
                &mut packet,
                FlowAddr::from(src),
                FlowAddr::from(Ipv4Addr::new(10, 231, 2, 1))
            ));
            assert_eq!(packet.payload(), original);
        }
    }

    #[test]
    fn dispatcher_prefers_source_owner_over_first_member() {
        let first = uuid::Uuid::from_u128(1);
        let owner = uuid::Uuid::from_u128(2);
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (mut state, [mut first_receiver, mut owner_receiver]) = test_state([
            (first, SharedVirtualNicMemberSources::default()),
            (owner, member_sources_with_ipv6(&["2001:db8::2/64"])),
        ]);
        state.forward_tun_packet_to_member(ipv6_packet(source, dst));

        assert!(first_receiver.try_recv().is_err());
        assert!(owner_receiver.try_recv().is_ok());
    }

    #[test]
    fn dispatcher_forwards_external_ipv6_to_route_only_owner() {
        let route_owner = uuid::Uuid::from_u128(1);
        let source = "2001:db8:ffff::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8:100::2".parse::<Ipv6Addr>().unwrap();
        let (mut state, [mut receiver]) = test_state([(
            route_owner,
            member_sources_with_ipv6_routes(&[], &["2001:db8:100::2/128"]),
        )]);
        // An exhausted local-flow table must not throttle kernel subnet forwarding.
        let local = "2001:db8:100::1".parse::<Ipv6Addr>().unwrap();
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            let mut packet = transport_packet(local, destination, IpProtocol::Tcp, port, 80);
            assert!(state.nat_table.prepare_packet(
                route_owner,
                Some(route_owner),
                SharedVirtualNicFlowKey::from_packet(&packet).unwrap(),
                &mut packet,
                local.into(),
            ));
        }
        for packet in [
            ipv6_packet(source, destination),
            transport_packet(source, destination, IpProtocol::Tcp, 443, 22001),
        ] {
            let unchanged = packet.payload().to_vec();
            assert!(state.send_packet(packet));
            assert_eq!(receiver.try_recv().unwrap().payload(), unchanged);
        }
    }

    #[test]
    fn dispatcher_drops_inactive_source_owner_without_fallback() {
        let fallback = uuid::Uuid::from_u128(1);
        let owner = uuid::Uuid::from_u128(2);
        let other = uuid::Uuid::from_u128(3);
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (mut state, [mut fallback_receiver, _owner_receiver, _other_receiver]) = test_state([
            (fallback, SharedVirtualNicMemberSources::default()),
            (owner, member_sources_with_ipv6(&["2001:db8::2/64"])),
            (other, SharedVirtualNicMemberSources::default()),
        ]);
        state.unregister(owner, uuid::Uuid::from_u128(1));
        state.forward_tun_packet_to_member(ipv6_packet(source, dst));

        assert!(fallback_receiver.try_recv().is_err());
    }

    #[test]
    fn dispatcher_drops_unknown_source_and_destination_without_fallback() {
        let member_id = uuid::Uuid::from_u128(1);
        let other = uuid::Uuid::from_u128(2);
        let unknown_source = Ipv4Addr::new(100, 64, 0, 1);
        let unknown_destination = Ipv4Addr::new(203, 0, 113, 1);
        let (mut state, [mut receiver, _other_receiver]) = test_state([
            (member_id, member_sources(&["10.231.1.1/24"])),
            (other, SharedVirtualNicMemberSources::default()),
        ]);
        state.forward_tun_packet_to_member(ipv4_udp_packet(unknown_source, unknown_destination));

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn dispatcher_single_member_forwards_unknown_addresses_unchanged() {
        let member_id = uuid::Uuid::from_u128(1);
        for translate_unknown_sources in [false, true] {
            let (sender, mut receiver) = member_channel(8);
            let mut state = SharedVirtualNicDispatcherState {
                translate_unknown_sources,
                ..Default::default()
            };
            state.register(member_id, sender);
            for packet in [
                ipv4_udp_packet(Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(203, 0, 113, 1)),
                transport_packet(
                    "2001:db8::1".parse::<Ipv6Addr>().unwrap(),
                    "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap(),
                    IpProtocol::Udp,
                    1234,
                    5678,
                ),
            ] {
                let original = packet.payload().to_vec();
                assert!(state.send_packet(packet));
                assert_eq!(receiver.try_recv().unwrap().payload(), original);
            }
        }
    }

    #[test]
    fn dispatcher_single_member_preserves_fragmented_packets() {
        let member_id = uuid::Uuid::from_u128(1);
        for translate_unknown_sources in [false, true] {
            let (sender, mut receiver) = member_channel(8);
            let mut state = SharedVirtualNicDispatcherState {
                translate_unknown_sources,
                ..Default::default()
            };
            state.register(member_id, sender);
            state.source_table.update_member_sources(
                member_id,
                SharedVirtualNicMemberSources::from_claims(&member_claims(
                    &["10.231.1.1/24"],
                    &["2001:db8:1::1/64"],
                    &[],
                    &[],
                )),
            );
            for source in [Ipv4Addr::new(10, 231, 1, 1), Ipv4Addr::new(100, 64, 0, 1)] {
                for (more_frags, offset) in [(true, 0), (false, 8)] {
                    let mut packet = ipv4_udp_packet(source, Ipv4Addr::new(10, 231, 1, 2));
                    let mut ipv4 = Ipv4Packet::new_checked(packet.mut_payload()).unwrap();
                    ipv4.set_more_frags(more_frags);
                    ipv4.set_frag_offset(offset);
                    ipv4.fill_checksum();
                    let original = packet.payload().to_vec();
                    assert!(state.send_packet(packet));
                    assert_eq!(receiver.try_recv().unwrap().payload(), original);
                }
            }
            for source in ["2001:db8:1::1", "2001:db8:ffff::1"] {
                for fragment_offset in [1u16, 8u16] {
                    let packet = transport_packet(
                        source.parse::<Ipv6Addr>().unwrap(),
                        "2001:db8:1::2".parse::<Ipv6Addr>().unwrap(),
                        IpProtocol::Udp,
                        1234,
                        5678,
                    );
                    let mut payload = packet.payload()[..IPV6_HEADER_LEN].to_vec();
                    payload.extend_from_slice(&[17, 0]); // Fragment's next header is UDP.
                    payload.extend_from_slice(&fragment_offset.to_be_bytes());
                    payload.extend_from_slice(&1u32.to_be_bytes());
                    payload.extend_from_slice(&packet.payload()[IPV6_HEADER_LEN..]);
                    let mut ipv6 = Ipv6Packet::new_unchecked(&mut payload);
                    ipv6.set_next_header(IpProtocol::from(44)); // Fragment header.
                    ipv6.set_payload_len((8 + UDP_HEADER_LEN) as u16);
                    assert!(state.send_packet(ZCPacket::new_with_payload(&payload)));
                    assert_eq!(receiver.try_recv().unwrap().payload(), payload);
                }
            }
        }
    }

    #[test]
    fn dispatcher_single_member_reserves_flows_before_another_member_joins() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let native = Ipv4Addr::new(10, 231, 1, 1);
        let source = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        for incoming_first in [false, true] {
            let (sender, mut receiver) = member_channel(8);
            let mut state = SharedVirtualNicDispatcherState::default();
            state.register(first, sender);
            state
                .source_table
                .update_member_sources(first, member_sources(&["10.231.1.1/24"]));
            let original = ipv4_udp_packet(native, remote);
            let original = original.payload().to_vec();
            if incoming_first {
                let packet = transport_packet(remote, native, IpProtocol::Udp, 5678, 1234);
                let unchanged = packet.payload().to_vec();
                assert_eq!(
                    state
                        .prepare_member_packet_to_tun(first, packet)
                        .unwrap()
                        .payload(),
                    unchanged
                );
            } else {
                assert!(state.send_packet(ZCPacket::new_with_payload(&original)));
                assert_eq!(receiver.try_recv().unwrap().payload(), original);
            }

            let (sender, _second_receiver) = member_channel(8);
            state.register(second, sender);
            state
                .source_table
                .update_member_sources(second, member_sources(&["10.231.2.1/24"]));
            assert!(state.send_packet(ipv4_udp_packet(source, remote)));
            let translated = receiver.try_recv().unwrap();
            let wire = SharedVirtualNicFlowKey::from_packet(&translated).unwrap();
            assert_eq!(wire.src, native.into());
            // Keep incoming UDP replies on their service port after a member joins.
            // A native outgoing flow still reserves its port against new clients.
            assert_eq!(
                wire.ports.unwrap().src,
                if incoming_first { 1234 } else { 1235 }
            );

            assert!(state.send_packet(ZCPacket::new_with_payload(&original)));
            assert_eq!(receiver.try_recv().unwrap().payload(), original);
            for (port, destination) in [
                (1234, native),
                (
                    wire.ports.unwrap().src,
                    if incoming_first { native } else { source },
                ),
            ] {
                let reply = state
                    .prepare_member_packet_to_tun(
                        first,
                        transport_packet(remote, native, IpProtocol::Udp, 5678, port),
                    )
                    .unwrap();
                let key = SharedVirtualNicFlowKey::from_packet(&reply).unwrap();
                assert_eq!(key.dst, destination.into());
                assert_eq!(key.ports.unwrap().dst, 1234);
            }
        }
    }

    #[test]
    fn dispatcher_single_member_keeps_existing_translations_after_other_member_leaves() {
        let member_id = uuid::Uuid::from_u128(1);
        let other = uuid::Uuid::from_u128(2);
        let native = Ipv4Addr::new(10, 231, 1, 1);
        let synthetic = Ipv4Addr::new(100, 64, 0, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        let (sender, mut receiver) = member_channel(8);
        let (other_sender, _other_receiver) = member_channel(8);
        let mut state = SharedVirtualNicDispatcherState {
            translate_unknown_sources: true,
            ..Default::default()
        };
        state.register(member_id, sender);
        state.register(other, other_sender);
        state
            .source_table
            .update_member_sources(member_id, member_sources(&["10.231.1.1/24"]));
        assert!(state.send_packet(ipv4_udp_packet(synthetic, remote)));
        let translated = receiver.try_recv().unwrap().payload().to_vec();
        assert_eq!(
            Ipv4Packet::new_checked(&translated).unwrap().src_addr(),
            native
        );

        state.unregister(other, uuid::Uuid::from_u128(1));
        assert!(state.send_packet(ipv4_udp_packet(synthetic, remote)));
        assert_eq!(receiver.try_recv().unwrap().payload(), translated);
        let reply = state
            .prepare_member_packet_to_tun(
                member_id,
                transport_packet(remote, native, IpProtocol::Udp, 5678, 1234),
            )
            .unwrap();
        assert_eq!(
            Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
            synthetic
        );

        let packet = transport_packet(synthetic, remote, IpProtocol::Udp, 4321, 5678);
        let original = packet.payload().to_vec();
        assert!(state.send_packet(packet));
        assert_eq!(receiver.try_recv().unwrap().payload(), original);
    }

    #[test]
    fn rewrite_ipv4_flow_preserves_zero_udp_checksum() {
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let translated_source = Ipv4Addr::new(10, 231, 2, 1);
        let destination = Ipv4Addr::new(10, 231, 2, 2);
        let request = ipv4_udp_packet(source, destination);
        let reply = transport_packet(destination, translated_source, IpProtocol::Udp, 5678, 4321);
        let original = SharedVirtualNicFlowKey::from_packet(&request).unwrap();
        let wire = SharedVirtualNicFlowKey::from_packet(&reply)
            .unwrap()
            .reversed();
        for (mut packet, from, to, direction) in [
            (request, original, wire, RewriteIpAddr::Source),
            (
                reply,
                wire.reversed(),
                original.reversed(),
                RewriteIpAddr::Destination,
            ),
        ] {
            UdpPacket::new_checked(&mut packet.mut_payload()[IPV4_HEADER_MIN_LEN..])
                .unwrap()
                .set_checksum(0);
            assert!(rewrite_packet_flow(&mut packet, from, to, direction));
            assert_eq!(SharedVirtualNicFlowKey::from_packet(&packet), Some(to));
            let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
            assert!(ipv4.verify_checksum());
            assert_eq!(
                UdpPacket::new_checked(ipv4.payload()).unwrap().checksum(),
                0
            );
        }
    }

    #[test]
    fn rewrite_tcp_flow_updates_checksums_and_restores_ports() {
        for ipv6 in [false, true] {
            let [source, _, native, remote] = test_addresses(ipv6);
            let request = transport_packet(source, remote, IpProtocol::Tcp, 1234, 5678);
            let reply = transport_packet(remote, native, IpProtocol::Tcp, 5678, 4321);
            let original = SharedVirtualNicFlowKey::from_packet(&request).unwrap();
            let wire = SharedVirtualNicFlowKey::from_packet(&reply)
                .unwrap()
                .reversed();
            for (mut packet, from, to, direction) in [
                (request, original, wire, RewriteIpAddr::Source),
                (
                    reply,
                    wire.reversed(),
                    original.reversed(),
                    RewriteIpAddr::Destination,
                ),
            ] {
                assert!(rewrite_packet_flow(&mut packet, from, to, direction));
                assert_eq!(SharedVirtualNicFlowKey::from_packet(&packet), Some(to));
                assert_checksums(&packet);
            }
        }
    }

    #[test]
    fn dispatcher_translates_wrong_local_ipv6_source_to_destination_member() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = "2001:db8:1::1".parse::<Ipv6Addr>().unwrap();
        let destination_owner_ip = "2001:db8:2::1".parse::<Ipv6Addr>().unwrap();
        let remote_ip = "2001:db8:99::2".parse::<Ipv6Addr>().unwrap();
        let (mut state, [mut source_receiver, mut destination_receiver]) = test_state([
            (
                source_owner,
                member_sources_with_ipv6(&["2001:db8:1::1/64"]),
            ),
            (
                destination_owner,
                member_sources_with_ipv6_routes(&["2001:db8:2::1/64"], &["2001:db8:99::/64"]),
            ),
        ]);

        // Reserve the native tuple so the translated request must also change its port.
        assert!(state.send_packet(transport_packet(
            destination_owner_ip,
            remote_ip,
            IpProtocol::Udp,
            1234,
            5678
        )));
        destination_receiver.try_recv().unwrap();

        state.forward_tun_packet_to_member(transport_packet(
            source_owner_ip,
            remote_ip,
            IpProtocol::Udp,
            1234,
            5678,
        ));

        assert!(source_receiver.try_recv().is_err());
        let translated = destination_receiver.try_recv().unwrap();
        let translated_ipv6 = Ipv6Packet::new_checked(translated.payload()).unwrap();
        assert_eq!(translated_ipv6.src_addr(), destination_owner_ip);
        assert_eq!(translated_ipv6.dst_addr(), remote_ip);
        let translated_udp = UdpPacket::new_checked(translated_ipv6.payload()).unwrap();
        assert_eq!(translated_udp.src_port(), 1235);
        assert_ne!(translated_udp.checksum(), 0);
        assert!(translated_udp.verify_checksum(
            &IpAddress::Ipv6(destination_owner_ip),
            &IpAddress::Ipv6(remote_ip)
        ));

        let reply = state
            .prepare_member_packet_to_tun(
                destination_owner,
                transport_packet(remote_ip, destination_owner_ip, IpProtocol::Udp, 5678, 1235),
            )
            .unwrap();
        let reply_ipv6 = Ipv6Packet::new_checked(reply.payload()).unwrap();
        assert_eq!(reply_ipv6.src_addr(), remote_ip);
        assert_eq!(reply_ipv6.dst_addr(), source_owner_ip);
        let reply_udp = UdpPacket::new_checked(reply_ipv6.payload()).unwrap();
        assert_eq!(reply_udp.dst_port(), 1234);
        assert_ne!(reply_udp.checksum(), 0);
        assert!(reply_udp.verify_checksum(
            &IpAddress::Ipv6(remote_ip),
            &IpAddress::Ipv6(source_owner_ip)
        ));
    }

    #[test]
    fn icmp_nat_replies_keep_distinct_source_networks() {
        let member_id = uuid::Uuid::from_u128(1);
        for ipv6 in [false, true] {
            let [first_source, second_source, native, remote] = test_addresses(ipv6);
            let mut nat = SharedVirtualNicNatTable::default();
            for (identifier, source, wire_identifier, sequence) in [
                (100, first_source, 100, 1),
                (200, second_source, 200, 1),
                (100, second_source, 101, 1),
                (100, second_source, 101, 2),
                (100, second_source, 101, u16::MAX),
                (100, second_source, 101, 0),
            ] {
                let mut packet = echo_packet(source, remote, false, identifier, sequence);
                let original = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
                assert!(nat.prepare_packet(member_id, None, original, &mut packet, native));
                let wire = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
                assert_eq!(wire.src, native);
                assert_eq!(wire.ports.unwrap().src, wire_identifier);
                assert_checksums(&packet);
                let mut reply = echo_packet(remote, native, true, wire_identifier, sequence);
                assert!(nat.translate_reply(member_id, &mut reply));
                assert_eq!(
                    SharedVirtualNicFlowKey::from_packet(&reply),
                    Some(original.reversed())
                );
                // Sequence numbers are payload, not part of the flow key.
                let header = if ipv6 {
                    IPV6_HEADER_LEN
                } else {
                    IPV4_HEADER_MIN_LEN
                };
                assert_eq!(
                    &packet.payload()[header + 6..header + 8],
                    &sequence.to_be_bytes()
                );
                assert_eq!(
                    &reply.payload()[header + 6..header + 8],
                    &sequence.to_be_bytes()
                );
                assert_checksums(&reply);
            }
        }
    }

    #[test]
    fn rewrite_ipv6_source_rejects_extension_headers_without_changing_packet() {
        let source = "2001:db8:1::1".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8:99::2".parse::<Ipv6Addr>().unwrap();
        let mut packet = ipv6_packet(source, destination);
        packet.mut_payload()[6] = 0; // Hop-by-hop options header.
        let original = packet.payload().to_vec();

        assert!(!rewrite_packet_source(
            &mut packet,
            FlowAddr::from(source),
            FlowAddr::from("2001:db8:2::1".parse::<Ipv6Addr>().unwrap()),
        ));
        assert_eq!(packet.payload(), original);
    }

    #[test]
    fn dispatcher_changed_members_clear_nat_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        for (member_id, unregister) in [
            (source_owner, true),
            (destination_owner, true),
            (source_owner, false),
            (destination_owner, false),
        ] {
            let (mut state, [_source_receiver, mut destination_receiver]) = test_state([
                (source_owner, member_sources(&["10.231.1.1/24"])),
                (destination_owner, member_sources(&["10.231.2.1/24"])),
            ]);
            assert!(state.send_packet(ipv4_udp_packet(source_owner_ip, remote_ip)));
            destination_receiver.try_recv().unwrap();

            if unregister {
                state.unregister(member_id, uuid::Uuid::from_u128(1));
            } else {
                let (ack, _rx) = oneshot::channel();
                state.handle_control(SharedVirtualNicControl::UpdateSources {
                    member_id,
                    sources: member_sources(&["10.231.3.1/24"]),
                    ack,
                });
            }
            let reply = state
                .prepare_member_packet_to_tun(
                    destination_owner,
                    transport_packet(remote_ip, destination_owner_ip, IpProtocol::Udp, 5678, 1234),
                )
                .unwrap();
            let reply_ipv4 = Ipv4Packet::new_checked(reply.payload()).unwrap();
            assert_eq!(reply_ipv4.src_addr(), remote_ip);
            assert_eq!(reply_ipv4.dst_addr(), destination_owner_ip);
        }
    }

    #[test]
    fn dispatcher_preserves_external_ipv4_source_to_route_owner() {
        let first = uuid::Uuid::from_u128(1);
        let route_owner = uuid::Uuid::from_u128(2);
        let synthetic_source = Ipv4Addr::new(100, 64, 0, 1);
        let remote_ip = Ipv4Addr::new(10, 99, 0, 2);
        let (mut state, [mut first_receiver, mut route_receiver]) = test_state([
            (first, member_sources(&["10.231.1.1/24"])),
            (
                route_owner,
                member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["10.99.0.0/24"]),
            ),
        ]);

        // An exhausted local-flow table must not throttle kernel subnet forwarding.
        let local = Ipv4Addr::new(10, 231, 2, 1);
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            assert!(state.send_packet(transport_packet(
                local,
                remote_ip,
                IpProtocol::Tcp,
                port,
                80
            )));
            route_receiver.try_recv().unwrap();
        }
        for packet in [
            ipv4_udp_packet(synthetic_source, remote_ip),
            transport_packet(synthetic_source, remote_ip, IpProtocol::Tcp, 443, 22001),
        ] {
            let unchanged = packet.payload().to_vec();
            assert!(state.send_packet(packet));
            assert_eq!(route_receiver.try_recv().unwrap().payload(), unchanged);
        }
        let incoming = transport_packet(remote_ip, synthetic_source, IpProtocol::Udp, 5678, 1234);
        let unchanged = incoming.payload().to_vec();
        assert_eq!(
            state
                .prepare_member_packet_to_tun(route_owner, incoming)
                .unwrap()
                .payload(),
            unchanged
        );
        assert!(first_receiver.try_recv().is_err());
    }

    #[test]
    fn dispatcher_translates_android_synthetic_icmp_source_to_destination_member() {
        let first = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let synthetic_source = Ipv4Addr::new(100, 64, 0, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 1, 2);
        let (first_sender, mut first_receiver) = member_channel(8);
        let (destination_sender, mut destination_receiver) = member_channel(8);
        let mut state = SharedVirtualNicDispatcherState {
            translate_unknown_sources: true,
            ..Default::default()
        };

        state.register(first, first_sender);
        state.register(destination_owner, destination_sender);
        state
            .source_table
            .update_member_sources(first, member_sources(&["10.231.2.1/24"]));
        state
            .source_table
            .update_member_sources(destination_owner, member_sources(&["10.231.1.1/24"]));

        state.forward_tun_packet_to_member(ipv4_icmp_echo_packet(synthetic_source, remote_ip));

        assert!(first_receiver.try_recv().is_err());
        let translated = destination_receiver.try_recv().unwrap();
        let translated_ipv4 = Ipv4Packet::new_checked(translated.payload()).unwrap();
        assert_eq!(translated_ipv4.src_addr(), destination_owner_ip);
        assert_eq!(translated_ipv4.dst_addr(), remote_ip);

        let reply = state
            .prepare_member_packet_to_tun(
                destination_owner,
                ipv4_icmp_echo_packet(remote_ip, destination_owner_ip),
            )
            .unwrap();
        let reply_ipv4 = Ipv4Packet::new_checked(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.src_addr(), remote_ip);
        assert_eq!(reply_ipv4.dst_addr(), synthetic_source);
    }

    #[test]
    fn dispatcher_icmp_sequences_preserve_other_members_flow_capacity() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        for ipv6 in [false, true] {
            let (mut state, [mut first_receiver, mut second_receiver]) = test_state([
                (
                    first,
                    SharedVirtualNicMemberSources::from_claims(&member_claims(
                        &["10.231.1.1/24"],
                        &["2001:db8:1::1/64"],
                        &[],
                        &[],
                    )),
                ),
                (second, member_sources(&["10.231.2.1/24"])),
            ]);

            for sequence in 0..=FLOW_OWNER_LIMIT as u16 {
                let packet = if ipv6 {
                    echo_packet(
                        "2001:db8:1::1".parse::<Ipv6Addr>().unwrap(),
                        "2001:db8:1::2".parse::<Ipv6Addr>().unwrap(),
                        false,
                        100,
                        sequence,
                    )
                } else {
                    echo_packet(
                        Ipv4Addr::new(10, 231, 1, 1),
                        Ipv4Addr::new(10, 231, 1, 2),
                        false,
                        100,
                        sequence,
                    )
                };
                let original = packet.payload().to_vec();
                assert!(state.send_packet(packet));
                assert_eq!(first_receiver.try_recv().unwrap().payload(), original);
            }

            let packet =
                ipv4_udp_packet(Ipv4Addr::new(10, 231, 2, 1), Ipv4Addr::new(10, 231, 2, 2));
            let original = packet.payload().to_vec();
            assert!(state.send_packet(packet));
            assert_eq!(second_receiver.try_recv().unwrap().payload(), original);
        }
    }

    #[test]
    fn dispatcher_preserves_owned_ipv4_source_with_unspecified_placeholder() {
        let member_id = uuid::Uuid::from_u128(1);
        let local_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 1, 2);
        let (mut state, [mut receiver]) =
            test_state([(member_id, member_sources(&["0.0.0.0/0", "10.231.1.1/24"]))]);
        state.forward_tun_packet_to_member(ipv4_udp_packet(local_ip, remote_ip));

        let packet = receiver.try_recv().unwrap();
        let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), local_ip);
        assert_eq!(ipv4.dst_addr(), remote_ip);
    }

    #[test]
    fn dispatcher_ignores_stale_member_unregister() {
        let member_id = uuid::Uuid::from_u128(1);
        let stale_registration = uuid::Uuid::from_u128(10);
        let current_registration = uuid::Uuid::from_u128(11);
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (sender, mut receiver) = member_channel(8);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(
            member_id,
            SharedVirtualNicMemberTunnelEntry {
                registration_id: current_registration,
                ..sender
            },
        );
        state
            .source_table
            .update_member_sources(member_id, member_sources_with_ipv6(&["2001:db8::1/64"]));
        state.unregister(member_id, stale_registration);
        state.forward_tun_packet_to_member(ipv6_packet(src, dst));

        assert!(receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dispatcher_invalidates_shared_nic_when_tun_read_fails() {
        let member_id = uuid::Uuid::from_u128(1);
        let (tun_tx, tun_rx) = mpsc::unbounded_channel();
        let tun_stream = futures::stream::unfold(tun_rx, |mut receiver| async move {
            receiver.recv().await.map(|packet| (packet, receiver))
        });
        let tun_sink = futures::sink::unfold((), |(), _packet: ZCPacket| async {
            Ok::<(), TunnelError>(())
        });
        let tunnel = TunnelWrapper::new(tun_stream, tun_sink, None);
        let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
        let valid = Arc::new(AtomicBool::new(true));
        let dispatcher = SharedVirtualNicDispatcher::start(
            Box::new(tunnel),
            member_tunnel_table.clone(),
            valid.clone(),
        );
        let close_notifier = Arc::new(Notify::new());
        let _member_tunnel = member_tunnel_table
            .register(member_id, uuid::Uuid::from_u128(1), close_notifier.clone())
            .unwrap();
        let empty_claims = SharedIfConfigClaims::default();
        dispatcher
            .update_sources(member_id, &empty_claims)
            .await
            .unwrap();

        tun_tx.send(Err(TunnelError::Shutdown)).unwrap();

        tokio::time::timeout(Duration::from_secs(1), close_notifier.notified())
            .await
            .unwrap();
        assert!(!valid.load(Ordering::Acquire));
        assert!(member_tunnel_table.control_sender().is_none());
    }

    #[tokio::test]
    async fn dispatcher_shutdown_for_replacement_keeps_shared_nic_valid() {
        let member_id = uuid::Uuid::from_u128(1);
        let (_tun_tx, tun_rx) = mpsc::unbounded_channel();
        let tun_stream = futures::stream::unfold(tun_rx, |mut receiver| async move {
            receiver.recv().await.map(|packet| (packet, receiver))
        });
        let tun_sink = futures::sink::unfold((), |(), _packet: ZCPacket| async {
            Ok::<(), TunnelError>(())
        });
        let tunnel = TunnelWrapper::new(tun_stream, tun_sink, None);
        let member_tunnel_table = SharedVirtualNicMemberTunnelTable::default();
        let valid = Arc::new(AtomicBool::new(true));
        let dispatcher = SharedVirtualNicDispatcher::start(
            Box::new(tunnel),
            member_tunnel_table.clone(),
            valid.clone(),
        );
        let close_notifier = Arc::new(Notify::new());
        let _member_tunnel = member_tunnel_table
            .register(member_id, uuid::Uuid::from_u128(1), close_notifier.clone())
            .unwrap();
        let empty_claims = SharedIfConfigClaims::default();
        dispatcher
            .update_sources(member_id, &empty_claims)
            .await
            .unwrap();

        dispatcher.shutdown_without_invalidation().await;

        tokio::time::timeout(Duration::from_secs(1), close_notifier.notified())
            .await
            .unwrap();
        assert!(valid.load(Ordering::Acquire));
        assert!(member_tunnel_table.control_sender().is_none());
    }

    #[tokio::test]
    async fn dispatcher_shutdown_waits_for_resources_when_control_fails() {
        for receiver_closed in [true, false] {
            let (control_sender, control_receiver) = mpsc::unbounded_channel();
            let resource = Arc::new(());
            let weak = Arc::downgrade(&resource);
            let (ready, started) = oneshot::channel();
            let task = tokio::spawn(async move {
                let _resource = resource;
                let _receiver = if receiver_closed {
                    drop(control_receiver);
                    None
                } else {
                    Some(control_receiver)
                };
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            });
            started.await.unwrap();
            let dispatcher = SharedVirtualNicDispatcher {
                task: AbortOnDropHandle::new(task),
                control_sender,
            };

            dispatcher.shutdown_without_invalidation().await;
            assert!(weak.upgrade().is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_member_updates_finish_before_registration_cleanup() {
        use super::super::{SharedVirtualNic, SharedVirtualNicMember};
        use crate::{
            common::{ifcfg::IfConfiguerTrait, netns::NetNS},
            instance::virtual_nic::VirtualNicConfig,
        };

        #[derive(Clone)]
        struct PausingIfConfiger {
            claims: Arc<StdMutex<SharedIfConfigClaims>>,
            pause: Arc<AtomicBool>,
            applied: Arc<Notify>,
            resume: Arc<Notify>,
        }

        impl PausingIfConfiger {
            async fn after_apply(&self) {
                if self.pause.swap(false, Ordering::AcqRel) {
                    self.applied.notify_one();
                    self.resume.notified().await;
                }
            }
        }

        #[async_trait::async_trait]
        impl IfConfiguerTrait for PausingIfConfiger {
            async fn add_ipv4_ip(
                &self,
                _name: &str,
                address: Ipv4Addr,
                prefix: u8,
            ) -> Result<(), Error> {
                self.claims
                    .lock()
                    .unwrap()
                    .ipv4_addresses
                    .insert(Ipv4Inet::new(address, prefix).unwrap());
                self.after_apply().await;
                Ok(())
            }

            async fn remove_ip(&self, _name: &str, ip: Option<Ipv4Inet>) -> Result<(), Error> {
                self.claims
                    .lock()
                    .unwrap()
                    .ipv4_addresses
                    .remove(&ip.unwrap());
                Ok(())
            }

            async fn add_ipv4_route(
                &self,
                _name: &str,
                address: Ipv4Addr,
                prefix: u8,
                cost: Option<i32>,
            ) -> Result<(), Error> {
                self.claims
                    .lock()
                    .unwrap()
                    .ipv4_routes
                    .insert(SharedIpv4Route::new(address, prefix, cost));
                self.after_apply().await;
                Ok(())
            }

            async fn remove_ipv4_route(
                &self,
                _name: &str,
                address: Ipv4Addr,
                prefix: u8,
            ) -> Result<(), Error> {
                self.claims
                    .lock()
                    .unwrap()
                    .ipv4_routes
                    .retain(|route| route.address != address || route.prefix != prefix);
                Ok(())
            }

            async fn set_mtu(&self, _name: &str, mtu: u32) -> Result<(), Error> {
                self.claims.lock().unwrap().mtu = Some(mtu);
                self.after_apply().await;
                Ok(())
            }
        }

        for operation in ["address", "route", "mtu"] {
            for pause_in_ifcfg in [false, true] {
                let member_id = uuid::Uuid::from_u128(1);
                let other_member_id = uuid::Uuid::from_u128(2);
                let applied = Arc::new(Notify::new());
                let resume = Arc::new(Notify::new());
                let initial_claims = SharedIfConfigClaims {
                    mtu: Some(1500),
                    ..Default::default()
                };
                let ifcfg = PausingIfConfiger {
                    claims: Arc::new(StdMutex::new(initial_claims.clone())),
                    pause: Arc::new(AtomicBool::new(pause_in_ifcfg)),
                    applied: applied.clone(),
                    resume: resume.clone(),
                };
                let mut shared_nic = SharedVirtualNic::new(VirtualNicConfig::new(
                    String::new(),
                    1500,
                    NetNS::new(None),
                ));
                {
                    let mut nic = shared_nic.nic.lock().await;
                    nic.set_ifname_for_test("et0".to_owned());
                    nic.set_ifcfg_for_test(Box::new(ifcfg.clone()));
                }
                // A surviving member keeps the device alive after the caller exits.
                shared_nic
                    .member_registrations
                    .insert(other_member_id, uuid::Uuid::new_v4());
                shared_nic
                    .ifcfg
                    .apply_member_claims(other_member_id, initial_claims.clone());
                let (control_sender, mut controls) = mpsc::unbounded_channel();
                let ack_applied = applied.clone();
                let ack_resume = resume.clone();
                let task = shared_virtual_nic_runtime().spawn(async move {
                    let mut updates = 0;
                    while let Some(control) = controls.recv().await {
                        match control {
                            SharedVirtualNicControl::UpdateSources { ack, .. } => {
                                updates += 1;
                                if updates == 2 && !pause_in_ifcfg {
                                    ack_applied.notify_one();
                                    ack_resume.notified().await;
                                }
                                let _ = ack.send(());
                            }
                            SharedVirtualNicControl::Shutdown { ack, .. } => {
                                let _ = ack.send(());
                                break;
                            }
                            _ => {}
                        }
                    }
                });
                shared_nic.dispatcher = Some(SharedVirtualNicDispatcher {
                    task: AbortOnDropHandle::new(task),
                    control_sender,
                });
                let table = shared_nic.member_tunnel_table.clone();
                let lifetimes = shared_nic.lifetimes.clone();
                *lifetimes.lock().unwrap() = Some(1);
                let shared_nic = Arc::new(tokio::sync::Mutex::new(shared_nic));
                let member = SharedVirtualNicMember::new(
                    member_id,
                    1300,
                    shared_nic.clone(),
                    Arc::new(Notify::new()),
                    table,
                    lifetimes,
                );
                shared_nic
                    .lock()
                    .await
                    .member_registrations
                    .insert(member_id, member.registration.registration_id);

                let caller = tokio::spawn(async move {
                    match operation {
                        "address" => member.add_ip(Ipv4Addr::new(10, 231, 1, 1), 24).await,
                        "route" => member.add_route(Ipv4Addr::new(10, 99, 0, 0), 24).await,
                        "mtu" => member.create_dev().await.map(|_| ()),
                        _ => unreachable!(),
                    }
                });
                tokio::time::timeout(Duration::from_secs(5), applied.notified())
                    .await
                    .unwrap();
                caller.abort();
                assert!(caller.await.unwrap_err().is_cancelled());
                resume.notify_one();

                tokio::time::timeout(Duration::from_secs(5), async {
                    while shared_nic
                        .lock()
                        .await
                        .member_registrations
                        .contains_key(&member_id)
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .unwrap();
                assert_eq!(
                    *ifcfg.claims.lock().unwrap(),
                    initial_claims,
                    "operation={operation}, pause_in_ifcfg={pause_in_ifcfg}"
                );
                let mut shared_nic = shared_nic.lock().await;
                assert!(shared_nic.is_valid());
                assert!(!shared_nic.ifcfg.member_claims.contains_key(&member_id));
                shared_nic.shutdown_dispatcher().await;
            }
        }
    }

    #[test]
    fn dispatcher_preserves_incoming_udp_reply_ports_with_wrong_source() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        for ipv6 in [false, true] {
            let [source, _, native, remote] = test_addresses(ipv6);
            let source_sources = address_sources(source);
            let native_sources = address_sources(native);
            let incoming = transport_packet(remote, native, IpProtocol::Udp, 5678, 1234);
            let outgoing = transport_packet(source, remote, IpProtocol::Udp, 1234, 5678);
            let (mut state, [mut source_receiver, mut receiver]) = test_state([
                (source_owner, source_sources),
                (destination_owner, native_sources),
            ]);

            let incoming_payload = incoming.payload().to_vec();
            let expected_reply = SharedVirtualNicFlowKey::from_packet(&incoming)
                .unwrap()
                .reversed();
            for _ in 0..3 {
                // A wildcard UDP socket receives on B but replies with A's source IP.
                let received = state
                    .prepare_member_packet_to_tun(
                        destination_owner,
                        ZCPacket::new_with_payload(&incoming_payload),
                    )
                    .unwrap();
                assert_eq!(received.payload(), incoming_payload);
                assert!(state.send_packet(ZCPacket::new_with_payload(outgoing.payload())));
                let reply = receiver.try_recv().unwrap();
                assert_eq!(
                    SharedVirtualNicFlowKey::from_packet(&reply),
                    Some(expected_reply)
                );
                assert_checksums(&reply);
                assert!(source_receiver.try_recv().is_err());
            }
        }
    }

    #[test]
    fn dispatcher_reserves_native_incoming_tcp_flows_before_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        for ipv6 in [false, true] {
            let [source, _, native, remote] = test_addresses(ipv6);
            let source_sources = address_sources(source);
            let native_sources = address_sources(native);
            let incoming = transport_packet(remote, native, IpProtocol::Tcp, 5678, 1234);
            let outgoing = transport_packet(source, remote, IpProtocol::Tcp, 1234, 5678);
            let (mut state, [_source_receiver, mut receiver]) = test_state([
                (source_owner, source_sources),
                (destination_owner, native_sources),
            ]);

            let incoming_payload = incoming.payload().to_vec();
            let native_reply = state
                .prepare_member_packet_to_tun(destination_owner, incoming)
                .unwrap();
            assert_eq!(native_reply.payload(), incoming_payload);

            // The native socket has not replied when another member starts a flow.
            let original = SharedVirtualNicFlowKey::from_packet(&outgoing).unwrap();
            assert!(state.send_packet(outgoing));
            let translated = receiver.try_recv().unwrap();
            let wire = SharedVirtualNicFlowKey::from_packet(&translated).unwrap();
            assert_ne!(wire.ports.unwrap().src, original.ports.unwrap().src);

            let native_reply = state
                .prepare_member_packet_to_tun(
                    destination_owner,
                    ZCPacket::new_with_payload(&incoming_payload),
                )
                .unwrap();
            assert_eq!(native_reply.payload(), incoming_payload);

            assert_checksums(&translated);
            let translated_reply = transport_packet(
                wire.dst,
                wire.src,
                IpProtocol::Tcp,
                5678,
                wire.ports.unwrap().src,
            );
            let reply = state
                .prepare_member_packet_to_tun(destination_owner, translated_reply)
                .unwrap();
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&reply),
                Some(original.reversed())
            );
        }
    }

    #[test]
    fn nat_existing_outgoing_udp_mapping_precedes_incoming_reservation() {
        let member_id = uuid::Uuid::from_u128(1);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let other_native = Ipv4Addr::new(10, 231, 2, 3);
        let remote = Ipv4Addr::new(10, 231, 2, 2);
        let mut nat = SharedVirtualNicNatTable::default();
        let mut outgoing = ipv4_udp_packet(source, remote);
        let original = SharedVirtualNicFlowKey::from_packet(&outgoing).unwrap();
        assert!(nat.prepare_packet(member_id, None, original, &mut outgoing, native.into()));
        let wire = SharedVirtualNicFlowKey::from_packet(&outgoing).unwrap();

        let incoming = transport_packet(remote, other_native, IpProtocol::Udp, 5678, 1234);
        assert!(nat.reserve_reply(
            member_id,
            SharedVirtualNicFlowKey::from_packet(&incoming).unwrap()
        ));
        let mut outgoing = ipv4_udp_packet(source, remote);
        assert!(nat.prepare_packet(
            member_id,
            None,
            original,
            &mut outgoing,
            other_native.into()
        ));
        assert_eq!(SharedVirtualNicFlowKey::from_packet(&outgoing), Some(wire));
        let mut reply = transport_packet(remote, native, IpProtocol::Udp, 5678, 1234);
        assert!(nat.translate_reply(member_id, &mut reply));
        assert_eq!(
            SharedVirtualNicFlowKey::from_packet(&reply),
            Some(original.reversed())
        );
    }

    #[test]
    fn dispatcher_incoming_flow_pressure_keeps_active_reservations() {
        let member_id = uuid::Uuid::from_u128(1);
        let native = Ipv4Addr::new(10, 231, 1, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        let mut state = SharedVirtualNicDispatcherState::default();
        state
            .source_table
            .update_member_sources(member_id, member_sources(&["10.231.1.1/24"]));

        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            assert!(
                state
                    .prepare_member_packet_to_tun(
                        member_id,
                        transport_packet(remote, native, IpProtocol::Udp, 5678, port),
                    )
                    .is_some()
            );
        }
        let new_port = FLOW_OWNER_LIMIT as u16 + 1;
        assert!(
            state
                .prepare_member_packet_to_tun(
                    member_id,
                    transport_packet(remote, native, IpProtocol::Udp, 5678, new_port),
                )
                .is_none()
        );
        assert_eq!(state.nat_table.entries.len(), FLOW_OWNER_LIMIT);

        for entry in state.nat_table.entries.values_mut() {
            entry.last_active = Instant::now() - FLOW_IDLE_TIMEOUT - Duration::from_secs(1);
        }
        // Refresh a receive-only socket before pressure reclaims the idle entries.
        for port in [1, new_port] {
            let incoming = transport_packet(remote, native, IpProtocol::Udp, 5678, port);
            let unchanged = incoming.payload().to_vec();
            assert_eq!(
                state
                    .prepare_member_packet_to_tun(member_id, incoming)
                    .unwrap()
                    .payload(),
                unchanged
            );
        }
        assert_eq!(state.nat_table.entries.len(), 2);
        let active = SharedVirtualNicFlowKey::from_packet(&transport_packet(
            native,
            remote,
            IpProtocol::Udp,
            1,
            5678,
        ))
        .unwrap();
        assert!(state.nat_table.entries.contains_key(&(member_id, active)));
    }

    #[test]
    fn dispatcher_colliding_native_and_translated_flows_remain_distinct() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let destination = Ipv4Addr::new(10, 231, 2, 2);
        for native_first in [false, true] {
            let (mut state, [mut source_receiver, mut receiver]) = test_state([
                (source_owner, member_sources(&["10.231.1.1/24"])),
                (destination_owner, member_sources(&["10.231.2.1/24"])),
            ]);
            let mut wire_keys = Vec::new();
            for src in if native_first {
                [native, source]
            } else {
                [source, native]
            } {
                let packet = ipv4_udp_packet(src, destination);
                let original = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
                assert!(state.send_packet(packet));
                let sent = receiver.try_recv().unwrap();
                let wire = SharedVirtualNicFlowKey::from_packet(&sent).unwrap();
                assert_eq!(wire.src, native.into());
                assert_eq!(wire.dst, destination.into());
                let ipv4 = Ipv4Packet::new_checked(sent.payload()).unwrap();
                assert!(ipv4.verify_checksum());
                let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
                assert_ne!(udp.checksum(), 0);
                assert!(
                    udp.verify_checksum(&IpAddress::Ipv4(native), &IpAddress::Ipv4(destination))
                );
                wire_keys.push((original, wire));
            }
            assert!(source_receiver.try_recv().is_err());
            assert_ne!(wire_keys[0].1, wire_keys[1].1);
            for (original, wire) in wire_keys {
                let source = original.src.as_ipv4().unwrap();
                assert!(state.send_packet(ipv4_udp_packet(source, destination)));
                assert_eq!(
                    SharedVirtualNicFlowKey::from_packet(&receiver.try_recv().unwrap()),
                    Some(wire)
                );
                for (member_id, expected) in [
                    (source_owner, wire.reversed()),
                    (destination_owner, original.reversed()),
                ] {
                    let reply = state
                        .prepare_member_packet_to_tun(
                            member_id,
                            transport_packet(
                                destination,
                                native,
                                IpProtocol::Udp,
                                5678,
                                wire.ports.unwrap().src,
                            ),
                        )
                        .unwrap();
                    assert_eq!(SharedVirtualNicFlowKey::from_packet(&reply), Some(expected));
                    let ipv4 = Ipv4Packet::new_checked(reply.payload()).unwrap();
                    assert!(ipv4.verify_checksum());
                    let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
                    assert_ne!(udp.checksum(), 0);
                    assert!(udp.verify_checksum(
                        &IpAddress::Ipv4(destination),
                        &IpAddress::Ipv4(expected.dst.as_ipv4().unwrap())
                    ));
                }
            }
        }
    }

    #[test]
    fn dispatcher_unrelated_claims_and_unregister_preserve_replies() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let unrelated = uuid::Uuid::from_u128(3);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 2, 2);
        let mut state = SharedVirtualNicDispatcherState::default();
        let (sender, _source_receiver) = member_channel(8);
        state.register(source_owner, sender);
        let (sender, mut receiver) = member_channel(8);
        state.register(destination_owner, sender);
        let (sender, _unrelated_receiver) = member_channel(8);
        state.register(unrelated, sender);
        state
            .source_table
            .update_member_sources(source_owner, member_sources(&["10.231.1.1/24"]));
        state
            .source_table
            .update_member_sources(destination_owner, member_sources(&["10.231.2.1/24"]));
        state.forward_tun_packet_to_member(ipv4_udp_packet(source, remote));
        receiver.try_recv().unwrap();

        for (member_id, sources) in [
            (
                unrelated,
                member_sources_with_ipv4_routes(&["10.231.3.1/24"], &["192.0.2.0/24"]),
            ),
            (
                source_owner,
                member_sources_with_ipv4_routes(&["10.231.1.1/24"], &["198.51.100.0/24"]),
            ),
            (
                destination_owner,
                member_sources_with_ipv4_routes(
                    &["10.231.2.1/24", "10.231.4.1/24"],
                    &["203.0.113.0/24"],
                ),
            ),
        ] {
            let (ack, mut receiver) = oneshot::channel();
            state.handle_control(SharedVirtualNicControl::UpdateSources {
                member_id,
                sources,
                ack,
            });
            receiver.try_recv().unwrap();
            let reply = state
                .prepare_member_packet_to_tun(
                    destination_owner,
                    transport_packet(remote, native, IpProtocol::Udp, 5678, 1234),
                )
                .unwrap();
            assert_eq!(
                Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
                source
            );
        }
        state.unregister(unrelated, uuid::Uuid::from_u128(1));
        let reply = state
            .prepare_member_packet_to_tun(
                destination_owner,
                transport_packet(remote, native, IpProtocol::Udp, 5678, 1234),
            )
            .unwrap();
        assert_eq!(
            Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
            source
        );
    }

    #[test]
    fn dispatcher_full_member_queue_drops_only_packet_without_reserving_flow() {
        let slow = uuid::Uuid::from_u128(1);
        let active = uuid::Uuid::from_u128(2);
        let slow_ip = Ipv4Addr::new(10, 231, 1, 1);
        let active_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        let mut state = SharedVirtualNicDispatcherState::default();
        let (sender, mut slow_receiver) = member_channel(8);
        state.register(slow, sender);
        let (sender, mut active_receiver) = member_channel(8);
        state.register(active, sender);
        state
            .source_table
            .update_member_sources(slow, member_sources(&["10.231.1.1/24"]));
        state
            .source_table
            .update_member_sources(active, member_sources(&["10.231.2.1/24"]));
        for _ in 0..8 {
            assert!(state.send_packet(transport_packet(
                slow_ip,
                remote,
                IpProtocol::Udp,
                1000,
                5678
            )));
        }
        assert!(!state.send_packet(ipv4_udp_packet(active_ip, remote)));
        assert_eq!(state.nat_table.entries.len(), 1);
        let (ack, mut receiver) = oneshot::channel();
        state.handle_control(SharedVirtualNicControl::UpdateSources {
            member_id: active,
            sources: member_sources(&["10.231.2.1/24"]),
            ack,
        });
        receiver.try_recv().unwrap();
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(active_ip, Ipv4Addr::new(10, 231, 2, 2)));
        active_receiver.try_recv().unwrap();
        for _ in 0..8 {
            slow_receiver.try_recv().unwrap();
        }

        // The dropped translated flow must not steal this native flow's port.
        state.forward_tun_packet_to_member(ipv4_udp_packet(slow_ip, remote));
        let packet = slow_receiver.try_recv().unwrap();
        assert_eq!(
            SharedVirtualNicFlowKey::from_packet(&packet)
                .unwrap()
                .ports
                .unwrap()
                .src,
            1234
        );
        let reply = state
            .prepare_member_packet_to_tun(
                slow,
                transport_packet(remote, slow_ip, IpProtocol::Udp, 5678, 1234),
            )
            .unwrap();
        assert_eq!(
            Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
            slow_ip
        );
        drop(slow_receiver);
        state.forward_tun_packet_to_member(ipv4_udp_packet(slow_ip, remote));
        assert!(!state.members.contains_key(&slow));
    }

    #[test]
    fn nat_pressure_reclaims_idle_flows_but_preserves_active_reservations() {
        let member_id = uuid::Uuid::from_u128(1);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 2, 2);
        let mut nat = SharedVirtualNicNatTable::default();
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            let mut packet = transport_packet(source, remote, IpProtocol::Udp, port, 5678);
            assert!(nat.prepare_packet(
                member_id,
                None,
                SharedVirtualNicFlowKey::from_packet(&packet).unwrap(),
                &mut packet,
                native.into()
            ));
        }
        let mut new_flow = transport_packet(
            source,
            remote,
            IpProtocol::Udp,
            FLOW_OWNER_LIMIT as u16 + 1,
            5678,
        );
        let new_key = SharedVirtualNicFlowKey::from_packet(&new_flow).unwrap();
        assert!(!nat.prepare_packet(member_id, None, new_key, &mut new_flow, native.into()));
        let mut unsupported = ipv4_udp_packet(native, remote);
        {
            let mut ipv4 = Ipv4Packet::new_checked(unsupported.mut_payload()).unwrap();
            ipv4.set_next_header(IpProtocol::Unknown(253));
            ipv4.fill_checksum();
        }
        let unchanged = unsupported.payload().to_vec();
        assert!(nat.prepare_packet(
            member_id,
            None,
            SharedVirtualNicFlowKey::from_packet(&unsupported).unwrap(),
            &mut unsupported,
            native.into(),
        ));
        assert_eq!(unsupported.payload(), unchanged);
        for entry in nat.entries.values_mut() {
            entry.last_active = Instant::now() - FLOW_IDLE_TIMEOUT - Duration::from_secs(1);
        }
        // Activity in either direction protects the reservation during lazy reclamation.
        let mut active = transport_packet(source, remote, IpProtocol::Udp, 1, 5678);
        assert!(nat.prepare_packet(
            member_id,
            None,
            SharedVirtualNicFlowKey::from_packet(&active).unwrap(),
            &mut active,
            native.into()
        ));
        assert!(nat.translate_reply(
            member_id,
            &mut transport_packet(remote, native, IpProtocol::Udp, 5678, 2)
        ));
        assert!(nat.prepare_packet(member_id, None, new_key, &mut new_flow, native.into()));
        for port in [1, 2] {
            let mut native_packet = transport_packet(native, remote, IpProtocol::Udp, port, 5678);
            assert!(nat.prepare_packet(
                member_id,
                None,
                SharedVirtualNicFlowKey::from_packet(&native_packet).unwrap(),
                &mut native_packet,
                native.into(),
            ));
            let wire = SharedVirtualNicFlowKey::from_packet(&native_packet).unwrap();
            assert_ne!(wire.ports.unwrap().src, port);
            let mut reply = transport_packet(
                remote,
                native,
                IpProtocol::Udp,
                5678,
                wire.ports.unwrap().src,
            );
            assert!(nat.translate_reply(member_id, &mut reply));
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&reply)
                    .unwrap()
                    .ports
                    .unwrap()
                    .dst,
                port
            );
        }
    }

    #[test]
    fn nat_identical_wire_tuples_are_scoped_to_member() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        let first_source = Ipv4Addr::new(10, 231, 1, 1);
        let second_source = Ipv4Addr::new(10, 231, 2, 1);
        let wire_source = Ipv4Addr::new(10, 231, 3, 1);
        let remote = Ipv4Addr::new(10, 231, 3, 2);
        let mut nat = SharedVirtualNicNatTable::default();
        for (member_id, source) in [(first, first_source), (second, second_source)] {
            let mut packet = ipv4_udp_packet(source, remote);
            assert!(nat.prepare_packet(
                member_id,
                None,
                SharedVirtualNicFlowKey::from_packet(&packet).unwrap(),
                &mut packet,
                wire_source.into(),
            ));
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&packet)
                    .unwrap()
                    .ports
                    .unwrap()
                    .src,
                1234
            );
        }
        for (member_id, source) in [(first, first_source), (second, second_source)] {
            let mut reply = transport_packet(remote, wire_source, IpProtocol::Udp, 5678, 1234);
            assert!(nat.translate_reply(member_id, &mut reply));
            assert_eq!(
                Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
                source
            );
        }
    }
}

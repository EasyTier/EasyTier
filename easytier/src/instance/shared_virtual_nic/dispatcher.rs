use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{SinkExt, StreamExt};
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
    tunnel::{Tunnel, ZCPacketSink, ZCPacketStream},
};

use super::{
    SHARED_VIRTUAL_NIC_RUNTIME, SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route,
    SharedVirtualNicMemberId, SharedVirtualNicMemberRegistrationId,
};

const MEMBER_TUNNEL_BUFFER_SIZE: usize = 1024;
const FLOW_OWNER_LIMIT: usize = 4096;
// Match the core UDP proxy's idle lifetime; reclaim lazily under table pressure.
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(180);
const DISPATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
const DISPATCHER_TUN_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

struct SharedVirtualNicMemberPacket {
    member_id: SharedVirtualNicMemberId,
    packet: ZCPacket,
}

#[cfg(any(mobile, all(test, unix)))]
struct SharedVirtualNicMobileTunUpdate {
    tun_fd: std::os::fd::RawFd,
    ack: oneshot::Sender<Result<(), Error>>,
}

enum SharedVirtualNicControl {
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
    state: Arc<StdMutex<SharedVirtualNicMemberTunnelTableState>>,
}

#[derive(Default)]
struct SharedVirtualNicMemberTunnelTableState {
    to_tun_sender: Option<mpsc::Sender<SharedVirtualNicMemberPacket>>,
    control_sender: Option<mpsc::UnboundedSender<SharedVirtualNicControl>>,
}

struct SharedVirtualNicMemberTunnelEntry {
    registration_id: SharedVirtualNicMemberRegistrationId,
    sender: mpsc::Sender<ZCPacket>,
    close_notifier: Arc<Notify>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

impl SharedVirtualNicMemberTunnelTable {
    fn attach_dispatcher(
        &self,
        to_tun_sender: mpsc::Sender<SharedVirtualNicMemberPacket>,
        control_sender: mpsc::UnboundedSender<SharedVirtualNicControl>,
    ) {
        let mut state = self.state.lock().unwrap();
        state.to_tun_sender = Some(to_tun_sender);
        state.control_sender = Some(control_sender);
    }

    pub(super) fn detach_dispatcher(&self) {
        let mut state = self.state.lock().unwrap();
        state.to_tun_sender.take();
        state.control_sender.take();
    }

    pub(super) fn register(
        &self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
        tunnel: Box<dyn Tunnel>,
        close_notifier: Arc<Notify>,
    ) -> Result<(), Error> {
        let channels = self
            .dispatcher_channels()
            .ok_or_else(|| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        let (to_tun_sender, control_sender) = channels;
        let (mut member_stream, mut member_sink) = tunnel.split();
        let (to_member_sender, mut to_member_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let (reader_start_sender, reader_start_receiver) = oneshot::channel();

        let reader_control_sender = control_sender.clone();
        let reader_close_notifier = close_notifier.clone();
        let reader_task = AbortOnDropHandle::new(tokio::spawn(async move {
            if reader_start_receiver.await.is_err() {
                return;
            }

            while let Some(packet) = member_stream.next().await {
                let packet = match packet {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::error!(?member_id, ?err, "shared member tunnel read failed");
                        break;
                    }
                };

                if to_tun_sender
                    .send(SharedVirtualNicMemberPacket { member_id, packet })
                    .await
                    .is_err()
                {
                    break;
                }
            }

            notify_member_tunnel_closed(
                &reader_control_sender,
                &reader_close_notifier,
                member_id,
                registration_id,
            );
        }));

        let writer_control_sender = control_sender.clone();
        let writer_close_notifier = close_notifier.clone();
        let writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = to_member_receiver.recv().await {
                if let Err(err) = member_sink.send(packet).await {
                    tracing::error!(?member_id, ?err, "shared member tunnel write failed");
                    notify_member_tunnel_closed(
                        &writer_control_sender,
                        &writer_close_notifier,
                        member_id,
                        registration_id,
                    );
                    break;
                }
            }
        }));

        let entry = SharedVirtualNicMemberTunnelEntry {
            registration_id,
            sender: to_member_sender,
            close_notifier,
            _tasks: vec![reader_task, writer_task],
        };
        control_sender
            .send(SharedVirtualNicControl::Register { member_id, entry })
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        let _ = reader_start_sender.send(());

        Ok(())
    }

    pub(super) fn unregister(
        &self,
        member_id: SharedVirtualNicMemberId,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) {
        let Some(control_sender) = self.control_sender() else {
            return;
        };
        let _ = control_sender.send(SharedVirtualNicControl::Unregister {
            member_id,
            registration_id,
        });
    }

    fn dispatcher_channels(
        &self,
    ) -> Option<(
        mpsc::Sender<SharedVirtualNicMemberPacket>,
        mpsc::UnboundedSender<SharedVirtualNicControl>,
    )> {
        let state = self.state.lock().unwrap();
        Some((state.to_tun_sender.clone()?, state.control_sender.clone()?))
    }

    fn control_sender(&self) -> Option<mpsc::UnboundedSender<SharedVirtualNicControl>> {
        self.state.lock().unwrap().control_sender.clone()
    }
}

fn notify_member_tunnel_closed(
    control_sender: &mpsc::UnboundedSender<SharedVirtualNicControl>,
    close_notifier: &Notify,
    member_id: SharedVirtualNicMemberId,
    registration_id: SharedVirtualNicMemberRegistrationId,
) {
    let _ = control_sender.send(SharedVirtualNicControl::Unregister {
        member_id,
        registration_id,
    });
    close_notifier.notify_one();
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
        if !self.ensure_capacity(now) {
            return false;
        }

        let mut wire = original;
        wire.src = translated_src;
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
    _task: AbortOnDropHandle<()>,
    control_sender: mpsc::UnboundedSender<SharedVirtualNicControl>,
    #[cfg(mobile)]
    mobile_tun_update_sender: Option<mpsc::UnboundedSender<SharedVirtualNicMobileTunUpdate>>,
}

impl SharedVirtualNicDispatcher {
    pub(super) fn start(
        tunnel: Box<dyn Tunnel>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Self {
        let (tun_stream, tun_sink) = tunnel.split();
        let (to_tun_sender, to_tun_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        member_tunnel_table.attach_dispatcher(to_tun_sender, control_sender.clone());

        let task = SharedVirtualNicDispatcherTask {
            tun_stream,
            tun_sink,
            to_tun_receiver,
            control_receiver,
            member_tunnel_table,
            valid,
            state: SharedVirtualNicDispatcherState::default(),
        };

        Self {
            _task: AbortOnDropHandle::new(SHARED_VIRTUAL_NIC_RUNTIME.spawn(task.run())),
            control_sender,
            #[cfg(mobile)]
            mobile_tun_update_sender: None,
        }
    }

    #[cfg(mobile)]
    pub(super) async fn start_for_mobile(
        nic: Arc<Mutex<VirtualNic>>,
        tun_fd: std::os::fd::RawFd,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Result<Self, Error> {
        let (to_tun_sender, to_tun_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        let (mobile_tun_update_sender, mobile_tun_update_receiver) = mpsc::unbounded_channel();
        let (first_open_sender, first_open_receiver) = oneshot::channel();
        let task_member_tunnel_table = member_tunnel_table.clone();
        member_tunnel_table.attach_dispatcher(to_tun_sender, control_sender.clone());

        let task = SHARED_VIRTUAL_NIC_RUNTIME.spawn(async move {
            let task = SharedVirtualNicMobileDispatcherTask {
                nic,
                tun_stream: None,
                tun_sink: None,
                tun_fd,
                tun_update_receiver: mobile_tun_update_receiver,
                to_tun_receiver,
                control_receiver,
                member_tunnel_table: task_member_tunnel_table,
                valid,
                state: SharedVirtualNicDispatcherState {
                    translate_unknown_sources: true,
                    ..Default::default()
                },
            };

            task.run(first_open_sender).await;
        });

        let dispatcher = Self {
            _task: AbortOnDropHandle::new(task),
            control_sender,
            mobile_tun_update_sender: Some(mobile_tun_update_sender),
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
        let sender = self.mobile_tun_update_sender.as_ref().ok_or_else(|| {
            Error::from(anyhow::anyhow!(
                "shared virtual nic mobile dispatcher is not running"
            ))
        })?;
        let (ack, receiver) = oneshot::channel();
        sender
            .send(SharedVirtualNicMobileTunUpdate { tun_fd, ack })
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
        if self
            .control_sender
            .send(SharedVirtualNicControl::Shutdown {
                invalidate: false,
                ack,
            })
            .is_err()
        {
            return;
        }

        if tokio::time::timeout(DISPATCHER_SHUTDOWN_TIMEOUT, rx)
            .await
            .is_err()
        {
            tracing::warn!("timed out shutting down shared virtual nic dispatcher");
        }
    }
}

enum DispatcherControlResult {
    Continue,
    Stop {
        invalidate: bool,
        ack: Option<oneshot::Sender<()>>,
    },
}

fn handle_dispatcher_control(
    state: &mut SharedVirtualNicDispatcherState,
    control: Option<SharedVirtualNicControl>,
) -> DispatcherControlResult {
    let Some(control) = control else {
        return DispatcherControlResult::Stop {
            invalidate: true,
            ack: None,
        };
    };

    match control {
        SharedVirtualNicControl::Shutdown { invalidate, ack } => DispatcherControlResult::Stop {
            invalidate,
            ack: Some(ack),
        },
        other => {
            state.handle_control(other);
            DispatcherControlResult::Continue
        }
    }
}

fn acknowledge_dispatcher_shutdown(ack: Option<oneshot::Sender<()>>) {
    if let Some(ack) = ack {
        let _ = ack.send(());
    }
}

async fn send_packet_to_tun(
    tun_sink: &mut Pin<Box<dyn ZCPacketSink>>,
    packet: ZCPacket,
) -> Result<(), Error> {
    tokio::time::timeout(DISPATCHER_TUN_WRITE_TIMEOUT, tun_sink.send(packet)).await??;
    Ok(())
}

struct SharedVirtualNicDispatcherTask {
    tun_stream: Pin<Box<dyn ZCPacketStream>>,
    tun_sink: Pin<Box<dyn ZCPacketSink>>,
    to_tun_receiver: mpsc::Receiver<SharedVirtualNicMemberPacket>,
    control_receiver: mpsc::UnboundedReceiver<SharedVirtualNicControl>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    valid: Arc<AtomicBool>,
    state: SharedVirtualNicDispatcherState,
}

impl SharedVirtualNicDispatcherTask {
    async fn run(mut self) {
        loop {
            tokio::select! {
                control = self.control_receiver.recv() => {
                    if let DispatcherControlResult::Stop { invalidate, ack } =
                        handle_dispatcher_control(&mut self.state, control)
                    {
                        self.cleanup(invalidate);
                        acknowledge_dispatcher_shutdown(ack);
                        return;
                    }
                }
                member_packet = self.to_tun_receiver.recv() => {
                    let Some(member_packet) = member_packet else {
                        break;
                    };
                    if !self.forward_member_packet_to_tun(member_packet).await {
                        break;
                    }
                }
                packet = self.tun_stream.next() => {
                    let Some(packet) = packet else {
                        break;
                    };
                    let packet = match packet {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::error!(?err, "shared virtual nic read from tun failed");
                            break;
                        }
                    };
                    self.state.forward_tun_packet_to_member(packet).await;
                }
            }
        }

        self.cleanup(true);
    }

    fn cleanup(&mut self, invalidate: bool) {
        if invalidate {
            self.valid.store(false, Ordering::Release);
        }
        self.member_tunnel_table.detach_dispatcher();
        self.state.close_all();
    }

    async fn forward_member_packet_to_tun(
        &mut self,
        member_packet: SharedVirtualNicMemberPacket,
    ) -> bool {
        let Some(packet) = self
            .state
            .prepare_member_packet_to_tun(member_packet.member_id, member_packet.packet)
        else {
            return true;
        };
        if let Err(err) = send_packet_to_tun(&mut self.tun_sink, packet).await {
            tracing::error!(?err, "shared virtual nic write to tun failed");
            return false;
        }
        true
    }
}

#[cfg(any(mobile, all(test, unix)))]
struct SharedVirtualNicMobileDispatcherTask {
    nic: Arc<Mutex<VirtualNic>>,
    tun_stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    tun_sink: Option<Pin<Box<dyn ZCPacketSink>>>,
    tun_fd: std::os::fd::RawFd,
    tun_update_receiver: mpsc::UnboundedReceiver<SharedVirtualNicMobileTunUpdate>,
    to_tun_receiver: mpsc::Receiver<SharedVirtualNicMemberPacket>,
    control_receiver: mpsc::UnboundedReceiver<SharedVirtualNicControl>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    valid: Arc<AtomicBool>,
    state: SharedVirtualNicDispatcherState,
}

#[cfg(any(mobile, all(test, unix)))]
impl SharedVirtualNicMobileDispatcherTask {
    #[cfg(mobile)]
    async fn run(mut self, first_open_sender: oneshot::Sender<Result<(), Error>>) {
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

        self.run_opened_tun().await;
    }

    async fn run_opened_tun(mut self) {
        loop {
            tokio::select! {
                control = self.control_receiver.recv() => {
                    if !self.handle_control(control) {
                        return;
                    }
                }
                member_packet = self.to_tun_receiver.recv() => {
                    let Some(member_packet) = member_packet else {
                        self.cleanup(true);
                        return;
                    };
                    if !self.forward_member_packet_to_tun(member_packet).await {
                        self.cleanup(true);
                        return;
                    }
                }
                packet = async {
                    match self.tun_stream.as_mut() {
                        Some(stream) => stream.next().await,
                        None => std::future::pending().await,
                    }
                } => {
                    let Some(packet) = packet else {
                        tracing::error!("shared virtual nic mobile tun stream closed");
                        self.cleanup(true);
                        return;
                    };
                    match packet {
                        Ok(packet) => self.state.forward_tun_packet_to_member(packet).await,
                        Err(err) => {
                            tracing::error!(?err, "shared virtual nic read from mobile tun failed");
                            self.cleanup(true);
                            return;
                        }
                    }
                }
                update = self.tun_update_receiver.recv() => {
                    let Some(update) = update else {
                        self.cleanup(true);
                        return;
                    };
                    if !self.apply_tun_update(update).await {
                        return;
                    }
                }
            }
        }
    }

    async fn open_tun(&mut self) -> Result<(), Error> {
        let tun_fd = self.tun_fd;
        let tunnel = self.nic.lock().await.create_dev_for_mobile(tun_fd).await?;
        let (tun_stream, tun_sink) = tunnel.split();
        self.tun_stream = Some(tun_stream);
        self.tun_sink = Some(tun_sink);
        tracing::info!(fd = tun_fd, "opened shared virtual nic mobile tun");
        Ok(())
    }

    async fn apply_tun_update(&mut self, update: SharedVirtualNicMobileTunUpdate) -> bool {
        self.drop_tun();
        self.tun_fd = update.tun_fd;
        match self.open_tun().await {
            Ok(()) => {
                let _ = update.ack.send(Ok(()));
                true
            }
            Err(err) => {
                tracing::error!(fd = self.tun_fd, ?err, "failed to replace mobile tun");
                self.cleanup(true);
                let _ = update.ack.send(Err(err));
                false
            }
        }
    }

    async fn forward_member_packet_to_tun(
        &mut self,
        member_packet: SharedVirtualNicMemberPacket,
    ) -> bool {
        let Some(packet) = self
            .state
            .prepare_member_packet_to_tun(member_packet.member_id, member_packet.packet)
        else {
            return true;
        };
        let Some(tun_sink) = self.tun_sink.as_mut() else {
            return false;
        };

        if let Err(err) = send_packet_to_tun(tun_sink, packet).await {
            tracing::error!(?err, "shared virtual nic write to mobile tun failed");
            return false;
        }
        true
    }

    fn handle_control(&mut self, control: Option<SharedVirtualNicControl>) -> bool {
        match handle_dispatcher_control(&mut self.state, control) {
            DispatcherControlResult::Continue => true,
            DispatcherControlResult::Stop { invalidate, ack } => {
                self.cleanup(invalidate);
                acknowledge_dispatcher_shutdown(ack);
                false
            }
        }
    }

    fn drop_tun(&mut self) {
        self.tun_stream.take();
        self.tun_sink.take();
    }

    fn cleanup(&mut self, invalidate: bool) {
        self.drop_tun();
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

    async fn forward_tun_packet_to_member(&mut self, packet: ZCPacket) {
        if !self.send_packet(packet).await {
            tracing::trace!("shared virtual nic dropped packet without active member");
        }
    }

    async fn send_packet(&mut self, packet: ZCPacket) -> bool {
        let source_owner = self.source_table.owner_of_source(&packet, &self.members);
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
            return self
                .send_packet_to_member_with_translation(
                    member_id,
                    source_owner.active_member(),
                    packet,
                    translate_source,
                )
                .await
                .is_ok();
        }

        match source_owner {
            SourceOwner::Active(member_id) => {
                return self
                    .send_packet_to_member_with_translation(
                        member_id,
                        Some(member_id),
                        packet,
                        false,
                    )
                    .await
                    .is_ok();
            }
            SourceOwner::Inactive => return false,
            SourceOwner::None => {}
        }

        false
    }

    async fn send_packet_to_member_with_translation(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        source_owner: Option<SharedVirtualNicMemberId>,
        mut packet: ZCPacket,
        translate_source: bool,
    ) -> Result<(), ZCPacket> {
        let Some((registration_id, sender)) = self
            .members
            .get(&member_id)
            .map(|entry| (entry.registration_id, entry.sender.clone()))
        else {
            return Err(packet);
        };
        // Reserve queue capacity before allocating a flow, and never await a slow member.
        let permit = match sender.try_reserve() {
            Ok(permit) => permit,
            Err(mpsc::error::TrySendError::Full(())) => return Err(packet),
            Err(mpsc::error::TrySendError::Closed(())) => {
                self.unregister(member_id, registration_id);
                return Err(packet);
            }
        };
        // Forwarded subnet sources cannot collide with a member's translated address.
        if !translate_source && source_owner.is_none() {
            permit.send(packet);
            return Ok(());
        }
        let Some(key) = SharedVirtualNicFlowKey::from_packet(&packet) else {
            return Err(packet);
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
            return Err(packet);
        }
        permit.send(packet);
        Ok(())
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
            SharedVirtualNicFlowAddr::V4(dst) => sources
                .ipv4_source_for_destination(std::net::Ipv4Addr::from(dst))
                .map(SharedVirtualNicFlowAddr::from),
            SharedVirtualNicFlowAddr::V6(dst) => sources
                .ipv6_source_for_destination(std::net::Ipv6Addr::from(dst))
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

    fn ipv4_source_for_destination(&self, dst: std::net::Ipv4Addr) -> Option<std::net::Ipv4Addr> {
        let mut best = None;
        for addr in &self.ipv4_addresses {
            if addr.contains(&dst) {
                update_best_source(&mut best, addr.network_length(), addr.address());
            }
        }
        for route in &self.ipv4_routes {
            if route.contains(&dst) {
                let Some(source) = self.ipv4_source_for_route(route) else {
                    continue;
                };
                update_best_source(&mut best, route.network_length(), source);
            }
        }
        best.map(|(_, source)| source)
    }

    fn ipv4_source_for_route(&self, route: &Ipv4Inet) -> Option<std::net::Ipv4Addr> {
        let mut default_source = None;
        for addr in &self.ipv4_addresses {
            default_source.get_or_insert(addr.address());
            if route.contains(&addr.address()) {
                return Some(addr.address());
            }
        }
        default_source
    }
    fn ipv6_source_for_destination(&self, dst: std::net::Ipv6Addr) -> Option<std::net::Ipv6Addr> {
        let mut best = None;
        for addr in &self.ipv6_addresses {
            if addr.contains(&dst) {
                update_best_source(&mut best, addr.network_length(), addr.address());
            }
        }
        for route in &self.ipv6_routes {
            if route.contains(&dst) {
                let Some(source) = self.ipv6_source_for_route(route) else {
                    continue;
                };
                update_best_source(&mut best, route.network_length(), source);
            }
        }
        best.map(|(_, source)| source)
    }

    fn ipv6_source_for_route(&self, route: &Ipv6Inet) -> Option<std::net::Ipv6Addr> {
        let mut default_source = None;
        for addr in &self.ipv6_addresses {
            default_source.get_or_insert(addr.address());
            if route.contains(&addr.address()) {
                return Some(addr.address());
            }
        }
        default_source
    }
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

    use super::*;
    use easytier_core::tunnel::{
        TunnelError, ring::create_ring_tunnel_pair, wrapper::TunnelWrapper,
    };
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

    fn ipv6_udp_packet_with_ports(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV6_HEADER_LEN + UDP_HEADER_LEN];
        {
            let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut payload);
            ipv6_packet.set_version(6);
            ipv6_packet.set_payload_len(UDP_HEADER_LEN as u16);
            ipv6_packet.set_next_header(IpProtocol::Udp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_src_addr(src);
            ipv6_packet.set_dst_addr(dst);
        }
        {
            let mut udp_packet = UdpPacket::new_unchecked(&mut payload[IPV6_HEADER_LEN..]);
            udp_packet.set_src_port(src_port);
            udp_packet.set_dst_port(dst_port);
            udp_packet.set_len(UDP_HEADER_LEN as u16);
            udp_packet.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv6_tcp_packet_with_ports(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV6_HEADER_LEN + TCP_HEADER_MIN_LEN];
        {
            let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut payload);
            ipv6_packet.set_version(6);
            ipv6_packet.set_payload_len(TCP_HEADER_MIN_LEN as u16);
            ipv6_packet.set_next_header(IpProtocol::Tcp);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_src_addr(src);
            ipv6_packet.set_dst_addr(dst);
        }
        {
            let mut tcp_packet = TcpPacket::new_unchecked(&mut payload[IPV6_HEADER_LEN..]);
            tcp_packet.set_src_port(src_port);
            tcp_packet.set_dst_port(dst_port);
            tcp_packet.set_header_len(TCP_HEADER_MIN_LEN as u8);
            tcp_packet.fill_checksum(&IpAddress::Ipv6(src), &IpAddress::Ipv6(dst));
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv6_icmp_packet_with_id(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        reply: bool,
        identifier: u16,
        sequence: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV6_HEADER_LEN + ICMP_ECHO_HEADER_LEN];
        {
            let mut ipv6_packet = Ipv6Packet::new_unchecked(&mut payload);
            ipv6_packet.set_version(6);
            ipv6_packet.set_payload_len(ICMP_ECHO_HEADER_LEN as u16);
            ipv6_packet.set_next_header(IpProtocol::Icmpv6);
            ipv6_packet.set_hop_limit(64);
            ipv6_packet.set_src_addr(src);
            ipv6_packet.set_dst_addr(dst);
        }
        {
            let mut icmp_packet = Icmpv6Packet::new_unchecked(&mut payload[IPV6_HEADER_LEN..]);
            icmp_packet.set_msg_type(if reply {
                Icmpv6Message::EchoReply
            } else {
                Icmpv6Message::EchoRequest
            });
            icmp_packet.set_echo_ident(identifier);
            icmp_packet.set_echo_seq_no(sequence);
            icmp_packet.fill_checksum(&src, &dst);
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        ipv4_udp_packet_with_ports(src, dst, 1234, 5678)
    }

    fn ipv4_icmp_echo_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        ipv4_icmp_packet_with_id(src, dst, Icmpv4Message::EchoRequest, 0, 0)
    }

    fn ipv4_icmp_packet_with_id(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: Icmpv4Message,
        identifier: u16,
        sequence: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + 8];
        let payload_len = payload.len();
        {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut payload);
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_len(IPV4_HEADER_MIN_LEN as u8);
            ipv4_packet.set_total_len(payload_len as u16);
            ipv4_packet.set_hop_limit(64);
            ipv4_packet.set_next_header(IpProtocol::Icmp);
            ipv4_packet.set_src_addr(src);
            ipv4_packet.set_dst_addr(dst);
        }
        {
            let mut icmp_packet = Icmpv4Packet::new_unchecked(&mut payload[IPV4_HEADER_MIN_LEN..]);
            icmp_packet.set_msg_type(icmp_type);
            icmp_packet.set_msg_code(0);
            icmp_packet.set_echo_ident(identifier);
            icmp_packet.set_echo_seq_no(sequence);
            icmp_packet.fill_checksum();
        }
        {
            Ipv4Packet::new_unchecked(&mut payload).fill_checksum();
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_udp_packet_with_ports(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN];
        let payload_len = payload.len();
        {
            let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut payload);
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_len(IPV4_HEADER_MIN_LEN as u8);
            ipv4_packet.set_total_len(payload_len as u16);
            ipv4_packet.set_hop_limit(64);
            ipv4_packet.set_next_header(IpProtocol::Udp);
            ipv4_packet.set_src_addr(src);
            ipv4_packet.set_dst_addr(dst);
        }
        {
            let mut udp_packet = UdpPacket::new_unchecked(&mut payload[IPV4_HEADER_MIN_LEN..]);
            udp_packet.set_src_port(src_port);
            udp_packet.set_dst_port(dst_port);
            udp_packet.set_len(UDP_HEADER_LEN as u16);
            udp_packet.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        }
        {
            Ipv4Packet::new_unchecked(&mut payload).fill_checksum();
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_tcp_packet_with_ports(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + TCP_HEADER_MIN_LEN];
        let total_len = payload.len() as u16;
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut payload);
        ipv4.set_version(4);
        ipv4.set_header_len(IPV4_HEADER_MIN_LEN as u8);
        ipv4.set_total_len(total_len);
        ipv4.set_hop_limit(64);
        ipv4.set_next_header(IpProtocol::Tcp);
        ipv4.set_src_addr(src);
        ipv4.set_dst_addr(dst);
        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
        tcp.set_header_len(TCP_HEADER_MIN_LEN as u8);
        tcp.set_src_port(src_port);
        tcp.set_dst_port(dst_port);
        tcp.fill_checksum(&IpAddress::Ipv4(src), &IpAddress::Ipv4(dst));
        ipv4.fill_checksum();
        ZCPacket::new_with_payload(&payload)
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

    fn member_entry(sender: mpsc::Sender<ZCPacket>) -> SharedVirtualNicMemberTunnelEntry {
        member_entry_with_registration(sender, uuid::Uuid::from_u128(1))
    }

    fn member_entry_with_registration(
        sender: mpsc::Sender<ZCPacket>,
        registration_id: SharedVirtualNicMemberRegistrationId,
    ) -> SharedVirtualNicMemberTunnelEntry {
        SharedVirtualNicMemberTunnelEntry {
            registration_id,
            sender,
            close_notifier: Arc::new(Notify::new()),
            _tasks: Vec::new(),
        }
    }

    #[cfg(unix)]
    fn start_mobile_dispatcher_for_test(
        tunnel: Box<dyn Tunnel>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> (
        SharedVirtualNicDispatcher,
        mpsc::UnboundedSender<SharedVirtualNicMobileTunUpdate>,
    ) {
        use crate::{common::netns::NetNS, instance::virtual_nic::VirtualNicConfig};

        let (tun_stream, tun_sink) = tunnel.split();
        let (to_tun_sender, to_tun_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        let (tun_update_sender, tun_update_receiver) = mpsc::unbounded_channel();
        member_tunnel_table.attach_dispatcher(to_tun_sender, control_sender.clone());
        let task = SharedVirtualNicMobileDispatcherTask {
            nic: Arc::new(Mutex::new(VirtualNic::new(VirtualNicConfig::new(
                String::new(),
                1300,
                NetNS::new(None),
            )))),
            tun_stream: Some(tun_stream),
            tun_sink: Some(tun_sink),
            tun_fd: -1,
            tun_update_receiver,
            to_tun_receiver,
            control_receiver,
            member_tunnel_table,
            valid,
            state: SharedVirtualNicDispatcherState {
                translate_unknown_sources: true,
                ..Default::default()
            },
        };
        let dispatcher = SharedVirtualNicDispatcher {
            _task: AbortOnDropHandle::new(tokio::spawn(task.run_opened_tun())),
            control_sender,
            #[cfg(mobile)]
            mobile_tun_update_sender: Some(tun_update_sender.clone()),
        };
        (dispatcher, tun_update_sender)
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
            let (member_tunnel, shared_tunnel) = create_ring_tunnel_pair();
            member_tunnel_table
                .register(
                    member_id,
                    uuid::Uuid::new_v4(),
                    shared_tunnel,
                    close_notifier.clone(),
                )
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
        assert!(member_tunnel_table.dispatcher_channels().is_none());
        tokio::time::timeout(Duration::from_secs(1), dispatcher._task)
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
            .send(SharedVirtualNicMobileTunUpdate { tun_fd: -1, ack })
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
        assert!(member_tunnel_table.dispatcher_channels().is_none());
        assert!(
            dispatcher
                .remove_sources(uuid::Uuid::from_u128(1))
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(1), dispatcher._task)
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
            assert!(member_tunnel_table.dispatcher_channels().is_none());
            tokio::time::timeout(Duration::from_secs(1), dispatcher._task)
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
        let (first_sender, _first_receiver) = mpsc::channel(1);
        let (second_sender, _second_receiver) = mpsc::channel(1);
        let mut members = BTreeMap::new();
        members.insert(first, member_entry(first_sender));
        members.insert(second, member_entry(second_sender));

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
        let (first_sender, _first_receiver) = mpsc::channel(1);
        let (second_sender, _second_receiver) = mpsc::channel(1);
        let mut members = BTreeMap::new();
        members.insert(first, member_entry(first_sender));
        members.insert(second, member_entry(second_sender));

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

    #[tokio::test]
    async fn dispatcher_prefers_source_owner_for_shared_magic_dns() {
        let first = uuid::Uuid::from_u128(1);
        let source_owner = uuid::Uuid::from_u128(2);
        let first_ip = Ipv4Addr::new(10, 231, 1, 1);
        let source_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(100, 100, 100, 101);
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(first, member_entry(first_sender));
        state.register(source_owner, member_entry(source_sender));
        state.source_table.update_member_sources(
            first,
            member_sources_with_ipv4_routes(&["10.231.1.1/24"], &["100.100.100.101/32"]),
        );
        state.source_table.update_member_sources(
            source_owner,
            member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["100.100.100.101/32"]),
        );

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

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
                SharedVirtualNicFlowAddr::from(src),
                SharedVirtualNicFlowAddr::from(Ipv4Addr::new(10, 231, 2, 1))
            ));
            assert_eq!(packet.payload(), original);
        }
    }

    #[tokio::test]
    async fn dispatcher_prefers_source_owner_over_first_member() {
        let first = uuid::Uuid::from_u128(1);
        let owner = uuid::Uuid::from_u128(2);
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (owner_sender, mut owner_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(first, member_entry(first_sender));
        state.register(owner, member_entry(owner_sender));
        state
            .source_table
            .update_member_sources(owner, member_sources_with_ipv6(&["2001:db8::2/64"]));
        state
            .forward_tun_packet_to_member(ipv6_packet(source, dst))
            .await;

        assert!(first_receiver.try_recv().is_err());
        assert!(owner_receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dispatcher_forwards_external_ipv6_to_route_only_owner() {
        let route_owner = uuid::Uuid::from_u128(1);
        let source = "2001:db8:ffff::2".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8:100::2".parse::<Ipv6Addr>().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(route_owner, member_entry(sender));
        state.source_table.update_member_sources(
            route_owner,
            member_sources_with_ipv6_routes(&[], &["2001:db8:100::2/128"]),
        );
        // An exhausted local-flow table must not throttle kernel subnet forwarding.
        let local = "2001:db8:100::1".parse::<Ipv6Addr>().unwrap();
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            let mut packet = ipv6_tcp_packet_with_ports(local, destination, port, 80);
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
            ipv6_tcp_packet_with_ports(source, destination, 443, 22001),
        ] {
            let unchanged = packet.payload().to_vec();
            assert!(state.send_packet(packet).await);
            assert_eq!(receiver.try_recv().unwrap().payload(), unchanged);
        }
    }

    #[tokio::test]
    async fn dispatcher_drops_inactive_source_owner_without_fallback() {
        let fallback = uuid::Uuid::from_u128(1);
        let owner = uuid::Uuid::from_u128(2);
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (fallback_sender, mut fallback_receiver) = mpsc::channel(1);
        let (owner_sender, _owner_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(fallback, member_entry(fallback_sender));
        state.register(owner, member_entry(owner_sender));
        state
            .source_table
            .update_member_sources(owner, member_sources_with_ipv6(&["2001:db8::2/64"]));
        state.unregister(owner, uuid::Uuid::from_u128(1));
        state
            .forward_tun_packet_to_member(ipv6_packet(source, dst))
            .await;

        assert!(fallback_receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn dispatcher_drops_unknown_source_and_destination_without_fallback() {
        let member_id = uuid::Uuid::from_u128(1);
        let unknown_source = Ipv4Addr::new(100, 64, 0, 1);
        let unknown_destination = Ipv4Addr::new(203, 0, 113, 1);
        let (sender, mut receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(member_id, member_entry(sender));
        state
            .source_table
            .update_member_sources(member_id, member_sources(&["10.231.1.1/24"]));
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(unknown_source, unknown_destination))
            .await;

        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn rewrite_ipv4_flow_preserves_zero_udp_checksum() {
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let translated_source = Ipv4Addr::new(10, 231, 2, 1);
        let destination = Ipv4Addr::new(10, 231, 2, 2);
        let request = ipv4_udp_packet(source, destination);
        let reply = ipv4_udp_packet_with_ports(destination, translated_source, 5678, 4321);
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
    fn rewrite_ipv4_tcp_flow_updates_checksums_and_restores_ports() {
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let translated_source = Ipv4Addr::new(10, 231, 2, 1);
        let destination = Ipv4Addr::new(10, 231, 2, 2);
        let request = ipv4_tcp_packet_with_ports(source, destination, 1234, 5678);
        let reply = ipv4_tcp_packet_with_ports(destination, translated_source, 5678, 4321);
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
            let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
            assert!(ipv4.verify_checksum());
            let tcp = TcpPacket::new_checked(ipv4.payload()).unwrap();
            assert!(tcp.verify_checksum(
                &IpAddress::Ipv4(ipv4.src_addr()),
                &IpAddress::Ipv4(ipv4.dst_addr())
            ));
        }
    }

    #[tokio::test]
    async fn dispatcher_translates_wrong_local_ipv6_source_to_destination_member() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = "2001:db8:1::1".parse::<Ipv6Addr>().unwrap();
        let destination_owner_ip = "2001:db8:2::1".parse::<Ipv6Addr>().unwrap();
        let remote_ip = "2001:db8:99::2".parse::<Ipv6Addr>().unwrap();
        let (source_sender, mut source_receiver) = mpsc::channel(1);
        let (destination_sender, mut destination_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(source_owner, member_entry(source_sender));
        state.register(destination_owner, member_entry(destination_sender));
        state.source_table.update_member_sources(
            source_owner,
            member_sources_with_ipv6(&["2001:db8:1::1/64"]),
        );
        state.source_table.update_member_sources(
            destination_owner,
            member_sources_with_ipv6_routes(&["2001:db8:2::1/64"], &["2001:db8:99::/64"]),
        );

        // Reserve the native tuple so the translated request must also change its port.
        assert!(
            state
                .send_packet(ipv6_udp_packet_with_ports(
                    destination_owner_ip,
                    remote_ip,
                    1234,
                    5678,
                ))
                .await
        );
        destination_receiver.try_recv().unwrap();

        state
            .forward_tun_packet_to_member(ipv6_udp_packet_with_ports(
                source_owner_ip,
                remote_ip,
                1234,
                5678,
            ))
            .await;

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
                ipv6_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1235),
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
    fn rewrite_ipv6_tcp_flow_updates_checksums_and_restores_ports() {
        let source = "2001:db8:1::1".parse::<Ipv6Addr>().unwrap();
        let translated_source = "2001:db8:2::1".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8:99::2".parse::<Ipv6Addr>().unwrap();
        let request = ipv6_tcp_packet_with_ports(source, destination, 1234, 5678);
        let reply = ipv6_tcp_packet_with_ports(destination, translated_source, 5678, 4321);
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
            let ipv6 = Ipv6Packet::new_checked(packet.payload()).unwrap();
            let tcp = TcpPacket::new_checked(ipv6.payload()).unwrap();
            assert!(tcp.verify_checksum(
                &IpAddress::Ipv6(ipv6.src_addr()),
                &IpAddress::Ipv6(ipv6.dst_addr())
            ));
        }
    }

    #[test]
    fn icmpv6_nat_replies_keep_distinct_source_networks() {
        let member_id = uuid::Uuid::from_u128(1);
        let first_source = "2001:db8:1::1".parse::<Ipv6Addr>().unwrap();
        let second_source = "2001:db8:2::1".parse::<Ipv6Addr>().unwrap();
        let translated_source = "2001:db8:3::1".parse::<Ipv6Addr>().unwrap();
        let destination = "2001:db8:3::2".parse::<Ipv6Addr>().unwrap();
        let mut nat = SharedVirtualNicNatTable::default();

        for (identifier, source, wire_identifier, sequence) in [
            (100, first_source, 100, 1),
            (200, second_source, 200, 1),
            (100, second_source, 101, 1),
            (100, second_source, 101, 2),
            (100, second_source, 101, u16::MAX),
            (100, second_source, 101, 0),
        ] {
            let mut packet =
                ipv6_icmp_packet_with_id(source, destination, false, identifier, sequence);
            let original = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
            assert!(nat.prepare_packet(
                member_id,
                None,
                original,
                &mut packet,
                translated_source.into(),
            ));
            let ipv6 = Ipv6Packet::new_checked(packet.payload()).unwrap();
            assert_eq!(ipv6.src_addr(), translated_source);
            let icmp = Icmpv6Packet::new_checked(ipv6.payload()).unwrap();
            assert_eq!(icmp.echo_ident(), wire_identifier);
            assert_eq!(icmp.echo_seq_no(), sequence);
            assert!(icmp.verify_checksum(&translated_source, &destination));

            let mut reply = ipv6_icmp_packet_with_id(
                destination,
                translated_source,
                true,
                wire_identifier,
                sequence,
            );
            assert!(nat.translate_reply(member_id, &mut reply));
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&reply),
                Some(original.reversed())
            );
            let ipv6 = Ipv6Packet::new_checked(reply.payload()).unwrap();
            let icmp = Icmpv6Packet::new_checked(ipv6.payload()).unwrap();
            assert_eq!(icmp.echo_seq_no(), sequence);
            assert!(icmp.verify_checksum(&destination, &source));
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
            SharedVirtualNicFlowAddr::from(source),
            SharedVirtualNicFlowAddr::from("2001:db8:2::1".parse::<Ipv6Addr>().unwrap()),
        ));
        assert_eq!(packet.payload(), original);
    }

    #[tokio::test]
    async fn dispatcher_changed_members_clear_nat_translation() {
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
            let (source_sender, _source_receiver) = mpsc::channel(1);
            let (destination_sender, mut destination_receiver) = mpsc::channel(1);
            let mut state = SharedVirtualNicDispatcherState::default();
            state.register(source_owner, member_entry(source_sender));
            state.register(destination_owner, member_entry(destination_sender));
            state
                .source_table
                .update_member_sources(source_owner, member_sources(&["10.231.1.1/24"]));
            state
                .source_table
                .update_member_sources(destination_owner, member_sources(&["10.231.2.1/24"]));
            assert!(
                state
                    .send_packet(ipv4_udp_packet(source_owner_ip, remote_ip))
                    .await
            );
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
                    ipv4_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1234),
                )
                .unwrap();
            let reply_ipv4 = Ipv4Packet::new_checked(reply.payload()).unwrap();
            assert_eq!(reply_ipv4.src_addr(), remote_ip);
            assert_eq!(reply_ipv4.dst_addr(), destination_owner_ip);
        }
    }

    #[tokio::test]
    async fn dispatcher_preserves_external_ipv4_source_to_route_owner() {
        let first = uuid::Uuid::from_u128(1);
        let route_owner = uuid::Uuid::from_u128(2);
        let synthetic_source = Ipv4Addr::new(100, 64, 0, 1);
        let remote_ip = Ipv4Addr::new(10, 99, 0, 2);
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (route_sender, mut route_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(first, member_entry(first_sender));
        state.register(route_owner, member_entry(route_sender));
        state
            .source_table
            .update_member_sources(first, member_sources(&["10.231.1.1/24"]));
        state.source_table.update_member_sources(
            route_owner,
            member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["10.99.0.0/24"]),
        );

        // An exhausted local-flow table must not throttle kernel subnet forwarding.
        let local = Ipv4Addr::new(10, 231, 2, 1);
        for port in 1..=FLOW_OWNER_LIMIT as u16 {
            assert!(
                state
                    .send_packet(ipv4_tcp_packet_with_ports(local, remote_ip, port, 80))
                    .await
            );
            route_receiver.try_recv().unwrap();
        }
        for packet in [
            ipv4_udp_packet(synthetic_source, remote_ip),
            ipv4_tcp_packet_with_ports(synthetic_source, remote_ip, 443, 22001),
        ] {
            let unchanged = packet.payload().to_vec();
            assert!(state.send_packet(packet).await);
            assert_eq!(route_receiver.try_recv().unwrap().payload(), unchanged);
        }
        let incoming = ipv4_udp_packet_with_ports(remote_ip, synthetic_source, 5678, 1234);
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

    #[tokio::test]
    async fn dispatcher_translates_android_synthetic_icmp_source_to_destination_member() {
        let first = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let synthetic_source = Ipv4Addr::new(100, 64, 0, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 1, 2);
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (destination_sender, mut destination_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState {
            translate_unknown_sources: true,
            ..Default::default()
        };

        state.register(first, member_entry(first_sender));
        state.register(destination_owner, member_entry(destination_sender));
        state
            .source_table
            .update_member_sources(first, member_sources(&["10.231.2.1/24"]));
        state
            .source_table
            .update_member_sources(destination_owner, member_sources(&["10.231.1.1/24"]));

        state
            .forward_tun_packet_to_member(ipv4_icmp_echo_packet(synthetic_source, remote_ip))
            .await;

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

    #[tokio::test]
    async fn dispatcher_icmp_sequences_preserve_other_members_flow_capacity() {
        let first = uuid::Uuid::from_u128(1);
        let second = uuid::Uuid::from_u128(2);
        for ipv6 in [false, true] {
            let (first_sender, mut first_receiver) = mpsc::channel(1);
            let (second_sender, mut second_receiver) = mpsc::channel(1);
            let mut state = SharedVirtualNicDispatcherState::default();
            state.register(first, member_entry(first_sender));
            state.register(second, member_entry(second_sender));
            state.source_table.update_member_sources(
                first,
                SharedVirtualNicMemberSources::from_claims(&member_claims(
                    &["10.231.1.1/24"],
                    &["2001:db8:1::1/64"],
                    &[],
                    &[],
                )),
            );
            state
                .source_table
                .update_member_sources(second, member_sources(&["10.231.2.1/24"]));

            for sequence in 0..=FLOW_OWNER_LIMIT as u16 {
                let packet = if ipv6 {
                    ipv6_icmp_packet_with_id(
                        "2001:db8:1::1".parse().unwrap(),
                        "2001:db8:1::2".parse().unwrap(),
                        false,
                        100,
                        sequence,
                    )
                } else {
                    ipv4_icmp_packet_with_id(
                        Ipv4Addr::new(10, 231, 1, 1),
                        Ipv4Addr::new(10, 231, 1, 2),
                        Icmpv4Message::EchoRequest,
                        100,
                        sequence,
                    )
                };
                let original = packet.payload().to_vec();
                assert!(state.send_packet(packet).await);
                assert_eq!(first_receiver.try_recv().unwrap().payload(), original);
            }

            let packet =
                ipv4_udp_packet(Ipv4Addr::new(10, 231, 2, 1), Ipv4Addr::new(10, 231, 2, 2));
            let original = packet.payload().to_vec();
            assert!(state.send_packet(packet).await);
            assert_eq!(second_receiver.try_recv().unwrap().payload(), original);
        }
    }

    #[test]
    fn icmpv4_nat_replies_keep_distinct_source_networks() {
        let member_id = uuid::Uuid::from_u128(1);
        let first_source = Ipv4Addr::new(10, 231, 1, 1);
        let second_source = Ipv4Addr::new(10, 231, 2, 1);
        let translated_source = Ipv4Addr::new(10, 231, 3, 1);
        let destination = Ipv4Addr::new(10, 231, 3, 2);
        let mut nat = SharedVirtualNicNatTable::default();
        for (identifier, source, wire_identifier, sequence) in [
            (100, first_source, 100, 1),
            (200, second_source, 200, 1),
            (100, second_source, 101, 1),
            (100, second_source, 101, 2),
            (100, second_source, 101, u16::MAX),
            (100, second_source, 101, 0),
        ] {
            let mut packet = ipv4_icmp_packet_with_id(
                source,
                destination,
                Icmpv4Message::EchoRequest,
                identifier,
                sequence,
            );
            let original = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
            assert!(nat.prepare_packet(
                member_id,
                None,
                original,
                &mut packet,
                translated_source.into(),
            ));
            let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
            assert_eq!(ipv4.src_addr(), translated_source);
            assert!(ipv4.verify_checksum());
            let icmp = Icmpv4Packet::new_checked(ipv4.payload()).unwrap();
            assert_eq!(icmp.echo_ident(), wire_identifier);
            assert_eq!(icmp.echo_seq_no(), sequence);
            assert!(icmp.verify_checksum());

            let mut reply = ipv4_icmp_packet_with_id(
                destination,
                translated_source,
                Icmpv4Message::EchoReply,
                wire_identifier,
                sequence,
            );
            assert!(nat.translate_reply(member_id, &mut reply));
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&reply),
                Some(original.reversed())
            );
            let ipv4 = Ipv4Packet::new_checked(reply.payload()).unwrap();
            assert!(ipv4.verify_checksum());
            let icmp = Icmpv4Packet::new_checked(ipv4.payload()).unwrap();
            assert_eq!(icmp.echo_seq_no(), sequence);
            assert!(icmp.verify_checksum());
        }
    }

    #[tokio::test]
    async fn dispatcher_preserves_owned_ipv4_source_with_unspecified_placeholder() {
        let member_id = uuid::Uuid::from_u128(1);
        let local_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 1, 2);
        let (sender, mut receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(member_id, member_entry(sender));
        state
            .source_table
            .update_member_sources(member_id, member_sources(&["0.0.0.0/0", "10.231.1.1/24"]));
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(local_ip, remote_ip))
            .await;

        let packet = receiver.try_recv().unwrap();
        let ipv4 = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), local_ip);
        assert_eq!(ipv4.dst_addr(), remote_ip);
    }

    #[tokio::test]
    async fn dispatcher_ignores_stale_member_unregister() {
        let member_id = uuid::Uuid::from_u128(1);
        let stale_registration = uuid::Uuid::from_u128(10);
        let current_registration = uuid::Uuid::from_u128(11);
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(
            member_id,
            member_entry_with_registration(sender, current_registration),
        );
        state
            .source_table
            .update_member_sources(member_id, member_sources_with_ipv6(&["2001:db8::1/64"]));
        state.unregister(member_id, stale_registration);
        state
            .forward_tun_packet_to_member(ipv6_packet(src, dst))
            .await;

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
        let (_member_tunnel, shared_tunnel) = create_ring_tunnel_pair();

        member_tunnel_table
            .register(
                member_id,
                uuid::Uuid::from_u128(1),
                shared_tunnel,
                close_notifier.clone(),
            )
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
        assert!(member_tunnel_table.dispatcher_channels().is_none());
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
        let (_member_tunnel, shared_tunnel) = create_ring_tunnel_pair();

        member_tunnel_table
            .register(
                member_id,
                uuid::Uuid::from_u128(1),
                shared_tunnel,
                close_notifier.clone(),
            )
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
        assert!(member_tunnel_table.dispatcher_channels().is_none());
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
                let task = SHARED_VIRTUAL_NIC_RUNTIME.spawn(async move {
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
                    _task: AbortOnDropHandle::new(task),
                    control_sender,
                    #[cfg(mobile)]
                    mobile_tun_update_sender: None,
                });
                let table = shared_nic.member_tunnel_table.clone();
                let shared_nic = Arc::new(tokio::sync::Mutex::new(shared_nic));
                let member = SharedVirtualNicMember::new(
                    member_id,
                    1300,
                    shared_nic.clone(),
                    Arc::new(Notify::new()),
                    table,
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

    #[tokio::test]
    async fn dispatcher_reserves_native_incoming_flows_before_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        for (source_sources, native_sources, incoming, outgoing) in [
            (
                member_sources(&["10.231.1.1/24"]),
                member_sources(&["10.231.2.1/24"]),
                ipv4_udp_packet_with_ports(
                    Ipv4Addr::new(10, 231, 2, 2),
                    Ipv4Addr::new(10, 231, 2, 1),
                    5678,
                    1234,
                ),
                ipv4_udp_packet(Ipv4Addr::new(10, 231, 1, 1), Ipv4Addr::new(10, 231, 2, 2)),
            ),
            (
                member_sources_with_ipv6(&["2001:db8:1::1/64"]),
                member_sources_with_ipv6(&["2001:db8:2::1/64"]),
                ipv6_udp_packet_with_ports(
                    "2001:db8:2::2".parse().unwrap(),
                    "2001:db8:2::1".parse().unwrap(),
                    5678,
                    1234,
                ),
                ipv6_udp_packet_with_ports(
                    "2001:db8:1::1".parse().unwrap(),
                    "2001:db8:2::2".parse().unwrap(),
                    1234,
                    5678,
                ),
            ),
        ] {
            let (source_sender, _source_receiver) = mpsc::channel(1);
            let (sender, mut receiver) = mpsc::channel(1);
            let mut state = SharedVirtualNicDispatcherState::default();
            state.register(source_owner, member_entry(source_sender));
            state.register(destination_owner, member_entry(sender));
            state
                .source_table
                .update_member_sources(source_owner, source_sources);
            state
                .source_table
                .update_member_sources(destination_owner, native_sources);

            let incoming_payload = incoming.payload().to_vec();
            let native_reply = state
                .prepare_member_packet_to_tun(destination_owner, incoming)
                .unwrap();
            assert_eq!(native_reply.payload(), incoming_payload);

            // The native socket has not replied when another member starts a flow.
            let original = SharedVirtualNicFlowKey::from_packet(&outgoing).unwrap();
            assert!(state.send_packet(outgoing).await);
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

            let translated_reply = match (wire.dst, wire.src) {
                (SharedVirtualNicFlowAddr::V4(src), SharedVirtualNicFlowAddr::V4(dst)) => {
                    ipv4_udp_packet_with_ports(
                        src.into(),
                        dst.into(),
                        5678,
                        wire.ports.unwrap().src,
                    )
                }
                (SharedVirtualNicFlowAddr::V6(src), SharedVirtualNicFlowAddr::V6(dst)) => {
                    ipv6_udp_packet_with_ports(
                        src.into(),
                        dst.into(),
                        5678,
                        wire.ports.unwrap().src,
                    )
                }
                _ => unreachable!(),
            };
            let reply = state
                .prepare_member_packet_to_tun(destination_owner, translated_reply)
                .unwrap();
            assert_eq!(
                SharedVirtualNicFlowKey::from_packet(&reply),
                Some(original.reversed())
            );
        }
    }

    #[tokio::test]
    async fn dispatcher_incoming_flow_pressure_keeps_active_reservations() {
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
                        ipv4_udp_packet_with_ports(remote, native, 5678, port),
                    )
                    .is_some()
            );
        }
        let new_port = FLOW_OWNER_LIMIT as u16 + 1;
        assert!(
            state
                .prepare_member_packet_to_tun(
                    member_id,
                    ipv4_udp_packet_with_ports(remote, native, 5678, new_port),
                )
                .is_none()
        );
        assert_eq!(state.nat_table.entries.len(), FLOW_OWNER_LIMIT);

        for entry in state.nat_table.entries.values_mut() {
            entry.last_active = Instant::now() - FLOW_IDLE_TIMEOUT - Duration::from_secs(1);
        }
        // Refresh a receive-only socket before pressure reclaims the idle entries.
        for port in [1, new_port] {
            let incoming = ipv4_udp_packet_with_ports(remote, native, 5678, port);
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
        let active = SharedVirtualNicFlowKey::from_packet(&ipv4_udp_packet_with_ports(
            native, remote, 1, 5678,
        ))
        .unwrap();
        assert!(state.nat_table.entries.contains_key(&(member_id, active)));
    }

    #[tokio::test]
    async fn dispatcher_colliding_native_and_translated_flows_remain_distinct() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let destination = Ipv4Addr::new(10, 231, 2, 2);
        for native_first in [false, true] {
            let (source_sender, mut source_receiver) = mpsc::channel(1);
            let (sender, mut receiver) = mpsc::channel(1);
            let mut state = SharedVirtualNicDispatcherState::default();
            state.register(source_owner, member_entry(source_sender));
            state.register(destination_owner, member_entry(sender));
            state
                .source_table
                .update_member_sources(source_owner, member_sources(&["10.231.1.1/24"]));
            state
                .source_table
                .update_member_sources(destination_owner, member_sources(&["10.231.2.1/24"]));
            let mut wire_keys = Vec::new();
            for src in if native_first {
                [native, source]
            } else {
                [source, native]
            } {
                let packet = ipv4_udp_packet(src, destination);
                let original = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
                assert!(state.send_packet(packet).await);
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
                assert!(
                    state
                        .send_packet(ipv4_udp_packet(source, destination))
                        .await
                );
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
                            ipv4_udp_packet_with_ports(
                                destination,
                                native,
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

    #[tokio::test]
    async fn dispatcher_unrelated_claims_and_unregister_preserve_replies() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let unrelated = uuid::Uuid::from_u128(3);
        let source = Ipv4Addr::new(10, 231, 1, 1);
        let native = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 2, 2);
        let mut state = SharedVirtualNicDispatcherState::default();
        let (sender, _source_receiver) = mpsc::channel(1);
        state.register(source_owner, member_entry(sender));
        let (sender, mut receiver) = mpsc::channel(1);
        state.register(destination_owner, member_entry(sender));
        let (sender, _unrelated_receiver) = mpsc::channel(1);
        state.register(unrelated, member_entry(sender));
        state
            .source_table
            .update_member_sources(source_owner, member_sources(&["10.231.1.1/24"]));
        state
            .source_table
            .update_member_sources(destination_owner, member_sources(&["10.231.2.1/24"]));
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source, remote))
            .await;
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
                    ipv4_udp_packet_with_ports(remote, native, 5678, 1234),
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
                ipv4_udp_packet_with_ports(remote, native, 5678, 1234),
            )
            .unwrap();
        assert_eq!(
            Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
            source
        );
    }

    #[tokio::test]
    async fn dispatcher_full_member_queue_drops_only_packet_without_reserving_flow() {
        let slow = uuid::Uuid::from_u128(1);
        let active = uuid::Uuid::from_u128(2);
        let slow_ip = Ipv4Addr::new(10, 231, 1, 1);
        let active_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote = Ipv4Addr::new(10, 231, 1, 2);
        let mut state = SharedVirtualNicDispatcherState::default();
        let (sender, mut slow_receiver) = mpsc::channel(1);
        state.register(slow, member_entry(sender));
        let (sender, mut active_receiver) = mpsc::channel(1);
        state.register(active, member_entry(sender));
        state
            .source_table
            .update_member_sources(slow, member_sources(&["10.231.1.1/24"]));
        state
            .source_table
            .update_member_sources(active, member_sources(&["10.231.2.1/24"]));
        state
            .forward_tun_packet_to_member(ipv4_udp_packet_with_ports(slow_ip, remote, 1000, 5678))
            .await;
        tokio::time::timeout(
            Duration::from_secs(1),
            state.forward_tun_packet_to_member(ipv4_udp_packet(active_ip, remote)),
        )
        .await
        .unwrap();
        let (ack, mut receiver) = oneshot::channel();
        state.handle_control(SharedVirtualNicControl::UpdateSources {
            member_id: active,
            sources: member_sources(&["10.231.2.1/24"]),
            ack,
        });
        receiver.try_recv().unwrap();
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(active_ip, Ipv4Addr::new(10, 231, 2, 2)))
            .await;
        active_receiver.try_recv().unwrap();
        slow_receiver.try_recv().unwrap();

        // The dropped translated flow must not steal this native flow's port.
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(slow_ip, remote))
            .await;
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
                ipv4_udp_packet_with_ports(remote, slow_ip, 5678, 1234),
            )
            .unwrap();
        assert_eq!(
            Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
            slow_ip
        );
        drop(slow_receiver);
        state
            .forward_tun_packet_to_member(ipv4_udp_packet(slow_ip, remote))
            .await;
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
            let mut packet = ipv4_udp_packet_with_ports(source, remote, port, 5678);
            assert!(nat.prepare_packet(
                member_id,
                None,
                SharedVirtualNicFlowKey::from_packet(&packet).unwrap(),
                &mut packet,
                native.into()
            ));
        }
        let mut new_flow =
            ipv4_udp_packet_with_ports(source, remote, FLOW_OWNER_LIMIT as u16 + 1, 5678);
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
        let mut active = ipv4_udp_packet_with_ports(source, remote, 1, 5678);
        assert!(nat.prepare_packet(
            member_id,
            None,
            SharedVirtualNicFlowKey::from_packet(&active).unwrap(),
            &mut active,
            native.into()
        ));
        assert!(nat.translate_reply(
            member_id,
            &mut ipv4_udp_packet_with_ports(remote, native, 5678, 2)
        ));
        assert!(nat.prepare_packet(member_id, None, new_key, &mut new_flow, native.into()));
        for port in [1, 2] {
            let mut native_packet = ipv4_udp_packet_with_ports(native, remote, port, 5678);
            assert!(nat.prepare_packet(
                member_id,
                None,
                SharedVirtualNicFlowKey::from_packet(&native_packet).unwrap(),
                &mut native_packet,
                native.into(),
            ));
            let wire = SharedVirtualNicFlowKey::from_packet(&native_packet).unwrap();
            assert_ne!(wire.ports.unwrap().src, port);
            let mut reply =
                ipv4_udp_packet_with_ports(remote, native, 5678, wire.ports.unwrap().src);
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
            let mut reply = ipv4_udp_packet_with_ports(remote, wire_source, 5678, 1234);
            assert!(nat.translate_reply(member_id, &mut reply));
            assert_eq!(
                Ipv4Packet::new_checked(reply.payload()).unwrap().dst_addr(),
                source
            );
        }
    }
}

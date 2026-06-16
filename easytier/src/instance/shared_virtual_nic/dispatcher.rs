use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{SinkExt, StreamExt};
use pnet::packet::{
    MutablePacket as _, Packet as _,
    icmp::{self, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::{self, MutableUdpPacket},
};
#[cfg(mobile)]
use std::sync::OnceLock;
#[cfg(mobile)]
use tokio::runtime::{Builder, Runtime};
#[cfg(mobile)]
use tokio::sync::{Mutex, watch};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

#[cfg(mobile)]
use crate::instance::virtual_nic::VirtualNic;
use crate::{
    common::error::Error,
    tunnel::{Tunnel, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket},
};

use super::{
    SharedIfConfigClaims, SharedIpv4Route, SharedIpv6Route, SharedVirtualNicMemberId,
    SharedVirtualNicMemberRegistrationId,
};

const MEMBER_TUNNEL_BUFFER_SIZE: usize = 1024;
const FLOW_OWNER_LIMIT: usize = 4096;
const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_MIN_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_ECHO_HEADER_LEN: usize = 8;
const ICMP_PROTOCOL: u8 = 1;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;
const DISPATCHER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(mobile)]
const MOBILE_REBUILD_INITIAL_DELAY: Duration = Duration::from_millis(100);
#[cfg(mobile)]
const MOBILE_REBUILD_MAX_DELAY: Duration = Duration::from_secs(5);

#[cfg(mobile)]
fn mobile_dispatcher_runtime() -> &'static Runtime {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(1)
            .thread_name("easytier-shared-tun")
            .enable_all()
            .build()
            .expect("failed to build shared virtual nic mobile dispatcher runtime")
    })
}

struct SharedVirtualNicMemberPacket {
    member_id: SharedVirtualNicMemberId,
    packet: ZCPacket,
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
    exact: BTreeSet<SharedVirtualNicFlowAddr>,
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
            exact: ipv4_addresses
                .iter()
                .map(|addr| SharedVirtualNicFlowAddr::from(addr.address()))
                .chain(
                    ipv6_addresses
                        .iter()
                        .map(|addr| SharedVirtualNicFlowAddr::from(addr.address())),
                )
                .collect(),
            ipv4_addresses,
            ipv6_addresses,
            ipv4_routes,
            ipv6_routes,
        }
    }

    fn is_empty(&self) -> bool {
        self.exact.is_empty()
            && self.ipv4_addresses.is_empty()
            && self.ipv6_addresses.is_empty()
            && self.ipv4_routes.is_empty()
            && self.ipv6_routes.is_empty()
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
        if payload.len() < IPV4_HEADER_MIN_LEN {
            return None;
        }

        let header_len = usize::from(payload[0] & 0x0f) * 4;
        if header_len < IPV4_HEADER_MIN_LEN || payload.len() < header_len {
            return None;
        }

        let protocol = payload[9];
        let fragment_offset = u16::from_be_bytes([payload[6], payload[7]]) & 0x1fff;
        let src = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let dst = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        Some(Self {
            src: SharedVirtualNicFlowAddr::V4(src),
            dst: SharedVirtualNicFlowAddr::V4(dst),
            protocol,
            ports: if fragment_offset == 0 {
                transport_ports(protocol, &payload[header_len..])
            } else {
                None
            },
        })
    }

    fn from_ipv6_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() < IPV6_HEADER_LEN {
            return None;
        }

        let protocol = payload[6];
        Some(Self {
            src: SharedVirtualNicFlowAddr::V6(read_ipv6_addr(payload, 8)),
            dst: SharedVirtualNicFlowAddr::V6(read_ipv6_addr(payload, 24)),
            protocol,
            ports: transport_ports(protocol, &payload[IPV6_HEADER_LEN..]),
        })
    }

    fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
            ports: self.ports.map(|ports| {
                if self.protocol == ICMP_PROTOCOL {
                    ports
                } else {
                    ports.reversed()
                }
            }),
        }
    }
}

#[derive(Default)]
struct SharedVirtualNicFlowTable {
    owners: HashMap<SharedVirtualNicFlowKey, SharedVirtualNicMemberId>,
    insert_order: VecDeque<SharedVirtualNicFlowKey>,
}

impl SharedVirtualNicFlowTable {
    fn remember_reverse_owner(&mut self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        let Some(key) = SharedVirtualNicFlowKey::from_packet(packet).map(|key| key.reversed())
        else {
            return;
        };

        if !self.owners.contains_key(&key) {
            self.evict_before_insert();
            self.insert_order.push_back(key);
        }
        self.owners.insert(key, member_id);
    }

    fn owner_of(&self, packet: &ZCPacket) -> Option<SharedVirtualNicMemberId> {
        let key = SharedVirtualNicFlowKey::from_packet(packet)?;
        self.owners.get(&key).copied()
    }

    fn clear(&mut self) {
        self.owners.clear();
        self.insert_order.clear();
    }

    fn evict_before_insert(&mut self) {
        while self.owners.len() >= FLOW_OWNER_LIMIT {
            let Some(key) = self.insert_order.pop_front() else {
                self.owners.clear();
                return;
            };
            self.owners.remove(&key);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SharedVirtualNicNatEntry {
    original_src: SharedVirtualNicFlowAddr,
    translated_src: SharedVirtualNicFlowAddr,
}

#[derive(Default)]
struct SharedVirtualNicNatTable {
    entries: HashMap<SharedVirtualNicFlowKey, SharedVirtualNicNatEntry>,
    insert_order: VecDeque<SharedVirtualNicFlowKey>,
}

impl SharedVirtualNicNatTable {
    fn remember(
        &mut self,
        translated_packet: &ZCPacket,
        original_src: SharedVirtualNicFlowAddr,
        translated_src: SharedVirtualNicFlowAddr,
    ) {
        let Some(key) =
            SharedVirtualNicFlowKey::from_packet(translated_packet).map(|key| key.reversed())
        else {
            return;
        };

        if !self.entries.contains_key(&key) {
            self.evict_before_insert();
            self.insert_order.push_back(key);
        }
        self.entries.insert(
            key,
            SharedVirtualNicNatEntry {
                original_src,
                translated_src,
            },
        );
    }

    fn translate_reply(&mut self, packet: &mut ZCPacket) -> bool {
        let Some(key) = SharedVirtualNicFlowKey::from_packet(packet) else {
            return false;
        };
        let Some(entry) = self.entries.get(&key).copied() else {
            return false;
        };

        rewrite_packet_destination(packet, entry.translated_src, entry.original_src)
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.insert_order.clear();
    }

    fn evict_before_insert(&mut self) {
        while self.entries.len() >= FLOW_OWNER_LIMIT {
            let Some(key) = self.insert_order.pop_front() else {
                self.entries.clear();
                return;
            };
            self.entries.remove(&key);
        }
    }
}

pub(super) struct SharedVirtualNicDispatcher {
    _task: AbortOnDropHandle<()>,
    control_sender: mpsc::UnboundedSender<SharedVirtualNicControl>,
    #[cfg(mobile)]
    mobile_tun_fd_sender: Option<watch::Sender<std::os::fd::RawFd>>,
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
            _task: AbortOnDropHandle::new(tokio::spawn(task.run())),
            control_sender,
            #[cfg(mobile)]
            mobile_tun_fd_sender: None,
        }
    }

    #[cfg(mobile)]
    pub(super) fn start_for_mobile(
        nic: Arc<Mutex<VirtualNic>>,
        tun_fd: std::os::fd::RawFd,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Self {
        let (to_tun_sender, to_tun_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        let (control_sender, control_receiver) = mpsc::unbounded_channel();
        let (mobile_tun_fd_sender, mobile_tun_fd_receiver) = watch::channel(tun_fd);
        let task_member_tunnel_table = member_tunnel_table.clone();
        member_tunnel_table.attach_dispatcher(to_tun_sender, control_sender.clone());

        let task = mobile_dispatcher_runtime().spawn(async move {
            let task = SharedVirtualNicMobileDispatcherTask {
                nic,
                tun_stream: None,
                tun_sink: None,
                tun_fd: mobile_tun_fd_receiver,
                to_tun_receiver,
                control_receiver,
                member_tunnel_table: task_member_tunnel_table,
                valid,
                state: SharedVirtualNicDispatcherState::default(),
            };

            task.run().await;
        });

        Self {
            _task: AbortOnDropHandle::new(task),
            control_sender,
            mobile_tun_fd_sender: Some(mobile_tun_fd_sender),
        }
    }

    #[cfg(mobile)]
    pub(super) fn update_mobile_tun_fd(&self, tun_fd: std::os::fd::RawFd) {
        if let Some(sender) = &self.mobile_tun_fd_sender {
            sender.send_replace(tun_fd);
        }
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
        let packet = self
            .state
            .prepare_member_packet_to_tun(member_packet.member_id, member_packet.packet);
        if let Err(err) = self.tun_sink.send(packet).await {
            tracing::error!(?err, "shared virtual nic write to tun failed");
            return false;
        }
        true
    }
}

#[cfg(mobile)]
struct SharedVirtualNicMobileDispatcherTask {
    nic: Arc<Mutex<VirtualNic>>,
    tun_stream: Option<Pin<Box<dyn ZCPacketStream>>>,
    tun_sink: Option<Pin<Box<dyn ZCPacketSink>>>,
    tun_fd: watch::Receiver<std::os::fd::RawFd>,
    to_tun_receiver: mpsc::Receiver<SharedVirtualNicMemberPacket>,
    control_receiver: mpsc::UnboundedReceiver<SharedVirtualNicControl>,
    member_tunnel_table: SharedVirtualNicMemberTunnelTable,
    valid: Arc<AtomicBool>,
    state: SharedVirtualNicDispatcherState,
}

#[cfg(mobile)]
impl SharedVirtualNicMobileDispatcherTask {
    async fn run(mut self) {
        let mut rebuild_delay = MOBILE_REBUILD_INITIAL_DELAY;
        let mut wait_before_rebuild = false;
        let mut rebuild_deadline = None;

        loop {
            if self.tun_stream.is_none() {
                if !wait_before_rebuild {
                    if !self.rebuild_tun().await {
                        wait_before_rebuild = true;
                        rebuild_deadline = None;
                    }
                    continue;
                }

                let deadline = *rebuild_deadline
                    .get_or_insert_with(|| tokio::time::Instant::now() + rebuild_delay);
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
                        tracing::trace!(
                            member_id = ?member_packet.member_id,
                            "shared virtual nic dropped member packet while rebuilding mobile tun"
                        );
                    }
                    changed = self.tun_fd.changed() => {
                        if changed.is_err() {
                            self.cleanup(true);
                            return;
                        }
                        rebuild_delay = MOBILE_REBUILD_INITIAL_DELAY;
                        wait_before_rebuild = false;
                        rebuild_deadline = None;
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        rebuild_delay = next_mobile_rebuild_delay(rebuild_delay);
                        wait_before_rebuild = false;
                        rebuild_deadline = None;
                    }
                }
                continue;
            }

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
                    if self.forward_member_packet_to_tun(member_packet).await {
                        wait_before_rebuild = true;
                        rebuild_deadline = None;
                    } else {
                        rebuild_delay = MOBILE_REBUILD_INITIAL_DELAY;
                    }
                }
                packet = self.tun_stream.as_mut().expect("mobile tun stream should exist").next() => {
                    let Some(packet) = packet else {
                        tracing::error!("shared virtual nic mobile tun stream closed");
                        self.drop_tun();
                        wait_before_rebuild = true;
                        rebuild_deadline = None;
                        continue;
                    };
                    let packet = match packet {
                        Ok(packet) => packet,
                        Err(err) => {
                            tracing::error!(?err, "shared virtual nic read from mobile tun failed");
                            self.drop_tun();
                            wait_before_rebuild = true;
                            rebuild_deadline = None;
                            continue;
                        }
                    };
                    rebuild_delay = MOBILE_REBUILD_INITIAL_DELAY;
                    self.state.forward_tun_packet_to_member(packet).await;
                }
                changed = self.tun_fd.changed() => {
                    if changed.is_err() {
                        self.cleanup(true);
                        return;
                    }
                    self.drop_tun();
                    rebuild_delay = MOBILE_REBUILD_INITIAL_DELAY;
                    wait_before_rebuild = false;
                    rebuild_deadline = None;
                }
            }
        }
    }

    async fn rebuild_tun(&mut self) -> bool {
        let tun_fd = *self.tun_fd.borrow_and_update();
        match self.nic.lock().await.create_dev_for_mobile(tun_fd).await {
            Ok(tunnel) => {
                let (tun_stream, tun_sink) = tunnel.split();
                self.tun_stream = Some(tun_stream);
                self.tun_sink = Some(tun_sink);
                tracing::info!(fd = tun_fd, "rebuilt shared virtual nic mobile tun");
                true
            }
            Err(err) => {
                tracing::error!(
                    fd = tun_fd,
                    ?err,
                    "failed to rebuild shared virtual nic mobile tun"
                );
                false
            }
        }
    }

    async fn forward_member_packet_to_tun(
        &mut self,
        member_packet: SharedVirtualNicMemberPacket,
    ) -> bool {
        let packet = self
            .state
            .prepare_member_packet_to_tun(member_packet.member_id, member_packet.packet);
        let Some(tun_sink) = self.tun_sink.as_mut() else {
            tracing::trace!(
                member_id = ?member_packet.member_id,
                "shared virtual nic dropped member packet without mobile tun"
            );
            return false;
        };

        if let Err(err) = tun_sink.send(packet).await {
            tracing::error!(?err, "shared virtual nic write to mobile tun failed");
            self.drop_tun();
            return true;
        }
        false
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

#[cfg(mobile)]
fn next_mobile_rebuild_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(MOBILE_REBUILD_MAX_DELAY)
}

#[derive(Default)]
struct SharedVirtualNicDispatcherState {
    members: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    flow_table: SharedVirtualNicFlowTable,
    nat_table: SharedVirtualNicNatTable,
    source_table: SharedVirtualNicSourceTable,
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
                self.flow_table.clear();
                self.nat_table.clear();
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
        self.flow_table.clear();
        self.nat_table.clear();
        self.source_table.remove_owner(member_id);
    }

    fn close_all(&mut self) {
        let members = std::mem::take(&mut self.members);
        self.flow_table.clear();
        self.nat_table.clear();
        self.source_table.clear();

        for entry in members.into_values() {
            entry.close_notifier.notify_one();
        }
    }

    fn remember_reverse_owner(&mut self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        self.flow_table.remember_reverse_owner(member_id, packet);
    }

    fn prepare_member_packet_to_tun(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        mut packet: ZCPacket,
    ) -> ZCPacket {
        self.nat_table.translate_reply(&mut packet);
        self.remember_reverse_owner(member_id, &packet);
        packet
    }

    async fn forward_tun_packet_to_member(&mut self, packet: ZCPacket) {
        if !self.send_packet(packet).await {
            tracing::trace!("shared virtual nic dropped packet without active member");
        }
    }

    async fn send_packet(&mut self, packet: ZCPacket) -> bool {
        let source_owner = self.source_table.owner_of_source(&packet, &self.members);
        let preferred_destination_owner = source_owner.active_member();

        let flow_owner = self.flow_table.owner_of(&packet);
        let destination_owner = self.source_table.owner_of_destination(
            &packet,
            &self.members,
            preferred_destination_owner,
        );
        let mut packet = packet;
        if let Some(member_id) = flow_owner {
            let original_packet = packet.clone();
            let result = if should_translate_source_for_member(source_owner, member_id) {
                self.send_packet_to_member_with_translation(member_id, packet)
                    .await
            } else {
                self.send_packet_to_member(member_id, packet).await
            };

            match result {
                Ok(()) => return true,
                Err(_) => {
                    self.flow_table.clear();
                    self.nat_table.clear();
                    packet = original_packet;
                }
            }

            let source_owner = self.source_table.owner_of_source(&packet, &self.members);
            let preferred_destination_owner = source_owner.active_member();
            let destination_owner = self.source_table.owner_of_destination(
                &packet,
                &self.members,
                preferred_destination_owner,
            );
            return self
                .send_packet_without_flow_owner(packet, source_owner, destination_owner)
                .await;
        }

        self.send_packet_without_flow_owner(packet, source_owner, destination_owner)
            .await
    }

    async fn send_packet_without_flow_owner(
        &mut self,
        packet: ZCPacket,
        source_owner: SourceOwner,
        destination_owner: Option<SharedVirtualNicMemberId>,
    ) -> bool {
        if let Some(member_id) = destination_owner {
            if should_translate_source_for_member(source_owner, member_id) {
                return self
                    .send_packet_to_member_with_translation(member_id, packet)
                    .await
                    .is_ok();
            } else {
                return self.send_packet_to_member(member_id, packet).await.is_ok();
            }
        }

        match source_owner {
            SourceOwner::Active(member_id) => {
                return self.send_packet_to_member(member_id, packet).await.is_ok();
            }
            SourceOwner::Inactive => return false,
            SourceOwner::None => {}
        }

        false
    }

    async fn send_packet_to_member_with_translation(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        mut packet: ZCPacket,
    ) -> Result<(), ZCPacket> {
        let mut nat_entry = None;
        if let Some(key) = SharedVirtualNicFlowKey::from_packet(&packet) {
            if let Some(translated_src) = self
                .source_table
                .source_for_member_destination(member_id, key.dst)
            {
                if key.src != translated_src
                    && rewrite_packet_source(&mut packet, key.src, translated_src)
                {
                    nat_entry = Some((packet.clone(), key.src, translated_src));
                }
            }
        }

        self.send_packet_to_member(member_id, packet).await?;
        if let Some((translated_packet, original_src, translated_src)) = nat_entry {
            self.nat_table
                .remember(&translated_packet, original_src, translated_src);
        }
        Ok(())
    }

    async fn send_packet_to_member(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        packet: ZCPacket,
    ) -> Result<(), ZCPacket> {
        let Some((registration_id, sender)) = self
            .members
            .get(&member_id)
            .map(|entry| (entry.registration_id, entry.sender.clone()))
        else {
            return Err(packet);
        };

        match sender.send(packet).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.unregister(member_id, registration_id);
                Err(err.0)
            }
        }
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
) -> bool {
    !matches!(source_owner, SourceOwner::Active(source) if source == member_id)
}

fn rewrite_packet_source(
    packet: &mut ZCPacket,
    expected_source: SharedVirtualNicFlowAddr,
    new_source: SharedVirtualNicFlowAddr,
) -> bool {
    rewrite_ipv4_addr(packet, expected_source, new_source, RewriteIpv4Addr::Source)
}

fn rewrite_packet_destination(
    packet: &mut ZCPacket,
    expected_destination: SharedVirtualNicFlowAddr,
    new_destination: SharedVirtualNicFlowAddr,
) -> bool {
    rewrite_ipv4_addr(
        packet,
        expected_destination,
        new_destination,
        RewriteIpv4Addr::Destination,
    )
}

#[derive(Clone, Copy)]
enum RewriteIpv4Addr {
    Source,
    Destination,
}

fn rewrite_ipv4_addr(
    packet: &mut ZCPacket,
    expected_addr: SharedVirtualNicFlowAddr,
    new_addr: SharedVirtualNicFlowAddr,
    rewrite: RewriteIpv4Addr,
) -> bool {
    let Some(expected_addr) = expected_addr.as_ipv4() else {
        return false;
    };
    let Some(new_addr) = new_addr.as_ipv4() else {
        return false;
    };

    let payload = packet.mut_payload();
    let Some(mut ipv4_packet) = MutableIpv4Packet::new(payload) else {
        return false;
    };

    let header_len = usize::from(ipv4_packet.get_header_length()) * 4;
    if header_len < IPV4_HEADER_MIN_LEN || ipv4_packet.packet().len() < header_len {
        return false;
    }

    let old_source = ipv4_packet.get_source();
    let old_destination = ipv4_packet.get_destination();
    let is_fragmented = ipv4_packet.get_fragment_offset() != 0
        || (ipv4_packet.get_flags() & ipv4::Ipv4Flags::MoreFragments) != 0;

    match rewrite {
        RewriteIpv4Addr::Source if ipv4_packet.get_source() == expected_addr => {
            ipv4_packet.set_source(new_addr);
        }
        RewriteIpv4Addr::Destination if ipv4_packet.get_destination() == expected_addr => {
            ipv4_packet.set_destination(new_addr);
        }
        _ => return false,
    }

    if !is_fragmented {
        update_ipv4_transport_checksum(&mut ipv4_packet, header_len);
    } else if ipv4_packet.get_fragment_offset() == 0 {
        adjust_ipv4_fragment_transport_checksum(
            &mut ipv4_packet,
            header_len,
            old_source,
            old_destination,
        );
    }
    ipv4_packet.set_checksum(0);
    let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
    ipv4_packet.set_checksum(checksum);
    true
}

fn update_ipv4_transport_checksum(ipv4_packet: &mut MutableIpv4Packet<'_>, header_len: usize) {
    let source = ipv4_packet.get_source();
    let destination = ipv4_packet.get_destination();
    let protocol = ipv4_packet.get_next_level_protocol();
    let payload = ipv4_packet.packet_mut();
    let transport_payload = &mut payload[header_len..];

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(mut tcp_packet) = MutableTcpPacket::new(transport_payload) else {
                return;
            };
            tcp_packet.set_checksum(0);
            let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &source, &destination);
            tcp_packet.set_checksum(checksum);
        }
        IpNextHeaderProtocols::Udp => {
            let Some(mut udp_packet) = MutableUdpPacket::new(transport_payload) else {
                return;
            };
            if udp_packet.get_checksum() == 0 {
                return;
            }
            udp_packet.set_checksum(0);
            let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &source, &destination);
            udp_packet.set_checksum(checksum);
        }
        IpNextHeaderProtocols::Icmp => {
            let Some(mut icmp_packet) = MutableIcmpPacket::new(transport_payload) else {
                return;
            };
            icmp_packet.set_checksum(0);
            let checksum = icmp::checksum(&icmp_packet.to_immutable());
            icmp_packet.set_checksum(checksum);
        }
        _ => {}
    }
}

fn adjust_ipv4_fragment_transport_checksum(
    ipv4_packet: &mut MutableIpv4Packet<'_>,
    header_len: usize,
    old_source: std::net::Ipv4Addr,
    old_destination: std::net::Ipv4Addr,
) {
    let source = ipv4_packet.get_source();
    let destination = ipv4_packet.get_destination();
    let protocol = ipv4_packet.get_next_level_protocol();
    let payload = ipv4_packet.packet_mut();
    let transport_payload = &mut payload[header_len..];

    match protocol {
        IpNextHeaderProtocols::Tcp => {
            let Some(mut tcp_packet) = MutableTcpPacket::new(transport_payload) else {
                return;
            };
            let checksum = adjust_ipv4_pseudo_header_checksum(
                tcp_packet.get_checksum(),
                old_source,
                source,
                old_destination,
                destination,
            );
            tcp_packet.set_checksum(checksum);
        }
        IpNextHeaderProtocols::Udp => {
            let Some(mut udp_packet) = MutableUdpPacket::new(transport_payload) else {
                return;
            };
            let checksum = udp_packet.get_checksum();
            if checksum == 0 {
                return;
            }
            let checksum = adjust_ipv4_pseudo_header_checksum(
                checksum,
                old_source,
                source,
                old_destination,
                destination,
            );
            udp_packet.set_checksum(if checksum == 0 { 0xffff } else { checksum });
        }
        _ => {}
    }
}

fn adjust_ipv4_pseudo_header_checksum(
    checksum: u16,
    old_source: std::net::Ipv4Addr,
    source: std::net::Ipv4Addr,
    old_destination: std::net::Ipv4Addr,
    destination: std::net::Ipv4Addr,
) -> u16 {
    let mut checksum = checksum;
    for (old, new) in ipv4_checksum_words(old_source).zip(ipv4_checksum_words(source)) {
        checksum = adjust_checksum_word(checksum, old, new);
    }
    for (old, new) in ipv4_checksum_words(old_destination).zip(ipv4_checksum_words(destination)) {
        checksum = adjust_checksum_word(checksum, old, new);
    }
    checksum
}

fn ipv4_checksum_words(addr: std::net::Ipv4Addr) -> impl Iterator<Item = u16> {
    let octets = addr.octets();
    [
        u16::from_be_bytes([octets[0], octets[1]]),
        u16::from_be_bytes([octets[2], octets[3]]),
    ]
    .into_iter()
}

fn adjust_checksum_word(checksum: u16, old_word: u16, new_word: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old_word) + u32::from(new_word);
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[derive(Default)]
struct SharedVirtualNicSourceTable {
    member_sources: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberSources>,
    source_owners: BTreeMap<SharedVirtualNicFlowAddr, BTreeSet<SharedVirtualNicMemberId>>,
}

impl SharedVirtualNicSourceTable {
    fn update_member_sources(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        sources: SharedVirtualNicMemberSources,
    ) {
        let old_sources = self.member_sources.remove(&member_id).unwrap_or_default();

        for source in old_sources.exact.difference(&sources.exact) {
            self.remove_source_owner(*source, member_id);
        }
        for source in sources.exact.difference(&old_sources.exact) {
            self.source_owners
                .entry(*source)
                .or_default()
                .insert(member_id);
        }

        if !sources.is_empty() {
            self.member_sources.insert(member_id, sources);
        }
    }

    fn remove_owner(&mut self, member_id: SharedVirtualNicMemberId) {
        let Some(sources) = self.member_sources.remove(&member_id) else {
            return;
        };

        for source in sources.exact {
            self.remove_source_owner(source, member_id);
        }
    }

    fn clear(&mut self) {
        self.member_sources.clear();
        self.source_owners.clear();
    }

    fn owner_of_source(
        &self,
        packet: &ZCPacket,
        active_members: &BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    ) -> SourceOwner {
        let Some(source) = SharedVirtualNicFlowKey::from_packet(packet).map(|key| key.src) else {
            return SourceOwner::None;
        };
        let Some(owners) = self.source_owners.get(&source) else {
            return SourceOwner::None;
        };

        owners
            .iter()
            .find(|member_id| active_members.contains_key(member_id))
            .copied()
            .map(SourceOwner::Active)
            .unwrap_or(SourceOwner::Inactive)
    }

    fn owner_of_destination(
        &self,
        packet: &ZCPacket,
        active_members: &BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
        preferred_member: Option<SharedVirtualNicMemberId>,
    ) -> Option<SharedVirtualNicMemberId> {
        let dst = SharedVirtualNicFlowKey::from_packet(packet)?.dst;

        let mut best = None;
        for (member_id, sources) in &self.member_sources {
            if !active_members.contains_key(member_id) {
                continue;
            }
            let Some(prefix) = sources.destination_prefix(dst) else {
                continue;
            };
            if best
                .map(|(best_member, best_prefix)| {
                    prefix > best_prefix
                        || (prefix == best_prefix
                            && Some(*member_id) == preferred_member
                            && best_member != *member_id)
                })
                .unwrap_or(true)
            {
                best = Some((*member_id, prefix));
            }
        }
        best.map(|(member_id, _)| member_id)
    }

    fn source_for_member_destination(
        &self,
        member_id: SharedVirtualNicMemberId,
        dst: SharedVirtualNicFlowAddr,
    ) -> Option<SharedVirtualNicFlowAddr> {
        self.member_sources
            .get(&member_id)?
            .source_for_destination(dst)
    }

    fn remove_source_owner(
        &mut self,
        source: SharedVirtualNicFlowAddr,
        member_id: SharedVirtualNicMemberId,
    ) {
        let Some(owners) = self.source_owners.get_mut(&source) else {
            return;
        };

        owners.remove(&member_id);
        if owners.is_empty() {
            self.source_owners.remove(&source);
        }
    }
}

impl SharedVirtualNicMemberSources {
    fn destination_prefix(&self, dst: SharedVirtualNicFlowAddr) -> Option<u8> {
        match dst {
            SharedVirtualNicFlowAddr::V4(dst) => {
                let dst = std::net::Ipv4Addr::from(dst);
                self.ipv4_destination_prefix(dst)
            }
            SharedVirtualNicFlowAddr::V6(dst) => {
                let dst = std::net::Ipv6Addr::from(dst);
                self.ipv6_destination_prefix(dst)
            }
        }
    }

    fn source_for_destination(
        &self,
        dst: SharedVirtualNicFlowAddr,
    ) -> Option<SharedVirtualNicFlowAddr> {
        match dst {
            SharedVirtualNicFlowAddr::V4(dst) => {
                let dst = std::net::Ipv4Addr::from(dst);
                self.ipv4_source_for_destination(dst)
                    .map(SharedVirtualNicFlowAddr::from)
            }
            SharedVirtualNicFlowAddr::V6(dst) => {
                let dst = std::net::Ipv6Addr::from(dst);
                self.ipv6_source_for_destination(dst)
                    .map(SharedVirtualNicFlowAddr::from)
            }
        }
    }

    fn ipv4_destination_prefix(&self, dst: std::net::Ipv4Addr) -> Option<u8> {
        self.ipv4_addresses
            .iter()
            .filter(|addr| addr.contains(&dst))
            .map(|addr| addr.network_length())
            .chain(
                self.ipv4_routes
                    .iter()
                    .filter(|route| route.contains(&dst))
                    .map(|route| route.network_length()),
            )
            .max()
    }

    fn ipv6_destination_prefix(&self, dst: std::net::Ipv6Addr) -> Option<u8> {
        self.ipv6_addresses
            .iter()
            .filter(|addr| addr.contains(&dst))
            .map(|addr| addr.network_length())
            .chain(
                self.ipv6_routes
                    .iter()
                    .filter(|route| route.contains(&dst))
                    .map(|route| route.network_length()),
            )
            .max()
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

fn transport_ports(protocol: u8, payload: &[u8]) -> Option<SharedVirtualNicTransportPorts> {
    let min_len = match protocol {
        TCP_PROTOCOL => TCP_HEADER_MIN_LEN,
        UDP_PROTOCOL => UDP_HEADER_LEN,
        ICMP_PROTOCOL => ICMP_ECHO_HEADER_LEN,
        _ => return None,
    };

    if payload.len() < min_len {
        return None;
    }

    match protocol {
        ICMP_PROTOCOL => icmp_echo_flow(payload),
        _ => Some(SharedVirtualNicTransportPorts {
            src: u16::from_be_bytes([payload[0], payload[1]]),
            dst: u16::from_be_bytes([payload[2], payload[3]]),
        }),
    }
}

fn icmp_echo_flow(payload: &[u8]) -> Option<SharedVirtualNicTransportPorts> {
    match payload[0] {
        ty if ty == icmp::IcmpTypes::EchoRequest.0 || ty == icmp::IcmpTypes::EchoReply.0 => {
            Some(SharedVirtualNicTransportPorts {
                src: u16::from_be_bytes([payload[4], payload[5]]),
                dst: u16::from_be_bytes([payload[6], payload[7]]),
            })
        }
        _ => None,
    }
}

fn read_ipv6_addr(payload: &[u8], start: usize) -> [u8; 16] {
    let mut addr = [0; 16];
    addr.copy_from_slice(&payload[start..start + 16]);
    addr
}

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        time::Duration,
    };

    use super::*;
    use crate::tunnel::{TunnelError, common::TunnelWrapper, ring::create_ring_tunnel_pair};

    fn ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr) -> ZCPacket {
        let mut payload = vec![0; IPV6_HEADER_LEN];
        payload[0] = 0x60;
        payload[6] = 58;
        payload[8..24].copy_from_slice(&src.octets());
        payload[24..40].copy_from_slice(&dst.octets());
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        ipv4_udp_packet_with_ports(src, dst, 1234, 5678)
    }

    fn ipv4_icmp_echo_packet(src: Ipv4Addr, dst: Ipv4Addr) -> ZCPacket {
        ipv4_icmp_packet_with_id(src, dst, icmp::IcmpTypes::EchoRequest, 0, 0)
    }

    fn ipv4_icmp_packet_with_id(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        icmp_type: icmp::IcmpType,
        identifier: u16,
        sequence: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + 8];
        let payload_len = payload.len();
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(payload_len as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4_packet.set_source(src);
            ipv4_packet.set_destination(dst);
        }
        {
            let mut icmp_packet =
                MutableIcmpPacket::new(&mut payload[IPV4_HEADER_MIN_LEN..]).unwrap();
            icmp_packet.set_icmp_type(icmp_type);
            icmp_packet.set_icmp_code(icmp::IcmpCode(0));
            icmp_packet.packet_mut()[4..6].copy_from_slice(&identifier.to_be_bytes());
            icmp_packet.packet_mut()[6..8].copy_from_slice(&sequence.to_be_bytes());
            let checksum = icmp::checksum(&icmp_packet.to_immutable());
            icmp_packet.set_checksum(checksum);
        }
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
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
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(payload_len as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_source(src);
            ipv4_packet.set_destination(dst);
        }
        {
            let mut udp_packet =
                MutableUdpPacket::new(&mut payload[IPV4_HEADER_MIN_LEN..]).unwrap();
            udp_packet.set_source(src_port);
            udp_packet.set_destination(dst_port);
            udp_packet.set_length(UDP_HEADER_LEN as u16);
            let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
            udp_packet.set_checksum(checksum);
        }
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_non_first_fragment(src: Ipv4Addr, dst: Ipv4Addr, fragment_payload: &[u8]) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + fragment_payload.len()];
        let payload_len = payload.len();
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(payload_len as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_fragment_offset(1);
            ipv4_packet.set_source(src);
            ipv4_packet.set_destination(dst);
        }
        payload[IPV4_HEADER_MIN_LEN..].copy_from_slice(fragment_payload);
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }
        ZCPacket::new_with_payload(&payload)
    }

    fn ipv4_udp_first_fragment_with_more_fragments(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        checksum: u16,
    ) -> ZCPacket {
        let mut payload = vec![0; IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN + 4];
        let payload_len = payload.len();
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(payload_len as u16);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_flags(ipv4::Ipv4Flags::MoreFragments);
            ipv4_packet.set_source(src);
            ipv4_packet.set_destination(dst);
        }
        {
            let mut udp_packet =
                MutableUdpPacket::new(&mut payload[IPV4_HEADER_MIN_LEN..]).unwrap();
            udp_packet.set_source(1234);
            udp_packet.set_destination(5678);
            udp_packet.set_length((UDP_HEADER_LEN + 8) as u16);
            udp_packet.set_checksum(checksum);
        }
        payload[IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN..].copy_from_slice(&[1, 2, 3, 4]);
        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut payload).unwrap();
            let checksum = ipv4::checksum(&ipv4_packet.to_immutable());
            ipv4_packet.set_checksum(checksum);
        }
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
    async fn dispatcher_prefers_source_owner_for_equal_prefix_route_conflict() {
        let first = uuid::Uuid::from_u128(1);
        let source_owner = uuid::Uuid::from_u128(2);
        let first_ip = Ipv4Addr::new(10, 231, 1, 1);
        let source_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 99, 0, 2);
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(first, member_entry(first_sender));
        state.register(source_owner, member_entry(source_sender));
        state.source_table.update_member_sources(
            first,
            member_sources_with_ipv4_routes(&["10.231.1.1/24"], &["10.99.0.0/24"]),
        );
        state.source_table.update_member_sources(
            source_owner,
            member_sources_with_ipv4_routes(&["10.231.2.1/24"], &["10.99.0.0/24"]),
        );

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

        assert!(first_receiver.try_recv().is_err());
        let packet = source_receiver.try_recv().unwrap();
        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(ipv4.get_source(), source_owner_ip);
        assert_ne!(ipv4.get_source(), first_ip);
        assert_eq!(ipv4.get_destination(), remote_ip);
    }

    #[test]
    fn rewrite_ipv4_source_preserves_non_first_fragment_payload() {
        let src = Ipv4Addr::new(10, 231, 1, 1);
        let translated_src = Ipv4Addr::new(10, 231, 2, 1);
        let dst = Ipv4Addr::new(10, 231, 2, 2);
        let fragment_payload = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let mut packet = ipv4_non_first_fragment(src, dst, &fragment_payload);

        assert!(rewrite_packet_source(
            &mut packet,
            SharedVirtualNicFlowAddr::from(src),
            SharedVirtualNicFlowAddr::from(translated_src)
        ));

        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(ipv4.get_source(), translated_src);
        assert_eq!(ipv4.get_destination(), dst);
        assert_eq!(&packet.payload()[IPV4_HEADER_MIN_LEN..], &fragment_payload);
        let key = SharedVirtualNicFlowKey::from_packet(&packet).unwrap();
        assert_eq!(key.ports, None);
    }

    #[test]
    fn rewrite_ipv4_source_adjusts_first_fragment_transport_checksum() {
        let src = Ipv4Addr::new(10, 231, 1, 1);
        let translated_src = Ipv4Addr::new(10, 231, 2, 1);
        let dst = Ipv4Addr::new(10, 231, 2, 2);
        let checksum = 0x1234;
        let mut packet = ipv4_udp_first_fragment_with_more_fragments(src, dst, checksum);
        let expected_checksum =
            adjust_ipv4_pseudo_header_checksum(checksum, src, translated_src, dst, dst);

        assert!(rewrite_packet_source(
            &mut packet,
            SharedVirtualNicFlowAddr::from(src),
            SharedVirtualNicFlowAddr::from(translated_src)
        ));

        let udp =
            pnet::packet::udp::UdpPacket::new(&packet.payload()[IPV4_HEADER_MIN_LEN..]).unwrap();
        assert_eq!(udp.get_checksum(), expected_checksum);
        assert_eq!(
            &packet.payload()[IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN..],
            &[1, 2, 3, 4]
        );
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

    #[tokio::test]
    async fn dispatcher_translates_wrong_local_ipv4_source_to_destination_member() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
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

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

        assert!(source_receiver.try_recv().is_err());
        let translated = destination_receiver.try_recv().unwrap();
        let translated_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(translated.payload()).unwrap();
        assert_eq!(translated_ipv4.get_source(), destination_owner_ip);
        assert_eq!(translated_ipv4.get_destination(), remote_ip);

        let reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1234),
        );
        let reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.get_source(), remote_ip);
        assert_eq!(reply_ipv4.get_destination(), source_owner_ip);
    }

    #[tokio::test]
    async fn dispatcher_unregister_clears_nat_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
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

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

        assert!(source_receiver.try_recv().is_err());
        assert!(destination_receiver.try_recv().is_ok());

        state.unregister(destination_owner, uuid::Uuid::from_u128(1));
        let reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1234),
        );
        let reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.get_source(), remote_ip);
        assert_eq!(reply_ipv4.get_destination(), destination_owner_ip);
    }

    #[tokio::test]
    async fn dispatcher_unregister_source_owner_clears_nat_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
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

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

        assert!(source_receiver.try_recv().is_err());
        assert!(destination_receiver.try_recv().is_ok());

        state.unregister(source_owner, uuid::Uuid::from_u128(1));
        let reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1234),
        );
        let reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.get_source(), remote_ip);
        assert_eq!(reply_ipv4.get_destination(), destination_owner_ip);
    }

    #[tokio::test]
    async fn dispatcher_update_sources_clears_flow_owners_globally() {
        let stale_owner = uuid::Uuid::from_u128(2);
        let new_owner = uuid::Uuid::from_u128(1);
        let claimed_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(203, 0, 113, 1);
        let (stale_sender, mut stale_receiver) = mpsc::channel(1);
        let (new_sender, mut new_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(stale_owner, member_entry(stale_sender));
        state.register(new_owner, member_entry(new_sender));
        state
            .source_table
            .update_member_sources(stale_owner, member_sources(&["10.231.1.1/24"]));
        state.remember_reverse_owner(
            stale_owner,
            &ipv4_udp_packet_with_ports(remote_ip, claimed_ip, 5678, 1234),
        );

        let (ack, _rx) = oneshot::channel();
        state.handle_control(SharedVirtualNicControl::UpdateSources {
            member_id: new_owner,
            sources: member_sources(&["10.231.1.1/24"]),
            ack,
        });
        state
            .forward_tun_packet_to_member(ipv4_udp_packet_with_ports(
                claimed_ip, remote_ip, 1234, 5678,
            ))
            .await;

        assert!(stale_receiver.try_recv().is_err());
        assert!(new_receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn dispatcher_flow_owner_failure_retries_original_packet() {
        let stale_owner = uuid::Uuid::from_u128(1);
        let source_owner = uuid::Uuid::from_u128(2);
        let stale_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        let (stale_sender, stale_receiver) = mpsc::channel(1);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        drop(stale_receiver);
        state.register(stale_owner, member_entry(stale_sender));
        state.register(source_owner, member_entry(source_sender));
        state
            .source_table
            .update_member_sources(stale_owner, member_sources(&["10.231.2.1/24"]));
        state
            .source_table
            .update_member_sources(source_owner, member_sources(&["10.231.1.1/24"]));
        state.remember_reverse_owner(
            stale_owner,
            &ipv4_udp_packet_with_ports(remote_ip, source_owner_ip, 5678, 1234),
        );

        state
            .forward_tun_packet_to_member(ipv4_udp_packet_with_ports(
                source_owner_ip,
                remote_ip,
                1234,
                5678,
            ))
            .await;

        let packet = source_receiver.try_recv().unwrap();
        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(ipv4.get_source(), source_owner_ip);
        assert_ne!(ipv4.get_source(), stale_owner_ip);
        assert_eq!(ipv4.get_destination(), remote_ip);
    }

    #[tokio::test]
    async fn dispatcher_update_sources_clears_nat_translation() {
        let source_owner = uuid::Uuid::from_u128(1);
        let destination_owner = uuid::Uuid::from_u128(2);
        let source_owner_ip = Ipv4Addr::new(10, 231, 1, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 2, 2);
        let (source_sender, mut source_receiver) = mpsc::channel(1);
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

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(source_owner_ip, remote_ip))
            .await;

        assert!(source_receiver.try_recv().is_err());
        assert!(destination_receiver.try_recv().is_ok());

        let (ack, _rx) = oneshot::channel();
        state.handle_control(SharedVirtualNicControl::UpdateSources {
            member_id: destination_owner,
            sources: member_sources(&["10.231.3.1/24"]),
            ack,
        });
        let reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_udp_packet_with_ports(remote_ip, destination_owner_ip, 5678, 1234),
        );
        let reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.get_source(), remote_ip);
        assert_eq!(reply_ipv4.get_destination(), destination_owner_ip);
    }

    #[tokio::test]
    async fn dispatcher_translates_unknown_ipv4_source_to_route_owner() {
        let first = uuid::Uuid::from_u128(1);
        let route_owner = uuid::Uuid::from_u128(2);
        let synthetic_source = Ipv4Addr::new(100, 64, 0, 1);
        let route_owner_ip = Ipv4Addr::new(10, 231, 2, 1);
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

        state
            .forward_tun_packet_to_member(ipv4_udp_packet(synthetic_source, remote_ip))
            .await;

        assert!(first_receiver.try_recv().is_err());
        let translated = route_receiver.try_recv().unwrap();
        let translated_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(translated.payload()).unwrap();
        assert_eq!(translated_ipv4.get_source(), route_owner_ip);
        assert_eq!(translated_ipv4.get_destination(), remote_ip);
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
        let mut state = SharedVirtualNicDispatcherState::default();

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
        let translated_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(translated.payload()).unwrap();
        assert_eq!(translated_ipv4.get_source(), destination_owner_ip);
        assert_eq!(translated_ipv4.get_destination(), remote_ip);

        let reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_icmp_echo_packet(remote_ip, destination_owner_ip),
        );
        let reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(reply_ipv4.get_source(), remote_ip);
        assert_eq!(reply_ipv4.get_destination(), synthetic_source);
    }

    #[tokio::test]
    async fn dispatcher_keeps_distinct_icmp_nat_entries_by_echo_id() {
        let first_source = uuid::Uuid::from_u128(1);
        let second_source = uuid::Uuid::from_u128(2);
        let destination_owner = uuid::Uuid::from_u128(3);
        let first_source_ip = Ipv4Addr::new(10, 231, 1, 1);
        let second_source_ip = Ipv4Addr::new(10, 231, 2, 1);
        let destination_owner_ip = Ipv4Addr::new(10, 231, 3, 1);
        let remote_ip = Ipv4Addr::new(10, 231, 3, 2);
        let (first_sender, mut first_receiver) = mpsc::channel(1);
        let (second_sender, mut second_receiver) = mpsc::channel(1);
        let (destination_sender, mut destination_receiver) = mpsc::channel(2);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(first_source, member_entry(first_sender));
        state.register(second_source, member_entry(second_sender));
        state.register(destination_owner, member_entry(destination_sender));
        state
            .source_table
            .update_member_sources(first_source, member_sources(&["10.231.1.1/24"]));
        state
            .source_table
            .update_member_sources(second_source, member_sources(&["10.231.2.1/24"]));
        state
            .source_table
            .update_member_sources(destination_owner, member_sources(&["10.231.3.1/24"]));

        state
            .forward_tun_packet_to_member(ipv4_icmp_packet_with_id(
                first_source_ip,
                remote_ip,
                icmp::IcmpTypes::EchoRequest,
                100,
                1,
            ))
            .await;
        state
            .forward_tun_packet_to_member(ipv4_icmp_packet_with_id(
                second_source_ip,
                remote_ip,
                icmp::IcmpTypes::EchoRequest,
                200,
                1,
            ))
            .await;

        assert!(first_receiver.try_recv().is_err());
        assert!(second_receiver.try_recv().is_err());
        assert!(destination_receiver.try_recv().is_ok());
        assert!(destination_receiver.try_recv().is_ok());

        let first_reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_icmp_packet_with_id(
                remote_ip,
                destination_owner_ip,
                icmp::IcmpTypes::EchoReply,
                100,
                1,
            ),
        );
        let first_reply_ipv4 = pnet::packet::ipv4::Ipv4Packet::new(first_reply.payload()).unwrap();
        assert_eq!(first_reply_ipv4.get_destination(), first_source_ip);

        let second_reply = state.prepare_member_packet_to_tun(
            destination_owner,
            ipv4_icmp_packet_with_id(
                remote_ip,
                destination_owner_ip,
                icmp::IcmpTypes::EchoReply,
                200,
                1,
            ),
        );
        let second_reply_ipv4 =
            pnet::packet::ipv4::Ipv4Packet::new(second_reply.payload()).unwrap();
        assert_eq!(second_reply_ipv4.get_destination(), second_source_ip);
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
        let ipv4 = pnet::packet::ipv4::Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(ipv4.get_source(), local_ip);
        assert_eq!(ipv4.get_destination(), remote_ip);
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
        let tun_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(tun_rx);
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
        let tun_stream = tokio_stream::wrappers::UnboundedReceiverStream::new(tun_rx);
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
}

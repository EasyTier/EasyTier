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

use super::{SharedVirtualNicMemberId, SharedVirtualNicMemberRegistrationId};

const MEMBER_TUNNEL_BUFFER_SIZE: usize = 1024;
const FLOW_OWNER_LIMIT: usize = 4096;
const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_MIN_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
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
        sources: BTreeSet<SharedVirtualNicFlowAddr>,
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

            let _ = reader_control_sender.send(SharedVirtualNicControl::Unregister {
                member_id,
                registration_id,
            });
            reader_close_notifier.notify_one();
        }));

        let writer_control_sender = control_sender.clone();
        let writer_close_notifier = close_notifier.clone();
        let writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = to_member_receiver.recv().await {
                if let Err(err) = member_sink.send(packet).await {
                    tracing::error!(?member_id, ?err, "shared member tunnel write failed");
                    let _ = writer_control_sender.send(SharedVirtualNicControl::Unregister {
                        member_id,
                        registration_id,
                    });
                    writer_close_notifier.notify_one();
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
        let src = u32::from_be_bytes([payload[12], payload[13], payload[14], payload[15]]);
        let dst = u32::from_be_bytes([payload[16], payload[17], payload[18], payload[19]]);
        Some(Self {
            src: SharedVirtualNicFlowAddr::V4(src),
            dst: SharedVirtualNicFlowAddr::V4(dst),
            protocol,
            ports: transport_ports(protocol, &payload[header_len..]),
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
            ports: self.ports.map(|ports| ports.reversed()),
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

    fn remove_owner(&mut self, member_id: SharedVirtualNicMemberId) {
        self.owners.retain(|_, owner| *owner != member_id);
        self.insert_order
            .retain(|key| self.owners.contains_key(key));
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
        ipv4_addresses: &BTreeSet<Ipv4Inet>,
        ipv6_addresses: &BTreeSet<Ipv6Inet>,
    ) -> Result<(), Error> {
        let (ack, rx) = oneshot::channel();
        self.control_sender
            .send(SharedVirtualNicControl::UpdateSources {
                member_id,
                sources: sources_from_addresses(ipv4_addresses, ipv6_addresses),
                ack,
            })
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;
        rx.await
            .map_err(|_| anyhow::anyhow!("shared virtual nic dispatcher is not running").into())
    }

    pub(super) async fn remove_sources(
        &self,
        member_id: SharedVirtualNicMemberId,
    ) -> Result<(), Error> {
        let (ack, rx) = oneshot::channel();
        self.control_sender
            .send(SharedVirtualNicControl::UpdateSources {
                member_id,
                sources: BTreeSet::new(),
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
                    let Some(control) = control else {
                        break;
                    };
                    match control {
                        SharedVirtualNicControl::Shutdown { invalidate, ack } => {
                            self.cleanup(invalidate);
                            let _ = ack.send(());
                            return;
                        }
                        other => self.state.handle_control(other),
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
        self.state
            .remember_reverse_owner(member_packet.member_id, &member_packet.packet);
        if let Err(err) = self.tun_sink.send(member_packet.packet).await {
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
        self.state
            .remember_reverse_owner(member_packet.member_id, &member_packet.packet);
        let Some(tun_sink) = self.tun_sink.as_mut() else {
            tracing::trace!(
                member_id = ?member_packet.member_id,
                "shared virtual nic dropped member packet without mobile tun"
            );
            return false;
        };

        if let Err(err) = tun_sink.send(member_packet.packet).await {
            tracing::error!(?err, "shared virtual nic write to mobile tun failed");
            self.drop_tun();
            return true;
        }
        false
    }

    fn handle_control(&mut self, control: Option<SharedVirtualNicControl>) -> bool {
        let Some(control) = control else {
            self.cleanup(true);
            return false;
        };

        match control {
            SharedVirtualNicControl::Shutdown { invalidate, ack } => {
                self.cleanup(invalidate);
                let _ = ack.send(());
                false
            }
            other => {
                self.state.handle_control(other);
                true
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
        self.flow_table.remove_owner(member_id);
    }

    fn close_all(&mut self) {
        let members = std::mem::take(&mut self.members);
        self.flow_table.clear();
        self.source_table.clear();

        for entry in members.into_values() {
            entry.close_notifier.notify_one();
        }
    }

    fn remember_reverse_owner(&mut self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        self.flow_table.remember_reverse_owner(member_id, packet);
    }

    async fn forward_tun_packet_to_member(&mut self, packet: ZCPacket) {
        if !self.send_packet(packet).await {
            tracing::trace!("shared virtual nic dropped packet without active member");
        }
    }

    async fn send_packet(&mut self, packet: ZCPacket) -> bool {
        let mut packet = packet;

        if let Some(member_id) = self.flow_table.owner_of(&packet) {
            match self.send_packet_to_member(member_id, packet).await {
                Ok(()) => return true,
                Err(packet_on_failure) => {
                    packet = packet_on_failure;
                }
            }
        }

        match self.source_table.owner_of_source(&packet, &self.members) {
            SourceOwner::Active(member_id) => {
                return self.send_packet_to_member(member_id, packet).await.is_ok();
            }
            SourceOwner::Inactive => return false,
            SourceOwner::None => {}
        }

        let Some(member_id) = self.members.keys().next().copied() else {
            return false;
        };

        self.send_packet_to_member(member_id, packet).await.is_ok()
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

#[derive(Default)]
struct SharedVirtualNicSourceTable {
    member_sources: BTreeMap<SharedVirtualNicMemberId, BTreeSet<SharedVirtualNicFlowAddr>>,
    source_owners: BTreeMap<SharedVirtualNicFlowAddr, BTreeSet<SharedVirtualNicMemberId>>,
}

impl SharedVirtualNicSourceTable {
    fn update_member_sources(
        &mut self,
        member_id: SharedVirtualNicMemberId,
        sources: BTreeSet<SharedVirtualNicFlowAddr>,
    ) {
        let old_sources = self.member_sources.remove(&member_id).unwrap_or_default();

        for source in old_sources.difference(&sources) {
            self.remove_source_owner(*source, member_id);
        }
        for source in sources.difference(&old_sources) {
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

        for source in sources {
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

fn sources_from_addresses(
    ipv4_addresses: &BTreeSet<Ipv4Inet>,
    ipv6_addresses: &BTreeSet<Ipv6Inet>,
) -> BTreeSet<SharedVirtualNicFlowAddr> {
    ipv4_addresses
        .iter()
        .map(|addr| SharedVirtualNicFlowAddr::V4(u32::from_be_bytes(addr.address().octets())))
        .chain(
            ipv6_addresses
                .iter()
                .map(|addr| SharedVirtualNicFlowAddr::V6(addr.address().octets())),
        )
        .collect()
}

fn transport_ports(protocol: u8, payload: &[u8]) -> Option<SharedVirtualNicTransportPorts> {
    let min_len = match protocol {
        TCP_PROTOCOL => TCP_HEADER_MIN_LEN,
        UDP_PROTOCOL => UDP_HEADER_LEN,
        _ => return None,
    };

    if payload.len() < min_len {
        return None;
    }

    Some(SharedVirtualNicTransportPorts {
        src: u16::from_be_bytes([payload[0], payload[1]]),
        dst: u16::from_be_bytes([payload[2], payload[3]]),
    })
}

fn read_ipv6_addr(payload: &[u8], start: usize) -> [u8; 16] {
    let mut addr = [0; 16];
    addr.copy_from_slice(&payload[start..start + 16]);
    addr
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv6Addr, time::Duration};

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
        let first_addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let second_addr = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let mut table = SharedVirtualNicSourceTable::default();
        let (first_sender, _first_receiver) = mpsc::channel(1);
        let (second_sender, _second_receiver) = mpsc::channel(1);
        let mut members = BTreeMap::new();
        members.insert(first, member_entry(first_sender));
        members.insert(second, member_entry(second_sender));

        table.update_member_sources(
            first,
            BTreeSet::from([SharedVirtualNicFlowAddr::V6(first_addr.octets())]),
        );
        table.update_member_sources(
            second,
            BTreeSet::from([SharedVirtualNicFlowAddr::V6(second_addr.octets())]),
        );

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

    #[tokio::test]
    async fn dispatcher_prefers_source_owner_over_fallback_member() {
        let fallback = uuid::Uuid::from_u128(1);
        let owner = uuid::Uuid::from_u128(2);
        let source = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8:ffff::1".parse::<Ipv6Addr>().unwrap();
        let (fallback_sender, mut fallback_receiver) = mpsc::channel(1);
        let (owner_sender, mut owner_receiver) = mpsc::channel(1);
        let mut state = SharedVirtualNicDispatcherState::default();

        state.register(fallback, member_entry(fallback_sender));
        state.register(owner, member_entry(owner_sender));
        state.source_table.update_member_sources(
            owner,
            BTreeSet::from([SharedVirtualNicFlowAddr::V6(source.octets())]),
        );
        state
            .forward_tun_packet_to_member(ipv6_packet(source, dst))
            .await;

        assert!(fallback_receiver.try_recv().is_err());
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
        state.source_table.update_member_sources(
            owner,
            BTreeSet::from([SharedVirtualNicFlowAddr::V6(source.octets())]),
        );
        state.unregister(owner, uuid::Uuid::from_u128(1));
        state
            .forward_tun_packet_to_member(ipv6_packet(source, dst))
            .await;

        assert!(fallback_receiver.try_recv().is_err());
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
        dispatcher
            .update_sources(member_id, &BTreeSet::new(), &BTreeSet::new())
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
        dispatcher
            .update_sources(member_id, &BTreeSet::new(), &BTreeSet::new())
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

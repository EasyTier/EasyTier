use std::{
    collections::BTreeMap,
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, Ordering},
    },
};

use futures::{SinkExt, StreamExt};
use pnet::packet::{
    Packet as _, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket, udp::UdpPacket,
};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_util::task::AbortOnDropHandle;

use crate::{
    common::error::Error,
    tunnel::{Tunnel, ZCPacketSink, ZCPacketStream, packet_def::ZCPacket},
};

use super::SharedVirtualNicMemberId;

const MEMBER_TUNNEL_BUFFER_SIZE: usize = 1024;
const FLOW_OWNER_LIMIT: usize = 4096;

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

    fn detach_dispatcher(&self) {
        let mut state = self.state.lock().unwrap();
        state.to_tun_sender.take();
        state.control_sender.take();
    }

    pub(super) fn register(
        &self,
        member_id: SharedVirtualNicMemberId,
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

            let _ = reader_control_sender.send(SharedVirtualNicControl::Unregister { member_id });
            reader_close_notifier.notify_one();
        }));

        let writer_control_sender = control_sender.clone();
        let writer_close_notifier = close_notifier.clone();
        let writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = to_member_receiver.recv().await {
                if let Err(err) = member_sink.send(packet).await {
                    tracing::error!(?member_id, ?err, "shared member tunnel write failed");
                    let _ = writer_control_sender
                        .send(SharedVirtualNicControl::Unregister { member_id });
                    writer_close_notifier.notify_one();
                    break;
                }
            }
        }));

        let entry = SharedVirtualNicMemberTunnelEntry {
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

    pub(super) fn unregister(&self, member_id: SharedVirtualNicMemberId) {
        let Some(control_sender) = self.control_sender() else {
            return;
        };
        let _ = control_sender.send(SharedVirtualNicControl::Unregister { member_id });
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

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct SharedVirtualNicFlowKey {
    src: IpAddr,
    dst: IpAddr,
    protocol: u8,
    src_port: Option<u16>,
    dst_port: Option<u16>,
}

impl SharedVirtualNicFlowKey {
    fn from_packet(packet: &ZCPacket) -> Option<Self> {
        let payload = packet.payload();
        let version = payload.first()? >> 4;
        match version {
            4 => Self::from_ipv4_packet(Ipv4Packet::new(payload)?),
            6 => Self::from_ipv6_packet(Ipv6Packet::new(payload)?),
            _ => None,
        }
    }

    fn from_ipv4_packet(packet: Ipv4Packet<'_>) -> Option<Self> {
        let protocol = packet.get_next_level_protocol().0;
        let (src_port, dst_port) = transport_ports(protocol, packet.payload());
        Some(Self {
            src: IpAddr::V4(packet.get_source()),
            dst: IpAddr::V4(packet.get_destination()),
            protocol,
            src_port,
            dst_port,
        })
    }

    fn from_ipv6_packet(packet: Ipv6Packet<'_>) -> Option<Self> {
        let protocol = packet.get_next_header().0;
        let (src_port, dst_port) = transport_ports(protocol, packet.payload());
        Some(Self {
            src: IpAddr::V6(packet.get_source()),
            dst: IpAddr::V6(packet.get_destination()),
            protocol,
            src_port,
            dst_port,
        })
    }

    fn reversed(&self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            protocol: self.protocol,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Default)]
struct SharedVirtualNicFlowTable {
    owners: BTreeMap<SharedVirtualNicFlowKey, SharedVirtualNicMemberId>,
}

impl SharedVirtualNicFlowTable {
    fn remember_reverse_owner(&mut self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        let Some(key) = SharedVirtualNicFlowKey::from_packet(packet).map(|key| key.reversed())
        else {
            return;
        };

        if !self.owners.contains_key(&key) && self.owners.len() >= FLOW_OWNER_LIMIT {
            if let Some(oldest_key) = self.owners.keys().next().cloned() {
                self.owners.remove(&oldest_key);
            }
        }
        self.owners.insert(key, member_id);
    }

    fn owner_of(&self, packet: &ZCPacket) -> Option<SharedVirtualNicMemberId> {
        let key = SharedVirtualNicFlowKey::from_packet(packet)?;
        self.owners.get(&key).copied()
    }

    fn remove_owner(&mut self, member_id: SharedVirtualNicMemberId) {
        self.owners.retain(|_, owner| *owner != member_id);
    }
}

pub(super) struct SharedVirtualNicDispatcher {
    _task: AbortOnDropHandle<()>,
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
        member_tunnel_table.attach_dispatcher(to_tun_sender, control_sender);

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
                    self.state.handle_control(control);
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

        self.valid.store(false, Ordering::Release);
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

#[derive(Default)]
struct SharedVirtualNicDispatcherState {
    members: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    flow_table: SharedVirtualNicFlowTable,
}

impl SharedVirtualNicDispatcherState {
    fn handle_control(&mut self, control: SharedVirtualNicControl) {
        match control {
            SharedVirtualNicControl::Register { member_id, entry } => {
                self.register(member_id, entry);
            }
            SharedVirtualNicControl::Unregister { member_id } => {
                self.unregister(member_id);
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

    fn unregister(&mut self, member_id: SharedVirtualNicMemberId) {
        let entry = self.members.remove(&member_id);
        drop(entry);
        self.flow_table.remove_owner(member_id);
    }

    fn close_all(&mut self) {
        let members = std::mem::take(&mut self.members);
        self.flow_table.owners.clear();

        for entry in members.into_values() {
            entry.close_notifier.notify_one();
        }
    }

    fn remember_reverse_owner(&mut self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        self.flow_table.remember_reverse_owner(member_id, packet);
    }

    async fn forward_tun_packet_to_member(&mut self, packet: ZCPacket) {
        let member_id = self.flow_table.owner_of(&packet);
        if !self.send_packet(member_id, packet).await {
            tracing::trace!("shared virtual nic dropped packet without active member");
        }
    }

    async fn send_packet(
        &mut self,
        preferred_member_id: Option<SharedVirtualNicMemberId>,
        packet: ZCPacket,
    ) -> bool {
        let mut packet = packet;
        if let Some(member_id) = preferred_member_id {
            match self.send_packet_to_member(member_id, packet).await {
                Ok(()) => return true,
                Err(packet_on_failure) => {
                    packet = packet_on_failure;
                }
            }
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
        let Some(sender) = self
            .members
            .get(&member_id)
            .map(|entry| entry.sender.clone())
        else {
            return Err(packet);
        };

        match sender.send(packet).await {
            Ok(()) => Ok(()),
            Err(err) => {
                self.unregister(member_id);
                Err(err.0)
            }
        }
    }
}

fn transport_ports(protocol: u8, payload: &[u8]) -> (Option<u16>, Option<u16>) {
    match protocol {
        6 => TcpPacket::new(payload)
            .map(|packet| (Some(packet.get_source()), Some(packet.get_destination())))
            .unwrap_or((None, None)),
        17 => UdpPacket::new(payload)
            .map(|packet| (Some(packet.get_source()), Some(packet.get_destination())))
            .unwrap_or((None, None)),
        _ => (None, None),
    }
}

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
use tokio::sync::{Notify, mpsc};
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

#[derive(Clone, Default)]
pub(super) struct SharedVirtualNicMemberTunnelTable {
    state: Arc<StdMutex<SharedVirtualNicMemberTunnelTableState>>,
}

#[derive(Default)]
struct SharedVirtualNicMemberTunnelTableState {
    members: BTreeMap<SharedVirtualNicMemberId, SharedVirtualNicMemberTunnelEntry>,
    to_tun_sender: Option<mpsc::Sender<SharedVirtualNicMemberPacket>>,
}

struct SharedVirtualNicMemberTunnelEntry {
    sender: mpsc::Sender<ZCPacket>,
    close_notifier: Arc<Notify>,
    _tasks: Vec<AbortOnDropHandle<()>>,
}

impl SharedVirtualNicMemberTunnelTable {
    fn attach_dispatcher(&self, sender: mpsc::Sender<SharedVirtualNicMemberPacket>) {
        self.state.lock().unwrap().to_tun_sender = Some(sender);
    }

    pub(super) fn register(
        &self,
        member_id: SharedVirtualNicMemberId,
        tunnel: Box<dyn Tunnel>,
        close_notifier: Arc<Notify>,
    ) -> Result<(), Error> {
        let to_tun_sender = self
            .state
            .lock()
            .unwrap()
            .to_tun_sender
            .clone()
            .ok_or_else(|| anyhow::anyhow!("shared virtual nic dispatcher is not running"))?;

        let (mut member_stream, mut member_sink) = tunnel.split();
        let (sender, mut receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);

        let table = self.clone();
        let reader_close_notifier = close_notifier.clone();
        let reader_task = AbortOnDropHandle::new(tokio::spawn(async move {
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

            table.unregister(member_id);
            reader_close_notifier.notify_one();
        }));

        let table = self.clone();
        let writer_close_notifier = close_notifier.clone();
        let writer_task = AbortOnDropHandle::new(tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if let Err(err) = member_sink.send(packet).await {
                    tracing::error!(?member_id, ?err, "shared member tunnel write failed");
                    table.unregister(member_id);
                    writer_close_notifier.notify_one();
                    break;
                }
            }
        }));

        let entry = SharedVirtualNicMemberTunnelEntry {
            sender,
            close_notifier,
            _tasks: vec![reader_task, writer_task],
        };
        let old_entry = {
            let mut state = self.state.lock().unwrap();
            state.members.insert(member_id, entry)
        };
        drop(old_entry);
        Ok(())
    }

    pub(super) fn unregister(&self, member_id: SharedVirtualNicMemberId) {
        let entry = {
            let mut state = self.state.lock().unwrap();
            state.members.remove(&member_id)
        };
        drop(entry);
    }

    fn close_all(&self) {
        let entries = {
            let mut state = self.state.lock().unwrap();
            state.to_tun_sender.take();
            std::mem::take(&mut state.members)
        };

        for entry in entries.into_values() {
            entry.close_notifier.notify_one();
        }
    }

    async fn send_packet(
        &self,
        preferred_member_id: Option<SharedVirtualNicMemberId>,
        packet: ZCPacket,
    ) -> bool {
        let mut packet = packet;
        if let Some(member_id) = preferred_member_id {
            if let Some(sender) = self.member_sender(member_id) {
                match sender.send(packet).await {
                    Ok(()) => return true,
                    Err(err) => {
                        packet = err.0;
                        self.unregister(member_id);
                    }
                }
            }
        }

        let Some((member_id, sender)) = self.first_member_sender() else {
            return false;
        };

        match sender.send(packet).await {
            Ok(()) => true,
            Err(_) => {
                self.unregister(member_id);
                false
            }
        }
    }

    fn member_sender(&self, member_id: SharedVirtualNicMemberId) -> Option<mpsc::Sender<ZCPacket>> {
        self.state
            .lock()
            .unwrap()
            .members
            .get(&member_id)
            .map(|entry| entry.sender.clone())
    }

    fn first_member_sender(&self) -> Option<(SharedVirtualNicMemberId, mpsc::Sender<ZCPacket>)> {
        self.state
            .lock()
            .unwrap()
            .members
            .iter()
            .next()
            .map(|(member_id, entry)| (*member_id, entry.sender.clone()))
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

#[derive(Clone, Default)]
struct SharedVirtualNicFlowTable {
    owners: Arc<StdMutex<BTreeMap<SharedVirtualNicFlowKey, SharedVirtualNicMemberId>>>,
}

impl SharedVirtualNicFlowTable {
    fn remember_reverse_owner(&self, member_id: SharedVirtualNicMemberId, packet: &ZCPacket) {
        let Some(key) = SharedVirtualNicFlowKey::from_packet(packet).map(|key| key.reversed())
        else {
            return;
        };

        let mut owners = self.owners.lock().unwrap();
        if !owners.contains_key(&key) && owners.len() >= FLOW_OWNER_LIMIT {
            if let Some(oldest_key) = owners.keys().next().cloned() {
                owners.remove(&oldest_key);
            }
        }
        owners.insert(key, member_id);
    }

    fn owner_of(&self, packet: &ZCPacket) -> Option<SharedVirtualNicMemberId> {
        let key = SharedVirtualNicFlowKey::from_packet(packet)?;
        self.owners.lock().unwrap().get(&key).copied()
    }
}

pub(super) struct SharedVirtualNicDispatcher {
    _tasks: Vec<AbortOnDropHandle<()>>,
}

impl SharedVirtualNicDispatcher {
    pub(super) fn start(
        tunnel: Box<dyn Tunnel>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) -> Self {
        let (tun_stream, tun_sink) = tunnel.split();
        let (to_tun_sender, to_tun_receiver) = mpsc::channel(MEMBER_TUNNEL_BUFFER_SIZE);
        member_tunnel_table.attach_dispatcher(to_tun_sender);

        let flow_table = SharedVirtualNicFlowTable::default();
        let tasks = vec![
            AbortOnDropHandle::new(tokio::spawn(Self::forward_members_to_tun(
                to_tun_receiver,
                tun_sink,
                flow_table.clone(),
                member_tunnel_table.clone(),
                valid.clone(),
            ))),
            AbortOnDropHandle::new(tokio::spawn(Self::forward_tun_to_members(
                tun_stream,
                member_tunnel_table,
                flow_table,
                valid,
            ))),
        ];

        Self { _tasks: tasks }
    }

    async fn forward_members_to_tun(
        mut receiver: mpsc::Receiver<SharedVirtualNicMemberPacket>,
        mut tun_sink: Pin<Box<dyn ZCPacketSink>>,
        flow_table: SharedVirtualNicFlowTable,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        valid: Arc<AtomicBool>,
    ) {
        while let Some(member_packet) = receiver.recv().await {
            flow_table.remember_reverse_owner(member_packet.member_id, &member_packet.packet);
            if let Err(err) = tun_sink.send(member_packet.packet).await {
                tracing::error!(?err, "shared virtual nic write to tun failed");
                break;
            }
        }

        valid.store(false, Ordering::Release);
        member_tunnel_table.close_all();
    }

    async fn forward_tun_to_members(
        mut tun_stream: Pin<Box<dyn ZCPacketStream>>,
        member_tunnel_table: SharedVirtualNicMemberTunnelTable,
        flow_table: SharedVirtualNicFlowTable,
        valid: Arc<AtomicBool>,
    ) {
        while let Some(packet) = tun_stream.next().await {
            let packet = match packet {
                Ok(packet) => packet,
                Err(err) => {
                    tracing::error!(?err, "shared virtual nic read from tun failed");
                    break;
                }
            };
            let member_id = flow_table.owner_of(&packet);
            if !member_tunnel_table.send_packet(member_id, packet).await {
                tracing::trace!("shared virtual nic dropped packet without active member");
            }
        }

        valid.store(false, Ordering::Release);
        member_tunnel_table.close_all();
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

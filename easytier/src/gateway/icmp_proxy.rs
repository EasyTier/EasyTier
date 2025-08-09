use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{Arc, Weak},
    thread,
    time::Duration,
};

use anyhow::Context;
use pnet::packet::{
    icmp::{self, echo_reply::MutableEchoReplyPacket, IcmpCode, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    Packet,
};
use socket2::Socket;
use tokio::{
    sync::{mpsc::UnboundedSender, Mutex},
    task::JoinSet,
};

use tracing::Instrument;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, PeerId},
    gateway::ip_reassembler::ComposeIpv4PacketArgs,
    peers::{peer_manager::PeerManager, PeerPacketFilter},
    tunnel::packet_def::{PacketType, ZCPacket},
};

use super::{
    ip_reassembler::{compose_ipv4_packet, IpReassembler},
    CidrSet,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IcmpNatKey {
    real_dst_ip: std::net::IpAddr,
    icmp_id: u16,
    icmp_seq: u16,
}

#[derive(Debug)]
struct IcmpNatEntry {
    src_peer_id: PeerId,
    my_peer_id: PeerId,
    src_ip: IpAddr,
    start_time: std::time::Instant,
    mapped_dst_ip: std::net::Ipv4Addr,
}

impl IcmpNatEntry {
    fn new(
        src_peer_id: PeerId,
        my_peer_id: PeerId,
        src_ip: IpAddr,
        mapped_dst_ip: Ipv4Addr,
    ) -> Result<Self, Error> {
        Ok(Self {
            src_peer_id,
            my_peer_id,
            src_ip,
            start_time: std::time::Instant::now(),
            mapped_dst_ip,
        })
    }
}

type IcmpNatTable = Arc<dashmap::DashMap<IcmpNatKey, IcmpNatEntry>>;
type NewPacketSender = tokio::sync::mpsc::UnboundedSender<IcmpNatKey>;
type NewPacketReceiver = tokio::sync::mpsc::UnboundedReceiver<IcmpNatKey>;

#[derive(Debug)]
pub struct IcmpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<PeerManager>,

    cidr_set: CidrSet,
    socket: std::sync::Mutex<Option<Arc<socket2::Socket>>>,

    nat_table: IcmpNatTable,

    tasks: Mutex<JoinSet<()>>,

    ip_resemmbler: Arc<IpReassembler>,
    icmp_sender: Arc<std::sync::Mutex<Option<UnboundedSender<ZCPacket>>>>,
}

fn socket_recv(
    socket: &Socket,
    buf: &mut [MaybeUninit<u8>],
) -> Result<(usize, IpAddr), std::io::Error> {
    let (size, addr) = socket.recv_from(buf)?;
    let addr = match addr.as_socket() {
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(add) => add.ip(),
    };
    Ok((size, addr))
}

fn socket_recv_loop(
    socket: Arc<Socket>,
    nat_table: IcmpNatTable,
    sender: UnboundedSender<ZCPacket>,
) {
    let mut buf = [0u8; 8192];
    let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[..]) };

    loop {
        let (len, peer_ip) = match socket_recv(&socket, data) {
            Ok((len, peer_ip)) => (len, peer_ip),
            Err(e) => {
                tracing::error!("recv icmp packet failed: {:?}", e);
                if sender.is_closed() {
                    break;
                } else {
                    continue;
                }
            }
        };

        if len == 0 {
            tracing::error!("recv empty packet, len: {}", len);
            return;
        }

        if !peer_ip.is_ipv4() {
            continue;
        }

        let Some(ipv4_packet) = Ipv4Packet::new(&buf[..len]) else {
            continue;
        };

        let Some(icmp_packet) = icmp::echo_reply::EchoReplyPacket::new(ipv4_packet.payload())
        else {
            continue;
        };

        if icmp_packet.get_icmp_type() != IcmpTypes::EchoReply {
            continue;
        }

        let key = IcmpNatKey {
            real_dst_ip: peer_ip,
            icmp_id: icmp_packet.get_identifier(),
            icmp_seq: icmp_packet.get_sequence_number(),
        };

        let Some((_, v)) = nat_table.remove(&key) else {
            continue;
        };

        // send packet back to the peer where this request origin.
        let IpAddr::V4(dest_ip) = v.src_ip else {
            continue;
        };

        let payload_len = len - ipv4_packet.get_header_length() as usize * 4;
        let id = ipv4_packet.get_identification();
        let _ = compose_ipv4_packet(
            ComposeIpv4PacketArgs {
                buf: &mut buf[..],
                src_v4: &v.mapped_dst_ip,
                dst_v4: &dest_ip,
                next_protocol: IpNextHeaderProtocols::Icmp,
                payload_len,
                payload_mtu: 1200,
                ip_id: id,
            },
            |buf| {
                let mut p = ZCPacket::new_with_payload(buf);
                p.fill_peer_manager_hdr(v.my_peer_id, v.src_peer_id, PacketType::Data as u8);
                p.mut_peer_manager_header().unwrap().set_no_proxy(true);

                if let Err(e) = sender.send(p) {
                    tracing::error!("send icmp packet to peer failed: {:?}, may exiting..", e);
                }
                Ok(())
            },
        );
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for IcmpProxy {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        if self.try_handle_peer_packet(&packet).await.is_some() {
            return None;
        } else {
            return Some(packet);
        }
    }
}

impl IcmpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new(global_ctx.clone());
        let ret = Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            cidr_set,
            socket: std::sync::Mutex::new(None),

            nat_table: Arc::new(dashmap::DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),

            ip_resemmbler: Arc::new(IpReassembler::new(Duration::from_secs(10))),
            icmp_sender: Arc::new(std::sync::Mutex::new(None)),
        };

        Ok(Arc::new(ret))
    }

    fn create_raw_socket(self: &Arc<Self>) -> Result<Socket, Error> {
        let _g = self.global_ctx.net_ns.guard();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        Ok(socket)
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), Error> {
        let socket = self.create_raw_socket();
        match socket {
            Ok(socket) => {
                self.socket.lock().unwrap().replace(Arc::new(socket));
            }
            Err(e) => {
                tracing::warn!("create icmp socket failed: {:?}", e);
                if !self.global_ctx.no_tun() {
                    return Err(anyhow::anyhow!("create icmp socket failed: {:?}", e).into());
                }
            }
        }

        self.start_icmp_proxy().await?;
        self.start_nat_table_cleaner().await?;
        Ok(())
    }

    async fn start_nat_table_cleaner(self: &Arc<Self>) -> Result<(), Error> {
        let nat_table = self.nat_table.clone();
        self.tasks.lock().await.spawn(
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    nat_table.retain(|_, v| v.start_time.elapsed().as_secs() < 20);
                }
            }
            .instrument(tracing::info_span!("icmp proxy nat table cleaner")),
        );
        Ok(())
    }

    async fn start_icmp_proxy(self: &Arc<Self>) -> Result<(), Error> {
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        self.icmp_sender.lock().unwrap().replace(sender.clone());
        if let Some(socket) = self.socket.lock().unwrap().as_ref() {
            let socket = socket.clone();
            let nat_table = self.nat_table.clone();
            thread::spawn(|| {
                socket_recv_loop(socket, nat_table, sender);
            });
        }

        let peer_manager = self.peer_manager.clone();
        self.tasks.lock().await.spawn(
            async move {
                while let Some(msg) = receiver.recv().await {
                    let hdr = msg.peer_manager_header().unwrap();
                    let to_peer_id = hdr.to_peer_id.into();
                    let Some(pm) = peer_manager.upgrade() else {
                        tracing::warn!("peer manager is gone, icmp proxy send loop exit");
                        return;
                    };
                    let ret = pm.send_msg(msg, to_peer_id).await;
                    if ret.is_err() {
                        tracing::error!("send icmp packet to peer failed: {:?}", ret);
                    }
                }
            }
            .instrument(tracing::info_span!("icmp proxy send loop")),
        );

        let ip_resembler = self.ip_resemmbler.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                ip_resembler.remove_expired_packets();
            }
        });

        let Some(pm) = self.peer_manager.upgrade() else {
            tracing::warn!("peer manager is gone, icmp proxy init failed");
            return Err(anyhow::anyhow!("peer manager is gone").into());
        };

        pm.add_packet_process_pipeline(Box::new(self.clone())).await;
        Ok(())
    }

    fn send_icmp_packet(
        &self,
        dst_ip: Ipv4Addr,
        icmp_packet: &icmp::echo_request::EchoRequestPacket,
    ) -> Result<(), Error> {
        self.socket
            .lock()
            .unwrap()
            .as_ref()
            .with_context(|| "icmp socket not created")?
            .send_to(icmp_packet.packet(), &SocketAddrV4::new(dst_ip, 0).into())?;

        Ok(())
    }

    async fn send_icmp_reply_to_peer(
        &self,
        src_ip: &Ipv4Addr,
        dst_ip: &Ipv4Addr,
        src_peer_id: PeerId,
        dst_peer_id: PeerId,
        icmp_packet: &icmp::echo_request::EchoRequestPacket<'_>,
    ) {
        let mut buf = vec![0u8; icmp_packet.packet().len() + 20];
        let mut reply_packet = MutableEchoReplyPacket::new(&mut buf[20..]).unwrap();
        reply_packet.set_icmp_type(IcmpTypes::EchoReply);
        reply_packet.set_icmp_code(IcmpCode::new(0));
        reply_packet.set_identifier(icmp_packet.get_identifier());
        reply_packet.set_sequence_number(icmp_packet.get_sequence_number());
        reply_packet.set_payload(icmp_packet.payload());

        let mut icmp_packet = MutableIcmpPacket::new(&mut buf[20..]).unwrap();
        icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));

        let len = buf.len() - 20;
        let _ = compose_ipv4_packet(
            ComposeIpv4PacketArgs {
                buf: &mut buf[..],
                src_v4: src_ip,
                dst_v4: dst_ip,
                next_protocol: IpNextHeaderProtocols::Icmp,
                payload_len: len,
                payload_mtu: 1200,
                ip_id: rand::random(),
            },
            |buf| {
                let mut packet = ZCPacket::new_with_payload(buf);
                packet.fill_peer_manager_hdr(src_peer_id, dst_peer_id, PacketType::Data as u8);
                let _ = self
                    .icmp_sender
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .send(packet);
                Ok(())
            },
        );
    }

    async fn try_handle_peer_packet(&self, packet: &ZCPacket) -> Option<()> {
        if self.cidr_set.is_empty()
            && !self.global_ctx.enable_exit_node()
            && !self.global_ctx.no_tun()
        {
            return None;
        }

        let _ = self.global_ctx.get_ipv4()?;
        let hdr = packet.peer_manager_header().unwrap();
        let is_exit_node = hdr.is_exit_node();

        if hdr.packet_type != PacketType::Data as u8 || hdr.is_no_proxy() {
            return None;
        };

        let ipv4 = Ipv4Packet::new(packet.payload())?;

        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp
        {
            return None;
        }

        let mut real_dst_ip = ipv4.get_destination();

        if !(self
            .cidr_set
            .contains_v4(ipv4.get_destination(), &mut real_dst_ip)
            || is_exit_node
            || (self.global_ctx.no_tun()
                && Some(ipv4.get_destination())
                    == self
                        .global_ctx
                        .get_ipv4()
                        .as_ref()
                        .map(cidr::Ipv4Inet::address)))
        {
            return None;
        }

        let resembled_buf: Option<Vec<u8>>;
        let icmp_packet = if IpReassembler::is_packet_fragmented(&ipv4) {
            resembled_buf =
                self.ip_resemmbler
                    .add_fragment(ipv4.get_source(), ipv4.get_destination(), &ipv4);
            resembled_buf.as_ref()?;
            icmp::echo_request::EchoRequestPacket::new(resembled_buf.as_ref().unwrap())?
        } else {
            icmp::echo_request::EchoRequestPacket::new(ipv4.payload())?
        };

        if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
            // if it's other icmp type, just ignore it. may forwarding network to network replay packet.
            tracing::trace!("unsupported icmp type: {:?}", icmp_packet.get_icmp_type());
            return None;
        }

        if self.global_ctx.no_tun()
            && Some(ipv4.get_destination())
                == self
                    .global_ctx
                    .get_ipv4()
                    .as_ref()
                    .map(cidr::Ipv4Inet::address)
        {
            self.send_icmp_reply_to_peer(
                &ipv4.get_destination(),
                &ipv4.get_source(),
                hdr.to_peer_id.get(),
                hdr.from_peer_id.get(),
                &icmp_packet,
            )
            .await;
            return Some(());
        }

        let icmp_id = icmp_packet.get_identifier();
        let icmp_seq = icmp_packet.get_sequence_number();

        let key = IcmpNatKey {
            real_dst_ip: real_dst_ip.into(),
            icmp_id,
            icmp_seq,
        };

        let value = IcmpNatEntry::new(
            hdr.from_peer_id.into(),
            hdr.to_peer_id.into(),
            ipv4.get_source().into(),
            ipv4.get_destination(),
        )
        .ok()?;

        if let Some(old) = self.nat_table.insert(key, value) {
            tracing::info!("icmp nat table entry replaced: {:?}", old);
        }

        if let Err(e) = self.send_icmp_packet(real_dst_ip, &icmp_packet) {
            tracing::error!("send icmp packet failed: {:?}", e);
        }

        Some(())
    }
}

impl Drop for IcmpProxy {
    fn drop(&mut self) {
        tracing::info!(
            "dropping icmp proxy, {:?}",
            self.socket.lock().unwrap().as_ref()
        );
        if let Some(s) = self.socket.lock().unwrap().as_ref() {
            tracing::info!("shutting down icmp socket");
            let _ = s.shutdown(std::net::Shutdown::Both);
        }
    }
}

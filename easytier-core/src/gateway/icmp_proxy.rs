use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::Arc,
    thread,
};

use pnet::packet::{
    icmp::{self, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    Packet,
};
use socket2::Socket;
use tokio::{
    sync::{mpsc::UnboundedSender, Mutex},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
use tracing::Instrument;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, PeerId},
    peers::{
        packet,
        peer_manager::{PeerManager, PeerPacketFilter},
    },
};

use super::CidrSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IcmpNatKey {
    dst_ip: std::net::IpAddr,
    icmp_id: u16,
    icmp_seq: u16,
}

#[derive(Debug)]
struct IcmpNatEntry {
    src_peer_id: PeerId,
    my_peer_id: PeerId,
    src_ip: IpAddr,
    start_time: std::time::Instant,
}

impl IcmpNatEntry {
    fn new(src_peer_id: PeerId, my_peer_id: PeerId, src_ip: IpAddr) -> Result<Self, Error> {
        Ok(Self {
            src_peer_id,
            my_peer_id,
            src_ip,
            start_time: std::time::Instant::now(),
        })
    }
}

type IcmpNatTable = Arc<dashmap::DashMap<IcmpNatKey, IcmpNatEntry>>;
type NewPacketSender = tokio::sync::mpsc::UnboundedSender<IcmpNatKey>;
type NewPacketReceiver = tokio::sync::mpsc::UnboundedReceiver<IcmpNatKey>;

#[derive(Debug)]
pub struct IcmpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,

    cidr_set: CidrSet,
    socket: socket2::Socket,

    nat_table: IcmpNatTable,

    tasks: Mutex<JoinSet<()>>,
}

fn socket_recv(socket: &Socket, buf: &mut [MaybeUninit<u8>]) -> Result<(usize, IpAddr), Error> {
    let (size, addr) = socket.recv_from(buf)?;
    let addr = match addr.as_socket() {
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(add) => add.ip(),
    };
    Ok((size, addr))
}

fn socket_recv_loop(
    socket: Socket,
    nat_table: IcmpNatTable,
    sender: UnboundedSender<packet::Packet>,
) {
    let mut buf = [0u8; 4096];
    let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[12..]) };

    loop {
        let Ok((len, peer_ip)) = socket_recv(&socket, data) else {
            continue;
        };

        if !peer_ip.is_ipv4() {
            continue;
        }

        let Some(mut ipv4_packet) = MutableIpv4Packet::new(&mut buf[12..12 + len]) else {
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
            dst_ip: peer_ip,
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

        ipv4_packet.set_destination(dest_ip);
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        let peer_packet = packet::Packet::new_data_packet(
            v.my_peer_id,
            v.src_peer_id,
            &ipv4_packet.to_immutable().packet(),
        );

        if let Err(e) = sender.send(peer_packet) {
            tracing::error!("send icmp packet to peer failed: {:?}, may exiting..", e);
            break;
        }
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for IcmpProxy {
    async fn try_process_packet_from_peer(
        &self,
        packet: &packet::ArchivedPacket,
        _: &Bytes,
    ) -> Option<()> {
        let _ = self.global_ctx.get_ipv4()?;

        let packet::ArchivedPacketBody::Data(x) = &packet.body else {
            return None;
        };

        let ipv4 = Ipv4Packet::new(&x)?;

        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp
        {
            return None;
        }

        if !self.cidr_set.contains_v4(ipv4.get_destination()) {
            return None;
        }

        let icmp_packet = icmp::echo_request::EchoRequestPacket::new(&ipv4.payload())?;

        if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
            // drop it because we do not support other icmp types
            tracing::trace!("unsupported icmp type: {:?}", icmp_packet.get_icmp_type());
            return Some(());
        }

        let icmp_id = icmp_packet.get_identifier();
        let icmp_seq = icmp_packet.get_sequence_number();

        let key = IcmpNatKey {
            dst_ip: ipv4.get_destination().into(),
            icmp_id,
            icmp_seq,
        };

        let value = IcmpNatEntry::new(
            packet.from_peer.into(),
            packet.to_peer.into(),
            ipv4.get_source().into(),
        )
        .ok()?;

        if let Some(old) = self.nat_table.insert(key, value) {
            tracing::info!("icmp nat table entry replaced: {:?}", old);
        }

        if let Err(e) = self.send_icmp_packet(ipv4.get_destination(), &icmp_packet) {
            tracing::error!("send icmp packet failed: {:?}", e);
        }

        Some(())
    }
}

impl IcmpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new(global_ctx.clone());

        let _g = global_ctx.net_ns.guard();
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        )))?;

        let ret = Self {
            global_ctx,
            peer_manager,
            cidr_set,
            socket,

            nat_table: Arc::new(dashmap::DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
        };

        Ok(Arc::new(ret))
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), Error> {
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
        let socket = self.socket.try_clone()?;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
        let nat_table = self.nat_table.clone();
        thread::spawn(|| {
            socket_recv_loop(socket, nat_table, sender);
        });

        let peer_manager = self.peer_manager.clone();
        self.tasks.lock().await.spawn(
            async move {
                while let Some(msg) = receiver.recv().await {
                    let to_peer_id = msg.to_peer.into();
                    let ret = peer_manager.send_msg(msg.into(), to_peer_id).await;
                    if ret.is_err() {
                        tracing::error!("send icmp packet to peer failed: {:?}", ret);
                    }
                }
            }
            .instrument(tracing::info_span!("icmp proxy send loop")),
        );

        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.clone()))
            .await;
        Ok(())
    }

    fn send_icmp_packet(
        &self,
        dst_ip: Ipv4Addr,
        icmp_packet: &icmp::echo_request::EchoRequestPacket,
    ) -> Result<(), Error> {
        self.socket.send_to(
            icmp_packet.packet(),
            &SocketAddrV4::new(dst_ip.into(), 0).into(),
        )?;

        Ok(())
    }
}

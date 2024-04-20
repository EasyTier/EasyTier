use std::{
    net::{SocketAddr, SocketAddrV4},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use bytes::BytesMut;
use dashmap::DashMap;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket},
    Packet,
};
use tokio::{
    net::UdpSocket,
    sync::{
        mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender},
        Mutex,
    },
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use tokio_util::bytes::Bytes;
use tracing::Level;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, PeerId},
    peers::{packet, peer_manager::PeerManager, PeerPacketFilter},
    tunnel::packet_def::{PacketType, ZCPacket},
    tunnels::common::setup_sokcet2,
};

use super::CidrSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpNatKey {
    src_socket: SocketAddr,
}

#[derive(Debug)]
struct UdpNatEntry {
    src_peer_id: PeerId,
    my_peer_id: PeerId,
    src_socket: SocketAddr,
    socket: UdpSocket,
    forward_task: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
    start_time: std::time::Instant,
}

impl UdpNatEntry {
    #[tracing::instrument(err(level = Level::WARN))]
    fn new(src_peer_id: PeerId, my_peer_id: PeerId, src_socket: SocketAddr) -> Result<Self, Error> {
        // TODO: try use src port, so we will be ip restricted nat type
        let socket2_socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        let dst_socket_addr = "0.0.0.0:0".parse().unwrap();
        setup_sokcet2(&socket2_socket, &dst_socket_addr)?;
        let socket = UdpSocket::from_std(socket2_socket.into())?;

        Ok(Self {
            src_peer_id,
            my_peer_id,
            src_socket,
            socket,
            forward_task: Mutex::new(None),
            stopped: AtomicBool::new(false),
            start_time: std::time::Instant::now(),
        })
    }

    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn compose_ipv4_packet(
        self: &Arc<Self>,
        packet_sender: &mut UnboundedSender<ZCPacket>,
        buf: &mut [u8],
        src_v4: &SocketAddrV4,
        payload_len: usize,
        payload_mtu: usize,
        ip_id: u16,
    ) -> Result<(), Error> {
        let SocketAddr::V4(nat_src_v4) = self.src_socket else {
            return Err(Error::Unknown);
        };

        assert_eq!(0, payload_mtu % 8);

        // udp payload is in buf[20 + 8..]
        let mut udp_packet = MutableUdpPacket::new(&mut buf[20..28 + payload_len]).unwrap();
        udp_packet.set_source(src_v4.port());
        udp_packet.set_destination(self.src_socket.port());
        udp_packet.set_length(payload_len as u16 + 8);
        udp_packet.set_checksum(udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            src_v4.ip(),
            nat_src_v4.ip(),
        ));

        let payload_len = payload_len + 8; // include udp header
        let total_pieces = (payload_len + payload_mtu - 1) / payload_mtu;
        let mut buf_offset = 0;
        let mut fragment_offset = 0;
        let mut cur_piece = 0;
        while fragment_offset < payload_len {
            let next_fragment_offset = std::cmp::min(fragment_offset + payload_mtu, payload_len);
            let fragment_len = next_fragment_offset - fragment_offset;
            let mut ipv4_packet =
                MutableIpv4Packet::new(&mut buf[buf_offset..buf_offset + fragment_len + 20])
                    .unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length((fragment_len + 20) as u16);
            ipv4_packet.set_identification(ip_id);
            if total_pieces > 1 {
                if cur_piece != total_pieces - 1 {
                    ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
                } else {
                    ipv4_packet.set_flags(0);
                }
                assert_eq!(0, fragment_offset % 8);
                ipv4_packet.set_fragment_offset(fragment_offset as u16 / 8);
            } else {
                ipv4_packet.set_flags(Ipv4Flags::DontFragment);
                ipv4_packet.set_fragment_offset(0);
            }
            ipv4_packet.set_ecn(0);
            ipv4_packet.set_dscp(0);
            ipv4_packet.set_ttl(32);
            ipv4_packet.set_source(src_v4.ip().clone());
            ipv4_packet.set_destination(nat_src_v4.ip().clone());
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

            tracing::trace!(?ipv4_packet, "udp nat packet response send");

            let mut b = BytesMut::new();
            b.extend_from_slice(ipv4_packet.packet());
            let mut p = ZCPacket::new_with_payload(b);
            p.fill_peer_manager_hdr(self.my_peer_id, self.src_peer_id, PacketType::Data as u8);

            if let Err(e) = packet_sender.send(p) {
                tracing::error!("send icmp packet to peer failed: {:?}, may exiting..", e);
                return Err(Error::AnyhowError(e.into()));
            }

            buf_offset += next_fragment_offset - fragment_offset;
            fragment_offset = next_fragment_offset;
            cur_piece += 1;
        }
        Ok(())
    }

    async fn forward_task(self: Arc<Self>, mut packet_sender: UnboundedSender<ZCPacket>) {
        let mut buf = [0u8; 8192];
        let mut udp_body: &mut [u8] = unsafe { std::mem::transmute(&mut buf[20 + 8..]) };
        let mut ip_id = 1;

        loop {
            let (len, src_socket) = match timeout(
                Duration::from_secs(120),
                self.socket.recv_from(&mut udp_body),
            )
            .await
            {
                Ok(Ok(x)) => x,
                Ok(Err(err)) => {
                    tracing::error!(?err, "udp nat recv failed");
                    break;
                }
                Err(err) => {
                    tracing::error!(?err, "udp nat recv timeout");
                    break;
                }
            };

            tracing::trace!(?len, ?src_socket, "udp nat packet response received");

            if self.stopped.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }

            let SocketAddr::V4(src_v4) = src_socket else {
                continue;
            };

            let Ok(_) = Self::compose_ipv4_packet(
                &self,
                &mut packet_sender,
                &mut buf,
                &src_v4,
                len,
                1200,
                ip_id,
            )
            .await
            else {
                break;
            };
            ip_id = ip_id.wrapping_add(1);
        }

        self.stop();
    }
}

#[derive(Debug)]
pub struct UdpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,

    cidr_set: CidrSet,

    nat_table: Arc<DashMap<UdpNatKey, Arc<UdpNatEntry>>>,

    sender: UnboundedSender<ZCPacket>,
    receiver: Mutex<Option<UnboundedReceiver<ZCPacket>>>,

    tasks: Mutex<JoinSet<()>>,
}

impl UdpProxy {
    async fn try_handle_packet(&self, packet: &ZCPacket) -> Option<()> {
        if self.cidr_set.is_empty() {
            return None;
        }

        let _ = self.global_ctx.get_ipv4()?;
        let hdr = packet.peer_manager_header().unwrap();
        if hdr.packet_type != PacketType::Data as u8 {
            return None;
        };

        let ipv4 = Ipv4Packet::new(packet.payload())?;
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return None;
        }

        if !self.cidr_set.contains_v4(ipv4.get_destination()) {
            return None;
        }

        let udp_packet = udp::UdpPacket::new(ipv4.payload())?;

        tracing::trace!(
            ?packet,
            ?ipv4,
            ?udp_packet,
            "udp nat packet request received"
        );

        let nat_key = UdpNatKey {
            src_socket: SocketAddr::new(ipv4.get_source().into(), udp_packet.get_source()),
        };
        let nat_entry = self
            .nat_table
            .entry(nat_key)
            .or_try_insert_with::<Error>(|| {
                tracing::info!(?packet, ?ipv4, ?udp_packet, "udp nat table entry created");
                let _g = self.global_ctx.net_ns.guard();
                Ok(Arc::new(UdpNatEntry::new(
                    hdr.from_peer_id.get(),
                    hdr.to_peer_id.get(),
                    nat_key.src_socket,
                )?))
            })
            .ok()?
            .clone();

        if nat_entry.forward_task.lock().await.is_none() {
            nat_entry
                .forward_task
                .lock()
                .await
                .replace(tokio::spawn(UdpNatEntry::forward_task(
                    nat_entry.clone(),
                    self.sender.clone(),
                )));
        }

        // TODO: should it be async.
        let dst_socket =
            SocketAddr::new(ipv4.get_destination().into(), udp_packet.get_destination());
        let send_ret = {
            let _g = self.global_ctx.net_ns.guard();
            nat_entry
                .socket
                .send_to(udp_packet.payload(), dst_socket)
                .await
        };

        if let Err(send_err) = send_ret {
            tracing::error!(
                ?send_err,
                ?nat_key,
                ?nat_entry,
                ?send_err,
                "udp nat send failed"
            );
        }

        Some(())
    }
}

#[async_trait::async_trait]
impl PeerPacketFilter for UdpProxy {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        if let Some(_) = self.try_handle_packet(&packet).await {
            return None;
        } else {
            return Some(packet);
        }
    }
}

impl UdpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new(global_ctx.clone());
        let (sender, receiver) = unbounded_channel();
        let ret = Self {
            global_ctx,
            peer_manager,
            cidr_set,
            nat_table: Arc::new(DashMap::new()),
            sender,
            receiver: Mutex::new(Some(receiver)),
            tasks: Mutex::new(JoinSet::new()),
        };
        Ok(Arc::new(ret))
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), Error> {
        self.peer_manager
            .add_packet_process_pipeline(Box::new(self.clone()))
            .await;

        // clean up nat table
        let nat_table = self.nat_table.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                nat_table.retain(|_, v| {
                    if v.start_time.elapsed().as_secs() > 120 {
                        tracing::info!(?v, "udp nat table entry removed");
                        v.stop();
                        false
                    } else {
                        true
                    }
                });
            }
        });

        // forward packets to peer manager
        let mut receiver = self.receiver.lock().await.take().unwrap();
        let peer_manager = self.peer_manager.clone();
        self.tasks.lock().await.spawn(async move {
            while let Some(msg) = receiver.recv().await {
                let to_peer_id: PeerId = msg.peer_manager_header().unwrap().to_peer_id.get();
                tracing::trace!(?msg, ?to_peer_id, "udp nat packet response send");
                let ret = peer_manager.send_msg(msg, to_peer_id).await;
                if ret.is_err() {
                    tracing::error!("send icmp packet to peer failed: {:?}", ret);
                }
            }
        });
        Ok(())
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        for v in self.nat_table.iter() {
            v.stop();
        }
    }
}

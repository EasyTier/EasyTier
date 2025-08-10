use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{atomic::AtomicBool, Arc},
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use cidr::Ipv4Inet;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::{
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::{self, MutableUdpPacket},
    Packet,
};
use tachyonix::{channel, Receiver, Sender, TrySendError};
use tokio::{
    net::UdpSocket,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::timeout,
};

use tracing::Level;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, scoped_task::ScopedTask, PeerId},
    gateway::ip_reassembler::{compose_ipv4_packet, ComposeIpv4PacketArgs},
    peers::{peer_manager::PeerManager, PeerPacketFilter},
    tunnel::{
        common::{reserve_buf, setup_sokcet2},
        packet_def::{PacketType, ZCPacket},
    },
};

use super::{ip_reassembler::IpReassembler, CidrSet};

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
    last_active_time: AtomicCell<std::time::Instant>,
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
            last_active_time: AtomicCell::new(std::time::Instant::now()),
        })
    }

    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn compose_ipv4_packet(
        self: &Arc<Self>,
        packet_sender: &mut Sender<ZCPacket>,
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

        compose_ipv4_packet(
            ComposeIpv4PacketArgs {
                buf: &mut buf[..],
                src_v4: src_v4.ip(),
                dst_v4: nat_src_v4.ip(),
                next_protocol: IpNextHeaderProtocols::Udp,
                payload_len: payload_len + 8, // include udp header
                payload_mtu,
                ip_id,
            },
            |buf| {
                let mut p = ZCPacket::new_with_payload(buf);
                p.fill_peer_manager_hdr(self.my_peer_id, self.src_peer_id, PacketType::Data as u8);
                p.mut_peer_manager_header().unwrap().set_no_proxy(true);

                match packet_sender.try_send(p) {
                    Err(TrySendError::Closed(e)) => {
                        tracing::error!("send icmp packet to peer failed: {:?}, may exiting..", e);
                        Err(Error::Unknown)
                    }
                    _ => Ok(()),
                }
            },
        )?;

        Ok(())
    }

    async fn forward_task(
        self: Arc<Self>,
        mut packet_sender: Sender<ZCPacket>,
        virtual_ipv4: Ipv4Addr,
        real_ipv4: Ipv4Addr,
        mapped_ipv4: Ipv4Addr,
    ) {
        let (s, mut r) = tachyonix::channel(128);

        let self_clone = self.clone();
        let recv_task = ScopedTask::from(tokio::spawn(async move {
            let mut cur_buf = BytesMut::new();
            loop {
                if self_clone
                    .stopped
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }

                reserve_buf(&mut cur_buf, 64 * 1024 + 28, 128 * 1024 + 28);
                assert_eq!(cur_buf.len(), 0);
                unsafe {
                    cur_buf.advance_mut(28);
                }

                let (len, src_socket) = match timeout(
                    Duration::from_secs(120),
                    self_clone.socket.recv_buf_from(&mut cur_buf),
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

                let ret_buf = cur_buf.split();
                s.send((ret_buf, len, src_socket)).await.unwrap();
            }
        }));

        let self_clone = self.clone();
        let send_task = ScopedTask::from(tokio::spawn(async move {
            let mut ip_id = 1;
            while let Ok((mut packet, len, src_socket)) = r.recv().await {
                let SocketAddr::V4(mut src_v4) = src_socket else {
                    continue;
                };

                self_clone.mark_active();

                if src_v4.ip().is_loopback() {
                    src_v4.set_ip(virtual_ipv4);
                }

                if *src_v4.ip() == real_ipv4 {
                    src_v4.set_ip(mapped_ipv4);
                }

                let Ok(_) = Self::compose_ipv4_packet(
                    &self_clone,
                    &mut packet_sender,
                    &mut packet,
                    &src_v4,
                    len,
                    1280,
                    ip_id,
                )
                .await
                else {
                    break;
                };
                ip_id = ip_id.wrapping_add(1);
            }
        }));

        let _ = tokio::join!(recv_task, send_task);

        self.stop();
    }

    fn mark_active(&self) {
        self.last_active_time.store(std::time::Instant::now());
    }

    fn is_active(&self) -> bool {
        self.last_active_time.load().elapsed().as_secs() < 180
    }
}

#[derive(Debug)]
pub struct UdpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Arc<PeerManager>,

    cidr_set: CidrSet,

    nat_table: Arc<DashMap<UdpNatKey, Arc<UdpNatEntry>>>,

    sender: Sender<ZCPacket>,
    receiver: Mutex<Option<Receiver<ZCPacket>>>,

    tasks: Mutex<JoinSet<()>>,

    ip_resemmbler: Arc<IpReassembler>,
}

impl UdpProxy {
    async fn try_handle_packet(&self, packet: &ZCPacket) -> Option<()> {
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
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Udp {
            return None;
        }

        let mut real_dst_ip = ipv4.get_destination();

        if !(self
            .cidr_set
            .contains_v4(ipv4.get_destination(), &mut real_dst_ip)
            || is_exit_node
            || self.global_ctx.no_tun()
                && Some(ipv4.get_destination())
                    == self.global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address))
        {
            return None;
        }

        let resembled_buf: Option<Vec<u8>>;
        let udp_packet = if IpReassembler::is_packet_fragmented(&ipv4) {
            resembled_buf =
                self.ip_resemmbler
                    .add_fragment(ipv4.get_source(), ipv4.get_destination(), &ipv4);
            resembled_buf.as_ref()?;
            udp::UdpPacket::new(resembled_buf.as_ref().unwrap())?
        } else {
            udp::UdpPacket::new(ipv4.payload())?
        };

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
                    self.global_ctx.get_ipv4().map(|x| x.address())?,
                    real_dst_ip,
                    ipv4.get_destination(),
                )));
        }

        nat_entry.mark_active();

        // TODO: should it be async.
        let dst_socket = if Some(ipv4.get_destination())
            == self.global_ctx.get_ipv4().as_ref().map(Ipv4Inet::address)
        {
            format!("127.0.0.1:{}", udp_packet.get_destination())
                .parse()
                .unwrap()
        } else {
            SocketAddr::new(real_dst_ip.into(), udp_packet.get_destination())
        };

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
        if self.try_handle_packet(&packet).await.is_some() {
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
        let (sender, receiver) = channel(1024);
        let ret = Self {
            global_ctx,
            peer_manager,
            cidr_set,
            nat_table: Arc::new(DashMap::new()),
            sender,
            receiver: Mutex::new(Some(receiver)),
            tasks: Mutex::new(JoinSet::new()),
            ip_resemmbler: Arc::new(IpReassembler::new(Duration::from_secs(10))),
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
                    if !v.is_active() {
                        tracing::info!(?v, "udp nat table entry removed");
                        v.stop();
                        false
                    } else {
                        true
                    }
                });
            }
        });

        let ip_resembler = self.ip_resemmbler.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                ip_resembler.remove_expired_packets();
            }
        });

        // forward packets to peer manager
        let mut receiver = self.receiver.lock().await.take().unwrap();
        let peer_manager = self.peer_manager.clone();
        self.tasks.lock().await.spawn(async move {
            while let Ok(msg) = receiver.recv().await {
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

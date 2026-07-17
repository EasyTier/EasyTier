use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Weak, atomic::AtomicBool},
    time::Duration,
};

use bytes::{BufMut, BytesMut};
use cidr::Ipv4Inet;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use pnet::packet::{
    Packet,
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    udp::{self, MutableUdpPacket},
};
use quanta::Instant;
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};
use tokio::{
    net::UdpSocket,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;

use tracing::Level;

use super::{CidrSet, ip_reassembler::IpReassembler};
use crate::tunnel::common::bind;
use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx},
    gateway::ip_reassembler::{ComposeIpv4PacketArgs, compose_ipv4_packet},
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    tunnel::{
        common::reserve_buf,
        packet_def::{PacketType, ZCPacket},
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpNatKey {
    src_socket: SocketAddr,
    dst_socket: SocketAddr,
}

impl UdpNatKey {
    fn new(src_socket: SocketAddr, dst_socket: SocketAddr) -> Self {
        Self {
            src_socket,
            dst_socket,
        }
    }
}

#[derive(Debug)]
struct UdpNatEntry {
    src_peer_id: PeerId,
    my_peer_id: PeerId,
    src_socket: SocketAddr,
    socket: Option<UdpSocket>,
    forward_task: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
    start_time: Instant,
    last_active_time: AtomicCell<Instant>,
    denied: bool,
}

impl UdpNatEntry {
    #[tracing::instrument(err(level = Level::WARN))]
    fn new(
        src_peer_id: PeerId,
        my_peer_id: PeerId,
        src_socket: SocketAddr,
        denied: bool,
    ) -> Result<Self, Error> {
        // TODO: try use src port, so we will be ip restricted nat type
        let socket = (!denied)
            .then(|| bind().addr("0.0.0.0:0".parse().unwrap()).call())
            .transpose()?;

        Ok(Self {
            src_peer_id,
            my_peer_id,
            src_socket,
            socket,
            forward_task: Mutex::new(None),
            stopped: AtomicBool::new(false),
            start_time: Instant::now(),
            last_active_time: AtomicCell::new(Instant::now()),
            denied,
        })
    }

    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn compose_ipv4_packet(
        self: &Arc<Self>,
        packet_sender: &Sender<ZCPacket>,
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
        packet_sender: Sender<ZCPacket>,
        virtual_ipv4: Ipv4Addr,
        real_ipv4: Ipv4Addr,
        mapped_ipv4: Ipv4Addr,
    ) {
        let (s, mut r) = channel(128);

        let self_clone = self.clone();
        let recv_task = AbortOnDropHandle::new(tokio::spawn(async move {
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
                    self_clone
                        .socket
                        .as_ref()
                        .unwrap()
                        .recv_buf_from(&mut cur_buf),
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
        let send_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut ip_id = 1;
            while let Some((mut packet, len, src_socket)) = r.recv().await {
                let SocketAddr::V4(mut src_v4) = src_socket else {
                    continue;
                };

                self_clone.mark_active();

                let has_mapped_dst = real_ipv4 != mapped_ipv4;
                let mut reply_src_ip = *src_v4.ip();

                // Preserve the existing priority for proxy rules that expose a
                // real loopback address as a mapped address. Other loopback
                // replies come from local delivery to 127.0.0.1 for the local
                // virtual IP and may need the mapped rewrite below.
                if has_mapped_dst && reply_src_ip == real_ipv4 {
                    reply_src_ip = mapped_ipv4;
                } else if reply_src_ip.is_loopback() {
                    reply_src_ip = virtual_ipv4;
                }

                if has_mapped_dst && reply_src_ip == real_ipv4 {
                    reply_src_ip = mapped_ipv4;
                }
                src_v4.set_ip(reply_src_ip);

                let Ok(_) = Self::compose_ipv4_packet(
                    &self_clone,
                    &packet_sender,
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
        self.last_active_time.store(Instant::now());
    }

    fn is_active(&self) -> bool {
        self.last_active_time.load().elapsed().as_secs() < 180
    }
}

#[derive(Debug)]
pub struct UdpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<PeerManager>,

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

        // TODO: should it be async.
        let dst_socket = if self.global_ctx.is_ip_local_virtual_ip(&real_dst_ip.into()) {
            format!("127.0.0.1:{}", udp_packet.get_destination())
                .parse()
                .unwrap()
        } else {
            SocketAddr::new(real_dst_ip.into(), udp_packet.get_destination())
        };

        tracing::trace!(
            ?packet,
            ?ipv4,
            ?udp_packet,
            "udp nat packet request received"
        );

        let nat_key = UdpNatKey::new(
            SocketAddr::new(ipv4.get_source().into(), udp_packet.get_source()),
            SocketAddr::new(ipv4.get_destination().into(), udp_packet.get_destination()),
        );
        let nat_entry = self
            .nat_table
            .entry(nat_key)
            .or_try_insert_with::<Error>(|| {
                tracing::info!(?packet, ?ipv4, ?udp_packet, "udp nat table entry created");
                let denied = self.global_ctx.should_deny_proxy(
                    &SocketAddr::new(real_dst_ip.into(), udp_packet.get_destination()),
                    true,
                );
                let _g = self.global_ctx.net_ns.guard();
                Ok(Arc::new(UdpNatEntry::new(
                    hdr.from_peer_id.get(),
                    hdr.to_peer_id.get(),
                    nat_key.src_socket,
                    denied,
                )?))
            })
            .ok()?
            .clone();

        if nat_entry.denied {
            tracing::debug!(
                dst_port = udp_packet.get_destination(),
                "dst socket is in running listeners, ignore it"
            );
            return Some(());
        }

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

        let send_ret = {
            let _g = self.global_ctx.net_ns.guard();
            nat_entry
                .socket
                .as_ref()
                .unwrap()
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
        self.try_handle_packet(&packet)
            .await
            .is_none()
            .then_some(packet)
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
            peer_manager: Arc::downgrade(&peer_manager),
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
        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return Err(anyhow::anyhow!("peer manager is gone").into());
        };
        peer_manager
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
                nat_table.shrink_to_fit();
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
        let is_latency_first = self.global_ctx.latency_first();
        self.tasks.lock().await.spawn(async move {
            while let Some(mut msg) = receiver.recv().await {
                let hdr = msg.mut_peer_manager_header().unwrap();
                hdr.set_latency_first(is_latency_first);
                let to_peer_id = hdr.to_peer_id.into();
                tracing::trace!(?msg, ?to_peer_id, "udp nat packet response send");
                let Some(pm) = peer_manager.upgrade() else {
                    tracing::warn!("peer manager is gone, udp proxy send loop exit");
                    return;
                };
                let ret = pm.send_msg_for_proxy(msg, to_peer_id).await;
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

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    use pnet::packet::{
        MutablePacket, Packet,
        ip::IpNextHeaderProtocols,
        ipv4::{self, Ipv4Packet, MutableIpv4Packet},
        udp::{self, MutableUdpPacket, UdpPacket},
    };
    use tokio::{net::UdpSocket, sync::mpsc::Receiver, time::timeout};

    use crate::{
        common::{config::ConfigLoader, global_ctx::tests::get_mock_global_ctx},
        peers::{
            create_packet_recv_chan,
            peer_manager::{PeerManager, RouteAlgoType},
        },
        tunnel::packet_def::{PacketType, ZCPacket},
    };

    use super::UdpProxy;

    fn build_udp_proxy_packet(
        src_ip: Ipv4Addr,
        src_port: u16,
        dst_socket: SocketAddr,
        payload: &[u8],
    ) -> ZCPacket {
        let SocketAddr::V4(dst_socket) = dst_socket else {
            panic!("test only builds IPv4 UDP packets");
        };
        let dst_ip = *dst_socket.ip();
        let mut packet = vec![0; 20 + 8 + payload.len()];
        let packet_len = packet.len() as u16;

        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            ipv4_packet.set_version(4);
            ipv4_packet.set_header_length(5);
            ipv4_packet.set_total_length(packet_len);
            ipv4_packet.set_ttl(64);
            ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ipv4_packet.set_source(src_ip);
            ipv4_packet.set_destination(dst_ip);
        }

        {
            let mut udp_packet = MutableUdpPacket::new(&mut packet[20..]).unwrap();
            udp_packet.set_source(src_port);
            udp_packet.set_destination(dst_socket.port());
            udp_packet.set_length((8 + payload.len()) as u16);
            udp_packet.payload_mut().copy_from_slice(payload);
            udp_packet.set_checksum(udp::ipv4_checksum(
                &udp_packet.to_immutable(),
                &src_ip,
                &dst_ip,
            ));
        }

        {
            let mut ipv4_packet = MutableIpv4Packet::new(&mut packet).unwrap();
            ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));
        }

        let mut packet = ZCPacket::new_with_payload(&packet);
        packet.fill_peer_manager_hdr(1009867077, 3831440917, PacketType::Data as u8);
        packet
    }

    async fn wait_proxy_cidr_loaded(proxy: &UdpProxy) {
        timeout(Duration::from_secs(1), async {
            while proxy.cidr_set.is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    async fn recv_payload(socket: &UdpSocket) -> (Vec<u8>, SocketAddr) {
        let mut buf = [0; 64];
        let (len, addr) = timeout(Duration::from_secs(1), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        (buf[..len].to_vec(), addr)
    }

    async fn recv_response_packet(receiver: &mut Receiver<ZCPacket>) -> ZCPacket {
        timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn assert_udp_response(
        packet: ZCPacket,
        src_socket: SocketAddr,
        dst_ip: Ipv4Addr,
        dst_port: u16,
        payload: &[u8],
    ) {
        let SocketAddr::V4(src_socket) = src_socket else {
            panic!("test only checks IPv4 UDP packets");
        };
        let ipv4_packet = Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(ipv4_packet.get_source(), *src_socket.ip());
        assert_eq!(ipv4_packet.get_destination(), dst_ip);

        let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
        assert_eq!(udp_packet.get_source(), src_socket.port());
        assert_eq!(udp_packet.get_destination(), dst_port);
        assert_eq!(udp_packet.payload(), payload);
    }

    async fn stop_nat_entries(proxy: &UdpProxy) {
        let nat_socket_addrs = proxy
            .nat_table
            .iter()
            .filter_map(|entry| {
                entry
                    .socket
                    .as_ref()
                    .and_then(|socket| socket.local_addr().ok())
                    .map(|addr| SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())))
            })
            .collect::<Vec<_>>();

        for entry in proxy.nat_table.iter() {
            entry.stop();
        }

        let wake_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        for addr in nat_socket_addrs {
            let _ = wake_socket.send_to(b"wake", addr).await;
        }
    }

    #[tokio::test]
    async fn udp_proxy_rewrites_unmapped_loopback_reply_to_virtual_ip() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(Some("10.144.144.204/24".parse().unwrap()));
        global_ctx
            .config
            .add_proxy_cidr("127.0.0.1/32".parse().unwrap(), None)
            .unwrap();

        let (packet_sender, _packet_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            packet_sender,
        ));
        let proxy = UdpProxy::new(global_ctx, peer_manager).unwrap();
        wait_proxy_cidr_loaded(&proxy).await;
        let mut response_receiver = proxy.receiver.lock().await.take().unwrap();

        let real_dst = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let real_dst_port = real_dst.local_addr().unwrap().port();
        let dst_socket = SocketAddr::from((Ipv4Addr::LOCALHOST, real_dst_port));
        let src_ip = Ipv4Addr::new(10, 144, 144, 206);
        let src_port = 53864;

        let packet = build_udp_proxy_packet(src_ip, src_port, dst_socket, b"request");
        assert!(proxy.try_handle_packet(&packet).await.is_some());
        let (payload, nat_socket) = recv_payload(&real_dst).await;
        assert_eq!(payload, b"request");

        real_dst.send_to(b"reply", nat_socket).await.unwrap();
        assert_udp_response(
            recv_response_packet(&mut response_receiver).await,
            SocketAddr::from((Ipv4Addr::new(10, 144, 144, 204), real_dst_port)),
            src_ip,
            src_port,
            b"reply",
        );

        stop_nat_entries(&proxy).await;
    }

    #[tokio::test]
    async fn udp_proxy_maps_local_virtual_destination_reply_to_mapped_source() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(Some("10.144.144.204/24".parse().unwrap()));
        global_ctx
            .config
            .add_proxy_cidr(
                "10.144.144.204/32".parse().unwrap(),
                Some("10.10.10.3/32".parse().unwrap()),
            )
            .unwrap();

        let (packet_sender, _packet_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            packet_sender,
        ));
        let proxy = UdpProxy::new(global_ctx, peer_manager).unwrap();
        wait_proxy_cidr_loaded(&proxy).await;
        let mut response_receiver = proxy.receiver.lock().await.take().unwrap();

        let real_dst = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let real_dst_port = real_dst.local_addr().unwrap().port();
        let mapped_dst = SocketAddr::from((Ipv4Addr::new(10, 10, 10, 3), real_dst_port));
        let src_ip = Ipv4Addr::new(10, 144, 144, 206);
        let src_port = 53864;

        let packet = build_udp_proxy_packet(src_ip, src_port, mapped_dst, b"request");
        assert!(proxy.try_handle_packet(&packet).await.is_some());
        let (payload, nat_socket) = recv_payload(&real_dst).await;
        assert_eq!(payload, b"request");

        real_dst.send_to(b"reply", nat_socket).await.unwrap();
        assert_udp_response(
            recv_response_packet(&mut response_receiver).await,
            mapped_dst,
            src_ip,
            src_port,
            b"reply",
        );

        stop_nat_entries(&proxy).await;
    }

    #[tokio::test]
    async fn udp_proxy_separates_same_source_port_to_multiple_mapped_destinations() {
        let global_ctx = get_mock_global_ctx();
        global_ctx.set_ipv4(Some("10.144.144.204/24".parse().unwrap()));
        global_ctx
            .config
            .add_proxy_cidr(
                "127.0.0.1/32".parse().unwrap(),
                Some("10.10.10.1/32".parse().unwrap()),
            )
            .unwrap();
        global_ctx
            .config
            .add_proxy_cidr(
                "127.0.0.1/32".parse().unwrap(),
                Some("10.10.10.2/32".parse().unwrap()),
            )
            .unwrap();

        let (packet_sender, _packet_receiver) = create_packet_recv_chan();
        let peer_manager = Arc::new(PeerManager::new(
            RouteAlgoType::Ospf,
            global_ctx.clone(),
            packet_sender,
        ));
        let proxy = UdpProxy::new(global_ctx, peer_manager).unwrap();
        wait_proxy_cidr_loaded(&proxy).await;
        let mut response_receiver = proxy.receiver.lock().await.take().unwrap();

        let real_dst = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let real_dst_port = real_dst.local_addr().unwrap().port();
        let first_mapped_dst = SocketAddr::from((Ipv4Addr::new(10, 10, 10, 1), real_dst_port));
        let second_mapped_dst = SocketAddr::from((Ipv4Addr::new(10, 10, 10, 2), real_dst_port));
        let src_ip = Ipv4Addr::new(10, 144, 144, 206);
        let src_port = 53864;

        let first_packet = build_udp_proxy_packet(src_ip, src_port, first_mapped_dst, b"first");
        assert!(proxy.try_handle_packet(&first_packet).await.is_some());
        let (payload, first_nat_socket) = recv_payload(&real_dst).await;
        assert_eq!(payload, b"first");

        let second_packet = build_udp_proxy_packet(src_ip, src_port, second_mapped_dst, b"second");
        assert!(proxy.try_handle_packet(&second_packet).await.is_some());
        let (payload, second_nat_socket) = recv_payload(&real_dst).await;
        assert_eq!(payload, b"second");

        assert_eq!(proxy.nat_table.len(), 2);

        real_dst
            .send_to(b"first-reply", first_nat_socket)
            .await
            .unwrap();
        assert_udp_response(
            recv_response_packet(&mut response_receiver).await,
            first_mapped_dst,
            src_ip,
            src_port,
            b"first-reply",
        );

        real_dst
            .send_to(b"second-reply", second_nat_socket)
            .await
            .unwrap();
        assert_udp_response(
            recv_response_packet(&mut response_receiver).await,
            second_mapped_dst,
            src_ip,
            src_port,
            b"second-reply",
        );

        stop_nat_entries(&proxy).await;
    }
}

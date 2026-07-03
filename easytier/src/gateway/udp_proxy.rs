use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak, atomic::AtomicBool},
    time::Duration,
};

use dashmap::{DashMap, mapref::entry::Entry};
use easytier_core::proxy::udp_proxy::{
    UdpNatEntryId, UdpProxyAction, UdpProxyCore, UdpProxyPeerContext, UdpProxyRuntime,
};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::{
    net::UdpSocket,
    sync::Mutex,
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::task::AbortOnDropHandle;

use super::CidrSet;
use crate::tunnel::common::bind;
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    peers::{PeerPacketFilter, peer_manager::PeerManager},
    tunnel::packet_def::ZCPacket,
};

#[derive(Debug)]
struct RuntimeUdpNatEntry {
    socket: UdpSocket,
    forward_task: Mutex<Option<JoinHandle<()>>>,
    stopped: AtomicBool,
}

impl RuntimeUdpNatEntry {
    fn new() -> Result<Self, Error> {
        // TODO: try use src port, so we will be ip restricted nat type
        let socket = bind().addr("0.0.0.0:0".parse().unwrap()).call()?;

        Ok(Self {
            socket,
            forward_task: Mutex::new(None),
            stopped: AtomicBool::new(false),
        })
    }

    pub fn stop(&self) {
        self.stopped
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }

    async fn forward_task(
        self: Arc<Self>,
        core: Arc<UdpProxyCore>,
        entry_id: UdpNatEntryId,
        packet_sender: Sender<ZCPacket>,
    ) {
        let self_clone = self.clone();
        let recv_task = AbortOnDropHandle::new(tokio::spawn(async move {
            let mut ip_id = 1;
            loop {
                if self_clone
                    .stopped
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }

                let mut buf = vec![0; 64 * 1024];
                let (len, src_socket) = match timeout(
                    Duration::from_secs(120),
                    self_clone.socket.recv_from(&mut buf),
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

                let packets = match core.handle_socket_response(
                    entry_id,
                    src_socket,
                    &buf[..len],
                    1280,
                    ip_id,
                ) {
                    Ok(packets) => packets,
                    Err(err) => {
                        tracing::error!(?err, "compose udp response packet failed");
                        break;
                    }
                };
                ip_id = ip_id.wrapping_add(1);
                for packet in packets {
                    if let Err(err) = packet_sender.try_send(packet) {
                        tracing::error!(?err, "send udp packet to peer failed, may exiting");
                        break;
                    }
                }
            }
        }));

        let _ = recv_task.await;

        self.stop();
    }
}

#[derive(Debug)]
pub struct UdpProxy {
    global_ctx: ArcGlobalCtx,
    peer_manager: Weak<PeerManager>,

    cidr_set: CidrSet,
    core: Arc<UdpProxyCore>,
    socket_entries: Arc<DashMap<UdpNatEntryId, Arc<RuntimeUdpNatEntry>>>,

    sender: Sender<ZCPacket>,
    receiver: Mutex<Option<Receiver<ZCPacket>>>,

    tasks: Mutex<JoinSet<()>>,
}

impl UdpProxy {
    async fn try_handle_packet(&self, packet: &ZCPacket) -> Option<()> {
        let runtime = UdpProxyRuntimeView {
            global_ctx: &self.global_ctx,
        };
        let action = self.core.handle_peer_packet(
            packet,
            UdpProxyPeerContext {
                virtual_ipv4: self.global_ctx.get_ipv4().map(|inet| inet.address()),
                enable_exit_node: self.global_ctx.enable_exit_node(),
                no_tun: self.global_ctx.no_tun(),
            },
            &runtime,
        );

        let UdpProxyAction::ForwardToSocket {
            entry_id,
            dst,
            payload,
        } = action
        else {
            return matches!(action, UdpProxyAction::Drop).then_some(());
        };

        let nat_entry = match self.ensure_socket_entry(entry_id).await {
            Ok(entry) => entry,
            Err(err) => {
                tracing::error!(?err, ?entry_id, "create udp nat socket failed");
                self.core.remove_entry(entry_id);
                return None;
            }
        };
        let send_ret = {
            let _g = self.global_ctx.net_ns.guard();
            nat_entry.socket.send_to(&payload, dst).await
        };

        if let Err(send_err) = send_ret {
            tracing::error!(?send_err, "udp nat send failed");
        }

        Some(())
    }

    async fn ensure_socket_entry(
        &self,
        entry_id: UdpNatEntryId,
    ) -> Result<Arc<RuntimeUdpNatEntry>, Error> {
        let entry = match self.socket_entries.entry(entry_id) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let _g = self.global_ctx.net_ns.guard();
                let runtime_entry = Arc::new(RuntimeUdpNatEntry::new()?);
                entry.insert(runtime_entry.clone());
                runtime_entry
            }
        };

        let mut task = entry.forward_task.lock().await;
        if task.is_none() {
            task.replace(tokio::spawn(RuntimeUdpNatEntry::forward_task(
                entry.clone(),
                self.core.clone(),
                entry_id,
                self.sender.clone(),
            )));
        }
        drop(task);

        Ok(entry)
    }
}

struct UdpProxyRuntimeView<'a> {
    global_ctx: &'a ArcGlobalCtx,
}

impl UdpProxyRuntime for UdpProxyRuntimeView<'_> {
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
    }

    fn should_deny_proxy(&self, dst_socket: &SocketAddr, is_udp: bool) -> bool {
        self.global_ctx.should_deny_proxy(dst_socket, is_udp)
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
        let core = Arc::new(UdpProxyCore::new(cidr_set.table(), Duration::from_secs(10)));
        let (sender, receiver) = channel(1024);
        let ret = Self {
            global_ctx,
            peer_manager: Arc::downgrade(&peer_manager),
            cidr_set,
            core,
            socket_entries: Arc::new(DashMap::new()),
            sender,
            receiver: Mutex::new(Some(receiver)),
            tasks: Mutex::new(JoinSet::new()),
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
        let core = self.core.clone();
        let socket_entries = self.socket_entries.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(15)).await;
                for entry_id in core.remove_expired_entries() {
                    if let Some((_, entry)) = socket_entries.remove(&entry_id) {
                        entry.stop();
                    }
                }
                socket_entries.shrink_to_fit();
            }
        });

        let core = self.core.clone();
        self.tasks.lock().await.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                core.remove_expired_fragments();
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
        for v in self.socket_entries.iter() {
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
            .socket_entries
            .iter()
            .filter_map(|entry| {
                entry
                    .socket
                    .local_addr()
                    .ok()
                    .map(|addr| SocketAddr::from((Ipv4Addr::LOCALHOST, addr.port())))
            })
            .collect::<Vec<_>>();

        for entry in proxy.socket_entries.iter() {
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

        assert_eq!(proxy.core.nat_entry_count(), 2);

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

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use easytier_core::instance::ProxyService;
use easytier_core::proxy::{
    runtime::{
        ProxyRuntimeError, ProxyRuntimeInfo, ProxyRuntimeSnapshot, UdpProxyResponseSink,
        UdpProxyRuntime,
    },
    udp_proxy_engine::{UdpNatEntryId, UdpProxyEngine},
    udp_proxy_service::UdpProxyService,
};
#[cfg(test)]
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tokio::{net::UdpSocket, sync::Mutex, task::JoinHandle, time::timeout};
use tokio_util::task::AbortOnDropHandle;

use super::CidrSet;
use crate::tunnel::common::bind;
#[cfg(test)]
use crate::tunnel::packet_def::ZCPacket;
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    peers::peer_manager::PeerManager,
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
        if let Ok(local_addr) = self.socket.local_addr()
            && let Ok(wake_socket) = std::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        {
            let _ = wake_socket.send_to(&[], local_addr);
        }
    }

    async fn forward_task(
        self: Arc<Self>,
        entry_id: UdpNatEntryId,
        response_sink: std::sync::Weak<dyn UdpProxyResponseSink>,
    ) {
        let self_clone = self.clone();
        let recv_task = AbortOnDropHandle::new(tokio::spawn(async move {
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
                if self_clone
                    .stopped
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    break;
                }

                let Some(response_sink) = response_sink.upgrade() else {
                    break;
                };
                response_sink
                    .handle_socket_response(
                        entry_id,
                        src_socket,
                        Bytes::copy_from_slice(&buf[..len]),
                    )
                    .await;
            }
        }));

        let _ = recv_task.await;

        self.stop();
    }
}

#[derive(Debug)]
struct RuntimeUdpProxyAdapter {
    global_ctx: ArcGlobalCtx,
    socket_entries: Arc<DashMap<UdpNatEntryId, Arc<RuntimeUdpNatEntry>>>,
}

impl RuntimeUdpProxyAdapter {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            socket_entries: Arc::new(DashMap::new()),
        }
    }

    async fn ensure_socket_entry(
        &self,
        entry_id: UdpNatEntryId,
        response_sink: std::sync::Weak<dyn UdpProxyResponseSink>,
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
                entry_id,
                response_sink,
            )));
        }
        drop(task);

        Ok(entry)
    }

    fn close_all(&self) {
        let _g = self.global_ctx.net_ns.guard();
        for entry in self.socket_entries.iter() {
            entry.stop();
        }
        self.socket_entries.clear();
    }
}

impl ProxyRuntimeInfo for RuntimeUdpProxyAdapter {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        let local_inet = self.global_ctx.get_ipv4().as_ref().cloned();
        ProxyRuntimeSnapshot {
            local_inet,
            virtual_ipv4: local_inet.map(|inet| inet.address()),
            no_tun: self.global_ctx.no_tun(),
            enable_exit_node: self.global_ctx.enable_exit_node(),
            smoltcp_enabled: false,
            latency_first: self.global_ctx.latency_first(),
        }
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
    }
}

#[async_trait::async_trait]
impl UdpProxyRuntime for RuntimeUdpProxyAdapter {
    fn should_deny_udp_proxy(&self, dst: SocketAddr) -> bool {
        self.global_ctx.should_deny_proxy(&dst, true)
    }

    fn udp_response_ipv4_mtu(&self) -> usize {
        1280
    }

    async fn send_udp_to_socket(
        &self,
        entry_id: UdpNatEntryId,
        dst: SocketAddr,
        payload: Bytes,
        response_sink: std::sync::Weak<dyn UdpProxyResponseSink>,
    ) -> Result<(), ProxyRuntimeError> {
        let nat_entry = self
            .ensure_socket_entry(entry_id, response_sink)
            .await
            .map_err(|err| ProxyRuntimeError::Other(err.into()))?;
        let send_ret = {
            let _g = self.global_ctx.net_ns.guard();
            nat_entry.socket.send_to(&payload, dst).await
        };

        send_ret
            .map(|_| ())
            .map_err(|err| ProxyRuntimeError::Other(err.into()))
    }

    fn close_udp_socket(&self, entry_id: UdpNatEntryId) {
        if let Some((_, entry)) = self.socket_entries.remove(&entry_id) {
            let _g = self.global_ctx.net_ns.guard();
            entry.stop();
        }
        self.socket_entries.shrink_to_fit();
    }
}

pub struct UdpProxy {
    cidr_set: CidrSet,
    runtime: Arc<RuntimeUdpProxyAdapter>,
    service: Arc<UdpProxyService<RuntimeUdpProxyAdapter>>,
    #[cfg(test)]
    receiver: Mutex<Option<Receiver<ZCPacket>>>,
    #[cfg(test)]
    test_response_sink: Arc<TestUdpResponseSink>,
}

impl UdpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new_without_updater(global_ctx.clone());
        let runtime = Arc::new(RuntimeUdpProxyAdapter::new(global_ctx));
        let service = UdpProxyService::new(
            peer_manager.core(),
            runtime.clone(),
            cidr_set.table(),
            Duration::from_secs(10),
        );
        #[cfg(test)]
        let (sender, receiver) = channel(1024);
        #[cfg(test)]
        let test_response_sink = Arc::new(TestUdpResponseSink {
            engine: service.engine(),
            runtime: runtime.clone(),
            sender: sender.clone(),
        });
        Ok(Arc::new(Self {
            cidr_set,
            runtime,
            service,
            #[cfg(test)]
            receiver: Mutex::new(Some(receiver)),
            #[cfg(test)]
            test_response_sink,
        }))
    }

    pub async fn start(&self) -> Result<(), Error> {
        self.cidr_set.start_updater();
        self.service.start().await;
        Ok(())
    }

    pub fn stop(&self) {
        self.service.stop();
        self.runtime.close_all();
        self.cidr_set.stop_updater();
    }

    pub fn engine(&self) -> Arc<UdpProxyEngine> {
        self.service.engine()
    }

    #[cfg(test)]
    async fn try_handle_packet(&self, packet: &ZCPacket) -> Option<()> {
        use easytier_core::proxy::udp_proxy_engine::{UdpProxyAction, UdpProxyPeerContext};

        let snapshot = self.runtime.proxy_runtime_snapshot();
        let action = self.engine().handle_peer_packet(
            packet,
            UdpProxyPeerContext {
                virtual_ipv4: snapshot.virtual_ipv4,
                enable_exit_node: snapshot.enable_exit_node,
                no_tun: snapshot.no_tun,
            },
            self.runtime.as_ref(),
        );

        let UdpProxyAction::ForwardToSocket {
            entry_id,
            dst,
            payload,
        } = action
        else {
            return matches!(action, UdpProxyAction::Drop).then_some(());
        };

        let sink: Arc<dyn UdpProxyResponseSink> = self.test_response_sink.clone();
        if let Err(err) = self
            .runtime
            .send_udp_to_socket(entry_id, dst, payload, Arc::downgrade(&sink))
            .await
        {
            tracing::error!(?err, ?entry_id, "udp proxy runtime send failed");
            self.engine().remove_entry(entry_id);
            self.runtime.close_udp_socket(entry_id);
            return None;
        }
        Some(())
    }
}

#[cfg(test)]
struct TestUdpResponseSink {
    engine: Arc<UdpProxyEngine>,
    runtime: Arc<RuntimeUdpProxyAdapter>,
    sender: Sender<ZCPacket>,
}

#[cfg(test)]
#[async_trait::async_trait]
impl UdpProxyResponseSink for TestUdpResponseSink {
    async fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src: SocketAddr,
        payload: Bytes,
    ) {
        let packets = self
            .engine
            .handle_socket_response(
                entry_id,
                src,
                payload.as_ref(),
                self.runtime.udp_response_ipv4_mtu(),
            )
            .unwrap();
        let latency_first = self.runtime.proxy_runtime_snapshot().latency_first;
        for mut packet in packets {
            packet
                .mut_peer_manager_header()
                .expect("peer manager header")
                .set_latency_first(latency_first);
            self.sender.try_send(packet).unwrap();
        }
    }
}

impl Drop for UdpProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl ProxyService for UdpProxy {
    async fn start(&self) -> anyhow::Result<()> {
        UdpProxy::start(self).await.map_err(Into::into)
    }

    async fn stop(&self) {
        UdpProxy::stop(self);
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

    #[test]
    fn udp_proxy_construction_does_not_require_tokio_runtime() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (global_ctx, peer_manager, _packet_receiver) = {
            let _runtime_guard = runtime.enter();
            let global_ctx = get_mock_global_ctx();
            let (packet_sender, packet_receiver) = create_packet_recv_chan();
            let peer_manager = Arc::new(PeerManager::new(
                RouteAlgoType::Ospf,
                global_ctx.clone(),
                packet_sender,
            ));
            (global_ctx, peer_manager, packet_receiver)
        };

        UdpProxy::new(global_ctx, peer_manager).unwrap();
    }

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
            .runtime
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

        for entry in proxy.runtime.socket_entries.iter() {
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
        proxy.start().await.unwrap();
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
        proxy.start().await.unwrap();
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
        proxy.start().await.unwrap();
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

        assert_eq!(proxy.engine().nat_entry_count(), 2);

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

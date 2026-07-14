use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
use bytes::Bytes;
#[cfg(test)]
use easytier_core::proxy::{
    runtime::{UdpProxyResponseSink, UdpProxyRuntime},
    udp_proxy_engine::UdpNatEntryId,
};
use easytier_core::{
    instance::ProxyService,
    proxy::{
        runtime::{ProxyRuntimeInfo, ProxyRuntimeSnapshot, UdpProxyPolicy},
        udp_proxy_engine::UdpProxyEngine,
        udp_proxy_service::UdpProxyService,
        udp_socket_runtime::UdpSocketProxyRuntime,
    },
    socket::udp::UdpBindOptions,
};
#[cfg(test)]
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::mpsc::{Receiver, Sender, channel};

use super::CidrSet;
#[cfg(test)]
use crate::tunnel::packet_def::ZCPacket;
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    connector::{core_instance::runtime_socket_context, runtime::RuntimeConnectorHost},
    peers::peer_manager::PeerManager,
};

struct RuntimeUdpProxyPolicy {
    global_ctx: ArcGlobalCtx,
}

impl RuntimeUdpProxyPolicy {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

impl ProxyRuntimeInfo for RuntimeUdpProxyPolicy {
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
impl UdpProxyPolicy for RuntimeUdpProxyPolicy {
    fn should_deny_udp_proxy(&self, dst: SocketAddr) -> bool {
        self.global_ctx.should_deny_proxy(&dst, true)
    }

    fn udp_response_ipv4_mtu(&self) -> usize {
        1280
    }
}

type RuntimeUdpProxy = UdpSocketProxyRuntime<RuntimeConnectorHost, RuntimeUdpProxyPolicy>;

pub struct UdpProxy {
    cidr_set: Arc<CidrSet>,
    runtime: Arc<RuntimeUdpProxy>,
    service: Arc<UdpProxyService<RuntimeUdpProxy>>,
    #[cfg(test)]
    receiver: Mutex<Option<Receiver<ZCPacket>>>,
    #[cfg(test)]
    test_response_sink: Arc<TestUdpResponseSink>,
}

impl UdpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        cidr_set: Arc<CidrSet>,
    ) -> Result<Arc<Self>, Error> {
        let socket_context = runtime_socket_context(&global_ctx);
        let runtime = Arc::new(UdpSocketProxyRuntime::new(
            Arc::new(RuntimeConnectorHost::new(global_ctx.clone())),
            Arc::new(RuntimeUdpProxyPolicy::new(global_ctx)),
            UdpBindOptions::proxy_nat().with_context(socket_context),
            Duration::from_secs(120),
        ));
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
        self.service.start().await;
        Ok(())
    }

    pub fn stop(&self) {
        self.service.stop();
        self.runtime.close_all();
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
    runtime: Arc<RuntimeUdpProxy>,
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
    use crate::gateway::runtime_cidr_set_without_updater;

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

        let cidr_set = Arc::new(runtime_cidr_set_without_updater(global_ctx.clone()));
        UdpProxy::new(global_ctx, peer_manager, cidr_set).unwrap();
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

    fn stop_nat_entries(proxy: &UdpProxy) {
        proxy.runtime.close_all();
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
        let cidr_set = Arc::new(runtime_cidr_set_without_updater(global_ctx.clone()));
        cidr_set.start_updater();
        let proxy = UdpProxy::new(global_ctx, peer_manager, cidr_set).unwrap();
        proxy.start().await.unwrap();
        assert!(!proxy.cidr_set.is_empty());
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

        stop_nat_entries(&proxy);
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
        let cidr_set = Arc::new(runtime_cidr_set_without_updater(global_ctx.clone()));
        cidr_set.start_updater();
        let proxy = UdpProxy::new(global_ctx, peer_manager, cidr_set).unwrap();
        proxy.start().await.unwrap();
        assert!(!proxy.cidr_set.is_empty());
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

        stop_nat_entries(&proxy);
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
        let cidr_set = Arc::new(runtime_cidr_set_without_updater(global_ctx.clone()));
        cidr_set.start_updater();
        let proxy = UdpProxy::new(global_ctx, peer_manager, cidr_set).unwrap();
        proxy.start().await.unwrap();
        assert!(!proxy.cidr_set.is_empty());
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

        stop_nat_entries(&proxy);
    }
}

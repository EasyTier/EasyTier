use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use crate::{
    packet::ZCPacket,
    peers::{
        PeerPacketFilter, PeerPacketFilterResult,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
};

use super::{
    cidr_table::ProxyCidrTable,
    icmp_proxy_engine::{IcmpProxyAction, IcmpProxyContext, IcmpProxyEngine},
    traits::{IcmpProxyRuntime, IcmpProxySocket, ProxyRuntimeError},
};

pub struct IcmpProxyService<R: IcmpProxyRuntime + 'static> {
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<R>,
    engine: Arc<IcmpProxyEngine>,
    response_tx: UnboundedSender<ZCPacket>,
    response_rx: std::sync::Mutex<Option<UnboundedReceiver<ZCPacket>>>,
    pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    socket: std::sync::Mutex<Option<Arc<R::Socket>>>,
    socket_init: tokio::sync::Mutex<()>,
    stopped: CancellationToken,
    runtime_started: AtomicBool,
    started: AtomicBool,
}

impl<R: IcmpProxyRuntime + 'static> IcmpProxyService<R> {
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime: Arc<R>,
        cidr_table: Arc<ProxyCidrTable>,
        fragment_timeout: Duration,
    ) -> Arc<Self> {
        let (response_tx, response_rx) = unbounded_channel();
        Arc::new(Self {
            peer_manager,
            runtime,
            engine: Arc::new(IcmpProxyEngine::new(cidr_table, fragment_timeout)),
            response_tx,
            response_rx: std::sync::Mutex::new(Some(response_rx)),
            pipeline_guard: std::sync::Mutex::new(None),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            socket: std::sync::Mutex::new(None),
            socket_init: tokio::sync::Mutex::new(()),
            stopped: CancellationToken::new(),
            runtime_started: AtomicBool::new(false),
            started: AtomicBool::new(false),
        })
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), ProxyRuntimeError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let snapshot = self.runtime.proxy_runtime_snapshot();

        if let Some(mut response_rx) = self.response_rx.lock().unwrap().take() {
            let peer_manager = self.peer_manager.clone();
            let latency_first = snapshot.latency_first;
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(mut packet) = response_rx.recv().await {
                    let Some(header) = packet.mut_peer_manager_header() else {
                        continue;
                    };
                    header.set_latency_first(latency_first);
                    let to_peer_id = header.to_peer_id.into();
                    if let Err(err) = peer_manager.send_msg_for_proxy(packet, to_peer_id).await {
                        tracing::error!(?err, "send ICMP proxy response to peer failed");
                    }
                }
            });
        }

        let service = Arc::downgrade(self);
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(1)).await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                service.engine.remove_expired_fragments();
            }
        });

        let guard = self
            .peer_manager
            .add_managed_packet_process_pipeline(Box::new(IcmpProxyServiceFilter {
                service: Arc::downgrade(self),
            }))
            .await;
        self.pipeline_guard.lock().unwrap().replace(guard);

        let service = Arc::downgrade(self);
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                crate::foundation::time::sleep(Duration::from_secs(1)).await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                service
                    .engine
                    .remove_expired_entries(Duration::from_secs(20));
            }
        });

        Ok(())
    }

    pub fn stop(&self) {
        // Serialize shutdown with publication of a newly opened socket and its
        // receive task. Opening itself must not hold this synchronous lock.
        let mut socket = self.socket.lock().unwrap();
        if !self.started.swap(false, Ordering::AcqRel) {
            return;
        }
        self.stopped.cancel();
        if let Some(guard) = self.pipeline_guard.lock().unwrap().take() {
            guard.close();
        }
        self.tasks.lock().unwrap().abort_all();
        if self.runtime_started.swap(false, Ordering::AcqRel) {
            self.runtime.stop_icmp();
        }
        socket.take();
    }

    async fn socket(self: &Arc<Self>) -> Result<Arc<R::Socket>, ProxyRuntimeError> {
        let _init = self.socket_init.lock().await;
        if !self.started.load(Ordering::Acquire) || self.stopped.is_cancelled() {
            return Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into());
        }
        if let Some(socket) = self.socket.lock().unwrap().clone() {
            return Ok(socket);
        }

        // Roll back partial resources on errors, caller cancellation or stop.
        let rollback = guarden::guard! { self.runtime.stop_icmp(); };
        let socket = tokio::select! {
            biased;
            _ = self.stopped.cancelled() => {
                return Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into());
            }
            socket = self.runtime.start_icmp() => socket?,
        };
        let mut current = self.socket.lock().unwrap();
        if !self.started.load(Ordering::Acquire) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotConnected).into());
        }

        let service = Arc::downgrade(self);
        let receiver = socket.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let recv_result = receiver.recv().await;
                let (peer_ip, mut packet) = match recv_result {
                    Ok(packet) => packet,
                    Err(err) => {
                        tracing::error!(?err, "receive ICMP packet failed");
                        continue;
                    }
                };
                if packet.is_empty() {
                    tracing::error!("received empty ICMP packet");
                    break;
                }
                let IpAddr::V4(peer_ip) = peer_ip else {
                    continue;
                };
                let Some(service) = service.upgrade() else {
                    break;
                };
                service.handle_socket_response(peer_ip, &mut packet);
            }
        });
        *current = Some(socket.clone());
        self.runtime_started.store(true, Ordering::Release);
        rollback.defuse();
        Ok(socket)
    }

    async fn handle_peer_packet(self: Arc<Self>, packet: ZCPacket) -> Option<ZCPacket> {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        match self.engine.handle_peer_packet(
            &packet,
            IcmpProxyContext {
                virtual_ipv4: snapshot.virtual_ipv4,
                enable_exit_node: snapshot.enable_exit_node,
                no_tun: snapshot.no_tun,
            },
        ) {
            IcmpProxyAction::Pass => Some(packet),
            IcmpProxyAction::SendToSocket {
                destination,
                packet: request,
            } => {
                match self.socket().await {
                    Ok(socket) => {
                        if let Err(err) = socket.send(destination, &request).await {
                            tracing::error!(?err, "send ICMP packet through runtime failed");
                        }
                    }
                    Err(err) => tracing::error!(?err, "start ICMP runtime failed"),
                }
                None
            }
            IcmpProxyAction::SendToPeer(packets) => {
                for packet in packets {
                    if let Err(err) = self.response_tx.send(packet) {
                        tracing::error!(?err, "queue local ICMP response failed");
                    }
                }
                None
            }
        }
    }
}

impl<R: IcmpProxyRuntime + 'static> IcmpProxyService<R> {
    fn handle_socket_response(&self, peer_ip: Ipv4Addr, packet: &mut [u8]) {
        for response in self.engine.handle_socket_response(peer_ip, packet) {
            if let Err(err) = self.response_tx.send(response) {
                tracing::error!(?err, "queue ICMP socket response failed");
            }
        }
    }
}

impl<R: IcmpProxyRuntime + 'static> Drop for IcmpProxyService<R> {
    fn drop(&mut self) {
        self.stop();
    }
}

struct IcmpProxyServiceFilter<R: IcmpProxyRuntime + 'static> {
    service: Weak<IcmpProxyService<R>>,
}

#[async_trait::async_trait]
impl<R: IcmpProxyRuntime + 'static> PeerPacketFilter for IcmpProxyServiceFilter<R> {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> PeerPacketFilterResult {
        let Some(service) = self.service.upgrade() else {
            return PeerPacketFilterResult::Pass(packet);
        };
        service.handle_peer_packet(packet).await.into()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use smoltcp::wire::{Icmpv4Message, Icmpv4Packet, IpProtocol, Ipv4Packet};
    use tokio::sync::Semaphore;

    use super::*;
    use crate::{
        config::peers::PeerRuntimeSnapshot,
        gateway::proxy::{
            cidr_table::{ProxyCidrRule, ProxyCidrSnapshot},
            traits::{ProxyRuntimeInfo, ProxyRuntimeSnapshot},
        },
        packet::PacketType,
        peers::peer_manager::PortablePeerManagerConfig,
    };

    #[derive(Default)]
    struct TestSocket {
        sent: std::sync::Mutex<Vec<Ipv4Addr>>,
        receives: AtomicUsize,
    }

    #[async_trait::async_trait]
    impl IcmpProxySocket for TestSocket {
        async fn send(
            &self,
            destination: Ipv4Addr,
            _packet: &[u8],
        ) -> Result<(), ProxyRuntimeError> {
            self.sent.lock().unwrap().push(destination);
            Ok(())
        }

        async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError> {
            self.receives.fetch_add(1, Ordering::AcqRel);
            std::future::pending().await
        }
    }

    #[derive(Default)]
    struct TestRuntime {
        snapshot: ProxyRuntimeSnapshot,
        socket: Arc<TestSocket>,
        starts: AtomicUsize,
        stops: AtomicUsize,
        active: AtomicBool,
        fail: AtomicBool,
        start_gate: Option<Semaphore>,
    }

    impl ProxyRuntimeInfo for TestRuntime {
        fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
            self.snapshot
        }

        fn is_ip_local_virtual_ip(&self, _ip: &IpAddr) -> bool {
            false
        }
    }

    #[async_trait::async_trait]
    impl IcmpProxyRuntime for TestRuntime {
        type Socket = TestSocket;

        async fn start_icmp(&self) -> Result<Arc<Self::Socket>, ProxyRuntimeError> {
            self.starts.fetch_add(1, Ordering::AcqRel);
            self.active.store(true, Ordering::Release);
            if let Some(gate) = &self.start_gate {
                gate.acquire().await.unwrap().forget();
            }
            tokio::task::yield_now().await;
            if self.fail.load(Ordering::Acquire) {
                return Err(std::io::Error::other("partial start").into());
            }
            Ok(self.socket.clone())
        }

        fn stop_icmp(&self) {
            self.stops.fetch_add(1, Ordering::AcqRel);
            self.active.store(false, Ordering::Release);
        }
    }

    fn service(
        runtime: Arc<TestRuntime>,
        table: Arc<ProxyCidrTable>,
    ) -> Arc<IcmpProxyService<TestRuntime>> {
        let (packet_tx, _packet_rx) = crate::host::packet::host_packet_channel();
        let peer_manager = Arc::new(
            PeerManagerCore::new_portable_for_test(
                PortablePeerManagerConfig::new(PeerRuntimeSnapshot::default().runtime),
                packet_tx,
            )
            .unwrap(),
        );
        IcmpProxyService::new(peer_manager, runtime, table, Duration::from_secs(10))
    }

    fn runtime(no_tun: bool, enable_exit_node: bool) -> Arc<TestRuntime> {
        Arc::new(TestRuntime {
            snapshot: ProxyRuntimeSnapshot {
                virtual_ipv4: Some("10.0.0.1".parse().unwrap()),
                no_tun,
                enable_exit_node,
                ..Default::default()
            },
            ..Default::default()
        })
    }

    fn echo_request(destination: &str) -> ZCPacket {
        let mut bytes = [0_u8; 28];
        let mut request = Icmpv4Packet::new_unchecked(&mut bytes[20..]);
        request.set_msg_type(Icmpv4Message::EchoRequest);
        request.set_echo_ident(7);
        request.set_echo_seq_no(11);
        request.fill_checksum();
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut bytes[..]);
        ipv4.set_version(4);
        ipv4.set_header_len(20);
        ipv4.set_total_len(28);
        ipv4.set_hop_limit(64);
        ipv4.set_next_header(IpProtocol::Icmp);
        ipv4.set_src_addr("10.0.0.2".parse().unwrap());
        ipv4.set_dst_addr(destination.parse().unwrap());
        ipv4.fill_checksum();
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(101, 202, PacketType::Data as u8);
        packet
    }

    #[tokio::test]
    async fn no_tun_local_echo_does_not_open_socket() {
        let runtime = runtime(true, false);
        let service = service(runtime.clone(), Arc::new(ProxyCidrTable::new()));
        let mut responses = service.response_rx.lock().unwrap().take().unwrap();
        service.start().await.unwrap();
        assert!(
            service
                .clone()
                .handle_peer_packet(echo_request("10.0.0.1"))
                .await
                .is_none()
        );
        let response = responses.try_recv().unwrap();
        let ipv4 = Ipv4Packet::new_checked(response.payload()).unwrap();
        let icmp = Icmpv4Packet::new_checked(ipv4.payload()).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!(runtime.starts.load(Ordering::Acquire), 0);
        assert_eq!(runtime.socket.receives.load(Ordering::Acquire), 0);
        service.stop();
        assert_eq!(runtime.stops.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn dynamic_proxy_networks_open_once_and_follow_updated_rules() {
        let runtime = runtime(false, false);
        let table = Arc::new(ProxyCidrTable::new());
        let service = service(runtime.clone(), table.clone());
        service.start().await.unwrap();
        assert!(
            service
                .clone()
                .handle_peer_packet(echo_request("192.0.2.42"))
                .await
                .is_some()
        );
        assert_eq!(runtime.starts.load(Ordering::Acquire), 0);

        table.update_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: Some("192.0.2.0/24".parse().unwrap()),
            }],
        });
        // The first concurrent requests must share both the socket and receiver.
        futures::future::join_all((0..16).map(|_| {
            service
                .clone()
                .handle_peer_packet(echo_request("192.0.2.42"))
        }))
        .await;
        tokio::task::yield_now().await;
        assert_eq!(runtime.starts.load(Ordering::Acquire), 1);
        assert_eq!(runtime.socket.receives.load(Ordering::Acquire), 1);
        assert_eq!(
            *runtime.socket.sent.lock().unwrap(),
            vec!["127.0.0.42".parse::<Ipv4Addr>().unwrap(); 16]
        );

        table.update_snapshot(ProxyCidrSnapshot::default());
        assert!(
            service
                .clone()
                .handle_peer_packet(echo_request("192.0.2.42"))
                .await
                .is_some()
        );
        assert_eq!(runtime.socket.sent.lock().unwrap().len(), 16);
        // Keep the socket for in-flight replies and subsequent network additions.
        assert_eq!(runtime.stops.load(Ordering::Acquire), 0);
        table.update_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "192.0.2.0/24".parse().unwrap(),
                mapped_cidr: None,
            }],
        });
        assert!(
            service
                .clone()
                .handle_peer_packet(echo_request("192.0.2.42"))
                .await
                .is_none()
        );
        assert_eq!(runtime.starts.load(Ordering::Acquire), 1);
        assert_eq!(
            runtime.socket.sent.lock().unwrap().last(),
            Some(&"192.0.2.42".parse().unwrap())
        );
        service.stop();
        service.stop();
        assert_eq!(runtime.stops.load(Ordering::Acquire), 1);
        assert!(!runtime.active.load(Ordering::Acquire));
        assert!(service.socket().await.is_err());
    }

    #[tokio::test]
    async fn exit_node_opens_socket_without_proxy_networks() {
        let runtime = runtime(false, true);
        let service = service(runtime.clone(), Arc::new(ProxyCidrTable::new()));
        service.start().await.unwrap();
        assert_eq!(runtime.starts.load(Ordering::Acquire), 0);
        let mut packet = echo_request("192.0.2.42");
        packet
            .mut_peer_manager_header()
            .unwrap()
            .set_exit_node(true);
        assert!(service.clone().handle_peer_packet(packet).await.is_none());
        assert_eq!(runtime.starts.load(Ordering::Acquire), 1);
        assert_eq!(
            *runtime.socket.sent.lock().unwrap(),
            ["192.0.2.42".parse::<Ipv4Addr>().unwrap()]
        );
    }

    #[tokio::test]
    async fn failed_runtime_start_rolls_back_and_can_retry() {
        let runtime = runtime(true, false);
        runtime.fail.store(true, Ordering::Release);
        let service = service(runtime.clone(), Arc::new(ProxyCidrTable::new()));
        let mut responses = service.response_rx.lock().unwrap().take().unwrap();
        service.start().await.unwrap();
        assert!(service.socket().await.is_err());
        assert_eq!(runtime.stops.load(Ordering::Acquire), 1);
        assert!(!runtime.active.load(Ordering::Acquire));
        assert!(
            service
                .clone()
                .handle_peer_packet(echo_request("10.0.0.1"))
                .await
                .is_none()
        );
        assert!(responses.try_recv().is_ok());
        assert_eq!(runtime.starts.load(Ordering::Acquire), 1);
        runtime.fail.store(false, Ordering::Release);
        assert!(service.socket().await.is_ok());
        service.stop();
        assert_eq!(runtime.stops.load(Ordering::Acquire), 2);
    }

    #[tokio::test]
    async fn stop_cancels_pending_socket_start() {
        let runtime = Arc::new(TestRuntime {
            start_gate: Some(Semaphore::new(0)),
            ..Default::default()
        });
        let service = service(runtime.clone(), Arc::new(ProxyCidrTable::new()));
        service.start().await.unwrap();
        let mut opening = Box::pin(service.socket());
        assert!(futures::poll!(&mut opening).is_pending());
        assert!(runtime.active.load(Ordering::Acquire));
        service.stop();
        assert!(opening.await.is_err());
        assert!(!runtime.active.load(Ordering::Acquire));
        assert_eq!(runtime.stops.load(Ordering::Acquire), 1);
        assert_eq!(runtime.socket.receives.load(Ordering::Acquire), 0);
        assert!(service.socket().await.is_err());
        assert_eq!(runtime.starts.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn cancelled_caller_rolls_back_socket_start() {
        let runtime = Arc::new(TestRuntime {
            start_gate: Some(Semaphore::new(0)),
            ..Default::default()
        });
        let service = service(runtime.clone(), Arc::new(ProxyCidrTable::new()));
        service.start().await.unwrap();
        let mut opening = Box::pin(service.socket());
        assert!(futures::poll!(&mut opening).is_pending());
        drop(opening);
        assert!(!runtime.active.load(Ordering::Acquire));
        assert_eq!(runtime.stops.load(Ordering::Acquire), 1);
        runtime.start_gate.as_ref().unwrap().add_permits(1);
        assert!(service.socket().await.is_ok());
        service.stop();
        assert_eq!(runtime.stops.load(Ordering::Acquire), 2);
    }
}

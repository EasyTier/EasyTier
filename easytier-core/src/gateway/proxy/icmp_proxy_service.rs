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

use crate::{
    packet::ZCPacket,
    peers::{
        PeerPacketFilter,
        peer_manager::{PeerManagerCore, PipelineRegistrationGuard},
    },
};

use super::{
    cidr_table::ProxyCidrTable,
    icmp_proxy_engine::{IcmpProxyAction, IcmpProxyContext, IcmpProxyEngine},
    traits::{IcmpProxyRuntime, IcmpProxySocket, ProxyRuntimeError},
};

async fn start_icmp_runtime<R: IcmpProxyRuntime + 'static>(
    runtime: &R,
    no_tun: bool,
) -> Result<Option<Arc<R::Socket>>, ProxyRuntimeError> {
    match runtime.start_icmp().await {
        Ok(socket) => Ok(Some(socket)),
        Err(err) => {
            runtime.stop_icmp();
            if !no_tun {
                return Err(err);
            }
            tracing::warn!(?err, "start ICMP runtime failed without TUN");
            Ok(None)
        }
    }
}

pub struct IcmpProxyService<R: IcmpProxyRuntime + 'static> {
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<R>,
    engine: Arc<IcmpProxyEngine>,
    response_tx: UnboundedSender<ZCPacket>,
    response_rx: std::sync::Mutex<Option<UnboundedReceiver<ZCPacket>>>,
    pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    socket: std::sync::Mutex<Option<Arc<R::Socket>>>,
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
            runtime_started: AtomicBool::new(false),
            started: AtomicBool::new(false),
        })
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), ProxyRuntimeError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let snapshot = self.runtime.proxy_runtime_snapshot();
        let socket = match start_icmp_runtime(self.runtime.as_ref(), snapshot.no_tun).await {
            Ok(socket) => socket,
            Err(err) => {
                self.started.store(false, Ordering::Release);
                return Err(err);
            }
        };
        let runtime_started = socket.is_some();
        self.runtime_started
            .store(runtime_started, Ordering::Release);
        self.socket.lock().unwrap().clone_from(&socket);

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

        if let Some(socket) = socket {
            let service = Arc::downgrade(self);
            self.tasks.lock().unwrap().spawn(async move {
                loop {
                    let recv_result = socket.recv().await;
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
        if !self.started.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Some(guard) = self.pipeline_guard.lock().unwrap().take() {
            guard.close();
        }
        self.tasks.lock().unwrap().abort_all();
        if self.runtime_started.swap(false, Ordering::AcqRel) {
            self.runtime.stop_icmp();
        }
        self.socket.lock().unwrap().take();
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
                let socket = self.socket.lock().unwrap().clone();
                match socket {
                    Some(socket) => {
                        if let Err(err) = socket.send(destination, &request).await {
                            tracing::error!(?err, "send ICMP packet through runtime failed");
                        }
                    }
                    None => tracing::error!("send ICMP packet without a runtime socket"),
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
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(service) = self.service.upgrade() else {
            return Some(packet);
        };
        service.handle_peer_packet(packet).await
    }
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr},
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::*;
    use crate::gateway::proxy::traits::{IcmpProxySocket, ProxyRuntimeInfo, ProxyRuntimeSnapshot};

    #[derive(Default)]
    struct PartialStartRuntime {
        stop_count: AtomicUsize,
    }

    impl ProxyRuntimeInfo for PartialStartRuntime {
        fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
            ProxyRuntimeSnapshot::default()
        }

        fn is_ip_local_virtual_ip(&self, _ip: &IpAddr) -> bool {
            false
        }
    }

    struct NoopIcmpSocket;

    #[async_trait::async_trait]
    impl IcmpProxySocket for NoopIcmpSocket {
        async fn send(
            &self,
            _destination: Ipv4Addr,
            _packet: &[u8],
        ) -> Result<(), ProxyRuntimeError> {
            Ok(())
        }

        async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError> {
            Err(std::io::Error::other("unused test socket").into())
        }
    }

    #[async_trait::async_trait]
    impl IcmpProxyRuntime for PartialStartRuntime {
        type Socket = NoopIcmpSocket;

        async fn start_icmp(&self) -> Result<Arc<Self::Socket>, ProxyRuntimeError> {
            Err(std::io::Error::other("partial start").into())
        }

        fn stop_icmp(&self) {
            self.stop_count.fetch_add(1, Ordering::AcqRel);
        }
    }

    #[tokio::test]
    async fn failed_runtime_start_rolls_back_partial_resources() {
        let runtime = PartialStartRuntime::default();

        assert!(start_icmp_runtime(&runtime, false).await.is_err());
        assert_eq!(runtime.stop_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn no_tun_suppresses_start_error_after_rollback() {
        let runtime = PartialStartRuntime::default();

        let socket = start_icmp_runtime(&runtime, true).await.unwrap();
        assert!(socket.is_none());
        if socket.is_some() {
            runtime.stop_icmp();
        }
        assert_eq!(runtime.stop_count.load(Ordering::Acquire), 1);
    }
}

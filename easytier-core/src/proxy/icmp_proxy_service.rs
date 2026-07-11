use std::{
    net::Ipv4Addr,
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
    runtime::{IcmpProxyResponseSink, IcmpProxyRuntime, ProxyRuntimeError},
};

pub struct IcmpProxyService<R: IcmpProxyRuntime + 'static> {
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<R>,
    engine: Arc<IcmpProxyEngine>,
    response_tx: UnboundedSender<ZCPacket>,
    response_rx: std::sync::Mutex<Option<UnboundedReceiver<ZCPacket>>>,
    pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
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
            started: AtomicBool::new(false),
        })
    }

    pub fn engine(&self) -> Arc<IcmpProxyEngine> {
        self.engine.clone()
    }

    pub async fn start(self: &Arc<Self>) -> Result<(), ProxyRuntimeError> {
        if self.started.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let snapshot = self.runtime.proxy_runtime_snapshot();
        let response_sink: Arc<dyn IcmpProxyResponseSink> = self.clone();
        if let Err(err) = self.runtime.start_icmp(Arc::downgrade(&response_sink)) {
            if !snapshot.no_tun {
                self.started.store(false, Ordering::Release);
                return Err(err);
            }
            tracing::warn!(?err, "start ICMP runtime failed without TUN");
        }

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
                tokio::time::sleep(Duration::from_secs(1)).await;
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
                tokio::time::sleep(Duration::from_secs(1)).await;
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
        self.runtime.stop_icmp();
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
                if let Err(err) = self.runtime.send_icmp_to_socket(destination, &request) {
                    tracing::error!(?err, "send ICMP packet through runtime failed");
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

impl<R: IcmpProxyRuntime + 'static> IcmpProxyResponseSink for IcmpProxyService<R> {
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

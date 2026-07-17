use std::sync::{
    Arc, Weak,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::JoinSet;

use crate::packet::ZCPacket;
use crate::peers::PeerPacketFilter;
use crate::peers::peer_manager::{PeerManagerCore, PipelineRegistrationGuard};

use super::cidr_table::ProxyCidrTable;
use super::runtime::{UdpProxyResponseSink, UdpProxyRuntime};
use super::udp_proxy_engine::{UdpNatEntryId, UdpProxyAction, UdpProxyEngine, UdpProxyPeerContext};

pub struct UdpProxyService<R: UdpProxyRuntime + 'static> {
    peer_manager: Arc<PeerManagerCore>,
    runtime: Arc<R>,
    engine: Arc<UdpProxyEngine>,
    response_tx: Sender<ZCPacket>,
    response_rx: std::sync::Mutex<Option<Receiver<ZCPacket>>>,
    pipeline_guard: std::sync::Mutex<Option<PipelineRegistrationGuard>>,
    tasks: std::sync::Mutex<JoinSet<()>>,
    started: AtomicBool,
}

impl<R: UdpProxyRuntime + 'static> UdpProxyService<R> {
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime: Arc<R>,
        cidr_table: Arc<ProxyCidrTable>,
        fragment_timeout: Duration,
    ) -> Arc<Self> {
        let (response_tx, response_rx) = mpsc::channel(1024);
        Arc::new(Self {
            peer_manager,
            runtime,
            engine: Arc::new(UdpProxyEngine::new(cidr_table, fragment_timeout)),
            response_tx,
            response_rx: std::sync::Mutex::new(Some(response_rx)),
            pipeline_guard: std::sync::Mutex::new(None),
            tasks: std::sync::Mutex::new(JoinSet::new()),
            started: AtomicBool::new(false),
        })
    }

    pub async fn start(self: &Arc<Self>) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }

        let guard = self
            .peer_manager
            .add_managed_packet_process_pipeline(Box::new(UdpProxyServiceFilter {
                service: Arc::downgrade(self),
            }))
            .await;
        self.pipeline_guard.lock().unwrap().replace(guard);

        if let Some(mut response_rx) = self.response_rx.lock().unwrap().take() {
            let service = Arc::downgrade(self);
            self.tasks.lock().unwrap().spawn(async move {
                while let Some(mut packet) = response_rx.recv().await {
                    let Some(service) = service.upgrade() else {
                        break;
                    };
                    let latency_first = service.runtime.proxy_runtime_snapshot().latency_first;
                    let Some(hdr) = packet.mut_peer_manager_header() else {
                        continue;
                    };
                    hdr.set_latency_first(latency_first);
                    let dst_peer_id = hdr.to_peer_id.into();
                    tracing::trace!(?packet, ?dst_peer_id, "udp nat packet response send");
                    if let Err(err) = service
                        .peer_manager
                        .send_msg_for_proxy(packet, dst_peer_id)
                        .await
                    {
                        tracing::error!(?err, "send udp proxy response to peer failed");
                    }
                }
            });
        }

        let service = Arc::downgrade(self);
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                crate::runtime_time::sleep(Duration::from_secs(15)).await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                for entry_id in service.engine.remove_expired_entries() {
                    service.runtime.close_udp_socket(entry_id);
                }
            }
        });

        let service = Arc::downgrade(self);
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                crate::runtime_time::sleep(Duration::from_secs(1)).await;
                let Some(service) = service.upgrade() else {
                    break;
                };
                service.engine.remove_expired_fragments();
            }
        });
    }

    pub fn stop(&self) {
        if !self.started.swap(false, Ordering::AcqRel) {
            return;
        }
        if let Some(guard) = self.pipeline_guard.lock().unwrap().take() {
            guard.close();
        }
        self.tasks.lock().unwrap().abort_all();
        for entry_id in self.engine.entry_ids() {
            self.engine.remove_entry(entry_id);
            self.runtime.close_udp_socket(entry_id);
        }
    }

    async fn handle_peer_packet(self: Arc<Self>, packet: ZCPacket) -> Option<ZCPacket> {
        let snapshot = self.runtime.proxy_runtime_snapshot();
        let action = self.engine.handle_peer_packet(
            &packet,
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
            return matches!(action, UdpProxyAction::Pass).then_some(packet);
        };

        let sink: Arc<dyn UdpProxyResponseSink> = self.clone();
        if let Err(err) = self
            .runtime
            .send_udp_to_socket(entry_id, dst, payload, Arc::downgrade(&sink))
            .await
        {
            tracing::error!(?err, ?entry_id, "udp proxy runtime send failed");
            self.engine.remove_entry(entry_id);
            self.runtime.close_udp_socket(entry_id);
        }

        None
    }
}

impl<R: UdpProxyRuntime + 'static> Drop for UdpProxyService<R> {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl<R: UdpProxyRuntime + 'static> UdpProxyResponseSink for UdpProxyService<R> {
    async fn handle_socket_response(
        &self,
        entry_id: UdpNatEntryId,
        src: std::net::SocketAddr,
        payload: Bytes,
    ) {
        let packets = match self.engine.handle_socket_response(
            entry_id,
            src,
            payload.as_ref(),
            self.runtime.udp_response_ipv4_mtu(),
        ) {
            Ok(packets) => packets,
            Err(err) => {
                tracing::error!(?err, ?entry_id, "compose udp response packet failed");
                self.engine.remove_entry(entry_id);
                self.runtime.close_udp_socket(entry_id);
                return;
            }
        };

        for mut packet in packets {
            let Some(hdr) = packet.mut_peer_manager_header() else {
                continue;
            };
            let dst_peer_id: crate::config::PeerId = hdr.to_peer_id.into();
            tracing::trace!(?packet, ?dst_peer_id, "udp nat packet response queued");
            if let Err(err) = self.response_tx.try_send(packet) {
                tracing::error!(?err, ?dst_peer_id, "queue udp proxy response failed");
            }
        }
    }
}

struct UdpProxyServiceFilter<R: UdpProxyRuntime + 'static> {
    service: Weak<UdpProxyService<R>>,
}

#[async_trait::async_trait]
impl<R: UdpProxyRuntime + 'static> PeerPacketFilter for UdpProxyServiceFilter<R> {
    async fn try_process_packet_from_peer(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(service) = self.service.upgrade() else {
            return Some(packet);
        };
        service.handle_peer_packet(packet).await
    }
}

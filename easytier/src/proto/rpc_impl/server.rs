use std::{
    pin::Pin,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use dashmap::DashMap;
use prost::Message;
use tokio::{task::JoinSet, time::timeout};
use tokio_stream::StreamExt;

use crate::{
    common::{join_joinset_background, PeerId},
    proto::{
        common::{self, RpcDescriptor, RpcPacket, RpcRequest, RpcResponse},
        rpc_types::error::Result,
    },
    tunnel::{
        mpsc::{MpscTunnel, MpscTunnelSender},
        ring::create_ring_tunnel_pair,
        Tunnel, ZCPacketStream,
    },
};

use super::{
    packet::{build_rpc_packet, PacketMerger},
    service_registry::ServiceRegistry,
    RpcController, Transport,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PacketMergerKey {
    from_peer_id: PeerId,
    rpc_desc: RpcDescriptor,
    transaction_id: i64,
}

pub struct Server {
    registry: Arc<ServiceRegistry>,

    mpsc: Mutex<Option<MpscTunnel<Box<dyn Tunnel>>>>,

    transport: Mutex<Transport>,

    tasks: Arc<Mutex<JoinSet<()>>>,
    packet_mergers: Arc<DashMap<PacketMergerKey, PacketMerger>>,
}

impl Server {
    pub fn new() -> Self {
        Server::new_with_registry(Arc::new(ServiceRegistry::new()))
    }

    pub fn new_with_registry(registry: Arc<ServiceRegistry>) -> Self {
        let (ring_a, ring_b) = create_ring_tunnel_pair();

        Self {
            registry,
            mpsc: Mutex::new(Some(MpscTunnel::new(ring_a))),
            transport: Mutex::new(MpscTunnel::new(ring_b)),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            packet_mergers: Arc::new(DashMap::new()),
        }
    }

    pub fn registry(&self) -> &ServiceRegistry {
        &self.registry
    }

    pub fn get_transport_sink(&self) -> MpscTunnelSender {
        self.transport.lock().unwrap().get_sink()
    }

    pub fn get_transport_stream(&self) -> Pin<Box<dyn ZCPacketStream>> {
        self.transport.lock().unwrap().get_stream()
    }

    pub fn run(&self) {
        let tasks = self.tasks.clone();
        join_joinset_background(tasks.clone(), "rpc server".to_string());

        let mpsc = self.mpsc.lock().unwrap().take().unwrap();

        let packet_merges = self.packet_mergers.clone();
        let reg = self.registry.clone();
        let t = tasks.clone();
        tasks.lock().unwrap().spawn(async move {
            let mut mpsc = mpsc;
            let mut rx = mpsc.get_stream();

            while let Some(packet) = rx.next().await {
                if let Err(err) = packet {
                    tracing::error!(?err, "Failed to receive packet");
                    continue;
                }
                let packet = match common::RpcPacket::decode(packet.unwrap().payload()) {
                    Err(err) => {
                        tracing::error!(?err, "Failed to decode packet");
                        continue;
                    }
                    Ok(packet) => packet,
                };

                if !packet.is_request {
                    tracing::warn!(?packet, "Received non-request packet");
                    continue;
                }

                let key = PacketMergerKey {
                    from_peer_id: packet.from_peer,
                    rpc_desc: packet.descriptor.clone().unwrap_or_default(),
                    transaction_id: packet.transaction_id,
                };

                let ret = packet_merges
                    .entry(key.clone())
                    .or_insert_with(PacketMerger::new)
                    .feed(packet);

                match ret {
                    Ok(Some(packet)) => {
                        packet_merges.remove(&key);
                        t.lock().unwrap().spawn(Self::handle_rpc(
                            mpsc.get_sink(),
                            packet,
                            reg.clone(),
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::error!("Failed to feed packet to merger, {}", err.to_string());
                    }
                }
            }
        });

        let packet_mergers = self.packet_mergers.clone();
        tasks.lock().unwrap().spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                packet_mergers.retain(|_, v| v.last_updated().elapsed().as_secs() < 10);
            }
        });
    }

    async fn handle_rpc_request(packet: RpcPacket, reg: Arc<ServiceRegistry>) -> Result<Bytes> {
        let rpc_request = RpcRequest::decode(Bytes::from(packet.body))?;
        let timeout_duration = std::time::Duration::from_millis(rpc_request.timeout_ms as u64);
        let ctrl = RpcController::default();
        Ok(timeout(
            timeout_duration,
            reg.call_method(
                packet.descriptor.unwrap(),
                ctrl,
                Bytes::from(rpc_request.request),
            ),
        )
        .await??)
    }

    async fn handle_rpc(sender: MpscTunnelSender, packet: RpcPacket, reg: Arc<ServiceRegistry>) {
        let from_peer = packet.from_peer;
        let to_peer = packet.to_peer;
        let transaction_id = packet.transaction_id;
        let trace_id = packet.trace_id;
        let desc = packet.descriptor.clone().unwrap();

        let mut resp_msg = RpcResponse::default();
        let now = std::time::Instant::now();

        let resp_bytes = Self::handle_rpc_request(packet, reg).await;

        match &resp_bytes {
            Ok(r) => {
                resp_msg.response = r.clone().into();
            }
            Err(err) => {
                resp_msg.error = Some(err.into());
            }
        };
        resp_msg.runtime_us = now.elapsed().as_micros() as u64;

        let packets = build_rpc_packet(
            to_peer,
            from_peer,
            desc,
            transaction_id,
            false,
            &resp_msg.encode_to_vec(),
            trace_id,
        );

        for packet in packets {
            if let Err(err) = sender.send(packet).await {
                tracing::error!(?err, "Failed to send response packet");
            }
        }
    }

    pub fn inflight_count(&self) -> usize {
        self.packet_mergers.len()
    }

    pub fn close(&self) {
        self.transport.lock().unwrap().close();
    }
}

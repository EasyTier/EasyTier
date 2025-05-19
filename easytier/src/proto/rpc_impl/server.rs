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
        common::{
            self, CompressionAlgoPb, RpcCompressionInfo, RpcPacket, RpcRequest, RpcResponse,
            TunnelInfo,
        },
        rpc_types::{controller::Controller, error::Result},
    },
    tunnel::{
        mpsc::{MpscTunnel, MpscTunnelSender},
        ring::create_ring_tunnel_pair,
        Tunnel, ZCPacketStream,
    },
};

use super::{
    packet::{build_rpc_packet, compress_packet, decompress_packet, PacketMerger},
    service_registry::ServiceRegistry,
    RpcController, Transport,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PacketMergerKey {
    from_peer_id: PeerId,
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
            mpsc: Mutex::new(Some(MpscTunnel::new(ring_a, None))),
            transport: Mutex::new(MpscTunnel::new(ring_b, None)),
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
        let t = Arc::downgrade(&tasks);
        let tunnel_info = mpsc.tunnel_info();
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
                    transaction_id: packet.transaction_id,
                };

                tracing::trace!(?key, ?packet, "Received request packet");

                let ret = packet_merges
                    .entry(key.clone())
                    .or_insert_with(PacketMerger::new)
                    .feed(packet);

                match ret {
                    Ok(Some(packet)) => {
                        packet_merges.remove(&key);
                        let Some(t) = t.upgrade() else {
                            tracing::error!("tasks is dropped");
                            return;
                        };
                        t.lock().unwrap().spawn(Self::handle_rpc(
                            mpsc.get_sink(),
                            packet,
                            reg.clone(),
                            tunnel_info.clone(),
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

    async fn handle_rpc_request(
        packet: RpcPacket,
        reg: Arc<ServiceRegistry>,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Bytes> {
        let body = if let Some(compression_info) = packet.compression_info {
            decompress_packet(
                compression_info.algo.try_into().unwrap_or_default(),
                &packet.body,
            )
            .await?
        } else {
            packet.body
        };
        let rpc_request = RpcRequest::decode(Bytes::from(body))?;
        let timeout_duration = std::time::Duration::from_millis(rpc_request.timeout_ms as u64);
        let mut ctrl = RpcController::default();
        let raw_req = Bytes::from(rpc_request.request);
        ctrl.set_raw_input(raw_req.clone());
        ctrl.set_tunnel_info(tunnel_info);
        let ret = timeout(
            timeout_duration,
            reg.call_method(packet.descriptor.unwrap(), ctrl.clone(), raw_req),
        )
        .await??;
        if let Some(raw_output) = ctrl.get_raw_output() {
            Ok(raw_output)
        } else {
            Ok(ret)
        }
    }

    async fn handle_rpc(
        sender: MpscTunnelSender,
        packet: RpcPacket,
        reg: Arc<ServiceRegistry>,
        tunnel_info: Option<TunnelInfo>,
    ) {
        let from_peer = packet.from_peer;
        let to_peer = packet.to_peer;
        let transaction_id = packet.transaction_id;
        let trace_id = packet.trace_id;
        let desc = packet.descriptor.clone().unwrap();

        let mut resp_msg = RpcResponse::default();
        let now = std::time::Instant::now();

        let compression_info = packet.compression_info.clone();
        let resp_bytes = Self::handle_rpc_request(packet, reg, tunnel_info).await;

        match &resp_bytes {
            Ok(r) => {
                resp_msg.response = r.clone().into();
            }
            Err(err) => {
                resp_msg.error = Some(err.into());
            }
        };
        resp_msg.runtime_us = now.elapsed().as_micros() as u64;

        let (compressed_resp, algo) = compress_packet(
            compression_info.unwrap_or_default().accepted_algo(),
            &resp_msg.encode_to_vec(),
        )
        .await
        .unwrap();

        let packets = build_rpc_packet(
            to_peer,
            from_peer,
            desc,
            transaction_id,
            false,
            &compressed_resp,
            trace_id,
            RpcCompressionInfo {
                algo: algo.into(),
                accepted_algo: CompressionAlgoPb::Zstd.into(),
            },
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

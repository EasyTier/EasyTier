use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use dashmap::DashMap;
use prost::Message;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_stream::StreamExt;

use crate::common::PeerId;
use crate::defer;
use crate::proto::common::{RpcDescriptor, RpcPacket, RpcRequest, RpcResponse};
use crate::proto::rpc_impl::packet::build_rpc_packet;
use crate::proto::rpc_types::controller::Controller;
use crate::proto::rpc_types::descriptor::MethodDescriptor;
use crate::proto::rpc_types::{
    __rt::RpcClientFactory, descriptor::ServiceDescriptor, handler::Handler,
};

use crate::proto::rpc_types::error::Result;
use crate::tunnel::mpsc::{MpscTunnel, MpscTunnelSender};
use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::ring::create_ring_tunnel_pair;
use crate::tunnel::{Tunnel, TunnelError};

use super::packet::PacketMerger;
use super::{RpcTransactId, Transport};

static CUR_TID: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

type RpcPacketSender = mpsc::UnboundedSender<RpcPacket>;
type RpcPacketReceiver = mpsc::UnboundedReceiver<RpcPacket>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct InflightRequestKey {
    from_peer_id: PeerId,
    to_peer_id: PeerId,
    transaction_id: RpcTransactId,
}

struct InflightRequest {
    sender: RpcPacketSender,
    merger: PacketMerger,
    start_time: std::time::Instant,
}

type InflightRequestTable = Arc<DashMap<InflightRequestKey, InflightRequest>>;

pub struct Client {
    mpsc: MpscTunnel<Box<dyn Tunnel>>,
    transport: Option<Transport>,
    inflight_requests: InflightRequestTable,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl Client {
    pub fn new() -> Self {
        let (ring_a, ring_b) = create_ring_tunnel_pair();
        Self {
            mpsc: MpscTunnel::new(ring_a),
            transport: Some(MpscTunnel::new(ring_b)),
            inflight_requests: Arc::new(DashMap::new()),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }

    pub fn get_transport(&mut self) -> Option<Transport> {
        self.transport.take()
    }

    pub fn run(&mut self) {
        let mut tasks = self.tasks.lock().unwrap();

        let mut rx = self.mpsc.get_stream();
        let inflight_requests = self.inflight_requests.clone();
        tasks.spawn(async move {
            while let Some(packet) = rx.next().await {
                if let Err(err) = packet {
                    tracing::error!(?err, "Failed to receive packet");
                    continue;
                }
                let packet = match RpcPacket::decode(packet.unwrap().payload()) {
                    Err(err) => {
                        tracing::error!(?err, "Failed to decode packet");
                        continue;
                    }
                    Ok(packet) => packet,
                };

                if packet.is_request {
                    tracing::warn!(?packet, "Received non-response packet");
                    continue;
                }

                let key = InflightRequestKey {
                    from_peer_id: packet.to_peer,
                    to_peer_id: packet.from_peer,
                    transaction_id: packet.transaction_id,
                };

                let Some(mut inflight_request) = inflight_requests.get_mut(&key) else {
                    tracing::warn!(?key, "No inflight request found for key");
                    continue;
                };

                let ret = inflight_request.merger.feed(packet);
                match ret {
                    Ok(Some(rpc_packet)) => {
                        inflight_request.sender.send(rpc_packet).unwrap();
                    }
                    Ok(None) => {}
                    Err(err) => {
                        tracing::error!(?err, "Failed to feed packet to merger");
                    }
                }
            }
        });
    }

    pub fn scoped_client<F: RpcClientFactory>(
        &self,
        from_peer_id: PeerId,
        to_peer_id: PeerId,
    ) -> F::ClientImpl {
        #[derive(Clone)]
        struct HandlerImpl<F> {
            from_peer_id: PeerId,
            to_peer_id: PeerId,
            zc_packet_sender: MpscTunnelSender,
            inflight_requests: InflightRequestTable,
            _phan: PhantomData<F>,
        }

        impl<F: RpcClientFactory> HandlerImpl<F> {
            async fn do_rpc(
                &self,
                packets: Vec<ZCPacket>,
                rx: &mut RpcPacketReceiver,
            ) -> Result<RpcPacket> {
                for packet in packets {
                    self.zc_packet_sender.send(packet).await?;
                }

                Ok(rx.recv().await.ok_or(TunnelError::Shutdown)?)
            }
        }

        #[async_trait::async_trait]
        impl<F: RpcClientFactory> Handler for HandlerImpl<F> {
            type Descriptor = F::Descriptor;
            type Controller = F::Controller;

            async fn call(
                &self,
                ctrl: Self::Controller,
                method: <Self::Descriptor as ServiceDescriptor>::Method,
                input: bytes::Bytes,
            ) -> Result<bytes::Bytes> {
                let transaction_id = CUR_TID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (tx, mut rx) = mpsc::unbounded_channel();
                let key = InflightRequestKey {
                    from_peer_id: self.from_peer_id,
                    to_peer_id: self.to_peer_id,
                    transaction_id,
                };

                defer!(self.inflight_requests.remove(&key););
                self.inflight_requests.insert(
                    key.clone(),
                    InflightRequest {
                        sender: tx,
                        merger: PacketMerger::new(),
                        start_time: std::time::Instant::now(),
                    },
                );

                let desc = self.service_descriptor();

                let rpc_desc = RpcDescriptor {
                    proto_name: desc.proto_name().to_string(),
                    service_name: desc.name().to_string(),
                    method_index: method.index() as u32,
                };

                let rpc_req = RpcRequest {
                    descriptor: Some(rpc_desc.clone()),
                    request: input.into(),
                    timeout_ms: ctrl.timeout_ms(),
                };

                let packets = build_rpc_packet(
                    self.from_peer_id,
                    self.to_peer_id,
                    rpc_desc,
                    transaction_id,
                    true,
                    &rpc_req.encode_to_vec(),
                    ctrl.trace_id(),
                );

                let timeout_dur = std::time::Duration::from_millis(ctrl.timeout_ms() as u64);
                let rpc_packet = timeout(timeout_dur, self.do_rpc(packets, &mut rx)).await??;

                assert_eq!(rpc_packet.transaction_id, transaction_id);

                let rpc_resp = RpcResponse::decode(Bytes::from(rpc_packet.body))?;

                if let Some(err) = &rpc_resp.error {
                    return Err(err.into());
                }

                Ok(bytes::Bytes::from(rpc_resp.response))
            }
        }

        F::new(HandlerImpl::<F> {
            from_peer_id,
            to_peer_id,
            zc_packet_sender: self.mpsc.get_sink(),
            inflight_requests: self.inflight_requests.clone(),
            _phan: PhantomData,
        })
    }

    pub fn inflight_count(&self) -> usize {
        self.inflight_requests.len()
    }
}

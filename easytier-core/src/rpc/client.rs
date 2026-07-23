use std::{
    marker::PhantomData,
    pin::Pin,
    sync::{Arc, LazyLock, Mutex, atomic::Ordering},
};

use atomic_shim::AtomicI64;
use bytes::Bytes;
use dashmap::DashMap;
use futures::StreamExt;
use prost::Message;
use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    config::PeerId,
    foundation::{
        stats::{ArcRpcMetrics, RpcMetricLabels, RpcMetricsProvider},
        time::timeout,
    },
    proto::{
        common::{
            CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket, RpcRequest,
            RpcResponse,
        },
        rpc_types::controller::Controller,
        rpc_types::descriptor::MethodDescriptor,
        rpc_types::error::{Error, Result},
        rpc_types::{__rt::RpcClientFactory, descriptor::ServiceDescriptor, handler::Handler},
    },
    rpc::packet::{
        BuildRpcPacketArgs, PacketMerger, build_rpc_packet, compress_packet, decompress_packet,
    },
    tunnel::{
        Tunnel, TunnelError, ZCPacketStream,
        mpsc::{MpscTunnel, MpscTunnelSender},
        ring::create_ring_tunnel_pair,
    },
};

use super::{RpcTransactId, Transport};

static CUR_TID: LazyLock<AtomicI64> = LazyLock::new(|| AtomicI64::new(rand::random()));

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

impl std::fmt::Debug for InflightRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InflightRequest")
            .field("sender", &self.sender)
            .field("start_time", &self.start_time)
            .finish()
    }
}

struct InflightCleanup {
    table: InflightRequestTable,
    key: InflightRequestKey,
}

impl Drop for InflightCleanup {
    fn drop(&mut self) {
        self.table.remove(&self.key);
        if self.table.capacity() - self.table.len() > 4 {
            self.table.shrink_to_fit();
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub compression_info: RpcCompressionInfo,
    pub last_active: Option<std::time::Instant>,
}

type InflightRequestTable = Arc<DashMap<InflightRequestKey, InflightRequest>>;
pub type PeerInfoTable = Arc<DashMap<PeerId, PeerInfo>>;

pub struct Client {
    mpsc: Mutex<MpscTunnel<Box<dyn Tunnel>>>,
    transport: Mutex<Transport>,
    inflight_requests: InflightRequestTable,
    peer_info: PeerInfoTable,
    tasks: Mutex<JoinSet<()>>,
    metrics: Option<ArcRpcMetrics>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        let (ring_a, ring_b) = create_ring_tunnel_pair();
        Self {
            mpsc: Mutex::new(MpscTunnel::new(ring_a, None)),
            transport: Mutex::new(MpscTunnel::new(ring_b, None)),
            inflight_requests: Arc::new(DashMap::new()),
            peer_info: Arc::new(DashMap::new()),
            tasks: Mutex::new(JoinSet::new()),
            metrics: None,
        }
    }

    pub fn new_with_stats_manager<T>(stats_manager: T) -> Self
    where
        T: RpcMetricsProvider,
    {
        let mut client = Self::new();
        client.metrics = stats_manager.into_rpc_metrics();
        client
    }

    pub fn new_with_metrics(metrics: ArcRpcMetrics) -> Self {
        let mut client = Self::new();
        client.metrics = Some(metrics);
        client
    }

    pub fn get_transport_sink(&self) -> MpscTunnelSender {
        self.transport.lock().unwrap().get_sink()
    }

    pub fn get_transport_stream(&self) -> Pin<Box<dyn ZCPacketStream>> {
        self.transport.lock().unwrap().get_stream()
    }

    pub fn run(&self) {
        let mut tasks = self.tasks.lock().unwrap();

        let peer_infos = self.peer_info.clone();
        tasks.spawn(async move {
            loop {
                crate::foundation::time::sleep(std::time::Duration::from_secs(30)).await;
                let now = std::time::Instant::now();
                peer_infos.retain(|_, v| {
                    if let Some(last_active) = v.last_active {
                        return now.duration_since(last_active)
                            < std::time::Duration::from_secs(120);
                    }
                    true
                });
                peer_infos.shrink_to_fit();
            }
        });

        let mut rx = self.mpsc.lock().unwrap().get_stream();
        let inflight_requests = self.inflight_requests.clone();
        tasks.spawn(async move {
            while let Some(packet) = rx.next().await {
                let packet = match packet {
                    Err(err) => {
                        tracing::error!(?err, "Failed to receive packet");
                        continue;
                    }
                    Ok(packet) => packet,
                };
                let packet = match RpcPacket::decode(packet.payload()) {
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
                    tracing::warn!(
                        ?key,
                        ?inflight_requests,
                        "No inflight request found for key"
                    );
                    continue;
                };

                tracing::trace!(?packet, "Received response packet");

                let ret = inflight_request.merger.feed(packet);
                match ret {
                    Ok(Some(rpc_packet)) => {
                        if let Err(err) = inflight_request.sender.send(rpc_packet) {
                            tracing::warn!(
                                ?err,
                                ?key,
                                "RPC response receiver is gone, removing inflight request"
                            );
                            drop(inflight_request);
                            inflight_requests.remove(&key);
                        }
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
        domain_name: String,
    ) -> F::ClientImpl {
        #[derive(Clone)]
        struct HandlerImpl<F> {
            domain_name: String,
            from_peer_id: PeerId,
            to_peer_id: PeerId,
            zc_packet_sender: MpscTunnelSender,
            inflight_requests: InflightRequestTable,
            peer_info: PeerInfoTable,
            metrics: Option<ArcRpcMetrics>,
            _phan: PhantomData<F>,
        }

        impl<F: RpcClientFactory> HandlerImpl<F> {
            async fn do_rpc(
                &self,
                packets: Vec<crate::packet::ZCPacket>,
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
                mut ctrl: Self::Controller,
                method: <Self::Descriptor as ServiceDescriptor>::Method,
                input: Bytes,
            ) -> Result<Bytes> {
                let start_time = std::time::Instant::now();
                let transaction_id = CUR_TID.fetch_add(1, Ordering::Relaxed);
                let (tx, mut rx) = mpsc::unbounded_channel();
                let key = InflightRequestKey {
                    from_peer_id: self.from_peer_id,
                    to_peer_id: self.to_peer_id,
                    transaction_id,
                };
                let desc = self.service_descriptor();
                let labels = RpcMetricLabels {
                    network_name: self.domain_name.clone(),
                    src_peer_id: self.from_peer_id,
                    dst_peer_id: self.to_peer_id,
                    service_name: desc.name().to_string(),
                    method_name: method.name().to_string(),
                };

                self.inflight_requests.insert(
                    key.clone(),
                    InflightRequest {
                        sender: tx,
                        merger: PacketMerger::new(),
                        start_time,
                    },
                );
                let _cleanup = InflightCleanup {
                    table: self.inflight_requests.clone(),
                    key: key.clone(),
                };

                if let Some(metrics) = &self.metrics {
                    metrics.client_tx(&labels);
                }

                let rpc_desc = RpcDescriptor {
                    domain_name: self.domain_name.clone(),
                    proto_name: desc.proto_name().to_string(),
                    service_name: desc.name().to_string(),
                    method_index: method.index() as u32,
                };

                let rpc_req = RpcRequest {
                    request: if let Some(raw_input) = ctrl.get_raw_input() {
                        raw_input.into()
                    } else {
                        input.into()
                    },
                    timeout_ms: ctrl.timeout_ms(),
                    ..Default::default()
                };

                let peer_info = self
                    .peer_info
                    .get(&self.to_peer_id)
                    .map(|v| v.clone())
                    .unwrap_or_default();
                let (buf, c_algo) = compress_packet(
                    peer_info.compression_info.accepted_algo(),
                    &rpc_req.encode_to_vec(),
                )
                .await
                .unwrap();

                let packets = build_rpc_packet(BuildRpcPacketArgs {
                    from_peer: self.from_peer_id,
                    to_peer: self.to_peer_id,
                    rpc_desc,
                    transaction_id,
                    is_req: true,
                    content: &buf,
                    trace_id: ctrl.trace_id(),
                    compression_info: RpcCompressionInfo {
                        algo: c_algo.into(),
                        accepted_algo: CompressionAlgoPb::Zstd.into(),
                    },
                });
                let timeout_dur = std::time::Duration::from_millis(ctrl.timeout_ms() as u64);
                let rpc_ret = timeout(timeout_dur, self.do_rpc(packets, &mut rx)).await;
                let mut rpc_packet = match rpc_ret {
                    Ok(Ok(packet)) => packet,
                    Ok(Err(err)) => {
                        if let Some(metrics) = &self.metrics {
                            metrics.client_error(
                                &labels,
                                Some(format!("{:?}", err)),
                                start_time.elapsed().as_millis() as u64,
                            );
                        }
                        return Err(err);
                    }
                    Err(err) => {
                        let err = Error::from(err);
                        if let Some(metrics) = &self.metrics {
                            metrics.client_error(
                                &labels,
                                Some(format!("{:?}", err)),
                                start_time.elapsed().as_millis() as u64,
                            );
                        }
                        return Err(err);
                    }
                };

                if let Some(compression_info) = rpc_packet.compression_info {
                    self.peer_info.insert(
                        self.to_peer_id,
                        PeerInfo {
                            peer_id: self.to_peer_id,
                            compression_info,
                            last_active: Some(std::time::Instant::now()),
                        },
                    );

                    rpc_packet.body =
                        decompress_packet(compression_info.algo(), &rpc_packet.body).await?;
                }

                assert_eq!(rpc_packet.transaction_id, transaction_id);

                let rpc_resp = RpcResponse::decode(Bytes::from(rpc_packet.body))?;

                if let Some(err) = &rpc_resp.error {
                    if let Some(metrics) = &self.metrics {
                        metrics.client_error(
                            &labels,
                            Some(format!("{:?}", err.error_kind)),
                            start_time.elapsed().as_millis() as u64,
                        );
                    }
                    return Err(err.into());
                }

                let raw_output = Bytes::from(rpc_resp.response);
                ctrl.set_raw_output(raw_output.clone());

                if let Some(metrics) = &self.metrics {
                    metrics.client_rx(&labels, start_time.elapsed().as_millis() as u64);
                }

                Ok(raw_output)
            }
        }

        F::new(HandlerImpl::<F> {
            domain_name,
            from_peer_id,
            to_peer_id,
            zc_packet_sender: self.mpsc.lock().unwrap().get_sink(),
            inflight_requests: self.inflight_requests.clone(),
            peer_info: self.peer_info.clone(),
            metrics: self.metrics.clone(),
            _phan: PhantomData,
        })
    }

    pub async fn stop(&self) {
        self.transport.lock().unwrap().close();
        let mut tasks = {
            let mut task_slot = self.tasks.lock().unwrap();
            std::mem::replace(&mut *task_slot, JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[cfg(any(test, feature = "test-utils"))]
mod test_utils {
    use super::{Client, PeerInfoTable};

    impl Client {
        #[doc(hidden)]
        pub fn inflight_count(&self) -> usize {
            self.inflight_requests.len()
        }

        #[doc(hidden)]
        pub fn peer_info_table(&self) -> PeerInfoTable {
            self.peer_info.clone()
        }
    }
}

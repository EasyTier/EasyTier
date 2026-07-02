use std::sync::{Arc, Weak};
use std::time::SystemTime;

use tokio::sync::{
    Mutex,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
    peers::{PacketRecvChan, PacketRecvChanReceiver, recv_packet_from_chan},
    stats_manager::{CounterHandle, LabelSet, LabelType, MetricName, StatsManager},
    token_bucket::TokenBucket,
};

use super::{
    context::{ArcPeerContext, NetworkIdentity},
    peer_map::PeerMap,
    peer_rpc::{PeerRpcManager, PeerRpcManagerTransport},
    relay_peer_map::RelayPeerMap,
    route_trait::{NextHopPolicy, RouteInterface, RouteInterfaceBox},
    traffic_metrics::{
        TrafficKind, TrafficMetricRecorder, is_relay_data_packet_type, traffic_kind,
    },
};
use crate::proto::peer_rpc::PeerIdentityType;

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Box, Arc)]
pub trait GlobalForeignNetworkAccessor: Send + Sync + 'static {
    async fn list_global_foreign_peer(&self, network_identity: &NetworkIdentity) -> Vec<PeerId>;
}

#[derive(Clone, Debug, Default)]
pub struct ForeignNetworkRouteInfo {
    pub network_name: String,
    pub peer_ids: Vec<PeerId>,
    pub network_secret_digest: Vec<u8>,
    pub my_peer_id_for_this_network: PeerId,
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait ForeignNetworkRouteInfoProvider: Send + Sync + 'static {
    async fn list_foreign_network_route_infos(&self) -> Vec<ForeignNetworkRouteInfo>;

    fn get_foreign_network_last_update(&self, _network_name: &str) -> Option<SystemTime> {
        None
    }
}

pub fn peer_map_foreign_network_accessor(
    peer_map: Weak<PeerMap>,
) -> Box<dyn GlobalForeignNetworkAccessor> {
    struct PeerMapForeignNetworkAccessor {
        peer_map: Weak<PeerMap>,
    }

    #[async_trait::async_trait]
    impl GlobalForeignNetworkAccessor for PeerMapForeignNetworkAccessor {
        async fn list_global_foreign_peer(
            &self,
            network_identity: &NetworkIdentity,
        ) -> Vec<PeerId> {
            let Some(peer_map) = self.peer_map.upgrade() else {
                return vec![];
            };

            peer_map
                .list_peers_own_foreign_network(network_identity)
                .await
        }
    }

    Box::new(PeerMapForeignNetworkAccessor { peer_map })
}

pub struct ForeignNetworkRouteInterface {
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,
    network_identity: NetworkIdentity,
    accessor: Box<dyn GlobalForeignNetworkAccessor>,
}

impl ForeignNetworkRouteInterface {
    pub fn new(
        my_peer_id: PeerId,
        peer_map: Weak<PeerMap>,
        network_identity: NetworkIdentity,
        accessor: Box<dyn GlobalForeignNetworkAccessor>,
    ) -> Self {
        Self {
            my_peer_id,
            peer_map,
            network_identity,
            accessor,
        }
    }
}

#[async_trait::async_trait]
impl RouteInterface for ForeignNetworkRouteInterface {
    async fn list_peers(&self) -> Vec<PeerId> {
        let Some(peer_map) = self.peer_map.upgrade() else {
            return vec![];
        };

        let mut global = self
            .accessor
            .list_global_foreign_peer(&self.network_identity)
            .await;
        let local = peer_map.list_peers_with_conn().await;
        global.extend(local.iter().cloned());
        global
            .into_iter()
            .filter(|peer_id| *peer_id != self.my_peer_id)
            .collect()
    }

    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    fn need_periodic_requery_peers(&self) -> bool {
        true
    }

    async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        let peer_map = self.peer_map.upgrade()?;
        peer_map.get_peer_identity_type(peer_id)
    }

    async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let peer_map = self.peer_map.upgrade()?;
        peer_map.get_peer_public_key(peer_id)
    }

    async fn close_peer(&self, peer_id: PeerId) {
        if let Some(peer_map) = self.peer_map.upgrade() {
            let _ = peer_map.close_peer(peer_id).await;
        }
    }
}

pub fn foreign_network_route_interface(
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,
    network_identity: NetworkIdentity,
    accessor: Box<dyn GlobalForeignNetworkAccessor>,
) -> RouteInterfaceBox {
    Box::new(ForeignNetworkRouteInterface::new(
        my_peer_id,
        peer_map,
        network_identity,
        accessor,
    ))
}

pub struct RpcTransport {
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
}

impl RpcTransport {
    pub fn new(my_peer_id: PeerId, peer_map: Weak<PeerMap>) -> (Self, UnboundedSender<ZCPacket>) {
        let (rpc_transport_sender, packet_recv) = mpsc::unbounded_channel();
        (
            Self {
                my_peer_id,
                peer_map,
                packet_recv: Mutex::new(packet_recv),
            },
            rpc_transport_sender,
        )
    }
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()> {
        tracing::debug!(
            "foreign network manager send rpc to peer: {:?}",
            dst_peer_id
        );
        let peer_map = self
            .peer_map
            .upgrade()
            .ok_or(anyhow::anyhow!("peer map is gone"))?;

        // send to ourselves so we can handle it in forward logic.
        peer_map.send_msg_directly(msg, self.my_peer_id).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<ZCPacket> {
        if let Some(packet) = self.packet_recv.lock().await.recv().await {
            tracing::trace!("recv rpc packet in foreign network manager rpc transport");
            Ok(packet)
        } else {
            Err(anyhow::anyhow!("unknown data store error"))
        }
    }
}

impl Drop for RpcTransport {
    fn drop(&mut self) {
        tracing::debug!(
            "drop rpc transport for foreign network manager, my_peer_id: {:?}",
            self.my_peer_id
        );
    }
}

pub fn build_rpc_transport(
    my_peer_id: PeerId,
    peer_map: Weak<PeerMap>,
) -> (Arc<PeerRpcManager>, UnboundedSender<ZCPacket>) {
    let (transport, sender) = RpcTransport::new(my_peer_id, peer_map);
    (Arc::new(PeerRpcManager::new(transport)), sender)
}

struct ForeignNetworkForwardCounters {
    forward_data_bytes: CounterHandle,
    forward_data_packets: CounterHandle,
    forward_control_bytes: CounterHandle,
    forward_control_packets: CounterHandle,
    rx_bytes: CounterHandle,
    rx_packets: CounterHandle,
}

pub struct ForeignNetworkPacketRouter {
    my_node_id: PeerId,
    packet_recv: PacketRecvChanReceiver,
    rpc_sender: UnboundedSender<ZCPacket>,
    peer_map: Arc<PeerMap>,
    relay_peer_map: Arc<RelayPeerMap>,
    traffic_metrics: Arc<TrafficMetricRecorder>,
    parent_context: ArcPeerContext,
    relay_data: bool,
    pm_sender: PacketRecvChan,
    network_name: String,
    bps_limiter: Option<Arc<TokenBucket>>,
    counters: ForeignNetworkForwardCounters,
}

impl ForeignNetworkPacketRouter {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        my_node_id: PeerId,
        packet_recv: PacketRecvChanReceiver,
        rpc_sender: UnboundedSender<ZCPacket>,
        peer_map: Arc<PeerMap>,
        relay_peer_map: Arc<RelayPeerMap>,
        traffic_metrics: Arc<TrafficMetricRecorder>,
        parent_context: ArcPeerContext,
        relay_data: bool,
        pm_sender: PacketRecvChan,
        network_name: String,
        bps_limiter: Option<Arc<TokenBucket>>,
        stats_mgr: Arc<StatsManager>,
    ) -> Self {
        let label_set =
            LabelSet::new().with_label_type(LabelType::NetworkName(network_name.clone()));
        let counters = ForeignNetworkForwardCounters {
            forward_data_bytes: stats_mgr
                .get_counter(MetricName::TrafficBytesForwarded, label_set.clone()),
            forward_data_packets: stats_mgr
                .get_counter(MetricName::TrafficPacketsForwarded, label_set.clone()),
            forward_control_bytes: stats_mgr
                .get_counter(MetricName::TrafficControlBytesForwarded, label_set.clone()),
            forward_control_packets: stats_mgr.get_counter(
                MetricName::TrafficControlPacketsForwarded,
                label_set.clone(),
            ),
            rx_bytes: stats_mgr.get_counter(MetricName::TrafficBytesSelfRx, label_set.clone()),
            rx_packets: stats_mgr.get_counter(MetricName::TrafficPacketsRx, label_set),
        };

        Self {
            my_node_id,
            packet_recv,
            rpc_sender,
            peer_map,
            relay_peer_map,
            traffic_metrics,
            parent_context,
            relay_data,
            pm_sender,
            network_name,
            bps_limiter,
            counters,
        }
    }

    pub async fn run(self) {
        let Self {
            my_node_id,
            mut packet_recv,
            rpc_sender,
            peer_map,
            relay_peer_map,
            traffic_metrics,
            parent_context,
            relay_data,
            pm_sender,
            network_name,
            bps_limiter,
            counters,
        } = self;

        while let Ok(mut zc_packet) = recv_packet_from_chan(&mut packet_recv).await {
            let buf_len = zc_packet.buf_len();
            let Some(hdr) = zc_packet.peer_manager_header() else {
                tracing::warn!("invalid packet, skip");
                continue;
            };
            tracing::trace!(?hdr, "recv packet in foreign network manager");
            let from_peer_id = hdr.from_peer_id.get();
            let packet_type = hdr.packet_type;
            let len = hdr.len.get();
            let to_peer_id = hdr.to_peer_id.get();
            let is_local_delivery = to_peer_id == my_node_id;
            let is_locally_originated = from_peer_id == my_node_id;
            if is_local_delivery && !is_locally_originated {
                traffic_metrics
                    .record_rx(from_peer_id, packet_type, buf_len as u64)
                    .await;
            }
            if is_local_delivery {
                if packet_type == PacketType::RelayHandshake as u8
                    || packet_type == PacketType::RelayHandshakeAck as u8
                {
                    let _ = relay_peer_map.handle_handshake_packet(zc_packet).await;
                    continue;
                }

                if relay_peer_map.is_secure_mode_enabled() && hdr.is_encrypted() {
                    match relay_peer_map.decrypt_if_needed(&mut zc_packet).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::error!("secure session not found");
                            continue;
                        }
                        Err(e) => {
                            tracing::error!(?e, "secure decrypt failed");
                            continue;
                        }
                    }
                }

                if packet_type == PacketType::TaRpc as u8
                    || packet_type == PacketType::RpcReq as u8
                    || packet_type == PacketType::RpcResp as u8
                {
                    counters.rx_bytes.add(buf_len as u64);
                    counters.rx_packets.inc();
                    rpc_sender.send(zc_packet).unwrap();
                    continue;
                }
                tracing::trace!(
                    ?packet_type,
                    ?len,
                    ?from_peer_id,
                    ?to_peer_id,
                    "ignore packet in foreign network"
                );
            } else {
                if is_relay_data_packet_type(packet_type) {
                    let disable_relay_data = parent_context.disable_relay_data();
                    if !relay_data || disable_relay_data {
                        tracing::debug!(
                            ?from_peer_id,
                            ?to_peer_id,
                            packet_type,
                            disable_relay_data,
                            "drop foreign network relay data"
                        );
                        continue;
                    }
                    if let Some(bps_limiter) = bps_limiter.as_ref()
                        && !bps_limiter.try_consume(len.into())
                    {
                        continue;
                    }
                }

                match traffic_kind(packet_type) {
                    TrafficKind::Data => {
                        counters.forward_data_bytes.add(buf_len as u64);
                        counters.forward_data_packets.inc();
                    }
                    TrafficKind::Control => {
                        counters.forward_control_bytes.add(buf_len as u64);
                        counters.forward_control_packets.inc();
                    }
                }

                let gateway_peer_id = peer_map
                    .get_gateway_peer_id(to_peer_id, NextHopPolicy::LeastHop)
                    .await;

                match gateway_peer_id {
                    Some(peer_id) if peer_map.has_peer(peer_id) => {
                        if peer_id != to_peer_id && hdr.from_peer_id.get() == my_node_id {
                            if let Err(e) = relay_peer_map
                                .send_msg(zc_packet, to_peer_id, NextHopPolicy::LeastHop)
                                .await
                            {
                                tracing::error!(
                                    ?e,
                                    "send packet to foreign peer inside relay peer map failed"
                                );
                            } else if is_locally_originated {
                                traffic_metrics
                                    .record_tx(to_peer_id, packet_type, buf_len as u64)
                                    .await;
                            }
                        } else if let Err(e) = peer_map.send_msg_directly(zc_packet, peer_id).await
                        {
                            tracing::error!(
                                ?e,
                                "send packet to foreign peer inside peer map failed"
                            );
                        } else if is_locally_originated {
                            traffic_metrics
                                .record_tx(to_peer_id, packet_type, buf_len as u64)
                                .await;
                        }
                    }
                    _ => {
                        let mut foreign_packet = ZCPacket::new_for_foreign_network(
                            &network_name,
                            to_peer_id,
                            &zc_packet,
                        );
                        let via_peer = gateway_peer_id.unwrap_or(to_peer_id);
                        foreign_packet.fill_peer_manager_hdr(
                            my_node_id,
                            via_peer,
                            PacketType::ForeignNetworkPacket as u8,
                        );
                        if let Err(e) = pm_sender.send(foreign_packet).await {
                            tracing::error!("send packet to peer with pm failed: {:?}", e);
                        } else if is_locally_originated {
                            traffic_metrics
                                .record_tx(to_peer_id, packet_type, buf_len as u64)
                                .await;
                        }
                    }
                };
            }
        }
    }
}

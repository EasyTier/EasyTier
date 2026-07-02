use std::sync::{Arc, Weak};

use anyhow::Context;
use tokio::sync::{
    Mutex,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{config::PeerId, packet::ZCPacket};

use super::{
    encrypt::Encryptor, error::Error, foreign_network_client::ForeignNetworkClient,
    peer_map::PeerMap, peer_rpc::PeerRpcManagerTransport, relay_peer_map::RelayPeerMap,
    route_trait::NextHopPolicy, traffic_metrics::TrafficMetricRecorder,
};

pub struct RpcTransport {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    // TODO: this seems can be removed
    foreign_peers: Mutex<Option<Weak<ForeignNetworkClient>>>,

    packet_recv: Mutex<UnboundedReceiver<ZCPacket>>,
    peer_rpc_tspt_sender: UnboundedSender<ZCPacket>,

    encryptor: Arc<dyn Encryptor>,
    is_secure_mode_enabled: bool,
}

impl RpcTransport {
    pub fn new(
        my_peer_id: PeerId,
        peers: Weak<PeerMap>,
        encryptor: Arc<dyn Encryptor>,
        is_secure_mode_enabled: bool,
    ) -> Arc<Self> {
        let (peer_rpc_tspt_sender, peer_rpc_tspt_recv) = mpsc::unbounded_channel();
        Arc::new(Self {
            my_peer_id,
            peers,
            foreign_peers: Mutex::new(None),
            packet_recv: Mutex::new(peer_rpc_tspt_recv),
            peer_rpc_tspt_sender,
            encryptor,
            is_secure_mode_enabled,
        })
    }

    pub fn packet_sender(&self) -> UnboundedSender<ZCPacket> {
        self.peer_rpc_tspt_sender.clone()
    }

    pub async fn set_foreign_peers(&self, foreign_peers: Option<Weak<ForeignNetworkClient>>) {
        *self.foreign_peers.lock().await = foreign_peers;
    }
}

#[async_trait::async_trait]
impl PeerRpcManagerTransport for RpcTransport {
    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn send(&self, mut msg: ZCPacket, dst_peer_id: PeerId) -> anyhow::Result<()> {
        let peers = self
            .peers
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("peer map is gone"))?;
        // NOTE: if route info is not exchanged, this will return None. treat it as public server.
        let is_dst_peer_public_server = peers
            .get_route_peer_info(dst_peer_id)
            .await
            .and_then(|x| x.feature_flag.map(|x| x.is_public_server))
            // if dst is directly connected, it's must not public server
            .unwrap_or(!peers.has_peer(dst_peer_id));
        if !is_dst_peer_public_server && !self.is_secure_mode_enabled {
            self.encryptor
                .encrypt(&mut msg)
                .with_context(|| "encrypt failed")?;
        }
        // send to self and this packet will be forwarded in peer_recv loop
        peers.send_msg_directly(msg, self.my_peer_id).await?;
        Ok(())
    }

    async fn recv(&self) -> anyhow::Result<ZCPacket> {
        if let Some(o) = self.packet_recv.lock().await.recv().await {
            Ok(o)
        } else {
            Err(anyhow::anyhow!("rpc transport is closed"))
        }
    }
}

pub fn get_next_hop_policy(is_latency_first: bool) -> NextHopPolicy {
    if is_latency_first {
        NextHopPolicy::LeastCost
    } else {
        NextHopPolicy::LeastHop
    }
}

pub async fn send_msg_internal(
    peers: &PeerMap,
    foreign_network_client: &Arc<ForeignNetworkClient>,
    relay_peer_map: &Arc<RelayPeerMap>,
    direct_tx_metrics: Option<&Arc<TrafficMetricRecorder>>,
    msg: ZCPacket,
    dst_peer_id: PeerId,
) -> Result<(), Error> {
    let policy = get_next_hop_policy(msg.peer_manager_header().unwrap().is_latency_first());
    let is_latency_first = msg.peer_manager_header().unwrap().is_latency_first();
    let packet_type = msg.peer_manager_header().unwrap().packet_type;
    let msg_len = msg.buf_len() as u64;
    let latency_first_gateway = if is_latency_first {
        peers
            .get_gateway_peer_id(dst_peer_id, policy.clone())
            .await
            .filter(|gateway| *gateway != dst_peer_id)
    } else {
        None
    };
    let send_result = if let Some(gateway) = latency_first_gateway
        && (peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway))
    {
        relay_peer_map
            .send_msg(msg, dst_peer_id, policy)
            .await
            .map_err(Error::from)
    } else if peers.has_peer(dst_peer_id) {
        peers.send_msg_directly(msg, dst_peer_id).await
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else if let Some(gateway) = peers.get_gateway_peer_id(dst_peer_id, policy.clone()).await {
        if peers.has_peer(gateway) || foreign_network_client.has_next_hop(gateway) {
            relay_peer_map
                .send_msg(msg, dst_peer_id, policy)
                .await
                .map_err(Error::from)
        } else {
            tracing::warn!(
                ?gateway,
                ?dst_peer_id,
                "cannot send msg to peer through gateway"
            );
            Err(Error::RouteError(None))
        }
    } else if foreign_network_client.has_next_hop(dst_peer_id) {
        // check foreign network again. so in happy path we can avoid extra check
        foreign_network_client.send_msg(msg, dst_peer_id).await
    } else {
        tracing::debug!(?dst_peer_id, "no gateway for peer");
        Err(Error::RouteError(None))
    };

    if send_result.is_ok()
        && let Some(metrics) = direct_tx_metrics
    {
        metrics.record_tx(dst_peer_id, packet_type, msg_len).await;
    }

    send_result
}

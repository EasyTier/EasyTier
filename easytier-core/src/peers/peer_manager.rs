use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

use anyhow::Context;
use dashmap::DashMap;
use quanta::Instant;
use tokio::sync::{
    Mutex,
    mpsc::{self, UnboundedReceiver, UnboundedSender},
};

use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
};

use super::{
    context::NetworkIdentity,
    encrypt::Encryptor,
    error::Error,
    foreign_network_client::ForeignNetworkClient,
    foreign_network_manager::ForeignNetworkRouteInfoProvider,
    peer_conn::PeerConn,
    peer_map::PeerMap,
    peer_rpc::PeerRpcManagerTransport,
    peer_task::ExternalTaskSignal,
    relay_peer_map::RelayPeerMap,
    route_trait::{ForeignNetworkRouteInfoMap, NextHopPolicy, RouteInterface, RouteInterfaceBox},
    traffic_metrics::TrafficMetricRecorder,
    util::shrink_dashmap,
};
use crate::proto::peer_rpc::{
    ForeignNetworkRouteInfoEntry, ForeignNetworkRouteInfoKey, PeerIdentityType,
};
use crate::stats_manager::{LabelSet, LabelType, MetricName, StatsManager};

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

fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
    network
        .network_secret_digest
        .as_ref()
        .is_none_or(|d| d.iter().all(|b| *b == 0))
}

pub async fn add_new_peer_conn(
    peer_map: &PeerMap,
    local_identity: &NetworkIdentity,
    local_secure_mode: bool,
    peer_conn: PeerConn,
) -> Result<PeerId, Error> {
    let peer_identity = peer_conn.get_network_identity();
    let conn_info = peer_conn.get_conn_info();
    let peer_secure_mode = !conn_info.noise_remote_static_pubkey.is_empty();

    if local_secure_mode != peer_secure_mode {
        return Err(Error::SecretKeyError(
            "same-network peers must use the same secure mode".to_string(),
        ));
    }

    // For credential nodes, network_secret_digest is either None or all-zeros
    // (all-zeros when received over the wire via handshake).
    // In this case, only compare network_name.
    let my_digest_empty = network_secret_digest_is_empty(local_identity);
    let peer_digest_empty = network_secret_digest_is_empty(&peer_identity);

    let identity_ok = if my_digest_empty || peer_digest_empty {
        // Credential node: only check network_name
        local_identity.network_name == peer_identity.network_name
    } else {
        local_identity == &peer_identity
    };

    if !identity_ok {
        return Err(Error::SecretKeyError(
            "network identity not match".to_string(),
        ));
    }
    let peer_id = peer_conn.get_peer_id();
    peer_map.add_new_peer_conn(peer_conn).await?;
    Ok(peer_id)
}

pub async fn close_untrusted_credential_peers<F>(
    peer_map: &PeerMap,
    network_name: &str,
    mut is_pubkey_trusted: F,
) where
    F: FnMut(&[u8], &str) -> bool + Send,
{
    for peer_id in peer_map.list_peers() {
        if !matches!(
            peer_map.get_peer_identity_type(peer_id),
            Some(PeerIdentityType::Credential)
        ) {
            continue;
        }
        let Some(peer) = peer_map.get_peer_by_id(peer_id) else {
            continue;
        };
        let Some(pubkey) = peer.get_peer_public_key() else {
            continue;
        };

        if is_pubkey_trusted(&pubkey, network_name) {
            continue;
        }

        tracing::warn!(?peer_id, "closing untrusted credential peer");
        if let Err(e) = peer_map.close_peer(peer_id).await {
            tracing::warn!(?e, ?peer_id, "failed to close untrusted credential peer");
        }
    }
}

// Keep lazy-p2p demand alive across the 5s task rescan interval and a full on-demand
// connect attempt, without retaining extra per-task state in the hot path.
pub const RECENT_HAVE_TRAFFIC_TTL: Duration = Duration::from_secs(30);

pub fn should_mark_recent_traffic_for_fanout(total_dst_peers: usize) -> bool {
    total_dst_peers <= 1
}

fn gc_recent_traffic_entries<F>(
    recent_have_traffic: &DashMap<PeerId, Instant>,
    now: Instant,
    mut has_directly_connected_conn: F,
) where
    F: FnMut(PeerId) -> bool,
{
    let mut to_remove = Vec::new();
    for entry in recent_have_traffic.iter() {
        let peer_id = *entry.key();
        let expired = now.saturating_duration_since(*entry.value()) > RECENT_HAVE_TRAFFIC_TTL;
        if expired || has_directly_connected_conn(peer_id) {
            to_remove.push(peer_id);
        }
    }

    if !to_remove.is_empty() {
        for peer_id in to_remove {
            recent_have_traffic.remove(&peer_id);
        }
        shrink_dashmap(recent_have_traffic, None);
    }
}

#[derive(Clone)]
pub struct RecentTrafficTracker {
    my_peer_id: PeerId,
    recent_have_traffic: Arc<DashMap<PeerId, Instant>>,
    p2p_demand_notify: Arc<ExternalTaskSignal>,
}

impl RecentTrafficTracker {
    pub fn new(my_peer_id: PeerId) -> Self {
        Self {
            my_peer_id,
            recent_have_traffic: Arc::new(DashMap::new()),
            p2p_demand_notify: Arc::new(ExternalTaskSignal::new()),
        }
    }

    pub fn mark<F>(
        &self,
        dst_peer_id: PeerId,
        disable_p2p: bool,
        lazy_p2p: bool,
        mut has_directly_connected_conn: F,
    ) where
        F: FnMut(PeerId) -> bool,
    {
        if dst_peer_id == self.my_peer_id {
            return;
        }

        if disable_p2p || !lazy_p2p || has_directly_connected_conn(dst_peer_id) {
            return;
        }

        let now = Instant::now();
        if let Some(mut last_seen) = self.recent_have_traffic.get_mut(&dst_peer_id) {
            let should_notify = now.saturating_duration_since(*last_seen) > RECENT_HAVE_TRAFFIC_TTL;
            *last_seen = now;
            if !should_notify {
                return;
            }
        } else {
            self.recent_have_traffic.insert(dst_peer_id, now);
        }
        self.p2p_demand_notify.notify();
    }

    pub fn has<F>(&self, peer_id: PeerId, now: Instant, mut has_directly_connected_conn: F) -> bool
    where
        F: FnMut(PeerId) -> bool,
    {
        if has_directly_connected_conn(peer_id) {
            return false;
        }

        self.recent_have_traffic
            .get(&peer_id)
            .map(|last_seen| now.saturating_duration_since(*last_seen) <= RECENT_HAVE_TRAFFIC_TTL)
            .unwrap_or(false)
    }

    pub fn clear(&self, peer_id: PeerId) {
        self.recent_have_traffic.remove(&peer_id);
    }

    pub fn gc<F>(&self, now: Instant, has_directly_connected_conn: F)
    where
        F: FnMut(PeerId) -> bool,
    {
        gc_recent_traffic_entries(
            self.recent_have_traffic.as_ref(),
            now,
            has_directly_connected_conn,
        );
    }

    pub fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal> {
        self.p2p_demand_notify.clone()
    }
}

#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc)]
pub trait ForeignNetworkPacketHandler: Send + Sync + 'static {
    fn get_network_peer_id(&self, network_name: &str) -> Option<PeerId>;

    async fn forward_foreign_network_packet(
        &self,
        network_name: &str,
        dst_peer_id: PeerId,
        msg: ZCPacket,
    ) -> anyhow::Result<()>;
}

pub fn is_relay_data_packet(packet_type: u8) -> bool {
    super::traffic_metrics::is_relay_data_packet_type(packet_type)
}

pub fn is_relay_data_zc_packet(packet: &ZCPacket) -> bool {
    let Some(hdr) = packet.peer_manager_header() else {
        return false;
    };

    if hdr.packet_type == PacketType::ForeignNetworkPacket as u8 {
        let inner_packet_type = packet.foreign_network_inner_packet_type();
        if inner_packet_type.is_none() {
            tracing::warn!(
                ?hdr,
                "foreign network packet has unparseable inner peer manager header"
            );
        }
        return inner_packet_type.is_none_or(is_relay_data_packet);
    }

    is_relay_data_packet(hdr.packet_type)
}

pub async fn try_handle_foreign_network_packet<H>(
    mut packet: ZCPacket,
    my_peer_id: PeerId,
    peer_map: &PeerMap,
    foreign_network_handler: &H,
    stats_manager: &StatsManager,
    disable_relay_data: bool,
) -> Result<(), ZCPacket>
where
    H: ForeignNetworkPacketHandler + ?Sized,
{
    let pm_header = packet.peer_manager_header().unwrap();
    if pm_header.packet_type != PacketType::ForeignNetworkPacket as u8 {
        return Err(packet);
    }

    let from_peer_id = pm_header.from_peer_id.get();
    let to_peer_id = pm_header.to_peer_id.get();

    if disable_relay_data && is_relay_data_zc_packet(&packet) {
        tracing::debug!(
            ?from_peer_id,
            ?to_peer_id,
            inner_packet_type = ?packet.foreign_network_inner_packet_type(),
            "drop foreign network relay data while relay data is disabled"
        );
        return Ok(());
    }

    let foreign_hdr = packet.foreign_network_hdr().unwrap();
    let foreign_network_name = foreign_hdr.get_network_name(packet.payload());
    let foreign_peer_id = foreign_hdr.get_dst_peer_id();

    let foreign_network_my_peer_id =
        foreign_network_handler.get_network_peer_id(&foreign_network_name);

    let buf_len = packet.buf_len();
    let label_set =
        LabelSet::new().with_label_type(LabelType::NetworkName(foreign_network_name.clone()));
    let add_counter = move |bytes_metric, packets_metric| {
        stats_manager
            .get_counter(bytes_metric, label_set.clone())
            .add(buf_len as u64);
        stats_manager.get_counter(packets_metric, label_set).inc();
    };

    // NOTICE: the to peer id is modified by the src from foreign network my peer id to the origin my peer id
    if to_peer_id == my_peer_id {
        // packet sent from other peer to me, extract the inner packet and forward it
        add_counter(
            MetricName::TrafficBytesForeignForwardRx,
            MetricName::TrafficPacketsForeignForwardRx,
        );
        if let Err(e) = foreign_network_handler
            .forward_foreign_network_packet(
                &foreign_network_name,
                foreign_peer_id,
                packet.foreign_network_packet(),
            )
            .await
        {
            tracing::debug!(
                ?e,
                ?foreign_network_name,
                ?foreign_peer_id,
                "foreign network mgr send_msg_to_peer failed"
            );
        }
        Ok(())
    } else if Some(from_peer_id) == foreign_network_my_peer_id {
        // to_peer_id is my peer id for the foreign network, need to convert to the origin my_peer_id of dst
        let Some(to_peer_id) = peer_map
            .get_origin_my_peer_id(&foreign_network_name, to_peer_id)
            .await
        else {
            tracing::debug!(
                ?foreign_network_name,
                ?to_peer_id,
                "cannot find origin my peer id for foreign network."
            );
            return Err(packet);
        };

        add_counter(
            MetricName::TrafficBytesForeignForwardTx,
            MetricName::TrafficPacketsForeignForwardTx,
        );

        // modify the to_peer id from foreign network my peer id to the origin my peer id
        packet
            .mut_peer_manager_header()
            .unwrap()
            .to_peer_id
            .set(to_peer_id);

        // packet is generated from foreign network mgr and should be forward to other peer
        if let Err(e) = peer_map
            .send_msg(packet, to_peer_id, NextHopPolicy::LeastHop)
            .await
        {
            tracing::debug!(
                ?e,
                ?to_peer_id,
                "send_msg_directly failed when forward local generated foreign network packet"
            );
        }
        Ok(())
    } else {
        // target is not me, forward it. try get origin peer id
        add_counter(
            MetricName::TrafficBytesForeignForwardForwarded,
            MetricName::TrafficPacketsForeignForwardForwarded,
        );
        Err(packet)
    }
}

pub struct PeerManagerRouteInterface {
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_network_client: Weak<ForeignNetworkClient>,
    foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
}

impl PeerManagerRouteInterface {
    pub fn new(
        my_peer_id: PeerId,
        peers: Weak<PeerMap>,
        foreign_network_client: Weak<ForeignNetworkClient>,
        foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
    ) -> Self {
        Self {
            my_peer_id,
            peers,
            foreign_network_client,
            foreign_network_provider,
        }
    }
}

#[async_trait::async_trait]
impl RouteInterface for PeerManagerRouteInterface {
    async fn list_peers(&self) -> Vec<PeerId> {
        let Some(foreign_client) = self.foreign_network_client.upgrade() else {
            return vec![];
        };

        let Some(peer_map) = self.peers.upgrade() else {
            return vec![];
        };

        let mut peers = foreign_client.list_public_peers().await;
        peers.extend(peer_map.list_peers_with_conn().await);
        peers
    }

    fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    async fn close_peer(&self, peer_id: PeerId) {
        if let Some(peer_map) = self.peers.upgrade() {
            let _ = peer_map.close_peer(peer_id).await;
        }

        if let Some(foreign_client) = self.foreign_network_client.upgrade() {
            let _ = foreign_client.get_peer_map().close_peer(peer_id).await;
        }
    }

    async fn get_peer_public_key(&self, peer_id: PeerId) -> Option<Vec<u8>> {
        let peer_map = self.peers.upgrade()?;
        peer_map.get_peer_public_key(peer_id)
    }

    async fn get_peer_identity_type(&self, peer_id: PeerId) -> Option<PeerIdentityType> {
        let peer_map = self.peers.upgrade()?;
        peer_map.get_peer_identity_type(peer_id)
    }

    async fn list_foreign_networks(&self) -> ForeignNetworkRouteInfoMap {
        let ret = ForeignNetworkRouteInfoMap::new();
        let Some(provider) = self.foreign_network_provider.upgrade() else {
            return ret;
        };

        let networks = provider.list_foreign_network_route_infos().await;
        for info in networks {
            if info.peer_ids.is_empty() {
                continue;
            }

            let last_update = provider
                .get_foreign_network_last_update(&info.network_name)
                .unwrap_or(SystemTime::now());
            ret.insert(
                ForeignNetworkRouteInfoKey {
                    peer_id: self.my_peer_id,
                    network_name: info.network_name,
                },
                ForeignNetworkRouteInfoEntry {
                    foreign_peer_ids: info.peer_ids,
                    last_update: Some(last_update.into()),
                    version: 0,
                    network_secret_digest: info.network_secret_digest,
                    my_peer_id_for_this_network: info.my_peer_id_for_this_network,
                },
            );
        }
        ret
    }
}

pub fn peer_manager_route_interface(
    my_peer_id: PeerId,
    peers: Weak<PeerMap>,
    foreign_network_client: Weak<ForeignNetworkClient>,
    foreign_network_provider: Weak<dyn ForeignNetworkRouteInfoProvider>,
) -> RouteInterfaceBox {
    Box::new(PeerManagerRouteInterface::new(
        my_peer_id,
        peers,
        foreign_network_client,
        foreign_network_provider,
    ))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use dashmap::DashMap;
    use quanta::Instant;

    use super::*;

    #[test]
    fn recent_traffic_fanout_policy_only_marks_single_peer() {
        assert!(should_mark_recent_traffic_for_fanout(0));
        assert!(should_mark_recent_traffic_for_fanout(1));
        assert!(!should_mark_recent_traffic_for_fanout(2));
    }

    #[test]
    fn gc_recent_traffic_removes_expired_and_connected_entries() {
        let stale_peer = 1;
        let direct_peer = 2;
        let active_peer = 3;
        let recent_have_traffic = DashMap::new();

        recent_have_traffic.insert(
            stale_peer,
            Instant::now() - RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1),
        );
        recent_have_traffic.insert(direct_peer, Instant::now());
        recent_have_traffic.insert(active_peer, Instant::now());

        let future_peer = 4;
        recent_have_traffic.insert(future_peer, Instant::now() + Duration::from_secs(1));

        gc_recent_traffic_entries(&recent_have_traffic, Instant::now(), |peer_id| {
            peer_id == direct_peer
        });

        assert!(!recent_have_traffic.contains_key(&stale_peer));
        assert!(!recent_have_traffic.contains_key(&direct_peer));
        assert!(recent_have_traffic.contains_key(&active_peer));
        assert!(recent_have_traffic.contains_key(&future_peer));
    }

    #[test]
    fn recent_traffic_notifies_only_when_demand_becomes_active() {
        let tracker = RecentTrafficTracker::new(1);
        let peer_id = 2;
        let signal = tracker.p2p_demand_notify();

        let initial_version = signal.version();
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(signal.version(), initial_version + 1);

        let first_seen = *tracker.recent_have_traffic.get(&peer_id).unwrap();
        std::thread::sleep(Duration::from_millis(5));
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(
            signal.version(),
            initial_version + 1,
            "fresh demand should not wake all p2p workers again"
        );
        let refreshed_seen = *tracker.recent_have_traffic.get(&peer_id).unwrap();
        assert!(refreshed_seen > first_seen);

        if let Some(mut last_seen) = tracker.recent_have_traffic.get_mut(&peer_id) {
            *last_seen = Instant::now() - RECENT_HAVE_TRAFFIC_TTL - Duration::from_millis(1);
        }
        tracker.mark(peer_id, false, true, |_| false);
        assert_eq!(signal.version(), initial_version + 2);
    }

    #[test]
    fn recent_traffic_tolerates_future_timestamps() {
        let tracker = RecentTrafficTracker::new(1);
        let peer_id = 2;
        tracker
            .recent_have_traffic
            .insert(peer_id, Instant::now() + Duration::from_secs(1));

        assert!(tracker.has(peer_id, Instant::now(), |_| false));
        tracker.mark(peer_id, false, true, |_| false);
    }
}

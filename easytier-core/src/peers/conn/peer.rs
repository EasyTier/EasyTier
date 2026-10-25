use std::{
    collections::{HashMap, hash_map::RandomState},
    hash::BuildHasher,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use crossbeam_utils::atomic::AtomicCell;
use dashmap::{DashMap, DashSet};
use parking_lot::{Mutex, RwLock};

use tokio::{select, sync::mpsc};

use tracing::Instrument;

use super::peer_conn::{PeerConn, PeerConnId};
use crate::peers::{
    PacketRecvChan,
    context::{ArcPeerContext, PeerEvent},
    util::shrink_dashmap,
};
use crate::{
    config::PeerId,
    foundation::small_map_shard_amount,
    packet::{FlowKey, ZCPacket},
    peers::error::Error,
    proto::{core_peer::peer::PeerConnInfo, peer_rpc::PeerIdentityType},
};
use tokio_util::task::AbortOnDropHandle;

type ArcPeerConn = Arc<PeerConn>;
type ConnMap = Arc<DashMap<PeerConnId, ArcPeerConn>>;

struct FlowBinding {
    conn_id: PeerConnId,
    last_active: Instant,
}

#[derive(Default)]
struct FlowBindings {
    hash: RandomState,
    buckets: HashMap<usize, FlowBinding>,
}

impl FlowBindings {
    const BUCKETS: usize = 4096;
    const IDLE_TIMEOUT: Duration = Duration::from_secs(120);

    fn bucket(&self, key: FlowKey) -> usize {
        self.hash.hash_one(key) as usize % Self::BUCKETS
    }
}

fn conn_selection_key(conn: &PeerConn) -> (bool, u8, u64) {
    let latency = conn.quality.latency();
    let previous = conn.get_stats().latency_us;
    (
        conn.quality.is_degraded(),
        if latency.is_some() {
            0
        } else if previous > 0 {
            1
        } else if conn.is_hole_punched() {
            // Prefer regular connections until hole punching has a measured RTT.
            3
        } else {
            2
        },
        latency.unwrap_or(if previous > 0 { previous } else { u64::MAX }),
    )
}

pub struct Peer {
    pub peer_node_id: PeerId,
    conns: ConnMap,
    context: ArcPeerContext,

    packet_recv_chan: PacketRecvChan,

    close_event_sender: mpsc::Sender<PeerConnId>,
    #[allow(dead_code)]
    close_event_listener: AbortOnDropHandle<()>,

    shutdown_notifier: Arc<tokio::sync::Notify>,

    default_conn: Arc<ArcSwapOption<PeerConn>>,
    default_conn_update_lock: Arc<Mutex<()>>,
    flow_bindings: Mutex<FlowBindings>,
    data_active: Arc<AtomicBool>,
    peer_identity_type: Arc<AtomicCell<Option<PeerIdentityType>>>,
    peer_public_key: Arc<RwLock<Option<Vec<u8>>>>,
    #[allow(dead_code)]
    default_conn_clear_task: AbortOnDropHandle<()>,
}

impl Peer {
    pub(crate) fn new(
        peer_node_id: PeerId,
        packet_recv_chan: PacketRecvChan,
        context: ArcPeerContext,
    ) -> Self {
        let conns: ConnMap = Arc::new(DashMap::with_shard_amount(small_map_shard_amount()));
        let (close_event_sender, mut close_event_receiver) = mpsc::channel(10);
        let shutdown_notifier = Arc::new(tokio::sync::Notify::new());
        let peer_identity_type = Arc::new(AtomicCell::new(None));
        let peer_identity_type_copy = peer_identity_type.clone();
        let peer_public_key = Arc::new(RwLock::new(None));
        let peer_public_key_copy = peer_public_key.clone();
        let default_conn = Arc::new(ArcSwapOption::empty());
        let default_conn_update_lock = Arc::new(Mutex::new(()));
        let data_active = Arc::new(AtomicBool::new(false));

        let conns_copy = conns.clone();
        let shutdown_notifier_copy = shutdown_notifier.clone();
        let context_copy = context.clone();
        let default_conn_copy = default_conn.clone();
        let default_conn_update_lock_copy = default_conn_update_lock.clone();
        let close_event_listener = AbortOnDropHandle::new(tokio::spawn(
            async move {
                loop {
                    select! {
                        ret = close_event_receiver.recv() => {
                            if ret.is_none() {
                                break;
                            }
                            let ret = ret.unwrap();
                            tracing::warn!(
                                ?peer_node_id,
                                ?ret,
                                "notified that peer conn is closed",
                            );

                            let removed_conn = {
                                let _update_guard = default_conn_update_lock_copy.lock();
                                let removed_conn = conns_copy.remove(&ret);
                                if let Some((_, conn)) = removed_conn.as_ref() {
                                    let cached_conn = default_conn_copy.load();
                                    if cached_conn
                                        .as_ref()
                                        .is_some_and(|cached| Arc::ptr_eq(cached, conn))
                                    {
                                        default_conn_copy.store(None);
                                    }
                                }
                                removed_conn
                            };

                            if let Some((_, conn)) = removed_conn {
                                context_copy.issue_event(PeerEvent::PeerConnRemoved(
                                    conn.get_conn_info(),
                                ));
                                shrink_dashmap(&conns_copy, Some(4));
                                if conns_copy.is_empty() {
                                    peer_identity_type_copy.store(None);
                                    *peer_public_key_copy.write() = None;
                                }
                            }
                        }

                        _ = shutdown_notifier_copy.notified() => {
                            close_event_receiver.close();
                            tracing::warn!(?peer_node_id, "peer close event listener notified");
                        }
                    }
                }
                tracing::info!("peer {} close event listener exit", peer_node_id);
            }
            .instrument(tracing::info_span!(
                "peer_close_event_listener",
                ?peer_node_id,
            )),
        ));

        let conns_copy = conns.clone();
        let default_conn_copy = default_conn.clone();
        let data_active_copy = data_active.clone();
        let default_conn_clear_task = AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                crate::foundation::time::sleep(std::time::Duration::from_secs(5)).await;
                if conns_copy.len() > 1 {
                    default_conn_copy.store(None);
                }
                let active = data_active_copy.swap(false, Ordering::Relaxed);
                let fast_ping = conns_copy.len() > 1 && active;
                for conn in conns_copy.iter() {
                    conn.quality.fast_ping.store(fast_ping, Ordering::Relaxed);
                }
            }
        }));

        Peer {
            peer_node_id,
            conns,
            packet_recv_chan,
            context,

            close_event_sender,
            close_event_listener,

            shutdown_notifier,
            default_conn,
            default_conn_update_lock,
            flow_bindings: Mutex::new(FlowBindings::default()),
            data_active,
            peer_identity_type,
            peer_public_key,
            default_conn_clear_task,
        }
    }

    pub async fn add_peer_conn(&self, mut conn: PeerConn) -> Result<(), Error> {
        let conn_identity_type = conn.get_peer_identity_type();
        let peer_identity_type = self.peer_identity_type.load();
        if let Some(peer_identity_type) = peer_identity_type {
            if peer_identity_type != conn_identity_type {
                return Err(Error::SecretKeyError(format!(
                    "peer identity type mismatch. peer: {:?}, conn: {:?}",
                    peer_identity_type, conn_identity_type
                )));
            }
        } else {
            self.peer_identity_type.store(Some(conn_identity_type));
        }

        let close_notifier = conn.get_close_notifier();
        let conn_info = conn.get_conn_info();
        let conn_pubkey = conn_info.noise_remote_static_pubkey.clone();
        {
            let mut peer_pubkey = self.peer_public_key.write();
            if let Some(existing_pubkey) = peer_pubkey.as_ref() {
                if existing_pubkey != &conn_pubkey {
                    return Err(Error::SecretKeyError(format!(
                        "peer public key mismatch. peer_id: {}, existing_len: {}, new_len: {}",
                        self.peer_node_id,
                        existing_pubkey.len(),
                        conn_pubkey.len()
                    )));
                }
            } else {
                *peer_pubkey = Some(conn_pubkey);
            }
        }

        conn.start_recv_loop(self.packet_recv_chan.clone()).await;
        conn.start_pingpong();
        self.conns.insert(conn.get_conn_id(), Arc::new(conn));

        let close_event_sender = self.close_event_sender.clone();
        tokio::spawn(async move {
            let conn_id = close_notifier.get_conn_id();
            if let Some(mut waiter) = close_notifier.get_waiter().await {
                let _ = waiter.recv().await;
            }
            if let Err(e) = close_event_sender.send(conn_id).await {
                tracing::warn!(?conn_id, "failed to send close event: {}", e);
            }
        });

        self.context
            .issue_event(PeerEvent::PeerConnAdded(conn_info));
        Ok(())
    }

    fn select_conn(&self) -> Option<ArcPeerConn> {
        let _update_guard = self.default_conn_update_lock.lock();
        if let Some(conn) = self.default_conn.load_full()
            && !conn.is_closed()
            && !conn.quality.is_degraded()
        {
            return Some(conn);
        }

        // Unmeasured paths are usable for startup/recovery, but cannot outrank a
        // healthy path with a fresh Pong merely because their RTT is still zero.
        let selected = self
            .conns
            .iter()
            .filter(|conn| !conn.is_closed())
            .min_by_key(|conn| conn_selection_key(conn.value()))
            .map(|conn| conn.value().clone());

        if let Some(conn) = selected.as_ref() {
            self.default_conn.store(Some(conn.clone()));
        }
        selected
    }

    fn select_flow_conn(&self, key: FlowKey) -> Option<ArcPeerConn> {
        let mut flows = self.flow_bindings.lock();
        let bucket = flows.bucket(key);
        if let Some(binding) = flows.buckets.get_mut(&bucket)
            && binding.last_active.elapsed() < FlowBindings::IDLE_TIMEOUT
        {
            let bound = self
                .conns
                .get(&binding.conn_id)
                .map(|conn| conn.value().clone());
            if let Some(conn) = bound.filter(|conn| !conn.is_closed()) {
                binding.last_active = Instant::now();
                if conn.quality.is_degraded() {
                    let replacement = self
                        .conns
                        .iter()
                        .filter(|entry| {
                            !entry.is_closed()
                                && !entry.quality.is_degraded()
                                && entry.quality.latency().is_some()
                        })
                        .min_by_key(|entry| conn_selection_key(entry.value()))
                        .map(|entry| entry.value().clone());
                    if let Some(replacement) = replacement {
                        tracing::debug!(peer_id = self.peer_node_id, old = ?binding.conn_id,
                            new = ?replacement.get_conn_id(), "migrate flow bucket from degraded connection");
                        binding.conn_id = replacement.get_conn_id();
                        return Some(replacement);
                    }
                }
                return Some(conn);
            }
        }
        let conn = self.select_conn()?;
        // A collision joins the bucket's active binding rather than evicting an
        // existing flow. This bounds memory without migrating flows under load.
        flows.buckets.insert(
            bucket,
            FlowBinding {
                conn_id: conn.get_conn_id(),
                last_active: Instant::now(),
            },
        );
        Some(conn)
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        if crate::peers::traffic_metrics::data_packet_payload_len(&msg).is_some() {
            self.data_active.store(true, Ordering::Relaxed);
        }
        if let Some(key) = msg.flow_key {
            let conn = self
                .select_flow_conn(key)
                .ok_or(Error::PeerNoConnectionError(self.peer_node_id))?;
            conn.send_msg(msg).await?;
            return Ok(());
        }
        let default_conn = self.default_conn.load();
        if let Some(conn) = default_conn.as_ref()
            && !conn.is_closed()
        {
            conn.send_msg(msg).await?;
            return Ok(());
        }
        drop(default_conn);

        let Some(conn) = self.select_conn() else {
            return Err(Error::PeerNoConnectionError(self.peer_node_id));
        };
        conn.send_msg(msg).await?;

        Ok(())
    }

    pub async fn close_peer_conn(&self, conn_id: &PeerConnId) -> Result<(), Error> {
        let has_key = self.conns.contains_key(conn_id);
        if !has_key {
            return Err(Error::NotFound);
        }
        self.close_event_sender.send(*conn_id).await.unwrap();
        Ok(())
    }

    pub async fn list_peer_conns(&self) -> Vec<PeerConnInfo> {
        let mut conns = vec![];
        for conn in self.conns.iter() {
            // do not lock here, otherwise it will cause dashmap deadlock
            conns.push(conn.clone());
        }

        let mut ret = Vec::new();
        for conn in conns {
            let info = conn.get_conn_info();
            if !info.is_closed {
                ret.push(info);
            } else {
                let conn_id = info.conn_id.parse().unwrap();
                let _ = self.close_peer_conn(&conn_id).await;
            }
        }
        ret
    }

    pub fn has_live_conns(&self) -> bool {
        self.conns.iter().any(|entry| !entry.value().is_closed())
    }

    pub fn has_directly_connected_conn(&self) -> bool {
        self.conns
            .iter()
            .any(|entry| !entry.value().is_closed() && !entry.value().is_hole_punched())
    }

    pub(crate) fn has_direct_attached_conn(&self) -> bool {
        self.conns.iter().any(|entry| {
            let conn = entry.value();
            !conn.is_closed() && !conn.is_hole_punched() && conn.is_attached()
        })
    }

    pub fn get_directly_connections(&self) -> DashSet<uuid::Uuid> {
        self.conns
            .iter()
            .filter(|entry| !(entry.value()).is_hole_punched())
            .map(|entry| (entry.value()).get_conn_id())
            .collect()
    }

    pub fn get_default_conn_id(&self) -> PeerConnId {
        self.default_conn
            .load()
            .as_ref()
            .map(|conn| conn.get_conn_id())
            .unwrap_or_default()
    }

    pub fn get_peer_identity_type(&self) -> Option<PeerIdentityType> {
        self.peer_identity_type.load()
    }

    pub fn get_peer_public_key(&self) -> Option<Vec<u8>> {
        self.peer_public_key.read().clone()
    }
}

// pritn on drop
impl Drop for Peer {
    fn drop(&mut self) {
        self.conns.retain(|_, conn| {
            self.context
                .issue_event(PeerEvent::PeerConnRemoved(conn.get_conn_info()));
            false
        });
        self.shutdown_notifier.notify_one();
        tracing::info!("peer {} drop", self.peer_node_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        packet::PacketType,
        peers::{
            PeerConnectionOrigin,
            conn::{peer_conn_quality::QualityHistory, peer_session::PeerSessionStore},
            create_packet_recv_chan, recv_packet_envelope_from_chan,
            test_support::NoopPeerContext,
        },
        tunnel::ring::create_ring_tunnel_pair,
    };

    fn flow(port: u16) -> FlowKey {
        FlowKey {
            src: ([10, 0, 0, 1], port).into(),
            dst: ([10, 0, 0, 2], 5000).into(),
            protocol: 17,
        }
    }

    async fn add_connection(
        peer: &Peer,
        recv: PacketRecvChan,
        rtt: Option<u64>,
    ) -> (PeerConnId, PeerConn) {
        let (left, right) = create_ring_tunnel_pair();
        let sessions = Arc::new(PeerSessionStore::new());
        let context = Arc::new(NoopPeerContext::default());
        let mut client = PeerConn::new(1, context.clone(), left, sessions.clone());
        let mut server = PeerConn::new(2, context, right, sessions);
        let (left, right) = tokio::join!(
            client.do_handshake_as_client(),
            server.do_handshake_as_server_ext(|_, _| Ok(())),
        );
        left.unwrap();
        right.unwrap();
        server.start_recv_loop(recv).await;
        if let Some(rtt) = rtt {
            QualityHistory::default().record(&client.quality, Some(rtt), Instant::now());
        }
        let id = client.get_conn_id();
        peer.add_peer_conn(client).await.unwrap();
        (id, server)
    }

    fn new_peer() -> Peer {
        let (sender, _receiver) = create_packet_recv_chan();
        Peer::new(2, sender, Arc::new(NoopPeerContext::default()))
    }

    #[tokio::test]
    async fn send_failure_marks_connection_closed_without_waiting_for_ping() {
        let (left, right) = create_ring_tunnel_pair();
        let (stream, _sink) = right.split();
        drop(stream);
        let conn = PeerConn::new(
            1,
            Arc::new(NoopPeerContext::default()),
            left,
            Arc::new(PeerSessionStore::new()),
        );
        crate::foundation::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut packet = ZCPacket::new_with_payload(b"closed sink");
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                if conn.send_msg(packet).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn unkeyed_packet_skips_failed_connection_before_cache_cleanup() {
        let peer = new_peer();
        let (sender, mut receiver) = create_packet_recv_chan();
        let (old, old_server) = add_connection(&peer, sender.clone(), Some(20_000)).await;
        let (_, new_server) = add_connection(&peer, sender, Some(1_000)).await;
        let old_conn = peer.conns.get(&old).unwrap().value().clone();
        peer.default_conn.store(Some(old_conn.clone()));
        // Keep the stale cache entry so the result cannot depend on task ordering.
        peer.close_event_listener.abort();
        drop(old_server);
        crate::foundation::time::timeout(Duration::from_secs(1), async {
            loop {
                let mut packet = ZCPacket::new_with_payload(b"closed sink");
                packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
                if old_conn.send_msg(packet).await.is_err() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(old_conn.is_closed());
        assert_eq!(peer.get_default_conn_id(), old);

        let mut packet = ZCPacket::new_with_payload(b"unkeyed packet");
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        assert!(packet.flow_key.is_none());
        peer.send_msg(packet).await.unwrap();
        let envelope = crate::foundation::time::timeout(
            Duration::from_secs(1),
            recv_packet_envelope_from_chan(&mut receiver),
        )
        .await
        .unwrap()
        .unwrap();
        let (packet, ingress) = envelope.into_parts();
        assert_eq!(packet.payload(), b"unkeyed packet");
        assert_eq!(
            ingress.peer_connection().unwrap().1,
            new_server.get_conn_id()
        );
    }

    #[tokio::test]
    async fn unmeasured_regular_connection_precedes_unverified_hole_punch() {
        let (tunnel, _remote) = create_ring_tunnel_pair();
        let regular = PeerConn::new(
            1,
            Arc::new(NoopPeerContext::default()),
            tunnel,
            Arc::new(PeerSessionStore::new()),
        );
        for origin in [
            PeerConnectionOrigin::TcpHolePunch,
            PeerConnectionOrigin::UdpHolePunch,
        ] {
            let (tunnel, _remote) = create_ring_tunnel_pair();
            let hole_punched = PeerConn::new_with_peer_id_hint_and_origin(
                1,
                Arc::new(NoopPeerContext::default()),
                tunnel,
                None,
                Arc::new(PeerSessionStore::new()),
                origin,
            );
            assert!(conn_selection_key(&regular) < conn_selection_key(&hole_punched));
            QualityHistory::default().record(&hole_punched.quality, Some(1_000), Instant::now());
            assert!(conn_selection_key(&hole_punched) < conn_selection_key(&regular));
        }
    }

    fn distinct_flow(peer: &Peer, existing: FlowKey) -> FlowKey {
        let flows = peer.flow_bindings.lock();
        (1..=u16::MAX)
            .map(flow)
            .find(|key| flows.bucket(*key) != flows.bucket(existing))
            .unwrap()
    }

    #[tokio::test]
    async fn active_flow_survives_new_connection_and_periodic_reselection() {
        let peer = new_peer();
        let (sender, mut receiver) = create_packet_recv_chan();
        let (old, old_server) = add_connection(&peer, sender.clone(), Some(20_000)).await;
        let key = flow(1234);
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
        let (new, new_server) = add_connection(&peer, sender, Some(1_000)).await;
        peer.default_conn.store(None);
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
        let new_key = distinct_flow(&peer, key);
        assert_eq!(peer.select_flow_conn(new_key).unwrap().get_conn_id(), new);

        for (key, expected) in [
            (key, old_server.get_conn_id()),
            (new_key, new_server.get_conn_id()),
        ] {
            let mut packet = ZCPacket::new_with_payload(b"business data");
            packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
            packet.flow_key = Some(key);
            peer.send_msg(packet).await.unwrap();
            let envelope = crate::foundation::time::timeout(
                Duration::from_secs(1),
                recv_packet_envelope_from_chan(&mut receiver),
            )
            .await
            .unwrap()
            .unwrap();
            let (packet, ingress) = envelope.into_parts();
            assert_eq!(packet.payload(), b"business data");
            assert_eq!(ingress.peer_connection().unwrap().1, expected);
        }
    }

    #[tokio::test]
    async fn idle_flow_can_rebind_and_closed_connection_cannot_trap_active_flow() {
        let peer = new_peer();
        let (sender, _receiver) = create_packet_recv_chan();
        let (old, _old_server) = add_connection(&peer, sender.clone(), Some(20_000)).await;
        let key = flow(1234);
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
        let (new, _new_server) = add_connection(&peer, sender, Some(1_000)).await;
        peer.default_conn.store(None);
        {
            let mut flows = peer.flow_bindings.lock();
            let bucket = flows.bucket(key);
            flows.buckets.get_mut(&bucket).unwrap().last_active -= FlowBindings::IDLE_TIMEOUT;
        }
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), new);
        peer.close_peer_conn(&new).await.unwrap();
        crate::foundation::time::timeout(Duration::from_secs(1), async {
            while peer.conns.contains_key(&new) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
    }

    #[tokio::test]
    async fn bucket_collisions_and_capacity_never_evict_an_active_binding() {
        let peer = new_peer();
        let (sender, _receiver) = create_packet_recv_chan();
        let (old, _old_server) = add_connection(&peer, sender.clone(), Some(20_000)).await;
        for port in 1..=u16::MAX {
            assert_eq!(
                peer.select_flow_conn(flow(port)).unwrap().get_conn_id(),
                old
            );
        }
        assert!(peer.flow_bindings.lock().buckets.len() <= FlowBindings::BUCKETS);
        let (_new, _new_server) = add_connection(&peer, sender, Some(1_000)).await;
        peer.default_conn.store(None);
        for port in 1..=u16::MAX {
            assert_eq!(
                peer.select_flow_conn(flow(port)).unwrap().get_conn_id(),
                old
            );
        }
    }

    #[tokio::test]
    async fn degraded_flow_migrates_only_to_a_measured_healthy_connection() {
        let peer = new_peer();
        let (sender, _receiver) = create_packet_recv_chan();
        let (old, _old_server) = add_connection(&peer, sender.clone(), Some(15_000)).await;
        let key = flow(1234);
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
        let (new, _new_server) = add_connection(&peer, sender, None).await;
        // Unknown RTT must not become a zero-latency winner for a new flow.
        peer.default_conn.store(None);
        assert_eq!(peer.select_conn().unwrap().get_conn_id(), old);
        let quality = peer.conns.get(&old).unwrap().quality.clone();
        let mut history = QualityHistory::default();
        history.record(&quality, Some(15_000), Instant::now());
        for _ in 0..3 {
            history.record(&quality, Some(500_000), Instant::now());
        }
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), old);
        QualityHistory::default().record(
            &peer.conns.get(&new).unwrap().quality,
            Some(20_000),
            Instant::now(),
        );
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), new);
        // The original path becoming idle and faster cannot steal the old flow.
        for _ in 0..3 {
            history.record(&quality, Some(1_000), Instant::now());
        }
        peer.default_conn.store(None);
        assert_eq!(peer.select_flow_conn(key).unwrap().get_conn_id(), new);
    }
}

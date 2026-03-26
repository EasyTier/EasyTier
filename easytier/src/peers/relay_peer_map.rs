use std::{sync::Arc, time::Instant};

use dashmap::DashMap;
use prost::Message;
use snow::params::NoiseParams;
use tokio::sync::{oneshot, Mutex, OwnedMutexGuard};
use tokio::time::{timeout, Duration};

use crate::peers::foreign_network_client::ForeignNetworkClient;
use crate::{
    common::error::Error,
    common::{global_ctx::ArcGlobalCtx, PeerId},
    peers::peer_map::PeerMap,
    peers::peer_session::{PeerSession, PeerSessionAction, PeerSessionStore, SessionKey},
    peers::route_trait::NextHopPolicy,
    peers::traffic_metrics::AggregateTrafficMetrics,
    proto::peer_rpc::{PeerConnSessionActionPb, RelayNoiseMsg1Pb, RelayNoiseMsg2Pb},
    tunnel::packet_def::{PacketType, ZCPacket},
};

const RELAY_NOISE_VERSION: u32 = 1;
const RELAY_NOISE_PROLOGUE: &[u8] = b"easytier-relay-noise";
const HANDSHAKE_TIMEOUT_SECS: u64 = 5;
const HANDSHAKE_RETRY_BASE_MS: u64 = 200;
const HANDSHAKE_MAX_ATTEMPTS: u32 = 3;
const MAX_PENDING_PACKETS_PER_PEER: usize = 32;

#[derive(Clone)]
pub struct RelayPeerState {
    pub last_active_at: Instant,
    pub failure_count: u32,
    pub next_retry_at: Option<Instant>,
}

impl Default for RelayPeerState {
    fn default() -> Self {
        Self {
            last_active_at: Instant::now(),
            failure_count: 0,
            next_retry_at: None,
        }
    }
}

pub struct RelayPeerMap {
    peer_map: Arc<PeerMap>,
    foreign_network_client: Option<Arc<ForeignNetworkClient>>,
    global_ctx: ArcGlobalCtx,
    my_peer_id: PeerId,
    peer_session_store: Arc<PeerSessionStore>,
    states: DashMap<PeerId, RelayPeerState>,
    pending_handshakes: DashMap<PeerId, oneshot::Sender<ZCPacket>>,
    handshake_locks: DashMap<PeerId, Arc<Mutex<()>>>,
    pub(crate) pending_packets: DashMap<PeerId, Vec<(ZCPacket, NextHopPolicy)>>,

    is_secure_mode_enabled: bool,
    control_metrics: AggregateTrafficMetrics,
}

impl RelayPeerMap {
    pub fn new(
        peer_map: Arc<PeerMap>,
        foreign_network_client: Option<Arc<ForeignNetworkClient>>,
        global_ctx: ArcGlobalCtx,
        my_peer_id: PeerId,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Arc<Self> {
        let is_secure_mode_enabled = global_ctx
            .config
            .get_secure_mode()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false);
        Arc::new(Self {
            control_metrics: AggregateTrafficMetrics::control(
                global_ctx.stats_manager().clone(),
                global_ctx.get_network_name(),
            ),
            peer_map,
            foreign_network_client,
            global_ctx,
            my_peer_id,
            peer_session_store,
            states: DashMap::new(),
            pending_handshakes: DashMap::new(),
            handshake_locks: DashMap::new(),
            pending_packets: DashMap::new(),
            is_secure_mode_enabled,
        })
    }

    pub fn is_secure_mode_enabled(&self) -> bool {
        self.is_secure_mode_enabled
    }

    fn get_local_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let cfg = self
            .global_ctx
            .config
            .get_secure_mode()
            .ok_or_else(|| Error::RouteError(Some("secure mode config not set".to_string())))?;
        let private = cfg
            .private_key()
            .map_err(|e| Error::RouteError(Some(format!("invalid private key: {e:?}"))))?;
        let public = cfg
            .public_key()
            .map_err(|e| Error::RouteError(Some(format!("invalid public key: {e:?}"))))?;
        Ok((private.as_bytes().to_vec(), public.as_bytes().to_vec()))
    }

    async fn get_remote_static_pubkey(&self, peer_id: PeerId) -> Result<Vec<u8>, Error> {
        let info = self
            .peer_map
            .get_route_peer_info(peer_id)
            .await
            .ok_or_else(|| Error::RouteError(Some("route peer info not found".to_string())))?;
        if info.noise_static_pubkey.is_empty() {
            return Err(Error::RouteError(Some(
                "remote static pubkey not found".to_string(),
            )));
        }
        Ok(info.noise_static_pubkey)
    }

    fn get_handshake_lock(&self, peer_id: PeerId) -> Arc<Mutex<()>> {
        self.handshake_locks
            .entry(peer_id)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    async fn send_handshake_packet(
        &self,
        payload: Vec<u8>,
        packet_type: PacketType,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let mut pkt = ZCPacket::new_with_payload(&payload);
        pkt.fill_peer_manager_hdr(self.my_peer_id, dst_peer_id, packet_type as u8);
        let pkt_len = pkt.buf_len() as u64;
        self.send_via_next_hop(pkt, dst_peer_id, policy).await?;
        self.control_metrics.record_tx(pkt_len);
        Ok(())
    }

    async fn send_via_next_hop(
        &self,
        msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let Some(next_hop) = self.peer_map.get_gateway_peer_id(dst_peer_id, policy).await else {
            return Err(Error::RouteError(Some(format!(
                "next hop not found in route for peer {dst_peer_id:?}"
            ))));
        };
        if self.peer_map.has_peer(next_hop) {
            self.peer_map.send_msg_directly(msg, next_hop).await
        } else if let Some(foreign_network_client) = &self.foreign_network_client {
            foreign_network_client.send_msg(msg, next_hop).await
        } else {
            Err(Error::RouteError(Some(format!(
                "next hop not found in direct peer map: {next_hop:?}"
            ))))
        }
    }

    pub async fn send_msg(
        self: &Arc<Self>,
        mut msg: ZCPacket,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<(), Error> {
        let now = Instant::now();

        self.states.entry(dst_peer_id).or_default().last_active_at = now;

        if self.is_secure_mode_enabled() {
            match self.ensure_session(dst_peer_id, policy.clone()).await {
                Ok(session) => {
                    let my_peer_id = self.my_peer_id;
                    session
                        .encrypt_payload(my_peer_id, dst_peer_id, &mut msg)
                        .map_err(|e| Error::RouteError(Some(format!("{e:?}"))))?;
                }
                Err(_) => {
                    // Handshake in progress, buffer the packet instead of dropping it
                    self.buffer_pending_packet(dst_peer_id, msg, policy);
                    return Ok(());
                }
            }
        }

        self.send_via_next_hop(msg, dst_peer_id, policy).await
    }

    fn buffer_pending_packet(&self, dst_peer_id: PeerId, pkt: ZCPacket, policy: NextHopPolicy) {
        let mut entry = self.pending_packets.entry(dst_peer_id).or_default();
        if entry.len() < MAX_PENDING_PACKETS_PER_PEER {
            entry.push((pkt, policy));
        }
        // silently drop when buffer is full
    }

    async fn flush_pending_packets(&self, dst_peer_id: PeerId, session: Arc<PeerSession>) {
        let packets = self.pending_packets.remove(&dst_peer_id).map(|(_, v)| v);
        let Some(packets) = packets else { return };
        if packets.is_empty() {
            return;
        }

        tracing::debug!(
            ?dst_peer_id,
            count = packets.len(),
            "flushing pending packets after relay handshake"
        );

        for (mut pkt, policy) in packets {
            if session
                .encrypt_payload(self.my_peer_id, dst_peer_id, &mut pkt)
                .is_err()
            {
                continue;
            }
            let _ = self.send_via_next_hop(pkt, dst_peer_id, policy).await;
        }
    }

    pub fn has_session(&self, dst_peer_id: PeerId) -> bool {
        self.peer_session_store
            .get(&SessionKey::new(
                self.global_ctx.get_network_identity().network_name.clone(),
                dst_peer_id,
            ))
            .is_some()
    }

    pub async fn ensure_session(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<Arc<PeerSession>, Error> {
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        if let Some(session) = self.peer_session_store.get(&key) {
            return Ok(session);
        }

        let lock = self.get_handshake_lock(dst_peer_id);
        if let Ok(guard) = lock.try_lock_owned() {
            let self_clone = self.clone();
            tokio::spawn(async move {
                self_clone
                    .handshake_session(dst_peer_id, policy, Some(guard))
                    .await
            });
        };
        Err(Error::RouteError(Some(
            "relay handshake in progress".to_string(),
        )))
    }

    #[tracing::instrument(skip(self, _lock_guard), level = "debug", ret)]
    pub async fn handshake_session(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
        _lock_guard: Option<OwnedMutexGuard<()>>,
    ) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        if let Some(session) = self.peer_session_store.get(&key) {
            self.flush_pending_packets(dst_peer_id, session).await;
            return Ok(());
        }

        if let Some(next_retry_at) = self.states.get(&dst_peer_id).and_then(|v| v.next_retry_at) {
            if Instant::now() < next_retry_at {
                self.pending_packets.remove(&dst_peer_id);
                return Err(Error::RouteError(Some(
                    "relay handshake backoff".to_string(),
                )));
            }
        }

        let mut last_err = None;
        for attempt in 0..HANDSHAKE_MAX_ATTEMPTS {
            let ret = self
                .handshake_session_once(dst_peer_id, policy.clone())
                .await;
            match ret {
                Ok(session) => {
                    self.register_handshake_success(dst_peer_id);
                    self.flush_pending_packets(dst_peer_id, session).await;
                    return Ok(());
                }
                Err(e) => {
                    last_err = Some(e);
                    self.register_handshake_failure(dst_peer_id, attempt);
                    if attempt + 1 < HANDSHAKE_MAX_ATTEMPTS {
                        let backoff = HANDSHAKE_RETRY_BASE_MS.saturating_mul(1 << attempt);
                        tokio::time::sleep(Duration::from_millis(backoff)).await;
                    }
                }
            }
        }

        // All attempts failed, drop buffered packets
        self.pending_packets.remove(&dst_peer_id);

        Err(last_err
            .unwrap_or_else(|| Error::RouteError(Some("relay handshake failed".to_string()))))
    }

    #[tracing::instrument(skip(self), level = "debug", ret)]
    async fn handshake_session_once(
        &self,
        dst_peer_id: PeerId,
        policy: NextHopPolicy,
    ) -> Result<Arc<PeerSession>, Error> {
        let network = self.global_ctx.get_network_identity();
        let session_key = SessionKey::new(network.network_name.clone(), dst_peer_id);
        let (local_private_key, _local_public_key) = self.get_local_keypair()?;
        let remote_static = self.get_remote_static_pubkey(dst_peer_id).await?;
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::RouteError(Some(format!("parse noise params failed: {e:?}"))))?;

        let builder = snow::Builder::new(params);
        let mut hs = builder
            .prologue(RELAY_NOISE_PROLOGUE)
            .map_err(|e| Error::RouteError(Some(format!("set prologue failed: {e:?}"))))?
            .local_private_key(&local_private_key)
            .map_err(|e| Error::RouteError(Some(format!("set local key failed: {e:?}"))))?
            .remote_public_key(&remote_static)
            .map_err(|e| Error::RouteError(Some(format!("set remote key failed: {e:?}"))))?
            .build_initiator()
            .map_err(|e| Error::RouteError(Some(format!("build initiator failed: {e:?}"))))?;

        let a_session_generation = self
            .peer_session_store
            .get(&session_key)
            .map(|s| s.session_generation());
        let a_conn_id = uuid::Uuid::new_v4();
        let msg1_pb = RelayNoiseMsg1Pb {
            version: RELAY_NOISE_VERSION,
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.global_ctx.get_flags().encryption_algorithm.clone(),
        };
        let payload = msg1_pb.encode_to_vec();
        let mut out = vec![0u8; 4096];
        let out_len = hs
            .write_message(&payload, &mut out)
            .map_err(|e| Error::RouteError(Some(format!("noise write msg1 failed: {e:?}"))))?;
        let (tx, rx) = oneshot::channel();
        self.pending_handshakes.insert(dst_peer_id, tx);

        let send_res = self
            .send_handshake_packet(
                out[..out_len].to_vec(),
                PacketType::RelayHandshake,
                dst_peer_id,
                policy,
            )
            .await;

        if send_res.is_err() {
            self.pending_handshakes.remove(&dst_peer_id);
        }
        send_res?;
        let msg2_pkt = match timeout(Duration::from_secs(HANDSHAKE_TIMEOUT_SECS), rx).await {
            Ok(Ok(pkt)) => pkt,
            Ok(Err(_)) => {
                self.pending_handshakes.remove(&dst_peer_id);
                return Err(Error::RouteError(Some(
                    "relay handshake canceled".to_string(),
                )));
            }
            Err(_) => {
                self.pending_handshakes.remove(&dst_peer_id);
                return Err(Error::RouteError(Some(
                    "relay handshake timeout".to_string(),
                )));
            }
        };

        let msg2_pb = self.decode_handshake_message::<RelayNoiseMsg2Pb>(
            PacketType::RelayHandshakeAck,
            &mut hs,
            msg2_pkt,
        )?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::RouteError(Some(
                "relay msg2 conn_id_echo mismatch".to_string(),
            )));
        }

        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::RouteError(Some("invalid session action".to_string())))?;
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };
        let root_key_bytes = msg2_pb
            .root_key_32
            .as_deref()
            .filter(|v| v.len() == 32)
            .map(|v| {
                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(v);
                key_bytes
            });
        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let session = self
            .peer_session_store
            .apply_initiator_action(
                &session_key,
                session_action,
                msg2_pb.b_session_generation,
                root_key_bytes,
                msg2_pb.initial_epoch,
                algo,
                msg2_pb.server_encryption_algorithm.clone(),
                remote_static_key,
            )
            .map_err(|e| Error::RouteError(Some(format!("{e:?}"))))?;

        Ok(session)
    }

    fn register_handshake_success(&self, dst_peer_id: PeerId) {
        let mut entry = self.states.entry(dst_peer_id).or_default();
        entry.failure_count = 0;
        entry.next_retry_at = None;
    }

    fn register_handshake_failure(&self, dst_peer_id: PeerId, attempt: u32) {
        let mut entry = self.states.entry(dst_peer_id).or_default();
        entry.failure_count = entry.failure_count.saturating_add(1);
        let backoff = HANDSHAKE_RETRY_BASE_MS.saturating_mul(1 << attempt);
        entry.next_retry_at = Some(Instant::now() + Duration::from_millis(backoff));
    }

    fn decode_handshake_message<MsgT: Message + Default>(
        &self,
        expected_type: PacketType,
        hs: &mut snow::HandshakeState,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error> {
        let hdr = pkt.peer_manager_header().ok_or_else(|| {
            Error::RouteError(Some("packet without peer manager header".to_string()))
        })?;
        if hdr.packet_type != expected_type as u8 {
            return Err(Error::RouteError(Some("packet type mismatch".to_string())));
        }
        let mut out = vec![0u8; 4096];
        let out_len = hs
            .read_message(pkt.payload(), &mut out)
            .map_err(|e| Error::RouteError(Some(format!("noise read msg failed: {e:?}"))))?;
        let msg = MsgT::decode(&out[..out_len])
            .map_err(|e| Error::RouteError(Some(format!("decode message failed: {e:?}"))))?;
        Ok(msg)
    }

    pub async fn handle_handshake_packet(&self, packet: ZCPacket) -> Result<(), Error> {
        let hdr = packet
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let src_peer_id = hdr.from_peer_id.get();
        self.control_metrics.record_rx(packet.buf_len() as u64);
        match hdr.packet_type {
            x if x == PacketType::RelayHandshake as u8 => {
                tracing::debug!("handle_relay_msg1 from {:?}", src_peer_id);
                self.handle_relay_msg1(packet, src_peer_id).await
            }
            x if x == PacketType::RelayHandshakeAck as u8 => {
                if let Some((_, sender)) = self.pending_handshakes.remove(&src_peer_id) {
                    let _ = sender.send(packet);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn handle_relay_msg1(&self, msg1: ZCPacket, remote_peer_id: PeerId) -> Result<(), Error> {
        // Check for bidirectional handshake race condition.
        // If we are also waiting for a RelayHandshakeAck from this peer,
        // use deterministic rule: the peer with smaller peer_id becomes initiator.
        if self.pending_handshakes.contains_key(&remote_peer_id) {
            // We have a pending handshake as initiator.
            // If remote_peer_id < my_peer_id, remote should be initiator, we should be responder.
            // Cancel our pending handshake and proceed as responder.
            if remote_peer_id < self.my_peer_id {
                tracing::debug!(
                    ?remote_peer_id,
                    my_peer_id = ?self.my_peer_id,
                    "bidirectional handshake race: yielding initiator role to smaller peer_id"
                );
                // Remove our pending handshake
                self.pending_handshakes.remove(&remote_peer_id);
            } else {
                // We have smaller peer_id, we should remain initiator.
                // Ignore this RelayHandshake and let our initiator flow complete.
                tracing::debug!(
                    ?remote_peer_id,
                    my_peer_id = ?self.my_peer_id,
                    "bidirectional handshake race: keeping initiator role due to smaller peer_id"
                );
                return Err(Error::RouteError(Some(
                    "bidirectional handshake race: we are initiator".to_string(),
                )));
            }
        }

        let (local_private_key, _local_public_key) = self.get_local_keypair()?;
        let params: NoiseParams = "Noise_IK_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::RouteError(Some(format!("parse noise params failed: {e:?}"))))?;
        let builder = snow::Builder::new(params);
        let mut hs = builder
            .prologue(RELAY_NOISE_PROLOGUE)
            .map_err(|e| Error::RouteError(Some(format!("set prologue failed: {e:?}"))))?
            .local_private_key(&local_private_key)
            .map_err(|e| Error::RouteError(Some(format!("set local key failed: {e:?}"))))?
            .build_responder()
            .map_err(|e| Error::RouteError(Some(format!("build responder failed: {e:?}"))))?;

        let msg1_pb = self.decode_handshake_message::<RelayNoiseMsg1Pb>(
            PacketType::RelayHandshake,
            &mut hs,
            msg1,
        )?;
        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();
        let remote_static_key = if remote_static.len() == 32 {
            let mut key = [0u8; 32];
            key.copy_from_slice(&remote_static);
            Some(key)
        } else {
            None
        };

        // Verify initiator's static public key matches the expected key from route info
        let expected_pubkey = self.get_remote_static_pubkey(remote_peer_id).await?;
        if remote_static != expected_pubkey {
            return Err(Error::RouteError(Some(format!(
                "responder: initiator static pubkey mismatch for peer {}, expected {} bytes, got {} bytes",
                remote_peer_id,
                expected_pubkey.len(),
                remote_static.len()
            ))));
        }

        let server_network_name = self.global_ctx.get_network_name();
        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let key = SessionKey::new(server_network_name.clone(), remote_peer_id);
        let upsert = self
            .peer_session_store
            .upsert_responder_session(
                &key,
                msg1_pb.a_session_generation,
                algo.clone(),
                msg1_pb.client_encryption_algorithm.clone(),
                remote_static_key,
            )
            .map_err(|e| Error::RouteError(Some(format!("{e:?}"))))?;
        let msg2_pb = RelayNoiseMsg2Pb {
            action: match upsert.action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation: upsert.session_generation,
            root_key_32: upsert.root_key.map(|k| k.to_vec()),
            initial_epoch: upsert.initial_epoch,
            b_conn_id: Some(uuid::Uuid::new_v4().into()),
            a_conn_id_echo: msg1_pb.a_conn_id,
            server_encryption_algorithm: algo,
        };
        let payload = msg2_pb.encode_to_vec();
        let mut out = vec![0u8; 4096];
        let out_len = hs
            .write_message(&payload, &mut out)
            .map_err(|e| Error::RouteError(Some(format!("noise write msg2 failed: {e:?}"))))?;

        self.register_handshake_success(remote_peer_id);

        self.send_handshake_packet(
            out[..out_len].to_vec(),
            PacketType::RelayHandshakeAck,
            remote_peer_id,
            NextHopPolicy::LeastHop,
        )
        .await?;

        // Flush any packets buffered while waiting for the handshake to complete
        self.flush_pending_packets(remote_peer_id, upsert.session)
            .await;

        Ok(())
    }

    pub async fn decrypt_if_needed(self: &Arc<Self>, packet: &mut ZCPacket) -> Result<bool, Error> {
        if !self.is_secure_mode_enabled() {
            return Ok(false);
        }
        let hdr = packet
            .peer_manager_header()
            .ok_or_else(|| Error::RouteError(Some("packet without header".to_string())))?;
        let from_peer_id = hdr.from_peer_id.get();
        let network = self.global_ctx.get_network_identity();
        let key = SessionKey::new(network.network_name.clone(), from_peer_id);
        let Some(session) = self.peer_session_store.get(&key) else {
            tracing::debug!(
                "relay session not found for peer {}, try handshake",
                from_peer_id
            );
            self.ensure_session(from_peer_id, NextHopPolicy::LeastHop)
                .await?;
            return Ok(false);
        };
        let now = Instant::now();
        let mut entry = self.states.entry(from_peer_id).or_default();
        entry.last_active_at = now;
        session.decrypt_payload(from_peer_id, self.my_peer_id, packet)?;
        Ok(true)
    }

    pub fn evict_idle_sessions(&self, idle: Duration) {
        let now = Instant::now();
        let mut to_remove = Vec::new();
        for entry in self.states.iter() {
            if now.duration_since(entry.last_active_at) > idle {
                to_remove.push(*entry.key());
            }
        }
        for peer_id in to_remove {
            self.states.remove(&peer_id);
            self.pending_handshakes.remove(&peer_id);
            self.handshake_locks.remove(&peer_id);
            self.pending_packets.remove(&peer_id);
        }
    }

    pub fn has_state(&self, peer_id: PeerId) -> bool {
        self.states.contains_key(&peer_id)
    }

    pub fn failure_count(&self, peer_id: PeerId) -> Option<u32> {
        self.states.get(&peer_id).map(|v| v.failure_count)
    }

    pub fn is_backoff_active(&self, peer_id: PeerId) -> bool {
        self.states
            .get(&peer_id)
            .and_then(|v| v.next_retry_at)
            .is_some_and(|ts| Instant::now() < ts)
    }

    /// Remove relay-specific state for a specific peer.
    /// This does NOT remove the session from PeerSessionStore, because the
    /// session lifecycle is independent of any particular connection type
    /// (relay or direct). The session may still be used by direct connections
    /// or for fast reconnection (Join instead of Create).
    pub fn remove_peer(&self, peer_id: PeerId) {
        self.states.remove(&peer_id);
        self.pending_handshakes.remove(&peer_id);
        self.handshake_locks.remove(&peer_id);
        self.pending_packets.remove(&peer_id);

        tracing::debug!(?peer_id, "RelayPeerMap removed peer relay state");
    }
}

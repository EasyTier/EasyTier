use std::{
    any::Any,
    fmt::Debug,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use arc_swap::ArcSwapOption;
use crossbeam::atomic::AtomicCell;
use futures::{StreamExt, TryFutureExt};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::Mac;
use prost::Message;

use tokio::{
    sync::{broadcast, Mutex},
    task::JoinSet,
    time::{timeout, Duration},
};

use tracing::Instrument;
use zerocopy::AsBytes;

use snow::{params::NoiseParams, HandshakeState};

use crate::{
    common::{
        config::{NetworkIdentity, NetworkSecretDigest},
        defer,
        error::Error,
        global_ctx::ArcGlobalCtx,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        PeerId,
    },
    peers::peer_session::{PeerSessionStore, SessionKey, UpsertResponderSessionReturn},
    proto::{
        api::instance::{PeerConnInfo, PeerConnStats},
        common::{LimiterConfig, SecureModeConfig, TunnelInfo},
        peer_rpc::{
            HandshakeRequest, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb, SecureAuthLevel,
        },
    },
    tunnel::{
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
        Tunnel, TunnelError, ZCPacketStream,
    },
    use_global_var,
};

use super::{
    peer_conn_ping::PeerConnPinger,
    peer_session::{PeerSession, PeerSessionAction},
    PacketRecvChan,
};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

/// The proof of client secret.
#[derive(Debug)]
struct SecretProof {
    challenge: Vec<u8>,
    proof: Vec<u8>,
}

/// The result of noise handshake.
#[derive(Debug)]
struct NoiseHandshakeResult {
    peer_id: PeerId,
    session: Arc<PeerSession>,
    local_static_pubkey: Vec<u8>,
    remote_static_pubkey: Vec<u8>,
    handshake_hash: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
    remote_network_name: String,

    secret_digest: Vec<u8>,

    // foreign network manager use this to verify peer.
    // the challenge will be sent to authorized peer and compare the proof against it.
    client_secret_proof: Option<SecretProof>,

    my_encrypt_algo: String,
    remote_encrypt_algo: String,
}

#[derive(Clone)]
struct PeerSessionTunnelFilter {
    enabled: bool,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    session: Arc<std::sync::Mutex<Option<Arc<PeerSession>>>>,
}

impl PeerSessionTunnelFilter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            my_peer_id: Arc::new(AtomicCell::new(PeerId::default())),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn new_with_peer(my_peer_id: PeerId, enabled: bool) -> Self {
        Self {
            enabled,
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn set_my_peer_id(&self, my_peer_id: PeerId) {
        self.my_peer_id.store(my_peer_id);
    }

    fn set_peer_id(&self, peer_id: PeerId) {
        self.peer_id.store(Some(peer_id));
    }

    fn set_session(&self, session: Arc<PeerSession>) {
        *self.session.lock().unwrap() = Some(session);
    }

    fn should_skip_encrypt(&self, hdr: &crate::tunnel::packet_def::PeerManagerHeader) -> bool {
        hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg2 as u8
            || hdr.packet_type == PacketType::NoiseHandshakeMsg3 as u8
            || hdr.packet_type == PacketType::Ping as u8
            || hdr.packet_type == PacketType::Pong as u8
    }
}

impl TunnelFilter for PeerSessionTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        if !self.enabled {
            return Some(data);
        }

        let Some(hdr) = data.peer_manager_header() else {
            return Some(data);
        };

        if self.should_skip_encrypt(hdr) {
            return Some(data);
        }

        let Some(peer_id) = self.peer_id.load() else {
            return Some(data);
        };

        let mut guard = self.session.lock().unwrap();
        let Some(session) = guard.as_mut() else {
            return Some(data);
        };

        let my_peer_id = self.my_peer_id.load();
        session
            .encrypt_payload(my_peer_id, peer_id, &mut data)
            .ok()?;

        Some(data)
    }

    fn after_received(&self, data: crate::tunnel::StreamItem) -> Option<crate::tunnel::StreamItem> {
        if !self.enabled {
            return Some(data);
        }

        let mut data = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let Some(hdr) = data.peer_manager_header() else {
            return Some(Ok(data));
        };

        if self.should_skip_encrypt(hdr) {
            return Some(Ok(data));
        }

        let from_peer_id = hdr.from_peer_id.get();
        if from_peer_id == 0 {
            return Some(Ok(data));
        }
        self.peer_id.store(Some(from_peer_id));

        let mut guard = self.session.lock().unwrap();
        let Some(session) = guard.as_mut() else {
            return Some(Ok(data));
        };

        let my_peer_id = self.my_peer_id.load();
        let _ = session.decrypt_payload(from_peer_id, my_peer_id, &mut data);

        Some(Ok(data))
    }

    fn filter_output(&self) {}
}

pub struct PeerConnCloseNotify {
    conn_id: PeerConnId,
    sender: Arc<std::sync::Mutex<Option<broadcast::Sender<()>>>>,
}

impl PeerConnCloseNotify {
    fn new(conn_id: PeerConnId) -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            conn_id,
            sender: Arc::new(std::sync::Mutex::new(Some(sender))),
        }
    }

    fn notify_close(&self) {
        self.sender.lock().unwrap().take();
    }

    pub async fn get_waiter(&self) -> Option<broadcast::Receiver<()>> {
        if let Some(sender) = self.sender.lock().unwrap().as_mut() {
            let receiver = sender.subscribe();
            return Some(receiver);
        }
        None
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub fn is_closed(&self) -> bool {
        self.sender.lock().unwrap().is_none()
    }
}

struct PeerConnCounter {
    traffic_tx_bytes: CounterHandle,
    traffic_rx_bytes: CounterHandle,
    traffic_tx_packets: CounterHandle,
    traffic_rx_packets: CounterHandle,
}

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    peer_id_hint: Option<PeerId>,
    global_ctx: ArcGlobalCtx,

    secure_mode_cfg: Option<SecureModeConfig>,
    session_filter: PeerSessionTunnelFilter,
    noise_handshake_result: Option<NoiseHandshakeResult>,

    tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: MpscTunnelSender,
    recv: Mutex<Option<Pin<Box<dyn ZCPacketStream>>>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,
    is_client: Option<bool>,

    // remote or local
    is_hole_punched: bool,

    close_event_notifier: Arc<PeerConnCloseNotify>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,

    counters: ArcSwapOption<PeerConnCounter>,

    peer_session_store: Arc<PeerSessionStore>,
    my_encrypt_algo: String,
}

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

impl PeerConn {
    pub fn new(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        tunnel: Box<dyn Tunnel>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        Self::new_with_peer_id_hint(my_peer_id, global_ctx, tunnel, None, peer_session_store)
    }

    pub fn new_with_peer_id_hint(
        my_peer_id: PeerId,
        global_ctx: ArcGlobalCtx,
        tunnel: Box<dyn Tunnel>,
        peer_id_hint: Option<PeerId>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        let flags = global_ctx.get_flags();
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let secure_mode_cfg = global_ctx.config.get_secure_mode();
        let session_filter = PeerSessionTunnelFilter::new_with_peer(
            my_peer_id,
            secure_mode_cfg
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false),
        );

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let filter_chain = TunnelFilterChain::new(session_filter.clone(), peer_conn_tunnel_filter);
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
        let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));

        let (recv, sink) = (mpsc_tunnel.get_stream(), mpsc_tunnel.get_sink());

        let conn_id = PeerConnId::new_v4();
        let my_encrypt_algo = flags.encryption_algorithm;

        PeerConn {
            conn_id,

            my_peer_id,
            peer_id_hint,
            global_ctx,

            secure_mode_cfg,
            session_filter,
            noise_handshake_result: None,

            tunnel: Arc::new(Mutex::new(Box::new(defer::Defer::new(move || {
                mpsc_tunnel.close()
            })))),
            sink,
            recv: Mutex::new(Some(recv)),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            is_hole_punched: true,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id)),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),

            counters: ArcSwapOption::new(None),

            peer_session_store,
            my_encrypt_algo,
        }
    }

    fn get_peer_session_store(&self) -> &Arc<PeerSessionStore> {
        &self.peer_session_store
    }

    pub fn is_secure_mode_enabled(&self) -> bool {
        self.secure_mode_cfg
            .as_ref()
            .map(|cfg| cfg.enabled)
            .unwrap_or(false)
    }

    // pri, pub
    fn get_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let cfg = self
            .secure_mode_cfg
            .as_ref()
            .ok_or_else(|| Error::WaitRespError("secure mode config not set".to_owned()))?;
        Ok((
            cfg.private_key()?.as_bytes().to_vec(),
            cfg.public_key()?.as_bytes().to_vec(),
        ))
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub fn set_is_hole_punched(&mut self, is_hole_punched: bool) {
        self.is_hole_punched = is_hole_punched;
    }

    pub fn is_hole_punched(&self) -> bool {
        self.is_hole_punched
    }

    async fn wait_handshake(&self, need_retry: &mut bool) -> Result<HandshakeRequest, Error> {
        *need_retry = false;

        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();
        let rsp = match recv.next().await {
            Some(Ok(rsp)) => rsp,
            Some(Err(e)) => {
                return Err(Error::WaitRespError(format!(
                    "conn recv error during wait handshake response, err: {:?}",
                    e
                )))
            }
            None => {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ))
            }
        };

        *need_retry = true;

        let Some(peer_mgr_hdr) = rsp.peer_manager_header() else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet: {:?}, cannot decode peer manager hdr",
                rsp
            )));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}, packet: {:?}",
                peer_mgr_hdr.packet_type, rsp
            )));
        }

        let rsp = HandshakeRequest::decode(rsp.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        Ok(rsp)
    }

    async fn wait_handshake_loop(&self) -> Result<HandshakeRequest, Error> {
        timeout(Duration::from_secs(5), async move {
            loop {
                let mut need_retry = true;
                match self.wait_handshake(&mut need_retry).await {
                    Ok(rsp) => return Ok(rsp),
                    Err(e) => {
                        tracing::warn!("wait handshake error: {:?}", e);
                        if !need_retry {
                            return Err(e);
                        }
                    }
                }
            }
        })
        .map_err(|e| Error::WaitRespError(format!("wait handshake timeout: {:?}", e)))
        .await?
    }

    async fn send_handshake(&self, send_secret_digest: bool) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let mut req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };

        // only send network secret digest if the network is the same
        if send_secret_digest {
            req.network_secret_digest
                .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        } else {
            // fill zero
            req.network_secret_digest
                .extend_from_slice(&[0u8; std::mem::size_of::<NetworkSecretDigest>()]);
        }

        let hs_req = req.encode_to_vec();
        let mut zc_packet = ZCPacket::new_with_payload(hs_req.as_bytes());
        zc_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::HandShake as u8,
        );

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;

        // yield to send the response packet
        tokio::task::yield_now().await;

        Ok(())
    }

    fn decode_handshake_packet(pkt: &ZCPacket) -> Result<HandshakeRequest, Error> {
        let Some(peer_mgr_hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "unexpected packet: cannot decode peer manager hdr".to_owned(),
            ));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}",
                peer_mgr_hdr.packet_type
            )));
        }

        let rsp = HandshakeRequest::decode(pkt.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        Ok(rsp)
    }

    async fn recv_next_peer_manager_packet(
        &self,
        expected_pkt_type: Option<PacketType>,
    ) -> Result<ZCPacket, Error> {
        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();

        loop {
            let Some(ret) = recv.next().await else {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ));
            };
            let pkt = match ret {
                Ok(v) => v,
                Err(e) => {
                    return Err(Error::WaitRespError(format!(
                        "conn recv error during wait handshake response, err: {:?}",
                        e
                    )))
                }
            };

            let Some(peer_mgr_hdr) = pkt.peer_manager_header() else {
                continue;
            };

            if expected_pkt_type.is_none()
                || peer_mgr_hdr.packet_type == *expected_pkt_type.as_ref().unwrap() as u8
            {
                return Ok(pkt);
            }
        }
    }

    fn decode_b64_32(input: &str) -> Result<Vec<u8>, Error> {
        let decoded = BASE64_STANDARD
            .decode(input)
            .map_err(|e| Error::WaitRespError(format!("base64 decode failed: {e:?}")))?;
        if decoded.len() != 32 {
            return Err(Error::WaitRespError(format!(
                "invalid key length: {}",
                decoded.len()
            )));
        }
        Ok(decoded)
    }

    fn get_pinned_remote_static_pubkey_b64(&self) -> Option<String> {
        let remote_url_str = self
            .tunnel_info
            .as_ref()
            .and_then(|t| t.remote_addr.as_ref())
            .map(|u| u.url.as_str())?;
        let remote_url: url::Url = remote_url_str.parse().ok()?;

        self.global_ctx
            .config
            .get_peers()
            .into_iter()
            .find(|p| p.uri == remote_url)
            .and_then(|p| p.peer_public_key)
    }

    async fn send_noise_msg<Msg: prost::Message>(
        &self,
        pb: Msg,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        hs: &mut snow::HandshakeState,
    ) -> Result<(), Error> {
        tracing::info!(
            "send noise msg: {:?}, packet_type: {:?}, from: {:?}, to: {:?}",
            pb,
            packet_type,
            self.my_peer_id,
            remote_peer_id
        );
        let payload = pb.encode_to_vec();
        let mut msg = vec![0u8; 4096];
        let msg_len = hs
            .write_message(&payload, &mut msg)
            .map_err(|e| Error::WaitRespError(format!("noise write msg1 failed: {e:?}")))?;
        let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
        pkt.fill_peer_manager_hdr(self.my_peer_id, remote_peer_id, packet_type as u8);
        Ok(self.sink.send(pkt).await?)
    }

    async fn do_noise_handshake_as_client(&self) -> Result<NoiseHandshakeResult, Error> {
        let prologue = b"easytier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;

        let pinned_remote_pubkey = self
            .get_pinned_remote_static_pubkey_b64()
            .map(|v| Self::decode_b64_32(&v))
            .transpose()?;

        let builder = snow::Builder::new(params);
        let (local_private_key, local_static_pubkey) = self.get_keypair()?;

        let network = self.global_ctx.get_network_identity();
        let a_session_generation = self
            .peer_id_hint
            .and_then(|peer_id| {
                self.get_peer_session_store()
                    .get(&SessionKey::new(network.network_name.clone(), peer_id))
            })
            .map(|s| s.session_generation());

        let a_conn_id = uuid::Uuid::new_v4();
        let msg1_pb = PeerConnNoiseMsg1Pb {
            version: VERSION,
            a_network_name: network.network_name.clone(),
            a_session_generation,
            a_conn_id: Some(a_conn_id.into()),
            client_encryption_algorithm: self.my_encrypt_algo.clone(),
        };

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_private_key)?
            .build_initiator()?;

        let mut secure_auth_level = SecureAuthLevel::EncryptedUnauthenticated;

        self.send_noise_msg(
            msg1_pb,
            PacketType::NoiseHandshakeMsg1,
            PeerId::default(),
            &mut hs,
        )
        .await?;

        let server_handshake_hash = hs.get_handshake_hash().to_vec();

        let msg2 = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg2)),
        )
        .await??;
        let remote_peer_id = msg2.get_src_peer_id().expect("missing src peer id");
        if let Some(hint) = self.peer_id_hint {
            if hint != remote_peer_id {
                return Err(Error::WaitRespError("peer_id mismatch".to_owned()));
            }
        }
        let msg2_pb = Self::decode_handshake_message::<PeerConnNoiseMsg2Pb>(
            PacketType::NoiseHandshakeMsg2,
            Some(&mut hs),
            msg2,
        )?;
        if msg2_pb.a_conn_id_echo != Some(a_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg2 conn_id_echo mismatch".to_owned(),
            ));
        }
        let action = PeerConnSessionActionPb::try_from(msg2_pb.action)
            .map_err(|_| Error::WaitRespError("invalid session action".to_owned()))?;
        let remote_network_name = msg2_pb.b_network_name.clone();

        if remote_network_name == network.network_name {
            if msg2_pb.role_hint != 1 {
                return Err(Error::WaitRespError(
                    "role_hint must be 1 when network_name is same".to_owned(),
                ));
            }
            let Some(secret_proof_32) = msg2_pb.secret_proof_32 else {
                return Err(Error::WaitRespError(
                    "secret_proof_32 must be present when role_hint is 1".to_owned(),
                ));
            };
            let verify_result = self
                .global_ctx
                .get_secret_proof(&server_handshake_hash)
                .map(|mac| mac.verify_slice(&secret_proof_32).is_ok());
            if verify_result != Some(true) {
                return Err(Error::WaitRespError(format!(
                    "secret_proof_32 verify failed: {verify_result:?}"
                )));
            }

            secure_auth_level = secure_auth_level.max(SecureAuthLevel::NetworkSecretConfirmed);
        }

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();
        let secret_proof_32 = self
            .global_ctx
            .get_secret_proof(&handshake_hash_for_proof)
            .map(|mac| mac.finalize().into_bytes().to_vec());

        let secret_digest = if use_global_var!(HMAC_SECRET_DIGEST) {
            self.global_ctx
                .get_secret_proof("digest".as_bytes())
                .map(|mac| mac.finalize().into_bytes().to_vec())
                .unwrap_or_default()
        } else {
            network.network_secret_digest.unwrap_or_default().to_vec()
        };

        let msg3_pb = PeerConnNoiseMsg3Pb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: msg2_pb.b_conn_id,
            secret_proof_32,
            secret_digest: secret_digest.clone(),
        };
        self.send_noise_msg(
            msg3_pb,
            PacketType::NoiseHandshakeMsg3,
            remote_peer_id,
            &mut hs,
        )
        .await?;

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();

        if let Some(pinned) = pinned_remote_pubkey.as_ref() {
            if pinned.as_slice() == remote_static.as_slice() {
                secure_auth_level =
                    secure_auth_level.max(SecureAuthLevel::SharedNodePubkeyVerified);
            } else {
                return Err(Error::WaitRespError(
                    "pinned remote static pubkey mismatch".to_owned(),
                ));
            }
        }

        let handshake_hash = hs.get_handshake_hash().to_vec();

        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let root_key = msg2_pb
            .root_key_32
            .as_deref()
            .filter(|v| v.len() == 32)
            .map(|v| {
                let mut key = [0u8; 32];
                key.copy_from_slice(v);
                key
            });
        let session_action = match action {
            PeerConnSessionActionPb::Join => PeerSessionAction::Join,
            PeerConnSessionActionPb::Sync => PeerSessionAction::Sync,
            PeerConnSessionActionPb::Create => PeerSessionAction::Create,
        };
        let session = self.get_peer_session_store().apply_initiator_action(
            &SessionKey::new(network.network_name.clone(), remote_peer_id),
            session_action,
            msg2_pb.b_session_generation,
            root_key,
            msg2_pb.initial_epoch,
            algo,
            msg2_pb.server_encryption_algorithm.clone(),
        )?;

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            remote_network_name,
            // we have authorized the peer with noise handshake, so just set secret digest same as us even remote is a shared node.
            secret_digest,
            client_secret_proof: None,

            my_encrypt_algo: self.my_encrypt_algo.clone(),
            remote_encrypt_algo: msg2_pb.server_encryption_algorithm.clone(),
        })
    }

    fn decode_handshake_message<MsgT>(
        expected_pkt_type: PacketType,
        hs: Option<&mut HandshakeState>,
        pkt: ZCPacket,
    ) -> Result<MsgT, Error>
    where
        MsgT: prost::Message + Default,
    {
        tracing::info!(
            "decode_handshake_message: {:?}, expected_pkt_type: {:?}",
            pkt,
            expected_pkt_type
        );
        let Some(hdr) = pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "packet without peer manager header".to_owned(),
            ));
        };

        if hdr.packet_type != expected_pkt_type as u8 {
            return Err(Error::WaitRespError(format!(
                "packet type not {:?}",
                expected_pkt_type
            )));
        }

        let msg = match hs {
            Some(hs) => {
                let mut out = vec![0u8; 4096];
                let out_len = hs
                    .read_message(pkt.payload(), &mut out)
                    .map_err(|e| Error::WaitRespError(format!("noise read msg failed: {e:?}")))?;
                MsgT::decode(&out[..out_len])
                    .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?
            }
            None => MsgT::decode(pkt.payload())
                .map_err(|e| Error::WaitRespError(format!("decode message failed: {e:?}")))?,
        };

        Ok(msg)
    }

    async fn read_next_message_with_timeout(
        &mut self,
        read_timeout: Duration,
    ) -> Result<ZCPacket, Error> {
        timeout(read_timeout, async {
            let mut locked = self.recv.lock().await;
            let recv = locked.as_mut().unwrap();
            Ok(recv
                .next()
                .await
                .ok_or(Error::WaitRespError("read next message failed".to_owned()))??)
        })
        .await
        .map_err(|e| Error::WaitRespError(format!("read next message timeout: {e:?}")))?
    }

    async fn do_noise_handshake_as_server<Fn>(
        &mut self,
        first_msg1: ZCPacket,
        mut handshake_recved: Fn,
    ) -> Result<NoiseHandshakeResult, Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let prologue = b"easytier-peerconn-noise".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;
        let builder = snow::Builder::new(params);

        let (local_static_private_key, local_static_pubkey) = self.get_keypair()?;

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_static_private_key)?
            .build_responder()?;

        let remote_peer_id = first_msg1
            .get_src_peer_id()
            .expect("msg1 must have src peer id");

        let msg1_pb = Self::decode_handshake_message::<PeerConnNoiseMsg1Pb>(
            PacketType::NoiseHandshakeMsg1,
            Some(&mut hs),
            first_msg1,
        )?;
        let remote_network_name = msg1_pb.a_network_name.clone();

        // this may update my peer id
        handshake_recved(self, &remote_network_name)?;

        let server_network_name = self.global_ctx.get_network_name();
        let (role_hint, secret_proof_32) = if msg1_pb.a_network_name == server_network_name {
            (
                1,
                self.global_ctx
                    .get_secret_proof(hs.get_handshake_hash())
                    .map(|m| m.finalize().into_bytes().to_vec()),
            )
        } else {
            (2, None)
        };

        let algo = self.global_ctx.get_flags().encryption_algorithm.clone();
        let UpsertResponderSessionReturn {
            session,
            action,
            session_generation: b_session_generation,
            root_key: root_key_32,
            initial_epoch,
        } = self.get_peer_session_store().upsert_responder_session(
            &SessionKey::new(remote_network_name.clone(), remote_peer_id),
            msg1_pb.a_session_generation,
            algo.clone(),
            msg1_pb.client_encryption_algorithm.clone(),
        )?;

        let b_conn_id = uuid::Uuid::new_v4();
        let msg2_pb = PeerConnNoiseMsg2Pb {
            b_network_name: server_network_name,
            role_hint,
            action: match action {
                PeerSessionAction::Join => PeerConnSessionActionPb::Join as i32,
                PeerSessionAction::Sync => PeerConnSessionActionPb::Sync as i32,
                PeerSessionAction::Create => PeerConnSessionActionPb::Create as i32,
            },
            b_session_generation,
            root_key_32: root_key_32.map(|k| k.to_vec()),
            initial_epoch,
            b_conn_id: Some(b_conn_id.into()),
            a_conn_id_echo: msg1_pb.a_conn_id,
            secret_proof_32,
            server_encryption_algorithm: algo,
        };
        self.send_noise_msg(
            msg2_pb,
            PacketType::NoiseHandshakeMsg2,
            remote_peer_id,
            &mut hs,
        )
        .await?;

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();

        let msg3_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg3)),
        )
        .await??;
        let msg3_pb = Self::decode_handshake_message::<PeerConnNoiseMsg3Pb>(
            PacketType::NoiseHandshakeMsg3,
            Some(&mut hs),
            msg3_pkt,
        )?;

        if msg3_pb.a_conn_id_echo != msg1_pb.a_conn_id {
            return Err(Error::WaitRespError(
                "noise msg3 a_conn_id mismatch".to_owned(),
            ));
        }
        if msg3_pb.b_conn_id_echo != Some(b_conn_id.into()) {
            return Err(Error::WaitRespError(
                "noise msg3 b_conn_id mismatch".to_owned(),
            ));
        }

        let mut secure_auth_level = SecureAuthLevel::EncryptedUnauthenticated;
        let Some(proof) = msg3_pb.secret_proof_32.as_ref() else {
            return Err(Error::WaitRespError(
                "noise msg3 secret_proof_32 is required".to_owned(),
            ));
        };

        if role_hint == 1 {
            if let Some(mac) = self.global_ctx.get_secret_proof(&handshake_hash_for_proof) {
                if mac.verify_slice(proof).is_ok() {
                    secure_auth_level =
                        secure_auth_level.max(SecureAuthLevel::NetworkSecretConfirmed);
                } else {
                    return Err(Error::WaitRespError("invalid secret_proof".to_owned()));
                }
            }
        }

        let remote_static = hs
            .get_remote_static()
            .map(|x: &[u8]| x.to_vec())
            .unwrap_or_default();

        let handshake_hash = hs.get_handshake_hash().to_vec();

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
            client_secret_proof: Some(SecretProof {
                challenge: handshake_hash_for_proof,
                proof: proof.clone(),
            }),

            my_encrypt_algo: self.my_encrypt_algo.clone(),
            remote_encrypt_algo: msg1_pb.client_encryption_algorithm.clone(),
        })
    }

    fn build_handshake_rsp(&self, noise: &NoiseHandshakeResult) -> HandshakeRequest {
        tracing::info!("build_handshake_rsp: {:?}", noise);
        HandshakeRequest {
            magic: MAGIC,
            my_peer_id: noise.peer_id,
            version: VERSION,
            network_name: noise.remote_network_name.clone(),

            features: Vec::new(),
            network_secret_digest: noise.secret_digest.clone(),
        }
    }

    #[tracing::instrument(skip(handshake_recved))]
    pub async fn do_handshake_as_server_ext<Fn>(
        &mut self,
        mut handshake_recved: Fn,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut PeerConn, &str) -> Result<(), Error> + Send,
    {
        let first_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(None),
        )
        .await??;
        let Some(hdr) = first_pkt.peer_manager_header() else {
            return Err(Error::WaitRespError(
                "first packet must have peer manager header".to_owned(),
            ));
        };

        if self.is_secure_mode_enabled() && hdr.packet_type == PacketType::NoiseHandshakeMsg1 as u8
        {
            let noise = self
                .do_noise_handshake_as_server(first_pkt, handshake_recved)
                .await?;
            // construct handshake rsp from noise result for compat.
            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);
            self.noise_handshake_result = Some(noise);

            self.info = Some(handshake_rsp);
            self.is_client = Some(false);
        } else if hdr.packet_type == PacketType::HandShake as u8 {
            let rsp = Self::decode_handshake_packet(&first_pkt)?;
            handshake_recved(self, &rsp.network_name)?;
            tracing::info!("handshake request: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest).await?;
        } else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type during handshake: {}",
                hdr.packet_type
            )));
        }

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        self.do_handshake_as_server_ext(|_, _| Ok(())).await
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        if self.is_secure_mode_enabled() {
            let noise = self.do_noise_handshake_as_client().await?;
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);

            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.noise_handshake_result = Some(noise);
            self.info = Some(handshake_rsp);
            self.is_client = Some(true);
        } else {
            self.send_handshake(true).await?;
            tracing::info!("waiting for handshake request from server");
            let rsp = self.wait_handshake_loop().await?;
            tracing::info!("handshake response: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(true);
        }

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError(
                "peer id conflict, are you connecting to yourself?".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.lock().await.take().unwrap();
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();

        let stats_mgr = self.global_ctx.stats_manager();
        let label_set = LabelSet::new().with_label_type(LabelType::NetworkName(
            conn_info_for_instrument.network_name.clone(),
        ));
        let counters = PeerConnCounter {
            traffic_tx_bytes: stats_mgr.get_counter(MetricName::TrafficBytesTx, label_set.clone()),
            traffic_rx_bytes: stats_mgr.get_counter(MetricName::TrafficBytesRx, label_set.clone()),
            traffic_tx_packets: stats_mgr
                .get_counter(MetricName::TrafficPacketsTx, label_set.clone()),
            traffic_rx_packets: stats_mgr.get_counter(MetricName::TrafficPacketsRx, label_set),
        };
        self.counters.store(Some(Arc::new(counters)));

        let is_foreign_network = conn_info_for_instrument.network_name
            != self.global_ctx.get_network_identity().network_name;
        let recv_limiter = if is_foreign_network {
            let relay_network_bps_limit = self.global_ctx.get_flags().foreign_relay_bps_limit;
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(relay_network_bps_limit),
                fill_duration_ms: None,
            };
            Some(self.global_ctx.token_bucket_manager().get_or_create(
                &format!("{}:recv", conn_info_for_instrument.network_name),
                limiter_config.into(),
            ))
        } else {
            None
        };

        let counters = self.counters.load_full().unwrap();

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        task_ret = Err(ret.err().unwrap());
                        break;
                    }

                    let mut zc_packet = ret.unwrap();
                    let buf_len = zc_packet.buf_len() as u64;

                    counters.traffic_rx_bytes.add(buf_len);
                    counters.traffic_rx_packets.inc();

                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        break;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        if let Err(e) = ctrl_sender.send(zc_packet) {
                            tracing::error!(?e, "peer conn send ctrl resp error");
                        }
                    } else if sender.send(zc_packet).await.is_err() {
                        break;
                    }

                    if let Some(limiter) = recv_limiter.as_ref() {
                        limiter.consume(buf_len).await;
                    }
                }

                tracing::info!("end recving peer conn packet");

                drop(sink);
                close_event_notifier.notify_close();

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.sink.clone(),
            self.ctrl_resp_sender.clone(),
            self.latency_stats.clone(),
            self.loss_rate_stats.clone(),
            self.throughput.clone(),
        );

        let close_event_notifier = self.close_event_notifier.clone();

        self.tasks.spawn(async move {
            pingpong.pingpong().await;

            tracing::warn!(?pingpong, "pingpong task exit");

            close_event_notifier.notify_close();

            Ok(())
        });
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        let counters = self.counters.load();
        if let Some(ref counters) = *counters {
            counters.traffic_tx_bytes.add(msg.buf_len() as u64);
            counters.traffic_tx_packets.inc();
        }
        Ok(self.sink.send(msg).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        let mut ret = NetworkIdentity {
            network_name: info.network_name.clone(),
            ..Default::default()
        };
        ret.network_secret_digest = Some([0u8; 32]);
        ret.network_secret_digest
            .as_mut()
            .unwrap()
            .copy_from_slice(&info.network_secret_digest);
        ret
    }

    pub fn get_close_notifier(&self) -> Arc<PeerConnCloseNotify> {
        self.close_event_notifier.clone()
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        let info = self.info.as_ref().unwrap();
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: info.features.clone(),
            tunnel: self.tunnel_info.clone(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
            is_client: self.is_client.unwrap_or_default(),
            network_name: info.network_name.clone(),
            is_closed: self.close_event_notifier.is_closed(),
            noise_local_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.local_static_pubkey.clone())
                .unwrap_or_default(),
            noise_remote_static_pubkey: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.remote_static_pubkey.clone())
                .unwrap_or_default(),
            secure_auth_level: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.secure_auth_level as i32)
                .unwrap_or_default(),
        }
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        if self.info.is_some() {
            panic!("set_peer_id should only be called before handshake");
        }
        self.my_peer_id = peer_id;
        self.session_filter.set_my_peer_id(peer_id);
    }

    pub fn get_my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        // if someone drop a conn manually, the notifier is not called.
        self.close_event_notifier.notify_close();
    }
}

#[cfg(test)]
pub mod tests {
    use std::sync::Arc;

    use rand::rngs::OsRng;

    use super::*;
    use crate::common::config::PeerConfig;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::global_ctx::GlobalCtx;
    use crate::common::new_peer_id;
    use crate::common::scoped_task::ScopedTask;
    use crate::peers::create_packet_recv_chan;
    use crate::peers::recv_packet_from_chan;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    pub fn set_secure_mode_cfg(global_ctx: &GlobalCtx, enabled: bool) {
        if !enabled {
            global_ctx.config.set_secure_mode(None);
        } else {
            // generate x25519 key pair
            let private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
            let public = x25519_dalek::PublicKey::from(&private);

            global_ctx.config.set_secure_mode(Some(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }));
        }
    }

    #[tokio::test]
    async fn peer_conn_handshake_same_id() {
        let ps = Arc::new(PeerSessionStore::new());
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = c_peer_id;

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        assert!(c_ret.is_err());
        assert!(s_ret.is_err());
    }

    #[tokio::test]
    async fn peer_conn_handshake() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let ps = Arc::new(PeerSessionStore::new());

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c), ps.clone());

        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(c_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(c_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(s_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(s_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(c_peer.get_peer_id(), s_peer_id);
        assert_eq!(s_peer.get_peer_id(), c_peer_id);
        assert_eq!(c_peer.get_network_identity(), s_peer.get_network_identity());
        assert_eq!(c_peer.get_network_identity(), NetworkIdentity::default());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_pubkey_and_encryption() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        let c_info = c_peer.get_conn_info();
        let s_info = s_peer.get_conn_info();

        assert_eq!(c_info.noise_local_static_pubkey.len(), 32);
        assert_eq!(c_info.noise_remote_static_pubkey.len(), 32);
        assert_eq!(s_info.noise_local_static_pubkey.len(), 32);
        assert_eq!(s_info.noise_remote_static_pubkey.len(), 32);

        assert_eq!(
            c_info.noise_remote_static_pubkey,
            s_info.noise_local_static_pubkey
        );
        assert_eq!(
            s_info.noise_remote_static_pubkey,
            c_info.noise_local_static_pubkey
        );

        let network = s_ctx.get_network_identity();
        let mut expected = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: s_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };
        expected
            .network_secret_digest
            .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        let expected_payload = expected.encode_to_vec();

        println!("sent: {:?}", c_recorder.sent.lock().unwrap());

        let wire_hs = c_recorder
            .sent
            .lock()
            .unwrap()
            .iter()
            .find(|p| {
                p.peer_manager_header()
                    .is_some_and(|h| h.packet_type == PacketType::NoiseHandshakeMsg3 as u8)
            })
            .unwrap()
            .clone();
        assert_ne!(wire_hs.payload(), expected_payload.as_slice());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_server_accept_legacy_client() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "shared".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None as i32,
        );

        assert_eq!(c_peer.get_conn_info().network_name, "shared".to_string());
        assert_eq!(s_peer.get_conn_info().network_name, "user".to_string());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_different_network_name_ok() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("user".to_string(), "sec1".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "shared".to_string(),
            "sec2".to_string(),
        ));

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );

        assert_eq!(c_peer.get_conn_info().network_name, "shared".to_string());
        assert_eq!(s_peer.get_conn_info().network_name, "user".to_string());
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_data_roundtrip() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        let (packet_send, mut packet_recv) = create_packet_recv_chan();
        s_peer.start_recv_loop(packet_send).await;

        let payload = b"secure-data-123";
        let mut pkt = ZCPacket::new_with_payload(payload);
        pkt.fill_peer_manager_hdr(c_peer_id, s_peer_id, PacketType::Data as u8);
        c_peer.send_msg(pkt).await.unwrap();

        let got = timeout(Duration::from_secs(2), async move {
            recv_packet_from_chan(&mut packet_recv).await
        })
        .await
        .unwrap()
        .unwrap();

        assert_eq!(got.payload(), payload);
        assert_eq!(
            got.peer_manager_header().unwrap().packet_type,
            PacketType::Data as u8
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_network_secret_confirmed() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));
        s_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec1".to_string()));

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_shared_node_pubkey_verified() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx
            .config
            .set_network_identity(NetworkIdentity::new("net1".to_string(), "sec2".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "net2".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });

        let remote_url: url::Url = c.info().unwrap().remote_addr.unwrap().url.parse().unwrap();

        set_secure_mode_cfg(&c_ctx, true);
        set_secure_mode_cfg(&s_ctx, true);

        c_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_public_key: Some(
                s_ctx
                    .config
                    .get_secure_mode()
                    .unwrap()
                    .local_public_key
                    .unwrap(),
            ),
            needs_better_route: false,
        }]);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::SharedNodePubkeyVerified as i32,
        );
    }

    async fn peer_conn_pingpong_test_common(
        drop_start: u32,
        drop_end: u32,
        conn_closed: bool,
        drop_both: bool,
    ) {
        let (c, s) = create_ring_tunnel_pair();

        // drop 1-3 packets should not affect pingpong
        let c_recorder = Arc::new(DropSendTunnelFilter::new(drop_start, drop_end));
        let c = TunnelWithFilter::new(c, c_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        s_peer.start_recv_loop(create_packet_recv_chan().0).await;
        // do not start ping for s, s only reponde to ping from c

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        let close_notifier = c_peer.get_close_notifier();
        c_peer.start_pingpong();
        c_peer.start_recv_loop(create_packet_recv_chan().0).await;

        let throughput = c_peer.throughput.clone();
        let _t = ScopedTask::from(tokio::spawn(async move {
            // if not drop both, we mock some rx traffic for client peer to test pinger
            if drop_both {
                return;
            }
            loop {
                tokio::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(3);
            }
        }));

        tokio::time::sleep(Duration::from_secs(15)).await;

        if conn_closed {
            assert!(close_notifier.is_closed());
        } else {
            assert!(!close_notifier.is_closed());
        }
    }

    #[tokio::test]
    async fn peer_conn_pingpong_timeout_not_close() {
        peer_conn_pingpong_test_common(3, 5, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_oneside_timeout() {
        peer_conn_pingpong_test_common(4, 12, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_bothside_timeout() {
        peer_conn_pingpong_test_common(3, 14, true, true).await;
    }

    #[tokio::test]
    async fn close_tunnel_during_handshake() {
        let ps = Arc::new(PeerSessionStore::new());
        let (c, s) = create_ring_tunnel_pair();
        let mut c_peer = PeerConn::new(
            new_peer_id(),
            get_mock_global_ctx(),
            Box::new(c),
            ps.clone(),
        );
        let j = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(s);
        });
        timeout(Duration::from_millis(1500), c_peer.do_handshake_as_client())
            .await
            .unwrap()
            .unwrap_err();
        let _ = tokio::join!(j);
    }
}

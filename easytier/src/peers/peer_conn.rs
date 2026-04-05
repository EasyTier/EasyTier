use crossbeam::atomic::AtomicCell;
use futures::{StreamExt, TryFutureExt};
use std::{
    any::Any,
    fmt::Debug,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use hmac::Mac;
use prost::Message;

use tokio::{
    sync::{Mutex, broadcast},
    task::JoinSet,
    time::{Duration, timeout},
};

use tracing::Instrument;
use zerocopy::AsBytes;

use snow::{HandshakeState, params::NoiseParams};

use super::{
    PacketRecvChan,
    peer_conn_ping::PeerConnPinger,
    peer_session::{PeerSession, PeerSessionAction},
    traffic_metrics::AggregateTrafficMetrics,
};
use crate::utils::BoxExt;
use crate::{
    common::{
        PeerId,
        config::{NetworkIdentity, NetworkSecretDigest},
        error::Error,
        global_ctx::ArcGlobalCtx,
    },
    guard,
    peers::peer_session::{PeerSessionStore, SessionKey, UpsertResponderSessionReturn},
    proto::{
        api::instance::{PeerConnInfo, PeerConnStats},
        common::{LimiterConfig, SecureModeConfig, TunnelInfo},
        peer_rpc::{
            HandshakeRequest, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb, PeerIdentityType, SecureAuthLevel,
        },
    },
    tunnel::{
        Tunnel, TunnelError, ZCPacketStream,
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
    },
    use_global_var,
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
    peer_identity_type: PeerIdentityType,
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
            || hdr.packet_type == PacketType::RelayHandshake as u8
            || hdr.packet_type == PacketType::RelayHandshakeAck as u8
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
        if my_peer_id != hdr.from_peer_id.get() {
            return Some(data);
        }

        if let Err(e) = session.encrypt_payload(my_peer_id, peer_id, &mut data) {
            tracing::warn!(
                ?my_peer_id,
                ?peer_id,
                ?e,
                "PeerSessionTunnelFilter: encrypt failed, dropping packet"
            );
            return None;
        }

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

        let Some(peer_id) = self.peer_id.load() else {
            return Some(Ok(data));
        };

        if from_peer_id != peer_id {
            return Some(Ok(data));
        }

        let mut guard = self.session.lock().unwrap();
        let Some(session) = guard.as_mut() else {
            return Some(Ok(data));
        };

        let my_peer_id = self.my_peer_id.load();
        if hdr.to_peer_id.get() != my_peer_id {
            return Some(Ok(data));
        }

        if let Err(e) = session.decrypt_payload(from_peer_id, my_peer_id, &mut data) {
            if !session.is_valid() {
                // Session auto-invalidated after too many consecutive failures.
                // Close the connection to trigger reconnection with a fresh handshake.
                tracing::error!(?e, "session invalidated, closing connection");
                return Some(Err(TunnelError::InternalError(
                    "session invalidated due to consecutive decrypt failures".to_string(),
                )));
            }
            // Transient failure, drop this packet but keep the connection alive.
            return None;
        }

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

            tunnel: Arc::new(Mutex::new(
                guard!([mut mpsc_tunnel] mpsc_tunnel.close()).boxed(),
            )),
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

    pub fn is_closed(&self) -> bool {
        self.close_event_notifier.is_closed()
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
                )));
            }
            None => {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ));
            }
        };

        *need_retry = true;
        let rsp_len = rsp.buf_len() as u64;

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

        self.record_control_rx(&rsp.network_name, rsp_len);

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

    async fn send_handshake(
        &self,
        send_secret_digest: bool,
        metric_network_name: &str,
    ) -> Result<(), Error> {
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
        let pkt_len = zc_packet.buf_len() as u64;

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;
        self.record_control_tx(metric_network_name, pkt_len);

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
                    )));
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
            .and_then(|t| t.remote_url.as_ref())
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
        metric_network_name: &str,
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
        let pkt_len = pkt.buf_len() as u64;
        self.sink.send(pkt).await?;
        self.record_control_tx(metric_network_name, pkt_len);
        Ok(())
    }

    /// Unified remote peer authentication verification.
    ///
    /// Auth outcome matrix (current behavior):
    ///
    /// | Client role | Server role | Typical credential condition | Client auth level | Server auth level | Client sees server type | Server sees client type |
    /// | --- | --- | --- | --- | --- | --- | --- |
    /// | Admin | Admin | same network_secret, proof verified | NetworkSecretConfirmed | NetworkSecretConfirmed | Admin | Admin |
    /// | Credential | Admin | client pubkey is trusted by admin | EncryptedUnauthenticated | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is unknown | handshake may fail | handshake reject | unknown | unknown |
    /// | Admin | SharedNode | pinned key match | PeerVerified | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Admin | SharedNode | local has no pinned key requirement | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Credential | SharedNode | no pin and not trusted | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Credential |
    /// | Credential | Credential | should reject | handshake reject | handshake reject | unknown | unknown |
    ///
    /// Logic (in priority order):
    /// 1. **NetworkSecretConfirmed**: proof verification succeeds
    /// 2. **PeerVerified**: pinned_pubkey matches and is in trusted list
    ///    (if no network_secret, pinned_pubkey must be in trusted list)
    /// 3. **PeerVerified**: pubkey is in trusted list
    /// 4. **EncryptedUnauthenticated**: initiator without network_secret
    /// 5. **Reject**: none of the above
    #[allow(clippy::too_many_arguments)]
    fn verify_remote_auth(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_pubkey: &[u8],
        pinned_pubkey: Option<&[u8]>,
        has_network_secret: bool,
        is_initiator: bool,
        remote_network_name: &str,
    ) -> Result<SecureAuthLevel, Error> {
        // 1. Verify proof
        if let Some(proof) = proof
            && let Some(mac) = self.global_ctx.get_secret_proof(handshake_hash)
            && mac.verify_slice(proof).is_ok()
        {
            return Ok(SecureAuthLevel::NetworkSecretConfirmed);
        }

        // 2. Check pinned pubkey
        if let Some(pinned) = pinned_pubkey {
            if pinned != remote_pubkey {
                return Err(Error::WaitRespError(
                    "pinned remote static pubkey mismatch".to_owned(),
                ));
            }
            // If no network_secret, pinned key must be in trusted list
            if !has_network_secret
                && !self
                    .global_ctx
                    .is_pubkey_trusted(remote_pubkey, remote_network_name)
            {
                return Err(Error::WaitRespError(
                    "pinned pubkey not in trusted list".to_owned(),
                ));
            }
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 3. Check if pubkey is in trusted list
        if self
            .global_ctx
            .is_pubkey_trusted(remote_pubkey, remote_network_name)
        {
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 4. If we are the initiator without network_secret, keep encrypted channel only.
        if is_initiator && !has_network_secret {
            return Ok(SecureAuthLevel::EncryptedUnauthenticated);
        }

        // 5. Reject
        Err(Error::WaitRespError(
            "authentication failed: invalid proof and unknown credential".to_owned(),
        ))
    }

    fn classify_remote_identity(
        &self,
        remote_network_name: &str,
        secure_auth_level: SecureAuthLevel,
        remote_role_hint_is_same_network: bool,
        remote_sent_secret_proof: bool,
        is_client: bool,
    ) -> PeerIdentityType {
        if !remote_role_hint_is_same_network
            || remote_network_name != self.global_ctx.get_network_name()
        {
            if is_client {
                PeerIdentityType::SharedNode
            } else if remote_sent_secret_proof {
                PeerIdentityType::Admin
            } else {
                PeerIdentityType::Credential
            }
        } else {
            if matches!(secure_auth_level, SecureAuthLevel::NetworkSecretConfirmed)
                || remote_sent_secret_proof
            {
                return PeerIdentityType::Admin;
            }

            PeerIdentityType::Credential
        }
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

        self.send_noise_msg(
            msg1_pb,
            PacketType::NoiseHandshakeMsg1,
            PeerId::default(),
            &network.network_name,
            &mut hs,
        )
        .await?;

        let server_handshake_hash = hs.get_handshake_hash().to_vec();

        let msg2 = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg2)),
        )
        .await??;
        self.record_control_rx(&network.network_name, msg2.buf_len() as u64);
        let remote_peer_id = msg2.get_src_peer_id().expect("missing src peer id");
        if let Some(hint) = self.peer_id_hint
            && hint != remote_peer_id
        {
            return Err(Error::WaitRespError("peer_id mismatch".to_owned()));
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
        let remote_sent_secret_proof = msg2_pb.secret_proof_32.is_some();

        if remote_network_name == network.network_name && msg2_pb.role_hint != 1 {
            return Err(Error::WaitRespError(
                "role_hint must be 1 when network_name is same".to_owned(),
            ));
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
            &network.network_name,
            &mut hs,
        )
        .await?;

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

        // Verify server authentication using unified logic
        let secure_auth_level = if msg2_pb.role_hint != 1 && pinned_remote_pubkey.is_none() {
            SecureAuthLevel::EncryptedUnauthenticated
        } else {
            self.verify_remote_auth(
                msg2_pb.secret_proof_32.as_deref(),
                &server_handshake_hash,
                &remote_static,
                pinned_remote_pubkey.as_deref(),
                network.network_secret.is_some(),
                true, // is_initiator
                &remote_network_name,
            )?
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            msg2_pb.role_hint == 1,
            remote_sent_secret_proof,
            true,
        );

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
            remote_static_key,
        )?;

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            peer_identity_type,
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
        let first_msg1_len = first_msg1.buf_len() as u64;

        let msg1_pb = Self::decode_handshake_message::<PeerConnNoiseMsg1Pb>(
            PacketType::NoiseHandshakeMsg1,
            Some(&mut hs),
            first_msg1,
        )?;
        let remote_network_name = msg1_pb.a_network_name.clone();
        self.record_control_rx(&remote_network_name, first_msg1_len);

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
            None,
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
            &remote_network_name,
            &mut hs,
        )
        .await?;

        let handshake_hash_for_proof = hs.get_handshake_hash().to_vec();

        let msg3_pkt = timeout(
            Duration::from_secs(5),
            self.recv_next_peer_manager_packet(Some(PacketType::NoiseHandshakeMsg3)),
        )
        .await??;
        self.record_control_rx(&remote_network_name, msg3_pkt.buf_len() as u64);
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
        session.check_or_set_peer_static_pubkey(remote_static_key)?;

        // Verify client authentication using unified logic
        // Note: Server doesn't use pinned_pubkey since it's the responder
        let secure_auth_level = if role_hint == 1 {
            self.verify_remote_auth(
                msg3_pb.secret_proof_32.as_deref(),
                &handshake_hash_for_proof,
                &remote_static,
                None, // Server doesn't have pinned_remote_pubkey
                self.global_ctx
                    .get_network_identity()
                    .network_secret
                    .is_some(),
                false, // is_initiator
                &remote_network_name,
            )?
        } else {
            SecureAuthLevel::EncryptedUnauthenticated
        };
        let peer_identity_type = self.classify_remote_identity(
            &remote_network_name,
            secure_auth_level,
            role_hint == 1,
            msg3_pb.secret_proof_32.is_some(),
            false,
        );

        let handshake_hash = hs.get_handshake_hash().to_vec();

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            handshake_hash,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
            client_secret_proof: msg3_pb.secret_proof_32.as_ref().map(|p| SecretProof {
                challenge: handshake_hash_for_proof,
                proof: p.clone(),
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
            self.record_control_rx(&rsp.network_name, first_pkt.buf_len() as u64);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest, &self.get_network_identity().network_name)
                .await?;
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
            let network = self.global_ctx.get_network_identity();
            self.send_handshake(true, &network.network_name).await?;
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

    fn control_metrics(&self, network_name: &str) -> AggregateTrafficMetrics {
        AggregateTrafficMetrics::control(
            self.global_ctx.stats_manager().clone(),
            network_name.to_string(),
        )
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.control_metrics(network_name).record_tx(bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.control_metrics(network_name).record_rx(bytes);
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.lock().await.take().unwrap();
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();
        let control_metrics = self.control_metrics(&conn_info_for_instrument.network_name);

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
        } else if self.global_ctx.get_flags().instance_recv_bps_limit != u64::MAX {
            let limiter_config = LimiterConfig {
                burst_rate: None,
                bps: Some(self.global_ctx.get_flags().instance_recv_bps_limit),
                fill_duration_ms: None,
            };
            Some(
                self.global_ctx
                    .token_bucket_manager()
                    .get_or_create("instance:recv", limiter_config.into()),
            )
        } else {
            None
        };

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
                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        break;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        control_metrics.record_rx(buf_len);
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        } else {
                            control_metrics.record_tx(buf_len);
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        control_metrics.record_rx(buf_len);
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
            self.control_metrics(&self.get_conn_info().network_name),
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
        Ok(self.sink.send(msg).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        let mut ret = NetworkIdentity {
            network_name: info.network_name.clone(),
            network_secret: None,
            network_secret_digest: Some([0u8; 32]),
        };
        ret.network_secret_digest
            .as_mut()
            .unwrap()
            .copy_from_slice(&info.network_secret_digest);
        ret
    }

    fn network_secret_digest_is_empty(network: &NetworkIdentity) -> bool {
        network
            .network_secret_digest
            .as_ref()
            .is_none_or(|digest| digest.iter().all(|byte| *byte == 0))
    }

    fn matches_local_secret_proof(&self) -> bool {
        let Some(secret_proof) = self
            .noise_handshake_result
            .as_ref()
            .and_then(|noise| noise.client_secret_proof.as_ref())
        else {
            return false;
        };

        self.global_ctx
            .get_secret_proof(&secret_proof.challenge)
            .is_some_and(|mac| mac.verify_slice(&secret_proof.proof).is_ok())
    }

    pub(crate) fn matches_local_network_secret(&self) -> bool {
        if self.matches_local_secret_proof() {
            return true;
        }

        let my_identity = self.global_ctx.get_network_identity();
        let peer_identity = self.get_network_identity();

        !Self::network_secret_digest_is_empty(&my_identity)
            && !Self::network_secret_digest_is_empty(&peer_identity)
            && my_identity.network_secret_digest == peer_identity.network_secret_digest
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
            peer_identity_type: self
                .noise_handshake_result
                .as_ref()
                .map(|x| x.peer_identity_type as i32)
                .unwrap_or(PeerIdentityType::Admin as i32),
        }
    }

    pub fn get_peer_identity_type(&self) -> PeerIdentityType {
        self.noise_handshake_result
            .as_ref()
            .map(|x| x.peer_identity_type)
            .unwrap_or(PeerIdentityType::Admin)
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
    use std::{sync::Arc, time::Duration};

    use rand::rngs::OsRng;

    use super::*;
    use crate::common::config::PeerConfig;
    use crate::common::global_ctx::GlobalCtx;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::common::stats_manager::{LabelSet, LabelType, MetricName};
    use crate::peers::create_packet_recv_chan;
    use crate::peers::recv_packet_from_chan;
    use crate::tunnel::common::tests::wait_for_condition;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;
    use tokio_util::task::AbortOnDropHandle;

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

    fn metric_value(global_ctx: &GlobalCtx, metric: MetricName, network_name: &str) -> u64 {
        global_ctx
            .stats_manager()
            .get_metric(
                metric,
                &LabelSet::new().with_label_type(LabelType::NetworkName(network_name.to_string())),
            )
            .map(|metric| metric.value)
            .unwrap_or(0)
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
        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());

        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

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

        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default"),
            c_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default"),
            c_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default"),
            s_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default"),
            s_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );

        assert_eq!(c_peer.get_peer_id(), s_peer_id);
        assert_eq!(s_peer.get_peer_id(), c_peer_id);
        assert_eq!(c_peer.get_network_identity(), s_peer.get_network_identity());
        assert_eq!(
            c_peer.get_network_identity().network_name,
            NetworkIdentity::default().network_name
        );
        assert_eq!(c_peer.get_network_identity().network_secret, None);
        assert_eq!(
            c_peer.get_network_identity().network_secret_digest,
            NetworkIdentity::default().network_secret_digest
        );
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

        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default"),
            c_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default"),
            c_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default"),
            s_recorder
                .sent
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );
        assert_eq!(
            metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default"),
            s_recorder
                .received
                .lock()
                .unwrap()
                .iter()
                .map(|pkt| pkt.buf_len() as u64)
                .sum::<u64>()
        );

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
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
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

        let remote_url: url::Url = c.info().unwrap().remote_url.unwrap().url.parse().unwrap();

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
            SecureAuthLevel::PeerVerified as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::SharedNode as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );
    }

    #[tokio::test]
    async fn peer_conn_secure_mode_shared_node_without_pin_is_unauthenticated() {
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
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::SharedNode as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
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
        let _t = AbortOnDropHandle::new(tokio::spawn(async move {
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
    async fn peer_conn_pingpong_records_control_metrics() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();
        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        s_peer.start_recv_loop(create_packet_recv_chan().0).await;
        c_peer.start_pingpong();
        c_peer.start_recv_loop(create_packet_recv_chan().0).await;

        wait_for_condition(
            || {
                let c_ctx = c_ctx.clone();
                let s_ctx = s_ctx.clone();
                async move {
                    metric_value(&c_ctx, MetricName::TrafficControlBytesTx, "default") > 0
                        && metric_value(&c_ctx, MetricName::TrafficControlBytesRx, "default") > 0
                        && metric_value(&s_ctx, MetricName::TrafficControlBytesTx, "default") > 0
                        && metric_value(&s_ctx, MetricName::TrafficControlBytesRx, "default") > 0
                }
            },
            Duration::from_secs(5),
        )
        .await;
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

    /// Helper: set up a credential node's GlobalCtx with a specific private key
    /// (no network_secret, secure mode enabled with the given keypair)
    fn set_credential_mode_cfg(
        global_ctx: &GlobalCtx,
        network_name: &str,
        private_key: &x25519_dalek::StaticSecret,
    ) {
        use crate::common::config::NetworkIdentity;
        let public = x25519_dalek::PublicKey::from(private_key);
        global_ctx
            .config
            .set_network_identity(NetworkIdentity::new_credential(network_name.to_string()));
        global_ctx.config.set_secure_mode(Some(SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private_key.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        }));
    }

    /// Test: credential node connects to admin node, admin has credential in trusted list.
    /// Handshake should succeed with PeerVerified auth level on server side.
    #[tokio::test]
    async fn peer_conn_credential_node_connects_to_admin() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        // Admin node (server) has network_secret
        let s_ctx = get_mock_global_ctx();
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&s_ctx, true);

        // Generate a credential on admin and get the private key for the client
        let (cred_id, cred_secret) = s_ctx.get_credential_manager().generate_credential(
            vec!["guest".to_string()],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

        // Credential node (client) uses credential private key
        let c_ctx = get_mock_global_ctx();
        let privkey_bytes: [u8; 32] = BASE64_STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        set_credential_mode_cfg(&c_ctx, "net1", &private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        // Server should see credential node as PeerVerified
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::PeerVerified as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Credential as i32,
        );

        // Client (credential node) keeps encrypted unauthenticated level
        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated as i32,
        );
        assert_eq!(
            c_peer.get_conn_info().peer_identity_type,
            PeerIdentityType::Admin as i32,
        );

        // Verify credential ID matches
        let _ = cred_id; // just to use it
    }

    /// Test: unknown credential node (not in trusted list) is rejected by admin.
    #[tokio::test]
    async fn peer_conn_unknown_credential_rejected() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        // Admin node (server) with no credentials generated
        let s_ctx = get_mock_global_ctx();
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&s_ctx, true);

        // Unknown credential node (client) with random key, not in admin's trusted list
        let c_ctx = get_mock_global_ctx();
        let random_private = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        set_credential_mode_cfg(&c_ctx, "net1", &random_private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        // Server should reject the unknown credential
        assert!(s_ret.is_err(), "server should reject unknown credential");
        // Client may also fail due to connection being closed
        let _ = c_ret;
    }

    /// Test: two admin nodes with same network_secret still get NetworkSecretConfirmed.
    /// (Regression test: credential system should not break normal admin-to-admin auth)
    #[tokio::test]
    async fn peer_conn_admin_to_admin_still_works() {
        let (c, s) = create_ring_tunnel_pair();

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let s_ctx = get_mock_global_ctx();

        c_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        s_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
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
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed as i32,
        );
    }

    /// Test: revoked credential is rejected on new connection attempt.
    #[tokio::test]
    async fn peer_conn_revoked_credential_rejected() {
        // Admin generates credential, then revokes it
        let admin_ctx = get_mock_global_ctx();
        admin_ctx.config.set_network_identity(NetworkIdentity::new(
            "net1".to_string(),
            "secret".to_string(),
        ));
        set_secure_mode_cfg(&admin_ctx, true);

        let (cred_id, cred_secret) = admin_ctx.get_credential_manager().generate_credential(
            vec![],
            false,
            vec![],
            std::time::Duration::from_secs(3600),
        );

        // Revoke the credential
        assert!(
            admin_ctx
                .get_credential_manager()
                .revoke_credential(&cred_id)
        );

        // Now try to connect with the revoked credential
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let c_ctx = get_mock_global_ctx();
        let privkey_bytes: [u8; 32] = BASE64_STANDARD
            .decode(&cred_secret)
            .unwrap()
            .try_into()
            .unwrap();
        let private = x25519_dalek::StaticSecret::from(privkey_bytes);
        set_credential_mode_cfg(&c_ctx, "net1", &private);

        let ps = Arc::new(PeerSessionStore::new());
        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c), ps.clone());
        let mut s_peer = PeerConn::new(s_peer_id, admin_ctx, Box::new(s), ps.clone());

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        // Server should reject the revoked credential
        assert!(s_ret.is_err(), "server should reject revoked credential");
        let _ = c_ret;
    }
}

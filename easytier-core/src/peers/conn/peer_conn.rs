use arc_swap::ArcSwapOption;
use crossbeam_utils::atomic::AtomicCell;
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

use tokio::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use guarden::guard;
use hmac::Mac;
use prost::Message;

use tokio::{sync::broadcast, task::JoinSet};

use tracing::Instrument;
use zerocopy::AsBytes;
use zeroize::Zeroizing;

use snow::{HandshakeState, params::NoiseParams};

use crate::foundation::time::{Duration, timeout};

use super::{
    fec::{PeerConnFec, PeerConnFecIo},
    peer_conn_liveness::PeerConnLiveness,
    peer_conn_ping::PeerConnPinger,
    peer_session::{PeerSession, PeerSessionAction},
};
use crate::peers::{
    PacketRecvChan, PeerConnectionOrigin, PeerPacketIngress,
    context::{ArcPeerContext, NetworkIdentity, NetworkSecretDigest},
    send_peer_packet_to_chan,
    traffic_metrics::data_packet_payload_len,
};
use crate::{
    config::PeerId,
    packet::{PacketType, ZCPacket},
    peers::conn::peer_session::{PeerSessionStore, SessionKey, UpsertResponderSessionReturn},
    peers::error::Error,
    proto::{
        common::{SecureModeConfig, TunnelInfo},
        core_peer::peer::{PeerConnInfo, PeerConnStats},
        peer_rpc::{
            HandshakeRequest, PeerConnNoiseMsg1Pb, PeerConnNoiseMsg2Pb, PeerConnNoiseMsg3Pb,
            PeerConnSessionActionPb, PeerIdentityType, SecureAuthLevel,
        },
    },
    tunnel::{
        Tunnel, TunnelError, ZCPacketStream,
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        stats::{Throughput, WindowLatency},
    },
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
#[allow(dead_code)]
struct NoiseHandshakeResult {
    peer_id: PeerId,
    session: Arc<PeerSession>,
    local_static_pubkey: Vec<u8>,
    remote_static_pubkey: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
    peer_identity_type: PeerIdentityType,
    remote_network_name: String,

    secret_digest: Vec<u8>,

    // foreign network manager use this to verify peer.
    // the challenge will be sent to authorized peer and compare the proof against it.
    client_secret_proof: Option<SecretProof>,
    remote_features: Vec<String>,
}

#[derive(Clone)]
struct PeerSessionTunnelFilter {
    enabled: bool,
    my_peer_id: Arc<AtomicCell<PeerId>>,
    peer_id: Arc<AtomicCell<Option<PeerId>>>,
    session: Arc<ArcSwapOption<PeerSession>>,
}

impl PeerSessionTunnelFilter {
    fn new_with_peer(my_peer_id: PeerId, enabled: bool) -> Self {
        Self {
            enabled,
            my_peer_id: Arc::new(AtomicCell::new(my_peer_id)),
            peer_id: Arc::new(AtomicCell::new(None)),
            session: Arc::new(ArcSwapOption::empty()),
        }
    }

    fn set_my_peer_id(&self, my_peer_id: PeerId) {
        self.my_peer_id.store(my_peer_id);
    }

    fn set_peer_id(&self, peer_id: PeerId) {
        self.peer_id.store(Some(peer_id));
    }

    fn set_session(&self, session: Arc<PeerSession>) {
        self.session.store(Some(session));
    }

    fn should_skip_encrypt(&self, hdr: &crate::packet::PeerManagerHeader) -> bool {
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

        let my_peer_id = self.my_peer_id.load();
        if my_peer_id != hdr.from_peer_id.get() || hdr.to_peer_id.get() != peer_id {
            return Some(data);
        }

        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
            return Some(data);
        };
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

        let session_guard = self.session.load();
        let Some(session) = session_guard.as_deref() else {
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
    fec: Arc<PeerConnFec>,
}

impl PeerConnCloseNotify {
    fn new(conn_id: PeerConnId, fec: Arc<PeerConnFec>) -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            conn_id,
            sender: Arc::new(std::sync::Mutex::new(Some(sender))),
            fec,
        }
    }

    fn notify_close(&self) {
        self.fec.close();
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
    origin: PeerConnectionOrigin,

    my_peer_id: PeerId,
    peer_id_hint: Option<PeerId>,
    context: ArcPeerContext,

    secure_mode_cfg: Option<SecureModeConfig>,
    session_filter: PeerSessionTunnelFilter,
    noise_handshake_result: Option<NoiseHandshakeResult>,

    #[allow(dead_code)]
    tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: MpscTunnelSender,
    recv: Mutex<Option<Pin<Box<dyn ZCPacketStream>>>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,
    is_client: Option<bool>,

    close_event_notifier: Arc<PeerConnCloseNotify>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,
    liveness: PeerConnLiveness,
    fec: Arc<PeerConnFec>,

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
    #[cfg(test)]
    pub(crate) fn new(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        tunnel: Box<dyn Tunnel>,
        peer_session_store: Arc<PeerSessionStore>,
    ) -> Self {
        Self::new_with_peer_id_hint_and_origin(
            my_peer_id,
            context,
            tunnel,
            None,
            peer_session_store,
            PeerConnectionOrigin::Manual,
        )
    }

    pub(crate) fn new_with_peer_id_hint_and_origin(
        my_peer_id: PeerId,
        context: ArcPeerContext,
        tunnel: Box<dyn Tunnel>,
        peer_id_hint: Option<PeerId>,
        peer_session_store: Arc<PeerSessionStore>,
        origin: PeerConnectionOrigin,
    ) -> Self {
        let flags = context.flags();
        let tunnel_info = tunnel.info();
        let fec_supported = tunnel_info
            .as_ref()
            .is_some_and(|info| info.tunnel_type == "udp");
        let fec = Arc::new(PeerConnFec::new(
            context.fec_config(),
            fec_supported,
            fec_supported.then(|| context.fec_budget()).flatten(),
        ));
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let secure_mode_cfg = context.secure_mode();
        let session_filter = PeerSessionTunnelFilter::new_with_peer(
            my_peer_id,
            secure_mode_cfg
                .as_ref()
                .map(|cfg| cfg.enabled)
                .unwrap_or(false),
        );

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let liveness = PeerConnLiveness::new();
        let filter_chain = TunnelFilterChain::new(session_filter.clone(), peer_conn_tunnel_filter)
            .chain(liveness.clone());
        let (recv, sink, tunnel): (_, _, Box<dyn Any + Send + 'static>) = if fec.advertised() {
            let mut fec_tunnel = PeerConnFecIo::new(tunnel, filter_chain, fec.clone());
            let recv = fec_tunnel.get_stream();
            let sink = fec_tunnel.get_sink();
            (
                recv,
                sink,
                Box::new(guard!([mut fec_tunnel] fec_tunnel.close())),
            )
        } else {
            let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
            let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));
            let recv = mpsc_tunnel.get_stream();
            let sink = mpsc_tunnel.get_sink();
            (
                recv,
                sink,
                Box::new(guard!([mut mpsc_tunnel] mpsc_tunnel.close())),
            )
        };

        let conn_id = PeerConnId::new_v4();
        let my_encrypt_algo = flags.encryption_algorithm;

        PeerConn {
            conn_id,
            origin,

            my_peer_id,
            peer_id_hint,
            context,

            secure_mode_cfg,
            session_filter,
            noise_handshake_result: None,

            tunnel: Arc::new(Mutex::new(tunnel)),
            sink,
            recv: Mutex::new(Some(recv)),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id, fec.clone())),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
            liveness,
            fec,

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

    pub(crate) fn is_attached(&self) -> bool {
        self.origin == PeerConnectionOrigin::Attached
    }

    pub fn is_hole_punched(&self) -> bool {
        matches!(
            self.origin,
            PeerConnectionOrigin::TcpHolePunch | PeerConnectionOrigin::UdpHolePunch
        )
    }

    fn max_ping_interval(&self) -> Duration {
        match self.origin {
            // TCP hole-punched connections need frequent traffic to stay alive.
            PeerConnectionOrigin::TcpHolePunch => Duration::from_secs(1),
            PeerConnectionOrigin::Manual
            | PeerConnectionOrigin::Direct
            | PeerConnectionOrigin::Listener
            | PeerConnectionOrigin::UdpHolePunch
            | PeerConnectionOrigin::Attached => Duration::from_secs(32),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.close_event_notifier.is_closed()
    }

    async fn wait_handshake(&self, need_retry: &mut bool) -> Result<HandshakeRequest, Error> {
        *need_retry = false;

        let rsp = self.recv_next_peer_manager_packet(None).await?;

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

    fn features(&self) -> Vec<String> {
        let mut features = vec![super::peer_conn_liveness::FEATURE.to_owned()];
        self.fec.append_features(&mut features);
        features
    }

    async fn send_handshake(
        &self,
        send_secret_digest: bool,
        metric_network_name: &str,
    ) -> Result<(), Error> {
        let network = self.context.network_identity();
        let mut req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: self.features(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };

        // only send network secret digest if the network is the same
        if send_secret_digest {
            req.network_secret_digest
                .extend_from_slice(&network.secret_digest().unwrap_or_default());
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
        self.context
            .pinned_remote_static_pubkey(self.tunnel_info.as_ref())
    }

    async fn send_noise_msg(
        &self,
        payload: Zeroizing<Vec<u8>>,
        packet_type: PacketType,
        remote_peer_id: PeerId,
        metric_network_name: &str,
        hs: &mut snow::HandshakeState,
    ) -> Result<(), Error> {
        tracing::info!(
            "send noise msg, packet_type: {:?}, from: {:?}, to: {:?}",
            packet_type,
            self.my_peer_id,
            remote_peer_id
        );
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
    /// | Credential | Admin | admin key is pinned and client key is trusted | PeerVerified | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is trusted, admin key is not pinned | EncryptedUnauthenticated | PeerVerified | Admin | Credential |
    /// | Credential | Admin | client pubkey is unknown | handshake may fail | handshake reject | unknown | unknown |
    /// | Admin | SharedNode | pinned key match | PeerVerified | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Admin | SharedNode | local has no pinned key requirement | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Admin |
    /// | Credential | SharedNode | no pin and not trusted | EncryptedUnauthenticated | EncryptedUnauthenticated | SharedNode | Credential |
    /// | Credential | Credential | should reject | handshake reject | handshake reject | unknown | unknown |
    ///
    /// Logic (in priority order):
    /// 1. **NetworkSecretConfirmed**: proof verification succeeds
    /// 2. **PeerVerified**: pinned_pubkey matches
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
            && let Some(mac) = self.context.secret_proof(handshake_hash)
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
            return Ok(SecureAuthLevel::PeerVerified);
        }

        // 3. Check if pubkey is in trusted list
        if self
            .context
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
        if !remote_role_hint_is_same_network || remote_network_name != self.context.network_name() {
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

        let network = self.context.network_identity();
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
            features: self.features(),
        };

        let mut hs = builder
            .prologue(&prologue)?
            .local_private_key(&local_private_key)?
            .build_initiator()?;

        self.send_noise_msg(
            Zeroizing::new(msg1_pb.encode_to_vec()),
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
            .context
            .secret_proof(&handshake_hash_for_proof)
            .map(|mac| mac.finalize().into_bytes().to_vec());

        let secret_digest = self.context.secret_digest(&network);

        let msg3_pb = PeerConnNoiseMsg3Pb {
            a_conn_id_echo: Some(a_conn_id.into()),
            b_conn_id_echo: msg2_pb.b_conn_id,
            secret_proof_32,
            secret_digest: secret_digest.clone(),
        };
        self.send_noise_msg(
            Zeroizing::new(msg3_pb.encode_to_vec()),
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

        let algo = self.context.flags().encryption_algorithm.clone();
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
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            // we have authorized the peer with noise handshake, so just set secret digest same as us even remote is a shared node.
            secret_digest,
            client_secret_proof: None,
            remote_features: msg2_pb.features,
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
                let mut out = Zeroizing::new(vec![0u8; 4096]);
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

        let server_network_name = self.context.network_name();
        let (role_hint, secret_proof_32) = if msg1_pb.a_network_name == server_network_name {
            (
                1,
                self.context
                    .secret_proof(hs.get_handshake_hash())
                    .map(|m| m.finalize().into_bytes().to_vec()),
            )
        } else {
            (2, None)
        };

        let algo = self.context.flags().encryption_algorithm.clone();
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
            features: self.features(),
        };
        let payload = Zeroizing::new(msg2_pb.encode_to_vec());
        self.send_noise_msg(
            payload,
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
                self.context.network_identity().network_secret.is_some(),
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

        Ok(NoiseHandshakeResult {
            peer_id: remote_peer_id,
            session,
            local_static_pubkey: local_static_pubkey.to_vec(),
            remote_static_pubkey: remote_static,
            secure_auth_level,
            peer_identity_type,
            remote_network_name,
            secret_digest: msg3_pb.secret_digest,
            client_secret_proof: msg3_pb.secret_proof_32.as_ref().map(|p| SecretProof {
                challenge: handshake_hash_for_proof,
                proof: p.clone(),
            }),
            remote_features: msg1_pb.features,
        })
    }

    fn build_handshake_rsp(&self, noise: &NoiseHandshakeResult) -> HandshakeRequest {
        tracing::info!("build_handshake_rsp: {:?}", noise);
        HandshakeRequest {
            magic: MAGIC,
            my_peer_id: noise.peer_id,
            version: VERSION,
            network_name: noise.remote_network_name.clone(),

            features: noise.remote_features.clone(),
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
        let fec = self.fec.clone();
        let close_fec_on_error = guard!([fec] fec.close());
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

            let send_digest = self.get_network_identity() == self.context.network_identity();
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
            self.liveness
                .set_remote_features(&self.info.as_ref().unwrap().features);
            self.fec
                .set_remote_features(&self.info.as_ref().unwrap().features);
            close_fec_on_error.defuse();
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        let fec = self.fec.clone();
        let close_fec_on_error = guard!([fec] fec.close());
        if self.is_secure_mode_enabled() {
            let noise = self.do_noise_handshake_as_client().await?;
            self.session_filter.set_session(noise.session.clone());
            self.session_filter.set_peer_id(noise.peer_id);

            let handshake_rsp = self.build_handshake_rsp(&noise);
            self.noise_handshake_result = Some(noise);
            self.info = Some(handshake_rsp);
            self.is_client = Some(true);
        } else {
            let network = self.context.network_identity();
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
            self.liveness
                .set_remote_features(&self.info.as_ref().unwrap().features);
            self.fec
                .set_remote_features(&self.info.as_ref().unwrap().features);
            close_fec_on_error.defuse();
            Ok(())
        }
    }

    fn record_control_tx(&self, network_name: &str, bytes: u64) {
        self.context.record_control_tx(network_name, bytes);
    }

    fn record_control_rx(&self, network_name: &str, bytes: u64) {
        self.context.record_control_rx(network_name, bytes);
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.lock().await.take().unwrap();
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();
        let context = self.context.clone();
        let ingress = PeerPacketIngress::Peer {
            peer_id: self.get_peer_id(),
            conn_id: self.conn_id,
            origin: self.origin,
        };
        let control_network_name = conn_info_for_instrument.network_name.clone();

        let is_foreign_network =
            conn_info_for_instrument.network_name != self.context.network_identity().network_name;
        let recv_limiter = self
            .context
            .recv_limiter(&conn_info_for_instrument.network_name, is_foreign_network);

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
                    if let Some(payload_len) = data_packet_payload_len(&zc_packet)
                        && let Some(limiter) = recv_limiter.as_ref()
                        && !limiter.try_consume(payload_len)
                    {
                        continue;
                    }
                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        break;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        context.record_control_rx(&control_network_name, buf_len);
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        } else {
                            context.record_control_tx(&control_network_name, buf_len);
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        context.record_control_rx(&control_network_name, buf_len);
                        if let Err(e) = ctrl_sender.send(zc_packet) {
                            tracing::error!(?e, "peer conn send ctrl resp error");
                        }
                    } else if send_peer_packet_to_chan(&sender, zc_packet, ingress)
                        .await
                        .is_err()
                    {
                        break;
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
            self.context.clone(),
            self.get_conn_info().network_name,
            self.liveness.clone(),
            self.max_ping_interval(),
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
            .secret_digest()
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

        self.context
            .secret_proof(&secret_proof.challenge)
            .is_some_and(|mac| mac.verify_slice(&secret_proof.proof).is_ok())
    }

    pub fn matches_local_network_secret(&self) -> bool {
        if self.matches_local_secret_proof() {
            return true;
        }

        let my_identity = self.context.network_identity();
        let peer_identity = self.get_network_identity();

        !Self::network_secret_digest_is_empty(&my_identity)
            && !Self::network_secret_digest_is_empty(&peer_identity)
            && my_identity.secret_digest() == peer_identity.secret_digest()
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
            fec: Some(self.fec.info()),
            session_replay_rejections: self
                .noise_handshake_result
                .as_ref()
                .map(|noise| noise.session.replay_rejections())
                .unwrap_or_default(),
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
mod tests {
    use super::*;
    use crate::{
        config::FecConfig,
        packet::{FEC_HEADER_SIZE, ZCPacketType},
        peers::{PacketRecvChanReceiver, conn::fec::FecInstanceBudget},
        tunnel::SplitTunnel,
    };
    use crate::{peers::test_support::NoopPeerContext, tunnel::ring::create_ring_tunnel_pair};
    use std::sync::atomic::{AtomicBool, AtomicUsize};
    use tokio::sync::Notify;

    #[tokio::test]
    async fn connection_origin_determines_hole_punch_and_ping_policy() {
        for (origin, is_hole_punched, max_interval) in [
            (PeerConnectionOrigin::Manual, false, 32),
            (PeerConnectionOrigin::Direct, false, 32),
            (PeerConnectionOrigin::Listener, false, 32),
            (PeerConnectionOrigin::TcpHolePunch, true, 1),
            (PeerConnectionOrigin::UdpHolePunch, true, 32),
            (PeerConnectionOrigin::Attached, false, 32),
        ] {
            // Admission determines the policy even when the transport is a ring.
            let (tunnel, _remote_tunnel) = create_ring_tunnel_pair();
            let conn = PeerConn::new_with_peer_id_hint_and_origin(
                1,
                Arc::new(NoopPeerContext::default()),
                tunnel,
                None,
                Arc::new(PeerSessionStore::new()),
                origin,
            );

            assert_eq!(conn.is_hole_punched(), is_hole_punched, "{origin:?}");
            assert_eq!(
                conn.max_ping_interval(),
                Duration::from_secs(max_interval),
                "{origin:?}",
            );
            assert_eq!(conn.is_attached(), origin == PeerConnectionOrigin::Attached);
        }
    }

    struct FecTestContext {
        inner: NoopPeerContext,
        fec: crate::config::FecConfig,
        budget: Arc<FecInstanceBudget>,
    }

    impl crate::peers::context::PeerContext for FecTestContext {
        fn network_identity(&self) -> NetworkIdentity {
            self.inner.network_identity()
        }
        fn flags(&self) -> crate::proto::common::Flags {
            self.inner.flags()
        }
        fn secure_mode(&self) -> Option<SecureModeConfig> {
            self.inner.secure_mode()
        }
        fn secret_proof(&self, challenge: &[u8]) -> Option<hmac::Hmac<sha2::Sha256>> {
            self.inner.secret_proof(challenge)
        }
        fn fec_config(&self) -> crate::config::FecConfig {
            self.fec.clone()
        }
        fn fec_budget(&self) -> Option<Arc<FecInstanceBudget>> {
            Some(self.budget.clone())
        }
    }

    fn fec_context(
        network: &str,
        secret: Option<&str>,
        secure: bool,
        key: u8,
        fec: FecConfig,
    ) -> ArcPeerContext {
        let mut inner = NoopPeerContext::new(NetworkIdentity {
            network_name: network.to_owned(),
            network_secret: secret.map(str::to_owned),
            network_secret_digest: None,
        });
        if secure {
            let private = x25519_dalek::StaticSecret::from([key; 32]);
            let public = x25519_dalek::PublicKey::from(&private);
            inner = inner.with_secure_mode(SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            });
        }
        Arc::new(FecTestContext {
            inner,
            fec,
            budget: Arc::new(FecInstanceBudget::default()),
        })
    }

    // Exercise the real PeerConn adapter without depending on UDP socket internals.
    // Each direction can erase one selected source and hold the final handshake
    // while later source/repair frames continue reaching the remote adapter.
    #[derive(Default)]
    struct FecTestWire {
        drop_source: Option<usize>,
        source_count: AtomicUsize,
        sent: parking_lot::Mutex<Vec<ZCPacket>>,
        delay_handshake: Option<PacketType>,
        handshake_held: AtomicBool,
        release_handshake: Notify,
    }

    impl TunnelFilter for FecTestWire {
        type FilterOutput = ();

        fn before_send(&self, packet: ZCPacket) -> Option<ZCPacket> {
            let packet_type = packet.peer_manager_header().unwrap().packet_type;
            self.sent.lock().push(packet.clone());
            if packet_type == PacketType::FecSource as u8 {
                let index = self.source_count.fetch_add(1, Ordering::Relaxed);
                if self.drop_source == Some(index) {
                    return None;
                }
            }
            Some(packet)
        }

        fn filter_output(&self) {}
    }

    struct FecTestTunnel {
        inner: TunnelWithFilter<Box<dyn Tunnel>, Arc<FecTestWire>>,
        incoming: Arc<FecTestWire>,
        tunnel_type: &'static str,
    }

    impl Tunnel for FecTestTunnel {
        fn split(&self) -> SplitTunnel {
            let (stream, sink) = self.inner.split();
            let incoming = self.incoming.clone();
            let stream = futures::stream::unfold((stream, None), move |(mut stream, mut held)| {
                let incoming = incoming.clone();
                async move {
                    loop {
                        let packet = if held.is_some() {
                            tokio::select! {
                                _ = incoming.release_handshake.notified() => {
                                    return Some((held.take().unwrap(), (stream, held)));
                                }
                                packet = stream.next() => packet?,
                            }
                        } else {
                            stream.next().await?
                        };
                        if packet.as_ref().ok().is_some_and(|packet| {
                            incoming.delay_handshake.is_some_and(|kind| {
                                packet.peer_manager_header().unwrap().packet_type == kind as u8
                            })
                        }) {
                            assert!(held.is_none());
                            held = Some(packet);
                            incoming.handshake_held.store(true, Ordering::Relaxed);
                        } else {
                            return Some((packet, (stream, held)));
                        }
                    }
                }
            });
            (Box::pin(stream), sink)
        }

        fn info(&self) -> Option<TunnelInfo> {
            Some(TunnelInfo {
                tunnel_type: self.tunnel_type.to_owned(),
                ..Default::default()
            })
        }
    }

    fn fec_peers(
        a: ArcPeerContext,
        b: ArcPeerContext,
        tunnel_type: &'static str,
        a_wire: Arc<FecTestWire>,
        b_wire: Arc<FecTestWire>,
    ) -> (PeerConn, PeerConn) {
        let (a_tunnel, b_tunnel) = create_ring_tunnel_pair();
        let a_tunnel = FecTestTunnel {
            inner: TunnelWithFilter::new(a_tunnel, a_wire.clone()),
            incoming: b_wire.clone(),
            tunnel_type,
        };
        let b_tunnel = FecTestTunnel {
            inner: TunnelWithFilter::new(b_tunnel, b_wire),
            incoming: a_wire,
            tunnel_type,
        };
        (
            PeerConn::new(1, a, Box::new(a_tunnel), Arc::new(PeerSessionStore::new())),
            PeerConn::new(2, b, Box::new(b_tunnel), Arc::new(PeerSessionStore::new())),
        )
    }

    fn fec_policy(max_repair_percent: u32, udp_payload_mtu: u32) -> FecConfig {
        FecConfig {
            enabled: true,
            force_peer: false,
            udp_payload_mtu,
            max_repair_percent,
        }
    }

    fn erased_wire(delay_handshake: Option<PacketType>) -> Arc<FecTestWire> {
        Arc::new(FecTestWire {
            drop_source: Some(0),
            delay_handshake,
            ..Default::default()
        })
    }

    async fn send_block(conn: &PeerConn, from: u32, to: u32, count: u8, size: usize) {
        for index in 1..=count {
            conn.send_msg(peer_data(from, to, &vec![index; size]))
                .await
                .unwrap();
        }
    }

    async fn receive_block(receiver: &mut PacketRecvChanReceiver, count: u8, size: usize) {
        let mut payloads = Vec::new();
        for _ in 0..count {
            let packet = timeout(Duration::from_secs(1), receiver.recv())
                .await
                .unwrap()
                .unwrap();
            assert!(!packet.peer_manager_header().unwrap().is_encrypted());
            payloads.push(packet.payload().to_vec());
        }
        payloads.sort();
        assert_eq!(
            payloads,
            (1..=count).map(|i| vec![i; size]).collect::<Vec<_>>()
        );
    }

    fn protected_source(wire: &FecTestWire) -> ZCPacket {
        let sent = wire.sent.lock();
        let source = sent
            .iter()
            .find(|packet| {
                packet.peer_manager_header().unwrap().packet_type == PacketType::FecSource as u8
            })
            .expect("the erased packet must be a protected source");
        ZCPacket::new_from_buf(
            bytes::BytesMut::from(&source.payload()[FEC_HEADER_SIZE..]),
            ZCPacketType::DummyTunnel,
        )
    }

    fn assert_uncoded(wire: &FecTestWire) {
        assert!(wire.sent.lock().iter().all(|packet| {
            let kind = packet.peer_manager_header().unwrap().packet_type;
            kind != PacketType::FecSource as u8 && kind != PacketType::FecRepair as u8
        }));
    }

    async fn wait_early_recovery(fec: &PeerConnFec, wire: &FecTestWire) {
        timeout(Duration::from_secs(1), async {
            while fec.info().stats.unwrap().recovered_packets == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("early business must be decoded while the handshake is still waiting");
        assert!(wire.handshake_held.load(Ordering::Relaxed));
        assert!(!fec.info().tx_active);
        assert!(!fec.info().rx_active);
    }

    async fn handshake_pair(a: &mut PeerConn, b: &mut PeerConn) {
        let (a_result, b_result) = tokio::join!(
            a.do_handshake_as_client(),
            b.do_handshake_as_server_ext(|_, _| Ok(()))
        );
        a_result.unwrap();
        b_result.unwrap();
    }

    fn peer_data(from: u32, to: u32, payload: &[u8]) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(from, to, PacketType::Data as u8);
        packet
    }

    #[tokio::test]
    async fn fec_legacy_and_noise_restore_asymmetric_erased_packets() {
        for (secure, a_network, b_network, secret) in [
            (false, "mesh", "mesh", Some("secret")),
            (true, "mesh", "mesh", Some("secret")),
            (false, "mesh", "mesh", None),
            (true, "a-network", "b-network", None),
        ] {
            let a_wire = erased_wire(None);
            let b_wire = erased_wire(None);
            let (mut a, mut b) = fec_peers(
                fec_context(a_network, secret, secure, 1, fec_policy(100, 900)),
                fec_context(b_network, secret, secure, 2, fec_policy(100, 1800)),
                "udp",
                a_wire.clone(),
                b_wire.clone(),
            );
            handshake_pair(&mut a, &mut b).await;
            assert!(a.fec.info().tx_active && b.fec.info().tx_active);
            let (a_tx, mut a_rx) = crate::peers::create_packet_recv_chan();
            let (b_tx, mut b_rx) = crate::peers::create_packet_recv_chan();
            a.start_recv_loop(a_tx).await;
            b.start_recv_loop(b_tx).await;
            send_block(&a, 1, 2, 4, 80).await;
            // B's protected packets exceed A's local TX MTU.
            send_block(&b, 2, 1, 8, 1100).await;
            receive_block(&mut b_rx, 4, 80).await;
            receive_block(&mut a_rx, 8, 1100).await;
            assert_eq!(a.fec.info().stats.unwrap().recovered_packets, 1);
            assert_eq!(b.fec.info().stats.unwrap().recovered_packets, 1);
            for wire in [&a_wire, &b_wire] {
                let protected = protected_source(wire);
                assert_eq!(
                    protected.peer_manager_header().unwrap().is_encrypted(),
                    secure
                );
                if secure {
                    assert_ne!(protected.payload(), vec![1; protected.payload().len()]);
                }
            }
            assert_eq!(a.get_conn_info().session_replay_rejections, 0);
            assert_eq!(b.get_conn_info().session_replay_rejections, 0);
            a.close_event_notifier.notify_close();
            assert!(!a.fec.info().tx_active);
            assert_eq!(a.fec.info().stats.unwrap().memory_bytes, 0);
        }
    }

    #[tokio::test]
    async fn fec_sends_only_in_enabled_or_requested_directions() {
        for secure in [false, true] {
            for (a_enabled, a_force_peer, b_enabled, b_force_peer, tunnel_type) in [
                (false, false, false, false, "udp"),
                (true, false, false, false, "udp"),
                (false, false, true, false, "udp"),
                (true, false, true, false, "udp"),
                (false, true, false, false, "udp"),
                (false, false, false, true, "udp"),
                (true, true, false, false, "udp"),
                (false, false, true, true, "udp"),
                (false, true, true, false, "udp"),
                (true, false, false, true, "udp"),
                (false, true, false, true, "udp"),
                (true, true, false, true, "udp"),
                (false, true, true, true, "udp"),
                (true, false, true, true, "udp"),
                (true, true, true, false, "udp"),
                (true, true, true, true, "udp"),
                (true, true, true, true, "tcp"),
                (true, true, true, true, "quic"),
            ] {
                let a_wire = erased_wire(None);
                let b_wire = erased_wire(None);
                let (mut a, mut b) = fec_peers(
                    fec_context(
                        "mesh",
                        Some("secret"),
                        secure,
                        1,
                        FecConfig {
                            enabled: a_enabled,
                            force_peer: a_force_peer,
                            ..fec_policy(100, 1400)
                        },
                    ),
                    fec_context(
                        "mesh",
                        Some("secret"),
                        secure,
                        2,
                        FecConfig {
                            enabled: b_enabled,
                            force_peer: b_force_peer,
                            ..fec_policy(100, 1800)
                        },
                    ),
                    tunnel_type,
                    a_wire.clone(),
                    b_wire.clone(),
                );
                handshake_pair(&mut a, &mut b).await;
                let (a_tx, mut a_rx) = crate::peers::create_packet_recv_chan();
                let (b_tx, mut b_rx) = crate::peers::create_packet_recv_chan();
                a.start_recv_loop(a_tx).await;
                b.start_recv_loop(b_tx).await;
                send_block(&a, 1, 2, 4, 80).await;
                send_block(&b, 2, 1, 8, 1100).await;
                receive_block(&mut b_rx, 4, 80).await;
                receive_block(&mut a_rx, 8, 1100).await;
                for (conn, wire, enabled, force_peer, remote_enabled, remote_force_peer, count) in [
                    (
                        &a,
                        &a_wire,
                        a_enabled,
                        a_force_peer,
                        b_enabled,
                        b_force_peer,
                        4,
                    ),
                    (
                        &b,
                        &b_wire,
                        b_enabled,
                        b_force_peer,
                        a_enabled,
                        a_force_peer,
                        8,
                    ),
                ] {
                    let info = conn.fec.info();
                    let tx_active = (enabled || remote_force_peer) && tunnel_type == "udp";
                    assert_eq!(info.desired_enabled, enabled);
                    assert_eq!(info.desired_force_peer, force_peer);
                    assert_eq!(
                        info.peer_requested,
                        remote_force_peer && tunnel_type == "udp"
                    );
                    assert_eq!(conn.context.fec_config().enabled, enabled);
                    assert_eq!(conn.context.fec_config().force_peer, force_peer);
                    assert_eq!(info.tx_active, tx_active);
                    assert_eq!(info.rx_active, tunnel_type == "udp");
                    assert_eq!(info.tx_parameters.is_some(), tx_active);
                    if let Some(parameters) = info.tx_parameters {
                        assert_eq!(parameters.window_packets, Some(64));
                        assert_eq!(
                            parameters.udp_payload_mtu,
                            Some(conn.context.fec_config().udp_payload_mtu)
                        );
                        assert_eq!(parameters.max_repair_percent, Some(100));
                    }
                    let stats = info.stats.unwrap();
                    assert_eq!(stats.tx_source_packets, if tx_active { count } else { 0 });
                    assert_eq!(
                        stats.recovered_packets,
                        u64::from((remote_enabled || force_peer) && tunnel_type == "udp")
                    );
                    if !tx_active {
                        assert_uncoded(wire);
                        assert_eq!(stats.tx_repair_packets, 0);
                    }
                    conn.close_event_notifier.notify_close();
                    assert!(!conn.fec.info().tx_active);
                    assert!(!conn.fec.info().rx_active);
                    assert_eq!(conn.fec.info().stats.unwrap().memory_bytes, 0);
                }
            }
        }
    }

    #[tokio::test]
    async fn fec_force_peer_is_connection_local() {
        for secure in [false, true] {
            let shared = fec_context("mesh", Some("secret"), secure, 2, FecConfig::default());
            let (mut a, mut b) = fec_peers(
                fec_context(
                    "mesh",
                    Some("secret"),
                    secure,
                    1,
                    FecConfig {
                        force_peer: true,
                        ..FecConfig::default()
                    },
                ),
                shared.clone(),
                "udp",
                Arc::new(FecTestWire::default()),
                Arc::new(FecTestWire::default()),
            );
            handshake_pair(&mut a, &mut b).await;
            assert!(!a.fec.info().tx_active);
            assert!(b.fec.info().tx_active);
            assert!(b.fec.info().peer_requested);
            assert_eq!(shared.fec_config(), FecConfig::default());

            let (mut c, mut other) = fec_peers(
                fec_context("mesh", Some("secret"), secure, 3, FecConfig::default()),
                shared,
                "udp",
                Arc::new(FecTestWire::default()),
                Arc::new(FecTestWire::default()),
            );
            handshake_pair(&mut c, &mut other).await;
            assert!(!c.fec.info().tx_active);
            assert!(!other.fec.info().tx_active);
            assert!(!other.fec.info().peer_requested);
            assert!(b.fec.info().tx_active);
        }
    }

    #[tokio::test]
    async fn fec_peer_without_support_uses_original_framing() {
        let a_wire = Arc::new(FecTestWire::default());
        let b_wire = Arc::new(FecTestWire::default());
        let (mut a, mut b) = fec_peers(
            fec_context(
                "mesh",
                Some("secret"),
                false,
                1,
                FecConfig {
                    force_peer: true,
                    ..fec_policy(100, 1400)
                },
            ),
            Arc::new(NoopPeerContext::new(NetworkIdentity {
                network_name: "mesh".to_owned(),
                network_secret: Some("secret".to_owned()),
                network_secret_digest: None,
            })),
            "udp",
            a_wire.clone(),
            b_wire.clone(),
        );
        handshake_pair(&mut a, &mut b).await;
        assert_eq!(a.fec.info().tx_reason, "remote_unsupported");
        assert!(!a.fec.info().rx_active);
        let (a_tx, mut a_rx) = crate::peers::create_packet_recv_chan();
        let (b_tx, mut b_rx) = crate::peers::create_packet_recv_chan();
        a.start_recv_loop(a_tx).await;
        b.start_recv_loop(b_tx).await;
        send_block(&a, 1, 2, 4, 80).await;
        send_block(&b, 2, 1, 4, 80).await;
        receive_block(&mut b_rx, 4, 80).await;
        receive_block(&mut a_rx, 4, 80).await;
        assert_uncoded(&a_wire);
        assert_uncoded(&b_wire);
        assert_eq!(a.fec.info().stats.unwrap().memory_bytes, 0);
    }

    #[tokio::test]
    async fn fec_early_business_waits_for_legacy_response_and_noise_msg3() {
        for (secure, force_peer) in [(false, false), (true, false), (false, true), (true, true)] {
            let a_wire = erased_wire(secure.then_some(PacketType::NoiseHandshakeMsg3));
            let b_wire = erased_wire((!secure).then_some(PacketType::HandShake));
            let (mut a, mut b) = fec_peers(
                fec_context(
                    "mesh",
                    Some("secret"),
                    secure,
                    1,
                    FecConfig {
                        enabled: secure && !force_peer,
                        force_peer: !secure && force_peer,
                        ..fec_policy(100, 1400)
                    },
                ),
                fec_context(
                    "mesh",
                    Some("secret"),
                    secure,
                    2,
                    FecConfig {
                        enabled: !secure && !force_peer,
                        force_peer: secure && force_peer,
                        ..fec_policy(100, 1400)
                    },
                ),
                "udp",
                a_wire.clone(),
                b_wire.clone(),
            );
            if secure {
                let b_fec = b.fec.clone();
                let b_session = b.session_filter.clone();
                let ((), server_result) = tokio::join!(
                    async {
                        a.do_handshake_as_client().await.unwrap();
                        send_block(&a, 1, 2, 4, 80).await;
                        wait_early_recovery(&b_fec, &a_wire).await;
                        assert!(b_session.session.load().is_none());
                        assert!(
                            protected_source(&a_wire)
                                .peer_manager_header()
                                .unwrap()
                                .is_encrypted()
                        );
                        a_wire.release_handshake.notify_one();
                    },
                    b.do_handshake_as_server_ext(|_, _| Ok(())),
                );
                server_result.unwrap();
            } else {
                let a_fec = a.fec.clone();
                let (client_result, ()) = tokio::join!(a.do_handshake_as_client(), async {
                    b.do_handshake_as_server_ext(|_, _| Ok(())).await.unwrap();
                    send_block(&b, 2, 1, 4, 80).await;
                    wait_early_recovery(&a_fec, &b_wire).await;
                    b_wire.release_handshake.notify_one();
                },);
                client_result.unwrap();
            }
            let (a_tx, mut a_rx) = crate::peers::create_packet_recv_chan();
            let (b_tx, mut b_rx) = crate::peers::create_packet_recv_chan();
            a.start_recv_loop(a_tx).await;
            b.start_recv_loop(b_tx).await;
            if secure {
                receive_block(&mut b_rx, 4, 80).await;
                assert_eq!(b.get_conn_info().session_replay_rejections, 0);
            } else {
                receive_block(&mut a_rx, 4, 80).await;
            }
        }
    }

    #[tokio::test]
    async fn fec_handshake_rejection_releases_prepared_resources() {
        let (a, mut b) = fec_peers(
            fec_context("mesh", Some("secret"), false, 1, fec_policy(100, 1400)),
            fec_context("mesh", Some("secret"), false, 2, fec_policy(100, 1400)),
            "udp",
            Arc::new(FecTestWire::default()),
            Arc::new(FecTestWire::default()),
        );
        assert!(b.fec.advertised());
        a.send_handshake(true, "mesh").await.unwrap();
        assert!(
            b.do_handshake_as_server_ext(|_, _| {
                Err(Error::WaitRespError("admission rejected".to_owned()))
            })
            .await
            .is_err()
        );
        assert!(!b.fec.info().tx_active);
        assert_eq!(b.fec.info().stats.unwrap().memory_bytes, 0);
    }
}

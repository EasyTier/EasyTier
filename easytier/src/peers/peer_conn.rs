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
use futures::{StreamExt, TryFutureExt};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::Engine as _;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;

use tokio::{
    sync::{broadcast, Mutex},
    task::JoinSet,
    time::{timeout, Duration},
};

use tracing::Instrument;
use zerocopy::AsBytes;

use snow::params::NoiseParams;

use crate::{
    common::{
        config::{NetworkIdentity, NetworkSecretDigest},
        defer,
        error::Error,
        global_ctx::ArcGlobalCtx,
        stats_manager::{CounterHandle, LabelSet, LabelType, MetricName},
        PeerId,
    },
    proto::{
        api::instance::{PeerConnInfo, PeerConnStats},
        common::TunnelInfo,
        peer_rpc::HandshakeRequest,
    },
    tunnel::{
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelFilterChain, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
        Tunnel, TunnelError, ZCPacketStream,
    },
};

use super::{peer_conn_ping::PeerConnPinger, PacketRecvChan};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SecureAuthLevel {
    None,
    EncryptedUnauthenticated,
    SharedNodePubkeyVerified,
    NetworkSecretConfirmed,
}

impl SecureAuthLevel {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::EncryptedUnauthenticated => "encrypted_unauthenticated",
            Self::SharedNodePubkeyVerified => "shared_node_pubkey_verified",
            Self::NetworkSecretConfirmed => "network_secret_confirmed",
        }
    }

    fn max(self, other: Self) -> Self {
        std::cmp::max_by_key(self, other, |v| match v {
            SecureAuthLevel::None => 0,
            SecureAuthLevel::EncryptedUnauthenticated => 1,
            SecureAuthLevel::SharedNodePubkeyVerified => 2,
            SecureAuthLevel::NetworkSecretConfirmed => 3,
        })
    }
}

struct NoiseHandshakeResult {
    transport: snow::TransportState,
    local_static_pubkey: Vec<u8>,
    remote_static_pubkey: Vec<u8>,
    handshake_hash: Vec<u8>,
    secure_auth_level: SecureAuthLevel,
    remote_network_name: Option<String>,
    peer_handshake_request: Option<HandshakeRequest>,
}

#[derive(Clone)]
struct NoiseTunnelFilter {
    enabled: bool,
    transport: Arc<std::sync::Mutex<Option<snow::TransportState>>>,
}

impl NoiseTunnelFilter {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            transport: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    fn set_transport_state(&self, transport: snow::TransportState) {
        *self.transport.lock().unwrap() = Some(transport);
    }
}

impl TunnelFilter for NoiseTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, mut data: crate::tunnel::SinkItem) -> Option<crate::tunnel::SinkItem> {
        if !self.enabled {
            return Some(data);
        }

        let Some(hdr) = data.peer_manager_header() else {
            return Some(data);
        };

        if hdr.packet_type == PacketType::NoiseHandshake as u8 {
            return Some(data);
        }

        let mut guard = self.transport.lock().unwrap();
        let Some(transport) = guard.as_mut() else {
            return Some(data);
        };

        let plaintext = data.payload().to_vec();
        let mut out = vec![0u8; plaintext.len() + 64];
        let out_len = transport.write_message(&plaintext, &mut out).ok()?;

        let payload_offset = data.payload_offset();
        data.mut_inner().truncate(payload_offset);
        data.mut_inner().extend_from_slice(&out[..out_len]);

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

        if hdr.packet_type == PacketType::NoiseHandshake as u8 {
            return Some(Ok(data));
        }

        let mut guard = self.transport.lock().unwrap();
        let Some(transport) = guard.as_mut() else {
            return Some(Ok(data));
        };

        let ciphertext = data.payload().to_vec();
        let mut out = vec![0u8; ciphertext.len() + 64];
        let out_len = match transport.read_message(&ciphertext, &mut out) {
            Ok(n) => n,
            Err(e) => {
                return Some(Err(TunnelError::InvalidPacket(format!(
                    "noise decrypt failed: {e:?}"
                ))))
            }
        };

        let payload_offset = data.payload_offset();
        data.mut_inner().truncate(payload_offset);
        data.mut_inner().extend_from_slice(&out[..out_len]);

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
    global_ctx: ArcGlobalCtx,

    secure_mode: bool,
    noise_filter: NoiseTunnelFilter,
    noise_local_static_pubkey: Option<Vec<u8>>,
    noise_remote_static_pubkey: Option<Vec<u8>>,
    noise_handshake_hash: Option<Vec<u8>>,
    secure_auth_level: SecureAuthLevel,

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
    pub fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>) -> Self {
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let secure_mode = global_ctx.get_flags().enable_peer_conn_secure_mode;
        let noise_filter = NoiseTunnelFilter::new(secure_mode);

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let filter_chain = TunnelFilterChain::new(noise_filter.clone(), peer_conn_tunnel_filter);
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, filter_chain);
        let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));

        let (recv, sink) = (mpsc_tunnel.get_stream(), mpsc_tunnel.get_sink());

        let conn_id = PeerConnId::new_v4();

        PeerConn {
            conn_id,

            my_peer_id,
            global_ctx,

            secure_mode,
            noise_filter,
            noise_local_static_pubkey: None,
            noise_remote_static_pubkey: None,
            noise_handshake_hash: None,
            secure_auth_level: if secure_mode {
                SecureAuthLevel::EncryptedUnauthenticated
            } else {
                SecureAuthLevel::None
            },

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
        }
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

        if rsp.network_secret_digrest.len() != std::mem::size_of::<NetworkSecretDigest>() {
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
            req.network_secret_digrest
                .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        } else {
            // fill zero
            req.network_secret_digrest
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

        if rsp.network_secret_digrest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        Ok(rsp)
    }

    async fn recv_next_peer_manager_packet(&self) -> Result<ZCPacket, Error> {
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
            if pkt.peer_manager_header().is_some() {
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
            .and_then(|p| p.peer_conn_pinned_remote_static_pubkey)
    }

    async fn do_noise_handshake_as_client(&self) -> Result<NoiseHandshakeResult, Error> {
        let prologue = b"easytier-peerconn-noise-v2".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;

        let pinned_remote_pubkey = self
            .get_pinned_remote_static_pubkey_b64()
            .map(|v| Self::decode_b64_32(&v))
            .transpose()?;

        let builder = snow::Builder::new(params);
        let keypair = builder
            .generate_keypair()
            .map_err(|e| Error::WaitRespError(format!("generate noise keypair failed: {e:?}")))?;
        let local_static_pubkey = keypair.public.clone();

        let network = self.global_ctx.get_network_identity();
        let mut hs_req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };
        hs_req
            .network_secret_digrest
            .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        let hs_req_bytes = hs_req.encode_to_vec();

        let mut hs = builder
            .prologue(&prologue)
            .local_private_key(&keypair.private)
            .build_initiator()
            .map_err(|e| Error::WaitRespError(format!("build noise initiator failed: {e:?}")))?;

        let mut secure_auth_level = SecureAuthLevel::EncryptedUnauthenticated;

        timeout(Duration::from_secs(5), async move {
            let mut msg = vec![0u8; 4096];
            let msg_len = hs
                .write_message(&[], &mut msg)
                .map_err(|e| Error::WaitRespError(format!("noise write msg1 failed: {e:?}")))?;
            let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
            pkt.fill_peer_manager_hdr(
                self.my_peer_id,
                PeerId::default(),
                PacketType::NoiseHandshake as u8,
            );
            self.sink.send(pkt).await?;

            let mut locked = self.recv.lock().await;
            let recv = locked.as_mut().unwrap();

            let msg2 = loop {
                let Some(ret) = recv.next().await else {
                    return Err(Error::WaitRespError(
                        "conn closed during noise handshake".to_owned(),
                    ));
                };
                let pkt = ret?;
                let Some(hdr) = pkt.peer_manager_header() else {
                    continue;
                };
                if hdr.packet_type == PacketType::NoiseHandshake as u8 {
                    break pkt;
                }
            };

            let mut out = vec![0u8; 4096];
            let out_len = hs
                .read_message(msg2.payload(), &mut out)
                .map_err(|e| Error::WaitRespError(format!("noise read msg2 failed: {e:?}")))?;

            let remote_network_name = if out_len == 0 {
                None
            } else {
                String::from_utf8(out[..out_len].to_vec()).ok()
            };

            let msg_len = hs
                .write_message(&hs_req_bytes, &mut msg)
                .map_err(|e| Error::WaitRespError(format!("noise write msg3 failed: {e:?}")))?;
            let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
            pkt.fill_peer_manager_hdr(
                self.my_peer_id,
                PeerId::default(),
                PacketType::NoiseHandshake as u8,
            );
            self.sink.send(pkt).await?;

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

            let transport = hs
                .into_transport_mode()
                .map_err(|e| Error::WaitRespError(format!("noise into transport failed: {e:?}")))?;

            Ok(NoiseHandshakeResult {
                transport,
                local_static_pubkey,
                remote_static_pubkey: remote_static,
                handshake_hash,
                secure_auth_level,
                remote_network_name,
                peer_handshake_request: None,
            })
        })
        .await
        .map_err(|e| Error::WaitRespError(format!("noise handshake timeout: {e:?}")))?
    }

    async fn do_noise_handshake_as_server(
        &self,
        first_msg1: Option<ZCPacket>,
    ) -> Result<NoiseHandshakeResult, Error> {
        let prologue = b"easytier-peerconn-noise-v2".to_vec();

        let params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256"
            .parse()
            .map_err(|e| Error::WaitRespError(format!("parse noise params failed: {e:?}")))?;
        let flags = self.global_ctx.get_flags();
        let builder = snow::Builder::new(params);

        let (local_static_private_key, local_static_pubkey) =
            if flags.peer_conn_static_private_key.is_empty() {
                let keypair = builder.generate_keypair().map_err(|e| {
                    Error::WaitRespError(format!("generate noise keypair failed: {e:?}"))
                })?;
                (keypair.private, keypair.public)
            } else {
                if flags.peer_conn_static_public_key.is_empty() {
                    return Err(Error::WaitRespError(
                        "peer_conn_static_public_key is required".to_owned(),
                    ));
                }
                let private = Self::decode_b64_32(&flags.peer_conn_static_private_key)?;
                let public = Self::decode_b64_32(&flags.peer_conn_static_public_key)?;
                (private, public)
            };

        let mut hs = builder
            .prologue(&prologue)
            .local_private_key(&local_static_private_key)
            .build_responder()
            .map_err(|e| Error::WaitRespError(format!("build noise responder failed: {e:?}")))?;

        timeout(Duration::from_secs(5), async move {
            let mut locked = self.recv.lock().await;
            let recv = locked.as_mut().unwrap();

            let msg1 = if let Some(pkt) = first_msg1 {
                pkt
            } else {
                loop {
                    let Some(ret) = recv.next().await else {
                        return Err(Error::WaitRespError(
                            "conn closed during noise handshake".to_owned(),
                        ));
                    };
                    let pkt = ret?;
                    let Some(hdr) = pkt.peer_manager_header() else {
                        continue;
                    };
                    if hdr.packet_type == PacketType::NoiseHandshake as u8 {
                        break pkt;
                    }
                }
            };

            let mut out = vec![0u8; 4096];
            hs.read_message(msg1.payload(), &mut out)
                .map_err(|e| Error::WaitRespError(format!("noise read msg1 failed: {e:?}")))?;

            let mut msg = vec![0u8; 4096];
            let server_network_name = self.global_ctx.get_network_name();
            let msg_len = hs
                .write_message(server_network_name.as_bytes(), &mut msg)
                .map_err(|e| Error::WaitRespError(format!("noise write msg2 failed: {e:?}")))?;
            let mut pkt = ZCPacket::new_with_payload(&msg[..msg_len]);
            pkt.fill_peer_manager_hdr(
                self.my_peer_id,
                PeerId::default(),
                PacketType::NoiseHandshake as u8,
            );
            self.sink.send(pkt).await?;

            let msg3 = loop {
                let Some(ret) = recv.next().await else {
                    return Err(Error::WaitRespError(
                        "conn closed during noise handshake".to_owned(),
                    ));
                };
                let pkt = ret?;
                let Some(hdr) = pkt.peer_manager_header() else {
                    continue;
                };
                if hdr.packet_type == PacketType::NoiseHandshake as u8 {
                    break pkt;
                }
            };

            let out_len = hs
                .read_message(msg3.payload(), &mut out)
                .map_err(|e| Error::WaitRespError(format!("noise read msg3 failed: {e:?}")))?;

            let peer_handshake_request = if out_len == 0 {
                None
            } else if let Ok(req) = HandshakeRequest::decode(&out[..out_len]) {
                if req.network_secret_digrest.len() != std::mem::size_of::<NetworkSecretDigest>() {
                    None
                } else {
                    Some(req)
                }
            } else {
                None
            };

            let remote_static = hs
                .get_remote_static()
                .map(|x: &[u8]| x.to_vec())
                .unwrap_or_default();

            let handshake_hash = hs.get_handshake_hash().to_vec();

            let transport = hs
                .into_transport_mode()
                .map_err(|e| Error::WaitRespError(format!("noise into transport failed: {e:?}")))?;

            Ok(NoiseHandshakeResult {
                transport,
                local_static_pubkey,
                remote_static_pubkey: remote_static,
                handshake_hash,
                secure_auth_level: SecureAuthLevel::EncryptedUnauthenticated,
                remote_network_name: None,
                peer_handshake_request,
            })
        })
        .await
        .map_err(|e| Error::WaitRespError(format!("noise handshake timeout: {e:?}")))?
    }

    async fn maybe_confirm_network_secret(&mut self) -> Result<(), Error> {
        if !self.secure_mode {
            return Ok(());
        }

        let Some(handshake_hash) = self.noise_handshake_hash.clone() else {
            return Ok(());
        };

        if self
            .global_ctx
            .get_network_identity()
            .network_secret
            .is_none()
        {
            return Ok(());
        }

        let role: u8 = if self.is_client.unwrap_or_default() {
            1
        } else {
            2
        };
        let key = self.global_ctx.get_256_key();

        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| Error::WaitRespError(format!("hmac init failed: {e:?}")))?;
        mac.update(&[role]);
        mac.update(&handshake_hash);
        let tag = mac.finalize().into_bytes();

        let mut payload = Vec::with_capacity(1 + tag.len());
        payload.push(role);
        payload.extend_from_slice(&tag);

        let mut auth_packet = ZCPacket::new_with_payload(&payload);
        auth_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::SecureAuth as u8,
        );
        let _ = self.sink.send(auth_packet).await?;

        let recv_mutex = &self.recv;
        let peer_payload = timeout(Duration::from_millis(200), async {
            let mut locked = recv_mutex.lock().await;
            let recv = locked.as_mut().unwrap();

            loop {
                let Some(ret) = recv.next().await else {
                    return Ok::<Option<Vec<u8>>, Error>(None);
                };
                let pkt = ret.map_err(Error::from)?;
                let Some(hdr) = pkt.peer_manager_header() else {
                    continue;
                };
                if hdr.packet_type == PacketType::SecureAuth as u8 {
                    return Ok::<Option<Vec<u8>>, Error>(Some(pkt.payload().to_vec()));
                }
            }
        })
        .await;

        let peer_payload: Result<Option<Vec<u8>>, Error> = match peer_payload {
            Ok(v) => v,
            Err(_) => return Ok(()),
        };
        let peer_payload = match peer_payload {
            Ok(Some(v)) => v,
            _ => return Ok(()),
        };

        if peer_payload.len() != 33 {
            return Ok(());
        }

        let peer_role = peer_payload[0];
        let peer_tag = &peer_payload[1..];

        let mut mac = Hmac::<Sha256>::new_from_slice(&key)
            .map_err(|e| Error::WaitRespError(format!("hmac init failed: {e:?}")))?;
        mac.update(&[peer_role]);
        mac.update(&handshake_hash);

        if mac.verify_slice(peer_tag).is_ok() {
            self.secure_auth_level = self
                .secure_auth_level
                .max(SecureAuthLevel::NetworkSecretConfirmed);
        }

        Ok(())
    }

    #[tracing::instrument(skip(handshake_recved))]
    pub async fn do_handshake_as_server_ext<Fn>(
        &mut self,
        mut handshake_recved: Fn,
    ) -> Result<(), Error>
    where
        Fn: FnMut(&mut Self, &HandshakeRequest) -> Result<(), Error> + Send,
    {
        let mut first_pkt: Option<ZCPacket> = None;
        if self.secure_mode {
            let pkt = self.recv_next_peer_manager_packet().await?;
            let hdr = pkt.peer_manager_header().unwrap();
            if hdr.packet_type == PacketType::HandShake as u8 {
                self.secure_mode = false;
                self.secure_auth_level = SecureAuthLevel::None;
                first_pkt = Some(pkt);
            } else if hdr.packet_type == PacketType::NoiseHandshake as u8 {
                first_pkt = Some(pkt);
            } else {
                return Err(Error::WaitRespError(format!(
                    "unexpected packet type during handshake: {}",
                    hdr.packet_type
                )));
            }
        }

        if self.secure_mode {
            let noise = self.do_noise_handshake_as_server(first_pkt).await?;
            self.noise_filter.set_transport_state(noise.transport);
            self.noise_local_static_pubkey = Some(noise.local_static_pubkey);
            self.noise_remote_static_pubkey = Some(noise.remote_static_pubkey);
            self.noise_handshake_hash = Some(noise.handshake_hash);
            self.secure_auth_level = self.secure_auth_level.max(noise.secure_auth_level);

            let rsp = if let Some(req) = noise.peer_handshake_request {
                req
            } else {
                self.wait_handshake_loop().await?
            };

            handshake_recved(self, &rsp)?;

            tracing::info!("handshake request: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest).await?;

            let _ = self.maybe_confirm_network_secret().await;

            if self.get_peer_id() == self.my_peer_id {
                Err(Error::WaitRespError("peer id conflict".to_owned()))
            } else {
                Ok(())
            }
        } else {
            let rsp = if let Some(pkt) = first_pkt.as_ref() {
                Self::decode_handshake_packet(pkt)?
            } else {
                self.wait_handshake_loop().await?
            };

            handshake_recved(self, &rsp)?;

            tracing::info!("handshake request: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest).await?;

            if self.get_peer_id() == self.my_peer_id {
                Err(Error::WaitRespError("peer id conflict".to_owned()))
            } else {
                Ok(())
            }
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        let mut first_pkt: Option<ZCPacket> = None;
        if self.secure_mode {
            let pkt = self.recv_next_peer_manager_packet().await?;
            let hdr = pkt.peer_manager_header().unwrap();
            if hdr.packet_type == PacketType::HandShake as u8 {
                self.secure_mode = false;
                self.secure_auth_level = SecureAuthLevel::None;
                first_pkt = Some(pkt);
            } else if hdr.packet_type == PacketType::NoiseHandshake as u8 {
                first_pkt = Some(pkt);
            } else {
                return Err(Error::WaitRespError(format!(
                    "unexpected packet type during handshake: {}",
                    hdr.packet_type
                )));
            }
        }

        if self.secure_mode {
            let noise = self.do_noise_handshake_as_server(first_pkt).await?;
            self.noise_filter.set_transport_state(noise.transport);
            self.noise_local_static_pubkey = Some(noise.local_static_pubkey);
            self.noise_remote_static_pubkey = Some(noise.remote_static_pubkey);
            self.noise_handshake_hash = Some(noise.handshake_hash);
            self.secure_auth_level = self.secure_auth_level.max(noise.secure_auth_level);

            let rsp = if let Some(req) = noise.peer_handshake_request {
                req
            } else {
                self.wait_handshake_loop().await?
            };
            tracing::info!("handshake request: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest).await?;

            let _ = self.maybe_confirm_network_secret().await;

            if self.get_peer_id() == self.my_peer_id {
                Err(Error::WaitRespError(
                    "peer id conflict, are you connecting to yourself?".to_owned(),
                ))
            } else {
                Ok(())
            }
        } else {
            let rsp = if let Some(pkt) = first_pkt.as_ref() {
                Self::decode_handshake_packet(pkt)?
            } else {
                self.wait_handshake_loop().await?
            };
            tracing::info!("handshake request: {:?}", rsp);
            self.info = Some(rsp);
            self.is_client = Some(false);

            let send_digest = self.get_network_identity() == self.global_ctx.get_network_identity();
            self.send_handshake(send_digest).await?;

            if self.get_peer_id() == self.my_peer_id {
                Err(Error::WaitRespError(
                    "peer id conflict, are you connecting to yourself?".to_owned(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        if self.secure_mode {
            let noise = self.do_noise_handshake_as_client().await?;
            self.noise_filter.set_transport_state(noise.transport);
            self.noise_local_static_pubkey = Some(noise.local_static_pubkey);
            self.noise_remote_static_pubkey = Some(noise.remote_static_pubkey);
            self.noise_handshake_hash = Some(noise.handshake_hash);
            self.secure_auth_level = self.secure_auth_level.max(noise.secure_auth_level);
        }

        if !self.secure_mode {
            self.send_handshake(true).await?;
        }
        tracing::info!("waiting for handshake request from server");
        let rsp = self.wait_handshake_loop().await?;
        tracing::info!("handshake response: {:?}", rsp);
        self.info = Some(rsp);
        self.is_client = Some(true);

        let _ = self.maybe_confirm_network_secret().await;

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

                    counters.traffic_rx_bytes.add(zc_packet.buf_len() as u64);
                    counters.traffic_rx_packets.inc();

                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        continue;
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
            .copy_from_slice(&info.network_secret_digrest);
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
            noise_local_static_pubkey: self.noise_local_static_pubkey.clone().unwrap_or_default(),
            noise_remote_static_pubkey: self.noise_remote_static_pubkey.clone().unwrap_or_default(),
            secure_auth_level: self.secure_auth_level.as_str().to_string(),
        }
    }

    pub fn set_peer_id(&mut self, peer_id: PeerId) {
        if self.info.is_some() {
            panic!("set_peer_id should only be called before handshake");
        }
        self.my_peer_id = peer_id;
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
    use std::sync::Arc;

    use super::*;
    use crate::common::config::PeerConfig;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::common::scoped_task::ScopedTask;
    use crate::peers::create_packet_recv_chan;
    use crate::peers::recv_packet_from_chan;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    #[tokio::test]
    async fn peer_conn_handshake_same_id() {
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = c_peer_id;

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

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

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));

        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

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
        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = true;
        c_ctx.set_flags(c_flags);
        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx.clone(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx.clone(), Box::new(s));

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
            .network_secret_digrest
            .extend_from_slice(&network.network_secret_digest.unwrap_or_default());
        let expected_payload = expected.encode_to_vec();

        let wire_hs = c_recorder
            .sent
            .lock()
            .unwrap()
            .iter()
            .find(|p| {
                p.peer_manager_header()
                    .is_some_and(|h| h.packet_type == PacketType::HandShake as u8)
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

        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = false;
        c_ctx.set_flags(c_flags);

        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None.as_str()
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::None.as_str()
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

        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = true;
        c_ctx.set_flags(c_flags);
        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated.as_str()
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::EncryptedUnauthenticated.as_str()
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
        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = true;
        c_ctx.set_flags(c_flags);
        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s));

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

        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = true;
        c_ctx.set_flags(c_flags);
        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed.as_str()
        );
        assert_eq!(
            s_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::NetworkSecretConfirmed.as_str()
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
            .set_network_identity(NetworkIdentity::new("net2".to_string(), "sec2".to_string()));
        s_ctx.config.set_network_identity(NetworkIdentity {
            network_name: "net2".to_string(),
            network_secret: None,
            network_secret_digest: None,
        });

        let noise_params: NoiseParams = "Noise_XX_25519_ChaChaPoly_SHA256".parse().unwrap();
        let builder = snow::Builder::new(noise_params);
        let keypair = builder.generate_keypair().unwrap();
        let server_priv_b64 = BASE64_STANDARD.encode(keypair.private);
        let server_pub_b64 = BASE64_STANDARD.encode(keypair.public.clone());

        let remote_url: url::Url = c.info().unwrap().remote_addr.unwrap().url.parse().unwrap();

        let mut c_flags = c_ctx.get_flags();
        c_flags.enable_peer_conn_secure_mode = true;
        c_ctx.set_flags(c_flags);
        c_ctx.config.set_peers(vec![PeerConfig {
            uri: remote_url,
            peer_conn_pinned_remote_static_pubkey: Some(server_pub_b64.clone()),
        }]);

        let mut s_flags = s_ctx.get_flags();
        s_flags.enable_peer_conn_secure_mode = true;
        s_flags.peer_conn_static_private_key = server_priv_b64;
        s_flags.peer_conn_static_public_key = server_pub_b64;
        s_ctx.set_flags(s_flags);

        let mut c_peer = PeerConn::new(c_peer_id, c_ctx, Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, s_ctx, Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );
        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(
            c_peer.get_conn_info().secure_auth_level,
            SecureAuthLevel::SharedNodePubkeyVerified.as_str()
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

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

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
        let (c, s) = create_ring_tunnel_pair();
        let mut c_peer = PeerConn::new(new_peer_id(), get_mock_global_ctx(), Box::new(c));
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

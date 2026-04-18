use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use snow::{Builder, params::NoiseParams};

use crate::{
    common::config::EncryptionAlgorithm,
    proto::common::TunnelInfo,
    secure_datagram::{SecureDatagramDirection, SecureDatagramSession},
    tunnel::{
        SplitTunnel, StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
        filter::{TunnelFilter, TunnelWithFilter},
        packet_def::{PacketType, ZCPacket, ZCPacketType},
    },
};

const NOISE_MAGIC: &[u8] = b"ET_WEB_NOISE_V1:";
const NOISE_PROLOGUE: &[u8] = b"easytier-webclient-noise-v1";
const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";
const WEB_SECURE_CIPHER_ALGORITHM: &str = "aes-gcm";
const WEB_SESSION_GENERATION: u32 = 1;
const WEB_INITIAL_EPOCH: u32 = 0;
const WEB_SECURE_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);
const WEB_SECURE_ACCEPT_TIMEOUT: Duration = WEB_SECURE_HANDSHAKE_TIMEOUT;

struct RawSplitTunnel {
    info: Option<TunnelInfo>,
    split: Mutex<Option<SplitTunnel>>,
}

impl RawSplitTunnel {
    fn new(
        info: Option<TunnelInfo>,
        stream: std::pin::Pin<Box<dyn ZCPacketStream>>,
        sink: std::pin::Pin<Box<dyn ZCPacketSink>>,
    ) -> Self {
        Self {
            info,
            split: Mutex::new(Some((stream, sink))),
        }
    }
}

impl Tunnel for RawSplitTunnel {
    fn split(&self) -> SplitTunnel {
        self.split
            .lock()
            .unwrap()
            .take()
            .expect("split can only be called once")
    }

    fn info(&self) -> Option<TunnelInfo> {
        self.info.clone()
    }
}

#[derive(Clone, Copy)]
enum SecureTunnelRole {
    Initiator,
    Responder,
}

impl SecureTunnelRole {
    fn send_dir(self) -> SecureDatagramDirection {
        match self {
            Self::Initiator => SecureDatagramDirection::AToB,
            Self::Responder => SecureDatagramDirection::BToA,
        }
    }

    fn recv_dir(self) -> SecureDatagramDirection {
        match self {
            Self::Initiator => SecureDatagramDirection::BToA,
            Self::Responder => SecureDatagramDirection::AToB,
        }
    }
}

struct SecureDatagramTunnelFilter {
    session: Arc<SecureDatagramSession>,
    role: SecureTunnelRole,
}

impl TunnelFilter for SecureDatagramTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, data: ZCPacket) -> Option<ZCPacket> {
        let mut packet = ZCPacket::new_with_payload(data.tunnel_payload());
        packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        self.session
            .encrypt_payload(self.role.send_dir(), &mut packet)
            .ok()?;
        Some(packet)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let packet = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        let mut cipher = ZCPacket::new_with_payload(packet.payload());
        cipher.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        cipher
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        if let Err(e) = self
            .session
            .decrypt_payload(self.role.recv_dir(), &mut cipher)
        {
            return Some(Err(TunnelError::InvalidPacket(format!(
                "secure datagram decrypt failed: {e}"
            ))));
        }

        Some(Ok(ZCPacket::new_from_buf(
            cipher.payload_bytes(),
            ZCPacketType::DummyTunnel,
        )))
    }

    fn filter_output(&self) {}
}

fn pack_control_packet(payload: &[u8]) -> ZCPacket {
    let mut packet = ZCPacket::new_with_payload(payload);
    packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
    packet
}

fn encode_noise_payload(buf: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(NOISE_MAGIC.len() + buf.len());
    payload.extend_from_slice(NOISE_MAGIC);
    payload.extend_from_slice(buf);
    payload
}

fn decode_noise_payload(payload: &[u8]) -> Option<&[u8]> {
    payload.strip_prefix(NOISE_MAGIC)
}

pub fn web_secure_tunnel_supported() -> bool {
    WEB_SECURE_CIPHER_ALGORITHM
        .parse::<EncryptionAlgorithm>()
        .is_ok()
}

fn web_secure_cipher_algorithm() -> Result<&'static str, TunnelError> {
    if !web_secure_tunnel_supported() {
        return Err(TunnelError::InternalError(format!(
            "web secure tunnel requires {WEB_SECURE_CIPHER_ALGORITHM} support"
        )));
    }
    Ok(WEB_SECURE_CIPHER_ALGORITHM)
}

fn new_web_secure_session(root_key: [u8; 32], algorithm: &str) -> Arc<SecureDatagramSession> {
    let algo = algorithm.to_string();
    Arc::new(SecureDatagramSession::new(
        root_key,
        WEB_SESSION_GENERATION,
        WEB_INITIAL_EPOCH,
        algo.clone(),
        algo,
    ))
}

fn wrap_secure_tunnel(
    info: Option<TunnelInfo>,
    stream: std::pin::Pin<Box<dyn ZCPacketStream>>,
    sink: std::pin::Pin<Box<dyn ZCPacketSink>>,
    session: Arc<SecureDatagramSession>,
    role: SecureTunnelRole,
) -> Box<dyn Tunnel> {
    let raw = RawSplitTunnel::new(info, stream, sink);
    Box::new(TunnelWithFilter::new(
        raw,
        SecureDatagramTunnelFilter { session, role },
    ))
}

pub async fn upgrade_client_tunnel(
    tunnel: Box<dyn Tunnel>,
) -> Result<Box<dyn Tunnel>, TunnelError> {
    let web_cipher_algorithm = web_secure_cipher_algorithm()?;
    let info = tunnel.info();
    let (mut stream, mut sink) = tunnel.split();

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| TunnelError::InternalError(format!("parse noise params failed: {e}")))?;
    let mut state = Builder::new(params)
        .prologue(NOISE_PROLOGUE)
        .map_err(|e| TunnelError::InternalError(format!("set prologue failed: {e}")))?
        .build_initiator()
        .map_err(|e| TunnelError::InternalError(format!("build initiator failed: {e}")))?;

    let mut msg1 = vec![0u8; 1024];
    let msg1_len = state
        .write_message(&[], &mut msg1)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg1 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_noise_payload(
        &msg1[..msg1_len],
    )))
    .await?;

    let msg2_packet = match tokio::time::timeout(WEB_SECURE_HANDSHAKE_TIMEOUT, stream.next()).await
    {
        Ok(Some(Ok(packet))) => packet,
        Ok(Some(Err(error))) => return Err(error),
        Ok(None) => return Err(TunnelError::Shutdown),
        Err(error) => return Err(error.into()),
    };
    let msg2_cipher = decode_noise_payload(msg2_packet.payload())
        .ok_or_else(|| TunnelError::InvalidPacket("invalid noise msg2 magic".to_string()))?;
    let mut root_key_buf = [0u8; 32];
    let root_key_len = state
        .read_message(msg2_cipher, &mut root_key_buf)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg2 failed: {e}")))?;
    if root_key_len != root_key_buf.len() {
        return Err(TunnelError::InvalidPacket(format!(
            "invalid web secure root key len: {root_key_len}"
        )));
    }

    Ok(wrap_secure_tunnel(
        info,
        stream,
        sink,
        new_web_secure_session(root_key_buf, web_cipher_algorithm),
        SecureTunnelRole::Initiator,
    ))
}

pub async fn accept_or_upgrade_server_tunnel(
    tunnel: Box<dyn Tunnel>,
) -> Result<(Box<dyn Tunnel>, bool), TunnelError> {
    let info = tunnel.info();
    let (stream, sink) = tunnel.split();
    let mut stream = stream;
    let mut sink = sink;

    let first_packet = match tokio::time::timeout(WEB_SECURE_ACCEPT_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(packet))) => packet,
        Ok(Some(Err(error))) => return Err(error),
        Ok(None) => return Err(TunnelError::Shutdown),
        Err(_) => {
            return Ok((
                Box::new(RawSplitTunnel::new(info, stream, sink)) as Box<dyn Tunnel>,
                false,
            ));
        }
    };
    let Some(msg1_cipher) = decode_noise_payload(first_packet.payload()) else {
        let stream = Box::pin(futures::stream::once(async move { Ok(first_packet) }).chain(stream));
        return Ok((
            Box::new(RawSplitTunnel::new(info, stream, sink)) as Box<dyn Tunnel>,
            false,
        ));
    };
    let web_cipher_algorithm = web_secure_cipher_algorithm()?;

    let params: NoiseParams = NOISE_PATTERN
        .parse()
        .map_err(|e| TunnelError::InternalError(format!("parse noise params failed: {e}")))?;
    let mut state = Builder::new(params)
        .prologue(NOISE_PROLOGUE)
        .map_err(|e| TunnelError::InternalError(format!("set prologue failed: {e}")))?
        .build_responder()
        .map_err(|e| TunnelError::InternalError(format!("build responder failed: {e}")))?;

    let mut msg1 = vec![0u8; 1024];
    state
        .read_message(msg1_cipher, &mut msg1)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg1 failed: {e}")))?;

    let root_key = SecureDatagramSession::new_root_key();
    let mut msg2 = vec![0u8; 1024];
    let msg2_len = state
        .write_message(&root_key, &mut msg2)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg2 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_noise_payload(
        &msg2[..msg2_len],
    )))
    .await?;

    Ok((
        wrap_secure_tunnel(
            info,
            stream,
            sink,
            new_web_secure_session(root_key, web_cipher_algorithm),
            SecureTunnelRole::Responder,
        ),
        true,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    #[test]
    fn web_secure_cipher_algorithm_matches_support_flag() {
        let result = web_secure_cipher_algorithm();
        if web_secure_tunnel_supported() {
            assert_eq!(result.unwrap(), WEB_SECURE_CIPHER_ALGORITHM);
        } else {
            assert!(matches!(result, Err(TunnelError::InternalError(_))));
        }
    }

    #[test]
    fn web_secure_session_uses_pinned_cipher_algorithm() {
        if !web_secure_tunnel_supported() {
            return;
        }

        let session = new_web_secure_session(
            SecureDatagramSession::new_root_key(),
            web_secure_cipher_algorithm().unwrap(),
        );
        session
            .check_encrypt_algo_same(WEB_SECURE_CIPHER_ALGORITHM, WEB_SECURE_CIPHER_ALGORITHM)
            .unwrap();
    }

    #[tokio::test]
    async fn upgrade_client_tunnel_times_out_when_server_never_replies() {
        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();
        let _server_tunnel = server_tunnel;

        let err = upgrade_client_tunnel(client_tunnel).await.unwrap_err();
        assert!(matches!(err, TunnelError::Timeout(_)));
    }

    #[tokio::test]
    async fn accept_secure_tunnel_after_short_client_delay() {
        let (server_tunnel, client_tunnel) = create_ring_tunnel_pair();

        let server_task =
            tokio::spawn(async move { accept_or_upgrade_server_tunnel(server_tunnel).await });

        tokio::time::sleep(Duration::from_millis(1500)).await;

        let client_task = tokio::spawn(async move { upgrade_client_tunnel(client_tunnel).await });

        let (server_res, client_res) = tokio::join!(server_task, client_task);
        let (_, secure) = server_res.unwrap().unwrap();
        assert!(secure);
        assert!(client_res.unwrap().is_ok());
    }
}

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use snow::{Builder, TransportState, params::NoiseParams};

use crate::{
    proto::common::TunnelInfo,
    tunnel::{
        SplitTunnel, StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
        filter::{TunnelFilter, TunnelWithFilter},
        packet_def::{PacketType, ZCPacket, ZCPacketType},
    },
};

const NOISE_MAGIC: &[u8] = b"ET_WEB_NOISE_V1:";
const NOISE_PROLOGUE: &[u8] = b"easytier-webclient-noise-v1";
const NOISE_PATTERN: &str = "Noise_NN_25519_ChaChaPoly_SHA256";

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

struct NoiseTunnelFilter {
    transport: Arc<Mutex<TransportState>>,
}

impl TunnelFilter for NoiseTunnelFilter {
    type FilterOutput = ();

    fn before_send(&self, data: ZCPacket) -> Option<ZCPacket> {
        let plain = data.tunnel_payload();
        let mut encrypted = vec![0u8; plain.len() + 64];
        let len = self
            .transport
            .lock()
            .unwrap()
            .write_message(plain, &mut encrypted)
            .ok()?;
        let mut packet = ZCPacket::new_with_payload(&encrypted[..len]);
        packet.fill_peer_manager_hdr(0, 0, PacketType::Data as u8);
        Some(packet)
    }

    fn after_received(&self, data: StreamItem) -> Option<StreamItem> {
        let packet = match data {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let cipher = packet.payload();
        let mut plain = vec![0u8; cipher.len() + 64];
        let len = match self
            .transport
            .lock()
            .unwrap()
            .read_message(cipher, &mut plain)
        {
            Ok(v) => v,
            Err(e) => {
                return Some(Err(TunnelError::InvalidPacket(format!(
                    "noise decrypt failed: {e}"
                ))));
            }
        };
        Some(Ok(ZCPacket::new_from_buf(
            BytesMut::from(&plain[..len]),
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

fn wrap_secure_tunnel(
    info: Option<TunnelInfo>,
    stream: std::pin::Pin<Box<dyn ZCPacketStream>>,
    sink: std::pin::Pin<Box<dyn ZCPacketSink>>,
    transport: TransportState,
) -> Box<dyn Tunnel> {
    let raw = RawSplitTunnel::new(info, stream, sink);
    Box::new(TunnelWithFilter::new(
        raw,
        NoiseTunnelFilter {
            transport: Arc::new(Mutex::new(transport)),
        },
    ))
}

pub async fn upgrade_client_tunnel(
    tunnel: Box<dyn Tunnel>,
) -> Result<Box<dyn Tunnel>, TunnelError> {
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

    let msg2_packet = stream.next().await.ok_or(TunnelError::Shutdown)??;
    let msg2_cipher = decode_noise_payload(msg2_packet.payload())
        .ok_or_else(|| TunnelError::InvalidPacket("invalid noise msg2 magic".to_string()))?;
    let mut msg2 = vec![0u8; 1024];
    state
        .read_message(msg2_cipher, &mut msg2)
        .map_err(|e| TunnelError::InvalidPacket(format!("read noise msg2 failed: {e}")))?;

    let transport = state
        .into_transport_mode()
        .map_err(|e| TunnelError::InternalError(format!("switch transport mode failed: {e}")))?;

    Ok(wrap_secure_tunnel(info, stream, sink, transport))
}

pub async fn accept_or_upgrade_server_tunnel(
    tunnel: Box<dyn Tunnel>,
) -> Result<(Box<dyn Tunnel>, bool), TunnelError> {
    let info = tunnel.info();
    let (stream, sink) = tunnel.split();
    let mut stream = stream;
    let mut sink = sink;

    let first_packet = match tokio::time::timeout(Duration::from_secs(1), stream.next()).await {
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

    let mut msg2 = vec![0u8; 1024];
    let msg2_len = state
        .write_message(&[], &mut msg2)
        .map_err(|e| TunnelError::InternalError(format!("write noise msg2 failed: {e}")))?;
    sink.send(pack_control_packet(&encode_noise_payload(
        &msg2[..msg2_len],
    )))
    .await?;

    let transport = state
        .into_transport_mode()
        .map_err(|e| TunnelError::InternalError(format!("switch transport mode failed: {e}")))?;

    Ok((wrap_secure_tunnel(info, stream, sink, transport), true))
}

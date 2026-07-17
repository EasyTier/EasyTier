use prost::{Message as _, length_delimiter_len};

use crate::{
    config::PeerId,
    packet::{CompressorAlgo, PacketType, TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
    proto::{
        common::{CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket},
        rpc_types::error::Error,
    },
};

use super::RpcTransactId;

const RPC_PACKET_UDP_PAYLOAD_BUDGET: usize = 1300;

pub async fn compress_packet(
    accepted_compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<(Vec<u8>, CompressionAlgoPb), Error> {
    let algo = CompressorAlgo::try_from(accepted_compression_algo).unwrap_or(CompressorAlgo::None);
    let compressed = crate::foundation::compressor::DefaultCompressor::new()
        .compress_raw(content, algo)
        .await
        .map_err(Error::from)?;
    if compressed.len() >= content.len() {
        Ok((content.to_vec(), CompressionAlgoPb::None))
    } else {
        Ok((
            compressed,
            CompressionAlgoPb::try_from(algo).expect("CompressorAlgo should map to protobuf"),
        ))
    }
}

pub async fn decompress_packet(
    compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let algo = CompressorAlgo::try_from(compression_algo).map_err(anyhow::Error::from)?;
    crate::foundation::compressor::DefaultCompressor::new()
        .decompress_raw(content, algo)
        .await
        .map_err(Error::from)
}

pub(crate) struct PacketMerger {
    first_piece: Option<RpcPacket>,
    pieces: Vec<RpcPacket>,
    last_updated: std::time::Instant,
}

impl Default for PacketMerger {
    fn default() -> Self {
        Self::new()
    }
}

impl PacketMerger {
    pub fn new() -> Self {
        Self {
            first_piece: None,
            pieces: Vec::new(),
            last_updated: std::time::Instant::now(),
        }
    }

    fn try_merge_pieces(&self) -> Option<RpcPacket> {
        if self.first_piece.is_none() || self.pieces.is_empty() {
            return None;
        }

        for p in &self.pieces {
            if p.total_pieces == 0 {
                return None;
            }
        }

        let mut body = Vec::new();
        for p in &self.pieces {
            body.extend_from_slice(&p.body);
        }

        let mut tmpl_packet = self.pieces[0].clone();
        tmpl_packet.total_pieces = 1;
        tmpl_packet.piece_idx = 0;
        tmpl_packet.body = body;

        Some(tmpl_packet)
    }

    pub fn feed(&mut self, rpc_packet: RpcPacket) -> Result<Option<RpcPacket>, Error> {
        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;

        if total_pieces == 0 && piece_idx == 0 {
            return Ok(Some(rpc_packet));
        }

        if rpc_packet.piece_idx == 0 && rpc_packet.descriptor.is_none() {
            return Err(Error::MalformatRpcPacket(
                "descriptor is missing".to_owned(),
            ));
        }

        if total_pieces > 32 * 1024 || total_pieces == 0 {
            return Err(Error::MalformatRpcPacket(format!(
                "total_pieces is invalid: {}",
                total_pieces
            )));
        }

        if piece_idx >= total_pieces {
            return Err(Error::MalformatRpcPacket(
                "piece_idx >= total_pieces".to_owned(),
            ));
        }

        if self.first_piece.is_none()
            || self.first_piece.as_ref().unwrap().transaction_id != rpc_packet.transaction_id
            || self.first_piece.as_ref().unwrap().from_peer != rpc_packet.from_peer
        {
            self.first_piece = Some(rpc_packet.clone());
            self.pieces.clear();
            tracing::trace!(?rpc_packet, "got first piece");
        }

        self.pieces
            .resize(total_pieces as usize, Default::default());
        self.pieces[piece_idx as usize] = rpc_packet;

        self.last_updated = std::time::Instant::now();

        Ok(self.try_merge_pieces())
    }

    pub(crate) fn last_updated(&self) -> std::time::Instant {
        self.last_updated
    }
}

pub struct BuildRpcPacketArgs<'a> {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    pub rpc_desc: RpcDescriptor,
    pub transaction_id: RpcTransactId,
    pub is_req: bool,
    pub content: &'a [u8],
    pub trace_id: i32,
    pub compression_info: RpcCompressionInfo,
}

fn udp_rpc_tunnel_overhead() -> usize {
    ZCPacketType::UDP.get_packet_offsets().payload_offset + TAIL_RESERVED_SIZE
}

fn max_rpc_packet_encoded_len_for_udp() -> usize {
    RPC_PACKET_UDP_PAYLOAD_BUDGET.saturating_sub(udp_rpc_tunnel_overhead())
}

fn build_rpc_piece(
    args: &BuildRpcPacketArgs<'_>,
    total_pieces: u32,
    piece_idx: u32,
    body: &[u8],
) -> RpcPacket {
    RpcPacket {
        from_peer: args.from_peer,
        to_peer: args.to_peer,
        descriptor: if piece_idx == 0
            || args.compression_info.algo == CompressionAlgoPb::None as i32
        {
            Some(args.rpc_desc.clone())
        } else {
            None
        },
        is_request: args.is_req,
        total_pieces,
        piece_idx,
        transaction_id: args.transaction_id,
        body: body.to_vec(),
        trace_id: args.trace_id,
        compression_info: if piece_idx == 0 {
            Some(args.compression_info)
        } else {
            None
        },
    }
}

fn pick_piece_len_for_budget(
    base_encoded_len_without_body: usize,
    remaining: usize,
    max_encoded_len: usize,
) -> usize {
    if remaining == 0 {
        return 0;
    }

    if base_encoded_len_without_body + 3 > max_encoded_len {
        tracing::warn!(
            base_encoded_len_without_body,
            max_encoded_len,
            "rpc metadata exceeds udp payload budget; falling back to a minimal piece"
        );
        return 1;
    }

    let budget = max_encoded_len - base_encoded_len_without_body;
    let reserved_for_body_header = 1 + length_delimiter_len(budget);
    remaining
        .min(budget.saturating_sub(reserved_for_body_header))
        .max(1)
}

fn split_rpc_content_for_udp_budget(args: &BuildRpcPacketArgs<'_>) -> Vec<(usize, usize)> {
    if args.content.is_empty() {
        return vec![(0, 0)];
    }

    let max_encoded_len = max_rpc_packet_encoded_len_for_udp().max(1);
    let first_piece_base_len = build_rpc_piece(args, u32::MAX, 0, &[]).encoded_len();
    let other_piece_base_len = build_rpc_piece(args, u32::MAX, u32::MAX, &[]).encoded_len();

    let mut pieces = Vec::new();
    let mut offset = 0usize;
    while offset < args.content.len() {
        let base_len = if pieces.is_empty() {
            first_piece_base_len
        } else {
            other_piece_base_len
        };
        let piece_len =
            pick_piece_len_for_budget(base_len, args.content.len() - offset, max_encoded_len);
        pieces.push((offset, piece_len));
        offset += piece_len;
    }

    pieces
}

pub fn build_rpc_packet(args: BuildRpcPacketArgs<'_>) -> Vec<ZCPacket> {
    let mut ret = Vec::new();
    let pieces = split_rpc_content_for_udp_budget(&args);
    let total_pieces = pieces.len() as u32;
    for (piece_idx, (offset, len)) in pieces.into_iter().enumerate() {
        let cur_packet = build_rpc_piece(
            &args,
            total_pieces,
            piece_idx as u32,
            &args.content[offset..offset + len],
        );

        let packet_type = if args.is_req {
            PacketType::RpcReq
        } else {
            PacketType::RpcResp
        };

        let mut buf = Vec::new();
        cur_packet.encode(&mut buf).unwrap();
        let mut zc_packet = ZCPacket::new_with_payload(&buf);
        zc_packet.fill_peer_manager_hdr(args.from_peer, args.to_peer, packet_type as u8);
        ret.push(zc_packet);
    }

    ret
}

use prost::{length_delimiter_len, Message as _};

use crate::{
    common::{compressor::DefaultCompressor, PeerId},
    proto::{
        common::{CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket},
        rpc_types::error::Error,
    },
    tunnel::packet_def::{CompressorAlgo, PacketType, ZCPacket, ZCPacketType, TAIL_RESERVED_SIZE},
};

use super::RpcTransactId;

// Budget the final UDP payload size on the wire for peer RPC over `udp://`.
// This includes EasyTier's UDP tunnel header, peer header, and reserved tail
// space for encryption/compression metadata, but excludes the outer IP header.
const RPC_PACKET_UDP_PAYLOAD_BUDGET: usize = 1300;

pub async fn compress_packet(
    accepted_compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<(Vec<u8>, CompressionAlgoPb), Error> {
    let compressor = DefaultCompressor::new();
    let algo = accepted_compression_algo
        .try_into()
        .unwrap_or(CompressorAlgo::None);
    let compressed = compressor.compress_raw(content, algo).await?;
    if compressed.len() >= content.len() {
        Ok((content.to_vec(), CompressionAlgoPb::None))
    } else {
        Ok((compressed, algo.try_into().unwrap()))
    }
}

pub async fn decompress_packet(
    compression_algo: CompressionAlgoPb,
    content: &[u8],
) -> Result<Vec<u8>, Error> {
    let compressor = DefaultCompressor::new();
    let algo = compression_algo.try_into()?;
    let decompressed = compressor.decompress_raw(content, algo).await?;
    Ok(decompressed)
}

pub struct PacketMerger {
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
            // some piece is missing
            if p.total_pieces == 0 {
                return None;
            }
        }

        // all pieces are received
        let mut body = Vec::new();
        for p in &self.pieces {
            body.extend_from_slice(&p.body);
        }

        // only the first packet contains the complete info
        let mut tmpl_packet = self.pieces[0].clone();
        tmpl_packet.total_pieces = 1;
        tmpl_packet.piece_idx = 0;
        tmpl_packet.body = body;

        Some(tmpl_packet)
    }

    pub fn feed(&mut self, rpc_packet: RpcPacket) -> Result<Option<RpcPacket>, Error> {
        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;

        // for compatibility with old version
        if total_pieces == 0 && piece_idx == 0 {
            return Ok(Some(rpc_packet));
        }

        if rpc_packet.piece_idx == 0 && rpc_packet.descriptor.is_none() {
            return Err(Error::MalformatRpcPacket(
                "descriptor is missing".to_owned(),
            ));
        }

        // about 32MB max size
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

    pub fn last_updated(&self) -> std::time::Instant {
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

// Fixed transport overhead for peer RPC carried by EasyTier's UDP tunnel:
//
//   UDP payload budget
//   +-------------------------------------------------------------------------+
//   | EasyTier UDP tunnel hdr | PeerManager hdr | RpcPacket bytes | tail room |
//   +-------------------------------------------------------------------------+
//   |<------ ZCPacketType::UDP payload_offset ------>|<-- TAIL_RESERVED_SIZE -->|
//
// `udp_rpc_tunnel_overhead()` is everything except `RpcPacket bytes`.
fn udp_rpc_tunnel_overhead() -> usize {
    ZCPacketType::UDP.get_packet_offsets().payload_offset + TAIL_RESERVED_SIZE
}

// Maximum encoded RpcPacket size we can admit before adding it to a UDP tunnel.
// This budget excludes the outer UDP/IP headers because the caller only controls
// the EasyTier payload carried inside the UDP datagram.
fn max_rpc_packet_encoded_len_for_udp() -> usize {
    RPC_PACKET_UDP_PAYLOAD_BUDGET.saturating_sub(udp_rpc_tunnel_overhead())
}

// Build one logical RpcPacket piece. This is reused both for the actual output
// packets and for sizing templates that estimate worst-case protobuf overhead.
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
            // old version must have descriptor on every piece
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
            Some(args.compression_info.clone())
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

    // Minimum non-empty body field encoding cost:
    //   body tag (1 byte) + body length (1 byte) + body data (1 byte)
    if base_encoded_len_without_body + 3 > max_encoded_len {
        tracing::warn!(
            base_encoded_len_without_body,
            max_encoded_len,
            "rpc metadata exceeds udp payload budget; falling back to a minimal piece"
        );
        return 1;
    }

    // `budget` is what remains for the protobuf `body` field after all fixed
    // RpcPacket metadata has been accounted for.
    let budget = max_encoded_len - base_encoded_len_without_body;
    // Reserve the bytes field wrapper conservatively, then use the rest for
    // the body itself.
    //
    // Encoded RpcPacket layout relevant to `body`:
    //
    //   +------------------------------- max_encoded_len -------------------------------+
    //   | fixed RpcPacket fields | body tag (1B) | body len varint (worst-case) | body |
    //   +--------------------------------------------------------------------------- --+
    //   ^                         ^
    //   |                         `- reserve by using the varint width of `budget`
    //   `- base_encoded_len_without_body
    //
    // This is intentionally conservative. A few bytes may be left unused, but
    // every piece stays within the UDP payload budget without iterative sizing.
    let reserved_for_body_header = 1 + length_delimiter_len(budget);
    remaining
        .min(budget.saturating_sub(reserved_for_body_header))
        .max(1)
}

// Pre-split the raw RPC content using conservative worst-case protobuf sizing.
// We compute separate base sizes for the first piece and later pieces because
// only the first piece carries `compression_info`, and old compatibility rules
// may also force `descriptor` to appear on every piece.
//
// Split flow:
//
//   raw RPC content
//   +--------------------------------------------------------------+
//   |                         args.content                          |
//   +--------------------------------------------------------------+
//        | first piece uses first_piece_base_len
//        | later pieces use other_piece_base_len
//        v
//   +-----------+-----------+-----------+----- ...
//   | offset,len| offset,len| offset,len|
//   +-----------+-----------+-----------+----- ...
//
// The result is only a slicing plan. Actual RpcPacket objects are built later
// with the real `total_pieces`.
fn split_rpc_content_for_udp_budget(args: &BuildRpcPacketArgs<'_>) -> Vec<(usize, usize)> {
    if args.content.is_empty() {
        return vec![(0, 0)];
    }

    let max_encoded_len = max_rpc_packet_encoded_len_for_udp().max(1);
    // Use the worst-case varint width for piece counters so the budget remains
    // valid without iterating on `total_pieces`/`piece_idx`.
    let first_piece_base_len = build_rpc_piece(args, u32::MAX, 0, &[]).encoded_len();
    let other_piece_base_len = build_rpc_piece(args, u32::MAX, u32::MAX, &[]).encoded_len();

    let mut pieces = Vec::new();
    let mut offset = 0usize;
    while offset < args.content.len() {
        // First and subsequent pieces have different metadata shapes, so they
        // use different fixed-size templates.
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

// Build the final transport packets after the payload has been split. We do the
// actual `total_pieces` assignment only here so the wire packet stays accurate,
// while the earlier sizing step remains simple and conservatively safe.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_args<'a>(
        content: &'a [u8],
        compression_algo: CompressionAlgoPb,
    ) -> BuildRpcPacketArgs<'a> {
        BuildRpcPacketArgs {
            from_peer: 11,
            to_peer: 22,
            rpc_desc: RpcDescriptor {
                domain_name: "very-long-domain-name-for-rpc-packet-budget-check".repeat(2),
                proto_name: "extremely.verbose.proto.name.for.rpc.packet.tests".repeat(2),
                service_name: "LargeMetadataServiceForRpcPacketBudget".repeat(2),
                method_index: 7,
            },
            transaction_id: 33,
            is_req: true,
            content,
            trace_id: 44,
            compression_info: RpcCompressionInfo {
                algo: compression_algo.into(),
                accepted_algo: CompressionAlgoPb::Zstd.into(),
            },
        }
    }

    fn udp_packet_size_after_tail(packet: &ZCPacket) -> usize {
        ZCPacketType::UDP.get_packet_offsets().payload_offset
            + packet.payload_len()
            + TAIL_RESERVED_SIZE
    }

    #[test]
    fn build_rpc_packet_respects_udp_budget_with_large_metadata() {
        let content = vec![0x5a; 4096];
        let packets = build_rpc_packet(build_test_args(&content, CompressionAlgoPb::None));

        assert!(packets.len() > 1);
        for packet in packets {
            assert!(
                udp_packet_size_after_tail(&packet) <= RPC_PACKET_UDP_PAYLOAD_BUDGET,
                "packet size {} exceeded budget {}",
                udp_packet_size_after_tail(&packet),
                RPC_PACKET_UDP_PAYLOAD_BUDGET
            );
        }
    }

    #[test]
    fn build_rpc_packet_respects_udp_budget_for_empty_payload() {
        let packets = build_rpc_packet(build_test_args(&[], CompressionAlgoPb::Zstd));

        assert_eq!(1, packets.len());
        assert!(udp_packet_size_after_tail(&packets[0]) <= RPC_PACKET_UDP_PAYLOAD_BUDGET);
    }
}

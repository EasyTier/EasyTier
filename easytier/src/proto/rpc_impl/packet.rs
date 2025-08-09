use prost::Message as _;

use crate::{
    common::{compressor::DefaultCompressor, PeerId},
    proto::{
        common::{CompressionAlgoPb, RpcCompressionInfo, RpcDescriptor, RpcPacket},
        rpc_types::error::Error,
    },
    tunnel::packet_def::{CompressorAlgo, PacketType, ZCPacket},
};

use super::RpcTransactId;

const RPC_PACKET_CONTENT_MTU: usize = 1300;

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

pub fn build_rpc_packet(args: BuildRpcPacketArgs<'_>) -> Vec<ZCPacket> {
    let mut ret = Vec::new();
    let content_mtu = RPC_PACKET_CONTENT_MTU;
    let total_pieces = args.content.len().div_ceil(content_mtu);
    let mut cur_offset = 0;
    while cur_offset < args.content.len() || args.content.is_empty() {
        let mut cur_len = content_mtu;
        if cur_offset + cur_len > args.content.len() {
            cur_len = args.content.len() - cur_offset;
        }

        let mut cur_content = Vec::new();
        cur_content.extend_from_slice(&args.content[cur_offset..cur_offset + cur_len]);

        let cur_packet = RpcPacket {
            from_peer: args.from_peer,
            to_peer: args.to_peer,
            descriptor: if cur_offset == 0
                || args.compression_info.algo == CompressionAlgoPb::None as i32
            {
                // old version must have descriptor on every piece
                Some(args.rpc_desc.clone())
            } else {
                None
            },
            is_request: args.is_req,
            total_pieces: total_pieces as u32,
            piece_idx: (cur_offset / RPC_PACKET_CONTENT_MTU) as u32,
            transaction_id: args.transaction_id,
            body: cur_content,
            trace_id: args.trace_id,
            compression_info: if cur_offset == 0 {
                Some(args.compression_info)
            } else {
                None
            },
        };
        cur_offset += cur_len;

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

        if args.content.is_empty() {
            break;
        }
    }

    ret
}

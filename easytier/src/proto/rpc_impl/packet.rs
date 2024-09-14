use prost::Message as _;

use crate::{
    common::PeerId,
    proto::{
        common::{RpcDescriptor, RpcPacket},
        rpc_types::error::Error,
    },
    tunnel::packet_def::{PacketType, ZCPacket},
};

use super::RpcTransactId;

const RPC_PACKET_CONTENT_MTU: usize = 1300;

pub struct PacketMerger {
    first_piece: Option<RpcPacket>,
    pieces: Vec<RpcPacket>,
    last_updated: std::time::Instant,
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

        let mut tmpl_packet = self.first_piece.as_ref().unwrap().clone();
        tmpl_packet.total_pieces = 1;
        tmpl_packet.piece_idx = 0;
        tmpl_packet.body = body;

        Some(tmpl_packet)
    }

    pub fn feed(&mut self, rpc_packet: RpcPacket) -> Result<Option<RpcPacket>, Error> {
        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;

        if rpc_packet.descriptor.is_none() {
            return Err(Error::MalformatRpcPacket(
                "descriptor is missing".to_owned(),
            ));
        }

        // for compatibility with old version
        if total_pieces == 0 && piece_idx == 0 {
            return Ok(Some(rpc_packet));
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

pub fn build_rpc_packet(
    from_peer: PeerId,
    to_peer: PeerId,
    rpc_desc: RpcDescriptor,
    transaction_id: RpcTransactId,
    is_req: bool,
    content: &Vec<u8>,
    trace_id: i32,
) -> Vec<ZCPacket> {
    let mut ret = Vec::new();
    let content_mtu = RPC_PACKET_CONTENT_MTU;
    let total_pieces = (content.len() + content_mtu - 1) / content_mtu;
    let mut cur_offset = 0;
    while cur_offset < content.len() || content.len() == 0 {
        let mut cur_len = content_mtu;
        if cur_offset + cur_len > content.len() {
            cur_len = content.len() - cur_offset;
        }

        let mut cur_content = Vec::new();
        cur_content.extend_from_slice(&content[cur_offset..cur_offset + cur_len]);

        let cur_packet = RpcPacket {
            from_peer,
            to_peer,
            descriptor: Some(rpc_desc.clone()),
            is_request: is_req,
            total_pieces: total_pieces as u32,
            piece_idx: (cur_offset / content_mtu) as u32,
            transaction_id,
            body: cur_content,
            trace_id,
        };
        cur_offset += cur_len;

        let packet_type = if is_req {
            PacketType::RpcReq
        } else {
            PacketType::RpcResp
        };

        let mut buf = Vec::new();
        cur_packet.encode(&mut buf).unwrap();
        let mut zc_packet = ZCPacket::new_with_payload(&buf);
        zc_packet.fill_peer_manager_hdr(from_peer, to_peer, packet_type as u8);
        ret.push(zc_packet);

        if content.len() == 0 {
            break;
        }
    }

    ret
}

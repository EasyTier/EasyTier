use bytes::BytesMut;

use crate::packet::{
    FEC_KIND_MASK as KIND_MASK, FEC_REPAIR_KIND as REPAIR, FEC_SOURCE_KIND as SOURCE,
    PEER_MANAGER_HEADER_SIZE, PacketType, UDP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType,
};

use super::codec::WINDOW;

const KIND_OFFSET: usize = 8;
pub(super) const SOURCE_HEADER_SIZE: usize = 9;
pub(super) const REPAIR_HEADER_SIZE: usize = 14;
// Keep native TUN reservation tied to the largest expansion of a peer packet.
const _: () = assert!(REPAIR_HEADER_SIZE + 2 == crate::packet::FEC_MAX_OVERHEAD);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FrameKind {
    Plain,
    Source,
    Repair,
    Invalid,
}

/// Both plain peer packets and independent FEC frames put their discriminator
/// at byte 8 of the tunnel payload. For plain packets this is packet_type:
/// values 0..63 are reserved for that namespace. FEC uses the high two bits,
/// without adding a second peer header or changing the UDP transport header.
///
/// This offset is intentional. The first eight bytes of a plain packet are
/// arbitrary peer IDs, so a type in an eight-byte prefix would be ambiguous.
/// A nine-byte source prefix puts its type in the shared discriminator slot.
/// Classification must not switch with negotiation state: a FEC frame can
/// overtake the final handshake, and a plain packet can arrive after activation.
pub(super) fn classify(packet: &ZCPacket) -> FrameKind {
    let Some(&kind) = packet.tunnel_payload().get(KIND_OFFSET) else {
        return FrameKind::Invalid;
    };
    match kind & KIND_MASK {
        0 => FrameKind::Plain,
        SOURCE if kind == SOURCE => FrameKind::Source,
        REPAIR => FrameKind::Repair,
        _ => FrameKind::Invalid,
    }
}

pub(super) fn eligible_peer(peer: &[u8]) -> bool {
    // The original peer length describes the uncompressed payload, and is not
    // necessarily its wire length after compression or encryption.
    // This is the receive format's capability, not the local send policy.
    // KCP and QUIC participation is selected separately during negotiation.
    (PEER_MANAGER_HEADER_SIZE..=u16::MAX as usize).contains(&peer.len())
        && [
            PacketType::Data as u8,
            PacketType::KcpSrc as u8,
            PacketType::KcpDst as u8,
            PacketType::QuicSrc as u8,
            PacketType::QuicDst as u8,
        ]
        .contains(&peer[KIND_OFFSET])
}

fn wrap(data: &[u8]) -> ZCPacket {
    let mut bytes = BytesMut::with_capacity(UDP_TUNNEL_HEADER_SIZE + data.len());
    bytes.resize(UDP_TUNNEL_HEADER_SIZE, 0);
    bytes.extend_from_slice(data);
    ZCPacket::new_from_buf(bytes, ZCPacketType::UDP)
}

pub(super) fn wrap_source(id: u64, source: &ZCPacket) -> ZCPacket {
    let peer = source.tunnel_payload();
    let mut data = Vec::with_capacity(SOURCE_HEADER_SIZE + peer.len());
    data.extend_from_slice(&id.to_le_bytes());
    data.push(SOURCE);
    data.extend_from_slice(peer);
    wrap(&data)
}

pub(super) fn wrap_repair(first: u64, count: usize, repair: u32, symbol: &[u8]) -> ZCPacket {
    let mut data = Vec::with_capacity(REPAIR_HEADER_SIZE + symbol.len());
    data.extend_from_slice(&first.to_le_bytes());
    data.push(REPAIR | count as u8);
    data.push(0);
    data.extend_from_slice(&repair.to_le_bytes());
    data.extend_from_slice(symbol);
    wrap(&data)
}

pub(super) fn parse_source(packet: &ZCPacket, max_symbol_len: usize) -> Option<(u64, &[u8])> {
    if classify(packet) != FrameKind::Source {
        return None;
    }
    let data = packet.tunnel_payload();
    let id = u64::from_le_bytes(data.get(..8)?.try_into().ok()?);
    let peer = data.get(SOURCE_HEADER_SIZE..)?;
    (id != u64::MAX && peer.len() + 2 <= max_symbol_len && eligible_peer(peer))
        .then_some((id, peer))
}

pub(super) fn parse_repair(
    packet: &ZCPacket,
    max_symbol_len: usize,
) -> Option<(u64, usize, u32, &[u8])> {
    if classify(packet) != FrameKind::Repair {
        return None;
    }
    let data = packet.tunnel_payload();
    let first = u64::from_le_bytes(data.get(..8)?.try_into().ok()?);
    let count = usize::from(data[KIND_OFFSET] & !KIND_MASK);
    let reserved = *data.get(9)?;
    let repair = u32::from_le_bytes(data.get(10..REPAIR_HEADER_SIZE)?.try_into().ok()?);
    let symbol = data.get(REPAIR_HEADER_SIZE..)?;
    if reserved != 0
        || !(1..=WINDOW).contains(&count)
        || first.checked_add(count as u64).is_none()
        || !(PEER_MANAGER_HEADER_SIZE + 2..=max_symbol_len.min(u16::MAX as usize + 2))
            .contains(&symbol.len())
    {
        return None;
    }
    Some((first, count, repair, symbol))
}

pub(super) fn restore_peer(peer: &[u8]) -> Option<ZCPacket> {
    if !eligible_peer(peer) {
        return None;
    }
    let mut bytes = BytesMut::with_capacity(UDP_TUNNEL_HEADER_SIZE + peer.len());
    bytes.resize(UDP_TUNNEL_HEADER_SIZE, 0);
    bytes.extend_from_slice(peer);
    Some(ZCPacket::new_from_buf(bytes, ZCPacketType::UDP))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source() -> ZCPacket {
        let mut source = ZCPacket::new_with_payload(b"source payload");
        source.fill_peer_manager_hdr(11, 22, PacketType::Data as u8);
        source
    }

    #[test]
    fn source_roundtrip_preserves_complete_peer_packet() {
        let mut source = source();
        source
            .mut_peer_manager_header()
            .unwrap()
            .set_encrypted(true);
        source.mut_peer_manager_header().unwrap().len.set(7);
        for kind in [
            PacketType::Data,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
        ] {
            source.mut_peer_manager_header().unwrap().packet_type = kind as u8;
            let frame = wrap_source(17, &source);
            assert_eq!(classify(&frame), FrameKind::Source);
            let (id, peer) = parse_source(&frame, 1400).unwrap();
            assert_eq!(id, 17);
            assert_eq!(peer, source.tunnel_payload());
            assert_eq!(restore_peer(peer).unwrap().tunnel_payload(), peer);
            assert_eq!(frame.tunnel_payload().len(), peer.len() + 9);

            let mut symbol = (peer.len() as u16).to_le_bytes().to_vec();
            symbol.extend_from_slice(peer);
            let repair = wrap_repair(17, 1, 9, &symbol);
            assert_eq!(classify(&repair), FrameKind::Repair);
            assert_eq!(repair.tunnel_payload().len(), peer.len() + 16);
            assert_eq!(
                parse_repair(&repair, 1400),
                Some((17, 1, 9, symbol.as_slice()))
            );
        }
    }

    #[test]
    fn discriminator_matches_the_plain_packet_type_namespace() {
        assert_eq!(
            std::mem::offset_of!(crate::packet::PeerManagerHeader, packet_type),
            KIND_OFFSET
        );
        // The exhaustive match makes adding an enum variant a deliberate
        // update to this namespace check rather than silently omitting it.
        let check = |kind: PacketType| match kind {
            PacketType::Invalid
            | PacketType::Data
            | PacketType::HandShake
            | PacketType::RoutePacket
            | PacketType::Ping
            | PacketType::Pong
            | PacketType::TaRpc
            | PacketType::Route
            | PacketType::RpcReq
            | PacketType::RpcResp
            | PacketType::ForeignNetworkPacket
            | PacketType::KcpSrc
            | PacketType::KcpDst
            | PacketType::QuicSrc
            | PacketType::QuicDst
            | PacketType::NoiseHandshakeMsg1
            | PacketType::NoiseHandshakeMsg2
            | PacketType::NoiseHandshakeMsg3
            | PacketType::RelayHandshake
            | PacketType::RelayHandshakeAck
            | PacketType::DataWithKcpSrcModified
            | PacketType::DataWithQuicSrcModified => assert!((kind as u8) < SOURCE),
        };
        for kind in [
            PacketType::Invalid,
            PacketType::Data,
            PacketType::HandShake,
            PacketType::RoutePacket,
            PacketType::Ping,
            PacketType::Pong,
            PacketType::TaRpc,
            PacketType::Route,
            PacketType::RpcReq,
            PacketType::RpcResp,
            PacketType::ForeignNetworkPacket,
            PacketType::KcpSrc,
            PacketType::KcpDst,
            PacketType::QuicSrc,
            PacketType::QuicDst,
            PacketType::NoiseHandshakeMsg1,
            PacketType::NoiseHandshakeMsg2,
            PacketType::NoiseHandshakeMsg3,
            PacketType::RelayHandshake,
            PacketType::RelayHandshakeAck,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            check(kind);
        }

        let mut packet = source();
        let header = packet.mut_peer_manager_header().unwrap();
        header.from_peer_id.set(u32::MAX);
        header.to_peer_id.set(u32::MAX);
        for kind in 0..SOURCE {
            packet.mut_peer_manager_header().unwrap().packet_type = kind;
            assert_eq!(classify(&packet), FrameKind::Plain);
        }
        // First-byte/first-word sniffing would misclassify some of these IDs.
        for id in [0, 1, u32::MAX as u64, u64::MAX - 1] {
            assert_eq!(classify(&wrap_source(id, &source())), FrameKind::Source);
        }
    }

    #[test]
    fn framing_rejects_truncation_invalid_span_and_oversized_symbols() {
        let source = source();
        let frame = wrap_source(17, &source);
        // The original header's length may describe uncompressed plaintext,
        // so framing can reject an incomplete header, not a shorter payload.
        // Ciphertext integrity is checked by the existing session filter.
        for len in 0..SOURCE_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE {
            let packet = ZCPacket::new_from_buf(
                BytesMut::from(&frame.tunnel_payload()[..len]),
                ZCPacketType::DummyTunnel,
            );
            assert!(parse_source(&packet, 1400).is_none());
        }
        assert!(parse_source(&frame, source.tunnel_payload().len() + 1).is_none());
        assert!(parse_source(&wrap_source(u64::MAX, &source), 1400).is_none());
        let symbol = vec![0; PEER_MANAGER_HEADER_SIZE + 2];
        for (first, count) in [(0, 0), (0, WINDOW + 1), (u64::MAX, 1)] {
            assert!(parse_repair(&wrap_repair(first, count, 1, &symbol), 1400).is_none());
        }
        let repair = wrap_repair(7, WINDOW, 19, &symbol);
        assert_eq!(
            parse_repair(&repair, 1400),
            Some((7, WINDOW, 19, symbol.as_slice()))
        );
        for len in 0..repair.tunnel_payload().len() {
            let packet = ZCPacket::new_from_buf(
                BytesMut::from(&repair.tunnel_payload()[..len]),
                ZCPacketType::DummyTunnel,
            );
            assert!(parse_repair(&packet, 1400).is_none());
        }
        assert!(parse_repair(&repair, symbol.len() - 1).is_none());
        for kind in [0, SOURCE | 1, REPAIR, KIND_MASK] {
            let mut data = frame.tunnel_payload().to_vec();
            data[KIND_OFFSET] = kind;
            assert!(parse_source(&wrap(&data), 1400).is_none());
        }
        for (offset, value) in [(KIND_OFFSET, SOURCE), (KIND_OFFSET, KIND_MASK), (9, 1)] {
            let mut data = repair.tunnel_payload().to_vec();
            data[offset] = value;
            assert!(parse_repair(&wrap(&data), 1400).is_none());
        }
        let mut control = source;
        for kind in [
            PacketType::Ping,
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            control.mut_peer_manager_header().unwrap().packet_type = kind as u8;
            assert!(parse_source(&wrap_source(0, &control), 1400).is_none());
            assert!(restore_peer(control.tunnel_payload()).is_none());
        }
    }
}

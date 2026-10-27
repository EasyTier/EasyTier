use bytes::BytesMut;

use crate::packet::{
    FEC_HEADER_SIZE, FEC_MAX_OVERHEAD, PEER_MANAGER_HEADER_SIZE, PacketType,
    UDP_TUNNEL_HEADER_SIZE, ZCPacket, ZCPacketType,
};

pub(super) const SOURCE: u8 = PacketType::FecSource as u8;
pub(super) const REPAIR: u8 = PacketType::FecRepair as u8;
pub(super) const FEEDBACK: u8 = PacketType::FecFeedback as u8;
pub(super) const MAX_MTU: usize = 8192;
pub(super) const OVERHEAD: usize = FEC_MAX_OVERHEAD - 2;
pub(super) const MAX_SYMBOL: usize = MAX_MTU - OVERHEAD;

#[derive(Clone, Copy, Debug)]
pub(super) struct Header {
    pub kind: u8,
    pub sequence: u64,
    pub source: u64,
    pub repair: u32,
    pub count: u8,
}

pub(super) struct Fragment<'a> {
    pub header: Header,
    pub payload: &'a [u8],
}

pub(super) fn encode(header: Header, payload: &[u8]) -> ZCPacket {
    // Leave ordinary UDP headroom so the transport does not copy the frame.
    let mut out = BytesMut::with_capacity(OVERHEAD + payload.len());
    out.resize(UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE, 0);
    out.extend_from_slice(&[1, header.count]);
    out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
    out.extend_from_slice(&header.sequence.to_le_bytes());
    out.extend_from_slice(&header.source.to_le_bytes());
    out.extend_from_slice(&header.repair.to_le_bytes());
    out.extend_from_slice(payload);
    let mut packet = ZCPacket::new_from_buf(out, ZCPacketType::UDP);
    packet.fill_peer_manager_hdr(0, 0, header.kind);
    packet
}

pub(super) fn decode(packet: &ZCPacket) -> Option<Fragment<'_>> {
    let peer = packet.tunnel_payload();
    if peer.len() + UDP_TUNNEL_HEADER_SIZE > MAX_MTU
        || peer.len() < PEER_MANAGER_HEADER_SIZE + FEC_HEADER_SIZE
    {
        return None;
    }
    let data = &peer[PEER_MANAGER_HEADER_SIZE..];
    let payload_len = u16::from_le_bytes(data[2..4].try_into().ok()?) as usize;
    if data[0] != 1 || payload_len + FEC_HEADER_SIZE != data.len() {
        return None;
    }
    let header = Header {
        kind: peer[8],
        count: data[1],
        sequence: u64::from_le_bytes(data[4..12].try_into().ok()?),
        source: u64::from_le_bytes(data[12..20].try_into().ok()?),
        repair: u32::from_le_bytes(data[20..24].try_into().ok()?),
    };
    if header.sequence == u64::MAX || header.source == u64::MAX {
        return None;
    }
    match header.kind {
        SOURCE => {
            if header.count != 0
                || header.repair != 0
                || !(PEER_MANAGER_HEADER_SIZE..=MAX_SYMBOL - 2).contains(&payload_len)
            {
                return None;
            }
        }
        REPAIR => {
            if !(1..=64).contains(&header.count)
                || header.source.checked_add(u64::from(header.count)).is_none()
                || !(PEER_MANAGER_HEADER_SIZE + 2..=MAX_SYMBOL).contains(&payload_len)
            {
                return None;
            }
        }
        FEEDBACK => {
            if header.count != 0 || header.repair != 0 || payload_len != 8 {
                return None;
            }
        }
        _ => return None,
    }
    Some(Fragment {
        header,
        payload: &data[FEC_HEADER_SIZE..],
    })
}

pub(super) fn eligible_peer(bytes: &[u8]) -> bool {
    if bytes.len() < PEER_MANAGER_HEADER_SIZE {
        return false;
    }
    // The peer length is the uncompressed length, not necessarily the wire size.
    matches!(bytes[8], 1 | 3 | 6..=12 | 16..=19)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_bounds_reject_invalid_windows_and_lengths() {
        let repair = Header {
            kind: REPAIR,
            sequence: 100,
            source: 20,
            repair: 3,
            count: 64,
        };
        assert!(decode(&encode(repair, &vec![0; MAX_SYMBOL])).is_some());
        assert!(decode(&encode(repair, &vec![0; MAX_SYMBOL + 1])).is_none());
        for header in [
            Header { count: 0, ..repair },
            Header {
                count: 65,
                ..repair
            },
            Header {
                source: u64::MAX - 1,
                ..repair
            },
            Header {
                sequence: u64::MAX,
                ..repair
            },
            Header {
                kind: SOURCE,
                ..repair
            },
            Header {
                kind: FEEDBACK,
                count: 0,
                repair: 0,
                ..repair
            },
        ] {
            assert!(decode(&encode(header, &[0; 18])).is_none());
        }
        let valid = encode(repair, &[0; 18]);
        // Use a fresh buffer to exercise malformed on-wire headers without the
        // encoder repairing their version or payload-length fields.
        for (offset, value) in [(0, 2), (2, 17), (3, 1)] {
            let mut bytes = BytesMut::from(valid.tunnel_payload());
            bytes[PEER_MANAGER_HEADER_SIZE + offset] = value;
            let packet = ZCPacket::new_from_buf(bytes, ZCPacketType::DummyTunnel);
            assert!(decode(&packet).is_none());
        }
    }
}

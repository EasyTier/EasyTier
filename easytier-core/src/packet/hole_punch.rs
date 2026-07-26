use bytes::BytesMut;
use rand::{Rng, SeedableRng};
use zerocopy::FromBytes as _;

use super::{UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, UdpPacketType, ZCPacket, ZCPacketType};

pub(crate) const HOLE_PUNCH_PACKET_BODY_LEN: u16 = 16;

fn new_udp_packet<F>(f: F, udp_body: &[u8]) -> ZCPacket
where
    F: FnOnce(&mut UDPTunnelHeader),
{
    let mut buf = BytesMut::new();
    buf.resize(UDP_TUNNEL_HEADER_SIZE + udp_body.len(), 0);
    buf[UDP_TUNNEL_HEADER_SIZE..].copy_from_slice(udp_body);

    let mut ret = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = ret.mut_udp_tunnel_header().unwrap();
    f(header);
    ret
}

pub(crate) fn new_hole_punch_packet(tid: u32, buf_len: u16) -> ZCPacket {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut buf = vec![0u8; buf_len as usize];
    rng.fill(&mut buf[..]);
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::HolePunch as u8;
            header.conn_id.set(tid);
            header.len.set(buf_len);
        },
        &buf,
    )
}

pub(crate) fn hole_punch_packet_tid(data: &[u8], body_len: u16) -> Option<u32> {
    if data.len() != UDP_TUNNEL_HEADER_SIZE + body_len as usize {
        return None;
    }

    let header = UDPTunnelHeader::ref_from_prefix(data)?;
    let valid = header.msg_type == UdpPacketType::HolePunch as u8 && header.len.get() == body_len;

    valid.then(|| header.conn_id.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_and_parses_hole_punch_packet() {
        let tid = 0x1234_5678;
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN);
        let bytes = packet.into_bytes();

        assert_eq!(
            bytes.len(),
            UDP_TUNNEL_HEADER_SIZE + HOLE_PUNCH_PACKET_BODY_LEN as usize
        );
        assert_eq!(
            hole_punch_packet_tid(&bytes, HOLE_PUNCH_PACKET_BODY_LEN),
            Some(tid)
        );
    }

    #[test]
    fn rejects_non_matching_hole_punch_packet_length() {
        let packet = new_hole_punch_packet(1, HOLE_PUNCH_PACKET_BODY_LEN);
        let mut bytes = packet.into_bytes().to_vec();
        bytes.pop();

        assert_eq!(
            hole_punch_packet_tid(&bytes, HOLE_PUNCH_PACKET_BODY_LEN),
            None
        );
    }
}

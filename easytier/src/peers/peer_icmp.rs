use crate::common::global_ctx::ArcGlobalCtx;
use crate::tunnel::packet_def::{PacketType, ZCPacket};
use pnet::packet::icmp::IcmpCode;
use pnet::packet::{
    icmp::{self, destination_unreachable, time_exceeded, IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::{Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    Packet as _,
};
use std::net::Ipv4Addr;

pub fn build_icmp_unreachable_reply(
    ctx: &ArcGlobalCtx,
    code: IcmpCode,
    from_peer_id: u32,
    to_peer_id: u32,
    msg: &ZCPacket,
) -> Option<ZCPacket> {
    build_icmp_error_reply(ctx, from_peer_id, to_peer_id, msg, |ipv4, inner_len| {
        let mut icmp_buf = vec![0u8; 8 + inner_len];
        let mut icmp_packet =
            destination_unreachable::MutableDestinationUnreachablePacket::new(&mut icmp_buf)?;
        icmp_packet.set_icmp_type(IcmpTypes::DestinationUnreachable);
        icmp_packet.set_icmp_code(code);
        icmp_packet.set_unused(0);
        icmp_packet.set_next_hop_mtu(0);
        icmp_packet.set_payload(&ipv4.packet()[..inner_len]);
        icmp_packet.set_checksum(icmp::checksum(&IcmpPacket::new(icmp_packet.packet())?));
        Some(icmp_buf)
    })
}

pub fn build_icmp_time_exceeded_reply(
    ctx: &ArcGlobalCtx,
    code: IcmpCode,
    from_peer_id: u32,
    to_peer_id: u32,
    msg: &ZCPacket,
) -> Option<ZCPacket> {
    build_icmp_error_reply(ctx, from_peer_id, to_peer_id, msg, |ipv4, inner_len| {
        let mut icmp_buf = vec![0u8; 8 + inner_len];
        let mut icmp_packet = time_exceeded::MutableTimeExceededPacket::new(&mut icmp_buf)?;
        icmp_packet.set_icmp_type(IcmpTypes::TimeExceeded);
        icmp_packet.set_icmp_code(code);
        icmp_packet.set_unused(0);
        icmp_packet.set_payload(&ipv4.packet()[..inner_len]);
        icmp_packet.set_checksum(icmp::checksum(&IcmpPacket::new(icmp_packet.packet())?));
        Some(icmp_buf)
    })
}

fn build_icmp_error_reply<F>(
    ctx: &ArcGlobalCtx,
    from_peer_id: u32,
    to_peer_id: u32,
    msg: &ZCPacket,
    build_icmp: F,
) -> Option<ZCPacket>
where
    F: FnOnce(&Ipv4Packet, usize) -> Option<Vec<u8>>,
{
    let ipv4 = Ipv4Packet::new(msg.payload())?;
    if ipv4.get_version() != 4 {
        return None;
    }

    if ipv4.get_fragment_offset() != 0 {
        return None;
    }

    let src_ip = ipv4.get_source();
    if !is_valid_icmp_src_ipv4(src_ip) {
        return None;
    }

    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
        let icmp_packet = IcmpPacket::new(ipv4.payload())?;
        let icmp_type = icmp_packet.get_icmp_type();
        if is_icmp_error_type(icmp_type) {
            return None;
        }
    }

    let src_v4 = ctx.get_ipv4()?.address();
    let dst_v4 = src_ip;

    let header_len = ipv4.get_header_length() as usize * 4;
    let original_payload_len = ipv4.payload().len();
    let inner_len = std::cmp::min(576 - 8, header_len + original_payload_len);

    let icmp_buf = build_icmp(&ipv4, inner_len)?;

    let mut ipv4_buf = vec![0u8; 20 + icmp_buf.len()];
    {
        let len = ipv4_buf.len() as u16;
        let mut out_ipv4 = MutableIpv4Packet::new(&mut ipv4_buf)?;
        out_ipv4.set_version(4);
        out_ipv4.set_header_length(5);
        out_ipv4.set_total_length(len);
        out_ipv4.set_identification(rand::random());
        out_ipv4.set_flags(Ipv4Flags::DontFragment);
        out_ipv4.set_fragment_offset(0);
        out_ipv4.set_ttl(32);
        out_ipv4.set_source(src_v4);
        out_ipv4.set_destination(dst_v4);
        out_ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
        out_ipv4.set_payload(&icmp_buf);
        out_ipv4.set_checksum(pnet::packet::ipv4::checksum(&out_ipv4.to_immutable()));
    }

    let mut packet = ZCPacket::new_with_payload(&ipv4_buf);
    packet.fill_peer_manager_hdr(from_peer_id, to_peer_id, PacketType::Data as u8);
    Some(packet)
}

fn is_valid_icmp_src_ipv4(src_ip: Ipv4Addr) -> bool {
    if src_ip.is_unspecified() || src_ip.is_multicast() || src_ip.is_broadcast() {
        return false;
    }

    if src_ip.is_loopback() {
        return false;
    }

    true
}

fn is_icmp_error_type(icmp_type: pnet::packet::icmp::IcmpType) -> bool {
    matches!(
        icmp_type,
        IcmpTypes::DestinationUnreachable
            | IcmpTypes::SourceQuench
            | IcmpTypes::RedirectMessage
            | IcmpTypes::TimeExceeded
            | IcmpTypes::ParameterProblem
    )
}

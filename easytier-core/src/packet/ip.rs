//! Shared IP and transport-header parsing for packet consumers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub(crate) const IP_PROTO_ICMP: u8 = 1;
pub(crate) const IP_PROTO_TCP: u8 = 6;
pub(crate) const IP_PROTO_UDP: u8 = 17;
pub(crate) const IP_PROTO_ICMPV6: u8 = 58;
pub(crate) const IP_PROTO_UNSPECIFIED: u8 = u8::MAX;

pub(crate) const IPV6_HOP_BY_HOP: u8 = 0;
pub(crate) const IPV6_ROUTING: u8 = 43;
pub(crate) const IPV6_FRAGMENT: u8 = 44;
pub(crate) const IPV6_AUTHENTICATION: u8 = 51;
pub(crate) const IPV6_DESTINATION_OPTIONS: u8 = 60;

#[derive(Clone, Copy)]
pub(crate) struct ParsedIpPacket<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub protocol: u8,
    pub transport_payload: &'a [u8],
    pub is_non_initial_fragment: bool,
    pub is_fragment: bool,
    /// Whether the IP header and declared packet length fit in the input.
    pub has_valid_length: bool,
}

pub(crate) fn parse_ip_packet(payload: &[u8]) -> Option<ParsedIpPacket<'_>> {
    let version = payload.first()? >> 4;
    match version {
        4 => parse_ipv4_packet(payload),
        6 => parse_ipv6_packet(payload),
        _ => None,
    }
}

fn parse_ipv4_packet(payload: &[u8]) -> Option<ParsedIpPacket<'_>> {
    if payload.len() < 20 {
        return None;
    }
    let header_len = usize::from(payload[0] & 0x0f) * 4;
    let options_len = header_len.saturating_sub(20);
    let payload_offset = 20 + options_len;
    let payload_start = payload_offset.min(payload.len());
    let total_length = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    let payload_len = total_length.saturating_sub(header_len);
    let payload_end = payload_start.saturating_add(payload_len).min(payload.len());

    Some(ParsedIpPacket {
        src_ip: IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        )),
        dst_ip: IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        )),
        protocol: payload[9],
        transport_payload: payload.get(payload_start..payload_end)?,
        is_non_initial_fragment: u16::from_be_bytes([payload[6], payload[7]]) & 0x1fff != 0,
        is_fragment: u16::from_be_bytes([payload[6], payload[7]]) & 0x3fff != 0,
        has_valid_length: header_len >= 20
            && total_length >= header_len
            && total_length <= payload.len(),
    })
}

fn parse_ipv6_packet(payload: &[u8]) -> Option<ParsedIpPacket<'_>> {
    if payload.len() < 40 {
        return None;
    }

    let payload_len = usize::from(u16::from_be_bytes([payload[4], payload[5]]));

    // A valid base header still supplies the addresses needed for ACL rules,
    // even when the upper-layer headers cannot be decoded.
    let parsed = ParsedIpPacket {
        src_ip: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[8..24]).ok()?)),
        dst_ip: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&payload[24..40]).ok()?)),
        protocol: IP_PROTO_UNSPECIFIED,
        transport_payload: &[],
        is_non_initial_fragment: false,
        is_fragment: false,
        has_valid_length: 40 + payload_len <= payload.len(),
    };

    let payload_end = 40usize.saturating_add(payload_len).min(payload.len());
    let mut protocol = payload[6];
    let mut payload_offset = 40;
    let mut is_non_initial_fragment = false;
    let mut is_fragment = false;
    let mut saw_fragment_header = false;

    loop {
        match protocol {
            IPV6_HOP_BY_HOP | IPV6_ROUTING | IPV6_DESTINATION_OPTIONS => {
                let header = &payload[payload_offset..payload_end];
                let Some(&header_len) = header.get(1) else {
                    return Some(parsed);
                };
                let extension_len = (usize::from(header_len) + 1) * 8;
                let next_protocol = header[0];
                let extension_end = payload_offset + extension_len;
                if extension_end > payload_end {
                    return Some(parsed);
                }
                protocol = next_protocol;
                payload_offset = extension_end;
            }
            IPV6_AUTHENTICATION => {
                let header = &payload[payload_offset..payload_end];
                let Some(&header_len) = header.get(1) else {
                    return Some(parsed);
                };
                let extension_len = (usize::from(header_len) + 2) * 4;
                let next_protocol = header[0];
                let extension_end = payload_offset + extension_len;
                if extension_end > payload_end {
                    return Some(parsed);
                }
                protocol = next_protocol;
                payload_offset = extension_end;
            }
            IPV6_FRAGMENT => {
                if saw_fragment_header {
                    return Some(parsed);
                }
                saw_fragment_header = true;

                let fragment_end = payload_offset + 8;
                if fragment_end > payload_end {
                    return Some(parsed);
                }
                let header = &payload[payload_offset..fragment_end];
                let fragment_field = u16::from_be_bytes([header[2], header[3]]);
                is_non_initial_fragment = fragment_field & 0xfff8 != 0;
                // An atomic fragment has its complete transport header.
                is_fragment = fragment_field & 0xfff9 != 0;
                let next_protocol = header[0];
                payload_offset = fragment_end;

                protocol = next_protocol;
                if is_non_initial_fragment {
                    // Extension headers after the Fragment Header are only in the first
                    // fragment. Do not interpret tail data as an extension header.
                    // Only ICMPv6 tails can use the response records without a
                    // transport header. Leave other tails to address/group ACLs.
                    if protocol != IP_PROTO_ICMPV6 {
                        protocol = IP_PROTO_UNSPECIFIED;
                    }
                    break;
                }
            }
            _ => break,
        }
    }

    let transport_payload = &payload[payload_offset..payload_end];
    if payload_offset != 40 && parse_transport_ports(protocol, transport_payload).is_none() {
        return Some(parsed);
    }

    Some(ParsedIpPacket {
        protocol,
        transport_payload,
        is_non_initial_fragment,
        is_fragment,
        ..parsed
    })
}

pub(crate) fn parse_transport_ports(
    protocol: u8,
    payload: &[u8],
) -> Option<(Option<u16>, Option<u16>)> {
    let min_len = match protocol {
        IP_PROTO_TCP => 20,
        IP_PROTO_UDP => 8,
        _ => return Some((None, None)),
    };
    if payload.len() < min_len {
        return None;
    }

    Some((
        Some(u16::from_be_bytes([payload[0], payload[1]])),
        Some(u16::from_be_bytes([payload[2], payload[3]])),
    ))
}

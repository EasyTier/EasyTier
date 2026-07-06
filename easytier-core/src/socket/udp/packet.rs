use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
};

use bytes::BytesMut;
use zerocopy::{AsBytes, FromBytes};

use crate::packet::{
    UDP_TUNNEL_HEADER_SIZE, UDPTunnelHeader, UdpPacketType, V4HolePunchPacket, V6HolePunchPacket,
    ZCPacket, ZCPacketType,
};

use super::{session::UdpSessionProtocol, virtual_socket::PreferredIpv6Source};

#[derive(Debug, thiserror::Error)]
pub enum UdpSessionPacketError {
    #[error("udp packet size too small: {datagram_size:?}, packet: {packet:?}")]
    TooSmall {
        datagram_size: usize,
        packet: BytesMut,
    },
    #[error(
        "udp packet payload len not match: header len: {header_len:?}, real len: {datagram_size:?}"
    )]
    PayloadLenMismatch {
        header_len: usize,
        datagram_size: usize,
    },
}

pub(super) fn new_udp_packet<F>(f: F, udp_body: &[u8]) -> ZCPacket
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

pub fn new_syn_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Syn as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

pub fn new_sack_packet(conn_id: u32, magic: u64) -> ZCPacket {
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Sack as u8;
            header.conn_id.set(conn_id);
            header.len.set(8);
        },
        &magic.to_le_bytes(),
    )
}

pub(super) fn new_data_packet(conn_id: u32, payload: &[u8]) -> io::Result<ZCPacket> {
    let len = udp_session_payload_len(payload)?;

    Ok(new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::Data as u8;
            header.conn_id.set(conn_id);
            header.len.set(len);
        },
        payload,
    ))
}

pub(super) fn udp_session_payload_len(payload: &[u8]) -> io::Result<u16> {
    u16::try_from(payload.len()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("udp session payload too large: {}", payload.len()),
        )
    })
}

pub fn new_v6_hole_punch_packet(
    dst: &SocketAddrV6,
    preferred_src: Option<PreferredIpv6Source>,
) -> ZCPacket {
    let mut body = V6HolePunchPacket::default();
    body.dst_ipv6.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    if let Some(src) = preferred_src {
        body.preferred_src_ipv6.copy_from_slice(&src.ip.octets());
        body.preferred_src_ifindex.set(src.ifindex);
    }
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V6HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V6HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn new_v4_hole_punch_packet(dst: &SocketAddrV4) -> ZCPacket {
    let mut body = V4HolePunchPacket::default();
    body.dst_ipv4.copy_from_slice(&dst.ip().octets());
    body.dst_port.set(dst.port());
    new_udp_packet(
        |header| {
            header.msg_type = UdpPacketType::V4HolePunch as u8;
            header.conn_id.set(dst.port() as u32);
            header
                .len
                .set(std::mem::size_of::<V4HolePunchPacket>() as u16);
        },
        body.as_bytes(),
    )
}

pub fn extract_dst_addr_from_v4_hole_punch_packet(buf: &[u8]) -> Option<SocketAddrV4> {
    let body = V4HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv4Addr::from(body.dst_ipv4);
    Some(SocketAddrV4::new(ip, body.dst_port.get()))
}

pub fn extract_v6_hole_punch_packet(
    buf: &[u8],
) -> Option<(SocketAddrV6, Option<PreferredIpv6Source>)> {
    let body = V6HolePunchPacket::ref_from_prefix(buf)?;
    let ip = Ipv6Addr::from(body.dst_ipv6);
    let preferred_src_ipv6 = Ipv6Addr::from(body.preferred_src_ipv6);
    let preferred_src = (!preferred_src_ipv6.is_unspecified()).then_some(PreferredIpv6Source {
        ip: preferred_src_ipv6,
        ifindex: body.preferred_src_ifindex.get(),
    });
    Some((
        SocketAddrV6::new(ip, body.dst_port.get(), 0, 0),
        preferred_src,
    ))
}

pub fn is_stun_packet(data: &[u8]) -> bool {
    data.len() >= UDP_TUNNEL_HEADER_SIZE
        && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
        && data[0] & 0xC0 == 0
}

#[derive(Debug)]
pub(super) enum UdpDatagramClassification {
    Stun(BytesMut),
    EasyTier {
        kind: EasyTierUdpPacketKind,
        conn_id: u32,
        packet: ZCPacket,
        fallback: UdpSessionPacketKind,
    },
    SessionPacket {
        kind: UdpSessionPacketKind,
        datagram: BytesMut,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UdpSessionPacketKind {
    Classified(UdpSessionProtocol),
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EasyTierUdpPacketKind {
    Data,
    Syn,
    Sack,
    HolePunch,
    V4HolePunch,
    V6HolePunch,
}

impl EasyTierUdpPacketKind {
    fn from_msg_type(msg_type: u8) -> Option<Self> {
        match msg_type {
            msg_type if msg_type == UdpPacketType::Data as u8 => Some(Self::Data),
            msg_type if msg_type == UdpPacketType::Syn as u8 => Some(Self::Syn),
            msg_type if msg_type == UdpPacketType::Sack as u8 => Some(Self::Sack),
            msg_type if msg_type == UdpPacketType::HolePunch as u8 => Some(Self::HolePunch),
            msg_type if msg_type == UdpPacketType::V4HolePunch as u8 => Some(Self::V4HolePunch),
            msg_type if msg_type == UdpPacketType::V6HolePunch as u8 => Some(Self::V6HolePunch),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct EasyTierUdpDatagramInfo {
    pub(super) kind: EasyTierUdpPacketKind,
    pub(super) conn_id: u32,
}

#[derive(Debug)]
pub(super) enum EasyTierUdpDatagramInspectError {
    TooSmall {
        datagram_size: usize,
    },
    PayloadLenMismatch {
        header_len: usize,
        datagram_size: usize,
    },
}

fn classify_session_udp_datagram(data: &[u8]) -> UdpSessionPacketKind {
    if is_wireguard_packet(data) {
        UdpSessionPacketKind::Classified(UdpSessionProtocol::WireGuard)
    } else if is_quic_packet(data) {
        UdpSessionPacketKind::Classified(UdpSessionProtocol::Quic)
    } else {
        UdpSessionPacketKind::Unknown
    }
}

fn is_wireguard_packet(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    let msg_type = u32::from_le_bytes(data[..4].try_into().unwrap());
    match msg_type {
        1 => data.len() == 148,
        2 => data.len() == 92,
        3 => data.len() == 64,
        4 => data.len() >= 32,
        _ => false,
    }
}

fn parse_quic_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return None;
    }

    let mut value = u64::from(first & 0x3f);
    for byte in &data[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, len))
}

pub fn parse_quic_initial_dcid(data: &[u8]) -> Option<Vec<u8>> {
    const QUIC_INITIAL_HEADER_FORM_AND_FIXED_BIT: u8 = 0xC0;
    const QUIC_LONG_PACKET_TYPE_MASK: u8 = 0x30;
    const QUIC_MIN_INITIAL_DATAGRAM_LEN: usize = 1200;
    const QUIC_MAX_CID_LEN: usize = 20;

    let first = *data.first()?;
    if (first & QUIC_INITIAL_HEADER_FORM_AND_FIXED_BIT) != QUIC_INITIAL_HEADER_FORM_AND_FIXED_BIT
        || (first & QUIC_LONG_PACKET_TYPE_MASK) != 0
        || data.len() < QUIC_MIN_INITIAL_DATAGRAM_LEN
    {
        return None;
    }

    let version = data.get(1..5)?;
    if version == [0, 0, 0, 0] {
        return None;
    }

    let dcid_len = usize::from(*data.get(5)?);
    if dcid_len == 0 || dcid_len > QUIC_MAX_CID_LEN {
        return None;
    }
    let dcid_start = 6;
    let dcid_end = dcid_start + dcid_len;
    let dcid = data.get(dcid_start..dcid_end)?;

    let scid_len = usize::from(*data.get(dcid_end)?);
    if scid_len > QUIC_MAX_CID_LEN {
        return None;
    }
    let token_len_offset = dcid_end + 1 + scid_len;
    let (token_len, token_len_size) = parse_quic_varint(data.get(token_len_offset..)?)?;
    let packet_len_offset = token_len_offset + token_len_size + usize::try_from(token_len).ok()?;
    let (packet_len, packet_len_size) = parse_quic_varint(data.get(packet_len_offset..)?)?;
    let packet_offset = packet_len_offset + packet_len_size;
    if packet_len == 0
        || data.len().saturating_sub(packet_offset) < usize::try_from(packet_len).ok()?
    {
        return None;
    }

    Some(dcid.to_vec())
}

fn is_quic_packet(data: &[u8]) -> bool {
    parse_quic_initial_dcid(data).is_some()
}

pub(super) fn inspect_easytier_udp_datagram(
    data: &[u8],
) -> Result<Option<EasyTierUdpDatagramInfo>, EasyTierUdpDatagramInspectError> {
    let datagram_size = data.len();
    if datagram_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(EasyTierUdpDatagramInspectError::TooSmall { datagram_size });
    }

    let header = UDPTunnelHeader::ref_from_prefix(data).unwrap();
    let header_len = header.len.get() as usize;
    let real_len = datagram_size - UDP_TUNNEL_HEADER_SIZE;
    if header_len != real_len {
        return Err(EasyTierUdpDatagramInspectError::PayloadLenMismatch {
            header_len,
            datagram_size,
        });
    }

    Ok(
        EasyTierUdpPacketKind::from_msg_type(header.msg_type).map(|kind| EasyTierUdpDatagramInfo {
            kind,
            conn_id: header.conn_id.get(),
        }),
    )
}

pub(super) fn classify_udp_datagram(datagram: BytesMut) -> UdpDatagramClassification {
    if is_stun_packet(&datagram) {
        return UdpDatagramClassification::Stun(datagram);
    }

    let fallback = classify_session_udp_datagram(&datagram);
    let easytier = match inspect_easytier_udp_datagram(&datagram) {
        Ok(Some(easytier)) => easytier,
        Ok(None) => {
            return UdpDatagramClassification::SessionPacket {
                kind: fallback,
                datagram,
            };
        }
        Err(err) => {
            match err {
                EasyTierUdpDatagramInspectError::TooSmall { datagram_size } => {
                    tracing::debug!(datagram_size, "udp session packet too small");
                }
                EasyTierUdpDatagramInspectError::PayloadLenMismatch {
                    header_len,
                    datagram_size,
                } => {
                    tracing::debug!(
                        header_len,
                        datagram_size,
                        "udp session packet payload len mismatch"
                    );
                }
            }
            return UdpDatagramClassification::SessionPacket {
                kind: fallback,
                datagram,
            };
        }
    };
    let packet = ZCPacket::new_from_buf(datagram, ZCPacketType::UDP);

    UdpDatagramClassification::EasyTier {
        kind: easytier.kind,
        conn_id: easytier.conn_id,
        packet,
        fallback,
    }
}

pub fn parse_udp_session_datagram(
    buf: BytesMut,
    allow_stun: bool,
) -> Result<ZCPacket, UdpSessionPacketError> {
    let datagram_size = buf.len();
    if datagram_size < UDP_TUNNEL_HEADER_SIZE {
        return Err(UdpSessionPacketError::TooSmall {
            datagram_size,
            packet: buf,
        });
    }

    if allow_stun && is_stun_packet(&buf[..UDP_TUNNEL_HEADER_SIZE]) {
        return Ok(ZCPacket::new_from_buf(buf, ZCPacketType::UDP));
    }

    let zc_packet = ZCPacket::new_from_buf(buf, ZCPacketType::UDP);
    let header = zc_packet.udp_tunnel_header().unwrap();
    let header_len = header.len.get() as usize;
    let real_len = datagram_size - UDP_TUNNEL_HEADER_SIZE;
    if header_len != real_len {
        return Err(UdpSessionPacketError::PayloadLenMismatch {
            header_len,
            datagram_size,
        });
    }

    Ok(zc_packet)
}

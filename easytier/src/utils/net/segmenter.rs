use crate::utils::buf::{BufMargins, BufPool};
use bytes::BytesMut;
use etherparse::{
    Ipv4Slice, Ipv6ExtensionSlice, Ipv6Slice, NetSlice, SlicedPacket, TcpSlice, TransportSlice,
    UdpSlice,
};
use std::collections::VecDeque;
use thiserror::Error;
use zerocopy::FromBytes;

use easytier_core::packet::{ZCPacket, ZCPacketType};

use super::virtio::*;

#[allow(dead_code)]
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const CWR: u8 = 0x80;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SegmentError {
    #[error("GSO packet has gso_size == 0")]
    InvalidGsoSize,

    #[error("unsupported virtio GSO type {0:#04x}")]
    UnsupportedGsoType(u8),

    #[error("virtio GSO type does not match the IP/transport packet")]
    ProtocolMismatch,

    #[error("failed to parse GSO IP packet")]
    InvalidPacket,

    #[error("unsupported network or transport protocol for GSO segmentation")]
    InvalidProtocol,

    #[error("GSO packet has no transport payload")]
    EmptyPayload,

    #[error("cannot software-segment a packet containing IPsec AH")]
    AuthenticationHeader,

    #[error("unsupported active IPv6 routing header type {0}")]
    UnsupportedRoutingHeader(u8),

    #[error("cannot software-segment an IPv4 packet containing source routing options")]
    SourceRouting,

    #[error("unsupported TCP flags in GSO packet: {0:#04x}")]
    UnsupportedTcpFlags(u8),

    #[error("software GSO segment exceeds protocol length limits")]
    SegmentTooLarge,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProto {
    Tcp = 6,
    Udp = 17,
}

impl IpProto {
    pub const fn checksum_offset(self) -> usize {
        match self {
            IpProto::Tcp => 16,
            IpProto::Udp => 6,
        }
    }
}

pub struct Segmenter {
    margins: BufMargins,
    queue: VecDeque<ZCPacket>,
}

impl Segmenter {
    pub fn new(margins: BufMargins) -> Self {
        Self {
            margins,
            queue: VecDeque::new(),
        }
    }

    pub fn pop(&mut self) -> Option<ZCPacket> {
        self.queue.pop_front()
    }

    fn write_checksum_at(buf: &mut [u8], offset: usize, csum: [u8; 2], proto: IpProto) {
        let csum = match (csum, proto) {
            ([0, 0], IpProto::Udp) => [0xff, 0xff],
            (csum, _) => csum,
        };
        if let Some(target) = buf.get_mut(offset..offset + 2) {
            target.copy_from_slice(&csum);
        }
    }

    fn write_vnet_checksum(buf: &mut [u8], vnet_hdr: &VirtioNetHdr, proto: IpProto) {
        if (vnet_hdr.flags & VNET_HDR_F_NEEDS_CSUM) == 0 {
            return;
        }

        let start = vnet_hdr.csum_start as usize;
        let offset = vnet_hdr.csum_offset as usize;

        if let Some(data) = buf.get_mut(start..) {
            Self::write_checksum_at(data, offset, internet_checksum::checksum(data), proto);
        }
    }

    fn write_segment_checksum(buf: &mut [u8], pseudo_hdr: &PseudoHdr, proto: IpProto) {
        let offset = proto.checksum_offset();
        if let Some(field) = buf.get_mut(offset..offset + 2) {
            field.fill(0);
        }
        let mut csum = internet_checksum::Checksum::new();
        csum.add_bytes(pseudo_hdr.as_ref());
        csum.add_bytes(buf);
        Self::write_checksum_at(buf, offset, csum.checksum(), proto);
    }

    pub fn push(&mut self, buf: &mut BufPool, mut packet: BytesMut, vnet_hdr_off: usize) {
        'push: {
            if packet.len() < self.margins.header {
                break 'push;
            }

            let (hdr, payload) = packet.split_at_mut(self.margins.header);
            let Some(vnet_hdr) = hdr
                .get(vnet_hdr_off..)
                .and_then(VirtioNetHdr::ref_from_prefix)
            else {
                break 'push;
            };

            let Ok(sliced) = SlicedPacket::from_ip(&*payload) else {
                break 'push;
            };

            let proto = match sliced.transport.as_ref() {
                Some(TransportSlice::Tcp(_)) => IpProto::Tcp,
                Some(TransportSlice::Udp(_)) => IpProto::Udp,
                _ => break 'push,
            };

            if vnet_hdr.gso_type != VNET_HDR_GSO_NONE {
                match self.segment(buf, vnet_hdr, &sliced, proto) {
                    Ok(_) => return,
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            "failed to software-segment GSO packet, passing through"
                        );
                    }
                }
            }

            drop(sliced);

            Self::write_vnet_checksum(payload, vnet_hdr, proto);
        }

        self.queue
            .push_back(ZCPacket::new_from_buf(packet, ZCPacketType::NIC));
    }

    fn parse_hdr_v4<'s>(
        ip: &'s Ipv4Slice<'s>,
        proto: IpProto,
    ) -> Result<(IpHdr<'s>, PseudoHdr), SegmentError> {
        if ip.extensions().auth.is_some() {
            return Err(SegmentError::AuthenticationHeader);
        }

        const IPOPT_EOL: u8 = 0x00;
        const IPOPT_NOP: u8 = 0x01;
        const IPOPT_LSRR: u8 = 0x83;
        const IPOPT_SSRR: u8 = 0x89;

        let mut opts = ip.header().options();
        while let Some((&kind, rest)) = opts.split_first() {
            match kind {
                IPOPT_EOL => break,
                IPOPT_NOP => {
                    opts = rest;
                }
                IPOPT_LSRR | IPOPT_SSRR => return Err(SegmentError::SourceRouting),
                _ => {
                    if let Some((&len, _)) = rest.split_first() {
                        let len = len as usize;
                        if len < 2 || len > opts.len() {
                            break;
                        }
                        opts = &opts[len..];
                    } else {
                        break;
                    }
                }
            }
        }

        Ok((
            IpHdr::from_v4(ip),
            PseudoHdr::new_v4(ip.header().source(), ip.header().destination(), proto),
        ))
    }

    fn parse_hdr_v6<'s>(
        ip: &'s Ipv6Slice<'s>,
        proto: IpProto,
    ) -> Result<(IpHdr<'s>, PseudoHdr), SegmentError> {
        let mut dst = ip.header().destination();

        for ext in ip.extensions().clone() {
            match ext {
                Ipv6ExtensionSlice::Authentication(_) => {
                    return Err(SegmentError::AuthenticationHeader);
                }
                Ipv6ExtensionSlice::Routing(routing) => {
                    let routing = routing.slice();
                    if routing.len() < 4 {
                        return Err(SegmentError::InvalidPacket);
                    }

                    if routing[3] > 0 {
                        let len = routing.len();
                        match routing[2] {
                            0 | 2 => {
                                if len < 24 {
                                    return Err(SegmentError::InvalidPacket);
                                }
                                dst.copy_from_slice(&routing[len - 16..]);
                            }
                            4 => {
                                if len < 24 {
                                    return Err(SegmentError::InvalidPacket);
                                }
                                dst.copy_from_slice(&routing[8..24]);
                            }
                            ty => return Err(SegmentError::UnsupportedRoutingHeader(ty)),
                        }
                    }
                }
                _ => {}
            }
        }

        Ok((
            IpHdr::from_v6(ip),
            PseudoHdr::new_v6(ip.header().source(), dst, proto),
        ))
    }

    /// Software-segment one GSO IP packet.
    ///
    /// `buf` is the buffer pool used to allocate memory for segmented packets.
    /// `vnet_hdr` is the virtio-net header.
    /// `packet` is the parsed IP packet slice.
    /// `proto` is the L4 protocol (TCP or UDP).
    ///
    /// Generated `ZCPacket`s are populated directly into `self.queue` with
    /// `self.margins` allocated from `buf`.
    pub fn segment<'s>(
        &mut self,
        buf: &mut BufPool,
        vnet_hdr: &VirtioNetHdr,
        packet: &'s SlicedPacket<'s>,
        proto: IpProto,
    ) -> Result<usize, SegmentError> {
        let mut gso_type = vnet_hdr.gso_type;
        let ecn = gso_type & VNET_HDR_GSO_ECN;
        gso_type &= !ecn;
        if ecn != 0 && gso_type == VNET_HDR_GSO_UDP_L4 {
            return Err(SegmentError::UnsupportedGsoType(vnet_hdr.gso_type));
        }

        let gso_size = vnet_hdr.gso_size as usize;
        if gso_size == 0 {
            return Err(SegmentError::InvalidGsoSize);
        }

        let net = packet.net.as_ref().ok_or(SegmentError::InvalidPacket)?;
        let transport = packet
            .transport
            .as_ref()
            .ok_or(SegmentError::InvalidPacket)?;

        let (ip_hdr, pseudo_hdr) = match net {
            NetSlice::Ipv4(ip) => Self::parse_hdr_v4(ip, proto)?,
            NetSlice::Ipv6(ip) => Self::parse_hdr_v6(ip, proto)?,
            _ => return Err(SegmentError::InvalidPacket),
        };

        match (gso_type, net, transport) {
            (VNET_HDR_GSO_TCPV4, NetSlice::Ipv4(_), TransportSlice::Tcp(tcp))
            | (VNET_HDR_GSO_TCPV6, NetSlice::Ipv6(_), TransportSlice::Tcp(tcp)) => {
                self.segment_tcp(buf, &ip_hdr, pseudo_hdr, tcp, gso_size)
            }
            (VNET_HDR_GSO_UDP_L4, _, TransportSlice::Udp(udp)) => {
                self.segment_udp(buf, &ip_hdr, pseudo_hdr, udp, gso_size)
            }
            (VNET_HDR_GSO_TCPV4 | VNET_HDR_GSO_TCPV6 | VNET_HDR_GSO_UDP_L4, _, _) => {
                Err(SegmentError::ProtocolMismatch)
            }
            _ => Err(SegmentError::UnsupportedGsoType(vnet_hdr.gso_type)),
        }
    }
}

enum PseudoHdr {
    V4([u8; 12]),
    V6([u8; 40]),
}

impl PseudoHdr {
    fn new_v4(src: [u8; 4], dst: [u8; 4], proto: IpProto) -> Self {
        let mut hdr = [0u8; 12];
        hdr[0..4].copy_from_slice(&src);
        hdr[4..8].copy_from_slice(&dst);
        hdr[8] = 0;
        hdr[9] = proto as _;
        Self::V4(hdr)
    }

    fn new_v6(src: [u8; 16], dst: [u8; 16], proto: IpProto) -> Self {
        let mut hdr = [0u8; 40];
        hdr[0..16].copy_from_slice(&src);
        hdr[16..32].copy_from_slice(&dst);
        hdr[39] = proto as _;
        Self::V6(hdr)
    }

    fn set_len(&mut self, len: u16) {
        match self {
            Self::V4(hdr) => hdr[10..12].copy_from_slice(&len.to_be_bytes()),
            Self::V6(hdr) => hdr[32..36].copy_from_slice(&(len as u32).to_be_bytes()),
        }
    }
}

impl AsRef<[u8]> for PseudoHdr {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::V4(hdr) => hdr,
            Self::V6(hdr) => hdr,
        }
    }
}

enum IpHdr<'s> {
    V4 { hdr: &'s [u8], df: bool, ident: u16 },
    V6 { hdr: &'s [u8], ext: &'s [u8] },
}

impl<'s> IpHdr<'s> {
    fn from_v4(ip: &'s Ipv4Slice<'s>) -> Self {
        let hdr = ip.header().slice();
        let df = (hdr[6] & 0x40) != 0;
        let ident = u16::from_be_bytes([hdr[4], hdr[5]]);
        Self::V4 { hdr, df, ident }
    }

    fn from_v6(ip: &'s Ipv6Slice<'s>) -> Self {
        Self::V6 {
            hdr: ip.header().slice(),
            ext: ip.extensions().slice(),
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::V4 { hdr, .. } => hdr.len(),
            Self::V6 { hdr, ext } => hdr.len() + ext.len(),
        }
    }

    fn write_header(&self, buf: &mut [u8], idx: usize, pkt_len: u16) {
        match self {
            Self::V4 { hdr, df, ident } => {
                let hdr_len = hdr.len();
                buf[..hdr_len].copy_from_slice(hdr);
                buf[2..4].copy_from_slice(&pkt_len.to_be_bytes());
                if !df {
                    buf[4..6].copy_from_slice(&ident.wrapping_add(idx as u16).to_be_bytes());
                }
                buf[10..12].copy_from_slice(&[0, 0]);
                let csum = internet_checksum::checksum(&buf[..hdr_len]);
                buf[10..12].copy_from_slice(&csum);
            }
            Self::V6 { hdr, ext } => {
                let hdr_len = hdr.len();
                buf[..hdr_len].copy_from_slice(hdr);
                buf[hdr_len..hdr_len + ext.len()].copy_from_slice(ext);
                buf[4..6].copy_from_slice(&(pkt_len - 40).to_be_bytes());
            }
        }
    }
}

impl Segmenter {
    fn segment_tcp(
        &mut self,
        buf: &mut BufPool,
        ip_hdr: &IpHdr,
        mut pseudo_hdr: PseudoHdr,
        tcp: &TcpSlice,
        seg_len: usize,
    ) -> Result<usize, SegmentError> {
        let payload = tcp.payload();
        let len = payload.len();
        if len == 0 {
            return Err(SegmentError::EmptyPayload);
        }

        let flags = tcp.slice()[13];
        if flags & (tcp_flags::SYN | tcp_flags::RST | tcp_flags::URG) != 0 {
            return Err(SegmentError::UnsupportedTcpFlags(flags));
        }

        let cwr = flags & tcp_flags::CWR;
        let psh = flags & tcp_flags::PSH;
        let fin = flags & tcp_flags::FIN;
        let flags = flags & !(tcp_flags::CWR | tcp_flags::PSH | tcp_flags::FIN);

        let seq = tcp.sequence_number();

        let ip_hdr_len = ip_hdr.len();
        let tcp_data_off = tcp.header_slice().len();
        let hdr_len = ip_hdr_len + tcp_data_off;

        let n = len.div_ceil(seg_len);
        for (idx, payload) in payload.chunks(seg_len).enumerate() {
            let last = idx == n - 1;
            let len = payload.len();
            let pkt_len =
                u16::try_from(hdr_len + len).map_err(|_| SegmentError::SegmentTooLarge)?;

            let mut writer = buf.writer(pkt_len as usize + self.margins.size(), self.margins);
            let slice = writer.as_slice();
            let buf = unsafe {
                std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, slice.len())
            };

            ip_hdr.write_header(buf, idx, pkt_len);
            buf[ip_hdr_len..hdr_len].copy_from_slice(tcp.header_slice());
            buf[hdr_len..hdr_len + len].copy_from_slice(payload);

            pseudo_hdr.set_len(
                u16::try_from(tcp_data_off + len).map_err(|_| SegmentError::SegmentTooLarge)?,
            );

            {
                let buf = &mut buf[ip_hdr_len..];

                buf[4..8].copy_from_slice(&seq.wrapping_add((idx * seg_len) as u32).to_be_bytes());

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                buf[13] = flags;
                buf[18..20].copy_from_slice(&[0, 0]);

                Self::write_segment_checksum(buf, &pseudo_hdr, IpProto::Tcp);
            }

            writer.commit(pkt_len as usize);
            let mut packet = writer.split();
            packet.truncate(packet.len() - self.margins.trailer);
            self.queue
                .push_back(ZCPacket::new_from_buf(packet, ZCPacketType::NIC));
        }

        Ok(n)
    }

    fn segment_udp(
        &mut self,
        buf: &mut BufPool,
        ip_hdr: &IpHdr,
        mut pseudo_hdr: PseudoHdr,
        udp: &UdpSlice,
        seg_len: usize,
    ) -> Result<usize, SegmentError> {
        let payload = udp.payload();
        let len = payload.len();
        if len == 0 {
            return Err(SegmentError::EmptyPayload);
        }

        let ip_hdr_len = ip_hdr.len();
        let hdr_len = ip_hdr_len + 8;

        let n = len.div_ceil(seg_len);
        for (idx, payload) in payload.chunks(seg_len).enumerate() {
            let len = payload.len();
            let pkt_len =
                u16::try_from(hdr_len + len).map_err(|_| SegmentError::SegmentTooLarge)?;

            let mut writer = buf.writer(pkt_len as usize + self.margins.size(), self.margins);
            let slice = writer.as_slice();
            let buf = unsafe {
                std::slice::from_raw_parts_mut(slice.as_mut_ptr() as *mut u8, slice.len())
            };

            ip_hdr.write_header(buf, idx, pkt_len);
            buf[ip_hdr_len..ip_hdr_len + 4].copy_from_slice(&udp.slice()[..4]);
            buf[hdr_len..hdr_len + len].copy_from_slice(payload);

            let udp_len = u16::try_from(8 + len).map_err(|_| SegmentError::SegmentTooLarge)?;
            pseudo_hdr.set_len(udp_len);

            {
                let buf = &mut buf[ip_hdr_len..];
                buf[4..6].copy_from_slice(&udp_len.to_be_bytes());
                Self::write_segment_checksum(buf, &pseudo_hdr, IpProto::Udp);
            }

            writer.commit(pkt_len as usize);
            let mut packet = writer.split();
            packet.truncate(packet.len() - self.margins.trailer);
            self.queue
                .push_back(ZCPacket::new_from_buf(packet, ZCPacketType::NIC));
        }

        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::packet::TAIL_RESERVED_SIZE;
    use zerocopy::AsBytes;

    fn test_margins() -> BufMargins {
        BufMargins {
            header: ZCPacketType::NIC.get_packet_offsets().payload_offset,
            trailer: TAIL_RESERVED_SIZE,
        }
    }

    fn make_packet(vnet_hdr: &VirtioNetHdr, ip_packet: &[u8]) -> (Vec<u8>, usize) {
        let vnet_hdr_off = test_margins().header - VNET_HDR_LEN;
        let mut buf = vec![0u8; test_margins().header + ip_packet.len()];
        buf[vnet_hdr_off..vnet_hdr_off + VNET_HDR_LEN].copy_from_slice(vnet_hdr.as_bytes());
        buf[test_margins().header..].copy_from_slice(ip_packet);
        (buf, vnet_hdr_off)
    }

    fn segment_raw(
        segmenter: &mut Segmenter,
        buf: &mut BufPool,
        packet: &[u8],
        vnet_hdr_off: usize,
    ) -> Result<usize, SegmentError> {
        let vnet_hdr = packet
            .get(vnet_hdr_off..)
            .and_then(VirtioNetHdr::ref_from_prefix)
            .ok_or(SegmentError::InvalidPacket)?;
        let sliced = SlicedPacket::from_ip(
            packet
                .get(segmenter.margins.header..)
                .ok_or(SegmentError::InvalidPacket)?,
        )
        .map_err(|_| SegmentError::InvalidPacket)?;
        let proto = match sliced.transport {
            Some(TransportSlice::Tcp(_)) => IpProto::Tcp,
            Some(TransportSlice::Udp(_)) => IpProto::Udp,
            _ => return Err(SegmentError::InvalidProtocol),
        };
        segmenter.segment(buf, vnet_hdr, &sliced, proto)
    }

    fn build_tcp4_packet(payload_len: usize, opts: &[u8]) -> Vec<u8> {
        let ip_hdr_len = 20 + opts.len();
        let total_len = ip_hdr_len + 20 + payload_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x40 | ((ip_hdr_len / 4) as u8);
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&1234u16.to_be_bytes());
        pkt[6] = 0x40;
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[12..16].copy_from_slice(&[192, 168, 1, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 2]);
        pkt[20..20 + opts.len()].copy_from_slice(opts);
        let ip_csum = internet_checksum::checksum(&pkt[..ip_hdr_len]);
        pkt[10..12].copy_from_slice(&ip_csum);

        let tcp = &mut pkt[ip_hdr_len..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].fill(0xAB);
        pkt
    }

    fn build_tcp6_routing_packet(routing_type: u8, segments_left: u8) -> Vec<u8> {
        let total_len = 40 + 24 + 20 + 3000;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(3044u16).to_be_bytes());
        pkt[6] = 43; // Routing header
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        pkt[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        pkt[40] = 6;
        pkt[41] = 2;
        pkt[42] = routing_type;
        pkt[43] = segments_left;
        pkt[48..64].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);

        let tcp = &mut pkt[64..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&2000u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].fill(0xCD);
        pkt
    }

    fn vnet_hdr(gso_type: u8, gso_size: u16) -> VirtioNetHdr {
        VirtioNetHdr {
            gso_type,
            gso_size,
            ..Default::default()
        }
    }

    #[test]
    fn test_segmenter_rejects_unsupported() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        // TCP SYN, RST, URG flags
        let hdr = vnet_hdr(VNET_HDR_GSO_TCPV4, 1460);
        for bad_flag in [tcp_flags::SYN, tcp_flags::RST, tcp_flags::URG] {
            let mut ip_packet = build_tcp4_packet(3000, &[]);
            ip_packet[33] |= bad_flag;
            let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
            assert!(matches!(
                segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
                Err(SegmentError::UnsupportedTcpFlags(flags)) if flags & bad_flag != 0
            ));
        }

        // IPv4 source routing options (LSRR: 0x83, SSRR: 0x89)
        for opt_kind in [0x83, 0x89] {
            let ip_packet = build_tcp4_packet(3000, &[opt_kind, 3, 4, 0x00]);
            let (packet, vnet_hdr_off) = make_packet(&hdr, &ip_packet);
            assert_eq!(
                segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
                Err(SegmentError::SourceRouting)
            );
        }

        // IPv6 active unknown routing header (type 99, segments_left = 1)
        let ip_packet = build_tcp6_routing_packet(99, 1);
        let hdr6 = vnet_hdr(VNET_HDR_GSO_TCPV6, 1000);
        let (packet, vnet_hdr_off) = make_packet(&hdr6, &ip_packet);
        assert_eq!(
            segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
            Err(SegmentError::UnsupportedRoutingHeader(99))
        );
    }

    #[test]
    fn test_segmenter_tcp4() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let (packet, vnet_hdr_off) = make_packet(
            &vnet_hdr(VNET_HDR_GSO_TCPV4, 1460),
            &build_tcp4_packet(3000, &[]),
        );
        assert_eq!(
            segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
            Ok(3)
        );

        for (seq, len, psh) in [(1000, 1460, false), (2460, 1460, false), (3920, 80, true)] {
            let seg = segmenter.pop().unwrap();
            let parsed = SlicedPacket::from_ip(seg.payload()).unwrap();
            let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
                panic!()
            };
            assert_eq!(tcp.sequence_number(), seq);
            assert_eq!(tcp.payload().len(), len);
            assert_eq!(tcp.slice()[13] & tcp_flags::PSH != 0, psh);
        }
        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_tcp6() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let mut ip_packet = vec![0u8; 40 + 20 + 3000];
        ip_packet[0] = 0x60;
        ip_packet[4..6].copy_from_slice(&(3020u16).to_be_bytes());
        ip_packet[6] = 6;
        ip_packet[7] = 64;
        ip_packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip_packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let tcp = &mut ip_packet[40..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&2000u32.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].fill(0xCD);

        let (packet, vnet_hdr_off) = make_packet(&vnet_hdr(VNET_HDR_GSO_TCPV6, 1440), &ip_packet);
        assert_eq!(
            segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
            Ok(3)
        );

        for (seq, len, psh) in [(2000, 1440, false), (3440, 1440, false), (4880, 120, true)] {
            let seg = segmenter.pop().unwrap();
            let parsed = SlicedPacket::from_ip(seg.payload()).unwrap();
            let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
                panic!()
            };
            assert_eq!(tcp.sequence_number(), seq);
            assert_eq!(tcp.payload().len(), len);
            assert_eq!(tcp.slice()[13] & tcp_flags::PSH != 0, psh);
        }
        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_udp4() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let total_len = 20 + 8 + 3000u16;
        let mut ip_packet = vec![0u8; total_len as usize];
        ip_packet[0] = 0x45;
        ip_packet[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip_packet[8] = 64;
        ip_packet[9] = 17;
        ip_packet[12..20].copy_from_slice(&[192, 168, 1, 1, 192, 168, 1, 2]);
        let ip_csum = internet_checksum::checksum(&ip_packet[..20]);
        ip_packet[10..12].copy_from_slice(&ip_csum);

        let udp = &mut ip_packet[20..];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        udp[4..6].copy_from_slice(&3008u16.to_be_bytes());
        udp[8..].fill(0xAB);

        let (packet, vnet_hdr_off) = make_packet(&vnet_hdr(VNET_HDR_GSO_UDP_L4, 1200), &ip_packet);
        assert_eq!(
            segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
            Ok(3)
        );

        for len in [1200, 1200, 600] {
            let seg = segmenter.pop().unwrap();
            let parsed = SlicedPacket::from_ip(seg.payload()).unwrap();
            let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
                panic!()
            };
            assert_eq!(udp.payload().len(), len);
        }
        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_udp6() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let mut ip_packet = vec![0u8; 40 + 8 + 8 + 2000];
        ip_packet[0] = 0x60;
        ip_packet[4..6].copy_from_slice(&(2016u16).to_be_bytes());
        ip_packet[6] = 60; // Destination Options
        ip_packet[7] = 64;
        ip_packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        ip_packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        ip_packet[40] = 17; // Next: UDP
        ip_packet[41] = 0;

        let udp = &mut ip_packet[48..];
        udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        udp[2..4].copy_from_slice(&80u16.to_be_bytes());
        udp[4..6].copy_from_slice(&2008u16.to_be_bytes());
        udp[8..].fill(0xEF);

        let (packet, vnet_hdr_off) = make_packet(&vnet_hdr(VNET_HDR_GSO_UDP_L4, 1000), &ip_packet);
        assert_eq!(
            segment_raw(&mut segmenter, &mut pool, &packet, vnet_hdr_off),
            Ok(2)
        );

        while let Some(seg) = segmenter.pop() {
            let parsed = SlicedPacket::from_ip(seg.payload()).unwrap();
            let NetSlice::Ipv6(ip) = parsed.net.unwrap() else {
                panic!()
            };
            assert_eq!(ip.extensions().slice(), &ip_packet[40..48]);
            let TransportSlice::Udp(udp) = parsed.transport.unwrap() else {
                panic!()
            };
            assert_eq!(udp.payload().len(), 1000);
        }
    }

    #[test]
    fn test_segmenter_push_not_gso_tcp() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let mut hdr = vnet_hdr(VNET_HDR_GSO_NONE, 0);
        hdr.flags = VNET_HDR_F_NEEDS_CSUM;
        hdr.csum_start = 20;
        hdr.csum_offset = 16;
        let (raw, vnet_hdr_off) = make_packet(&hdr, &build_tcp4_packet(100, &[]));

        segmenter.push(&mut pool, BytesMut::from(&raw[..]), vnet_hdr_off);

        let popped = segmenter.pop().expect("should pop non-GSO packet");
        let parsed = SlicedPacket::from_ip(popped.payload()).unwrap();
        let TransportSlice::Tcp(tcp) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_ne!(tcp.checksum(), 0);
        assert!(segmenter.pop().is_none());
    }

    #[test]
    fn test_segmenter_write_vnet_checksum_udp_vs_tcp_zero() {
        let test_csum = |proto, csum_offset, expected| {
            let hdr = VirtioNetHdr {
                flags: VNET_HDR_F_NEEDS_CSUM,
                csum_start: 20,
                csum_offset,
                ..Default::default()
            };
            let mut packet = vec![0u8; 20 + csum_offset as usize + 2];
            packet[20..22].copy_from_slice(&[0xff, 0xff]);
            Segmenter::write_vnet_checksum(&mut packet, &hdr, proto);
            assert_eq!(
                &packet[20 + csum_offset as usize..20 + csum_offset as usize + 2],
                expected
            );
        };

        // UDP converts [0, 0] to [0xff, 0xff]
        test_csum(IpProto::Udp, 6, &[0xff, 0xff]);
        // TCP keeps [0, 0]
        test_csum(IpProto::Tcp, 16, &[0x00, 0x00]);
    }

    #[test]
    fn test_segmenter_push_unsupported_or_invalid() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        // 1. Packet shorter than vnet_hdr_off + VNET_HDR_LEN
        let (raw, _) = make_packet(&VirtioNetHdr::default(), &[1, 2, 3]);
        segmenter.push(&mut pool, BytesMut::from(&raw[..]), raw.len() + 10);
        assert_eq!(segmenter.pop().unwrap().payload(), &[1, 2, 3]);

        // 2. Packet with valid vnet_hdr, but invalid IP bytes
        let (raw, vnet_hdr_off) = make_packet(&VirtioNetHdr::default(), &[0x00; 20]);
        segmenter.push(&mut pool, BytesMut::from(&raw[..]), vnet_hdr_off);
        assert_eq!(segmenter.pop().unwrap().payload(), &[0x00; 20]);

        // 3. ICMP packet with NEEDS_CSUM flag should be pushed directly without checksum computation
        let mut icmp_packet = vec![0u8; 28];
        icmp_packet[0] = 0x45;
        icmp_packet[2..4].copy_from_slice(&28u16.to_be_bytes());
        icmp_packet[8] = 64;
        icmp_packet[9] = 1; // ICMP
        icmp_packet[12..20].copy_from_slice(&[192, 168, 1, 1, 192, 168, 1, 2]);
        let mut hdr = vnet_hdr(VNET_HDR_GSO_NONE, 0);
        hdr.flags = VNET_HDR_F_NEEDS_CSUM;
        hdr.csum_start = 20;
        hdr.csum_offset = 2;
        let (raw, vnet_hdr_off) = make_packet(&hdr, &icmp_packet);
        segmenter.push(&mut pool, BytesMut::from(&raw[..]), vnet_hdr_off);
        assert_eq!(segmenter.pop().unwrap().payload(), &icmp_packet[..]);
    }

    #[test]
    fn test_segmenter_push_gso_tcp() {
        let mut segmenter = Segmenter::new(test_margins());
        let mut pool = BufPool::new(1 << 20);

        let (packet, vnet_hdr_off) = make_packet(
            &vnet_hdr(VNET_HDR_GSO_TCPV4, 1460),
            &build_tcp4_packet(3000, &[]),
        );
        segmenter.push(&mut pool, BytesMut::from(&packet[..]), vnet_hdr_off);

        assert_eq!(segmenter.queue.len(), 3);
        assert_eq!(segmenter.pop().unwrap().payload().len(), 1500);
        assert_eq!(segmenter.pop().unwrap().payload().len(), 1500);
        assert_eq!(segmenter.pop().unwrap().payload().len(), 40 + 80);
        assert!(segmenter.pop().is_none());
    }
}

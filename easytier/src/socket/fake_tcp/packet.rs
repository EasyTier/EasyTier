use bytes::{Bytes, BytesMut};
use smoltcp::wire::{
    ETHERNET_HEADER_LEN, EthernetAddress, EthernetFrame, EthernetProtocol, IpAddress, IpProtocol,
    Ipv4Packet, Ipv6Packet, TCP_HEADER_LEN, TcpPacket, TcpSeqNumber,
};
use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{IPV4_HEADER_LEN, IPV6_HEADER_LEN};

pub type MacAddr = EthernetAddress;

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

#[derive(Debug)]
pub enum IPPacket<'p> {
    V4(Ipv4Packet<&'p [u8]>),
    V6(Ipv6Packet<&'p [u8]>),
}

impl IPPacket<'_> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.src_addr()),
            IPPacket::V6(p) => IpAddr::V6(p.src_addr()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.dst_addr()),
            IPPacket::V6(p) => IpAddr::V6(p.dst_addr()),
        }
    }
}

fn set_tcp_flags<T: AsRef<[u8]> + AsMut<[u8]>>(tcp: &mut TcpPacket<T>, flags: u8) {
    tcp.set_fin(flags & TCP_FLAG_FIN != 0);
    tcp.set_syn(flags & TCP_FLAG_SYN != 0);
    tcp.set_rst(flags & TCP_FLAG_RST != 0);
    tcp.set_psh(flags & TCP_FLAG_PSH != 0);
    tcp.set_ack(flags & TCP_FLAG_ACK != 0);
    tcp.set_urg(flags & TCP_FLAG_URG != 0);
    tcp.set_ece(flags & TCP_FLAG_ECE != 0);
    tcp.set_cwr(flags & TCP_FLAG_CWR != 0);
}

#[cfg(test)]
pub fn tcp_flags<T: AsRef<[u8]>>(tcp: &TcpPacket<T>) -> u8 {
    u8::from(tcp.fin())
        | (u8::from(tcp.syn()) << 1)
        | (u8::from(tcp.rst()) << 2)
        | (u8::from(tcp.psh()) << 3)
        | (u8::from(tcp.ack()) << 4)
        | (u8::from(tcp.urg()) << 5)
        | (u8::from(tcp.ece()) << 6)
        | (u8::from(tcp.cwr()) << 7)
}

#[allow(clippy::too_many_arguments)]
pub fn build_tcp_packet(
    src_mac: MacAddr,
    dst_mac: MacAddr,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: Option<&[u8]>,
) -> Bytes {
    let ip_header_len = match local_addr {
        SocketAddr::V4(_) => IPV4_HEADER_LEN,
        SocketAddr::V6(_) => IPV6_HEADER_LEN,
    };
    let wscale = flags & TCP_FLAG_SYN != 0;
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
    let tcp_total_len = tcp_header_len + payload.map_or(0, |payload| payload.len());
    let total_len = ip_header_len + tcp_total_len;
    let mut buf = BytesMut::zeroed(ETHERNET_HEADER_LEN + total_len);

    let mut eth_buf = buf.split_to(ETHERNET_HEADER_LEN);
    let mut ip_buf = buf.split_to(ip_header_len);
    let mut tcp_buf = buf.split_to(tcp_total_len);
    assert_eq!(0, buf.len());

    let mut tcp = TcpPacket::new_unchecked(&mut tcp_buf);
    tcp.set_window_len(0xffff);
    tcp.set_src_port(local_addr.port());
    tcp.set_dst_port(remote_addr.port());
    tcp.set_seq_number(TcpSeqNumber(seq as i32));
    tcp.set_ack_number(TcpSeqNumber(ack as i32));
    set_tcp_flags(&mut tcp, flags);
    tcp.set_header_len(tcp_header_len as u8);
    if wscale {
        tcp.options_mut().copy_from_slice(&[1, 3, 3, 14]);
    }

    if let Some(payload) = payload {
        tcp.payload_mut().copy_from_slice(payload);
    }

    let mut ethernet = EthernetFrame::new_unchecked(&mut eth_buf);
    ethernet.set_dst_addr(dst_mac);
    ethernet.set_src_addr(src_mac);
    ethernet.set_ethertype(match local_addr {
        SocketAddr::V4(_) => EthernetProtocol::Ipv4,
        SocketAddr::V6(_) => EthernetProtocol::Ipv6,
    });

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 = Ipv4Packet::new_unchecked(&mut ip_buf);
            v4.set_version(4);
            v4.set_header_len(IPV4_HEADER_LEN as u8);
            v4.set_next_header(IpProtocol::Tcp);
            v4.set_hop_limit(64);
            v4.set_src_addr(*local.ip());
            v4.set_dst_addr(*remote.ip());
            v4.set_total_len(total_len.try_into().unwrap());
            v4.set_dont_frag(true);

            tcp.fill_checksum(
                &IpAddress::Ipv4(*local.ip()),
                &IpAddress::Ipv4(*remote.ip()),
            );
            v4.fill_checksum();
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let mut v6 = Ipv6Packet::new_unchecked(&mut ip_buf);
            v6.set_version(6);
            v6.set_payload_len(tcp_total_len.try_into().unwrap());
            v6.set_next_header(IpProtocol::Tcp);
            v6.set_hop_limit(64);
            v6.set_src_addr(*local.ip());
            v6.set_dst_addr(*remote.ip());

            tcp.fill_checksum(
                &IpAddress::Ipv6(*local.ip()),
                &IpAddress::Ipv6(*remote.ip()),
            );
        }
        _ => unreachable!(),
    };

    ip_buf.unsplit(tcp_buf);
    eth_buf.unsplit(ip_buf);
    eth_buf.freeze()
}

pub fn parse_ip_packet(buf: &Bytes) -> Option<(MacAddr, MacAddr, IPPacket<'_>, TcpPacket<&[u8]>)> {
    let eth = EthernetFrame::new_checked(buf.as_ref()).ok()?;
    let src_mac = eth.src_addr();
    let dst_mac = eth.dst_addr();
    let ethertype = eth.ethertype();

    tracing::trace!("Parsing IP packet: {:?}", eth);

    let ip_payload = eth.payload();

    match ethertype {
        EthernetProtocol::Ipv4 => {
            let v4 = Ipv4Packet::new_checked(ip_payload).ok()?;
            if usize::from(v4.header_len()) < IPV4_HEADER_LEN {
                return None;
            }
            if v4.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(v4.payload()).ok()?;
            Some((src_mac, dst_mac, IPPacket::V4(v4), tcp))
        }
        EthernetProtocol::Ipv6 => {
            let v6 = Ipv6Packet::new_checked(ip_payload).ok()?;
            if v6.next_header() != IpProtocol::Tcp {
                return None;
            }
            let tcp = TcpPacket::new_checked(v6.payload()).ok()?;
            Some((src_mac, dst_mac, IPPacket::V6(v6), tcp))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_packet_round_trip() {
        let src_mac = MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 1]);
        let dst_mac = MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 2]);
        let local_addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
        let remote_addr: SocketAddr = "198.51.100.2:23456".parse().unwrap();
        let payload = b"hello fake tcp";

        let packet = build_tcp_packet(
            src_mac,
            dst_mac,
            local_addr,
            remote_addr,
            10,
            20,
            TCP_FLAG_ACK,
            Some(payload),
        );

        let (parsed_src_mac, parsed_dst_mac, ip_packet, tcp_packet) =
            parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed_src_mac, src_mac);
        assert_eq!(parsed_dst_mac, dst_mac);
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.src_port(), local_addr.port());
        assert_eq!(tcp_packet.dst_port(), remote_addr.port());
        assert_eq!(tcp_packet.payload(), payload);
    }

    #[test]
    fn build_and_parse_ipv6_packet_round_trip() {
        let src_mac = MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 3]);
        let dst_mac = MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 4]);
        let local_addr: SocketAddr = "[2001:db8::1]:12345".parse().unwrap();
        let remote_addr: SocketAddr = "[2001:db8::2]:23456".parse().unwrap();
        let payload = b"ipv6 payload";

        let packet = build_tcp_packet(
            src_mac,
            dst_mac,
            local_addr,
            remote_addr,
            30,
            40,
            TCP_FLAG_ACK,
            Some(payload),
        );

        let ethernet = EthernetFrame::new_checked(packet.as_ref()).unwrap();
        assert_eq!(ethernet.ethertype(), EthernetProtocol::Ipv6);

        let (parsed_src_mac, parsed_dst_mac, ip_packet, tcp_packet) =
            parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed_src_mac, src_mac);
        assert_eq!(parsed_dst_mac, dst_mac);
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.src_port(), local_addr.port());
        assert_eq!(tcp_packet.dst_port(), remote_addr.port());
        assert_eq!(tcp_packet.payload(), payload);
    }

    #[test]
    fn parse_rejects_short_ethernet_frame() {
        let packet = Bytes::from_static(&[0u8; ETHERNET_HEADER_LEN - 1]);
        assert!(parse_ip_packet(&packet).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ipv4_tcp_packet() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 5]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 6]),
            "192.0.2.10:1111".parse().unwrap(),
            "198.51.100.20:2222".parse().unwrap(),
            1,
            2,
            TCP_FLAG_ACK,
            None,
        );
        let truncated =
            Bytes::copy_from_slice(&packet[..ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + 10]);

        assert!(parse_ip_packet(&truncated).is_none());
    }

    #[test]
    fn parse_rejects_ipv4_header_shorter_than_minimum() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 5]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 6]),
            "192.0.2.10:1111".parse().unwrap(),
            "198.51.100.20:2222".parse().unwrap(),
            1,
            0x5000_0000,
            TCP_FLAG_ACK,
            None,
        );
        let mut malformed = BytesMut::from(packet.as_ref());
        Ipv4Packet::new_unchecked(&mut malformed[ETHERNET_HEADER_LEN..])
            .set_header_len((IPV4_HEADER_LEN - 4) as u8);
        let malformed = malformed.freeze();

        assert!(parse_ip_packet(&malformed).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ipv6_header() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 7]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 8]),
            "[2001:db8::10]:1111".parse().unwrap(),
            "[2001:db8::20]:2222".parse().unwrap(),
            1,
            2,
            TCP_FLAG_ACK,
            None,
        );
        let truncated =
            Bytes::copy_from_slice(&packet[..ETHERNET_HEADER_LEN + IPV6_HEADER_LEN - 1]);

        assert!(parse_ip_packet(&truncated).is_none());
    }

    #[test]
    fn syn_packet_preserves_wire_format_and_unsigned_sequence() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 1]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 2]),
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
            0x8000_0001,
            0xffff_fffe,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            None,
        );

        assert_eq!(
            &packet[..ETHERNET_HEADER_LEN],
            &[0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1, 0x08, 0x00]
        );
        let (_, _, IPPacket::V4(ipv4), tcp) = parse_ip_packet(&packet).unwrap() else {
            panic!("expected IPv4 packet");
        };
        assert_eq!(ipv4.header_len(), IPV4_HEADER_LEN as u8);
        assert!(ipv4.dont_frag());
        assert_eq!(ipv4.hop_limit(), 64);
        assert!(ipv4.verify_checksum());
        assert_eq!(tcp.header_len(), (TCP_HEADER_LEN + 4) as u8);
        assert_eq!(tcp.options(), &[1, 3, 3, 14]);
        assert_eq!(tcp_flags(&tcp), TCP_FLAG_SYN | TCP_FLAG_ACK);
        assert_eq!(tcp.seq_number().0 as u32, 0x8000_0001);
        assert_eq!(tcp.ack_number().0 as u32, 0xffff_fffe);
        assert!(tcp.verify_checksum(
            &IpAddress::Ipv4(ipv4.src_addr()),
            &IpAddress::Ipv4(ipv4.dst_addr()),
        ));
    }

    #[test]
    fn ethernet_padding_is_not_tcp_payload() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 1]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 2]),
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
            1,
            2,
            TCP_FLAG_ACK,
            Some(b"payload"),
        );
        let mut padded = BytesMut::from(packet.as_ref());
        padded.extend_from_slice(&[0; 16]);
        let padded = padded.freeze();

        let (_, _, _, tcp) = parse_ip_packet(&padded).unwrap();
        assert_eq!(tcp.payload(), b"payload");
    }

    #[test]
    fn ipv4_options_do_not_shift_tcp_payload() {
        let packet = build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 1]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 2]),
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
            1,
            2,
            TCP_FLAG_ACK,
            Some(b"payload"),
        );
        let ip_start = ETHERNET_HEADER_LEN;
        let tcp_start = ip_start + IPV4_HEADER_LEN;
        let mut with_options = Vec::with_capacity(packet.len() + 4);
        with_options.extend_from_slice(&packet[..tcp_start]);
        with_options.extend_from_slice(&[1, 1, 1, 0]);
        with_options.extend_from_slice(&packet[tcp_start..]);
        {
            let total_len = with_options.len() - ip_start;
            let mut ipv4 = Ipv4Packet::new_unchecked(&mut with_options[ip_start..]);
            ipv4.set_header_len((IPV4_HEADER_LEN + 4) as u8);
            ipv4.set_total_len(total_len as u16);
            ipv4.fill_checksum();
        }
        let with_options = Bytes::from(with_options);

        let (_, _, IPPacket::V4(ipv4), tcp) = parse_ip_packet(&with_options).unwrap() else {
            panic!("expected IPv4 packet");
        };
        assert_eq!(ipv4.header_len(), (IPV4_HEADER_LEN + 4) as u8);
        assert_eq!(tcp.payload(), b"payload");
    }
}

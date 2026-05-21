use bytes::{Bytes, BytesMut};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::{ip, ipv4, ipv6, tcp};
use pnet::util::MacAddr;
use std::convert::TryInto;
use std::net::{IpAddr, SocketAddr};

const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_HEADER_LEN: usize = 20;
pub const MAX_PACKET_LEN: usize = 1500;

#[derive(Debug)]
pub enum IPPacket<'p> {
    V4(ipv4::Ipv4Packet<'p>),
    V6(ipv6::Ipv6Packet<'p>),
}

impl IPPacket<'_> {
    pub fn get_source(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_source()),
            IPPacket::V6(p) => IpAddr::V6(p.get_source()),
        }
    }

    pub fn get_destination(&self) -> IpAddr {
        match self {
            IPPacket::V4(p) => IpAddr::V4(p.get_destination()),
            IPPacket::V6(p) => IpAddr::V6(p.get_destination()),
        }
    }
}

const ETH_HDR_LEN: usize = 14;

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
    let wscale = (flags & tcp::TcpFlags::SYN) != 0;
    let tcp_header_len = TCP_HEADER_LEN + if wscale { 4 } else { 0 }; // nop + wscale
    let tcp_total_len = tcp_header_len + payload.map_or(0, |payload| payload.len());
    let total_len = ip_header_len + tcp_total_len;
    let mut buf = BytesMut::zeroed(ETH_HDR_LEN + total_len);

    let mut eth_buf = buf.split_to(ETH_HDR_LEN);
    let mut ip_buf = buf.split_to(ip_header_len);
    let mut tcp_buf = buf.split_to(tcp_total_len);
    assert_eq!(0, buf.len());

    let mut tcp = tcp::MutableTcpPacket::new(&mut tcp_buf).unwrap();
    tcp.set_window(0xffff);
    tcp.set_source(local_addr.port());
    tcp.set_destination(remote_addr.port());
    tcp.set_sequence(seq);
    tcp.set_acknowledgement(ack);
    tcp.set_flags(flags);
    tcp.set_data_offset(TCP_HEADER_LEN as u8 / 4 + if wscale { 1 } else { 0 });
    if wscale {
        let wscale = tcp::TcpOption::wscale(14);
        tcp.set_options(&[tcp::TcpOption::nop(), wscale]);
    }

    if let Some(payload) = payload {
        tcp.set_payload(payload);
    }

    let mut ethernet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    ethernet.set_destination(dst_mac);
    ethernet.set_source(src_mac);
    ethernet.set_ethertype(match local_addr {
        SocketAddr::V4(_) => EtherTypes::Ipv4,
        SocketAddr::V6(_) => EtherTypes::Ipv6,
    });

    match (local_addr, remote_addr) {
        (SocketAddr::V4(local), SocketAddr::V4(remote)) => {
            let mut v4 = ipv4::MutableIpv4Packet::new(&mut ip_buf).unwrap();
            v4.set_version(4);
            v4.set_header_length(IPV4_HEADER_LEN as u8 / 4);
            v4.set_next_level_protocol(ip::IpNextHeaderProtocols::Tcp);
            v4.set_ttl(64);
            v4.set_source(*local.ip());
            v4.set_destination(*remote.ip());
            v4.set_total_length(total_len.try_into().unwrap());
            v4.set_flags(ipv4::Ipv4Flags::DontFragment);

            tcp.set_checksum(tcp::ipv4_checksum(
                &tcp.to_immutable(),
                &v4.get_source(),
                &v4.get_destination(),
            ));

            v4.set_checksum(ipv4::checksum(&v4.to_immutable()));
        }
        (SocketAddr::V6(local), SocketAddr::V6(remote)) => {
            let mut v6 = ipv6::MutableIpv6Packet::new(&mut ip_buf).unwrap();
            v6.set_version(6);
            v6.set_payload_length(tcp_total_len.try_into().unwrap());
            v6.set_next_header(ip::IpNextHeaderProtocols::Tcp);
            v6.set_hop_limit(64);
            v6.set_source(*local.ip());
            v6.set_destination(*remote.ip());

            tcp.set_checksum(tcp::ipv6_checksum(
                &tcp.to_immutable(),
                &v6.get_source(),
                &v6.get_destination(),
            ));
        }
        _ => unreachable!(),
    };

    ip_buf.unsplit(tcp_buf);
    eth_buf.unsplit(ip_buf);
    eth_buf.freeze()
}

pub fn parse_ip_packet(
    buf: &Bytes,
) -> Option<(MacAddr, MacAddr, IPPacket<'_>, tcp::TcpPacket<'_>)> {
    let eth = EthernetPacket::new(buf.as_ref())?;
    let src_mac = eth.get_source();
    let dst_mac = eth.get_destination();
    let ethertype = eth.get_ethertype();

    tracing::trace!("Parsing IP packet: {:?}", eth);

    let ip_payload = &buf[ETH_HDR_LEN..];

    match ethertype {
        EtherTypes::Ipv4 => {
            let v4 = ipv4::Ipv4Packet::new(ip_payload)?;
            if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
                return None;
            }

            let tcp_offset = usize::from(v4.get_header_length()) * 4;
            if tcp_offset < IPV4_HEADER_LEN || tcp_offset > ip_payload.len() {
                return None;
            }

            let tcp = tcp::TcpPacket::new(&ip_payload[tcp_offset..])?;
            Some((src_mac, dst_mac, IPPacket::V4(v4), tcp))
        }
        EtherTypes::Ipv6 => {
            let v6 = ipv6::Ipv6Packet::new(ip_payload)?;
            if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
                return None;
            }

            let tcp = tcp::TcpPacket::new(&ip_payload[IPV6_HEADER_LEN..])?;
            Some((src_mac, dst_mac, IPPacket::V6(v6), tcp))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pnet::packet::Packet as _;

    #[test]
    fn parse_ipv4_packet_round_trip() {
        let src_mac = MacAddr::new(0x02, 0, 0, 0, 0, 1);
        let dst_mac = MacAddr::new(0x02, 0, 0, 0, 0, 2);
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
            tcp::TcpFlags::ACK,
            Some(payload),
        );

        let (parsed_src_mac, parsed_dst_mac, ip_packet, tcp_packet) =
            parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed_src_mac, src_mac);
        assert_eq!(parsed_dst_mac, dst_mac);
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.get_source(), local_addr.port());
        assert_eq!(tcp_packet.get_destination(), remote_addr.port());
        assert_eq!(tcp_packet.payload(), payload);
    }

    #[test]
    fn build_and_parse_ipv6_packet_round_trip() {
        let src_mac = MacAddr::new(0x02, 0, 0, 0, 0, 3);
        let dst_mac = MacAddr::new(0x02, 0, 0, 0, 0, 4);
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
            tcp::TcpFlags::ACK,
            Some(payload),
        );

        let ethernet = EthernetPacket::new(packet.as_ref()).unwrap();
        assert_eq!(ethernet.get_ethertype(), EtherTypes::Ipv6);

        let (parsed_src_mac, parsed_dst_mac, ip_packet, tcp_packet) =
            parse_ip_packet(&packet).unwrap();

        assert_eq!(parsed_src_mac, src_mac);
        assert_eq!(parsed_dst_mac, dst_mac);
        assert_eq!(ip_packet.get_source(), local_addr.ip());
        assert_eq!(ip_packet.get_destination(), remote_addr.ip());
        assert_eq!(tcp_packet.get_source(), local_addr.port());
        assert_eq!(tcp_packet.get_destination(), remote_addr.port());
        assert_eq!(tcp_packet.payload(), payload);
    }

    #[test]
    fn parse_rejects_short_ethernet_frame() {
        let packet = Bytes::from_static(&[0u8; ETH_HDR_LEN - 1]);
        assert!(parse_ip_packet(&packet).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ipv4_tcp_packet() {
        let packet = build_tcp_packet(
            MacAddr::new(0x02, 0, 0, 0, 0, 5),
            MacAddr::new(0x02, 0, 0, 0, 0, 6),
            "192.0.2.10:1111".parse().unwrap(),
            "198.51.100.20:2222".parse().unwrap(),
            1,
            2,
            tcp::TcpFlags::ACK,
            None,
        );
        let truncated = Bytes::copy_from_slice(&packet[..ETH_HDR_LEN + IPV4_HEADER_LEN + 10]);

        assert!(parse_ip_packet(&truncated).is_none());
    }

    #[test]
    fn parse_rejects_truncated_ipv6_header() {
        let packet = build_tcp_packet(
            MacAddr::new(0x02, 0, 0, 0, 0, 7),
            MacAddr::new(0x02, 0, 0, 0, 0, 8),
            "[2001:db8::10]:1111".parse().unwrap(),
            "[2001:db8::20]:2222".parse().unwrap(),
            1,
            2,
            tcp::TcpFlags::ACK,
            None,
        );
        let truncated = Bytes::copy_from_slice(&packet[..ETH_HDR_LEN + IPV6_HEADER_LEN - 1]);

        assert!(parse_ip_packet(&truncated).is_none());
    }
}

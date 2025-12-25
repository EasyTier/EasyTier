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
    ethernet.set_ethertype(EtherTypes::Ipv4);

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

#[tracing::instrument(ret)]
pub fn parse_ip_packet(
    buf: &Bytes,
) -> Option<(MacAddr, MacAddr, IPPacket<'_>, tcp::TcpPacket<'_>)> {
    let eth = EthernetPacket::new(buf).unwrap();
    let src_mac = eth.get_source();
    let dst_mac = eth.get_destination();

    tracing::trace!("Parsing IP packet: {:?}", eth);

    let buf = &buf[ETH_HDR_LEN..];
    if buf[0] >> 4 == 4 {
        let v4 = ipv4::Ipv4Packet::new(buf).unwrap();
        if v4.get_next_level_protocol() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV4_HEADER_LEN..]).unwrap();
        Some((src_mac, dst_mac, IPPacket::V4(v4), tcp))
    } else if buf[0] >> 4 == 6 {
        let v6 = ipv6::Ipv6Packet::new(buf).unwrap();
        if v6.get_next_header() != ip::IpNextHeaderProtocols::Tcp {
            return None;
        }

        let tcp = tcp::TcpPacket::new(&buf[IPV6_HEADER_LEN..]).unwrap();
        Some((src_mac, dst_mac, IPPacket::V6(v6), tcp))
    } else {
        tracing::trace!("Invalid IP version: {}", buf[0] >> 4);
        None
    }
}

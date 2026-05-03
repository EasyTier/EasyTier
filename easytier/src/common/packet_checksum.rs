use std::net::Ipv4Addr;

use pnet::packet::{
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::{self, MutableUdpPacket},
};

pub fn update_ip_packet_checksum(ip_packet: &mut MutableIpv4Packet) {
    ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
}

pub fn update_tcp_packet_checksum(
    tcp_packet: &mut MutableTcpPacket,
    ipv4_src: &Ipv4Addr,
    ipv4_dst: &Ipv4Addr,
) {
    tcp_packet.set_checksum(tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        ipv4_src,
        ipv4_dst,
    ));
}

pub fn update_udp_packet_checksum(
    udp_packet: &mut MutableUdpPacket,
    ipv4_src: &Ipv4Addr,
    ipv4_dst: &Ipv4Addr,
) {
    udp_packet.set_checksum(udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        ipv4_src,
        ipv4_dst,
    ));
}

pub fn update_udp_packet_checksum_if_present(
    udp_packet: &mut MutableUdpPacket,
    ipv4_src: &Ipv4Addr,
    ipv4_dst: &Ipv4Addr,
) {
    if udp_packet.get_checksum() != 0 {
        update_udp_packet_checksum(udp_packet, ipv4_src, ipv4_dst);
    }
}

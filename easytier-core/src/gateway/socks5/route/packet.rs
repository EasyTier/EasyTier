use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pnet_packet::{
    Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket,
};

use crate::{
    gateway::proxy::ip_reassembler::{IpReassembler, SmolIpv4Packet},
    packet::{PacketType, ZCPacket},
};

use super::super::entry_table::{Socks5Entry, Socks5EntryKind, Socks5EntryTable};

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClassifiedSocks5PeerPacket {
    Tcp {
        entry: Socks5Entry,
        listen_entry: Socks5Entry,
        flags: u8,
    },
    Udp {
        entry: Socks5Entry,
    },
    FragmentedUdp {
        source: Ipv4Addr,
    },
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Socks5PeerPacketRoute {
    Pass,
    Unmatched {
        entry: Socks5Entry,
        tcp_flags: Option<u8>,
    },
    Deliver {
        entry: Socks5Entry,
        tcp_flags: Option<u8>,
    },
    FragmentedUdp {
        source: Ipv4Addr,
        mirror: bool,
    },
}
fn classify_peer_ipv4_payload(payload: &[u8]) -> ClassifiedSocks5PeerPacket {
    let Some(ipv4) = Ipv4Packet::new(payload) else {
        return ClassifiedSocks5PeerPacket::Unsupported;
    };
    if ipv4.get_version() != 4 {
        return ClassifiedSocks5PeerPacket::Unsupported;
    }

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
                return ClassifiedSocks5PeerPacket::Unsupported;
            };
            let entry = Socks5Entry {
                dst: SocketAddr::new(ipv4.get_source().into(), tcp.get_source()),
                src: SocketAddr::new(ipv4.get_destination().into(), tcp.get_destination()),
                kind: Socks5EntryKind::Tcp,
            };
            let listen_entry = Socks5Entry {
                src: entry.src,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: Socks5EntryKind::TcpListen,
            };
            ClassifiedSocks5PeerPacket::Tcp {
                entry,
                listen_entry,
                flags: tcp.get_flags(),
            }
        }
        IpNextHeaderProtocols::Udp => {
            let smol_ipv4 = SmolIpv4Packet::new_unchecked(ipv4.packet());
            if IpReassembler::is_packet_fragmented(&smol_ipv4) {
                return ClassifiedSocks5PeerPacket::FragmentedUdp {
                    source: ipv4.get_source(),
                };
            }
            let Some(udp) = UdpPacket::new(ipv4.payload()) else {
                return ClassifiedSocks5PeerPacket::Unsupported;
            };
            ClassifiedSocks5PeerPacket::Udp {
                entry: Socks5Entry {
                    dst: SocketAddr::new(ipv4.get_source().into(), udp.get_source()),
                    src: SocketAddr::new(ipv4.get_destination().into(), udp.get_destination()),
                    kind: Socks5EntryKind::Udp,
                },
            }
        }
        _ => ClassifiedSocks5PeerPacket::Unsupported,
    }
}
impl<V> Socks5EntryTable<V> {
    pub fn route_peer_packet(
        &self,
        packet: &ZCPacket,
        allow_tcp_listen_fallback: bool,
    ) -> Socks5PeerPacketRoute {
        let Some(header) = packet.peer_manager_header() else {
            return Socks5PeerPacketRoute::Pass;
        };
        let is_modified_source = matches!(
            header.packet_type,
            x if x == PacketType::DataWithKcpSrcModified as u8
                || x == PacketType::DataWithQuicSrcModified as u8
        );
        if header.packet_type != PacketType::Data as u8 && !is_modified_source {
            return Socks5PeerPacketRoute::Pass;
        }
        if is_modified_source && header.from_peer_id != header.to_peer_id {
            return Socks5PeerPacketRoute::Pass;
        }

        self.route_peer_ipv4_payload(packet.payload(), allow_tcp_listen_fallback)
    }

    pub fn route_peer_ipv4_payload(
        &self,
        payload: &[u8],
        allow_tcp_listen_fallback: bool,
    ) -> Socks5PeerPacketRoute {
        let (entry, tcp_flags) = match classify_peer_ipv4_payload(payload) {
            ClassifiedSocks5PeerPacket::Tcp {
                entry,
                listen_entry,
                flags,
            } => {
                let entry = if allow_tcp_listen_fallback && !self.contains_key(&entry) {
                    listen_entry
                } else {
                    entry
                };
                (entry, Some(flags))
            }
            ClassifiedSocks5PeerPacket::Udp { entry } => (entry, None),
            ClassifiedSocks5PeerPacket::FragmentedUdp { source } => {
                return Socks5PeerPacketRoute::FragmentedUdp {
                    source,
                    mirror: self.contains_destination_ip(source.into()),
                };
            }
            ClassifiedSocks5PeerPacket::Unsupported => return Socks5PeerPacketRoute::Pass,
        };

        if self.contains_key(&entry) {
            Socks5PeerPacketRoute::Deliver { entry, tcp_flags }
        } else {
            Socks5PeerPacketRoute::Unmatched { entry, tcp_flags }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use pnet_packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags},
        udp::MutableUdpPacket,
    };

    use super::*;
    use crate::packet::{PacketType, ZCPacket};

    fn ipv4_packet(protocol: pnet_packet::ip::IpNextHeaderProtocol, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload_len];
        let packet_len = packet.len() as u16;
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        ipv4.set_version(4);
        ipv4.set_header_length(5);
        ipv4.set_total_length(packet_len);
        ipv4.set_source(Ipv4Addr::new(10, 1, 1, 2));
        ipv4.set_destination(Ipv4Addr::new(10, 2, 2, 3));
        ipv4.set_next_level_protocol(protocol);
        packet
    }
    #[test]
    fn classifies_tcp_and_listen_keys() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Tcp, 20);
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(4321);
        tcp.set_flags(TcpFlags::SYN);

        assert_eq!(
            classify_peer_ipv4_payload(&packet),
            ClassifiedSocks5PeerPacket::Tcp {
                entry: Socks5Entry {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: "10.1.1.2:1234".parse().unwrap(),
                    kind: Socks5EntryKind::Tcp,
                },
                listen_entry: Socks5Entry {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    kind: Socks5EntryKind::TcpListen,
                },
                flags: TcpFlags::SYN,
            }
        );
    }
    #[test]
    fn classifies_udp_and_fragmented_udp() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
        udp.set_source(1234);
        udp.set_destination(4321);
        assert_eq!(
            classify_peer_ipv4_payload(&packet),
            ClassifiedSocks5PeerPacket::Udp {
                entry: Socks5Entry {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: "10.1.1.2:1234".parse().unwrap(),
                    kind: Socks5EntryKind::Udp,
                }
            }
        );

        let mut fragmented = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        MutableIpv4Packet::new(&mut fragmented)
            .unwrap()
            .set_fragment_offset(1);
        assert_eq!(
            classify_peer_ipv4_payload(&fragmented),
            ClassifiedSocks5PeerPacket::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
            }
        );
    }
    #[test]
    fn rejects_malformed_and_unsupported_packets() {
        assert_eq!(
            classify_peer_ipv4_payload(&[]),
            ClassifiedSocks5PeerPacket::Unsupported
        );
        assert_eq!(
            classify_peer_ipv4_payload(&ipv4_packet(IpNextHeaderProtocols::Icmp, 8)),
            ClassifiedSocks5PeerPacket::Unsupported
        );
    }
    #[test]
    fn entry_table_routes_tcp_exact_and_listen_fallback() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Tcp, 20);
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(4321);
        tcp.set_flags(TcpFlags::SYN);

        let exact = Socks5Entry {
            src: "10.2.2.3:4321".parse().unwrap(),
            dst: "10.1.1.2:1234".parse().unwrap(),
            kind: Socks5EntryKind::Tcp,
        };
        let listen = Socks5Entry {
            src: exact.src,
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            kind: Socks5EntryKind::TcpListen,
        };
        let table = Socks5EntryTable::default();

        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            Socks5PeerPacketRoute::Unmatched {
                entry: exact.clone(),
                tcp_flags: Some(TcpFlags::SYN),
            }
        );

        table.insert(listen.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            Socks5PeerPacketRoute::Deliver {
                entry: listen,
                tcp_flags: Some(TcpFlags::SYN),
            }
        );

        table.insert(exact.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            Socks5PeerPacketRoute::Deliver {
                entry: exact,
                tcp_flags: Some(TcpFlags::SYN),
            }
        );
    }
    #[test]
    fn entry_table_routes_fragmented_udp_by_source_ip() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        MutableIpv4Packet::new(&mut packet)
            .unwrap()
            .set_fragment_offset(1);
        let table = Socks5EntryTable::default();

        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            Socks5PeerPacketRoute::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
                mirror: false,
            }
        );

        table.insert(
            Socks5Entry {
                src: "10.2.2.3:4321".parse().unwrap(),
                dst: "10.1.1.2:1234".parse().unwrap(),
                kind: Socks5EntryKind::Udp,
            },
            (),
        );
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            Socks5PeerPacketRoute::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
                mirror: true,
            }
        );
    }
    #[test]
    fn entry_table_routes_loopback_modified_source_packets() {
        let mut payload = ipv4_packet(IpNextHeaderProtocols::Tcp, 20);
        let mut ipv4 = MutableIpv4Packet::new(&mut payload).unwrap();
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(4321);
        let entry = Socks5Entry {
            src: "10.2.2.3:4321".parse().unwrap(),
            dst: "10.1.1.2:1234".parse().unwrap(),
            kind: Socks5EntryKind::Tcp,
        };
        let table = Socks5EntryTable::default();
        table.insert(entry.clone(), ());

        for packet_type in [
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(7, 7, packet_type as u8);
            assert_eq!(
                table.route_peer_packet(&packet, false),
                Socks5PeerPacketRoute::Deliver {
                    entry: entry.clone(),
                    tcp_flags: Some(0),
                }
            );
        }
    }
    #[test]
    fn entry_table_passes_non_loopback_or_malformed_modified_source_packets() {
        let table = Socks5EntryTable::<()>::default();
        let mut non_loopback =
            ZCPacket::new_with_payload(&ipv4_packet(IpNextHeaderProtocols::Tcp, 20));
        non_loopback.fill_peer_manager_hdr(7, 8, PacketType::DataWithKcpSrcModified as u8);
        assert_eq!(
            table.route_peer_packet(&non_loopback, false),
            Socks5PeerPacketRoute::Pass
        );

        let mut malformed = ZCPacket::new_with_payload(&[0u8; 8]);
        malformed.fill_peer_manager_hdr(7, 7, PacketType::DataWithQuicSrcModified as u8);
        assert_eq!(
            table.route_peer_packet(&malformed, false),
            Socks5PeerPacketRoute::Pass
        );
    }
}

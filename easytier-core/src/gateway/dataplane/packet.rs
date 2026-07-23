//! Peer-packet classification for registered data-plane flows.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use pnet_packet::{
    Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket,
};

use crate::{
    gateway::proxy::ip_reassembler::{IpReassembler, SmolIpv4Packet},
    packet::{PacketType, ZCPacket},
};

use super::flow::{FlowKey, FlowKind, FlowTable};

#[derive(Clone, Debug, Eq, PartialEq)]
enum ClassifiedPeerPacket {
    Tcp {
        entry: FlowKey,
        listen_entry: FlowKey,
        flags: u8,
    },
    Udp {
        entry: FlowKey,
    },
    FragmentedUdp {
        source: Ipv4Addr,
    },
    Unsupported,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PeerPacketRoute {
    Pass,
    Unmatched {
        entry: FlowKey,
        tcp_flags: Option<u8>,
    },
    Deliver {
        entry: FlowKey,
        tcp_flags: Option<u8>,
    },
    FragmentedUdp {
        source: Ipv4Addr,
        mirror: bool,
    },
}
fn classify_peer_ipv4_payload(payload: &[u8]) -> ClassifiedPeerPacket {
    let Some(ipv4) = Ipv4Packet::new(payload) else {
        return ClassifiedPeerPacket::Unsupported;
    };
    if ipv4.get_version() != 4 {
        return ClassifiedPeerPacket::Unsupported;
    }

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
                return ClassifiedPeerPacket::Unsupported;
            };
            let entry = FlowKey {
                dst: SocketAddr::new(ipv4.get_source().into(), tcp.get_source()),
                src: SocketAddr::new(ipv4.get_destination().into(), tcp.get_destination()),
                kind: FlowKind::Tcp,
            };
            let listen_entry = FlowKey {
                src: entry.src,
                dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                kind: FlowKind::TcpListen,
            };
            ClassifiedPeerPacket::Tcp {
                entry,
                listen_entry,
                flags: tcp.get_flags(),
            }
        }
        IpNextHeaderProtocols::Udp => {
            let smol_ipv4 = SmolIpv4Packet::new_unchecked(ipv4.packet());
            if IpReassembler::is_packet_fragmented(&smol_ipv4) {
                return ClassifiedPeerPacket::FragmentedUdp {
                    source: ipv4.get_source(),
                };
            }
            let Some(udp) = UdpPacket::new(ipv4.payload()) else {
                return ClassifiedPeerPacket::Unsupported;
            };
            ClassifiedPeerPacket::Udp {
                entry: FlowKey {
                    dst: SocketAddr::new(ipv4.get_source().into(), udp.get_source()),
                    src: SocketAddr::new(ipv4.get_destination().into(), udp.get_destination()),
                    kind: FlowKind::Udp,
                },
            }
        }
        _ => ClassifiedPeerPacket::Unsupported,
    }
}
impl<V> FlowTable<V> {
    pub fn route_peer_packet(
        &self,
        packet: &ZCPacket,
        allow_tcp_listen_fallback: bool,
    ) -> PeerPacketRoute {
        let Some(header) = packet.peer_manager_header() else {
            return PeerPacketRoute::Pass;
        };
        let is_modified_source = matches!(
            header.packet_type,
            x if x == PacketType::DataWithKcpSrcModified as u8
                || x == PacketType::DataWithQuicSrcModified as u8
        );
        if header.packet_type != PacketType::Data as u8 && !is_modified_source {
            return PeerPacketRoute::Pass;
        }
        if is_modified_source && header.from_peer_id != header.to_peer_id {
            return PeerPacketRoute::Pass;
        }

        self.route_peer_ipv4_payload(packet.payload(), allow_tcp_listen_fallback)
    }

    pub fn route_peer_ipv4_payload(
        &self,
        payload: &[u8],
        allow_tcp_listen_fallback: bool,
    ) -> PeerPacketRoute {
        let (entry, tcp_flags) = match classify_peer_ipv4_payload(payload) {
            ClassifiedPeerPacket::Tcp {
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
            ClassifiedPeerPacket::Udp { entry } => (entry, None),
            ClassifiedPeerPacket::FragmentedUdp { source } => {
                return PeerPacketRoute::FragmentedUdp {
                    source,
                    mirror: self.contains_destination_ip(source.into()),
                };
            }
            ClassifiedPeerPacket::Unsupported => return PeerPacketRoute::Pass,
        };

        if self.contains_key(&entry) {
            PeerPacketRoute::Deliver { entry, tcp_flags }
        } else {
            PeerPacketRoute::Unmatched { entry, tcp_flags }
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
            ClassifiedPeerPacket::Tcp {
                entry: FlowKey {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: "10.1.1.2:1234".parse().unwrap(),
                    kind: FlowKind::Tcp,
                },
                listen_entry: FlowKey {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    kind: FlowKind::TcpListen,
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
            ClassifiedPeerPacket::Udp {
                entry: FlowKey {
                    src: "10.2.2.3:4321".parse().unwrap(),
                    dst: "10.1.1.2:1234".parse().unwrap(),
                    kind: FlowKind::Udp,
                }
            }
        );

        let mut fragmented = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        MutableIpv4Packet::new(&mut fragmented)
            .unwrap()
            .set_fragment_offset(1);
        assert_eq!(
            classify_peer_ipv4_payload(&fragmented),
            ClassifiedPeerPacket::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
            }
        );
    }
    #[test]
    fn rejects_malformed_and_unsupported_packets() {
        assert_eq!(
            classify_peer_ipv4_payload(&[]),
            ClassifiedPeerPacket::Unsupported
        );
        assert_eq!(
            classify_peer_ipv4_payload(&ipv4_packet(IpNextHeaderProtocols::Icmp, 8)),
            ClassifiedPeerPacket::Unsupported
        );
    }
    #[test]
    fn flow_table_routes_tcp_exact_and_listen_fallback() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Tcp, 20);
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(4321);
        tcp.set_flags(TcpFlags::SYN);

        let exact = FlowKey {
            src: "10.2.2.3:4321".parse().unwrap(),
            dst: "10.1.1.2:1234".parse().unwrap(),
            kind: FlowKind::Tcp,
        };
        let listen = FlowKey {
            src: exact.src,
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            kind: FlowKind::TcpListen,
        };
        let table = FlowTable::default();

        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            PeerPacketRoute::Unmatched {
                entry: exact.clone(),
                tcp_flags: Some(TcpFlags::SYN),
            }
        );

        table.insert(listen.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            PeerPacketRoute::Deliver {
                entry: listen,
                tcp_flags: Some(TcpFlags::SYN),
            }
        );

        table.insert(exact.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            PeerPacketRoute::Deliver {
                entry: exact,
                tcp_flags: Some(TcpFlags::SYN),
            }
        );
    }
    #[test]
    fn flow_table_routes_fragmented_udp_by_source_ip() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        MutableIpv4Packet::new(&mut packet)
            .unwrap()
            .set_fragment_offset(1);
        let table = FlowTable::default();

        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            PeerPacketRoute::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
                mirror: false,
            }
        );

        table.insert(
            FlowKey {
                src: "10.2.2.3:4321".parse().unwrap(),
                dst: "10.1.1.2:1234".parse().unwrap(),
                kind: FlowKind::Udp,
            },
            (),
        );
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, false),
            PeerPacketRoute::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
                mirror: true,
            }
        );
    }
    #[test]
    fn flow_table_routes_loopback_modified_source_packets() {
        let mut payload = ipv4_packet(IpNextHeaderProtocols::Tcp, 20);
        let mut ipv4 = MutableIpv4Packet::new(&mut payload).unwrap();
        let mut tcp = MutableTcpPacket::new(ipv4.payload_mut()).unwrap();
        tcp.set_source(1234);
        tcp.set_destination(4321);
        let entry = FlowKey {
            src: "10.2.2.3:4321".parse().unwrap(),
            dst: "10.1.1.2:1234".parse().unwrap(),
            kind: FlowKind::Tcp,
        };
        let table = FlowTable::default();
        table.insert(entry.clone(), ());

        for packet_type in [
            PacketType::DataWithKcpSrcModified,
            PacketType::DataWithQuicSrcModified,
        ] {
            let mut packet = ZCPacket::new_with_payload(&payload);
            packet.fill_peer_manager_hdr(7, 7, packet_type as u8);
            assert_eq!(
                table.route_peer_packet(&packet, false),
                PeerPacketRoute::Deliver {
                    entry: entry.clone(),
                    tcp_flags: Some(0),
                }
            );
        }
    }
    #[test]
    fn flow_table_passes_non_loopback_or_malformed_modified_source_packets() {
        let table = FlowTable::<()>::default();
        let mut non_loopback =
            ZCPacket::new_with_payload(&ipv4_packet(IpNextHeaderProtocols::Tcp, 20));
        non_loopback.fill_peer_manager_hdr(7, 8, PacketType::DataWithKcpSrcModified as u8);
        assert_eq!(
            table.route_peer_packet(&non_loopback, false),
            PeerPacketRoute::Pass
        );

        let mut malformed = ZCPacket::new_with_payload(&[0u8; 8]);
        malformed.fill_peer_manager_hdr(7, 7, PacketType::DataWithQuicSrcModified as u8);
        assert_eq!(
            table.route_peer_packet(&malformed, false),
            PeerPacketRoute::Pass
        );
    }
}

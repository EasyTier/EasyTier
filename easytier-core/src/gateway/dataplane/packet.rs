//! Peer-packet classification for registered data-plane flows.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::wire::{IPV4_HEADER_LEN, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket};

use crate::{
    gateway::proxy::ip_reassembler::IpReassembler,
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
    let Ok(ipv4) = Ipv4Packet::new_checked(payload) else {
        return ClassifiedPeerPacket::Unsupported;
    };
    if ipv4.version() != 4 || usize::from(ipv4.header_len()) < IPV4_HEADER_LEN {
        return ClassifiedPeerPacket::Unsupported;
    }

    match ipv4.next_header() {
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(ipv4.payload()) else {
                return ClassifiedPeerPacket::Unsupported;
            };
            let entry = FlowKey {
                dst: SocketAddr::new(ipv4.src_addr().into(), tcp.src_port()),
                src: SocketAddr::new(ipv4.dst_addr().into(), tcp.dst_port()),
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
                flags: tcp_flags(&tcp),
            }
        }
        IpProtocol::Udp => {
            if IpReassembler::is_packet_fragmented(&ipv4) {
                return ClassifiedPeerPacket::FragmentedUdp {
                    source: ipv4.src_addr(),
                };
            }
            let Ok(udp) = UdpPacket::new_checked(ipv4.payload()) else {
                return ClassifiedPeerPacket::Unsupported;
            };
            ClassifiedPeerPacket::Udp {
                entry: FlowKey {
                    dst: SocketAddr::new(ipv4.src_addr().into(), udp.src_port()),
                    src: SocketAddr::new(ipv4.dst_addr().into(), udp.dst_port()),
                    kind: FlowKind::Udp,
                },
            }
        }
        _ => ClassifiedPeerPacket::Unsupported,
    }
}

pub(super) fn tcp_flags<T: AsRef<[u8]>>(tcp: &TcpPacket<T>) -> u8 {
    u8::from(tcp.fin())
        | (u8::from(tcp.syn()) << 1)
        | (u8::from(tcp.rst()) << 2)
        | (u8::from(tcp.psh()) << 3)
        | (u8::from(tcp.ack()) << 4)
        | (u8::from(tcp.urg()) << 5)
        | (u8::from(tcp.ece()) << 6)
        | (u8::from(tcp.cwr()) << 7)
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

    use super::*;
    use crate::packet::{PacketType, ZCPacket};

    const TCP_SYN: u8 = 0x02;

    fn ipv4_packet(protocol: IpProtocol, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0; 20 + payload_len];
        let packet_len = packet.len() as u16;
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
        ipv4.set_version(4);
        ipv4.set_header_len(20);
        ipv4.set_total_len(packet_len);
        ipv4.set_src_addr(Ipv4Addr::new(10, 1, 1, 2));
        ipv4.set_dst_addr(Ipv4Addr::new(10, 2, 2, 3));
        ipv4.set_next_header(protocol);
        packet
    }
    #[test]
    fn classifies_tcp_and_listen_keys() {
        let mut packet = ipv4_packet(IpProtocol::Tcp, 20);
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
        tcp.set_src_port(1234);
        tcp.set_dst_port(4321);
        tcp.set_header_len(20);
        tcp.set_syn(true);

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
                flags: TCP_SYN,
            }
        );
    }
    #[test]
    fn classifies_udp_and_fragmented_udp() {
        let mut packet = ipv4_packet(IpProtocol::Udp, 8);
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
        let mut udp = UdpPacket::new_unchecked(ipv4.payload_mut());
        udp.set_src_port(1234);
        udp.set_dst_port(4321);
        udp.set_len(8);
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

        let mut fragmented = ipv4_packet(IpProtocol::Udp, 8);
        Ipv4Packet::new_unchecked(&mut fragmented).set_frag_offset(8);
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
            classify_peer_ipv4_payload(&ipv4_packet(IpProtocol::Icmp, 8)),
            ClassifiedPeerPacket::Unsupported
        );
    }

    #[test]
    fn rejects_ipv4_header_shorter_than_minimum() {
        let mut packet = ipv4_packet(IpProtocol::Tcp, 20);
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
        ipv4.set_header_len(16);
        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
        tcp.set_src_port(1234);
        tcp.set_dst_port(4321);
        tcp.set_header_len(20);

        assert_eq!(
            classify_peer_ipv4_payload(&packet),
            ClassifiedPeerPacket::Unsupported
        );
    }
    #[test]
    fn flow_table_routes_tcp_exact_and_listen_fallback() {
        let mut packet = ipv4_packet(IpProtocol::Tcp, 20);
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut packet);
        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
        tcp.set_src_port(1234);
        tcp.set_dst_port(4321);
        tcp.set_header_len(20);
        tcp.set_syn(true);

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
                tcp_flags: Some(TCP_SYN),
            }
        );

        table.insert(listen.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            PeerPacketRoute::Deliver {
                entry: listen,
                tcp_flags: Some(TCP_SYN),
            }
        );

        table.insert(exact.clone(), ());
        assert_eq!(
            table.route_peer_ipv4_payload(&packet, true),
            PeerPacketRoute::Deliver {
                entry: exact,
                tcp_flags: Some(TCP_SYN),
            }
        );
    }
    #[test]
    fn flow_table_routes_fragmented_udp_by_source_ip() {
        let mut packet = ipv4_packet(IpProtocol::Udp, 8);
        Ipv4Packet::new_unchecked(&mut packet).set_frag_offset(8);
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
        let mut payload = ipv4_packet(IpProtocol::Tcp, 20);
        let mut ipv4 = Ipv4Packet::new_unchecked(&mut payload);
        let mut tcp = TcpPacket::new_unchecked(ipv4.payload_mut());
        tcp.set_src_port(1234);
        tcp.set_dst_port(4321);
        tcp.set_header_len(20);
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
        let mut non_loopback = ZCPacket::new_with_payload(&ipv4_packet(IpProtocol::Tcp, 20));
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

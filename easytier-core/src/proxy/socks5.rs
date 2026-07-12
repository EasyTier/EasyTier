use std::net::SocketAddr;

#[cfg(feature = "proxy-packet")]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(feature = "proxy-packet")]
use pnet_packet::{
    Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket,
};

#[cfg(feature = "proxy-packet")]
use super::ip_reassembler::{IpReassembler, SmolIpv4Packet};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum Socks5EntryKind {
    Udp = 1,
    Tcp = 2,
    TcpListen = 3,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Socks5Entry {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub kind: Socks5EntryKind,
}

#[cfg(feature = "proxy-packet")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5PeerPacket {
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

#[cfg(feature = "proxy-packet")]
pub fn classify_peer_ipv4_payload(payload: &[u8]) -> Socks5PeerPacket {
    let Some(ipv4) = Ipv4Packet::new(payload) else {
        return Socks5PeerPacket::Unsupported;
    };
    if ipv4.get_version() != 4 {
        return Socks5PeerPacket::Unsupported;
    }

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let Some(tcp) = TcpPacket::new(ipv4.payload()) else {
                return Socks5PeerPacket::Unsupported;
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
            Socks5PeerPacket::Tcp {
                entry,
                listen_entry,
                flags: tcp.get_flags(),
            }
        }
        IpNextHeaderProtocols::Udp => {
            let smol_ipv4 = SmolIpv4Packet::new_unchecked(ipv4.packet());
            if IpReassembler::is_packet_fragmented(&smol_ipv4) {
                return Socks5PeerPacket::FragmentedUdp {
                    source: ipv4.get_source(),
                };
            }
            let Some(udp) = UdpPacket::new(ipv4.payload()) else {
                return Socks5PeerPacket::Unsupported;
            };
            Socks5PeerPacket::Udp {
                entry: Socks5Entry {
                    dst: SocketAddr::new(ipv4.get_source().into(), udp.get_source()),
                    src: SocketAddr::new(ipv4.get_destination().into(), udp.get_destination()),
                    kind: Socks5EntryKind::Udp,
                },
            }
        }
        _ => Socks5PeerPacket::Unsupported,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5TcpRoute {
    Kernel,
    Smoltcp,
    Kcp,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Socks5TcpRouteContext {
    pub has_smoltcp_net: bool,
    pub destination_in_virtual_network: bool,
    pub destination_is_loopback: bool,
    pub kcp_available: bool,
    pub destination_allows_kcp: bool,
}

impl Socks5TcpRouteContext {
    pub fn routes_over_virtual_network(self) -> bool {
        self.has_smoltcp_net && self.destination_in_virtual_network && !self.destination_is_loopback
    }

    pub fn route(self) -> Socks5TcpRoute {
        if !self.routes_over_virtual_network() {
            Socks5TcpRoute::Kernel
        } else if self.kcp_available && self.destination_allows_kcp {
            Socks5TcpRoute::Kcp
        } else {
            Socks5TcpRoute::Smoltcp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Socks5EntryKind, Socks5TcpRoute, Socks5TcpRouteContext};

    #[cfg(feature = "proxy-packet")]
    use super::{Socks5Entry, Socks5PeerPacket, classify_peer_ipv4_payload};
    #[cfg(feature = "proxy-packet")]
    use pnet_packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags},
        udp::MutableUdpPacket,
    };
    #[cfg(feature = "proxy-packet")]
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn entry_kind_values_preserve_native_table_identity() {
        assert_eq!(Socks5EntryKind::Udp as u8, 1);
        assert_eq!(Socks5EntryKind::Tcp as u8, 2);
        assert_eq!(Socks5EntryKind::TcpListen as u8, 3);
    }

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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
            Socks5PeerPacket::Tcp {
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

    #[cfg(feature = "proxy-packet")]
    #[test]
    fn classifies_udp_and_fragmented_udp() {
        let mut packet = ipv4_packet(IpNextHeaderProtocols::Udp, 8);
        let mut ipv4 = MutableIpv4Packet::new(&mut packet).unwrap();
        let mut udp = MutableUdpPacket::new(ipv4.payload_mut()).unwrap();
        udp.set_source(1234);
        udp.set_destination(4321);
        assert_eq!(
            classify_peer_ipv4_payload(&packet),
            Socks5PeerPacket::Udp {
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
            Socks5PeerPacket::FragmentedUdp {
                source: Ipv4Addr::new(10, 1, 1, 2),
            }
        );
    }

    #[cfg(feature = "proxy-packet")]
    #[test]
    fn rejects_malformed_and_unsupported_packets() {
        assert_eq!(
            classify_peer_ipv4_payload(&[]),
            Socks5PeerPacket::Unsupported
        );
        assert_eq!(
            classify_peer_ipv4_payload(&ipv4_packet(IpNextHeaderProtocols::Icmp, 8)),
            Socks5PeerPacket::Unsupported
        );
    }

    fn virtual_destination() -> Socks5TcpRouteContext {
        Socks5TcpRouteContext {
            has_smoltcp_net: true,
            destination_in_virtual_network: true,
            ..Default::default()
        }
    }

    #[test]
    fn kernel_route_covers_non_virtual_destinations() {
        assert_eq!(
            Socks5TcpRouteContext::default().route(),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            Socks5TcpRouteContext {
                has_smoltcp_net: true,
                ..Default::default()
            }
            .route(),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            Socks5TcpRouteContext {
                destination_is_loopback: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Kernel
        );
    }

    #[test]
    fn virtual_route_uses_smoltcp_without_allowed_kcp() {
        assert_eq!(virtual_destination().route(), Socks5TcpRoute::Smoltcp);
        assert_eq!(
            Socks5TcpRouteContext {
                kcp_available: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Smoltcp
        );
        assert_eq!(
            Socks5TcpRouteContext {
                destination_allows_kcp: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Smoltcp
        );
    }

    #[test]
    fn virtual_route_uses_kcp_only_when_available_and_allowed() {
        assert_eq!(
            Socks5TcpRouteContext {
                kcp_available: true,
                destination_allows_kcp: true,
                ..virtual_destination()
            }
            .route(),
            Socks5TcpRoute::Kcp
        );
    }
}

use std::{future::Future, net::Ipv4Addr};

use async_trait::async_trait;
use pnet_packet::{
    MutablePacket, Packet,
    icmp::{self, IcmpPacket, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
};

use crate::{
    config::PeerId,
    packet::ZCPacket,
    peers::{BoxNicPacketFilter, NicPacketFilter},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsQuery {
    pub source: std::net::SocketAddr,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait MagicDnsQueryResolver: Send + Sync + 'static {
    async fn resolve(&self, query: MagicDnsQuery) -> Option<Vec<u8>>;
}

/// Owns one Magic DNS resolver installed in the core NIC pipeline.
///
/// `close` waits until readers that may already be invoking the resolver have
/// finished, then removes the entry so the resolver can be dropped promptly.
pub struct MagicDnsResolverRegistration {
    peer_manager: std::sync::Weak<crate::peers::peer_manager::PeerManagerCore>,
    pipeline: crate::peers::peer_manager::PipelineRegistrationGuard,
    runtime: tokio::runtime::Handle,
}

impl MagicDnsResolverRegistration {
    pub(crate) fn new(
        peer_manager: std::sync::Weak<crate::peers::peer_manager::PeerManagerCore>,
        pipeline: crate::peers::peer_manager::PipelineRegistrationGuard,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            peer_manager,
            pipeline,
            runtime,
        }
    }

    pub async fn close(&self) {
        self.pipeline.close();
        if let Some(peer_manager) = self.peer_manager.upgrade() {
            peer_manager
                .remove_managed_nic_packet_process_pipeline(&self.pipeline)
                .await;
        }
    }
}

impl Drop for MagicDnsResolverRegistration {
    fn drop(&mut self) {
        self.pipeline.close();
        let Some(peer_manager) = self.peer_manager.upgrade() else {
            return;
        };
        let pipeline = self.pipeline.clone();
        self.runtime.spawn(async move {
            peer_manager
                .remove_managed_nic_packet_process_pipeline(&pipeline)
                .await;
        });
    }
}

struct MagicDnsPacketFilter {
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,
    resolver: std::sync::Arc<dyn MagicDnsQueryResolver>,
}

pub(crate) fn magic_dns_packet_filter(
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,
    resolver: std::sync::Arc<dyn MagicDnsQueryResolver>,
) -> BoxNicPacketFilter {
    Box::new(MagicDnsPacketFilter {
        fake_ip,
        my_peer_id,
        resolver,
    })
}

#[async_trait]
impl NicPacketFilter for MagicDnsPacketFilter {
    async fn try_process_packet_from_nic(&self, packet: &mut ZCPacket) -> bool {
        process_magic_dns_packet(packet, self.fake_ip, self.my_peer_id, |query| {
            self.resolver.resolve(query)
        })
        .await
    }

    fn id(&self) -> String {
        "magic_dns_server".to_owned()
    }
}

pub async fn process_magic_dns_packet<F, Fut>(
    packet: &mut ZCPacket,
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,
    resolve: F,
) -> bool
where
    F: FnOnce(MagicDnsQuery) -> Fut,
    Fut: Future<Output = Option<Vec<u8>>>,
{
    if packet.peer_manager_header().is_none() {
        return false;
    }
    let Some(ip_packet) = Ipv4Packet::new(packet.payload()) else {
        return false;
    };
    if ip_packet.get_version() != 4 || ip_packet.get_destination() != fake_ip {
        return false;
    }

    let ip_header_length = ip_packet.get_header_length() as usize * 4;
    let ip_total_length = ip_packet.get_total_length() as usize;
    if ip_header_length < MutableIpv4Packet::minimum_packet_size()
        || ip_header_length > ip_total_length
        || ip_total_length != packet.payload().len()
        || ip_packet.get_fragment_offset() != 0
        || ip_packet.get_flags() & Ipv4Flags::MoreFragments != 0
    {
        return false;
    }

    let protocol = ip_packet.get_next_level_protocol();
    let source_ip = ip_packet.get_source();
    let destination_ip = ip_packet.get_destination();

    match protocol {
        IpNextHeaderProtocols::Udp => {
            let ip_payload = &packet.payload()[ip_header_length..ip_total_length];
            let Some(udp_packet) = UdpPacket::new(ip_payload) else {
                return false;
            };
            let udp_length = udp_packet.get_length() as usize;
            if udp_length != ip_payload.len() || udp_length < UdpPacket::minimum_packet_size() {
                return false;
            }
            if udp_packet.get_destination() != 53 {
                return false;
            }
            let source_port = udp_packet.get_source();
            let destination_port = udp_packet.get_destination();
            let query = MagicDnsQuery {
                source: std::net::SocketAddr::from((source_ip, source_port)),
                payload: udp_packet.payload().to_vec(),
            };
            let Some(response) = resolve(query).await else {
                return false;
            };
            if !apply_udp_response(
                packet,
                source_ip,
                destination_ip,
                source_port,
                destination_port,
                ip_header_length,
                &response,
            ) {
                return false;
            }
        }
        IpNextHeaderProtocols::Icmp => {
            let Some(icmp_packet) = IcmpPacket::new(&packet.payload()[ip_header_length..]) else {
                return false;
            };
            if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
                return false;
            }
            let Some(mut icmp_packet) =
                MutableIcmpPacket::new(&mut packet.mut_payload()[ip_header_length..])
            else {
                return false;
            };
            icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
            icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
        }
        _ => return false,
    }

    let Some(mut ip_packet) = MutableIpv4Packet::new(packet.mut_payload()) else {
        return false;
    };
    ip_packet.set_source(destination_ip);
    ip_packet.set_destination(source_ip);
    ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
    let payload_length = packet.payload().len() as u32;
    let Some(header) = packet.mut_peer_manager_header() else {
        return false;
    };
    header.to_peer_id = my_peer_id.into();
    header.len.set(payload_length);
    true
}

#[allow(clippy::too_many_arguments)]
fn apply_udp_response(
    packet: &mut ZCPacket,
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    ip_header_length: usize,
    response: &[u8],
) -> bool {
    let Some(udp_length) = UdpPacket::minimum_packet_size().checked_add(response.len()) else {
        return false;
    };
    let Some(ip_length) = ip_header_length.checked_add(udp_length) else {
        return false;
    };
    if ip_length > u16::MAX as usize {
        return false;
    }
    let Some(header_length) = packet.buf_len().checked_sub(packet.payload().len()) else {
        return false;
    };
    let Some(inner_length) = header_length.checked_add(ip_length) else {
        return false;
    };

    if packet.mut_inner().capacity() < inner_length {
        packet
            .mut_inner()
            .truncate(header_length + ip_header_length + UdpPacket::minimum_packet_size());
    }
    packet.mut_inner().resize(inner_length, 0);

    let Some(mut ip_packet) = MutableIpv4Packet::new(packet.mut_payload()) else {
        return false;
    };
    ip_packet.set_total_length(ip_length as u16);
    let Some(mut udp_packet) = MutableUdpPacket::new(ip_packet.payload_mut()) else {
        return false;
    };
    udp_packet.set_length(udp_length as u16);
    udp_packet.set_source(destination_port);
    udp_packet.set_destination(source_port);
    udp_packet.payload_mut().copy_from_slice(response);
    udp_packet.set_checksum(udp::ipv4_checksum(
        &udp_packet.to_immutable(),
        &destination_ip,
        &source_ip,
    ));
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_query(payload: &[u8], destination_port: u16) -> ZCPacket {
        let mut bytes = vec![0; 20 + 8 + payload.len()];
        {
            let mut ip = MutableIpv4Packet::new(&mut bytes).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length((20 + 8 + payload.len()) as u16);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip.set_source("10.0.0.2".parse().unwrap());
            ip.set_destination("100.100.100.101".parse().unwrap());
            let mut udp = MutableUdpPacket::new(ip.payload_mut()).unwrap();
            udp.set_source(53000);
            udp.set_destination(destination_port);
            udp.set_length((8 + payload.len()) as u16);
            udp.payload_mut().copy_from_slice(payload);
        }
        ZCPacket::new_with_payload(&bytes)
    }

    fn icmp_echo_request() -> ZCPacket {
        let mut bytes = vec![0; 20 + 8];
        {
            let mut ip = MutableIpv4Packet::new(&mut bytes).unwrap();
            ip.set_version(4);
            ip.set_header_length(5);
            ip.set_total_length(28);
            ip.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ip.set_source("10.0.0.2".parse().unwrap());
            ip.set_destination("100.100.100.101".parse().unwrap());
            let mut icmp = MutableIcmpPacket::new(ip.payload_mut()).unwrap();
            icmp.set_icmp_type(IcmpTypes::EchoRequest);
        }
        ZCPacket::new_with_payload(&bytes)
    }
    #[tokio::test]
    async fn packet_engine_rewrites_dns_query_response() {
        let mut packet = udp_query(b"query", 53);
        let handled = process_magic_dns_packet(
            &mut packet,
            "100.100.100.101".parse().unwrap(),
            42,
            |query| async move {
                assert_eq!(query.source, "10.0.0.2:53000".parse().unwrap());
                assert_eq!(query.payload, b"query");
                Some(b"response".to_vec())
            },
        )
        .await;

        assert!(handled);
        let ip = Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(
            ip.get_source(),
            "100.100.100.101".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ip.get_destination(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        let udp = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp.get_source(), 53);
        assert_eq!(udp.get_destination(), 53000);
        assert_eq!(udp.payload(), b"response");
        assert_eq!(packet.get_dst_peer_id(), Some(42));
        assert_eq!(
            packet.peer_manager_header().unwrap().len.get() as usize,
            packet.payload().len()
        );
    }

    #[tokio::test]
    async fn packet_engine_rejects_invalid_ipv4_header_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        MutableIpv4Packet::new(packet.mut_payload())
            .unwrap()
            .set_header_length(15);
        let original = packet.payload().to_vec();

        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { panic!("invalid IPv4 header must not invoke DNS") },
            )
            .await
        );
        assert_eq!(packet.payload(), original);
    }

    #[tokio::test]
    async fn packet_engine_rejects_short_zc_packet_without_panicking() {
        let mut packet =
            ZCPacket::new_from_buf(Default::default(), crate::packet::ZCPacketType::NIC);

        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { panic!("short packet must not invoke DNS") },
            )
            .await
        );
    }

    #[tokio::test]
    async fn packet_engine_rejects_inconsistent_udp_length_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        let mut ip = MutableIpv4Packet::new(packet.mut_payload()).unwrap();
        MutableUdpPacket::new(ip.payload_mut())
            .unwrap()
            .set_length(8);
        let original = packet.payload().to_vec();

        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { panic!("invalid UDP length must not invoke DNS") },
            )
            .await
        );
        assert_eq!(packet.payload(), original);
    }

    #[tokio::test]
    async fn packet_engine_rejects_fragmented_packets_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        MutableIpv4Packet::new(packet.mut_payload())
            .unwrap()
            .set_flags(Ipv4Flags::MoreFragments);
        let original = packet.payload().to_vec();

        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { panic!("fragmented packet must not invoke DNS") },
            )
            .await
        );
        assert_eq!(packet.payload(), original);
    }

    #[tokio::test]
    async fn packet_engine_rejects_oversized_response_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        let original = packet.payload().to_vec();
        let original_length = packet.buf_len();

        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { Some(vec![0; u16::MAX as usize]) },
            )
            .await
        );
        assert_eq!(packet.buf_len(), original_length);
        assert_eq!(packet.payload(), original);
    }

    #[tokio::test]
    async fn packet_engine_replies_to_icmp_without_calling_dns() {
        let mut packet = icmp_echo_request();
        let handled = process_magic_dns_packet(
            &mut packet,
            "100.100.100.101".parse().unwrap(),
            7,
            |_| async { panic!("ICMP must not invoke DNS") },
        )
        .await;

        assert!(handled);
        let ip = Ipv4Packet::new(packet.payload()).unwrap();
        assert_eq!(
            ip.get_source(),
            "100.100.100.101".parse::<Ipv4Addr>().unwrap()
        );
        let icmp = pnet_packet::icmp::IcmpPacket::new(ip.payload()).unwrap();
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoReply);
        assert_eq!(packet.get_dst_peer_id(), Some(7));
    }

    #[tokio::test]
    async fn packet_engine_ignores_non_dns_udp() {
        let mut packet = udp_query(b"query", 5353);
        assert!(
            !process_magic_dns_packet(
                &mut packet,
                "100.100.100.101".parse().unwrap(),
                42,
                |_| async { Some(Vec::new()) },
            )
            .await
        );
    }
}

use std::{future::Future, net::Ipv4Addr};

use async_trait::async_trait;
use smoltcp::wire::{
    IPV4_HEADER_LEN, Icmpv4Message, Icmpv4Packet, IpAddress, IpProtocol, Ipv4Packet,
    UDP_HEADER_LEN, UdpPacket,
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
    if packet.payload().len() < IPV4_HEADER_LEN {
        return false;
    }
    let ip_packet = Ipv4Packet::new_unchecked(packet.payload());
    if ip_packet.version() != 4 || ip_packet.dst_addr() != fake_ip {
        return false;
    }

    let ip_header_length = ip_packet.header_len() as usize;
    let ip_total_length = ip_packet.total_len() as usize;
    if ip_header_length < IPV4_HEADER_LEN
        || ip_header_length > ip_total_length
        || ip_total_length != packet.payload().len()
        || ip_packet.frag_offset() != 0
        || ip_packet.more_frags()
    {
        return false;
    }

    let protocol = ip_packet.next_header();
    let source_ip = ip_packet.src_addr();
    let destination_ip = ip_packet.dst_addr();

    match protocol {
        IpProtocol::Udp => {
            let ip_payload = &packet.payload()[ip_header_length..ip_total_length];
            if ip_payload.len() < UDP_HEADER_LEN {
                return false;
            }
            let udp_packet = UdpPacket::new_unchecked(ip_payload);
            let udp_length = udp_packet.len() as usize;
            if udp_length != ip_payload.len() || udp_length < UDP_HEADER_LEN {
                return false;
            }
            if udp_packet.dst_port() != 53 {
                return false;
            }
            let source_port = udp_packet.src_port();
            let destination_port = udp_packet.dst_port();
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
        IpProtocol::Icmp => {
            let Ok(icmp_packet) = Icmpv4Packet::new_checked(&packet.payload()[ip_header_length..])
            else {
                return false;
            };
            if icmp_packet.msg_type() != Icmpv4Message::EchoRequest {
                return false;
            }
            let mut icmp_packet =
                Icmpv4Packet::new_unchecked(&mut packet.mut_payload()[ip_header_length..]);
            icmp_packet.set_msg_type(Icmpv4Message::EchoReply);
            icmp_packet.fill_checksum();
        }
        _ => return false,
    }

    let mut ip_packet = Ipv4Packet::new_unchecked(packet.mut_payload());
    ip_packet.set_src_addr(destination_ip);
    ip_packet.set_dst_addr(source_ip);
    ip_packet.fill_checksum();
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
    let Some(udp_length) = UDP_HEADER_LEN.checked_add(response.len()) else {
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
            .truncate(header_length + ip_header_length + UDP_HEADER_LEN);
    }
    packet.mut_inner().resize(inner_length, 0);

    let mut ip_packet = Ipv4Packet::new_unchecked(packet.mut_payload());
    ip_packet.set_total_len(ip_length as u16);
    let mut udp_packet = UdpPacket::new_unchecked(ip_packet.payload_mut());
    udp_packet.set_len(udp_length as u16);
    udp_packet.set_src_port(destination_port);
    udp_packet.set_dst_port(source_port);
    udp_packet.payload_mut().copy_from_slice(response);
    udp_packet.fill_checksum(
        &IpAddress::Ipv4(destination_ip),
        &IpAddress::Ipv4(source_ip),
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_query(payload: &[u8], destination_port: u16) -> ZCPacket {
        let mut bytes = vec![0; 20 + 8 + payload.len()];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len((20 + 8 + payload.len()) as u16);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr("10.0.0.2".parse().unwrap());
            ip.set_dst_addr("100.100.100.101".parse().unwrap());
            let mut udp = UdpPacket::new_unchecked(ip.payload_mut());
            udp.set_src_port(53000);
            udp.set_dst_port(destination_port);
            udp.set_len((8 + payload.len()) as u16);
            udp.payload_mut().copy_from_slice(payload);
        }
        ZCPacket::new_with_payload(&bytes)
    }

    fn icmp_echo_request() -> ZCPacket {
        let mut bytes = vec![0; 20 + 8];
        {
            let mut ip = Ipv4Packet::new_unchecked(&mut bytes);
            ip.set_version(4);
            ip.set_header_len(20);
            ip.set_total_len(28);
            ip.set_next_header(IpProtocol::Icmp);
            ip.set_src_addr("10.0.0.2".parse().unwrap());
            ip.set_dst_addr("100.100.100.101".parse().unwrap());
            let mut icmp = Icmpv4Packet::new_unchecked(ip.payload_mut());
            icmp.set_msg_type(Icmpv4Message::EchoRequest);
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
        let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(
            ip.src_addr(),
            "100.100.100.101".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(ip.dst_addr(), "10.0.0.2".parse::<Ipv4Addr>().unwrap());
        let udp = UdpPacket::new_checked(ip.payload()).unwrap();
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 53000);
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
        Ipv4Packet::new_unchecked(packet.mut_payload()).set_header_len(60);
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
        let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
        UdpPacket::new_unchecked(ip.payload_mut()).set_len(8);
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
        Ipv4Packet::new_unchecked(packet.mut_payload()).set_more_frags(true);
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
        let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(
            ip.src_addr(),
            "100.100.100.101".parse::<Ipv4Addr>().unwrap()
        );
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
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

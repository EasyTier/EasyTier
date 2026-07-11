use std::{net::Ipv4Addr, sync::Arc, time::Duration};

use dashmap::DashMap;
use pnet_packet::{
    Packet,
    icmp::{self, IcmpCode, IcmpTypes, MutableIcmpPacket, echo_reply::MutableEchoReplyPacket},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
};
use quanta::Instant;

use crate::packet::{PacketType, ZCPacket};

use super::{
    cidr_table::ProxyCidrTable,
    ip_reassembler::{
        ComposeIpv4PacketArgs, IpProtocol, IpReassembler, SmolIpv4Packet, compose_ipv4_packet,
    },
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IcmpProxyContext {
    pub virtual_ipv4: Option<Ipv4Addr>,
    pub enable_exit_node: bool,
    pub no_tun: bool,
}

#[derive(Debug)]
pub enum IcmpProxyAction {
    Pass,
    SendToSocket {
        destination: Ipv4Addr,
        packet: Vec<u8>,
    },
    SendToPeer(ZCPacket),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IcmpNatKey {
    real_destination: Ipv4Addr,
    identifier: u16,
    sequence: u16,
}

#[derive(Debug)]
struct IcmpNatEntry {
    source_peer_id: u32,
    local_peer_id: u32,
    source_ip: Ipv4Addr,
    mapped_destination: Ipv4Addr,
    started_at: Instant,
}

#[derive(Debug)]
pub struct IcmpProxyEngine {
    cidr_table: Arc<ProxyCidrTable>,
    nat_table: DashMap<IcmpNatKey, IcmpNatEntry>,
    reassembler: IpReassembler,
}

impl IcmpProxyEngine {
    pub fn new(cidr_table: Arc<ProxyCidrTable>, fragment_timeout: Duration) -> Self {
        Self {
            cidr_table,
            nat_table: DashMap::new(),
            reassembler: IpReassembler::new(fragment_timeout),
        }
    }

    pub fn handle_peer_packet(
        &self,
        packet: &ZCPacket,
        context: IcmpProxyContext,
    ) -> IcmpProxyAction {
        if self.cidr_table.is_empty() && !context.enable_exit_node && !context.no_tun {
            return IcmpProxyAction::Pass;
        }
        let Some(virtual_ipv4) = context.virtual_ipv4 else {
            return IcmpProxyAction::Pass;
        };
        let Some(header) = packet.peer_manager_header() else {
            return IcmpProxyAction::Pass;
        };
        if header.packet_type != PacketType::Data as u8 || header.is_no_proxy() {
            return IcmpProxyAction::Pass;
        }
        let Some(ipv4) = Ipv4Packet::new(packet.payload()) else {
            return IcmpProxyAction::Pass;
        };
        if ipv4.get_version() != 4 || ipv4.get_next_level_protocol() != IpNextHeaderProtocols::Icmp
        {
            return IcmpProxyAction::Pass;
        }

        let mapped_destination = ipv4.get_destination();
        let real_destination = self.cidr_table.lookup_v4(mapped_destination);
        let is_local_no_tun = context.no_tun && mapped_destination == virtual_ipv4;
        if real_destination.is_none() && !header.is_exit_node() && !is_local_no_tun {
            return IcmpProxyAction::Pass;
        }

        let reassembled;
        let smol_ipv4 = SmolIpv4Packet::new_unchecked(ipv4.packet());
        let request = if IpReassembler::is_packet_fragmented(&smol_ipv4) {
            let Ok(smol_ipv4) = SmolIpv4Packet::new_checked(ipv4.packet()) else {
                return IcmpProxyAction::Pass;
            };
            reassembled = self.reassembler.add_fragment(&smol_ipv4);
            let Some(reassembled) = reassembled.as_ref() else {
                return IcmpProxyAction::Pass;
            };
            let Some(request) = icmp::echo_request::EchoRequestPacket::new(reassembled) else {
                return IcmpProxyAction::Pass;
            };
            request
        } else {
            let Some(request) = icmp::echo_request::EchoRequestPacket::new(ipv4.payload()) else {
                return IcmpProxyAction::Pass;
            };
            request
        };
        if request.get_icmp_type() != IcmpTypes::EchoRequest {
            return IcmpProxyAction::Pass;
        }

        if is_local_no_tun {
            return self.local_reply(
                mapped_destination,
                ipv4.get_source(),
                header.to_peer_id.get(),
                header.from_peer_id.get(),
                &request,
            );
        }

        let real_destination = real_destination.unwrap_or(mapped_destination);
        let key = IcmpNatKey {
            real_destination,
            identifier: request.get_identifier(),
            sequence: request.get_sequence_number(),
        };
        self.nat_table.insert(
            key,
            IcmpNatEntry {
                source_peer_id: header.from_peer_id.get(),
                local_peer_id: header.to_peer_id.get(),
                source_ip: ipv4.get_source(),
                mapped_destination,
                started_at: Instant::now(),
            },
        );

        IcmpProxyAction::SendToSocket {
            destination: real_destination,
            packet: request.packet().to_vec(),
        }
    }

    pub fn handle_socket_response(&self, peer_ip: Ipv4Addr, packet: &mut [u8]) -> Option<ZCPacket> {
        let ipv4 = Ipv4Packet::new(packet)?;
        let reply = icmp::echo_reply::EchoReplyPacket::new(ipv4.payload())?;
        if reply.get_icmp_type() != IcmpTypes::EchoReply {
            return None;
        }
        let key = IcmpNatKey {
            real_destination: peer_ip,
            identifier: reply.get_identifier(),
            sequence: reply.get_sequence_number(),
        };
        let (_, entry) = self.nat_table.remove(&key)?;
        let payload_len = packet
            .len()
            .checked_sub(ipv4.get_header_length() as usize * 4)?;
        let ip_id = ipv4.get_identification();
        let mut response = None;
        let _ = compose_ipv4_packet(
            ComposeIpv4PacketArgs {
                buf: packet,
                src_v4: &entry.mapped_destination,
                dst_v4: &entry.source_ip,
                next_protocol: IpProtocol::Icmp,
                payload_len,
                payload_mtu: 1200,
                ip_id,
            },
            |buf| {
                let mut packet = ZCPacket::new_with_payload(buf);
                packet.fill_peer_manager_hdr(
                    entry.local_peer_id,
                    entry.source_peer_id,
                    PacketType::Data as u8,
                );
                packet
                    .mut_peer_manager_header()
                    .expect("peer manager header")
                    .set_no_proxy(true);
                response = Some(packet);
                Ok(())
            },
        );
        response
    }

    pub fn remove_expired_entries(&self, max_age: Duration) {
        self.nat_table
            .retain(|_, entry| entry.started_at.elapsed() < max_age);
        self.nat_table.shrink_to_fit();
    }

    pub fn remove_expired_fragments(&self) {
        self.reassembler.remove_expired_packets();
    }

    fn local_reply(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_peer_id: u32,
        destination_peer_id: u32,
        request: &icmp::echo_request::EchoRequestPacket<'_>,
    ) -> IcmpProxyAction {
        let mut buffer = vec![0_u8; request.packet().len() + 20];
        let mut reply = MutableEchoReplyPacket::new(&mut buffer[20..]).unwrap();
        reply.set_icmp_type(IcmpTypes::EchoReply);
        reply.set_icmp_code(IcmpCode::new(0));
        reply.set_identifier(request.get_identifier());
        reply.set_sequence_number(request.get_sequence_number());
        reply.set_payload(request.payload());
        let mut reply = MutableIcmpPacket::new(&mut buffer[20..]).unwrap();
        reply.set_checksum(icmp::checksum(&reply.to_immutable()));

        let payload_len = buffer.len() - 20;
        let mut response = None;
        let _ = compose_ipv4_packet(
            ComposeIpv4PacketArgs {
                buf: &mut buffer,
                src_v4: &source,
                dst_v4: &destination,
                next_protocol: IpProtocol::Icmp,
                payload_len,
                payload_mtu: 1200,
                ip_id: rand::random(),
            },
            |buf| {
                let mut packet = ZCPacket::new_with_payload(buf);
                packet.fill_peer_manager_hdr(
                    source_peer_id,
                    destination_peer_id,
                    PacketType::Data as u8,
                );
                response = Some(packet);
                Ok(())
            },
        );
        IcmpProxyAction::SendToPeer(response.expect("ICMP reply composition should succeed"))
    }
}

#[cfg(test)]
mod tests {
    use pnet_packet::{
        MutablePacket as _,
        icmp::{MutableIcmpPacket, echo_request::MutableEchoRequestPacket},
        ipv4::{self, MutableIpv4Packet},
    };

    use super::*;
    use crate::proxy::cidr_table::{ProxyCidrRule, ProxyCidrSnapshot};

    fn echo_request(source: Ipv4Addr, destination: Ipv4Addr) -> ZCPacket {
        let mut bytes = vec![0_u8; 20 + 8 + 4];
        {
            let mut request = MutableEchoRequestPacket::new(&mut bytes[20..]).unwrap();
            request.set_icmp_type(IcmpTypes::EchoRequest);
            request.set_identifier(7);
            request.set_sequence_number(11);
            request.set_payload(b"ping");
            let mut icmp = MutableIcmpPacket::new(&mut bytes[20..]).unwrap();
            icmp.set_checksum(icmp::checksum(&icmp.to_immutable()));
        }
        {
            let packet_len = bytes.len() as u16;
            let mut ipv4 = MutableIpv4Packet::new(&mut bytes).unwrap();
            ipv4.set_version(4);
            ipv4.set_header_length(5);
            ipv4.set_total_length(packet_len);
            ipv4.set_ttl(64);
            ipv4.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
            ipv4.set_source(source);
            ipv4.set_destination(destination);
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
        }
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(101, 202, PacketType::Data as u8);
        packet
    }

    fn engine(rule: Option<ProxyCidrRule>) -> IcmpProxyEngine {
        let table = ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: rule.into_iter().collect(),
        });
        IcmpProxyEngine::new(Arc::new(table), Duration::from_secs(10))
    }

    #[test]
    fn inactive_proxy_passes_echo_request() {
        let engine = engine(None);
        let packet = echo_request("10.0.0.2".parse().unwrap(), "192.0.2.2".parse().unwrap());

        assert!(matches!(
            engine.handle_peer_packet(
                &packet,
                IcmpProxyContext {
                    virtual_ipv4: Some("10.0.0.1".parse().unwrap()),
                    ..Default::default()
                }
            ),
            IcmpProxyAction::Pass
        ));
    }

    #[test]
    fn no_tun_local_request_returns_echo_reply_to_origin_peer() {
        let engine = engine(None);
        let packet = echo_request("10.0.0.2".parse().unwrap(), "10.0.0.1".parse().unwrap());

        let IcmpProxyAction::SendToPeer(reply) = engine.handle_peer_packet(
            &packet,
            IcmpProxyContext {
                virtual_ipv4: Some("10.0.0.1".parse().unwrap()),
                no_tun: true,
                ..Default::default()
            },
        ) else {
            panic!("expected local reply");
        };
        let header = reply.peer_manager_header().unwrap();
        assert_eq!(header.from_peer_id.get(), 202);
        assert_eq!(header.to_peer_id.get(), 101);
        let ipv4 = Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(ipv4.get_source(), "10.0.0.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            ipv4.get_destination(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
        let reply = icmp::echo_reply::EchoReplyPacket::new(ipv4.payload()).unwrap();
        assert_eq!(reply.get_identifier(), 7);
        assert_eq!(reply.get_sequence_number(), 11);
        assert_eq!(reply.payload(), b"ping");
    }

    #[test]
    fn mapped_request_and_socket_reply_round_trip() {
        let engine = engine(Some(ProxyCidrRule {
            cidr: "127.0.0.0/24".parse().unwrap(),
            mapped_cidr: Some("10.10.10.0/24".parse().unwrap()),
        }));
        let packet = echo_request("10.0.0.2".parse().unwrap(), "10.10.10.42".parse().unwrap());

        let IcmpProxyAction::SendToSocket {
            destination,
            packet: request,
        } = engine.handle_peer_packet(
            &packet,
            IcmpProxyContext {
                virtual_ipv4: Some("10.0.0.1".parse().unwrap()),
                ..Default::default()
            },
        )
        else {
            panic!("expected socket request");
        };
        assert_eq!(destination, "127.0.0.42".parse::<Ipv4Addr>().unwrap());
        let request = icmp::echo_request::EchoRequestPacket::new(&request).unwrap();
        assert_eq!(request.payload(), b"ping");

        let mut response = echo_request(destination, "10.0.0.1".parse().unwrap())
            .payload()
            .to_vec();
        {
            let mut ipv4 = MutableIpv4Packet::new(&mut response).unwrap();
            let mut reply = MutableEchoReplyPacket::new(ipv4.payload_mut()).unwrap();
            reply.set_icmp_type(IcmpTypes::EchoReply);
            let mut icmp = MutableIcmpPacket::new(ipv4.payload_mut()).unwrap();
            icmp.set_checksum(icmp::checksum(&icmp.to_immutable()));
            ipv4.set_source(destination);
            ipv4.set_checksum(ipv4::checksum(&ipv4.to_immutable()));
        }
        let reply = engine
            .handle_socket_response(destination, &mut response)
            .expect("socket reply should match NAT entry");
        let header = reply.peer_manager_header().unwrap();
        assert_eq!(header.from_peer_id.get(), 202);
        assert_eq!(header.to_peer_id.get(), 101);
        assert!(header.is_no_proxy());
        let ipv4 = Ipv4Packet::new(reply.payload()).unwrap();
        assert_eq!(
            ipv4.get_source(),
            "10.10.10.42".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(
            ipv4.get_destination(),
            "10.0.0.2".parse::<Ipv4Addr>().unwrap()
        );
    }
}

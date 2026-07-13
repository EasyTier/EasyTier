use std::{net::Ipv4Addr, sync::Arc};

use dashmap::DashMap;

use crate::packet::{PacketType, ZCPacket};

const IPV4_HEADER_LEN: usize = 20;

pub struct VpnPortalClient<V> {
    endpoint_addr: Option<url::Url>,
    value: V,
}

impl<V> VpnPortalClient<V> {
    pub fn endpoint_addr(&self) -> Option<&url::Url> {
        self.endpoint_addr.as_ref()
    }

    pub fn value(&self) -> &V {
        &self.value
    }
}

pub struct VpnPortalClientTable<V> {
    entries: DashMap<Ipv4Addr, Arc<VpnPortalClient<V>>>,
}

impl<V> Default for VpnPortalClientTable<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<V> VpnPortalClientTable<V> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn endpoint_addrs(&self) -> Vec<Option<url::Url>> {
        self.entries
            .iter()
            .map(|entry| entry.value().endpoint_addr.clone())
            .collect()
    }

    pub fn route_peer_packet(&self, packet: &ZCPacket) -> VpnPortalPeerPacketRoute<V> {
        let Some(header) = packet.peer_manager_header() else {
            return VpnPortalPeerPacketRoute::Pass;
        };
        if header.packet_type != PacketType::Data as u8 {
            return VpnPortalPeerPacketRoute::Pass;
        }

        let payload = packet.payload();
        if payload.len() < IPV4_HEADER_LEN {
            return VpnPortalPeerPacketRoute::Drop;
        }
        if payload[0] >> 4 != 4 {
            return VpnPortalPeerPacketRoute::Pass;
        }
        let destination = ipv4_address(&payload[16..20]);
        let Some(client) = self
            .entries
            .get(&destination)
            .map(|entry| entry.value().clone())
        else {
            return VpnPortalPeerPacketRoute::Pass;
        };

        VpnPortalPeerPacketRoute::Deliver {
            destination,
            client,
        }
    }

    fn insert(&self, address: Ipv4Addr, client: Arc<VpnPortalClient<V>>) {
        self.entries.insert(address, client);
    }

    fn remove_if_endpoint(&self, address: &Ipv4Addr, endpoint_addr: &Option<url::Url>) -> bool {
        let removed = self
            .entries
            .remove_if(address, |_, client| &client.endpoint_addr == endpoint_addr)
            .is_some();
        if self.entries.capacity() - self.entries.len() > 16 {
            self.entries.shrink_to_fit();
        }
        removed
    }
}

pub enum VpnPortalPeerPacketRoute<V> {
    Pass,
    Drop,
    Deliver {
        destination: Ipv4Addr,
        client: Arc<VpnPortalClient<V>>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VpnPortalClientPacket {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VpnPortalClientRemoval {
    NotRegistered,
    Removed(Ipv4Addr),
    EntryChangedOrMissing(Ipv4Addr),
}

pub struct VpnPortalClientSession<V> {
    table: Arc<VpnPortalClientTable<V>>,
    client: Arc<VpnPortalClient<V>>,
    registered_ip: Option<Ipv4Addr>,
}

impl<V> VpnPortalClientSession<V> {
    pub fn new(
        table: Arc<VpnPortalClientTable<V>>,
        endpoint_addr: Option<url::Url>,
        value: V,
    ) -> Self {
        Self {
            table,
            client: Arc::new(VpnPortalClient {
                endpoint_addr,
                value,
            }),
            registered_ip: None,
        }
    }

    pub fn observe_ipv4_payload(&mut self, payload: &[u8]) -> Option<VpnPortalClientPacket> {
        if payload.len() < IPV4_HEADER_LEN {
            return None;
        }
        let packet = VpnPortalClientPacket {
            source: ipv4_address(&payload[12..16]),
            destination: ipv4_address(&payload[16..20]),
        };

        if self.registered_ip.is_none() {
            self.table.insert(packet.source, self.client.clone());
            self.registered_ip = Some(packet.source);
        }
        Some(packet)
    }

    pub fn registered_ip(&self) -> Option<Ipv4Addr> {
        self.registered_ip
    }

    pub fn close(&mut self) -> VpnPortalClientRemoval {
        let Some(address) = self.registered_ip.take() else {
            return VpnPortalClientRemoval::NotRegistered;
        };
        if self
            .table
            .remove_if_endpoint(&address, &self.client.endpoint_addr)
        {
            VpnPortalClientRemoval::Removed(address)
        } else {
            VpnPortalClientRemoval::EntryChangedOrMissing(address)
        }
    }
}

fn ipv4_address(bytes: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_payload(source: [u8; 4], destination: [u8; 4], version: u8) -> Vec<u8> {
        let mut payload = vec![0u8; IPV4_HEADER_LEN];
        payload[0] = version << 4 | 5;
        payload[12..16].copy_from_slice(&source);
        payload[16..20].copy_from_slice(&destination);
        payload
    }

    fn peer_packet(payload: &[u8], packet_type: PacketType) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(payload);
        packet.fill_peer_manager_hdr(1, 2, packet_type as u8);
        packet
    }

    #[test]
    fn session_registers_first_source_and_routes_peer_packet() {
        let table = Arc::new(VpnPortalClientTable::new());
        let endpoint = Some("wg://198.51.100.2:51820".parse().unwrap());
        let mut session = VpnPortalClientSession::new(table.clone(), endpoint, "client");

        let observed = session
            .observe_ipv4_payload(&ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4))
            .unwrap();
        assert_eq!(observed.source, Ipv4Addr::new(10, 10, 0, 2));
        assert_eq!(session.registered_ip(), Some(observed.source));

        let packet = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Data,
        );
        let VpnPortalPeerPacketRoute::Deliver {
            destination,
            client,
        } = table.route_peer_packet(&packet)
        else {
            panic!("registered destination must be delivered");
        };
        assert_eq!(destination, observed.source);
        assert_eq!(client.value(), &"client");
    }

    #[test]
    fn closing_old_endpoint_does_not_remove_replacement() {
        let table = Arc::new(VpnPortalClientTable::new());
        let payload = ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4);
        let mut old = VpnPortalClientSession::new(
            table.clone(),
            Some("wg://198.51.100.2:51820".parse().unwrap()),
            "old",
        );
        let mut replacement = VpnPortalClientSession::new(
            table.clone(),
            Some("wg://198.51.100.3:51820".parse().unwrap()),
            "replacement",
        );
        old.observe_ipv4_payload(&payload).unwrap();
        replacement.observe_ipv4_payload(&payload).unwrap();

        assert_eq!(
            old.close(),
            VpnPortalClientRemoval::EntryChangedOrMissing(Ipv4Addr::new(10, 10, 0, 2))
        );
        assert_eq!(table.len(), 1);

        let routed = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Data,
        );
        let VpnPortalPeerPacketRoute::Deliver { client, .. } = table.route_peer_packet(&routed)
        else {
            panic!("replacement must remain registered");
        };
        assert_eq!(client.value(), &"replacement");
    }

    #[test]
    fn close_removes_matching_entry_and_non_data_packets_pass() {
        let table = Arc::new(VpnPortalClientTable::new());
        let mut session = VpnPortalClientSession::new(table.clone(), None, ());
        session
            .observe_ipv4_payload(&ipv4_payload([10, 10, 0, 2], [10, 10, 0, 3], 4))
            .unwrap();

        let non_data = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 4),
            PacketType::Ping,
        );
        assert!(matches!(
            table.route_peer_packet(&non_data),
            VpnPortalPeerPacketRoute::Pass
        ));
        assert_eq!(
            session.close(),
            VpnPortalClientRemoval::Removed(Ipv4Addr::new(10, 10, 0, 2))
        );
        assert!(table.is_empty());
    }

    #[test]
    fn peer_route_rejects_non_ipv4_payload() {
        let table = VpnPortalClientTable::<()>::new();
        let packet = peer_packet(
            &ipv4_payload([10, 10, 0, 3], [10, 10, 0, 2], 6),
            PacketType::Data,
        );
        assert!(matches!(
            table.route_peer_packet(&packet),
            VpnPortalPeerPacketRoute::Pass
        ));
    }

    #[test]
    fn peer_route_drops_short_data_payload() {
        let table = VpnPortalClientTable::<()>::new();
        let packet = peer_packet(&[0u8; IPV4_HEADER_LEN - 1], PacketType::Data);
        assert!(matches!(
            table.route_peer_packet(&packet),
            VpnPortalPeerPacketRoute::Drop
        ));
    }
}

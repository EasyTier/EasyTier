pub(crate) mod protocol;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use dashmap::{DashMap, mapref::entry::Entry};

#[cfg(feature = "proxy-packet")]
use pnet_packet::{
    Packet, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket, udp::UdpPacket,
};

#[cfg(feature = "proxy-packet")]
use crate::gateway::proxy::ip_reassembler::{IpReassembler, SmolIpv4Packet};
#[cfg(feature = "proxy-packet")]
use crate::packet::{PacketType, ZCPacket};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socks5EntryCountChange {
    pub previous: usize,
    pub current: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socks5EntryInsert {
    pub replaced: bool,
    pub count: Socks5EntryCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socks5EntryRemoval {
    pub removed: bool,
    pub count: Socks5EntryCountChange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Socks5EntryRetain {
    pub removed: usize,
    pub count: Socks5EntryCountChange,
}

pub struct Socks5EntryTable<V> {
    entries: DashMap<Socks5Entry, V>,
    count: AtomicUsize,
}

pub struct Socks5EntryGuard<V> {
    table: Arc<Socks5EntryTable<V>>,
    entry: Socks5Entry,
    active: bool,
}

impl<V> Socks5EntryGuard<V> {
    pub fn register(
        table: Arc<Socks5EntryTable<V>>,
        entry: Socks5Entry,
        value: V,
    ) -> (Self, Socks5EntryInsert) {
        let insert = table.insert(entry.clone(), value);
        (
            Self {
                table,
                entry,
                active: true,
            },
            insert,
        )
    }

    pub fn try_register(
        table: Arc<Socks5EntryTable<V>>,
        entry: Socks5Entry,
        value: V,
    ) -> Option<Self> {
        if !table.try_insert(entry.clone(), value) {
            return None;
        }
        Some(Self {
            table,
            entry,
            active: true,
        })
    }
}

impl<V> Drop for Socks5EntryGuard<V> {
    fn drop(&mut self) {
        if self.active {
            self.table.remove(&self.entry);
        }
    }
}

impl<V> Default for Socks5EntryTable<V> {
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
            count: AtomicUsize::new(0),
        }
    }
}

impl<V> Socks5EntryTable<V> {
    pub fn count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains_key(&self, entry: &Socks5Entry) -> bool {
        self.entries.contains_key(entry)
    }

    pub fn contains_destination_ip(&self, destination: IpAddr) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.key().dst.ip() == destination)
    }

    pub fn with_entry<R>(&self, entry: &Socks5Entry, f: impl FnOnce(&V) -> R) -> Option<R> {
        self.entries.get(entry).map(|value| f(value.value()))
    }

    pub fn insert(&self, entry: Socks5Entry, value: V) -> Socks5EntryInsert {
        match self.entries.entry(entry) {
            Entry::Occupied(mut occupied) => {
                occupied.insert(value);
                let count = self.count();
                Socks5EntryInsert {
                    replaced: true,
                    count: Socks5EntryCountChange {
                        previous: count,
                        current: count,
                    },
                }
            }
            Entry::Vacant(vacant) => {
                // Reserve the count while holding the shard lock so retain cannot
                // observe the entry before its count is accounted for.
                let count = self.increment_count();
                vacant.insert(value);
                Socks5EntryInsert {
                    replaced: false,
                    count,
                }
            }
        }
    }

    pub fn try_insert(&self, entry: Socks5Entry, value: V) -> bool {
        match self.entries.entry(entry) {
            Entry::Occupied(_) => false,
            Entry::Vacant(vacant) => {
                self.increment_count();
                vacant.insert(value);
                true
            }
        }
    }

    pub fn remove(&self, entry: &Socks5Entry) -> Socks5EntryRemoval {
        let removed = self.entries.remove(entry).is_some();
        let count = if removed {
            self.decrement_count_by(1)
        } else {
            let count = self.count();
            Socks5EntryCountChange {
                previous: count,
                current: count,
            }
        };
        Socks5EntryRemoval { removed, count }
    }

    pub fn retain(&self, mut f: impl FnMut(&Socks5Entry, &mut V) -> bool) -> Socks5EntryRetain {
        let mut removed = 0;
        self.entries.retain(|entry, value| {
            let keep = f(entry, value);
            if !keep {
                removed += 1;
            }
            keep
        });
        Socks5EntryRetain {
            removed,
            count: self.decrement_count_by(removed),
        }
    }

    pub fn clear(&self) -> Socks5EntryRetain {
        self.retain(|_, _| false)
    }

    pub fn shrink_to_fit(&self) {
        self.entries.shrink_to_fit();
    }

    fn increment_count(&self) -> Socks5EntryCountChange {
        let previous = self
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                count.checked_add(1)
            })
            .unwrap_or_else(|count| count);
        Socks5EntryCountChange {
            previous,
            current: previous.saturating_add(1),
        }
    }

    fn decrement_count_by(&self, delta: usize) -> Socks5EntryCountChange {
        if delta == 0 {
            let count = self.count();
            return Socks5EntryCountChange {
                previous: count,
                current: count,
            };
        }

        let previous = self
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_sub(delta))
            })
            .unwrap_or_else(|count| count);
        Socks5EntryCountChange {
            previous,
            current: previous.saturating_sub(delta),
        }
    }
}

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Socks5PeerPacketRoute {
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

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Socks5TcpRoute {
    Kernel,
    Smoltcp,
    Kcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Socks5TcpConnectPlan {
    destination: SocketAddr,
    has_smoltcp_net: bool,
    kcp_available: bool,
}

impl Socks5TcpConnectPlan {
    pub fn new(
        destination: SocketAddr,
        local_virtual_ip: Option<IpAddr>,
        has_smoltcp_net: bool,
        kcp_available: bool,
    ) -> Self {
        let destination = if local_virtual_ip == Some(destination.ip()) {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), destination.port())
        } else {
            destination
        };

        Self {
            destination,
            has_smoltcp_net,
            kcp_available,
        }
    }

    pub fn destination(self) -> SocketAddr {
        self.destination
    }

    pub fn needs_virtual_network_lookup(self) -> bool {
        self.has_smoltcp_net && !self.destination.ip().is_loopback()
    }

    pub fn route(
        self,
        destination_in_virtual_network: bool,
        destination_allows_kcp: bool,
    ) -> Socks5TcpRoute {
        if !self.needs_virtual_network_lookup() || !destination_in_virtual_network {
            Socks5TcpRoute::Kernel
        } else if self.kcp_available && destination_allows_kcp {
            Socks5TcpRoute::Kcp
        } else {
            Socks5TcpRoute::Smoltcp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Socks5Entry, Socks5EntryGuard, Socks5EntryKind, Socks5EntryTable, Socks5TcpConnectPlan,
        Socks5TcpRoute,
    };

    #[cfg(feature = "proxy-packet")]
    use super::{ClassifiedSocks5PeerPacket, Socks5PeerPacketRoute, classify_peer_ipv4_payload};
    #[cfg(feature = "proxy-packet")]
    use crate::packet::{PacketType, ZCPacket};
    #[cfg(feature = "proxy-packet")]
    use pnet_packet::{
        MutablePacket,
        ip::IpNextHeaderProtocols,
        ipv4::MutableIpv4Packet,
        tcp::{MutableTcpPacket, TcpFlags},
        udp::MutableUdpPacket,
    };
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        sync::Arc,
    };

    impl<V> Socks5EntryGuard<V> {
        fn remove(mut self) -> super::Socks5EntryRemoval {
            self.active = false;
            self.table.remove(&self.entry)
        }
    }

    #[test]
    fn entry_kind_values_preserve_native_table_identity() {
        assert_eq!(Socks5EntryKind::Udp as u8, 1);
        assert_eq!(Socks5EntryKind::Tcp as u8, 2);
        assert_eq!(Socks5EntryKind::TcpListen as u8, 3);
    }

    fn table_entry(port: u16) -> Socks5Entry {
        Socks5Entry {
            src: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 2)), port),
            dst: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 42, 0, 1)), 22),
            kind: Socks5EntryKind::Tcp,
        }
    }

    #[test]
    fn entry_table_tracks_insert_replace_and_remove() {
        let table = Socks5EntryTable::default();
        let entry = table_entry(40000);

        let inserted = table.insert(entry.clone(), "first");
        assert!(!inserted.replaced);
        assert_eq!(inserted.count.previous, 0);
        assert_eq!(inserted.count.current, 1);
        assert_eq!(table.with_entry(&entry, |value| *value), Some("first"));

        let replaced = table.insert(entry.clone(), "second");
        assert!(replaced.replaced);
        assert_eq!(replaced.count.previous, 1);
        assert_eq!(replaced.count.current, 1);
        assert_eq!(table.with_entry(&entry, |value| *value), Some("second"));

        let removed = table.remove(&entry);
        assert!(removed.removed);
        assert_eq!(removed.count.previous, 1);
        assert_eq!(removed.count.current, 0);

        let missing = table.remove(&entry);
        assert!(!missing.removed);
        assert_eq!(missing.count.previous, 0);
        assert_eq!(missing.count.current, 0);
    }

    #[test]
    fn entry_table_try_insert_and_retain_keep_count_consistent() {
        let table = Socks5EntryTable::default();
        let first = table_entry(40000);
        let second = table_entry(40001);

        assert!(table.try_insert(first.clone(), 1));
        assert!(!table.try_insert(first.clone(), 2));
        assert!(table.try_insert(second.clone(), 3));
        assert_eq!(table.count(), 2);
        assert!(table.contains_destination_ip(first.dst.ip()));

        let retained = table.retain(|entry, _| entry == &second);
        assert_eq!(retained.removed, 1);
        assert_eq!(retained.count.previous, 2);
        assert_eq!(retained.count.current, 1);
        assert!(!table.contains_key(&first));
        assert!(table.contains_key(&second));

        let cleared = table.clear();
        assert_eq!(cleared.removed, 1);
        assert_eq!(cleared.count.current, 0);
        assert!(table.is_empty());
    }

    #[test]
    fn entry_guard_owns_registration_lifetime() {
        let table = Arc::new(Socks5EntryTable::default());
        let entry = table_entry(40000);

        let (guard, insert) = Socks5EntryGuard::register(table.clone(), entry.clone(), "first");
        assert!(!insert.replaced);
        assert!(table.contains_key(&entry));
        assert!(Socks5EntryGuard::try_register(table.clone(), entry.clone(), "second").is_none());
        assert_eq!(table.with_entry(&entry, |value| *value), Some("first"));

        drop(guard);
        assert!(!table.contains_key(&entry));

        let guard = Socks5EntryGuard::try_register(table.clone(), entry.clone(), "third").unwrap();
        let removal = guard.remove();
        assert!(removal.removed);
        assert_eq!(table.count(), 0);
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    fn virtual_destination(kcp_available: bool) -> Socks5TcpConnectPlan {
        Socks5TcpConnectPlan::new("10.1.1.2:443".parse().unwrap(), None, true, kcp_available)
    }

    #[test]
    fn kernel_route_covers_non_virtual_destinations() {
        assert_eq!(
            Socks5TcpConnectPlan::new("10.1.1.2:443".parse().unwrap(), None, false, false)
                .route(false, false),
            Socks5TcpRoute::Kernel
        );
        assert_eq!(
            virtual_destination(false).route(false, false),
            Socks5TcpRoute::Kernel
        );
    }

    #[test]
    fn kernel_route_covers_loopback_destination() {
        let plan = Socks5TcpConnectPlan::new("127.0.0.1:443".parse().unwrap(), None, true, true);

        assert!(!plan.needs_virtual_network_lookup());
        assert_eq!(plan.route(true, true), Socks5TcpRoute::Kernel);
    }

    #[test]
    fn virtual_route_uses_smoltcp_without_allowed_kcp() {
        assert_eq!(
            virtual_destination(false).route(true, false),
            Socks5TcpRoute::Smoltcp
        );
        assert_eq!(
            virtual_destination(true).route(true, false),
            Socks5TcpRoute::Smoltcp
        );
    }

    #[test]
    fn virtual_route_uses_kcp_only_when_available_and_allowed() {
        assert_eq!(
            virtual_destination(true).route(true, true),
            Socks5TcpRoute::Kcp
        );
    }

    #[test]
    fn local_virtual_destination_is_normalized_before_route_lookup() {
        let plan = Socks5TcpConnectPlan::new(
            "10.1.1.1:443".parse().unwrap(),
            Some("10.1.1.1".parse().unwrap()),
            true,
            true,
        );

        assert_eq!(plan.destination(), "127.0.0.1:443".parse().unwrap());
        assert!(!plan.needs_virtual_network_lookup());
        assert_eq!(plan.route(true, true), Socks5TcpRoute::Kernel);
    }
}

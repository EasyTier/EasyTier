use std::{collections::BTreeMap, net::Ipv4Addr, sync::Mutex, time::Duration};

use async_trait::async_trait;
use quanta::Instant;

#[cfg(feature = "proxy-packet")]
use std::future::Future;

#[cfg(feature = "proxy-packet")]
use pnet_packet::{
    MutablePacket, Packet,
    icmp::{self, IcmpPacket, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
};

#[cfg(feature = "proxy-packet")]
use crate::{
    config::PeerId,
    packet::ZCPacket,
    peers::{BoxNicPacketFilter, NicPacketFilter},
};

#[cfg(feature = "proxy-packet")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsQuery {
    pub source: std::net::SocketAddr,
    pub payload: Vec<u8>,
}

#[cfg(feature = "proxy-packet")]
#[async_trait]
pub trait MagicDnsQueryResolver: Send + Sync + 'static {
    async fn resolve(&self, query: MagicDnsQuery) -> Option<Vec<u8>>;
}

/// Owns one Magic DNS resolver installed in the core NIC pipeline.
///
/// `close` waits until readers that may already be invoking the resolver have
/// finished, then removes the entry so the resolver can be dropped promptly.
#[cfg(feature = "proxy-packet")]
pub struct MagicDnsResolverRegistration {
    peer_manager: std::sync::Weak<crate::peers::peer_manager::PeerManagerCore>,
    pipeline: crate::peers::peer_manager::PipelineRegistrationGuard,
    runtime: tokio::runtime::Handle,
}

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
struct MagicDnsPacketFilter {
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,
    resolver: std::sync::Arc<dyn MagicDnsQueryResolver>,
}

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
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

#[cfg(feature = "proxy-packet")]
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRoute {
    pub hostname: String,
    pub ipv4_addr: Option<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRouteSnapshot {
    pub revision: Instant,
    pub routes: Vec<MagicDnsRouteAdvertisement>,
    pub zone: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRouteAdvertisement {
    pub hostname: String,
    pub ipv4_addr: Option<crate::proto::common::Ipv4Inet>,
}

#[async_trait]
pub trait MagicDnsRouteSource: Send + Sync {
    async fn snapshot(&self) -> MagicDnsRouteSnapshot;
    async fn revision(&self) -> Instant;
}

#[async_trait]
pub trait MagicDnsRoutePublisher: Send {
    async fn handshake(&mut self) -> anyhow::Result<()>;
    async fn heartbeat(&mut self) -> anyhow::Result<()>;
    async fn publish(&mut self, snapshot: &MagicDnsRouteSnapshot) -> anyhow::Result<()>;
}

pub async fn run_magic_dns_route_publisher<S, P>(
    source: &S,
    publisher: &mut P,
    unchanged_interval: Duration,
) -> anyhow::Result<()>
where
    S: MagicDnsRouteSource + ?Sized,
    P: MagicDnsRoutePublisher + ?Sized,
{
    let mut published_revision = None;
    publisher.handshake().await?;
    loop {
        publisher.heartbeat().await?;

        let snapshot = source.snapshot().await;
        if published_revision == Some(snapshot.revision) {
            crate::foundation::time::sleep(unchanged_interval).await;
            continue;
        }

        publisher.publish(&snapshot).await?;
        if source.revision().await == snapshot.revision {
            published_revision = Some(snapshot.revision);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsRecordSnapshot {
    pub zones: BTreeMap<String, Vec<MagicDnsRoute>>,
}

#[derive(Debug, Default)]
pub struct MagicDnsRecordStore {
    zones: Mutex<BTreeMap<String, BTreeMap<String, Vec<MagicDnsRoute>>>>,
}

impl MagicDnsRecordStore {
    /// Replaces one client's routes within a zone.
    ///
    /// Returns `true` when the update removed the final client from an
    /// existing zone. The host can use that signal to keep an empty zone
    /// authoritative.
    pub fn replace_client_routes(
        &self,
        zone: String,
        client: String,
        routes: Vec<MagicDnsRoute>,
    ) -> bool {
        let mut zones = self.zones.lock().unwrap();
        let Some(routes_by_client) = zones.get_mut(&zone) else {
            if !routes.is_empty() {
                zones.entry(zone).or_default().insert(client, routes);
            }
            return false;
        };

        routes_by_client.remove(&client);
        if !routes.is_empty() {
            routes_by_client.insert(client, routes);
        }
        if !routes_by_client.is_empty() {
            return false;
        }
        zones.remove(&zone);
        true
    }

    /// Removes a disconnected client from every zone and returns the zones
    /// that became empty.
    pub fn remove_client(&self, client: &str) -> Vec<String> {
        let mut zones = self.zones.lock().unwrap();
        let mut removed_zones = Vec::new();
        zones.retain(|zone, routes_by_client| {
            routes_by_client.remove(client);
            let retain = !routes_by_client.is_empty();
            if !retain {
                removed_zones.push(zone.clone());
            }
            retain
        });
        removed_zones
    }

    pub fn snapshot(&self) -> MagicDnsRecordSnapshot {
        let zones = self.zones.lock().unwrap();
        MagicDnsRecordSnapshot {
            zones: zones
                .iter()
                .map(|(zone, routes_by_client)| {
                    (
                        zone.clone(),
                        routes_by_client
                            .values()
                            .flat_map(|routes| routes.iter().cloned())
                            .collect(),
                    )
                })
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    struct TestRouteSource {
        revision: Mutex<Instant>,
    }

    #[async_trait]
    impl MagicDnsRouteSource for TestRouteSource {
        async fn snapshot(&self) -> MagicDnsRouteSnapshot {
            MagicDnsRouteSnapshot {
                revision: *self.revision.lock().unwrap(),
                routes: vec![MagicDnsRouteAdvertisement {
                    hostname: "node-a".to_owned(),
                    ipv4_addr: Some("10.1.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                }],
                zone: "et.net.".to_owned(),
            }
        }

        async fn revision(&self) -> Instant {
            *self.revision.lock().unwrap()
        }
    }

    struct TestRoutePublisher {
        source: Arc<TestRouteSource>,
        heartbeat_calls: usize,
        fail_heartbeat_at: usize,
        change_revision_on_first_publish: bool,
        handshake_calls: usize,
        snapshots: Vec<MagicDnsRouteSnapshot>,
    }

    #[async_trait]
    impl MagicDnsRoutePublisher for TestRoutePublisher {
        async fn handshake(&mut self) -> anyhow::Result<()> {
            self.handshake_calls += 1;
            Ok(())
        }

        async fn heartbeat(&mut self) -> anyhow::Result<()> {
            self.heartbeat_calls += 1;
            if self.heartbeat_calls == self.fail_heartbeat_at {
                anyhow::bail!("stop test publisher");
            }
            Ok(())
        }

        async fn publish(&mut self, snapshot: &MagicDnsRouteSnapshot) -> anyhow::Result<()> {
            self.snapshots.push(snapshot.clone());
            if self.change_revision_on_first_publish && self.snapshots.len() == 1 {
                *self.source.revision.lock().unwrap() = snapshot.revision + Duration::from_secs(1);
            }
            Ok(())
        }
    }

    fn test_publisher(source: Arc<TestRouteSource>) -> TestRoutePublisher {
        TestRoutePublisher {
            source,
            heartbeat_calls: 0,
            fail_heartbeat_at: 3,
            change_revision_on_first_publish: false,
            handshake_calls: 0,
            snapshots: Vec::new(),
        }
    }

    #[tokio::test]
    async fn route_publisher_skips_unchanged_snapshot() {
        let source = Arc::new(TestRouteSource {
            revision: Mutex::new(Instant::now()),
        });
        let mut publisher = test_publisher(source.clone());

        let error = run_magic_dns_route_publisher(
            source.as_ref(),
            &mut publisher,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("stop test publisher"));
        assert_eq!(publisher.handshake_calls, 1);
        assert_eq!(publisher.snapshots.len(), 1);
    }

    #[tokio::test]
    async fn route_publisher_retries_change_during_publish() {
        let source = Arc::new(TestRouteSource {
            revision: Mutex::new(Instant::now()),
        });
        let mut publisher = test_publisher(source.clone());
        publisher.change_revision_on_first_publish = true;

        let error = run_magic_dns_route_publisher(
            source.as_ref(),
            &mut publisher,
            Duration::from_millis(1),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("stop test publisher"));
        assert_eq!(publisher.snapshots.len(), 2);
        assert_ne!(
            publisher.snapshots[0].revision,
            publisher.snapshots[1].revision
        );
    }

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    fn route(hostname: &str, addr: [u8; 4]) -> MagicDnsRoute {
        MagicDnsRoute {
            hostname: hostname.to_owned(),
            ipv4_addr: Some(addr.into()),
        }
    }

    #[test]
    fn replaces_routes_for_the_same_client_without_touching_other_clients() {
        let store = MagicDnsRecordStore::default();
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("old-a", [10, 0, 0, 1])],
        ));
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        ));
        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("new-a", [10, 0, 0, 3])],
        ));

        let routes = &store.snapshot().zones["et.net."];
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|route| route.hostname == "new-a"));
        assert!(routes.iter().any(|route| route.hostname == "peer-b"));
        assert!(!routes.iter().any(|route| route.hostname == "old-a"));
    }

    #[test]
    fn empty_update_removes_only_the_target_client_and_reports_empty_zone() {
        let store = MagicDnsRecordStore::default();
        store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            vec![route("peer-a", [10, 0, 0, 1])],
        );
        store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert!(!store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-a".to_owned(),
            Vec::new(),
        ));
        assert!(store.replace_client_routes(
            "et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            Vec::new(),
        ));
        assert!(store.snapshot().zones.is_empty());
    }

    #[test]
    fn disconnect_removes_client_from_all_zones() {
        let store = MagicDnsRecordStore::default();
        for zone in ["a.et.net.", "b.et.net."] {
            store.replace_client_routes(
                zone.to_owned(),
                "tcp://client-a".to_owned(),
                vec![route("peer-a", [10, 0, 0, 1])],
            );
        }
        store.replace_client_routes(
            "b.et.net.".to_owned(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert_eq!(
            store.remove_client("tcp://client-a"),
            vec!["a.et.net.".to_owned()]
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones.len(), 1);
        assert_eq!(snapshot.zones["b.et.net."][0].hostname, "peer-b");
    }

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

    #[cfg(feature = "proxy-packet")]
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

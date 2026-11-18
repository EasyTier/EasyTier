use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use futures::future::BoxFuture;
use smoltcp::wire::{
    IPV4_HEADER_LEN, Icmpv4Message, Icmpv4Packet, IpAddress, IpProtocol, Ipv4Packet,
    UDP_HEADER_LEN, UdpPacket,
};

use crate::{
    config::PeerId,
    packet::ZCPacket,
    peers::{BoxNicPacketFilter, NicPacketFilter, PacketRecvChan},
};
use tokio::{sync::Semaphore, task::JoinSet};

const MAX_CONCURRENT_FORWARDS: usize = 64;
const MAX_CONCURRENT_QUERIES: usize = 2 * MAX_CONCURRENT_FORWARDS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MagicDnsQuery {
    pub source: std::net::SocketAddr,
    pub payload: Vec<u8>,
}

#[async_trait]
pub trait MagicDnsQueryResolver: Send + Sync + 'static {
    /// Select the authority once. Local answers finish here; upstream I/O is
    /// deferred until the query has a forwarding permit.
    async fn resolve(&self, query: MagicDnsQuery) -> MagicDnsQueryResult;

    /// Answer an unadmitted query without consulting an authority.
    fn overload_response(&self, query: &MagicDnsQuery) -> Option<Vec<u8>>;
}

pub enum MagicDnsQueryResult {
    Response(Option<Vec<u8>>),
    Forward {
        response: BoxFuture<'static, Option<Vec<u8>>>,
        overload_response: Vec<u8>,
    },
}

pub(crate) struct MagicDnsResolverState {
    // None closes both admission and reply delivery under the same lock.
    tasks: Mutex<Option<JoinSet<()>>>,
    forwards: Semaphore,
    replies: PacketRecvChan,
    my_peer_id: PeerId,
}

impl MagicDnsResolverState {
    pub(crate) fn new(replies: PacketRecvChan, my_peer_id: PeerId) -> Arc<Self> {
        Arc::new(Self {
            tasks: Mutex::new(Some(JoinSet::new())),
            forwards: Semaphore::new(MAX_CONCURRENT_FORWARDS),
            replies,
            my_peer_id,
        })
    }

    fn stop(&self) -> JoinSet<()> {
        let mut tasks = self.tasks.lock().unwrap().take().unwrap_or_default();
        tasks.abort_all();
        tasks
    }

    fn reply(&self, mut packet: ZCPacket, info: MagicDnsPacketInfo, response: Option<&[u8]>) {
        let tasks = self.tasks.lock().unwrap();
        if tasks.is_none() {
            return;
        }
        if info.apply_response(&mut packet, self.my_peer_id, response) {
            // Keep the original peer receive pipeline (including ACL) without
            // awaiting capacity or creating detached delivery tasks.
            self.replies.try_send(packet);
        }
    }

    fn submit(
        self: &Arc<Self>,
        packet: ZCPacket,
        info: MagicDnsPacketInfo,
        query: MagicDnsQuery,
        resolver: Arc<dyn MagicDnsQueryResolver>,
    ) {
        let mut guard = self.tasks.lock().unwrap();
        let Some(tasks) = guard.as_mut() else {
            return;
        };
        while tasks.try_join_next().is_some() {}
        if tasks.len() >= MAX_CONCURRENT_QUERIES {
            drop(guard);
            let response = resolver.overload_response(&query);
            self.reply(packet, info, response.as_deref());
            return;
        }
        let state = self.clone();
        tasks.spawn(async move {
            let response = match resolver.resolve(query).await {
                MagicDnsQueryResult::Response(response) => response,
                MagicDnsQueryResult::Forward {
                    response,
                    overload_response,
                } => match state.forwards.try_acquire() {
                    Ok(_permit) => response.await,
                    Err(_) => Some(overload_response),
                },
            };
            state.reply(packet, info, response.as_deref());
        });
    }
}

/// Owns one Magic DNS resolver installed in the core NIC pipeline.
///
/// `close` unregisters the filter, stops admission and delivery, then cancels
/// and drains its DNS queries. Already queued replies remain queued.
pub struct MagicDnsResolverRegistration {
    pipeline: crate::peers::peer_manager::PipelineRegistrationGuard,
    state: Arc<MagicDnsResolverState>,
}

impl MagicDnsResolverRegistration {
    pub(crate) fn new(
        pipeline: crate::peers::peer_manager::PipelineRegistrationGuard,
        state: Arc<MagicDnsResolverState>,
    ) -> Self {
        Self { pipeline, state }
    }

    pub async fn close(self) {
        self.pipeline.close();
        let mut tasks = self.state.stop();
        while tasks.join_next().await.is_some() {}
    }
}

impl Drop for MagicDnsResolverRegistration {
    fn drop(&mut self) {
        self.pipeline.close();
        self.state.stop();
    }
}

struct MagicDnsPacketFilter {
    fake_ip: Ipv4Addr,
    resolver: std::sync::Arc<dyn MagicDnsQueryResolver>,
    state: Arc<MagicDnsResolverState>,
}

pub(crate) fn magic_dns_packet_filter(
    fake_ip: Ipv4Addr,
    resolver: std::sync::Arc<dyn MagicDnsQueryResolver>,
    state: Arc<MagicDnsResolverState>,
) -> BoxNicPacketFilter {
    Box::new(MagicDnsPacketFilter {
        fake_ip,
        resolver,
        state,
    })
}

#[async_trait]
impl NicPacketFilter for MagicDnsPacketFilter {
    async fn try_process_packet_from_nic(&self, packet: ZCPacket) -> Option<ZCPacket> {
        let Some(info) = MagicDnsPacketInfo::parse(&packet, self.fake_ip) else {
            return Some(packet);
        };
        let Some(query) = info.query(&packet) else {
            self.state.reply(packet, info, None);
            return None;
        };
        self.state
            .submit(packet, info, query, self.resolver.clone());
        None
    }

    fn id(&self) -> String {
        "magic_dns_server".to_owned()
    }
}

#[derive(Clone, Copy)]
struct MagicDnsPacketInfo {
    source_ip: Ipv4Addr,
    destination_ip: Ipv4Addr,
    ip_header_length: usize,
    udp_ports: Option<(u16, u16)>,
}

impl MagicDnsPacketInfo {
    fn parse(packet: &ZCPacket, fake_ip: Ipv4Addr) -> Option<Self> {
        packet.peer_manager_header()?;
        if packet.payload().len() < IPV4_HEADER_LEN {
            return None;
        }
        let ip = Ipv4Packet::new_unchecked(packet.payload());
        let header_length = ip.header_len() as usize;
        if ip.version() != 4
            || ip.dst_addr() != fake_ip
            || header_length < IPV4_HEADER_LEN
            || header_length > ip.total_len() as usize
            || ip.total_len() as usize != packet.payload().len()
            || ip.frag_offset() != 0
            || ip.more_frags()
        {
            return None;
        }
        let payload = &packet.payload()[header_length..];
        let udp_ports = match ip.next_header() {
            IpProtocol::Udp => {
                if payload.len() < UDP_HEADER_LEN {
                    return None;
                }
                let udp = UdpPacket::new_unchecked(payload);
                if udp.len() as usize != payload.len() || udp.dst_port() != 53 {
                    return None;
                }
                Some((udp.src_port(), udp.dst_port()))
            }
            IpProtocol::Icmp => {
                let icmp = Icmpv4Packet::new_checked(payload).ok()?;
                if icmp.msg_type() != Icmpv4Message::EchoRequest {
                    return None;
                }
                None
            }
            _ => return None,
        };
        Some(Self {
            source_ip: ip.src_addr(),
            destination_ip: ip.dst_addr(),
            ip_header_length: header_length,
            udp_ports,
        })
    }

    fn query(&self, packet: &ZCPacket) -> Option<MagicDnsQuery> {
        let (source_port, _) = self.udp_ports?;
        Some(MagicDnsQuery {
            source: (self.source_ip, source_port).into(),
            payload: packet.payload()[self.ip_header_length + UDP_HEADER_LEN..].to_vec(),
        })
    }

    fn apply_response(
        &self,
        packet: &mut ZCPacket,
        my_peer_id: PeerId,
        response: Option<&[u8]>,
    ) -> bool {
        if let Some((source_port, destination_port)) = self.udp_ports {
            let Some(response) = response else {
                return false;
            };
            if !apply_udp_response(
                packet,
                self.source_ip,
                self.destination_ip,
                source_port,
                destination_port,
                self.ip_header_length,
                response,
            ) {
                return false;
            }
        } else {
            let mut icmp =
                Icmpv4Packet::new_unchecked(&mut packet.mut_payload()[self.ip_header_length..]);
            icmp.set_msg_type(Icmpv4Message::EchoReply);
            icmp.fill_checksum();
        }
        let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
        ip.set_src_addr(self.destination_ip);
        ip.set_dst_addr(self.source_ip);
        ip.fill_checksum();
        let payload_length = packet.payload().len() as u32;
        let header = packet.mut_peer_manager_header().unwrap();
        header.to_peer_id = my_peer_id.into();
        header.len.set(payload_length);
        true
    }
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::Notify;

    struct ActiveQuery(Arc<AtomicUsize>);

    impl Drop for ActiveQuery {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }

    #[derive(Default)]
    struct SlowResolver {
        active: Arc<AtomicUsize>,
        release: Arc<Notify>,
    }

    #[async_trait]
    impl MagicDnsQueryResolver for SlowResolver {
        async fn resolve(&self, query: MagicDnsQuery) -> MagicDnsQueryResult {
            if query.payload == b"local" {
                return MagicDnsQueryResult::Response(Some(b"local answer".to_vec()));
            }
            if query.payload == b"blocked local" {
                self.active.fetch_add(1, Ordering::SeqCst);
                let _active = ActiveQuery(self.active.clone());
                self.release.notified().await;
                return MagicDnsQueryResult::Response(Some(b"late answer".to_vec()));
            }
            let active = self.active.clone();
            let release = self.release.clone();
            MagicDnsQueryResult::Forward {
                response: Box::pin(async move {
                    active.fetch_add(1, Ordering::SeqCst);
                    let _active = ActiveQuery(active);
                    release.notified().await;
                    Some(b"upstream answer".to_vec())
                }),
                overload_response: b"SERVFAIL".to_vec(),
            }
        }

        fn overload_response(&self, _query: &MagicDnsQuery) -> Option<Vec<u8>> {
            Some(b"SERVFAIL".to_vec())
        }
    }

    #[tokio::test]
    async fn saturated_forwarding_keeps_local_dns_icmp_and_other_packets_available() {
        let (sender, mut receiver) = crate::peers::create_packet_recv_chan();
        let state = MagicDnsResolverState::new(sender, 42);
        let resolver = Arc::new(SlowResolver::default());
        let filter = magic_dns_packet_filter(
            "100.100.100.101".parse().unwrap(),
            resolver.clone(),
            state.clone(),
        );
        for _ in 0..MAX_CONCURRENT_FORWARDS {
            assert!(
                filter
                    .try_process_packet_from_nic(udp_query(b"slow", 53))
                    .await
                    .is_none()
            );
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.active.load(Ordering::SeqCst) != MAX_CONCURRENT_FORWARDS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            resolver.active.load(Ordering::SeqCst),
            MAX_CONCURRENT_FORWARDS
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            filter
                .try_process_packet_from_nic(udp_query(b"overflow", 53))
                .await;
            filter
                .try_process_packet_from_nic(udp_query(b"local", 53))
                .await;
            filter
                .try_process_packet_from_nic(icmp_echo_request())
                .await;
            assert!(
                filter
                    .try_process_packet_from_nic(udp_query(b"ordinary", 54))
                    .await
                    .is_some()
            );
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut dns_answers = Vec::new();
            for _ in 0..3 {
                let packet = receiver.recv().await.unwrap();
                let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
                match ip.next_header() {
                    IpProtocol::Udp => dns_answers.push(
                        UdpPacket::new_checked(ip.payload())
                            .unwrap()
                            .payload()
                            .to_vec(),
                    ),
                    IpProtocol::Icmp => assert_eq!(
                        Icmpv4Packet::new_checked(ip.payload()).unwrap().msg_type(),
                        Icmpv4Message::EchoReply
                    ),
                    protocol => panic!("unexpected reply protocol {protocol}"),
                }
            }
            dns_answers.sort();
            assert_eq!(dns_answers, [b"SERVFAIL".as_slice(), b"local answer"]);
        })
        .await
        .unwrap();
        let mut tasks = state.stop();
        while tasks.join_next().await.is_some() {}
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
        filter
            .try_process_packet_from_nic(udp_query(b"local", 53))
            .await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), receiver.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn full_reply_queue_does_not_wait_or_create_delivery_tasks() {
        let (sender, mut receiver) = crate::peers::create_packet_recv_chan();
        let state = MagicDnsResolverState::new(sender.clone(), 42);
        while sender.try_send(ZCPacket::new_with_payload(b"queued")) {}
        let resolver = Arc::new(SlowResolver::default());
        let filter = magic_dns_packet_filter(
            "100.100.100.101".parse().unwrap(),
            resolver.clone(),
            state.clone(),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            filter
                .try_process_packet_from_nic(udp_query(b"local", 53))
                .await;
            filter
                .try_process_packet_from_nic(icmp_echo_request())
                .await;
        })
        .await
        .unwrap();
        filter
            .try_process_packet_from_nic(udp_query(b"forwarded", 53))
            .await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.active.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
            resolver.release.notify_waiters();
            loop {
                let finished = {
                    let mut guard = state.tasks.lock().unwrap();
                    let tasks = guard.as_mut().unwrap();
                    while tasks.try_join_next().is_some() {}
                    tasks.is_empty()
                };
                if finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
        let mut tasks = state.stop();
        assert!(tasks.join_next().await.is_none());
        drop(filter);
        drop(state);
        drop(sender);
        let mut queued = 0;
        while let Some(packet) = receiver.recv().await {
            assert_eq!(packet.payload(), b"queued");
            queued += 1;
        }
        assert_eq!(queued, 128);
    }

    #[tokio::test]
    async fn blocked_local_queries_leave_the_nic_available_and_are_cancelled_on_close() {
        let (sender, mut receiver) = crate::peers::create_packet_recv_chan();
        let state = MagicDnsResolverState::new(sender, 42);
        let resolver = Arc::new(SlowResolver::default());
        let filter = magic_dns_packet_filter(
            "100.100.100.101".parse().unwrap(),
            resolver.clone(),
            state.clone(),
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            for _ in 0..MAX_CONCURRENT_QUERIES {
                assert!(
                    filter
                        .try_process_packet_from_nic(udp_query(b"blocked local", 53))
                        .await
                        .is_none()
                );
            }
            while resolver.active.load(Ordering::SeqCst) != MAX_CONCURRENT_QUERIES {
                tokio::task::yield_now().await;
            }
            assert!(
                filter
                    .try_process_packet_from_nic(udp_query(b"ordinary", 54))
                    .await
                    .is_some()
            );
            filter
                .try_process_packet_from_nic(icmp_echo_request())
                .await;
            let echo = receiver.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(echo.payload()).unwrap();
            assert_eq!(
                Icmpv4Packet::new_checked(ip.payload()).unwrap().msg_type(),
                Icmpv4Message::EchoReply
            );
            filter
                .try_process_packet_from_nic(udp_query(b"overflow", 53))
                .await;
            let reply = receiver.recv().await.unwrap();
            let ip = Ipv4Packet::new_checked(reply.payload()).unwrap();
            assert_eq!(
                UdpPacket::new_checked(ip.payload()).unwrap().payload(),
                b"SERVFAIL"
            );
        })
        .await
        .unwrap();
        let mut tasks = state.stop();
        while tasks.join_next().await.is_some() {}
        assert_eq!(resolver.active.load(Ordering::SeqCst), 0);
        drop(filter);
        drop(state);
        assert!(receiver.recv().await.is_none());
    }

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
    #[test]
    fn packet_engine_rewrites_dns_query_response() {
        let mut packet = udp_query(b"query", 53);
        let info = MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).unwrap();
        let query = info.query(&packet).unwrap();
        assert_eq!(query.source, "10.0.0.2:53000".parse().unwrap());
        assert_eq!(query.payload, b"query");

        assert!(info.apply_response(&mut packet, 42, Some(b"response")));
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

    #[test]
    fn packet_engine_rejects_invalid_ipv4_header_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        Ipv4Packet::new_unchecked(packet.mut_payload()).set_header_len(60);
        let original = packet.payload().to_vec();

        assert!(MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).is_none());
        assert_eq!(packet.payload(), original);
    }

    #[test]
    fn packet_engine_rejects_short_zc_packet_without_panicking() {
        let packet = ZCPacket::new_from_buf(Default::default(), crate::packet::ZCPacketType::NIC);

        assert!(MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).is_none());
    }

    #[test]
    fn packet_engine_rejects_inconsistent_udp_length_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        let mut ip = Ipv4Packet::new_unchecked(packet.mut_payload());
        UdpPacket::new_unchecked(ip.payload_mut()).set_len(8);
        let original = packet.payload().to_vec();

        assert!(MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).is_none());
        assert_eq!(packet.payload(), original);
    }

    #[test]
    fn packet_engine_rejects_fragmented_packets_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        Ipv4Packet::new_unchecked(packet.mut_payload()).set_more_frags(true);
        let original = packet.payload().to_vec();

        assert!(MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).is_none());
        assert_eq!(packet.payload(), original);
    }

    #[test]
    fn packet_engine_rejects_oversized_response_without_mutation() {
        let mut packet = udp_query(b"query", 53);
        let original = packet.payload().to_vec();
        let original_length = packet.buf_len();

        let info = MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).unwrap();
        assert!(!info.apply_response(&mut packet, 42, Some(&vec![0; u16::MAX as usize])));
        assert_eq!(packet.buf_len(), original_length);
        assert_eq!(packet.payload(), original);
    }

    #[test]
    fn packet_engine_replies_to_icmp_without_calling_dns() {
        let mut packet = icmp_echo_request();
        let info = MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).unwrap();
        assert!(info.query(&packet).is_none());

        assert!(info.apply_response(&mut packet, 7, None));
        let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
        assert_eq!(
            ip.src_addr(),
            "100.100.100.101".parse::<Ipv4Addr>().unwrap()
        );
        let icmp = Icmpv4Packet::new_checked(ip.payload()).unwrap();
        assert_eq!(icmp.msg_type(), Icmpv4Message::EchoReply);
        assert_eq!(packet.get_dst_peer_id(), Some(7));
    }

    #[test]
    fn packet_engine_ignores_non_dns_udp() {
        let packet = udp_query(b"query", 5353);
        assert!(MagicDnsPacketInfo::parse(&packet, "100.100.100.101".parse().unwrap()).is_none());
    }
}

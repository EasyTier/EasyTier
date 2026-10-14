//! Route original UDP fragments together without assembling their payloads.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use ordered_hash_map::OrderedHashMap;
use smoltcp::wire::{Ipv4Packet, UDP_HEADER_LEN, UdpPacket};
use tokio::{sync::mpsc, time::Instant};

use super::{FlowKey, FlowSet, PeerPacketFilterResult};
use crate::packet::ZCPacket;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
struct UdpFragmentKey {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: u16,
    from_peer: u32,
    to_peer: u32,
    packet_type: u8,
    exit_node: bool,
    no_proxy: bool,
    not_send_to_tun: bool,
}

struct UdpFragmentRoute {
    entry: FlowKey,
    registration: Option<u64>,
}

struct UdpFragment {
    last_seen: Instant,
    route: Option<UdpFragmentRoute>,
    pending: Vec<ZCPacket>,
    bytes: usize,
}

impl UdpFragment {
    fn new(now: Instant) -> Self {
        Self {
            last_seen: now,
            route: None,
            pending: Vec::new(),
            bytes: 0,
        }
    }
}

#[derive(Default)]
pub(super) struct UdpFragments {
    local_ip: Option<Ipv4Addr>,
    packets: OrderedHashMap<UdpFragmentKey, UdpFragment>,
    bytes: usize,
}

impl UdpFragments {
    const CAPACITY: usize = 1024;
    // Budget retained packet bytes, not allocator overhead.
    const MAX_BYTES: usize = 1024 * 1024;
    // A shallow cache cannot detect completion. Randomizing each sending stack's
    // seed avoids deterministic IP ID reuse after a restart, but 16-bit IDs can
    // still collide. We accept occasional UDP loss or delivery to the cached
    // downstream route instead of tracking fragment ranges to detect completion.
    // Hits refresh this idle timeout, so repeated collisions can prolong it.
    // Expired/evicted unknown tails wait for a first fragment.
    const TIMEOUT: Duration = Duration::from_secs(1);

    pub(super) fn set_local_ip(&mut self, local_ip: Option<Ipv4Addr>) {
        if self.local_ip != local_ip {
            *self = Self {
                local_ip,
                ..Self::default()
            };
        }
    }

    fn evict_oldest(&mut self) {
        if let Some(packet) = self.packets.pop_front() {
            self.bytes -= packet.bytes;
        }
    }

    pub(super) fn remove_expired(&mut self) {
        let now = Instant::now();
        while self
            .packets
            .front()
            .is_some_and(|packet| now.duration_since(packet.last_seen) >= Self::TIMEOUT)
        {
            self.evict_oldest();
        }
    }

    pub(super) fn process(
        &mut self,
        packet: ZCPacket,
        local_ip: Option<Ipv4Addr>,
        flows: &FlowSet,
        sender: &mpsc::Sender<ZCPacket>,
    ) -> PeerPacketFilterResult {
        self.set_local_ip(local_ip);
        // The caller has already classified a valid IPv4 UDP fragment.
        let ip = Ipv4Packet::new_checked(packet.payload()).unwrap();
        if Some(ip.dst_addr()) != local_ip {
            return PeerPacketFilterResult::Pass(packet);
        }
        let payload = ip.payload();
        if !ip.verify_checksum()
            || payload.is_empty()
            || (ip.more_frags() && !payload.len().is_multiple_of(8))
            || usize::from(ip.frag_offset()) + payload.len() > usize::from(u16::MAX) - 20
        {
            return PeerPacketFilterResult::Consumed;
        }
        let port = if ip.frag_offset() == 0 {
            if payload.len() < UDP_HEADER_LEN {
                return PeerPacketFilterResult::Consumed;
            }
            // Its length covers the whole datagram, not just this fragment.
            let udp = UdpPacket::new_unchecked(payload);
            if usize::from(udp.len()) < UDP_HEADER_LEN {
                return PeerPacketFilterResult::Consumed;
            }
            Some(udp.dst_port())
        } else {
            None
        };
        let header = packet.peer_manager_header().unwrap();
        let key = UdpFragmentKey {
            source: ip.src_addr(),
            destination: ip.dst_addr(),
            id: ip.ident(),
            from_peer: header.from_peer_id.get(),
            to_peer: header.to_peer_id.get(),
            packet_type: header.packet_type,
            exit_node: header.is_exit_node(),
            no_proxy: header.is_no_proxy(),
            not_send_to_tun: header.is_not_send_to_tun(),
        };
        self.remove_expired();
        let now = Instant::now();
        let mut context = self
            .packets
            .get_mut(&key)
            .map(|context| std::mem::replace(context, UdpFragment::new(now)))
            .unwrap_or_else(|| UdpFragment::new(now));
        self.bytes -= context.bytes;
        context.last_seen = now;
        if context.route.is_none()
            && let Some(port) = port
        {
            let entry = FlowKey::udp_bind(SocketAddr::new(key.destination.into(), port));
            let registration = flows.registration(&entry);
            context.route = Some(UdpFragmentRoute {
                entry,
                registration,
            });
        }
        let result = if let Some(route) = &context.route {
            context.bytes = 0;
            // Preserve ownership across close/rebind, including downstream routes.
            if let Some(registration) = route.registration {
                if flows.registration(&route.entry) == Some(registration) {
                    for packet in std::iter::once(packet).chain(context.pending.drain(..)) {
                        if let Err(error) = sender.try_send(packet) {
                            tracing::trace!(?error, "data plane fragment queue full or closed");
                        }
                    }
                }
                context.pending = Vec::new();
                PeerPacketFilterResult::Consumed
            } else if context.pending.is_empty() {
                PeerPacketFilterResult::Pass(packet)
            } else {
                context.pending.push(packet);
                PeerPacketFilterResult::PassBatch(std::mem::take(&mut context.pending))
            }
        } else {
            context.bytes += packet.buf_len();
            context.pending.push(packet);
            PeerPacketFilterResult::Consumed
        };
        self.bytes += context.bytes;
        // Replacing an entry moves it to the back, keeping expiry and LRU order.
        self.packets.insert(key, context);
        while self.packets.len() > Self::CAPACITY || self.bytes > Self::MAX_BYTES {
            self.evict_oldest();
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::{
        FlowData, FlowTable,
        tests::{UDP_LOCAL_IP, build_udp_fragments},
    };
    use super::*;

    #[tokio::test]
    async fn recreated_sending_stack_does_not_replay_fragment_routes() {
        use super::super::stack::SmoltcpPlane;
        use crate::gateway::smoltcp::{Net, NetConfig, channel_device};

        let flows = Arc::new(FlowTable::default());
        let local = SocketAddr::new(UDP_LOCAL_IP.into(), 40000);
        flows.insert(FlowKey::udp_bind(local), FlowData::Udp);
        let (sender, mut receiver) = mpsc::channel(16);
        let mut cache = UdpFragments::default();
        // Use controlled seeds: random 16-bit IDs may legitimately collide.
        // Each iteration drops the old sender and creates a real new stack.
        for (seed, port) in [(1, 40001), (2, 40000)] {
            let mut capabilities = smoltcp::phy::DeviceCapabilities::default();
            capabilities.medium = smoltcp::phy::Medium::Ip;
            capabilities.max_transmission_unit = 1284;
            let (device, _input, mut output) = channel_device::ChannelDevice::new(capabilities);
            let net = Net::new(
                device,
                NetConfig::new(
                    SmoltcpPlane::interface_config(seed),
                    "10.144.144.3/24".parse().unwrap(),
                    Vec::new(),
                    None,
                ),
            );
            let socket = net
                .udp_bind("10.144.144.3:53".parse().unwrap())
                .await
                .unwrap();
            socket
                .send_to(&[0xab; 4096], SocketAddr::new(UDP_LOCAL_IP.into(), port))
                .await
                .unwrap();
            let mut count = 0;
            loop {
                let bytes = tokio::time::timeout(Duration::from_secs(1), output.recv())
                    .await
                    .unwrap()
                    .unwrap();
                let ip = Ipv4Packet::new_checked(bytes.as_slice()).unwrap();
                assert!(ip.more_frags() || ip.frag_offset() != 0);
                let last = !ip.more_frags();
                // Keep the old route live regardless of test-machine scheduling.
                for context in cache.packets.values_mut() {
                    context.last_seen = Instant::now();
                }
                let mut packet = ZCPacket::new_with_payload(&bytes);
                packet.fill_peer_manager_hdr(1, 2, crate::packet::PacketType::Data as u8);
                let result = cache.process(packet, Some(UDP_LOCAL_IP), &flows, &sender);
                if port == local.port() {
                    assert!(matches!(result, PeerPacketFilterResult::Consumed));
                    assert_eq!(receiver.try_recv().unwrap().payload(), bytes);
                } else {
                    assert!(matches!(result, PeerPacketFilterResult::Pass(_)));
                    assert!(receiver.try_recv().is_err());
                }
                count += 1;
                if last {
                    break;
                }
            }
            assert_eq!(count, 4);
        }
        assert_eq!(cache.packets.len(), 2);
    }

    #[test]
    fn routes_survive_binding_changes() {
        for bound in [false, true] {
            let flows = Arc::new(FlowTable::default());
            let entry = FlowKey::udp_bind(SocketAddr::new(UDP_LOCAL_IP.into(), 40000));
            if bound {
                flows.insert(entry.clone(), FlowData::Udp);
            }
            let (sender, mut receiver) = mpsc::channel(4);
            let mut cache = UdpFragments::default();
            let [first, tail] = build_udp_fragments();
            let result = cache.process(first, Some(UDP_LOCAL_IP), &flows, &sender);
            assert_eq!(matches!(result, PeerPacketFilterResult::Consumed), bound);
            if bound {
                receiver.try_recv().unwrap();
            }
            flows.clear();
            flows.insert(entry, FlowData::Udp);
            let result = cache.process(tail, Some(UDP_LOCAL_IP), &flows, &sender);
            assert_eq!(matches!(result, PeerPacketFilterResult::Consumed), bound);
            assert!(
                receiver.try_recv().is_err(),
                "old fragments reached a new binding"
            );
        }
    }

    #[test]
    fn cache_expires_and_resets_on_address_change() {
        let flows = Arc::new(FlowTable::default());
        let (sender, _receiver) = mpsc::channel(4);
        let mut cache = UdpFragments::default();
        let [first, tail] = build_udp_fragments();
        cache.process(tail.clone(), Some(UDP_LOCAL_IP), &flows, &sender);
        assert!(cache.bytes > 0);
        for context in cache.packets.values_mut() {
            context.last_seen -= UdpFragments::TIMEOUT;
        }
        cache.remove_expired();
        assert!(cache.packets.is_empty());
        assert_eq!(cache.bytes, 0);
        assert!(matches!(
            cache.process(first, Some(UDP_LOCAL_IP), &flows, &sender),
            PeerPacketFilterResult::Pass(_)
        ));
        cache.process(tail, Some(UDP_LOCAL_IP), &flows, &sender);
        cache.set_local_ip(None);
        assert!(cache.packets.is_empty());
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn cache_limits_pending_bytes_and_evicts_least_recent_entry() {
        let flows = Arc::new(FlowTable::default());
        let (sender, _receiver) = mpsc::channel(4);
        let mut cache = UdpFragments::default();
        for id in 0..=UdpFragments::CAPACITY as u16 {
            let [_, mut tail] = build_udp_fragments();
            let mut ip = Ipv4Packet::new_unchecked(tail.mut_payload());
            ip.set_ident(id);
            ip.fill_checksum();
            cache.process(tail, Some(UDP_LOCAL_IP), &flows, &sender);
        }
        assert_eq!(cache.packets.len(), UdpFragments::CAPACITY);
        assert!(!cache.packets.keys().any(|key| key.id == 0));
        let [_, tail] = build_udp_fragments();
        cache.process(tail.clone(), Some(UDP_LOCAL_IP), &flows, &sender);
        let refreshed = *cache.packets.keys().find(|key| key.id == 42).unwrap();
        cache.evict_oldest();
        assert!(cache.packets.contains_key(&refreshed));
        cache.set_local_ip(None);
        let mut payload = tail.payload().to_vec();
        payload.resize(65516, 0);
        let mut ip = Ipv4Packet::new_unchecked(&mut payload);
        ip.set_total_len(65516);
        ip.fill_checksum();
        let mut large = ZCPacket::new_with_payload(&payload);
        large.fill_peer_manager_hdr(1, 2, crate::packet::PacketType::Data as u8);
        for _ in 0..=UdpFragments::MAX_BYTES / large.buf_len() {
            cache.process(large.clone(), Some(UDP_LOCAL_IP), &flows, &sender);
            assert!(cache.bytes <= UdpFragments::MAX_BYTES);
        }
        assert_eq!(
            cache.bytes, 0,
            "over-budget pending datagram was not evicted"
        );
        assert!(cache.packets.is_empty());
    }

    #[test]
    fn pending_fragments_do_not_cross_peer_or_delivery_flags() {
        let flows = Arc::new(FlowTable::default());
        let (sender, _receiver) = mpsc::channel(4);
        for change_peer in [true, false] {
            let mut cache = UdpFragments::default();
            let [first, mut tail] = build_udp_fragments();
            if change_peer {
                tail.mut_peer_manager_header().unwrap().from_peer_id.set(9);
            } else {
                tail.mut_peer_manager_header().unwrap().set_no_proxy(false);
            }
            cache.process(tail, Some(UDP_LOCAL_IP), &flows, &sender);
            assert!(matches!(
                cache.process(first, Some(UDP_LOCAL_IP), &flows, &sender),
                PeerPacketFilterResult::Pass(_)
            ));
            assert!(cache.bytes > 0);
        }
    }
}

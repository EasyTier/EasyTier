use crate::common::global_ctx::ArcGlobalCtx;
use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::system;
use crate::dns::utils::addr::NameServerAddr;
use crate::dns::utils::response::ResponseHandle;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::NicPacketFilter;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::DnsNodeMgrRpcServer;
use crate::proto::rpc_impl::standalone::StandAloneServer;
use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::tcp::TcpTunnelListener;
use derivative::Derivative;
use hickory_net::runtime::{Time, TokioTime};
use hickory_net::xfer::Protocol;
use hickory_server::{
    Server,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::Catalog,
};
use parking_lot::RwLock;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet, icmp, ipv4, udp};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, instrument};

#[cfg(feature = "tun")]
use crate::instance::instance::{ArcNicCtx, NicCtx};
use crate::tunnel::common::bind;
use crate::utils::task::CancellableTask;

#[derive(Clone)]
struct DynamicCatalog {
    inner: Arc<tokio::sync::RwLock<Catalog>>,
}

impl DynamicCatalog {
    fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(Catalog::new())),
        }
    }

    async fn replace(&self, new: Catalog) {
        *self.inner.write().await = new;
    }
}

#[async_trait::async_trait]
impl RequestHandler for DynamicCatalog {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.inner
            .read()
            .await
            .handle_request::<_, T>(request, response_handle)
            .await
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DnsServer {
    mgr: Arc<DnsNodeMgr>,

    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx, // TODO: REMOVE THIS

    peer_mgr: Arc<PeerManager>,
    global_ctx: ArcGlobalCtx,

    #[derivative(Debug = "ignore")]
    catalog: DynamicCatalog,

    listeners: Arc<RwLock<HashSet<NameServerAddr>>>,
    addresses: Arc<RwLock<HashSet<NameServerAddr>>>,
}

const DNS_SERVER_LISTENER_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_SERVER_LISTENER_TCP_BUFFER_SIZE: usize = 32;

impl DnsServer {
    pub fn new(
        peer_mgr: Arc<PeerManager>,
        global_ctx: ArcGlobalCtx,
        #[cfg(feature = "tun")] nic_ctx: ArcNicCtx, // TODO: REMOVE THIS
    ) -> Self {
        Self {
            mgr: Arc::new(DnsNodeMgr::new()),
            #[cfg(feature = "tun")]
            nic_ctx,
            peer_mgr,
            global_ctx,
            catalog: DynamicCatalog::new(),
            listeners: Default::default(),
            addresses: Default::default(),
        }
    }

    pub fn register(&self, rpc: &StandAloneServer<TcpTunnelListener>) {
        rpc.registry()
            .register(DnsNodeMgrRpcServer::new_arc(self.mgr.clone()), "");
    }

    pub fn addresses(&self) -> HashSet<SocketAddr> {
        self.addresses.read().iter().map(|a| a.addr).collect()
    }

    #[instrument(skip_all)]
    async fn reload_addresses(
        &self,
        addresses: impl IntoIterator<Item = NameServerAddr>,
    ) -> anyhow::Result<()> {
        let addresses = addresses.into_iter().collect();

        if *self.addresses.read() == addresses {
            tracing::info!("addresses unchanged, no need to reload");
            return Ok(());
        }
        tracing::info!(?addresses, "reloading");

        #[cfg(feature = "tun")]
        {
            let nic_ctx = self.nic_ctx.lock().await;
            if let Some(nic_ctx) = nic_ctx
                .as_ref()
                .and_then(|nic_ctx| nic_ctx.downcast_ref::<NicCtx>())
                && let Some(system) = nic_ctx
                    .ifname()
                    .await
                    .map(|ifname| system::get(&ifname))
                    .transpose()?
                    .flatten()
            {
                let config = self.global_ctx.config.get_dns();
                let domain = vec![config.domain.to_string()];
                system.set_dns(&system::SystemConfig {
                    nameservers: addresses
                        .iter()
                        .filter_map(|a| {
                            (a.protocol == Protocol::Udp && a.addr.port() == 53)
                                .then_some(a.addr.ip().to_string())
                        })
                        .collect(),
                    search_domains: domain.clone(),
                    match_domains: domain
                        .into_iter()
                        .chain(config.zones.iter().map(|z| z.origin.to_string()))
                        .collect(),
                })?;
            }
        }

        *self.addresses.write() = addresses;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn reload_listeners(
        &self,
        listeners: impl IntoIterator<Item = NameServerAddr>,
        runtime: &mut Option<CancellableTask>,
    ) -> anyhow::Result<()> {
        let listeners = listeners.into_iter().collect();

        if *self.listeners.read() == listeners {
            tracing::info!("listeners unchanged, no need to reload");
            return Ok(());
        }
        tracing::info!(?listeners, "reloading");

        if let Some(runtime) = runtime.take()
            && let Err(error) = runtime.stop(None).await
        {
            tracing::error!(?error, "failed to stop old DNS server runtime");
        }

        let mut server = Server::new(self.catalog.clone());
        for listener in &listeners {
            let addr = listener.addr;
            tracing::info!(?addr, "binding listener");
            if let Err(error) = match listener.protocol {
                Protocol::Tcp => bind().addr(addr).call().map(|s| {
                    server.register_listener(
                        s,
                        DNS_SERVER_LISTENER_TCP_TIMEOUT,
                        DNS_SERVER_LISTENER_TCP_BUFFER_SIZE,
                    )
                }),
                Protocol::Udp => bind().addr(addr).call().map(|s| server.register_socket(s)),
                _ => unimplemented!(),
            } {
                tracing::error!(?addr, ?error, "failed to bind listener");
            }
        }

        let token = server.shutdown_token().clone();
        let handle = tokio::spawn(
            async move {
                server
                    .block_until_done()
                    .await
                    .unwrap_or_else(|e| tracing::error!("DNS server exited with error: {:?}", e));
            }
            .instrument(tracing::info_span!("DNS server backend runtime")),
        );

        *runtime = Some(CancellableTask::with_handle(token, handle));

        *self.listeners.write() = listeners;

        Ok(())
    }

    #[instrument(skip_all, name = "DnsServer main loop")]
    pub async fn run(&self, token: CancellationToken) {
        let dirty = &self.mgr.dirty;
        let mut runtime = None;

        let reload_catalog = async {
            loop {
                dirty.catalog.wait().await;
                if dirty.catalog.reset() {
                    self.catalog.replace(self.mgr.catalog()).await;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };

        let reload_addresses = async {
            loop {
                dirty.addresses.wait().await;
                if dirty.addresses.reset()
                    && let Err(error) = self.reload_addresses(self.mgr.iter_addresses()).await
                {
                    tracing::error!(?error, "failed to reload addresses");
                    dirty.addresses.mark();
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };

        let reload_listeners = async {
            loop {
                dirty.listeners.wait().await;
                if dirty.listeners.reset()
                    && let Err(error) = self
                        .reload_listeners(self.mgr.iter_listeners(), &mut runtime)
                        .await
                {
                    tracing::error!(?error, "failed to reload listeners");
                    dirty.listeners.mark();
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        };

        tokio::select!(
            _ = token.cancelled() => {
                tracing::info!("DnsServer received shutdown signal, exiting server loop");
            }

            _ = reload_catalog => {},
            _ = reload_addresses => {},
            _ = reload_listeners => {},
        );

        self.addresses.write().clear();
        self.listeners.write().clear();

        #[cfg(feature = "tun")]
        if let Some(nic_ctx) = self
            .nic_ctx
            .lock()
            .await
            .as_ref()
            .and_then(|nic_ctx| nic_ctx.downcast_ref::<NicCtx>())
            && let Some(system) = nic_ctx
                .ifname()
                .await
                .and_then(|ifname| system::get(&ifname).ok())
                .flatten()
        {
            let _ = system.clean();
        }

        if let Some(runtime) = runtime.take() {
            let _ = runtime.stop(None).await;
        }
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        tracing::info!("DnsServer is dropped");
        self.addresses.write().clear();
        self.listeners.write().clear();
    }
}

// region NIC packet filter

const NIC_PIPELINE_NAME: &str = "magic_dns_server";

#[async_trait::async_trait]
impl NicPacketFilter for DnsServer {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        self.handle_ip_packet(zc_packet).await.is_some()
    }

    fn id(&self) -> String {
        NIC_PIPELINE_NAME.to_string()
    }
}

impl DnsServer {
    fn is_hijacked_ip(&self, ip: &IpAddr) -> bool {
        self.addresses.read().iter().any(|a| a.addr.ip() == *ip)
    }

    fn is_hijacked_addr(&self, addr: SocketAddr) -> bool {
        self.addresses.read().contains(&addr.into())
    }

    /// Replace the content of an incoming UDP DNS request and ICMP echo request packet with reply data,
    /// and swap source and destination IP addresses to send it back.
    async fn handle_ip_packet(&self, zc_packet: &mut ZCPacket) -> Option<()> {
        let (ip_header_length, ip_protocol, src_ip, dst_ip) = {
            let ip_packet = Ipv4Packet::new(zc_packet.payload())?;

            if ip_packet.get_version() != 4 {
                return None;
            }

            (
                ip_packet.get_header_length() as usize * 4,
                ip_packet.get_next_level_protocol(),
                ip_packet.get_source(),
                ip_packet.get_destination(),
            )
        };

        if !self.is_hijacked_ip(&dst_ip.into()) {
            return None;
        }

        match ip_protocol {
            IpNextHeaderProtocols::Udp => {
                self.handle_udp_packet(zc_packet, ip_header_length, src_ip, dst_ip)
                    .await?;
            }
            IpNextHeaderProtocols::Icmp => {
                self.handle_icmp_packet(zc_packet, ip_header_length)?;
            }
            _ => {
                return None;
            }
        }

        // Swap source and destination IP addresses for the reply.
        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload())?;
        ip_packet.set_source(dst_ip);
        ip_packet.set_destination(src_ip);
        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

        // Route the response back to ourselves so it goes through the tun device.
        zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.peer_mgr.my_peer_id().into();

        Some(())
    }

    /// Extract the DNS request message from a UDP packet and send it to the catalog.
    /// Replace the content of the UDP packet with the response message.
    async fn handle_udp_packet(
        &self,
        zc_packet: &mut ZCPacket,
        ip_header_length: usize,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Option<()> {
        let (src_port, dst_port, request, request_length) = {
            let udp_packet = UdpPacket::new(&zc_packet.payload()[ip_header_length..])?;

            let src_port = udp_packet.get_source();
            let dst_port = udp_packet.get_destination();

            let request_payload = udp_packet.payload();

            (
                src_port,
                dst_port,
                Request::from_bytes(
                    request_payload.to_vec(),
                    SocketAddr::from(SocketAddrV4::new(src_ip, src_port)),
                    Protocol::Udp,
                )
                .ok()?,
                request_payload.len(),
            )
        };

        if !self.is_hijacked_addr(SocketAddr::new(dst_ip.into(), dst_port)) {
            return None;
        }

        let response_payload = {
            let response = ResponseHandle::new(512);

            self.catalog
                .handle_request::<_, TokioTime>(&request, response.clone())
                .await;

            response.into_inner()?
        };

        let response_length = response_payload.len();
        let delta_length = response_length as isize - request_length as isize;

        // Resize the packet buffer to accommodate the response.
        let inner_length = (zc_packet.buf_len() as isize + delta_length) as usize;
        if zc_packet.mut_inner().capacity() < inner_length {
            let header_length = inner_length - response_length;
            zc_packet.mut_inner().truncate(header_length);
        }
        zc_packet.mut_inner().resize(inner_length, 0);

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload())?;

        let ip_length = (ip_packet.get_total_length() as isize + delta_length) as u16;
        ip_packet.set_total_length(ip_length);

        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut())?;

        let udp_length = (udp_packet.get_length() as isize + delta_length) as u16;
        udp_packet.set_length(udp_length);

        udp_packet.set_source(dst_port);
        udp_packet.set_destination(src_port);

        udp_packet.payload_mut().copy_from_slice(&response_payload);

        udp_packet.set_checksum(udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &dst_ip,
            &src_ip,
        ));

        Some(())
    }

    /// Handle ICMP echo request by turning it into an echo reply.
    fn handle_icmp_packet(&self, zc_packet: &mut ZCPacket, ip_header_length: usize) -> Option<()> {
        let mut icmp_packet =
            MutableIcmpPacket::new(&mut zc_packet.mut_payload()[ip_header_length..])?;

        if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
            return None;
        }

        icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
        icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));

        Some(())
    }
}

// endregion

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::tests::{
        dns_snapshot_with as snapshot_with, heartbeat_with_snapshot, zone_data_a as valid_zone_data,
    };
    use crate::peers::tests::create_mock_peer_manager;
    use crate::proto::dns::DnsNodeMgrRpc;
    use crate::proto::rpc_types::controller::BaseController;
    use hickory_net::client::{Client, ClientHandle};
    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::udp::UdpClientStream;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
    use hickory_proto::serialize::binary::BinEncodable;
    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::ZoneType;
    use hickory_server::zone_handler::{AxfrPolicy, Catalog};
    use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
    use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
    use pnet::packet::{MutablePacket, Packet, icmp, ipv4, udp};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout};
    use uuid::Uuid;

    /// Build a `Catalog` containing a single A record: `test.example.com -> 1.2.3.4`.
    fn build_test_catalog() -> Catalog {
        let origin = Name::from_str("example.com.").unwrap();
        let mut zone_handler = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::default(),
        );

        let record = Record::from_rdata(
            Name::from_str("test.example.com.").unwrap(),
            60,
            RData::A(rdata::a::A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        let rr_key =
            hickory_proto::rr::RrKey::new(record.name.clone().into(), record.record_type());
        let mut rr_set =
            hickory_proto::rr::RecordSet::new(record.name.clone(), record.record_type(), 0);
        rr_set.insert(record, 0);
        zone_handler
            .records_get_mut()
            .insert(rr_key, Arc::new(rr_set));

        let mut catalog = Catalog::new();
        catalog.upsert(
            origin.into(),
            vec![Arc::new(zone_handler) as Arc<dyn hickory_server::zone_handler::ZoneHandler>],
        );
        catalog
    }

    /// Create a test `DnsServer` with `create_mock_peer_manager()`.
    async fn create_test_server() -> Arc<DnsServer> {
        let peer_mgr = create_mock_peer_manager().await;
        let global_ctx = peer_mgr.get_global_ctx();
        Arc::new(DnsServer::new(
            peer_mgr,
            global_ctx,
            #[cfg(feature = "tun")]
            ArcNicCtx::default(),
        ))
    }

    /// Build a raw IPv4 packet (as `Vec<u8>`) carrying the given L4 payload bytes.
    /// `protocol` selects ICMP / UDP etc.
    fn build_ipv4_packet(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        protocol: pnet::packet::ip::IpNextHeaderProtocol,
        l4_payload: &[u8],
    ) -> Vec<u8> {
        let ip_header_len = 20usize;
        let total_len = ip_header_len + l4_payload.len();
        let mut buf = vec![0u8; total_len];
        {
            let mut ip = MutableIpv4Packet::new(&mut buf).unwrap();
            ip.set_version(4);
            ip.set_header_length(5); // 20 bytes
            ip.set_total_length(total_len as u16);
            ip.set_ttl(64);
            ip.set_next_level_protocol(protocol);
            ip.set_source(src);
            ip.set_destination(dst);
            ip.payload_mut().copy_from_slice(l4_payload);
            ip.set_checksum(ipv4::checksum(&ip.to_immutable()));
        }
        buf
    }

    /// Build ICMP Echo Request payload (8 bytes minimum).
    fn build_icmp_echo_request() -> Vec<u8> {
        let mut buf = vec![0u8; 8];
        {
            let mut icmp_pkt = MutableIcmpPacket::new(&mut buf).unwrap();
            icmp_pkt.set_icmp_type(IcmpTypes::EchoRequest);
            icmp_pkt.set_icmp_code(icmp::IcmpCode::new(0));
            icmp_pkt.set_checksum(icmp::checksum(&icmp_pkt.to_immutable()));
        }
        buf
    }

    /// Build a minimal DNS query message for `name` and encode it to bytes.
    fn build_dns_query_bytes(name: &str) -> Vec<u8> {
        let mut msg = Message::new(0x1234, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let mut query = Query::new();
        query.set_name(Name::from_str(name).unwrap());
        query.set_query_type(RecordType::A);
        query.set_query_class(DNSClass::IN);
        msg.add_query(query);
        msg.to_bytes().unwrap().to_vec()
    }

    /// Build a UDP packet carrying `payload`, with given src/dst ports.
    fn build_udp_packet(
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut buf = vec![0u8; udp_len];
        {
            let mut udp_pkt = MutableUdpPacket::new(&mut buf).unwrap();
            udp_pkt.set_source(src_port);
            udp_pkt.set_destination(dst_port);
            udp_pkt.set_length(udp_len as u16);
            udp_pkt.payload_mut().copy_from_slice(payload);
            udp_pkt.set_checksum(udp::ipv4_checksum(
                &udp_pkt.to_immutable(),
                &src_ip,
                &dst_ip,
            ));
        }
        buf
    }

    async fn wait_until(mut f: impl FnMut() -> bool) {
        for _ in 0..80 {
            if f() {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
        panic!("condition not met in time");
    }

    // ─── Tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn should_match_hijacked_ip_and_addr_when_address_is_registered() {
        let server = create_test_server().await;
        let addr: SocketAddr = "10.0.0.53:53".parse().unwrap();
        assert!(!server.is_hijacked_ip(&addr.ip()));
        assert!(!server.is_hijacked_addr(addr));

        server.addresses.write().insert(addr.into());
        assert!(server.is_hijacked_ip(&addr.ip()));
        assert!(server.is_hijacked_addr(addr));

        // Different port on same IP — ip matches, but addr does not.
        let other_addr: SocketAddr = "10.0.0.53:5353".parse().unwrap();
        assert!(server.is_hijacked_ip(&other_addr.ip()));
        assert!(!server.is_hijacked_addr(other_addr));
    }

    #[tokio::test]
    async fn should_reply_icmp_echo_and_swap_endpoints_when_packet_is_hijacked() {
        let server = create_test_server().await;
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        // Register the dst IP as hijacked.
        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        let icmp_payload = build_icmp_echo_request();
        let ip_bytes =
            build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Icmp, &icmp_payload);

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        let result = server.handle_ip_packet(&mut zc).await;
        assert!(
            result.is_some(),
            "handle_ip_packet should succeed for echo request"
        );

        // Verify ICMP type is now EchoReply.
        let ip = Ipv4Packet::new(zc.payload()).unwrap();
        let icmp = IcmpPacket::new(ip.payload()).unwrap();
        assert_eq!(icmp.get_icmp_type(), IcmpTypes::EchoReply);

        // Verify IP addresses are swapped.
        assert_eq!(ip.get_source(), dst_ip);
        assert_eq!(ip.get_destination(), src_ip);

        // Verify route-to-self rewrite in peer manager header.
        let hdr = zc.peer_manager_header().unwrap();
        assert_eq!(hdr.to_peer_id.get(), server.peer_mgr.my_peer_id() as u32);
    }

    #[tokio::test]
    async fn should_ignore_icmp_when_type_is_not_echo_request() {
        let server = create_test_server().await;
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        // Build an ICMP Destination Unreachable (not echo request).
        let mut icmp_buf = vec![0u8; 8];
        {
            let mut pkt = MutableIcmpPacket::new(&mut icmp_buf).unwrap();
            pkt.set_icmp_type(IcmpTypes::DestinationUnreachable);
            pkt.set_checksum(icmp::checksum(&pkt.to_immutable()));
        }
        let ip_bytes = build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Icmp, &icmp_buf);

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        let result = server.handle_ip_packet(&mut zc).await;
        assert!(result.is_none(), "non-echo ICMP should be ignored");
    }

    #[tokio::test]
    async fn should_ignore_packet_when_destination_ip_is_not_hijacked() {
        let server = create_test_server().await;
        // Do NOT register any hijacked addresses.
        let icmp_payload = build_icmp_echo_request();
        let ip_bytes = build_ipv4_packet(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.99".parse().unwrap(),
            IpNextHeaderProtocols::Icmp,
            &icmp_payload,
        );

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        let result = server.handle_ip_packet(&mut zc).await;
        assert!(
            result.is_none(),
            "packet to non-hijacked IP should be ignored"
        );
    }

    #[tokio::test]
    async fn should_rewrite_udp_dns_packet_when_query_targets_hijacked_dns_addr() {
        let server = create_test_server().await;
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dns_port: u16 = 53;
        let client_port: u16 = 12345;

        // Register dst as hijacked.
        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), dns_port).into());

        // Load a catalog with test.example.com -> 1.2.3.4.
        server.catalog.replace(build_test_catalog()).await;

        // Build DNS query.
        let dns_bytes = build_dns_query_bytes("test.example.com.");
        let udp_bytes = build_udp_packet(client_port, dns_port, &dns_bytes, src_ip, dst_ip);
        let ip_bytes = build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Udp, &udp_bytes);

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        let result = server.handle_ip_packet(&mut zc).await;
        assert!(result.is_some(), "DNS query should be handled");

        // Parse the response IP packet => UDP => DNS message.
        let ip = Ipv4Packet::new(zc.payload()).unwrap();
        assert_eq!(
            ip.get_source(),
            dst_ip,
            "reply source should be the DNS server IP"
        );
        assert_eq!(
            ip.get_destination(),
            src_ip,
            "reply dest should be the client IP"
        );

        let udp_reply = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp_reply.get_source(), dns_port);
        assert_eq!(udp_reply.get_destination(), client_port);
        assert_eq!(
            udp_reply.get_length() as usize,
            8 + udp_reply.payload().len(),
            "UDP length should match payload size"
        );

        assert_eq!(
            udp_reply.get_checksum(),
            udp::ipv4_checksum(&udp_reply, &dst_ip, &src_ip),
            "UDP checksum should be recomputed for swapped src/dst IP"
        );

        assert_eq!(
            ip.get_total_length() as usize,
            20 + udp_reply.packet().len(),
            "IP total length should match rewritten packet"
        );

        let dns_reply = Message::from_vec(udp_reply.payload()).unwrap();
        assert_eq!(dns_reply.id, 0x1234);
        assert!(
            !dns_reply.answers.is_empty(),
            "DNS reply should contain answers"
        );

        let answer = &dns_reply.answers[0];
        if let RData::A(a) = answer.data {
            assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A record in answer, got {:?}", answer.data);
        }
    }

    /// Full end-to-end test: start a real DNS UDP listener via `ServerFuture`,
    /// send a query with a `hickory_client`, and verify the response.
    #[tokio::test]
    async fn should_resolve_record_via_real_udp_listener() {
        use hickory_server::Server;
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // Build a catalog with test.example.com -> 1.2.3.4.
        let catalog = build_test_catalog();

        // Bind to a random port.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let mut server = Server::new(catalog);
        server.register_socket(socket);

        let shutdown_token = server.shutdown_token().clone();
        tokio::spawn(async move {
            server.block_until_done().await.ok();
        });

        // Send a real DNS query using hickory_client.
        let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);

        tokio::spawn(bg);

        let response = timeout(
            Duration::from_secs(2),
            client.query(
                Name::from_str("test.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::A,
            ),
        )
        .await
        .expect("query timeout")
        .expect("query failed");

        assert!(!response.answers.is_empty(), "should get answers");
        let a_record = &response.answers[0];
        if let RData::A(a) = a_record.data {
            assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A record, got {:?}", a_record.data);
        }

        // Shutdown the server.
        shutdown_token.cancel();
    }

    #[tokio::test]
    async fn should_process_icmp_packet_and_expose_pipeline_id() {
        let server = create_test_server().await;
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        let icmp_payload = build_icmp_echo_request();
        let ip_bytes =
            build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Icmp, &icmp_payload);
        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        assert!(server.try_process_packet_from_nic(&mut zc).await);
        assert_eq!(server.id(), NIC_PIPELINE_NAME);
    }

    #[tokio::test]
    async fn should_ignore_packet_when_ipv4_header_has_non_ipv4_version() {
        let server = create_test_server().await;
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        let icmp_payload = build_icmp_echo_request();
        let mut ip_bytes =
            build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Icmp, &icmp_payload);
        ip_bytes[0] = (6 << 4) | 5; // fake IPv6 version in IPv4 header

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        assert!(server.handle_ip_packet(&mut zc).await.is_none());
    }

    #[tokio::test]
    async fn should_ignore_packet_when_protocol_is_unsupported() {
        let server = create_test_server().await;
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        let tcp_like_payload = vec![0u8; 20];
        let ip_bytes = build_ipv4_packet(
            src_ip,
            dst_ip,
            IpNextHeaderProtocols::Tcp,
            &tcp_like_payload,
        );

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        assert!(server.handle_ip_packet(&mut zc).await.is_none());
    }

    #[tokio::test]
    async fn should_ignore_udp_dns_packet_when_destination_port_is_not_hijacked() {
        let server = create_test_server().await;
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());
        server.catalog.replace(build_test_catalog()).await;

        let dns_bytes = build_dns_query_bytes("test.example.com.");
        let udp_bytes = build_udp_packet(12345, 5353, &dns_bytes, src_ip, dst_ip);
        let ip_bytes = build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Udp, &udp_bytes);

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        assert!(server.handle_ip_packet(&mut zc).await.is_none());
    }

    #[tokio::test]
    async fn should_ignore_udp_packet_when_dns_payload_is_invalid() {
        let server = create_test_server().await;
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();

        server
            .addresses
            .write()
            .insert(SocketAddr::new(dst_ip.into(), 53).into());

        let invalid_dns = vec![0xde, 0xad, 0xbe];
        let udp_bytes = build_udp_packet(12345, 53, &invalid_dns, src_ip, dst_ip);
        let ip_bytes = build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Udp, &udp_bytes);

        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        assert!(server.handle_ip_packet(&mut zc).await.is_none());
    }

    #[tokio::test]
    async fn should_update_public_addresses_when_reload_addresses_is_called() {
        let server = create_test_server().await;

        let addrs = vec![
            "udp://10.10.10.53:53".parse::<NameServerAddr>().unwrap(),
            "tcp://10.10.10.54:5353".parse::<NameServerAddr>().unwrap(),
        ];
        server.reload_addresses(addrs.clone()).await.unwrap();

        let as_socket = server.addresses();
        assert_eq!(as_socket.len(), 2);
        assert!(as_socket.contains(&addrs[0].addr));
        assert!(as_socket.contains(&addrs[1].addr));

        // No-op reload should keep the same content.
        server.reload_addresses(addrs).await.unwrap();
        assert_eq!(server.addresses().len(), 2);
    }

    #[tokio::test]
    async fn should_still_serve_working_listener_when_one_bind_fails() {
        let server = create_test_server().await;
        server.catalog.replace(build_test_catalog()).await;

        let occupied = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let occupied_addr = occupied.local_addr().unwrap();

        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let good_addr = probe.local_addr().unwrap();
        drop(probe);

        let listeners = vec![
            NameServerAddr {
                protocol: Protocol::Udp,
                addr: occupied_addr,
            },
            NameServerAddr {
                protocol: Protocol::Udp,
                addr: good_addr,
            },
        ];

        let mut runtime = None;
        server
            .reload_listeners(listeners, &mut runtime)
            .await
            .unwrap();

        let stream = UdpClientStream::builder(good_addr, TokioRuntimeProvider::default()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);
        tokio::spawn(bg);

        let response = timeout(
            Duration::from_secs(2),
            client.query(
                Name::from_str("test.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::A,
            ),
        )
        .await
        .expect("query timeout")
        .expect("query failed");

        assert!(!response.answers.is_empty());

        if let Some(runtime) = runtime.take() {
            let _ = runtime.stop(None).await;
        }
    }

    #[tokio::test]
    async fn should_apply_snapshot_updates_and_clear_state_on_shutdown() {
        let server = create_test_server().await;
        let token = CancellationToken::new();
        let run_server = server.clone();
        let run_token = token.clone();
        let run_task = tokio::spawn(async move {
            run_server.run(run_token).await;
        });

        let node_id = Uuid::new_v4();
        let snapshot = snapshot_with(
            vec![valid_zone_data("run-loop.test", "7.7.7.7")],
            vec!["udp://10.0.0.53:53"],
            vec![],
        );

        DnsNodeMgrRpc::heartbeat(
            &*server.mgr,
            BaseController::default(),
            heartbeat_with_snapshot(node_id, snapshot),
        )
        .await
        .unwrap();

        wait_until(|| {
            server
                .addresses()
                .contains(&"10.0.0.53:53".parse::<SocketAddr>().unwrap())
        })
        .await;

        // Verify catalog hot-reload by issuing a hijacked DNS packet query.
        let src_ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let dst_ip: Ipv4Addr = "10.0.0.53".parse().unwrap();
        let dns_bytes = build_dns_query_bytes("run-loop.test.");
        let udp_bytes = build_udp_packet(12000, 53, &dns_bytes, src_ip, dst_ip);
        let ip_bytes = build_ipv4_packet(src_ip, dst_ip, IpNextHeaderProtocols::Udp, &udp_bytes);
        let mut zc = ZCPacket::new_with_payload(&ip_bytes);
        zc.fill_peer_manager_hdr(1, 2, crate::tunnel::packet_def::PacketType::Data as u8);

        let mut handled = false;
        for _ in 0..80 {
            if server.handle_ip_packet(&mut zc).await.is_some() {
                handled = true;
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
        assert!(handled, "catalog should be hot-reloaded before timeout");

        token.cancel();
        let _ = run_task.await;

        assert!(
            server.addresses().is_empty(),
            "run() should clear addresses on exit"
        );
        assert!(
            server.listeners.read().is_empty(),
            "run() should clear listeners on exit"
        );
    }
}

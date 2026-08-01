use crate::common::global_ctx::ArcGlobalCtx;
use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::system;
use crate::dns::utils::addr::NameServerAddr;
#[cfg(feature = "tun")]
use crate::instance::instance::{ArcNicCtx, NicCtx};
#[cfg(feature = "tun")]
use crate::peers::NicPacketFilter;
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::DnsNodeMgrRpcServer;
use crate::proto::rpc_impl::standalone::StandAloneServer;
use crate::tunnel::common::bind;
#[cfg(feature = "tun")]
use crate::tunnel::packet_def::ZCPacket;
use crate::tunnel::tcp::TcpTunnelListener;
use crate::utils::task::CancellableTask;
use anyhow::Context;
use derivative::Derivative;
#[cfg(feature = "tun")]
use futures::StreamExt;
use guarden::guarded;
#[cfg(feature = "tun")]
use hickory_net::BufDnsStreamHandle;
use hickory_net::runtime::Time;
#[cfg(feature = "tun")]
use hickory_net::runtime::TokioTime;
use hickory_net::xfer::Protocol;
use hickory_server::{
    Server,
    server::{Request, RequestHandler, ResponseHandle, ResponseHandler, ResponseInfo},
    zone_handler::Catalog,
};
use itertools::chain;
#[cfg(feature = "tun")]
use pnet::packet::{
    MutablePacket, Packet,
    icmp::{self, IcmpCode, IcmpPacket, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocol,
    ipv4::{self, Ipv4Packet, MutableIpv4Packet},
    udp::{self, MutableUdpPacket, UdpPacket},
};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::IpAddr;
#[cfg(feature = "tun")]
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, instrument};

/// IANA protocol numbers used by the NicPacketFilter data plane.
#[cfg(feature = "tun")]
const IPPROTO_ICMP: u8 = 1;
#[cfg(feature = "tun")]
const IPPROTO_UDP: u8 = 17;

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
    runtime: Mutex<Option<CancellableTask<()>>>,
    bindings: RwLock<HashSet<NameServerAddr>>,

    addresses: RwLock<HashSet<NameServerAddr>>,
    listeners: RwLock<HashSet<NameServerAddr>>,
}

const DNS_SERVER_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_SERVER_TCP_BUFFER_SIZE: usize = 32;

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
            runtime: Default::default(),
            bindings: Default::default(),
            listeners: Default::default(),
            addresses: Default::default(),
        }
    }

    pub fn register(&self, rpc: &StandAloneServer<TcpTunnelListener>) {
        rpc.registry()
            .register(DnsNodeMgrRpcServer::new_arc(self.mgr.clone()), "");
    }

    #[cfg(feature = "tun")]
    async fn update_system(&self, nameservers: &HashSet<NameServerAddr>) -> anyhow::Result<()> {
        let nic_ctx = self.nic_ctx.lock().await;
        let nic_ctx = nic_ctx
            .as_ref()
            .and_then(|nic_ctx| nic_ctx.downcast_ref::<NicCtx>())
            .with_context(|| "failed to get NicCtx")?;
        let ifname = nic_ctx
            .ifname()
            .await
            .with_context(|| "failed to get interface name from NicCtx")?;
        let system = system::get(&ifname)?.with_context(|| "failed to get system configurator")?;
        let config = self.global_ctx.config.get_dns();
        let domain = vec![config.domain.to_string()];
        system.set_dns(&system::SystemConfig {
            nameservers: nameservers
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
        Ok(())
    }

    #[instrument(skip_all)]
    async fn rebind(&self) -> anyhow::Result<bool> {
        let Ok(mut runtime) = self.runtime.try_lock() else {
            return Ok(false);
        };

        let mut bindings = {
            let current = self.bindings.read();
            let bindings = chain(
                self.addresses.read().iter().cloned(),
                self.listeners.read().iter().cloned(),
            )
            .collect();
            if *current == bindings {
                tracing::info!("bindings unchanged, no need to rebind");
                return Ok(false);
            }
            bindings
        };

        if let Some(runtime) = runtime.take() {
            runtime.stop(None).await?;
        }

        let mut server = Server::new(self.catalog.clone());

        bindings.retain(|binding| {
            let addr = binding.addr;
            tracing::info!(?addr, "binding");
            match binding.protocol {
                Protocol::Tcp => bind().addr(addr).call().map(|s| {
                    server.register_listener(s, DNS_SERVER_TCP_TIMEOUT, DNS_SERVER_TCP_BUFFER_SIZE)
                }),
                Protocol::Udp => bind().addr(addr).call().map(|s| server.register_socket(s)),
                _ => unimplemented!(),
            }
            .inspect_err(|error| tracing::error!(?addr, ?error, "failed to bind"))
            .is_ok()
        });

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

        #[cfg(feature = "tun")]
        if let Err(error) = self.update_system(&bindings).await {
            tracing::error!(?error, "failed to update system DNS settings");
        }

        *self.bindings.write() = bindings;

        Ok(true)
    }

    #[instrument(skip_all)]
    async fn reload_addresses(&self) -> anyhow::Result<()> {
        let addresses = self.mgr.iter_addresses().collect();

        let removed = {
            let current = self.addresses.read();
            if *current == addresses {
                tracing::info!("addresses unchanged, no need to reload");
                return Ok(());
            }
            current
                .difference(&addresses)
                .cloned()
                .collect::<HashSet<_>>()
        };
        tracing::info!(?addresses, "reloading");

        #[cfg(feature = "tun")]
        {
            let nic_ctx = self.nic_ctx.lock().await;
            if let Some(nic_ctx) = nic_ctx
                .as_ref()
                .and_then(|nic_ctx| nic_ctx.downcast_ref::<NicCtx>())
            {
                for addr in &addresses {
                    let ip = addr.addr.ip();
                    if let Err(error) = match ip {
                        IpAddr::V4(ipv4) => nic_ctx.add_ipv4_to_tun_device(ipv4.into()).await,
                        IpAddr::V6(ipv6) => nic_ctx.add_ipv6_to_tun_device(ipv6.into()).await,
                    } {
                        tracing::error!(?addr, ?error, "failed to add address to tun device");
                    }
                }

                for addr in removed {
                    let ip = addr.addr.ip();
                    if let Err(error) = match ip {
                        IpAddr::V4(ipv4) => nic_ctx.remove_ipv4_from_tun_device(ipv4.into()).await,
                        IpAddr::V6(ipv6) => nic_ctx.remove_ipv6_from_tun_device(ipv6.into()).await,
                    } {
                        tracing::error!(?addr, ?error, "failed to remove address from tun device");
                    }
                }
            }
        }

        *self.addresses.write() = addresses;

        self.rebind().await?;

        Ok(())
    }

    #[instrument(skip_all)]
    async fn reload_listeners(&self) -> anyhow::Result<()> {
        let listeners = self.mgr.iter_listeners().collect();

        if *self.listeners.read() == listeners {
            tracing::info!("listeners unchanged, no need to reload");
            return Ok(());
        }
        tracing::info!(?listeners, "reloading");

        *self.listeners.write() = listeners;

        self.rebind().await?;

        Ok(())
    }

    #[instrument(skip_all, name = "DnsServer main loop")]
    pub async fn run(&self, token: CancellationToken) {
        let dirty = &self.mgr.dirty;
        let runtime = None::<CancellableTask<()>>;

        #[cfg(feature = "tun")]
        guarded! {
            system_guard => [
                nic_ctx = self.nic_ctx.clone(),
            ]
            async move {
                if let Some(nic_ctx) = nic_ctx
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
            }
        }

        guarded! {
            runtime_guard => [
                mut runtime,
            ]
            async move {
                if let Some(runtime) = runtime.take() {
                    let _ = runtime.stop(Some(Duration::from_secs(1))).await;
                }
            }
        }

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
                    && let Err(error) = self.reload_addresses().await
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
                    && let Err(error) = self.reload_listeners().await
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

        #[cfg(feature = "tun")]
        system_guard.trigger().await;
        runtime_guard.trigger().await;
    }
}

// ─── NicPacketFilter data plane ─────────────────────────────────────────────
//
// On platforms whose TUN device cannot be assigned the DNS IP (notably Android,
// where Rust only receives a read-only fd), `rebind()` cannot listen on the
// hijack address, so socket-based serving is impossible. Instead `DnsServer`
// attaches as a `NicPacketFilter` and answers DNS/ICMP straight from the packet
// pipeline: the query read from the TUN is resolved via the catalog and the
// response is re-injected into the NIC channel so the local app receives it.
//
// On desktop (Windows/Linux/macOS) the hijack IP is bound to the TUN, queries
// are answered by the bound socket and never enter this path, so the filter is
// dormant there and existing behavior is unchanged.

#[cfg(feature = "tun")]
impl DnsServer {
    /// Answer a UDP DNS query addressed to one of our hijack addresses.
    async fn handle_dns_query(&self, ip: &Ipv4Packet<'_>) {
        let Some(udp) = UdpPacket::new(ip.payload()) else {
            return;
        };
        if udp.get_destination() != 53 {
            return;
        }

        let src = SocketAddr::from(SocketAddrV4::new(ip.get_source(), udp.get_source()));
        let Ok(request) = Request::from_bytes(udp.payload().to_vec(), src, Protocol::Udp) else {
            return;
        };

        // Obtain the wire-format response the same way hickory does: drive the
        // catalog's request handler through a public `ResponseHandle` backed by a
        // `BufDnsStreamHandle`, then read the serialized bytes back. (`encode` is
        // pub(crate), so this is the supported path to response bytes off-crate.)
        let (stream_handle, mut stream_receiver) = BufDnsStreamHandle::new(src);
        let _ = self
            .catalog
            .handle_request::<ResponseHandle, TokioTime>(
                &request,
                ResponseHandle::new(src, stream_handle, Protocol::Udp),
            )
            .await;
        let Some(serial) = stream_receiver.next().await else {
            return;
        };
        let response = serial.into_parts().0;

        // Swap src/dst: the reply originates from the hijack address:53 and
        // returns to whoever issued the query.
        let packet = build_ipv4_udp(
            ip.get_destination(),
            ip.get_source(),
            udp.get_destination(),
            udp.get_source(),
            &response,
        );
        let _ = self
            .peer_mgr
            .get_nic_channel()
            .send(ZCPacket::new_with_payload(&packet))
            .await;
    }

    /// Rewrite an ICMP Echo Request as an Echo Reply so the hijack address is pingable.
    async fn handle_icmp_echo(&self, ip: &Ipv4Packet<'_>) {
        let Some(icmp) = IcmpPacket::new(ip.payload()) else {
            return;
        };
        if icmp.get_icmp_type() != IcmpTypes::EchoRequest {
            return;
        }

        let mut buf = ip.payload().to_vec();
        if let Some(mut reply) = MutableIcmpPacket::new(&mut buf) {
            reply.set_icmp_type(IcmpTypes::EchoReply);
            reply.set_icmp_code(IcmpCode::new(0));
            reply.set_checksum(icmp::checksum(&reply.to_immutable()));
        }

        let packet = build_ipv4(
            ip.get_destination(),
            ip.get_source(),
            IpNextHeaderProtocol(IPPROTO_ICMP),
            &buf,
        );
        let _ = self
            .peer_mgr
            .get_nic_channel()
            .send(ZCPacket::new_with_payload(&packet))
            .await;
    }
}

#[cfg(feature = "tun")]
#[async_trait::async_trait]
impl NicPacketFilter for DnsServer {
    async fn try_process_packet_from_nic(&self, data: &mut ZCPacket) -> bool {
        let Some(ip) = Ipv4Packet::new(data.payload()) else {
            return false;
        };
        if ip.get_version() != 4 {
            return false;
        }

        let dst = ip.get_destination();
        let is_hijack = self
            .addresses
            .read()
            .iter()
            .any(|addr| addr.addr.ip() == IpAddr::V4(dst));
        if !is_hijack {
            return false;
        }

        match ip.get_next_level_protocol().0 {
            IPPROTO_UDP => self.handle_dns_query(&ip).await,
            IPPROTO_ICMP => self.handle_icmp_echo(&ip).await,
            _ => {}
        }
        // The pipeline discards this return value. The original query keeps
        // flowing to the route lookup, which drops it (no peer owns the hijack
        // IP); the response was already re-injected into the NIC channel above.
        true
    }
}

/// Build a raw IPv4 packet carrying `l4_payload`.
#[cfg(feature = "tun")]
fn build_ipv4(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpNextHeaderProtocol,
    l4_payload: &[u8],
) -> Vec<u8> {
    let ip_header_len = 20usize;
    let total_len = ip_header_len + l4_payload.len();
    let mut buf = vec![0u8; total_len];
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
    buf
}

/// Build a UDP/IPv4 packet carrying `payload`, with corrected UDP checksum.
#[cfg(feature = "tun")]
fn build_ipv4_udp(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp_buf = vec![0u8; udp_len];
    {
        let mut udp = MutableUdpPacket::new(&mut udp_buf).unwrap();
        udp.set_source(src_port);
        udp.set_destination(dst_port);
        udp.set_length(udp_len as u16);
        udp.payload_mut().copy_from_slice(payload);
        udp.set_checksum(udp::ipv4_checksum(&udp.to_immutable(), &src_ip, &dst_ip));
    }
    build_ipv4(src_ip, dst_ip, IpNextHeaderProtocol(IPPROTO_UDP), &udp_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::tests::{create_mock_peer_manager, create_mock_peer_manager_with_recv};
    use hickory_net::client::{Client, ClientHandle};
    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::udp::UdpClientStream;
    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
    use hickory_proto::serialize::binary::BinEncodable;
    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::ZoneType;
    use hickory_server::zone_handler::{AxfrPolicy, Catalog};
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::{MutablePacket, Packet, icmp, ipv4, udp};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::time::sleep;

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

    /// The NicPacketFilter answers a UDP DNS query addressed to a hijack address
    /// (e.g. 100.100.100.101) by resolving it via the catalog and re-injecting the
    /// response into the NIC channel — the Android data plane.
    #[cfg(feature = "tun")]
    #[tokio::test]
    async fn nic_filter_answers_dns_query_to_hijack_address() {
        let (peer_mgr, mut nic_recv) = create_mock_peer_manager_with_recv().await;
        let global_ctx = peer_mgr.get_global_ctx();
        let server = Arc::new(DnsServer::new(
            peer_mgr,
            global_ctx,
            ArcNicCtx::default(),
        ));
        server.catalog.replace(build_test_catalog()).await;
        server
            .addresses
            .write()
            .insert(NameServerAddr {
                protocol: Protocol::Udp,
                addr: "100.100.100.101:53".parse().unwrap(),
            });

        // Query: test.example.com A, from 10.0.0.2:12345 -> 100.100.100.101:53
        let query = build_dns_query_bytes("test.example.com");
        let udp = build_udp_packet(
            12345,
            53,
            &query,
            "10.0.0.2".parse().unwrap(),
            "100.100.100.101".parse().unwrap(),
        );
        let pkt = build_ipv4_packet(
            "10.0.0.2".parse().unwrap(),
            "100.100.100.101".parse().unwrap(),
            IpNextHeaderProtocol(17),
            &udp,
        );
        let mut zc = ZCPacket::new_with_payload(&pkt);

        // Feed it through the filter (the pipeline call site).
        server.try_process_packet_from_nic(&mut zc).await;

        // The response must have been re-injected into the NIC channel.
        let resp = tokio::time::timeout(Duration::from_secs(2), nic_recv.recv())
            .await
            .expect("timed out waiting for DNS response")
            .expect("nic channel closed");

        let ip = Ipv4Packet::new(resp.payload()).unwrap();
        assert_eq!(ip.get_source(), Ipv4Addr::new(100, 100, 100, 101));
        assert_eq!(ip.get_destination(), Ipv4Addr::new(10, 0, 0, 2));
        let udp_resp = UdpPacket::new(ip.payload()).unwrap();
        assert_eq!(udp_resp.get_source(), 53);
        assert_eq!(udp_resp.get_destination(), 12345);

        let msg = Message::from_vec(udp_resp.payload()).unwrap();
        assert_eq!(msg.response_code, ResponseCode::NoError);
        assert!(!msg.answers.is_empty(), "expected an A record answer");
        let a_record = &msg.answers[0];
        if let RData::A(a) = a_record.data {
            assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A record, got {:?}", a_record.data);
        }
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
}

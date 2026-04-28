use crate::common::global_ctx::ArcGlobalCtx;
use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::system;
use crate::dns::utils::addr::NameServerAddr;
#[cfg(feature = "tun")]
use crate::instance::instance::{ArcNicCtx, NicCtx};
use crate::peers::peer_manager::PeerManager;
use crate::proto::dns::DnsNodeMgrRpcServer;
use crate::proto::rpc_impl::standalone::StandAloneServer;
use crate::tunnel::common::bind;
use crate::tunnel::tcp::TcpTunnelListener;
use crate::utils::task::CancellableTask;
use anyhow::Context;
use derivative::Derivative;
use guarden::guarded;
use hickory_net::runtime::Time;
use hickory_net::xfer::Protocol;
use hickory_server::{
    Server,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::Catalog,
};
use itertools::chain;
use parking_lot::RwLock;
use std::collections::HashSet;
use std::net::IpAddr;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, instrument};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peers::tests::create_mock_peer_manager;
    use hickory_net::client::{Client, ClientHandle};
    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::udp::UdpClientStream;
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{rdata, DNSClass, Name, RData, Record, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::ZoneType;
    use hickory_server::zone_handler::{AxfrPolicy, Catalog};
    use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
    use pnet::packet::ipv4::MutableIpv4Packet;
    use pnet::packet::udp::MutableUdpPacket;
    use pnet::packet::{icmp, ipv4, udp, MutablePacket};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::time::{sleep, timeout};

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
    async fn should_update_public_addresses_when_reload_addresses_is_called() {
        let server = create_test_server().await;

        let addrs = vec![
            "udp://10.10.10.53:53".parse::<NameServerAddr>().unwrap(),
            "tcp://10.10.10.54:5353".parse::<NameServerAddr>().unwrap(),
        ];
        server.reload_addresses().await.unwrap();

        let as_socket = server
            .addresses
            .read()
            .iter()
            .map(|a| a.addr)
            .collect::<HashSet<_>>();
        assert_eq!(as_socket.len(), 2);
        assert!(as_socket.contains(&addrs[0].addr));
        assert!(as_socket.contains(&addrs[1].addr));

        // No-op reload should keep the same content.
        server.reload_addresses().await.unwrap();
        assert_eq!(server.addresses.read().len(), 2);
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

        server.reload_listeners().await.unwrap();

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
    }
}

use crate::common::PeerId;
use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::utils::addr::NameServerAddr;
use crate::peer_center::instance::PeerCenterPeerManagerTrait;
use crate::peers::peer_manager::PeerManager;
use crate::peers::NicPacketFilter;
use crate::proto::dns::DnsNodeMgrRpcServer;
use crate::tunnel::common::bind_socket;
use crate::tunnel::packet_def::ZCPacket;
use derivative::Derivative;
use derive_more::{Deref, DerefMut, From, Into};
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_proto::xfer::Protocol;
use hickory_server::authority::MessageRequest;
use hickory_server::{
    authority::{Catalog, MessageResponse},
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    ServerFuture,
};
use itertools::Itertools;
use parking_lot::Mutex;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{icmp, ipv4, udp, MutablePacket, Packet};
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::{sync::Arc, time::Duration};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;

#[derive(Clone)]
pub struct DynamicCatalog {
    inner: Arc<RwLock<Catalog>>,
}

impl DynamicCatalog {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Catalog::new())),
        }
    }

    pub async fn replace(&self, new: Catalog) {
        *self.inner.write().await = new;
    }
}

#[async_trait::async_trait]
impl RequestHandler for DynamicCatalog {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.inner
            .read()
            .await
            .handle_request(request, response_handle)
            .await
    }
}

struct DnsServerRuntime {
    token: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl DnsServerRuntime {
    fn start<T: RequestHandler>(mut server: ServerFuture<T>) -> Self {
        Self {
            token: server.shutdown_token().clone(),
            task: Some(tokio::spawn(async move {
                server
                    .block_until_done()
                    .await
                    .unwrap_or_else(|e| tracing::error!("DNS server exited with error: {:?}", e));
            })),
        }
    }

    async fn stop(mut self) -> anyhow::Result<()> {
        self.token.cancel();
        if let Some(task) = self.task.take() {
            task.await?;
        }
        Ok(())
    }

}

impl Drop for DnsServerRuntime {
    fn drop(&mut self) {
        self.token.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
            tracing::warn!("DNS server runtime is leaked");
        }
    }
}

// ResponseWrapper for serializing DNS responses into a byte buffer.
// Used by the address hijacking NIC packet filter to produce DNS replies in-place.
#[derive(Debug, Clone, From, Into, Deref, DerefMut)]
struct Response(Arc<Mutex<Vec<u8>>>);

impl Response {
    pub fn new(capacity: usize) -> Self {
        Self(Arc::new(Mutex::new(Vec::with_capacity(capacity))))
    }

    pub fn into_inner(self) -> Option<Vec<u8>> {
        Arc::into_inner(self.0).map(Mutex::into_inner)
    }
}

trait RecordIter<'r>: Iterator<Item = &'r Record> + Send + 'r {}
impl<'r, T> RecordIter<'r> for T where T: Iterator<Item = &'r Record> + Send + 'r {}

#[async_trait::async_trait]
impl ResponseHandler for Response {
    async fn send_response<'r>(
        &mut self,
        response: MessageResponse<
            '_,
            'r,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
        >,
    ) -> io::Result<ResponseInfo> {
        let max_size = if let Some(edns) = response.get_edns() {
            edns.max_payload()
        } else {
            hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
        };

        let mut this = self.lock();
        let mut encoder = BinEncoder::new(this.as_mut());
        encoder.set_max_size(max_size);
        response
            .destructive_emit(&mut encoder)
            .map_err(io::Error::other)
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct DnsServer {
    mgr: Arc<DnsNodeMgr>,

    #[derivative(Debug = "ignore")]
    catalog: DynamicCatalog,

    my_peer_id: PeerId,
    addresses: Arc<RwLock<HashSet<NameServerAddr>>>,
}

const DNS_SERVER_LISTENER_TCP_TIMEOUT: Duration = Duration::from_secs(5);

impl DnsServer {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let mgr = Arc::new(DnsNodeMgr::new());
        peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                DnsNodeMgrRpcServer::new_arc(mgr.clone()),
                &peer_mgr.get_global_ctx_ref().get_network_name(),
            );

        Self {
            mgr,
            catalog: DynamicCatalog::new(),
            my_peer_id: peer_mgr.my_peer_id(),
            addresses: Arc::new(Default::default()),
        }
    }

    async fn reload_addresses(&self, addresses: impl IntoIterator<Item = NameServerAddr>) {
        let addresses = addresses.into_iter().collect::<HashSet<_>>();
        let mut current = self.addresses.write().await; // TODO: read?

        if *current == addresses {
            return;
        }

        let added = addresses.difference(&*current).cloned().collect_vec();
        let removed = current.difference(&addresses).cloned().collect_vec();

        *current = addresses;

        // TODO
    }

    async fn reload_listeners(
        &self,
        listeners: impl IntoIterator<Item = NameServerAddr>,
        runtime: &mut Option<DnsServerRuntime>,
    ) -> anyhow::Result<()> {
        if let Some(old) = runtime.take() {
            old.stop().await?;
        }

        let mut new = ServerFuture::new(self.catalog.clone());
        for listener in listeners {
            let addr = listener.addr;
            if let Err(e) = match listener.protocol {
                Protocol::Udp => bind_socket(addr, None).map(|s| new.register_socket(s)),
                Protocol::Tcp => bind_socket(addr, None)
                    .map(|s| new.register_listener(s, DNS_SERVER_LISTENER_TCP_TIMEOUT)),
                _ => unimplemented!(),
            } {
                tracing::error!("failed to bind DNS server on {}: {:?}", addr, e);
            }
        }

        runtime.replace(DnsServerRuntime::start(new));

        Ok(())
    }

    pub async fn run(&self) {
        let dirty = &self.mgr.dirty;

        tokio::join!(
            async {
                loop {
                    dirty.catalog.notified().await;
                    if dirty.catalog.reset() {
                        self.catalog.replace(self.mgr.catalog()).await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            async {
                loop {
                    dirty.addresses.notified().await;
                    if dirty.addresses.reset() {
                        self.reload_addresses(self.mgr.iter_addresses()).await;
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
            async {
                let mut runtime = None;
                loop {
                    dirty.listeners.notified().await;
                    if dirty.listeners.reset() {
                        if let Err(e) = self
                            .reload_listeners(self.mgr.iter_listeners(), &mut runtime)
                            .await
                        {
                            tracing::error!("failed to reload listeners: {:?}", e);
                            dirty.listeners.mark();
                        }
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            },
        );
    }
}

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
    async fn is_hijacked_ip(&self, ip: &IpAddr) -> bool {
        self.addresses
            .read()
            .await
            .iter()
            .any(|a| a.addr.ip() == *ip)
    }

    async fn is_hijacked_addr(&self, addr: &NameServerAddr) -> bool {
        self.addresses.read().await.contains(addr)
    }

    /// Replace content of incoming UDP DNS request and ICMP echo request packet with reply data,
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

        if !self.is_hijacked_ip(&dst_ip.into()).await {
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
        zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.my_peer_id.into();

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
                Request::new(
                    MessageRequest::from_bytes(request_payload).ok()?,
                    SocketAddr::from(SocketAddrV4::new(src_ip, src_port)),
                    Protocol::Udp,
                ),
                request_payload.len(),
            )
        };

        if !self
            .is_hijacked_addr(&SocketAddr::new(dst_ip.into(), dst_port).into())
            .await
        {
            return None;
        }

        let response_payload = {
            let response = Response::new(512);

            self.catalog
                .handle_request(&request, response.clone())
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

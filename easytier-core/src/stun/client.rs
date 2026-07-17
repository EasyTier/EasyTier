//! Portable STUN clients and NAT classification.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context as _;
use bytecodec::{DecodeExt as _, EncodeExt as _};
use quanta::Instant;
use rand::seq::IteratorRandom as _;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _},
    sync::{Mutex, broadcast},
    task::JoinSet,
};
use tracing::{Instrument as _, Level};

use crate::{
    host::dns::{DnsQuery, DnsRecordResolver, DnsResolver},
    proto::common::NatType,
    socket::{
        IpVersion, SocketContext,
        tcp::{TcpBindOptions, TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::{Attribute, ChangeRequest, tid_to_u32, u32_to_tid};
use stun_codec::rfc5389::methods::BINDING;

pub trait StunSocketRuntime: VirtualUdpSocketFactory + VirtualTcpSocketFactory {}

impl<T> StunSocketRuntime for T where T: VirtualUdpSocketFactory + VirtualTcpSocketFactory {}

pub trait StunDnsRuntime: DnsResolver + DnsRecordResolver {}

impl<T> StunDnsRuntime for T where T: DnsResolver + DnsRecordResolver {}

pub(super) struct HostResolverIter<D: ?Sized> {
    dns: Arc<D>,
    context: SocketContext,
    hostnames: Vec<String>,
    ips: Vec<SocketAddr>,
    max_ip_per_domain: u32,
    use_ipv6: bool,
}

impl<D> HostResolverIter<D>
where
    D: StunDnsRuntime + ?Sized,
{
    pub(super) fn new(
        dns: Arc<D>,
        context: SocketContext,
        hostnames: Vec<String>,
        max_ip_per_domain: u32,
        use_ipv6: bool,
    ) -> Self {
        Self {
            dns,
            context,
            hostnames,
            ips: Vec::new(),
            max_ip_per_domain,
            use_ipv6,
        }
    }

    async fn get_txt_record(&self, domain_name: &str) -> anyhow::Result<Vec<String>> {
        let txt_data = self
            .dns
            .resolve_txt(DnsQuery::new(domain_name, self.context.clone()))
            .await?;
        Ok(txt_data.split_whitespace().map(str::to_owned).collect())
    }

    pub(super) async fn next(&mut self) -> Option<SocketAddr> {
        loop {
            if let Some(addr) = self.ips.pop() {
                return Some(addr);
            }

            if self.hostnames.is_empty() {
                return None;
            }

            let endpoint = self.hostnames.remove(0);
            if let Some(domain_name) = endpoint.strip_prefix("txt:") {
                match self.get_txt_record(domain_name).await {
                    Ok(hosts) => {
                        tracing::info!(
                            ?domain_name,
                            ?hosts,
                            "get txt record success when resolve stun server"
                        );
                        self.hostnames.splice(0..0, hosts);
                    }
                    Err(error) => {
                        tracing::warn!(
                            ?domain_name,
                            ?error,
                            "get txt record failed when resolve stun server"
                        );
                    }
                }
                continue;
            }

            if let Some(addr) = explicit_socket_addr(&endpoint) {
                if addr.is_ipv6() == self.use_ipv6 {
                    return Some(addr);
                }
                continue;
            }

            let Some((host, port)) = host_and_port(&endpoint) else {
                tracing::warn!(?endpoint, "invalid stun server endpoint");
                continue;
            };
            match self
                .dns
                .resolve(DnsQuery::new(host.clone(), self.context.clone()))
                .await
            {
                Ok(ips) => {
                    self.ips = ips
                        .into_iter()
                        .filter(|ip| ip.is_ipv6() == self.use_ipv6)
                        .map(|ip| SocketAddr::new(ip, port))
                        .choose_multiple(&mut rand::thread_rng(), self.max_ip_per_domain as usize);
                }
                Err(error) => {
                    tracing::warn!(?host, ?error, "lookup host for stun failed");
                }
            }
        }
    }
}

fn explicit_socket_addr(endpoint: &str) -> Option<SocketAddr> {
    if let Ok(addr) = endpoint.parse() {
        return Some(addr);
    }
    endpoint
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, 3478))
}

fn host_and_port(endpoint: &str) -> Option<(String, u16)> {
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            Some((host.to_owned(), port.parse::<u16>().ok()?))
        }
        _ => Some((endpoint.to_owned(), 3478)),
    }
}

#[derive(Debug, Clone)]
struct StunPacket {
    data: Vec<u8>,
    addr: SocketAddr,
}

type StunPacketReceiver = broadcast::Receiver<StunPacket>;

#[derive(Debug, Clone, Copy)]
pub(super) struct BindRequestResponse {
    pub(super) local_addr: SocketAddr,
    pub(super) stun_server_addr: SocketAddr,
    pub(super) recv_from_addr: SocketAddr,
    pub(super) mapped_socket_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    changed_socket_addr: Option<SocketAddr>,
    #[allow(dead_code)]
    change_ip: bool,
    #[allow(dead_code)]
    change_port: bool,
    real_ip_changed: bool,
    real_port_changed: bool,
    #[allow(dead_code)]
    latency_us: u32,
}

#[derive(Debug, Clone)]
struct StunClient<S> {
    stun_server: SocketAddr,
    resp_timeout: Duration,
    req_repeat: u32,
    socket: Arc<S>,
    stun_packet_receiver: Arc<Mutex<StunPacketReceiver>>,
}

impl<S> StunClient<S>
where
    S: VirtualUdpSocket,
{
    fn new(
        stun_server: SocketAddr,
        socket: Arc<S>,
        stun_packet_receiver: StunPacketReceiver,
    ) -> Self {
        Self {
            stun_server,
            resp_timeout: Duration::from_millis(3000),
            req_repeat: 2,
            socket,
            stun_packet_receiver: Arc::new(Mutex::new(stun_packet_receiver)),
        }
    }

    async fn wait_stun_response(
        &self,
        tids: &[u32],
        stun_host: &SocketAddr,
    ) -> anyhow::Result<(Message<Attribute>, SocketAddr)> {
        let mut now = tokio::time::Instant::now();
        let deadline = now + self.resp_timeout;

        while now < deadline {
            let mut receiver = self.stun_packet_receiver.lock().await;
            let packet = tokio::time::timeout(deadline - now, receiver.recv()).await??;
            now = tokio::time::Instant::now();

            if packet.data.len() < 20 {
                continue;
            }

            let mut decoder = MessageDecoder::<Attribute>::new();
            let Ok(message) = decoder
                .decode_from_bytes(&packet.data)
                .with_context(|| format!("decode stun message from {}", packet.addr))?
            else {
                continue;
            };

            tracing::trace!(
                data = ?packet.data,
                ?tids,
                remote_addr = ?packet.addr,
                ?stun_host,
                "recv stun response: {message:#?}"
            );

            if message.class() != MessageClass::SuccessResponse
                || message.method() != BINDING
                || !tids.contains(&tid_to_u32(&message.transaction_id()))
            {
                continue;
            }

            return Ok((message, packet.addr));
        }

        anyhow::bail!("timed out waiting for STUN response")
    }

    fn extract_mapped_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::MappedAddress(addr) => Some(addr.address()),
            Attribute::XorMappedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    fn extract_changed_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::OtherAddress(addr) => Some(addr.address()),
            Attribute::ChangedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    #[tracing::instrument(ret, level = Level::TRACE, skip(self))]
    async fn bind_request(
        self,
        change_ip: bool,
        change_port: bool,
    ) -> anyhow::Result<BindRequestResponse> {
        let stun_host = self.stun_server;
        let mut tids = Vec::new();
        for _ in 0..self.req_repeat {
            let tid = rand::random::<u32>();
            let mut message =
                Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
            message.add_attribute(ChangeRequest::new(change_ip, change_port));
            let bytes = MessageEncoder::new()
                .encode_into_bytes(message.clone())
                .with_context(|| "encode stun message")?;
            tids.push(tid);
            tracing::trace!(?message, ?bytes, tid, "send stun request");
            self.socket.send_to(&bytes, stun_host).await?;
        }

        let now = Instant::now();
        let (message, recv_addr) = self.wait_stun_response(&tids, &stun_host).await?;
        let changed_socket_addr = Self::extract_changed_addr(&message);
        let response = BindRequestResponse {
            local_addr: self.socket.local_addr()?,
            stun_server_addr: stun_host,
            recv_from_addr: recv_addr,
            mapped_socket_addr: Self::extract_mapped_addr(&message),
            changed_socket_addr,
            change_ip,
            change_port,
            real_ip_changed: stun_host.ip() != recv_addr.ip(),
            real_port_changed: stun_host.port() != recv_addr.port(),
            latency_us: now.elapsed().as_micros() as u32,
        };

        tracing::trace!(
            ?stun_host,
            ?recv_addr,
            ?changed_socket_addr,
            "finish stun bind request"
        );
        Ok(response)
    }
}

struct StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    socket: Arc<S>,
    tasks: JoinSet<()>,
    stun_packet_sender: broadcast::Sender<StunPacket>,
}

impl<S> StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    fn new(socket: Arc<S>) -> Self {
        let (stun_packet_sender, _) = broadcast::channel(1024);
        let mut tasks = JoinSet::new();
        let listener_socket = socket.clone();
        let sender = stun_packet_sender.clone();
        tasks.spawn(
            async move {
                let mut buf = [0; 1620];
                tracing::trace!("start stun packet listener");
                loop {
                    let Ok((len, addr)) = listener_socket.recv_from(&mut buf).await else {
                        tracing::error!("udp recv_from error");
                        break;
                    };
                    let data = buf[..len].to_vec();
                    tracing::trace!(?addr, ?data, "recv udp stun packet");
                    let _ = sender.send(StunPacket { data, addr });
                }
            }
            .instrument(tracing::info_span!("stun_packet_listener")),
        );
        Self {
            socket,
            tasks,
            stun_packet_sender,
        }
    }

    fn new_stun_client(&self, stun_server: SocketAddr) -> StunClient<S> {
        StunClient::new(
            stun_server,
            self.socket.clone(),
            self.stun_packet_sender.subscribe(),
        )
    }

    async fn stop(&mut self) {
        self.tasks.shutdown().await;
    }
}

impl<S> Drop for StunClientBuilder<S>
where
    S: VirtualUdpSocket,
{
    fn drop(&mut self) {
        self.tasks.abort_all();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone)]
pub struct StunNatTypeDetectResult {
    transport: StunTransport,
    source_addr: SocketAddr,
    pub(super) stun_resps: Vec<BindRequestResponse>,
    pub(super) extra_bind_test: Option<BindRequestResponse>,
}

impl StunNatTypeDetectResult {
    fn new(
        transport: StunTransport,
        source_addr: SocketAddr,
        stun_resps: Vec<BindRequestResponse>,
    ) -> Self {
        Self {
            transport,
            source_addr,
            stun_resps,
            extra_bind_test: None,
        }
    }

    fn has_ip_changed_resp(&self) -> bool {
        self.stun_resps.iter().any(|resp| resp.real_ip_changed)
    }

    fn has_port_changed_resp(&self) -> bool {
        self.stun_resps.iter().any(|resp| resp.real_port_changed)
    }

    fn is_open_internet(&self) -> bool {
        self.stun_resps
            .iter()
            .any(|resp| resp.mapped_socket_addr == Some(self.source_addr))
    }

    fn is_no_pat(&self) -> bool {
        self.stun_resps.iter().any(|resp| {
            resp.mapped_socket_addr.map(|addr| addr.port()) == Some(self.source_addr.port())
        })
    }

    fn stun_server_count(&self) -> usize {
        self.stun_resps
            .iter()
            .map(|resp| resp.recv_from_addr)
            .collect::<BTreeSet<_>>()
            .len()
    }

    fn is_cone(&self) -> bool {
        self.stun_resps
            .iter()
            .filter_map(|resp| resp.mapped_socket_addr)
            .collect::<BTreeSet<_>>()
            .len()
            == 1
    }

    fn nat_type_udp(&self) -> NatType {
        if self.stun_server_count() < 2 {
            return NatType::Unknown;
        }

        if self.is_cone() {
            if self.has_ip_changed_resp() {
                if self.is_open_internet() {
                    NatType::OpenInternet
                } else if self.is_no_pat() {
                    NatType::NoPat
                } else {
                    NatType::FullCone
                }
            } else if self.has_port_changed_resp() {
                NatType::Restricted
            } else {
                NatType::PortRestricted
            }
        } else if !self.stun_resps.is_empty() {
            if self.public_ips().len() != 1
                || self.usable_stun_resp_count() <= 1
                || self.max_port() - self.min_port() > 15
            {
                NatType::Symmetric
            } else if let Some(extra_bind_mapped) = self
                .extra_bind_test
                .as_ref()
                .and_then(|extra| extra.mapped_socket_addr)
            {
                let extra_port = extra_bind_mapped.port();
                let max_port_diff = extra_port.saturating_sub(self.max_port());
                let min_port_diff = self.min_port().saturating_sub(extra_port);
                if max_port_diff != 0 && max_port_diff < 100 {
                    NatType::SymmetricEasyInc
                } else if min_port_diff != 0 && min_port_diff < 100 {
                    NatType::SymmetricEasyDec
                } else {
                    NatType::Symmetric
                }
            } else {
                NatType::Symmetric
            }
        } else {
            NatType::Unknown
        }
    }

    fn nat_type_tcp(&self) -> NatType {
        if self.is_open_internet() {
            return NatType::OpenInternet;
        }
        if self.stun_server_count() < 2 || self.stun_resps.is_empty() {
            return NatType::Unknown;
        }
        if self.is_cone() {
            if self.is_no_pat() {
                NatType::NoPat
            } else {
                NatType::FullCone
            }
        } else {
            NatType::Symmetric
        }
    }

    pub fn nat_type(&self) -> NatType {
        match self.transport {
            StunTransport::Udp => self.nat_type_udp(),
            StunTransport::Tcp => self.nat_type_tcp(),
        }
    }

    pub fn public_ips(&self) -> Vec<IpAddr> {
        self.stun_resps
            .iter()
            .filter_map(|resp| resp.mapped_socket_addr.map(|addr| addr.ip()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn collect_available_stun_server(&self) -> Vec<SocketAddr> {
        let mut servers = Vec::new();
        for response in &self.stun_resps {
            if !servers.contains(&response.stun_server_addr) {
                servers.push(response.stun_server_addr);
            }
        }
        servers
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.source_addr
    }

    pub fn extend_result(&mut self, other: Self) {
        self.stun_resps.extend(other.stun_resps);
    }

    pub fn min_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|response| response.mapped_socket_addr.map(|addr| addr.port()))
            .min()
            .unwrap_or(0)
    }

    pub fn max_port(&self) -> u16 {
        self.stun_resps
            .iter()
            .filter_map(|response| response.mapped_socket_addr.map(|addr| addr.port()))
            .max()
            .unwrap_or(u16::MAX)
    }

    pub fn usable_stun_resp_count(&self) -> usize {
        self.stun_resps
            .iter()
            .filter(|response| response.mapped_socket_addr.is_some())
            .count()
    }
}

pub struct UdpNatTypeDetector<R, D: ?Sized> {
    runtime: Arc<R>,
    dns: Arc<D>,
    socket_context: SocketContext,
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
}

impl<R, D> UdpNatTypeDetector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime + ?Sized,
{
    pub fn new(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        stun_server_hosts: Vec<String>,
        max_ip_per_domain: u32,
    ) -> Self {
        Self {
            runtime,
            dns,
            socket_context,
            stun_server_hosts,
            max_ip_per_domain,
        }
    }

    pub(super) async fn get_extra_bind_result(
        &self,
        source_port: u16,
        stun_server: SocketAddr,
    ) -> anyhow::Result<BindRequestResponse> {
        let socket = self
            .runtime
            .bind_udp(stun_udp_bind_options(
                self.socket_context.clone(),
                IpVersion::V4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), source_port),
            ))
            .await?;
        udp_bind_request(socket, stun_server).await
    }

    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let socket = self
            .runtime
            .bind_udp(stun_udp_bind_options(
                self.socket_context.clone(),
                IpVersion::V4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), source_port),
            ))
            .await?;
        self.detect_nat_type_with_socket(socket).await
    }

    #[tracing::instrument(skip(self, socket))]
    pub async fn detect_nat_type_with_socket(
        &self,
        socket: Arc<<R as VirtualUdpSocketFactory>::Socket>,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let mut resolver = HostResolverIter::new(
            self.dns.clone(),
            self.socket_context.clone().with_ip_version(IpVersion::V4),
            self.stun_server_hosts.clone(),
            self.max_ip_per_domain,
            false,
        );
        let mut stun_servers = Vec::new();
        while let Some(addr) = resolver.next().await {
            stun_servers.push(addr);
        }

        let client_builder = StunClientBuilder::new(socket.clone());
        let mut tasks = JoinSet::new();
        for stun_server in stun_servers {
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(false, false),
            );
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(false, true),
            );
            tasks.spawn(
                client_builder
                    .new_stun_client(stun_server)
                    .bind_request(true, true),
            );
        }

        let mut responses = Vec::new();
        while let Some(response) = tasks.join_next().await {
            if let Ok(Ok(response)) = response {
                responses.push(response);
            }
        }
        Ok(StunNatTypeDetectResult::new(
            StunTransport::Udp,
            socket.local_addr()?,
            responses,
        ))
    }
}

pub(super) async fn udp_bind_request<S>(
    socket: Arc<S>,
    stun_server: SocketAddr,
) -> anyhow::Result<BindRequestResponse>
where
    S: VirtualUdpSocket,
{
    let mut clients = StunClientBuilder::new(socket);
    let result = clients
        .new_stun_client(stun_server)
        .bind_request(false, false)
        .await;
    clients.stop().await;
    result
}

pub(super) fn stun_udp_bind_options(
    context: SocketContext,
    ip_version: IpVersion,
    local_addr: SocketAddr,
) -> UdpBindOptions {
    UdpBindOptions::stun_probe()
        .with_context(context.with_ip_version(ip_version))
        .with_local_addr(Some(local_addr))
}

struct TcpStunClient<R> {
    runtime: Arc<R>,
    socket_context: SocketContext,
    stun_server: SocketAddr,
    conn_timeout: Duration,
    io_timeout: Duration,
    source_port: u16,
}

impl<R> TcpStunClient<R>
where
    R: StunSocketRuntime,
{
    fn new(
        runtime: Arc<R>,
        socket_context: SocketContext,
        stun_server: SocketAddr,
        source_port: u16,
    ) -> Self {
        Self {
            runtime,
            socket_context,
            stun_server,
            conn_timeout: Duration::from_millis(1500),
            io_timeout: Duration::from_millis(3000),
            source_port,
        }
    }

    fn extract_mapped_addr(message: &Message<Attribute>) -> Option<SocketAddr> {
        message.attributes().find_map(|attribute| match attribute {
            Attribute::MappedAddress(addr) => Some(addr.address()),
            Attribute::XorMappedAddress(addr) => Some(addr.address()),
            _ => None,
        })
    }

    fn message_size_from_header(header: &[u8; 20]) -> anyhow::Result<usize> {
        if (header[0] & 0b1100_0000) != 0 {
            anyhow::bail!("invalid stun message type")
        }
        let message_len = u16::from_be_bytes([header[2], header[3]]) as usize;
        if !message_len.is_multiple_of(4) {
            anyhow::bail!("invalid stun message length")
        }
        let total = 20usize
            .checked_add(message_len)
            .context("invalid stun message size")?;
        if total > 4096 {
            anyhow::bail!("stun message too large")
        }
        Ok(total)
    }

    async fn tcp_read_stun_message<S>(
        stream: &mut S,
        timeout: Duration,
    ) -> anyhow::Result<Message<Attribute>>
    where
        S: AsyncRead + Unpin,
    {
        let mut header = [0u8; 20];
        tokio::time::timeout(timeout, stream.read_exact(&mut header)).await??;
        let total_size = Self::message_size_from_header(&header)?;
        let mut buf = vec![0u8; total_size];
        buf[..20].copy_from_slice(&header);
        if total_size > 20 {
            tokio::time::timeout(timeout, stream.read_exact(&mut buf[20..])).await??;
        }

        let mut decoder = MessageDecoder::<Attribute>::new();
        let Ok(message) = decoder
            .decode_from_bytes(&buf)
            .with_context(|| "decode tcp stun message")?
        else {
            anyhow::bail!("invalid stun message")
        };
        Ok(message)
    }

    async fn connect(&self) -> anyhow::Result<<R as VirtualTcpSocketFactory>::Socket> {
        let (bind_addr, ip_version) = match self.stun_server {
            SocketAddr::V4(_) => (
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), self.source_port),
                IpVersion::V4,
            ),
            SocketAddr::V6(_) => (
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), self.source_port),
                IpVersion::V6,
            ),
        };
        let bind = TcpBindOptions::default()
            .with_context(self.socket_context.clone().with_ip_version(ip_version))
            .with_local_addr(Some(bind_addr))
            .with_reuse_addr(true)
            .with_reuse_port(true)
            .with_only_v6(bind_addr.is_ipv6());
        Ok(tokio::time::timeout(
            self.conn_timeout,
            self.runtime.connect_tcp(
                TcpConnectOptions::stun_probe(self.stun_server, bind_addr).with_bind(bind),
            ),
        )
        .await??)
    }

    #[tracing::instrument(ret, level = Level::TRACE, skip(self))]
    async fn bind_request(self) -> anyhow::Result<BindRequestResponse> {
        let mut stream = self.connect().await?;
        let local_addr = stream.local_addr()?;
        let stun_host = self.stun_server;
        let tid = rand::random::<u32>();
        let message = Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(tid));
        let bytes = MessageEncoder::new()
            .encode_into_bytes(message)
            .with_context(|| "encode tcp stun message")?;
        tokio::time::timeout(self.io_timeout, stream.write_all(&bytes)).await??;

        let now = Instant::now();
        let message = Self::tcp_read_stun_message(&mut stream, self.io_timeout).await?;
        if message.class() != MessageClass::SuccessResponse
            || message.method() != BINDING
            || tid_to_u32(&message.transaction_id()) != tid
        {
            anyhow::bail!("unexpected stun response")
        }

        Ok(BindRequestResponse {
            local_addr,
            stun_server_addr: stun_host,
            recv_from_addr: stun_host,
            mapped_socket_addr: Self::extract_mapped_addr(&message),
            changed_socket_addr: None,
            change_ip: false,
            change_port: false,
            real_ip_changed: false,
            real_port_changed: false,
            latency_us: now.elapsed().as_micros() as u32,
        })
    }
}

pub(super) async fn tcp_bind_request<R>(
    runtime: Arc<R>,
    socket_context: SocketContext,
    stun_server: SocketAddr,
    source_port: u16,
) -> anyhow::Result<BindRequestResponse>
where
    R: StunSocketRuntime,
{
    TcpStunClient::new(runtime, socket_context, stun_server, source_port)
        .bind_request()
        .await
}

pub struct TcpNatTypeDetector<R, D: ?Sized> {
    runtime: Arc<R>,
    dns: Arc<D>,
    socket_context: SocketContext,
    stun_server_hosts: Vec<String>,
    max_ip_per_domain: u32,
}

impl<R, D> TcpNatTypeDetector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime + ?Sized,
{
    pub fn new(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        stun_server_hosts: Vec<String>,
        max_ip_per_domain: u32,
    ) -> Self {
        Self {
            runtime,
            dns,
            socket_context,
            stun_server_hosts,
            max_ip_per_domain,
        }
    }

    #[tracing::instrument(skip(self))]
    pub async fn detect_nat_type(
        &self,
        source_port: u16,
    ) -> anyhow::Result<StunNatTypeDetectResult> {
        let mut resolver = HostResolverIter::new(
            self.dns.clone(),
            self.socket_context.clone().with_ip_version(IpVersion::V4),
            self.stun_server_hosts.clone(),
            self.max_ip_per_domain,
            false,
        );
        let mut stun_servers = Vec::new();
        while let Some(addr) = resolver.next().await {
            stun_servers.push(addr);
        }

        let mut responses = Vec::new();
        let mut source_addr = None;
        let mut selected_source_port = (source_port != 0).then_some(source_port);
        for server in stun_servers {
            let response = TcpStunClient::new(
                self.runtime.clone(),
                self.socket_context.clone(),
                server,
                selected_source_port.unwrap_or(0),
            )
            .bind_request()
            .await;
            if let Ok(response) = response {
                if selected_source_port.is_none() {
                    selected_source_port = Some(response.local_addr.port());
                }
                source_addr.get_or_insert(response.local_addr);
                responses.push(response);
                if responses.len() >= 3 {
                    break;
                }
            }
        }

        let source_addr = source_addr.context("no TCP STUN response")?;
        Ok(StunNatTypeDetectResult::new(
            StunTransport::Tcp,
            source_addr,
            responses,
        ))
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;

    use crate::host::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};

    use super::*;

    struct EmptyDns;

    #[async_trait]
    impl DnsResolver for EmptyDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(Vec::new())
        }
    }

    #[async_trait]
    impl DnsRecordResolver for EmptyDns {
        async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
            Ok(String::new())
        }

        async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn explicit_endpoints_keep_ports_and_default_bare_ips() {
        assert_eq!(
            explicit_socket_addr("127.0.0.1:5555"),
            Some("127.0.0.1:5555".parse().unwrap())
        );
        assert_eq!(
            explicit_socket_addr("[::1]:5555"),
            Some("[::1]:5555".parse().unwrap())
        );
        assert_eq!(
            explicit_socket_addr("2001:db8::1"),
            Some("[2001:db8::1]:3478".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn invalid_endpoint_does_not_hide_later_servers() {
        let mut resolver = HostResolverIter::new(
            Arc::new(EmptyDns),
            SocketContext::default(),
            vec![
                "bad.example:not-a-port".to_owned(),
                "127.0.0.1:3478".to_owned(),
            ],
            1,
            false,
        );

        assert_eq!(
            resolver.next().await,
            Some("127.0.0.1:3478".parse().unwrap())
        );
    }

    #[test]
    fn stun_udp_bind_request_preserves_context_and_family() {
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(crate::socket::NetNamespace::new("instance-a")));
        let local_addr = "0.0.0.0:0".parse().unwrap();

        let options = stun_udp_bind_options(context, IpVersion::V4, local_addr);

        assert_eq!(options.context.ip_version, IpVersion::V4);
        assert_eq!(options.context.socket_mark, Some(0));
        assert_eq!(
            options.context.netns.as_ref().map(|netns| netns.token()),
            Some("instance-a")
        );
        assert_eq!(options.local_addr, Some(local_addr));
        assert_eq!(
            options.purpose,
            crate::socket::udp::UdpSocketPurpose::StunProbe
        );
    }
}

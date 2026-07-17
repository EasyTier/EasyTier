//! Per-instance STUN state and background detection lifecycle.

use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use rand::seq::IteratorRandom as _;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;

use crate::{
    proto::common::{NatType, StunInfo},
    socket::{
        IpVersion, SocketContext,
        udp::{VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};

use super::client::{
    HostResolverIter, StunDnsRuntime, StunNatTypeDetectResult, StunSocketRuntime,
    TcpNatTypeDetector, UdpNatTypeDetector, stun_udp_bind_options, tcp_bind_request,
    udp_bind_request,
};

const DEFAULT_UDP_STUN_SERVERS: &[&str] = &[
    "txt:stun.easytier.cn",
    "stun.miwifi.com",
    "stun.chat.bilibili.com",
    "stun.hitv.com",
];

const DEFAULT_TCP_STUN_SERVERS: &[&str] = &[
    "stun.hot-chilli.net",
    "stun.fitauto.ru",
    "fwa.lifesizecloud.com",
    "global.turn.twilio.com",
    "turn.cloudflare.com",
    "stun.voip.blackberry.com",
    "stun.radiojar.com",
];

const DEFAULT_UDP_V6_STUN_SERVERS: &[&str] = &["txt:stun-v6.easytier.cn"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StunServerConfig {
    pub udp_servers: Vec<String>,
    pub tcp_servers: Vec<String>,
    pub udp_v6_servers: Vec<String>,
}

impl Default for StunServerConfig {
    fn default() -> Self {
        Self {
            udp_servers: DEFAULT_UDP_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect(),
            tcp_servers: DEFAULT_TCP_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect(),
            udp_v6_servers: DEFAULT_UDP_V6_STUN_SERVERS
                .iter()
                .map(ToString::to_string)
                .collect(),
        }
    }
}

#[async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait StunInfoProvider: Send + Sync {
    fn get_stun_info(&self) -> StunInfo;

    async fn get_udp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr>;

    async fn get_tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr>;

    fn update_stun_info(&self);
}

#[async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait StunSocketMapper<S>: StunInfoProvider + Send + Sync
where
    S: VirtualUdpSocket,
{
    async fn get_udp_port_mapping_with_socket(&self, socket: Arc<S>) -> anyhow::Result<SocketAddr>;
}

/// Stable per-instance handle whose underlying STUN provider can be replaced.
///
/// Each async operation snapshots the current provider before awaiting so a
/// replacement never holds the slot lock across host I/O.
pub struct StunProviderSlot<S>
where
    S: VirtualUdpSocket,
{
    provider: RwLock<Option<Arc<dyn StunSocketMapper<S>>>>,
}

impl<S> StunProviderSlot<S>
where
    S: VirtualUdpSocket,
{
    pub fn new(provider: Arc<dyn StunSocketMapper<S>>) -> Self {
        Self {
            provider: RwLock::new(Some(provider)),
        }
    }

    #[cfg(test)]
    pub fn empty() -> Self {
        Self {
            provider: RwLock::new(None),
        }
    }

    /// Installs the production provider without overwriting an explicitly
    /// preinstalled test provider.
    pub fn install_if_empty(&self, provider: Arc<dyn StunSocketMapper<S>>) -> bool {
        let mut current = self.provider.write().unwrap();
        if current.is_some() {
            return false;
        }
        *current = Some(provider);
        true
    }

    #[cfg(test)]
    pub fn replace(&self, provider: Arc<dyn StunSocketMapper<S>>) {
        *self.provider.write().unwrap() = Some(provider);
    }

    fn current(&self) -> Option<Arc<dyn StunSocketMapper<S>>> {
        self.provider.read().unwrap().clone()
    }
}

#[async_trait]
impl<S> StunInfoProvider for StunProviderSlot<S>
where
    S: VirtualUdpSocket + 'static,
{
    fn get_stun_info(&self) -> StunInfo {
        self.current()
            .map(|provider| provider.get_stun_info())
            .unwrap_or_default()
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        let provider = self
            .current()
            .ok_or_else(|| anyhow::anyhow!("STUN provider is not installed"))?;
        provider.get_udp_port_mapping(local_port).await
    }

    async fn get_tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        let provider = self
            .current()
            .ok_or_else(|| anyhow::anyhow!("STUN provider is not installed"))?;
        provider.get_tcp_port_mapping(local_port).await
    }

    fn update_stun_info(&self) {
        if let Some(provider) = self.current() {
            provider.update_stun_info();
        }
    }
}

#[async_trait]
impl<S> StunSocketMapper<S> for StunProviderSlot<S>
where
    S: VirtualUdpSocket + 'static,
{
    async fn get_udp_port_mapping_with_socket(&self, socket: Arc<S>) -> anyhow::Result<SocketAddr> {
        let provider = self
            .current()
            .ok_or_else(|| anyhow::anyhow!("STUN provider is not installed"))?;
        provider.get_udp_port_mapping_with_socket(socket).await
    }
}

pub struct StunInfoCollector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime,
{
    runtime: Arc<R>,
    dns: Arc<D>,
    udp_socket_context: SocketContext,
    tcp_socket_context: SocketContext,
    stun_servers: Arc<RwLock<Vec<String>>>,
    tcp_stun_servers: Arc<RwLock<Vec<String>>>,
    stun_servers_v6: Arc<RwLock<Vec<String>>>,
    udp_nat_test_result: Arc<RwLock<Option<StunNatTypeDetectResult>>>,
    tcp_nat_test_result: Arc<RwLock<Option<StunNatTypeDetectResult>>>,
    public_ipv6: Arc<RwLock<Option<Ipv6Addr>>>,
    nat_test_result_time: Arc<RwLock<i64>>,
    redetect_notify: Arc<tokio::sync::Notify>,
    tasks: Mutex<JoinSet<()>>,
    started: AtomicBool,
}

impl<R, D> StunInfoCollector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime,
{
    pub fn new(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        udp_stun_servers: Vec<String>,
        tcp_stun_servers: Vec<String>,
        stun_servers_v6: Vec<String>,
    ) -> Self {
        Self::new_with_socket_contexts(
            runtime,
            dns,
            socket_context.clone(),
            socket_context,
            udp_stun_servers,
            tcp_stun_servers,
            stun_servers_v6,
        )
    }

    pub fn new_with_socket_contexts(
        runtime: Arc<R>,
        dns: Arc<D>,
        udp_socket_context: SocketContext,
        tcp_socket_context: SocketContext,
        udp_stun_servers: Vec<String>,
        tcp_stun_servers: Vec<String>,
        stun_servers_v6: Vec<String>,
    ) -> Self {
        Self {
            runtime,
            dns,
            udp_socket_context,
            tcp_socket_context,
            stun_servers: Arc::new(RwLock::new(udp_stun_servers)),
            tcp_stun_servers: Arc::new(RwLock::new(tcp_stun_servers)),
            stun_servers_v6: Arc::new(RwLock::new(stun_servers_v6)),
            udp_nat_test_result: Arc::new(RwLock::new(None)),
            tcp_nat_test_result: Arc::new(RwLock::new(None)),
            public_ipv6: Arc::new(RwLock::new(None)),
            nat_test_result_time: Arc::new(RwLock::new(unix_timestamp())),
            redetect_notify: Arc::new(tokio::sync::Notify::new()),
            tasks: Mutex::new(JoinSet::new()),
            started: AtomicBool::new(false),
        }
    }

    pub fn new_with_default_servers(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
    ) -> Self {
        Self::new(
            runtime,
            dns,
            socket_context,
            Self::get_default_servers(),
            Self::get_default_tcp_servers(),
            Self::get_default_servers_v6(),
        )
    }

    pub fn new_with_default_servers_and_socket_contexts(
        runtime: Arc<R>,
        dns: Arc<D>,
        udp_socket_context: SocketContext,
        tcp_socket_context: SocketContext,
    ) -> Self {
        Self::new_with_socket_contexts(
            runtime,
            dns,
            udp_socket_context,
            tcp_socket_context,
            Self::get_default_servers(),
            Self::get_default_tcp_servers(),
            Self::get_default_servers_v6(),
        )
    }

    pub fn set_stun_servers(&self, stun_servers: Vec<String>) {
        *self.stun_servers.write().unwrap() = stun_servers;
    }

    pub fn set_stun_servers_v6(&self, stun_servers_v6: Vec<String>) {
        *self.stun_servers_v6.write().unwrap() = stun_servers_v6;
    }

    pub fn set_tcp_stun_servers(&self, stun_servers: Vec<String>) {
        *self.tcp_stun_servers.write().unwrap() = stun_servers;
    }

    pub fn get_default_servers() -> Vec<String> {
        StunServerConfig::default().udp_servers
    }

    pub fn get_default_tcp_servers() -> Vec<String> {
        StunServerConfig::default().tcp_servers
    }

    pub fn get_default_servers_v6() -> Vec<String> {
        StunServerConfig::default().udp_v6_servers
    }

    async fn get_public_ipv6(
        runtime: Arc<R>,
        dns: Arc<D>,
        socket_context: SocketContext,
        servers: &[String],
    ) -> Option<Ipv6Addr> {
        let mut resolver = HostResolverIter::new(
            dns,
            socket_context.clone().with_ip_version(IpVersion::V6),
            servers.to_vec(),
            10,
            true,
        );
        while let Some(server) = resolver.next().await {
            let socket = runtime
                .bind_udp(stun_udp_bind_options(
                    socket_context.clone(),
                    IpVersion::V6,
                    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
                ))
                .await
                .ok()?;
            let response = udp_bind_request(socket, server).await;
            tracing::debug!(?response, "finish ipv6 udp nat type detect");
            if let Ok(Some(IpAddr::V6(ip))) =
                response.map(|response| response.mapped_socket_addr.map(|addr| addr.ip()))
            {
                return Some(ip);
            }
        }
        None
    }

    fn start_stun_routine(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }

        let runtime = self.runtime.clone();
        let dns = self.dns.clone();
        let socket_context = self.udp_socket_context.clone();
        let stun_servers = self.stun_servers.clone();
        let udp_nat_test_result = self.udp_nat_test_result.clone();
        let nat_test_time = self.nat_test_result_time.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let servers = sampled_servers(&stun_servers.read().unwrap());
                let detector = UdpNatTypeDetector::new(
                    runtime.clone(),
                    dns.clone(),
                    socket_context.clone(),
                    servers,
                    1,
                );
                let mut result = detector.detect_nat_type(0).await;
                tracing::debug!(?result, "finish udp nat type detect");

                let nat_type = result
                    .as_ref()
                    .map(StunNatTypeDetectResult::nat_type)
                    .unwrap_or(NatType::Unknown);
                if nat_type == NatType::Symmetric {
                    let old_result = result.as_mut().unwrap();
                    tracing::debug!(?old_result, "start get extra bind result");
                    for server in old_result.collect_available_stun_server() {
                        let extra = detector.get_extra_bind_result(0, server).await;
                        tracing::debug!(?extra, "finish udp nat type detect with another port");
                        if let Ok(response) = extra {
                            old_result.extra_bind_test = Some(response);
                            break;
                        }
                    }
                }

                let mut sleep_sec = 10;
                if let Ok(result) = result {
                    *nat_test_time.write().unwrap() = unix_timestamp();
                    let completed_extra_test = result.extra_bind_test.is_some();
                    *udp_nat_test_result.write().unwrap() = Some(result);
                    if nat_type != NatType::Unknown
                        && (nat_type != NatType::Symmetric || completed_extra_test)
                    {
                        sleep_sec = 600;
                    }
                }

                tokio::select! {
                    _ = redetect_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                }
            }
        });

        let runtime = self.runtime.clone();
        let dns = self.dns.clone();
        let socket_context = self.tcp_socket_context.clone();
        let tcp_stun_servers = self.tcp_stun_servers.clone();
        let tcp_nat_test_result = self.tcp_nat_test_result.clone();
        let nat_test_time = self.nat_test_result_time.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let servers = sampled_servers(&tcp_stun_servers.read().unwrap());
                let detector = TcpNatTypeDetector::new(
                    runtime.clone(),
                    dns.clone(),
                    socket_context.clone(),
                    servers,
                    1,
                );
                let result = detector.detect_nat_type(0).await;
                tracing::debug!(?result, "finish tcp nat type detect");

                let mut sleep_sec = 10;
                if let Ok(result) = result {
                    *nat_test_time.write().unwrap() = unix_timestamp();
                    let nat_type = result.nat_type();
                    *tcp_nat_test_result.write().unwrap() = Some(result);
                    if nat_type != NatType::Unknown {
                        sleep_sec = 600;
                    }
                }

                tokio::select! {
                    _ = redetect_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                }
            }
        });

        let runtime = self.runtime.clone();
        let dns = self.dns.clone();
        let socket_context = self.udp_socket_context.clone();
        let stun_servers_v6 = self.stun_servers_v6.clone();
        let public_ipv6 = self.public_ipv6.clone();
        let redetect_notify = self.redetect_notify.clone();
        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let servers = stun_servers_v6.read().unwrap().clone();
                if let Some(ip) = Self::get_public_ipv6(
                    runtime.clone(),
                    dns.clone(),
                    socket_context.clone(),
                    &servers,
                )
                .await
                {
                    *public_ipv6.write().unwrap() = Some(ip);
                }

                let sleep_sec = if public_ipv6.read().unwrap().is_none() {
                    60
                } else {
                    360
                };
                tokio::select! {
                    _ = redetect_notify.notified() => {}
                    _ = tokio::time::sleep(Duration::from_secs(sleep_sec)) => {}
                }
            }
        });
    }
}

#[async_trait]
impl<R, D> StunInfoProvider for StunInfoCollector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime,
{
    fn get_stun_info(&self) -> StunInfo {
        self.start_stun_routine();
        let udp_result = self.udp_nat_test_result.read().unwrap().clone();
        let tcp_result = self.tcp_nat_test_result.read().unwrap().clone();
        if udp_result.is_none() && tcp_result.is_none() {
            return StunInfo::default();
        }

        let mut public_ip = BTreeSet::<String>::new();
        if let Some(result) = &udp_result {
            public_ip.extend(result.public_ips().into_iter().map(|ip| ip.to_string()));
        }
        if let Some(result) = &tcp_result {
            public_ip.extend(result.public_ips().into_iter().map(|ip| ip.to_string()));
        }
        if let Some(ip) = *self.public_ipv6.read().unwrap() {
            public_ip.insert(ip.to_string());
        }

        StunInfo {
            udp_nat_type: udp_result
                .as_ref()
                .map(|result| result.nat_type() as i32)
                .unwrap_or(NatType::Unknown as i32),
            tcp_nat_type: tcp_result
                .as_ref()
                .map(|result| result.nat_type() as i32)
                .unwrap_or(NatType::Unknown as i32),
            last_update_time: *self.nat_test_result_time.read().unwrap(),
            public_ip: public_ip.into_iter().collect(),
            min_port: udp_result
                .as_ref()
                .map(|result| result.min_port() as u32)
                .or_else(|| tcp_result.as_ref().map(|result| result.min_port() as u32))
                .unwrap_or(0),
            max_port: udp_result
                .as_ref()
                .map(|result| result.max_port() as u32)
                .or_else(|| tcp_result.as_ref().map(|result| result.max_port() as u32))
                .unwrap_or(0),
        }
    }

    async fn get_udp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        let socket = self
            .runtime
            .bind_udp(stun_udp_bind_options(
                self.udp_socket_context.clone(),
                IpVersion::V4,
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), local_port),
            ))
            .await?;
        StunSocketMapper::get_udp_port_mapping_with_socket(self, socket).await
    }

    async fn get_tcp_port_mapping(&self, local_port: u16) -> anyhow::Result<SocketAddr> {
        self.start_stun_routine();
        let mut servers = self
            .tcp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|result| result.collect_available_stun_server())
            .unwrap_or_default();
        if servers.is_empty() {
            let mut resolver = HostResolverIter::new(
                self.dns.clone(),
                self.tcp_socket_context
                    .clone()
                    .with_ip_version(IpVersion::V4),
                self.tcp_stun_servers.read().unwrap().clone(),
                2,
                false,
            );
            while let Some(addr) = resolver.next().await {
                servers.push(addr);
                if servers.len() >= 2 {
                    break;
                }
            }
        }

        for server in servers {
            match tcp_bind_request(
                self.runtime.clone(),
                self.tcp_socket_context.clone(),
                server,
                local_port,
            )
            .await
            {
                Ok(response) => {
                    if let Some(mapped_addr) = response.mapped_socket_addr {
                        return Ok(mapped_addr);
                    }
                }
                Err(error) => tracing::warn!(?server, ?error, "tcp stun bind request failed"),
            }
        }
        anyhow::bail!("no TCP STUN mapping found")
    }

    fn update_stun_info(&self) {
        self.redetect_notify.notify_waiters();
    }
}

#[async_trait]
impl<R, D> StunSocketMapper<<R as VirtualUdpSocketFactory>::Socket> for StunInfoCollector<R, D>
where
    R: StunSocketRuntime,
    D: StunDnsRuntime,
{
    async fn get_udp_port_mapping_with_socket(
        &self,
        socket: Arc<<R as VirtualUdpSocketFactory>::Socket>,
    ) -> anyhow::Result<SocketAddr> {
        self.start_stun_routine();
        let mut servers = self
            .udp_nat_test_result
            .read()
            .unwrap()
            .clone()
            .map(|result| result.collect_available_stun_server())
            .unwrap_or_default();
        if servers.is_empty() {
            let mut resolver = HostResolverIter::new(
                self.dns.clone(),
                self.udp_socket_context
                    .clone()
                    .with_ip_version(IpVersion::V4),
                self.stun_servers.read().unwrap().clone(),
                2,
                false,
            );
            while let Some(addr) = resolver.next().await {
                servers.push(addr);
                if servers.len() >= 2 {
                    break;
                }
            }
        }

        for server in servers {
            match udp_bind_request(socket.clone(), server).await {
                Ok(response) => {
                    if let Some(mapped_addr) = response.mapped_socket_addr {
                        return Ok(mapped_addr);
                    }
                }
                Err(error) => tracing::warn!(?server, ?error, "stun bind request failed"),
            }
        }
        anyhow::bail!("no UDP STUN mapping found")
    }
}

fn sampled_servers(servers: &[String]) -> Vec<String> {
    servers
        .iter()
        .take(2)
        .chain(servers.iter().skip(2).choose(&mut rand::thread_rng()))
        .cloned()
        .collect()
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        task::{Context, Poll},
    };

    use bytecodec::{DecodeExt as _, EncodeExt as _};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    use crate::socket::{
        NetNamespace,
        dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord},
        tcp::{TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, UdpSocketPurpose},
    };

    use super::super::Attribute;
    use stun_codec::rfc5389::{attributes::XorMappedAddress, methods::BINDING};
    use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

    use super::*;

    struct MockUdpSocket {
        local_addr: SocketAddr,
        mapped_addr: SocketAddr,
        responses: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
        response_ready: tokio::sync::Notify,
    }

    #[async_trait]
    impl VirtualUdpSocket for MockUdpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            let request = MessageDecoder::<Attribute>::new()
                .decode_from_bytes(data)
                .map_err(|error| io::Error::other(format!("{error:?}")))?
                .map_err(|error| io::Error::other(format!("{error:?}")))?;
            let mut response = Message::<Attribute>::new(
                MessageClass::SuccessResponse,
                BINDING,
                request.transaction_id(),
            );
            response.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(
                self.mapped_addr,
            )));
            let bytes = MessageEncoder::new()
                .encode_into_bytes(response)
                .map_err(io::Error::other)?;
            self.responses.lock().unwrap().push_back((bytes, addr));
            self.response_ready.notify_one();
            Ok(data.len())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            loop {
                if let Some((bytes, addr)) = self.responses.lock().unwrap().pop_front() {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    return Ok((bytes.len(), addr));
                }
                self.response_ready.notified().await;
            }
        }
    }

    struct MockTcpSocket(tokio::io::DuplexStream);

    impl AsyncRead for MockTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockTcpSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for MockTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:40000".parse().unwrap())
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:3478".parse().unwrap())
        }
    }

    #[derive(Default)]
    struct MockRuntime {
        udp_binds: Mutex<Vec<UdpBindOptions>>,
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockRuntime {
        type Socket = MockUdpSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.udp_binds.lock().unwrap().push(options);
            Ok(Arc::new(MockUdpSocket {
                local_addr: "0.0.0.0:40000".parse().unwrap(),
                mapped_addr: "198.51.100.10:40123".parse().unwrap(),
                responses: Mutex::new(VecDeque::new()),
                response_ready: tokio::sync::Notify::new(),
            }))
        }
    }

    #[async_trait]
    impl VirtualTcpSocketFactory for MockRuntime {
        type Socket = MockTcpSocket;

        async fn connect_tcp(&self, _options: TcpConnectOptions) -> anyhow::Result<Self::Socket> {
            anyhow::bail!("TCP is not used by this test")
        }
    }

    struct MockDns;

    #[async_trait]
    impl DnsResolver for MockDns {
        async fn resolve(&self, _query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            Ok(vec!["192.0.2.1".parse().unwrap()])
        }
    }

    #[async_trait]
    impl DnsRecordResolver for MockDns {
        async fn resolve_txt(&self, _query: DnsQuery) -> anyhow::Result<String> {
            Ok(String::new())
        }

        async fn resolve_srv(&self, _query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
            Ok(Vec::new())
        }
    }

    struct FixedStunProvider(u16);

    #[async_trait]
    impl StunInfoProvider for FixedStunProvider {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                min_port: self.0 as u32,
                max_port: self.0 as u32,
                ..Default::default()
            }
        }

        async fn get_udp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], self.0)))
        }

        async fn get_tcp_port_mapping(&self, _local_port: u16) -> anyhow::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], self.0)))
        }

        fn update_stun_info(&self) {}
    }

    #[async_trait]
    impl StunSocketMapper<MockUdpSocket> for FixedStunProvider {
        async fn get_udp_port_mapping_with_socket(
            &self,
            _socket: Arc<MockUdpSocket>,
        ) -> anyhow::Result<SocketAddr> {
            self.get_udp_port_mapping(0).await
        }
    }

    #[tokio::test]
    async fn empty_provider_slot_has_explicit_pre_install_behavior() {
        let slot = StunProviderSlot::<MockUdpSocket>::empty();

        assert_eq!(slot.get_stun_info(), StunInfo::default());
        assert_eq!(
            slot.get_udp_port_mapping(0).await.unwrap_err().to_string(),
            "STUN provider is not installed"
        );
        assert_eq!(
            slot.get_tcp_port_mapping(0).await.unwrap_err().to_string(),
            "STUN provider is not installed"
        );
        slot.update_stun_info();
    }

    #[tokio::test]
    async fn provider_slot_installs_once_and_replaces_live_view() {
        let slot = StunProviderSlot::<MockUdpSocket>::empty();
        let first: Arc<dyn StunSocketMapper<MockUdpSocket>> = Arc::new(FixedStunProvider(11001));
        let second: Arc<dyn StunSocketMapper<MockUdpSocket>> = Arc::new(FixedStunProvider(11002));

        assert!(slot.install_if_empty(first));
        assert_eq!(slot.get_stun_info().min_port, 11001);
        assert!(!slot.install_if_empty(second.clone()));
        assert_eq!(slot.get_stun_info().min_port, 11001);

        slot.replace(second);
        assert_eq!(slot.get_stun_info().min_port, 11002);
        assert_eq!(
            slot.get_udp_port_mapping(0).await.unwrap(),
            SocketAddr::from(([127, 0, 0, 1], 11002))
        );
    }

    #[test]
    fn sampled_servers_keep_first_two_and_at_most_one_extra() {
        let servers = ["a", "b", "c", "d"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let sampled = sampled_servers(&servers);
        assert_eq!(&sampled[..2], &["a", "b"]);
        assert_eq!(sampled.len(), 3);
        assert!(matches!(sampled[2].as_str(), "c" | "d"));
    }

    #[test]
    fn collector_keeps_udp_and_tcp_socket_contexts_separate() {
        let udp_context = SocketContext::default()
            .with_socket_mark(Some(11))
            .with_netns(Some(NetNamespace::new("udp-instance")));
        let tcp_context = SocketContext::default()
            .with_socket_mark(Some(22))
            .with_netns(Some(NetNamespace::new("tcp-instance")));
        let collector = StunInfoCollector::new_with_socket_contexts(
            Arc::new(MockRuntime::default()),
            Arc::new(MockDns),
            udp_context.clone(),
            tcp_context.clone(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
        );

        assert_eq!(collector.udp_socket_context, udp_context);
        assert_eq!(collector.tcp_socket_context, tcp_context);
    }

    #[tokio::test]
    async fn udp_mapping_uses_portable_runtime_and_instance_context() {
        let runtime = Arc::new(MockRuntime::default());
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(NetNamespace::new("instance-a")));
        let collector = StunInfoCollector::new(
            runtime.clone(),
            Arc::new(MockDns),
            context,
            vec!["stun.example".to_owned()],
            Vec::new(),
            Vec::new(),
        );

        let mapped = collector.get_udp_port_mapping(0).await.unwrap();

        assert_eq!(mapped, "198.51.100.10:40123".parse().unwrap());
        let binds = runtime.udp_binds.lock().unwrap();
        assert!(!binds.is_empty());
        assert_eq!(binds[0].purpose, UdpSocketPurpose::StunProbe);
        assert_eq!(binds[0].local_addr, Some("0.0.0.0:0".parse().unwrap()));
        assert_eq!(binds[0].context.ip_version, IpVersion::V4);
        assert_eq!(binds[0].context.socket_mark, Some(0));
        assert_eq!(
            binds[0].context.netns.as_ref().map(|netns| netns.token()),
            Some("instance-a")
        );
    }
}

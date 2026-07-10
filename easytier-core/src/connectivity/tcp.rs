use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use dashmap::DashSet;
use futures::{StreamExt, stream::FuturesUnordered};
use percent_encoding::percent_decode_str;
use quanta::Instant;
use rand::seq::SliceRandom;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    peers::peer_manager::PeerManagerCore,
    proto::common::TunnelInfo,
    socket::{
        IpVersion, SocketContext,
        dns::{DnsQuery, DnsResolver},
        tcp::{TcpBindOptions, TcpConnectOptions, VirtualTcpSocket, VirtualTcpSocketFactory},
    },
    tunnel::{Tunnel, TunnelError, tcp::TcpTunnelUpgrader},
};

const TCP_DEFAULT_PORT: u16 = 11010;
const MANUAL_PREFLIGHT_DEFAULT_PORT: u16 = 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpInterfaceAddrs {
    pub interface_ipv4s: Vec<Ipv4Addr>,
    pub interface_ipv6s: Vec<Ipv6Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
}

#[async_trait]
pub trait TcpConnectorHost: VirtualTcpSocketFactory {
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr>;

    async fn interface_addrs(&self) -> anyhow::Result<TcpInterfaceAddrs>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpConnectivityEvent {
    Connecting {
        url: Url,
    },
    ConnectError {
        url: Url,
        ip_version: IpVersion,
        error: String,
    },
}

pub trait TcpConnectivityEventSink: Send + Sync + 'static {
    fn emit(&self, event: TcpConnectivityEvent);
}

#[derive(Debug)]
struct NoopTcpConnectivityEventSink;

impl TcpConnectivityEventSink for NoopTcpConnectivityEventSink {
    fn emit(&self, _event: TcpConnectivityEvent) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualTcpConnectorStatus {
    Connected,
    Disconnected,
    Connecting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualTcpConnectorSnapshot {
    pub url: Url,
    pub status: ManualTcpConnectorStatus,
}

#[derive(Debug, Clone)]
pub struct ManualTcpConnectorOptions {
    pub reconnect_interval: Duration,
    pub connect_timeout: Duration,
    pub bind_device: bool,
    pub allow_interface_bind: bool,
    pub bind: TcpBindOptions,
}

impl Default for ManualTcpConnectorOptions {
    fn default() -> Self {
        Self {
            reconnect_interval: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(2),
            bind_device: false,
            allow_interface_bind: true,
            bind: TcpBindOptions::default(),
        }
    }
}

struct ManualTcpConnectorData<H>
where
    H: TcpConnectorHost,
{
    connectors: DashSet<Url>,
    reconnecting: DashSet<Url>,
    removed: DashSet<Url>,
    peer_manager: Weak<PeerManagerCore>,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    events: Arc<dyn TcpConnectivityEventSink>,
    options: ManualTcpConnectorOptions,
}

pub struct ManualTcpConnectorManager<H>
where
    H: TcpConnectorHost,
{
    data: Arc<ManualTcpConnectorData<H>>,
    _task: AbortOnDropHandle<()>,
}

impl<H> ManualTcpConnectorManager<H>
where
    H: TcpConnectorHost,
{
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        options: ManualTcpConnectorOptions,
    ) -> Self {
        Self::new_with_events(
            peer_manager,
            host,
            dns,
            options,
            Arc::new(NoopTcpConnectivityEventSink),
        )
    }

    pub fn new_with_events(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        options: ManualTcpConnectorOptions,
        events: Arc<dyn TcpConnectivityEventSink>,
    ) -> Self {
        let data = Arc::new(ManualTcpConnectorData {
            connectors: DashSet::new(),
            reconnecting: DashSet::new(),
            removed: DashSet::new(),
            peer_manager: Arc::downgrade(&peer_manager),
            host,
            dns,
            events,
            options,
        });
        let task = AbortOnDropHandle::new(tokio::spawn(Self::run(data.clone())));
        Self { data, _task: task }
    }

    pub fn add_connector(&self, url: Url) -> anyhow::Result<()> {
        if url.scheme() != "tcp" {
            anyhow::bail!("manual TCP connector requires a tcp URL: {url}");
        }
        self.data.connectors.insert(url);
        Ok(())
    }

    pub fn remove_connector(&self, url: &Url) -> bool {
        if !self.data.connectors.contains(url) && !self.data.reconnecting.contains(url) {
            return false;
        }
        self.data.removed.insert(url.clone());
        true
    }

    pub fn clear_connectors(&self) {
        for url in self.data.connectors.iter() {
            self.data.removed.insert(url.key().clone());
        }
        for url in self.data.reconnecting.iter() {
            self.data.removed.insert(url.key().clone());
        }
    }

    pub fn list_connectors(&self) -> Vec<ManualTcpConnectorSnapshot> {
        let peer_manager = self.data.peer_manager.upgrade();
        let mut snapshots = self
            .data
            .connectors
            .iter()
            .map(|entry| {
                let url = entry.key().clone();
                let connected = peer_manager
                    .as_ref()
                    .is_some_and(|peer_manager| client_url_is_alive(peer_manager, &url));
                ManualTcpConnectorSnapshot {
                    url,
                    status: if connected {
                        ManualTcpConnectorStatus::Connected
                    } else {
                        ManualTcpConnectorStatus::Disconnected
                    },
                }
            })
            .collect::<Vec<_>>();
        snapshots.extend(
            self.data
                .reconnecting
                .iter()
                .map(|entry| ManualTcpConnectorSnapshot {
                    url: entry.key().clone(),
                    status: ManualTcpConnectorStatus::Connecting,
                }),
        );
        snapshots
    }

    async fn run(data: Arc<ManualTcpConnectorData<H>>) {
        let mut interval = tokio::time::interval(data.options.reconnect_interval);
        let mut reconnect_tasks = JoinSet::new();

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    let dead_urls = collect_dead_connectors(&data);
                    for url in dead_urls {
                        let removed = data.connectors.remove(&url);
                        debug_assert!(removed.is_some());
                        let inserted = data.reconnecting.insert(url.clone());
                        debug_assert!(inserted);
                        let task_data = data.clone();
                        reconnect_tasks.spawn(async move {
                            let result = reconnect(task_data, url.clone()).await;
                            (url, result)
                        });
                    }
                }
                result = reconnect_tasks.join_next(), if !reconnect_tasks.is_empty() => {
                    let Some(result) = result else {
                        continue;
                    };
                    match result {
                        Ok((url, reconnect_result)) => {
                            tracing::warn!(?url, ?reconnect_result, "manual TCP reconnect task done");
                            data.reconnecting.remove(&url);
                            data.connectors.insert(url);
                        }
                        Err(error) => {
                            tracing::error!(?error, "manual TCP reconnect task failed");
                        }
                    }
                }
            }
        }
    }
}

fn handle_removed_connectors<H>(data: &ManualTcpConnectorData<H>)
where
    H: TcpConnectorHost,
{
    let mut remove_later = Vec::new();
    for entry in data.removed.iter() {
        let url = entry.key();
        if data.connectors.remove(url).is_some() {
            tracing::warn!(%url, "manual TCP connector removed");
        } else if data.reconnecting.contains(url) {
            remove_later.push(url.clone());
        }
    }
    data.removed.clear();
    for url in remove_later {
        data.removed.insert(url);
    }
}

fn collect_dead_connectors<H>(data: &ManualTcpConnectorData<H>) -> BTreeSet<Url>
where
    H: TcpConnectorHost,
{
    handle_removed_connectors(data);
    let Some(peer_manager) = data.peer_manager.upgrade() else {
        tracing::warn!("peer manager is gone, skip manual TCP reconnect");
        return BTreeSet::new();
    };
    data.connectors
        .iter()
        .filter_map(|entry| {
            let url = entry.key();
            (!client_url_is_alive(&peer_manager, url)).then(|| url.clone())
        })
        .collect()
}

fn client_url_is_alive(peer_manager: &PeerManagerCore, url: &Url) -> bool {
    peer_manager.get_peer_map().is_client_url_alive(url)
        || peer_manager
            .get_foreign_network_client()
            .is_client_url_alive(url)
}

async fn reconnect<H>(data: Arc<ManualTcpConnectorData<H>>, url: Url) -> anyhow::Result<()>
where
    H: TcpConnectorHost,
{
    tracing::info!(%url, "manual TCP reconnect start");
    let normalized_url = match convert_idn_to_ascii(url.clone()) {
        Ok(url) => url,
        Err(error) => {
            emit_connect_error(&data, &url, IpVersion::Both, &error);
            return Err(error);
        }
    };
    let preflight = with_timeout_budget(
        "resolve",
        Instant::now(),
        data.options.connect_timeout,
        resolve_url_addrs(
            &normalized_url,
            MANUAL_PREFLIGHT_DEFAULT_PORT,
            IpVersion::Both,
            data.options.bind.socket_mark,
            data.dns.as_ref(),
        ),
    )
    .await;
    let addrs = match preflight {
        Ok(addrs) => addrs,
        Err(error) => {
            emit_connect_error(&data, &url, IpVersion::Both, &error);
            return Err(error);
        }
    };
    tracing::info!(?addrs, %url, "manual TCP preflight resolve done");

    let mut ip_versions = Vec::new();
    if addrs.iter().any(SocketAddr::is_ipv4) {
        ip_versions.push(IpVersion::V4);
    }
    if addrs.iter().any(SocketAddr::is_ipv6) {
        ip_versions.push(IpVersion::V6);
    }

    let mut last_error = anyhow::anyhow!("cannot get IP from URL");
    for ip_version in ip_versions {
        let started_at = Instant::now();
        match reconnect_with_ip_version(data.clone(), url.clone(), ip_version, started_at).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                emit_connect_error(&data, &url, ip_version, &error);
                last_error = error;
            }
        }
    }
    Err(last_error)
}

async fn reconnect_with_ip_version<H>(
    data: Arc<ManualTcpConnectorData<H>>,
    requested_url: Url,
    ip_version: IpVersion,
    started_at: Instant,
) -> anyhow::Result<()>
where
    H: TcpConnectorHost,
{
    let normalized_url = convert_idn_to_ascii(requested_url.clone())?;
    let (remote_addr, bind_addrs) =
        with_timeout_budget("resolve", started_at, data.options.connect_timeout, async {
            let remote_addr = resolve_remote_addr(&data, &normalized_url, ip_version).await?;
            let bind_addrs = if data.options.bind_device && data.options.allow_interface_bind {
                collect_bind_addrs(&data, remote_addr).await?
            } else {
                Vec::new()
            };
            Ok((remote_addr, bind_addrs))
        })
        .await?;
    data.events.emit(TcpConnectivityEvent::Connecting {
        url: requested_url.clone(),
    });

    let socket = with_timeout_budget(
        "connect",
        started_at,
        data.options.connect_timeout,
        connect_socket(&data, remote_addr, bind_addrs),
    )
    .await?;
    let tunnel = upgrade_connected_socket(socket, requested_url.clone())?;
    let peer_manager = data
        .peer_manager
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("peer manager is gone, cannot reconnect"))?;
    let (peer_id, conn_id) = with_timeout_budget(
        "handshake",
        started_at,
        data.options.connect_timeout,
        async move {
            peer_manager
                .add_client_tunnel_with_peer_id_hint(tunnel, true, None)
                .await
                .map_err(anyhow::Error::from)
        },
    )
    .await?;
    tracing::info!(peer_id, %conn_id, %requested_url, "manual TCP reconnect succeeded");
    Ok(())
}

async fn resolve_remote_addr<H>(
    data: &ManualTcpConnectorData<H>,
    url: &Url,
    ip_version: IpVersion,
) -> anyhow::Result<SocketAddr>
where
    H: TcpConnectorHost,
{
    let addrs = resolve_url_addrs(
        url,
        TCP_DEFAULT_PORT,
        ip_version,
        data.options.bind.socket_mark,
        data.dns.as_ref(),
    )
    .await?;
    let mut usable = Vec::new();
    let mut rejected_reason = None;
    let peer_manager = data
        .peer_manager
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("peer manager is gone, cannot resolve connector"))?;

    for addr in addrs {
        let SocketAddr::V6(v6_addr) = addr else {
            usable.push(addr);
            continue;
        };
        if peer_manager.is_easytier_managed_ipv6(v6_addr.ip()).await {
            rejected_reason = Some(format!(
                "{url} resolves to EasyTier-managed IPv6 {}",
                v6_addr.ip()
            ));
            continue;
        }
        match data.host.local_addr_for_remote(addr).await {
            Ok(SocketAddr::V6(local_addr))
                if peer_manager.is_easytier_managed_ipv6(local_addr.ip()).await =>
            {
                rejected_reason = Some(format!(
                    "{url} would use EasyTier-managed IPv6 {} as local source for {v6_addr}",
                    local_addr.ip()
                ));
            }
            Ok(_) => usable.push(addr),
            Err(error) => return Err(error),
        }
    }

    if usable.is_empty() {
        if let Some(reason) = rejected_reason {
            anyhow::bail!("{reason}, refusing overlay-backed underlay connection");
        }
        return Err(TunnelError::NoDnsRecordFound(ip_version).into());
    }
    usable
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or_else(|| TunnelError::NoDnsRecordFound(ip_version).into())
}

async fn connect_socket<H>(
    data: &ManualTcpConnectorData<H>,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
) -> anyhow::Result<H::Socket>
where
    H: TcpConnectorHost,
{
    let futures = FuturesUnordered::new();
    if bind_addrs.is_empty() {
        futures.push(data.host.connect_tcp(
            TcpConnectOptions::direct_connect(remote_addr).with_bind(data.options.bind.clone()),
        ));
    } else {
        for bind_addr in bind_addrs {
            let bind = data
                .options
                .bind
                .clone()
                .with_local_addr(Some(bind_addr))
                .with_only_v6(true);
            futures.push(
                data.host
                    .connect_tcp(TcpConnectOptions::direct_connect(remote_addr).with_bind(bind)),
            );
        }
    }
    first_success(futures).await
}

async fn collect_bind_addrs<H>(
    data: &ManualTcpConnectorData<H>,
    remote_addr: SocketAddr,
) -> anyhow::Result<Vec<SocketAddr>>
where
    H: TcpConnectorHost,
{
    let addrs = data.host.interface_addrs().await?;
    if remote_addr.is_ipv4() {
        return Ok(addrs
            .interface_ipv4s
            .into_iter()
            .map(|addr| SocketAddr::new(IpAddr::V4(addr), 0))
            .collect());
    }

    let peer_manager = data
        .peer_manager
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("peer manager is gone, cannot collect bind addresses"))?;
    let mut ipv6s = addrs.interface_ipv6s;
    ipv6s.extend(addrs.public_ipv6);
    let mut ret = Vec::new();
    for addr in ipv6s {
        if !peer_manager.is_easytier_managed_ipv6(&addr).await {
            ret.push(SocketAddr::new(IpAddr::V6(addr), 0));
        }
    }
    Ok(ret)
}

async fn first_success<F, T>(mut futures: FuturesUnordered<F>) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>> + Send,
{
    let mut last_error = None;
    while let Some(result) = futures.next().await {
        match result {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no TCP connect candidates")))
}

async fn resolve_url_addrs(
    url: &Url,
    default_port: u16,
    ip_version: IpVersion,
    socket_mark: Option<u32>,
    dns: &dyn DnsResolver,
) -> anyhow::Result<Vec<SocketAddr>> {
    let host = url
        .host()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?;
    let port = url.port().unwrap_or(default_port);
    let addrs = match host {
        url::Host::Ipv4(addr) => vec![SocketAddr::new(IpAddr::V4(addr), port)],
        url::Host::Ipv6(addr) => vec![SocketAddr::new(IpAddr::V6(addr), port)],
        url::Host::Domain(host) => dns
            .resolve(DnsQuery::new(
                host,
                SocketContext {
                    ip_version,
                    socket_mark,
                    netns: None,
                },
            ))
            .await?
            .into_iter()
            .map(|addr| SocketAddr::new(addr, port))
            .collect(),
    };
    let addrs = addrs
        .into_iter()
        .filter(|addr| match ip_version {
            IpVersion::V4 => addr.is_ipv4(),
            IpVersion::V6 => addr.is_ipv6(),
            IpVersion::Both => true,
        })
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err(TunnelError::NoDnsRecordFound(ip_version).into());
    }
    Ok(addrs)
}

fn convert_idn_to_ascii(mut url: Url) -> anyhow::Result<Url> {
    if url.is_special() {
        return Ok(url);
    }
    if let Some(domain) = url.domain() {
        let domain = percent_decode_str(domain).decode_utf8()?;
        let domain = idna::domain_to_ascii(&domain)?;
        url.set_host(Some(&domain))?;
    }
    Ok(url)
}

fn emit_connect_error<H>(
    data: &ManualTcpConnectorData<H>,
    url: &Url,
    ip_version: IpVersion,
    error: &anyhow::Error,
) where
    H: TcpConnectorHost,
{
    data.events.emit(TcpConnectivityEvent::ConnectError {
        url: url.clone(),
        ip_version,
        error: format!("{error:#?}"),
    });
}

async fn with_timeout_budget<T, F>(
    stage: &'static str,
    started_at: Instant,
    total_timeout: Duration,
    future: F,
) -> anyhow::Result<T>
where
    F: Future<Output = anyhow::Result<T>>,
{
    let remaining = total_timeout
        .checked_sub(started_at.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| anyhow::anyhow!("{stage} timeout after {:?}", started_at.elapsed()))?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| anyhow::anyhow!("{stage} timeout after {remaining:?}"))?
}

pub fn upgrade_connected_socket<S>(
    socket: S,
    requested_remote_addr: Url,
) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let resolved_remote_addr = socket.peer_addr()?;
    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(tcp_url(local_addr).into()),
        remote_addr: Some(requested_remote_addr.into()),
        resolved_remote_addr: Some(tcp_url(resolved_remote_addr).into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

pub fn upgrade_accepted_socket<S>(socket: S) -> Result<Box<dyn Tunnel>, TunnelError>
where
    S: VirtualTcpSocket,
{
    let local_addr = socket.local_addr()?;
    let remote_addr = socket.peer_addr()?;
    let remote_url = tcp_url(remote_addr);
    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: Some(tcp_url(local_addr).into()),
        remote_addr: Some(remote_url.clone().into()),
        resolved_remote_addr: Some(remote_url.into()),
    };
    TcpTunnelUpgrader::new(info).upgrade(socket)
}

fn tcp_url(addr: SocketAddr) -> Url {
    let mut url = Url::parse("tcp://0.0.0.0").expect("static TCP URL should be valid");
    url.set_ip_host(addr.ip())
        .expect("socket IP should be a valid URL host");
    url.set_port(Some(addr.port()))
        .expect("TCP URL should accept a port");
    url
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        pin::Pin,
        sync::Mutex,
        task::{Context, Poll},
    };

    use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

    use super::*;

    struct MockTcpSocket {
        stream: DuplexStream,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    }

    impl MockTcpSocket {
        fn new(local_addr: SocketAddr, peer_addr: SocketAddr) -> Self {
            let (stream, _) = tokio::io::duplex(64);
            Self {
                stream,
                local_addr,
                peer_addr,
            }
        }
    }

    impl AsyncRead for MockTcpSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockTcpSocket {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.stream).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    impl VirtualTcpSocket for MockTcpSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.peer_addr)
        }
    }

    struct StaticDnsResolver {
        ips: Vec<IpAddr>,
        queries: Mutex<Vec<DnsQuery>>,
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            self.queries.lock().unwrap().push(query);
            Ok(self.ips.clone())
        }
    }

    #[test]
    fn tcp_socket_upgrades_preserve_requested_and_resolved_addresses() {
        let local_addr: SocketAddr = "127.0.0.1:1000".parse().unwrap();
        let peer_addr: SocketAddr = "127.0.0.1:2000".parse().unwrap();
        let requested_url: Url = "tcp://example.com:2000".parse().unwrap();

        let connected = upgrade_connected_socket(
            MockTcpSocket::new(local_addr, peer_addr),
            requested_url.clone(),
        )
        .unwrap();
        let connected_info = connected.info().unwrap();
        assert_eq!(
            connected_info.remote_addr.unwrap().url,
            requested_url.as_str()
        );
        let connected_resolved: Url = connected_info.resolved_remote_addr.unwrap().into();
        assert_eq!(connected_resolved.host_str(), Some("127.0.0.1"));
        assert_eq!(connected_resolved.port(), Some(2000));

        let accepted = upgrade_accepted_socket(MockTcpSocket::new(local_addr, peer_addr)).unwrap();
        let accepted_info = accepted.info().unwrap();
        assert_eq!(
            accepted_info.remote_addr,
            accepted_info.resolved_remote_addr
        );
    }

    #[tokio::test]
    async fn resolver_receives_instance_socket_context_and_filters_family() {
        let resolver = StaticDnsResolver {
            ips: vec![IpAddr::from([127, 0, 0, 1]), Ipv6Addr::LOCALHOST.into()],
            queries: Mutex::new(Vec::new()),
        };
        let url: Url = "tcp://example.com:12000".parse().unwrap();

        let addrs = resolve_url_addrs(&url, TCP_DEFAULT_PORT, IpVersion::V6, Some(7), &resolver)
            .await
            .unwrap();

        assert_eq!(addrs, vec!["[::1]:12000".parse().unwrap()]);
        assert_eq!(
            resolver.queries.lock().unwrap().as_slice(),
            &[DnsQuery::new(
                "example.com",
                SocketContext {
                    ip_version: IpVersion::V6,
                    socket_mark: Some(7),
                    netns: None,
                }
            )]
        );
    }

    #[tokio::test]
    async fn timeout_budget_reports_the_active_stage() {
        let error =
            with_timeout_budget("connect", Instant::now(), Duration::from_millis(1), async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("connect timeout after"));
    }
}

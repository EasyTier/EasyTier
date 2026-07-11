use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use async_trait::async_trait;
use dashmap::DashSet;
use percent_encoding::percent_decode_str;
use quanta::Instant;
use rand::seq::SliceRandom;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;
use url::Url;

use crate::{
    connectivity::{
        protocol::raw,
        transport::{self, ConnectedTransport, UdpSessionMode},
    },
    peers::peer_manager::PeerManagerCore,
    socket::{
        IpVersion, SocketContext,
        dns::{DnsQuery, DnsResolver},
        tcp::{TcpBindOptions, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, UdpSessionControlHandler, VirtualUdpSocketFactory},
    },
    tunnel::TunnelError,
};

pub use crate::connectivity::protocol::raw::{
    upgrade_accepted_tcp as upgrade_accepted_socket,
    upgrade_accepted_udp as upgrade_accepted_session,
};

const MANUAL_DEFAULT_PORT: u16 = 11010;
const MANUAL_PREFLIGHT_DEFAULT_PORT: u16 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManualTransport {
    Tcp,
    Udp,
}

impl ManualTransport {
    pub(crate) fn from_url(url: &Url) -> anyhow::Result<Self> {
        match url.scheme() {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => anyhow::bail!("unsupported core manual connector URL: {url}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualInterfaceAddrs {
    pub interface_ipv4s: Vec<Ipv4Addr>,
    pub interface_ipv6s: Vec<Ipv6Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
}

#[async_trait]
pub trait ManualConnectorHost:
    VirtualTcpSocketFactory
    + VirtualUdpSocketFactory
    + UdpSessionControlHandler<<Self as VirtualUdpSocketFactory>::Socket>
{
    async fn local_addr_for_remote(&self, remote_addr: SocketAddr) -> anyhow::Result<SocketAddr>;

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManualConnectivityEvent {
    Connecting {
        url: Url,
    },
    ConnectError {
        url: Url,
        ip_version: IpVersion,
        error: String,
    },
}

pub trait ManualConnectivityEventSink: Send + Sync + 'static {
    fn emit(&self, event: ManualConnectivityEvent);
}

#[derive(Debug)]
struct NoopManualConnectivityEventSink;

impl ManualConnectivityEventSink for NoopManualConnectivityEventSink {
    fn emit(&self, _event: ManualConnectivityEvent) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualConnectorStatus {
    Connected,
    Disconnected,
    Connecting,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualConnectorSnapshot {
    pub url: Url,
    pub status: ManualConnectorStatus,
}

#[derive(Debug, Clone)]
pub struct ManualConnectorOptions {
    pub reconnect_interval: Duration,
    pub connect_timeout: Duration,
    pub bind_device: bool,
    pub allow_interface_bind: bool,
    pub tcp_bind: TcpBindOptions,
    pub udp_bind: UdpBindOptions,
}

impl Default for ManualConnectorOptions {
    fn default() -> Self {
        Self {
            reconnect_interval: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(2),
            bind_device: false,
            allow_interface_bind: true,
            tcp_bind: TcpBindOptions::default(),
            udp_bind: UdpBindOptions::direct_connect(),
        }
    }
}

impl ManualConnectorOptions {
    pub(crate) fn socket_mark(&self, transport: ManualTransport) -> Option<u32> {
        match transport {
            ManualTransport::Tcp => self.tcp_bind.socket_mark,
            ManualTransport::Udp => self.udp_bind.socket_mark,
        }
    }
}

struct ManualConnectorData<H>
where
    H: ManualConnectorHost,
{
    connectors: DashSet<Url>,
    reconnecting: DashSet<Url>,
    removed: DashSet<Url>,
    peer_manager: Weak<PeerManagerCore>,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    events: Arc<dyn ManualConnectivityEventSink>,
    options: ManualConnectorOptions,
}

pub struct ManualConnectorManager<H>
where
    H: ManualConnectorHost,
{
    data: Arc<ManualConnectorData<H>>,
    _task: AbortOnDropHandle<()>,
}

impl<H> ManualConnectorManager<H>
where
    H: ManualConnectorHost,
{
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        options: ManualConnectorOptions,
    ) -> Self {
        Self::new_with_events(
            peer_manager,
            host,
            dns,
            options,
            Arc::new(NoopManualConnectivityEventSink),
        )
    }

    pub fn new_with_events(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        options: ManualConnectorOptions,
        events: Arc<dyn ManualConnectivityEventSink>,
    ) -> Self {
        let data = Arc::new(ManualConnectorData {
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
        ManualTransport::from_url(&url)?;
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

    pub fn list_connectors(&self) -> Vec<ManualConnectorSnapshot> {
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
                ManualConnectorSnapshot {
                    url,
                    status: if connected {
                        ManualConnectorStatus::Connected
                    } else {
                        ManualConnectorStatus::Disconnected
                    },
                }
            })
            .collect::<Vec<_>>();
        snapshots.extend(
            self.data
                .reconnecting
                .iter()
                .map(|entry| ManualConnectorSnapshot {
                    url: entry.key().clone(),
                    status: ManualConnectorStatus::Connecting,
                }),
        );
        snapshots
    }

    async fn run(data: Arc<ManualConnectorData<H>>) {
        let mut interval = tokio::time::interval(data.options.reconnect_interval);
        let mut reconnect_tasks = JoinSet::new();

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    for url in collect_dead_connectors(&data) {
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
                            tracing::warn!(?url, ?reconnect_result, "manual reconnect task done");
                            data.reconnecting.remove(&url);
                            data.connectors.insert(url);
                        }
                        Err(error) => {
                            tracing::error!(?error, "manual reconnect task failed");
                        }
                    }
                }
            }
        }
    }
}

fn handle_removed_connectors<H>(data: &ManualConnectorData<H>)
where
    H: ManualConnectorHost,
{
    let mut remove_later = Vec::new();
    for entry in data.removed.iter() {
        let url = entry.key();
        if data.connectors.remove(url).is_some() {
            tracing::warn!(%url, "manual connector removed");
        } else if data.reconnecting.contains(url) {
            remove_later.push(url.clone());
        }
    }
    data.removed.clear();
    for url in remove_later {
        data.removed.insert(url);
    }
}

fn collect_dead_connectors<H>(data: &ManualConnectorData<H>) -> BTreeSet<Url>
where
    H: ManualConnectorHost,
{
    handle_removed_connectors(data);
    let Some(peer_manager) = data.peer_manager.upgrade() else {
        tracing::warn!("peer manager is gone, skip manual reconnect");
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

async fn reconnect<H>(data: Arc<ManualConnectorData<H>>, url: Url) -> anyhow::Result<()>
where
    H: ManualConnectorHost,
{
    let transport = ManualTransport::from_url(&url)?;
    tracing::info!(%url, ?transport, "manual reconnect start");
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
            data.options.socket_mark(transport),
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
    tracing::info!(?addrs, %url, "manual preflight resolve done");

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
        match reconnect_with_ip_version(
            data.clone(),
            url.clone(),
            transport,
            ip_version,
            started_at,
        )
        .await
        {
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
    data: Arc<ManualConnectorData<H>>,
    requested_url: Url,
    transport: ManualTransport,
    ip_version: IpVersion,
    started_at: Instant,
) -> anyhow::Result<()>
where
    H: ManualConnectorHost,
{
    let normalized_url = convert_idn_to_ascii(requested_url.clone())?;
    let (remote_addr, bind_addrs) =
        with_timeout_budget("resolve", started_at, data.options.connect_timeout, async {
            let peer_manager = data
                .peer_manager
                .upgrade()
                .ok_or_else(|| anyhow::anyhow!("peer manager is gone, cannot resolve connector"))?;
            let remote_addr = resolve_remote_addr(
                peer_manager.as_ref(),
                data.host.as_ref(),
                data.dns.as_ref(),
                &normalized_url,
                ip_version,
                data.options.socket_mark(transport),
            )
            .await?;
            let bind_addrs = if data.options.bind_device && data.options.allow_interface_bind {
                collect_bind_addrs(
                    peer_manager.as_ref(),
                    data.host.as_ref(),
                    transport,
                    remote_addr,
                )
                .await?
            } else {
                Vec::new()
            };
            Ok((remote_addr, bind_addrs))
        })
        .await?;
    data.events.emit(ManualConnectivityEvent::Connecting {
        url: requested_url.clone(),
    });

    let connected = with_timeout_budget(
        "connect",
        started_at,
        data.options.connect_timeout,
        connect_resolved(
            data.host.clone(),
            transport,
            remote_addr,
            bind_addrs,
            data.options.tcp_bind.clone(),
            data.options.udp_bind.clone(),
        ),
    )
    .await?;
    let tunnel = raw::upgrade_connected(connected, requested_url.clone())?;
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
    tracing::info!(peer_id, %conn_id, %requested_url, "manual reconnect succeeded");
    Ok(())
}

pub(crate) async fn connect_resolved<H>(
    host: Arc<H>,
    transport: ManualTransport,
    remote_addr: SocketAddr,
    bind_addrs: Vec<SocketAddr>,
    tcp_bind: TcpBindOptions,
    udp_bind: UdpBindOptions,
) -> anyhow::Result<ConnectedTransport<H>>
where
    H: ManualConnectorHost,
{
    match transport {
        ManualTransport::Tcp => transport::connect_tcp(host, remote_addr, bind_addrs, tcp_bind)
            .await
            .map(ConnectedTransport::Tcp),
        ManualTransport::Udp => transport::connect_udp(
            host,
            remote_addr,
            bind_addrs,
            udp_bind,
            UdpSessionMode::EasyTierMux,
        )
        .await
        .map(ConnectedTransport::Udp),
    }
}

pub(crate) async fn resolve_remote_addr<H>(
    peer_manager: &PeerManagerCore,
    host: &H,
    dns: &dyn DnsResolver,
    url: &Url,
    ip_version: IpVersion,
    socket_mark: Option<u32>,
) -> anyhow::Result<SocketAddr>
where
    H: ManualConnectorHost,
{
    let addrs = resolve_url_addrs(url, MANUAL_DEFAULT_PORT, ip_version, socket_mark, dns).await?;
    let mut usable = Vec::new();
    let mut rejected_reason = None;
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
        match host.local_addr_for_remote(addr).await {
            Ok(SocketAddr::V6(local_addr))
                if peer_manager.is_easytier_managed_ipv6(local_addr.ip()).await =>
            {
                rejected_reason = Some(format!(
                    "{url} would use EasyTier-managed IPv6 {} as local source for {v6_addr}",
                    local_addr.ip()
                ));
            }
            Ok(_) => usable.push(addr),
            Err(error) if ip_version == IpVersion::Both => {
                rejected_reason = Some(format!(
                    "{url} IPv6 candidate {v6_addr} could not be validated: {error}"
                ));
            }
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

pub(crate) async fn collect_bind_addrs<H>(
    peer_manager: &PeerManagerCore,
    host: &H,
    transport: ManualTransport,
    remote_addr: SocketAddr,
) -> anyhow::Result<Vec<SocketAddr>>
where
    H: ManualConnectorHost,
{
    if transport == ManualTransport::Udp && remote_addr.is_ipv6() {
        return Ok(Vec::new());
    }

    let addrs = host.interface_addrs().await?;
    if remote_addr.is_ipv4() {
        return Ok(addrs
            .interface_ipv4s
            .into_iter()
            .map(|addr| SocketAddr::new(IpAddr::V4(addr), 0))
            .collect());
    }

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

pub(crate) async fn resolve_url_addrs(
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

pub(crate) fn convert_idn_to_ascii(mut url: Url) -> anyhow::Result<Url> {
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
    data: &ManualConnectorData<H>,
    url: &Url,
    ip_version: IpVersion,
    error: &anyhow::Error,
) where
    H: ManualConnectorHost,
{
    data.events.emit(ManualConnectivityEvent::ConnectError {
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

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

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
    fn manual_transport_accepts_only_migrated_schemes() {
        assert_eq!(
            ManualTransport::from_url(&"tcp://127.0.0.1:1".parse().unwrap()).unwrap(),
            ManualTransport::Tcp
        );
        assert_eq!(
            ManualTransport::from_url(&"udp://127.0.0.1:1".parse().unwrap()).unwrap(),
            ManualTransport::Udp
        );
        assert!(ManualTransport::from_url(&"wg://127.0.0.1:1".parse().unwrap()).is_err());
    }

    #[tokio::test]
    async fn resolver_receives_instance_socket_context_and_filters_family() {
        let resolver = StaticDnsResolver {
            ips: vec![IpAddr::from([127, 0, 0, 1]), Ipv6Addr::LOCALHOST.into()],
            queries: Mutex::new(Vec::new()),
        };
        let url: Url = "udp://example.com:12000".parse().unwrap();

        let addrs = resolve_url_addrs(&url, MANUAL_DEFAULT_PORT, IpVersion::V6, Some(7), &resolver)
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

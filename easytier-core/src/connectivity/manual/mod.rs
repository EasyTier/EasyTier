pub mod discovery;

use std::{
    collections::BTreeSet,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, Weak},
    time::Duration,
};

use async_trait::async_trait;
use dashmap::DashSet;
use percent_encoding::percent_decode_str;
use quanta::Instant;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};
use url::Url;

use crate::tunnel::ring::RingTunnelRegistry;
use crate::{
    connectivity::{
        protocol::ClientProtocolUpgrader,
        transport::{self, ConnectedByteStream, ConnectedTransport, UdpSessionMode},
    },
    peers::peer_manager::PeerManagerCore,
    proto::common::TunnelInfo,
    socket::{
        IpVersion, SocketContext,
        dns::{DnsQuery, DnsResolver},
        tcp::{TcpBindOptions, TcpSocketPurpose, VirtualTcpSocketFactory},
        udp::{UdpBindOptions, UdpSessionProtocol, VirtualUdpSocketFactory},
    },
    tunnel::{SplitTunnel, Tunnel, TunnelError},
};

const MANUAL_PREFLIGHT_DEFAULT_PORT: u16 = 1000;
const MAX_MANUAL_ENDPOINT_HOPS: usize = 16;

fn manual_default_port(url: &Url) -> u16 {
    crate::connectivity::protocol::protocol_default_port(url.scheme()).unwrap_or(11010)
}

fn is_manual_endpoint_scheme(scheme: &str) -> bool {
    matches!(scheme, "http" | "https" | "txt" | "srv")
}

fn validate_manual_url(url: &Url) -> anyhow::Result<()> {
    if ManualTransport::from_url(url).is_ok() || is_manual_endpoint_scheme(url.scheme()) {
        Ok(())
    } else {
        anyhow::bail!("unsupported core manual connector URL: {url}")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ManualTransport {
    Tcp(TcpSocketPurpose),
    Udp(UdpSessionMode),
    ByteStream,
}

impl ManualTransport {
    pub(crate) fn from_url(url: &Url) -> anyhow::Result<Self> {
        match url.scheme() {
            "tcp" | "ws" | "wss" => Ok(Self::Tcp(TcpSocketPurpose::ManualConnect)),
            "faketcp" => Ok(Self::Tcp(TcpSocketPurpose::FakeTcp)),
            "udp" => Ok(Self::Udp(UdpSessionMode::EasyTierMux)),
            "wg" => Ok(Self::Udp(UdpSessionMode::Classified(
                UdpSessionProtocol::WireGuard,
            ))),
            "quic" => Ok(Self::Udp(UdpSessionMode::Classified(
                UdpSessionProtocol::Quic,
            ))),
            "ring" | "unix" => Ok(Self::ByteStream),
            _ => anyhow::bail!("unsupported core manual connector URL: {url}"),
        }
    }

    fn is_udp(self) -> bool {
        matches!(self, Self::Udp(_))
    }

    fn supports_interface_bind(self) -> bool {
        !matches!(
            self,
            Self::Tcp(TcpSocketPurpose::FakeTcp) | Self::ByteStream
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualInterfaceAddrs {
    pub interface_ipv4s: Vec<Ipv4Addr>,
    pub interface_ipv6s: Vec<Ipv6Addr>,
    pub public_ipv6: Option<Ipv6Addr>,
}

#[async_trait]
pub trait ManualConnectorHost: VirtualTcpSocketFactory + VirtualUdpSocketFactory {
    async fn local_addr_for_remote(
        &self,
        remote_addr: SocketAddr,
        context: SocketContext,
    ) -> anyhow::Result<SocketAddr>;

    async fn interface_addrs(&self) -> anyhow::Result<ManualInterfaceAddrs>;

    async fn connect_byte_stream(
        &self,
        url: &Url,
    ) -> anyhow::Result<ConnectedByteStream<<Self as VirtualTcpSocketFactory>::Socket>> {
        anyhow::bail!("host does not support external byte stream: {url}")
    }
}

#[async_trait]
pub trait ManualEndpointResolver: Send + Sync + 'static {
    async fn resolve_endpoint(&self, url: &Url) -> anyhow::Result<Url>;
}

/// Connects one endpoint without owning peer-manager retry or admission policy.
///
/// This is intended for application protocols such as standalone RPC and the
/// configuration client. The host creates transports, while core resolves the
/// endpoint chain and upgrades the resulting socket or session into a tunnel.
pub struct ManualTunnelConnector<H>
where
    H: ManualConnectorHost,
{
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    endpoint_resolver: Arc<dyn ManualEndpointResolver>,
    protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
    options: ManualConnectorOptions,
    ring_registry: Option<Arc<RingTunnelRegistry>>,
}

impl<H> ManualTunnelConnector<H>
where
    H: ManualConnectorHost,
{
    pub fn new(
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        endpoint_resolver: Arc<dyn ManualEndpointResolver>,
        protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
        options: ManualConnectorOptions,
    ) -> Self {
        Self {
            host,
            dns,
            endpoint_resolver,
            protocol,
            options,
            ring_registry: None,
        }
    }

    pub(crate) fn with_ring_registry(mut self, ring_registry: Arc<RingTunnelRegistry>) -> Self {
        self.ring_registry = Some(ring_registry);
        self
    }

    pub async fn connect(
        &self,
        requested_url: Url,
        ip_version: IpVersion,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        validate_manual_url(&requested_url)?;
        let endpoint = resolve_manual_endpoint(
            self.endpoint_resolver.as_ref(),
            convert_idn_to_ascii(requested_url.clone())?,
        )
        .await?;
        if endpoint.url.scheme() == "ring" {
            let registry = self
                .ring_registry
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("ring registry is not configured"))?;
            let tunnel = connect_ring_tunnel(registry, &endpoint.url)?;
            return Ok(apply_resolved_endpoint_info(
                tunnel,
                requested_url,
                endpoint.tunnel_prefixes,
            ));
        }

        if !self.protocol.supports_scheme(endpoint.url.scheme()) {
            anyhow::bail!(
                "unsupported client protocol upgrader: {}",
                endpoint.url.scheme()
            );
        }

        let transport = ManualTransport::from_url(&endpoint.url)?;
        let connected = if transport == ManualTransport::ByteStream {
            ConnectedTransport::ByteStream(self.host.connect_byte_stream(&endpoint.url).await?)
        } else {
            let remote_addr = resolve_url_addrs(
                &endpoint.url,
                manual_default_port(&endpoint.url),
                self.options.socket_context(transport, ip_version),
                self.dns.as_ref(),
            )
            .await?
            .choose(&mut rand::thread_rng())
            .copied()
            .ok_or(TunnelError::NoDnsRecordFound(ip_version))?;
            connect_resolved(
                self.host.clone(),
                transport,
                remote_addr,
                Vec::new(),
                self.options.tcp_bind.clone(),
                self.options.udp_bind.clone(),
            )
            .await?
        };

        let tunnel = self
            .protocol
            .upgrade_client(connected, endpoint.url)
            .await?;
        Ok(apply_resolved_endpoint_info(
            tunnel,
            requested_url,
            endpoint.tunnel_prefixes,
        ))
    }
}

struct ResolvedManualTunnel {
    inner: Box<dyn Tunnel>,
    info: TunnelInfo,
}

impl Tunnel for ResolvedManualTunnel {
    fn split(&self) -> SplitTunnel {
        self.inner.split()
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(self.info.clone())
    }
}

#[derive(Debug)]
struct ResolvedManualEndpoint {
    url: Url,
    tunnel_prefixes: Vec<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualConnectorOptions {
    pub reconnect_interval: Duration,
    pub connect_timeout: Duration,
    pub endpoint_discovery_timeout: Duration,
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
            endpoint_discovery_timeout: Duration::from_secs(20),
            bind_device: false,
            allow_interface_bind: true,
            tcp_bind: TcpBindOptions::default(),
            udp_bind: UdpBindOptions::direct_connect(),
        }
    }
}

impl ManualConnectorOptions {
    fn connect_timeout<TcpSocket: 'static>(
        &self,
        url: &Url,
        protocol: &dyn ClientProtocolUpgrader<TcpSocket>,
    ) -> Duration {
        if is_manual_endpoint_scheme(url.scheme()) {
            self.endpoint_discovery_timeout
        } else {
            protocol
                .connect_timeout(url.scheme())
                .unwrap_or(self.connect_timeout)
        }
    }

    pub(crate) fn socket_context(
        &self,
        transport: ManualTransport,
        ip_version: IpVersion,
    ) -> SocketContext {
        let context = match transport {
            ManualTransport::Tcp(_) => self.tcp_bind.context.clone(),
            ManualTransport::Udp(_) => self.udp_bind.context.clone(),
            ManualTransport::ByteStream => SocketContext::default(),
        };
        context.with_ip_version(ip_version)
    }
}

struct ManualConnectorData<H>
where
    H: ManualConnectorHost,
{
    connectors: DashSet<Url>,
    reconnecting: DashSet<Url>,
    removed: DashSet<Url>,
    state_lock: Mutex<()>,
    peer_manager: Weak<PeerManagerCore>,
    host: Arc<H>,
    dns: Arc<dyn DnsResolver>,
    endpoint_resolver: Arc<dyn ManualEndpointResolver>,
    protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
    ring_registry: Arc<RingTunnelRegistry>,
    events: Arc<dyn ManualConnectivityEventSink>,
    options: ManualConnectorOptions,
}

pub struct ManualConnectorManager<H>
where
    H: ManualConnectorHost,
{
    data: Arc<ManualConnectorData<H>>,
    task: Mutex<Option<ManualConnectorTask>>,
}

struct ManualConnectorTask {
    cancel: CancellationToken,
    handle: AbortOnDropHandle<()>,
}

impl<H> ManualConnectorManager<H>
where
    H: ManualConnectorHost,
{
    pub(crate) fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        endpoint_resolver: Arc<dyn ManualEndpointResolver>,
        protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
        ring_registry: Arc<RingTunnelRegistry>,
        options: ManualConnectorOptions,
    ) -> Self {
        Self::new_with_events(
            peer_manager,
            host,
            dns,
            endpoint_resolver,
            protocol,
            ring_registry,
            options,
            Arc::new(NoopManualConnectivityEventSink),
        )
    }

    pub(crate) fn new_with_events(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        dns: Arc<dyn DnsResolver>,
        endpoint_resolver: Arc<dyn ManualEndpointResolver>,
        protocol: Arc<dyn ClientProtocolUpgrader<<H as VirtualTcpSocketFactory>::Socket>>,
        ring_registry: Arc<RingTunnelRegistry>,
        options: ManualConnectorOptions,
        events: Arc<dyn ManualConnectivityEventSink>,
    ) -> Self {
        let data = Arc::new(ManualConnectorData {
            connectors: DashSet::new(),
            reconnecting: DashSet::new(),
            removed: DashSet::new(),
            state_lock: Mutex::new(()),
            peer_manager: Arc::downgrade(&peer_manager),
            host,
            dns,
            endpoint_resolver,
            protocol,
            ring_registry,
            events,
            options,
        });
        Self {
            data,
            task: Mutex::new(None),
        }
    }

    pub fn start(&self) {
        let mut task_slot = self.task.lock().unwrap();
        if task_slot
            .as_ref()
            .is_some_and(|task| !task.handle.is_finished())
        {
            return;
        }
        let cancel = CancellationToken::new();
        task_slot.replace(ManualConnectorTask {
            handle: AbortOnDropHandle::new(tokio::spawn(Self::run(
                self.data.clone(),
                cancel.clone(),
            ))),
            cancel,
        });
    }

    pub async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.cancel.cancel();
            let _ = task.handle.await;
        }
        let _state_guard = self.data.state_lock.lock().unwrap();
        restore_interrupted_connectors(
            &self.data.connectors,
            &self.data.reconnecting,
            &self.data.removed,
        );
    }

    pub fn add_connector(&self, url: Url) -> anyhow::Result<()> {
        validate_manual_url(&url)?;
        let _state_guard = self.data.state_lock.lock().unwrap();
        self.data.removed.remove(&url);
        if !self.data.reconnecting.contains(&url) {
            self.data.connectors.insert(url);
        }
        Ok(())
    }

    pub fn remove_connector(&self, url: &Url) -> bool {
        let _state_guard = self.data.state_lock.lock().unwrap();
        if self.data.connectors.remove(url).is_some() {
            tracing::warn!(%url, "manual connector removed");
            return true;
        }
        if self.data.reconnecting.contains(url) {
            self.data.removed.insert(url.clone());
            return true;
        }
        false
    }

    pub fn clear_connectors(&self) {
        let _state_guard = self.data.state_lock.lock().unwrap();
        self.data.connectors.clear();
        for url in self.data.reconnecting.iter() {
            self.data.removed.insert(url.key().clone());
        }
    }

    pub fn list_connectors(&self) -> Vec<ManualConnectorSnapshot> {
        let _state_guard = self.data.state_lock.lock().unwrap();
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

    async fn run(data: Arc<ManualConnectorData<H>>, cancel: CancellationToken) {
        let mut interval = crate::runtime_time::interval(data.options.reconnect_interval);
        let mut reconnect_tasks = JoinSet::new();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = interval.tick() => {
                    for url in take_dead_connectors_for_reconnect(&data) {
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
                            let _state_guard = data.state_lock.lock().unwrap();
                            data.reconnecting.remove(&url);
                            if data.removed.remove(&url).is_some() {
                                tracing::warn!(%url, "manual connector removed after reconnect");
                            } else {
                                data.connectors.insert(url);
                            }
                        }
                        Err(error) => {
                            tracing::error!(?error, "manual reconnect task failed");
                        }
                    }
                }
            }
        }

        reconnect_tasks.abort_all();
        while reconnect_tasks.join_next().await.is_some() {}

        let _state_guard = data.state_lock.lock().unwrap();
        restore_interrupted_connectors(&data.connectors, &data.reconnecting, &data.removed);
    }
}

fn restore_interrupted_connectors(
    connectors: &DashSet<Url>,
    reconnecting: &DashSet<Url>,
    removed: &DashSet<Url>,
) {
    let interrupted = reconnecting
        .iter()
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();
    for url in interrupted {
        reconnecting.remove(&url);
        if removed.remove(&url).is_none() {
            connectors.insert(url);
        }
    }
}

fn take_dead_connectors_for_reconnect<H>(data: &ManualConnectorData<H>) -> BTreeSet<Url>
where
    H: ManualConnectorHost,
{
    let _state_guard = data.state_lock.lock().unwrap();
    let Some(peer_manager) = data.peer_manager.upgrade() else {
        tracing::warn!("peer manager is gone, skip manual reconnect");
        return BTreeSet::new();
    };
    let dead_connectors = data
        .connectors
        .iter()
        .filter_map(|entry| {
            let url = entry.key();
            (!client_url_is_alive(&peer_manager, url)).then(|| url.clone())
        })
        .collect::<BTreeSet<_>>();
    for url in &dead_connectors {
        let removed = data.connectors.remove(url);
        debug_assert!(removed.is_some());
        let inserted = data.reconnecting.insert(url.clone());
        debug_assert!(inserted);
    }
    dead_connectors
}

fn client_url_is_alive(peer_manager: &PeerManagerCore, url: &Url) -> bool {
    peer_manager.get_peer_map().is_client_url_alive(url)
        || peer_manager
            .get_foreign_network_client()
            .is_client_url_alive(url)
}

async fn resolve_manual_endpoint(
    resolver: &dyn ManualEndpointResolver,
    requested_url: Url,
) -> anyhow::Result<ResolvedManualEndpoint> {
    let mut url = requested_url;
    let mut tunnel_prefixes = Vec::new();
    let mut visited = BTreeSet::new();
    loop {
        if !visited.insert(url.clone()) {
            anyhow::bail!("manual endpoint resolution cycle detected at {url}");
        }
        if ManualTransport::from_url(&url).is_ok() {
            return Ok(ResolvedManualEndpoint {
                url,
                tunnel_prefixes,
            });
        }
        if !is_manual_endpoint_scheme(url.scheme()) {
            anyhow::bail!("unsupported resolved manual connector URL: {url}");
        }
        if tunnel_prefixes.len() >= MAX_MANUAL_ENDPOINT_HOPS {
            anyhow::bail!("manual endpoint resolution exceeded {MAX_MANUAL_ENDPOINT_HOPS} hops");
        }
        tunnel_prefixes.push(url.scheme().to_owned());
        url = convert_idn_to_ascii(resolver.resolve_endpoint(&url).await?)?;
    }
}

fn apply_resolved_endpoint_info(
    tunnel: Box<dyn Tunnel>,
    requested_url: Url,
    tunnel_prefixes: Vec<String>,
) -> Box<dyn Tunnel> {
    if tunnel_prefixes.is_empty() {
        return tunnel;
    }
    let inner_info = tunnel.info().unwrap_or_default();
    let tunnel_type = format!("{}-{}", tunnel_prefixes.join("-"), inner_info.tunnel_type);
    Box::new(ResolvedManualTunnel {
        inner: tunnel,
        info: TunnelInfo {
            local_addr: inner_info.local_addr,
            remote_addr: Some(requested_url.into()),
            resolved_remote_addr: inner_info.resolved_remote_addr.or(inner_info.remote_addr),
            tunnel_type,
        },
    })
}

fn connect_ring_tunnel(
    registry: &RingTunnelRegistry,
    endpoint: &Url,
) -> anyhow::Result<Box<dyn Tunnel>> {
    let remote_id = endpoint
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("ring URL has no peer id: {endpoint}"))?
        .parse()?;
    Ok(registry.connect(remote_id)?.into_tunnel())
}

async fn resolve_reconnect_ip_versions(
    url: &Url,
    connect_timeout: Duration,
    context: SocketContext,
    dns: &dyn DnsResolver,
) -> anyhow::Result<Vec<IpVersion>> {
    if matches!(
        ManualTransport::from_url(url),
        Ok(ManualTransport::ByteStream)
    ) {
        return Ok(vec![IpVersion::Both]);
    }
    if matches!(url.scheme(), "txt" | "srv") {
        return Ok(vec![IpVersion::Both]);
    }

    let addrs = with_timeout_budget(
        "resolve",
        Instant::now(),
        connect_timeout,
        resolve_url_addrs(
            url,
            MANUAL_PREFLIGHT_DEFAULT_PORT,
            context.with_ip_version(IpVersion::Both),
            dns,
        ),
    )
    .await?;
    tracing::info!(?addrs, %url, "manual preflight resolve done");

    let mut ip_versions = Vec::new();
    if addrs.iter().any(SocketAddr::is_ipv4) {
        ip_versions.push(IpVersion::V4);
    }
    if addrs.iter().any(SocketAddr::is_ipv6) {
        ip_versions.push(IpVersion::V6);
    }
    Ok(ip_versions)
}

async fn reconnect<H>(data: Arc<ManualConnectorData<H>>, url: Url) -> anyhow::Result<()>
where
    H: ManualConnectorHost,
{
    validate_manual_url(&url)?;
    let connect_timeout = data.options.connect_timeout(&url, data.protocol.as_ref());
    tracing::info!(%url, "manual reconnect start");
    let normalized_url = match convert_idn_to_ascii(url.clone()) {
        Ok(url) => url,
        Err(error) => {
            emit_connect_error(&data, &url, IpVersion::Both, &error);
            return Err(error);
        }
    };
    let ip_versions = match resolve_reconnect_ip_versions(
        &normalized_url,
        connect_timeout,
        ManualTransport::from_url(&normalized_url)
            .ok()
            .map(|transport| data.options.socket_context(transport, IpVersion::Both))
            .unwrap_or_default(),
        data.dns.as_ref(),
    )
    .await
    {
        Ok(ip_versions) => ip_versions,
        Err(error) => {
            emit_connect_error(&data, &url, IpVersion::Both, &error);
            return Err(error);
        }
    };

    let mut last_error = anyhow::anyhow!("cannot get IP from URL");
    for ip_version in ip_versions {
        let started_at = Instant::now();
        match reconnect_with_ip_version(
            data.clone(),
            url.clone(),
            ip_version,
            started_at,
            connect_timeout,
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
    ip_version: IpVersion,
    started_at: Instant,
    connect_timeout: Duration,
) -> anyhow::Result<()>
where
    H: ManualConnectorHost,
{
    let endpoint = with_timeout_budget(
        "discover",
        started_at,
        connect_timeout,
        resolve_manual_endpoint(
            data.endpoint_resolver.as_ref(),
            convert_idn_to_ascii(requested_url.clone())?,
        ),
    )
    .await?;
    if endpoint.url.scheme() != "ring" && !data.protocol.supports_scheme(endpoint.url.scheme()) {
        anyhow::bail!(
            "unsupported client protocol upgrader: {}",
            endpoint.url.scheme()
        );
    }
    let transport = (endpoint.url.scheme() != "ring")
        .then(|| ManualTransport::from_url(&endpoint.url))
        .transpose()?;
    let resolved = match transport {
        None | Some(ManualTransport::ByteStream) => None,
        Some(transport) => Some(
            with_timeout_budget("resolve", started_at, connect_timeout, async {
                let peer_manager = data.peer_manager.upgrade().ok_or_else(|| {
                    anyhow::anyhow!("peer manager is gone, cannot resolve connector")
                })?;
                let remote_addr = resolve_remote_addr(
                    peer_manager.as_ref(),
                    data.host.as_ref(),
                    data.dns.as_ref(),
                    &endpoint.url,
                    manual_default_port(&endpoint.url),
                    data.options.socket_context(transport, ip_version),
                )
                .await?;
                let bind_addrs = if data.options.bind_device
                    && data.options.allow_interface_bind
                    && transport.supports_interface_bind()
                {
                    collect_bind_addrs(
                        peer_manager.as_ref(),
                        data.host.as_ref(),
                        transport.is_udp(),
                        remote_addr,
                    )
                    .await?
                } else {
                    Vec::new()
                };
                Ok((remote_addr, bind_addrs))
            })
            .await?,
        ),
    };
    data.events.emit(ManualConnectivityEvent::Connecting {
        url: requested_url.clone(),
    });

    let tunnel = with_timeout_budget("connect", started_at, connect_timeout, async {
        if endpoint.url.scheme() == "ring" {
            return connect_ring_tunnel(&data.ring_registry, &endpoint.url);
        }
        let transport = transport.expect("non-Ring endpoint should have a transport");
        let connected = match resolved {
            Some((remote_addr, bind_addrs)) => {
                connect_resolved(
                    data.host.clone(),
                    transport,
                    remote_addr,
                    bind_addrs,
                    data.options.tcp_bind.clone(),
                    data.options.udp_bind.clone(),
                )
                .await?
            }
            None => {
                ConnectedTransport::ByteStream(data.host.connect_byte_stream(&endpoint.url).await?)
            }
        };
        data.protocol.upgrade_client(connected, endpoint.url).await
    })
    .await?;
    let tunnel =
        apply_resolved_endpoint_info(tunnel, requested_url.clone(), endpoint.tunnel_prefixes);
    let peer_manager = data
        .peer_manager
        .upgrade()
        .ok_or_else(|| anyhow::anyhow!("peer manager is gone, cannot reconnect"))?;
    let (peer_id, conn_id) =
        with_timeout_budget("handshake", started_at, connect_timeout, async move {
            peer_manager
                .add_client_tunnel_with_peer_id_hint(tunnel, true, None)
                .await
                .map_err(anyhow::Error::from)
        })
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
) -> anyhow::Result<ConnectedTransport<<H as VirtualTcpSocketFactory>::Socket>>
where
    H: ManualConnectorHost,
{
    match transport {
        ManualTransport::Tcp(purpose) => {
            transport::connect_tcp(host, remote_addr, bind_addrs, tcp_bind, purpose)
                .await
                .map(ConnectedTransport::Tcp)
        }
        ManualTransport::Udp(mode) => {
            transport::connect_udp(host, remote_addr, bind_addrs, udp_bind, mode)
                .await
                .map(ConnectedTransport::Udp)
        }
        ManualTransport::ByteStream => {
            anyhow::bail!("external byte streams do not use an IP transport address")
        }
    }
}

pub(crate) async fn resolve_remote_addr<H>(
    peer_manager: &PeerManagerCore,
    host: &H,
    dns: &dyn DnsResolver,
    url: &Url,
    default_port: u16,
    context: SocketContext,
) -> anyhow::Result<SocketAddr>
where
    H: ManualConnectorHost,
{
    let ip_version = context.ip_version;
    let addrs = resolve_url_addrs(url, default_port, context.clone(), dns).await?;
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
        match host.local_addr_for_remote(addr, context.clone()).await {
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

pub(crate) async fn collect_bind_addrs<H>(
    peer_manager: &PeerManagerCore,
    host: &H,
    is_udp: bool,
    remote_addr: SocketAddr,
) -> anyhow::Result<Vec<SocketAddr>>
where
    H: ManualConnectorHost,
{
    if is_udp && remote_addr.is_ipv6() {
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
    context: SocketContext,
    dns: &dyn DnsResolver,
) -> anyhow::Result<Vec<SocketAddr>> {
    let ip_version = context.ip_version;
    let host = url
        .host()
        .ok_or_else(|| anyhow::anyhow!("URL has no host: {url}"))?;
    let port = url.port().unwrap_or(default_port);
    let addrs = match host {
        url::Host::Ipv4(addr) => vec![SocketAddr::new(IpAddr::V4(addr), port)],
        url::Host::Ipv6(addr) => vec![SocketAddr::new(IpAddr::V6(addr), port)],
        url::Host::Domain(host) => dns
            .resolve(DnsQuery::new(host, context))
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
    crate::runtime_time::timeout(remaining, future)
        .await
        .map_err(|_| anyhow::anyhow!("{stage} timeout after {remaining:?}"))?
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[test]
    fn idn_normalization_covers_connector_schemes_and_url_round_trips() {
        let cases = [
            ("example.com", "example.com"),
            ("test.org:8080/path", "test.org:8080/path"),
            ("räksmörgås.nu", "xn--rksmrgs-5wao1o.nu"),
            ("中文.测试", "xn--fiq228c.xn--0zwm56d"),
            ("räksmörgås.nu:8080", "xn--rksmrgs-5wao1o.nu:8080"),
            ("例子.测试/path", "xn--fsqu00a.xn--0zwm56d/path"),
            ("中文.测试:9000/api", "xn--fiq228c.xn--0zwm56d:9000/api"),
            ("räksmörgås.nu:8080/path", "xn--rksmrgs-5wao1o.nu:8080/path"),
            (
                "中文.测试:8000/用户/管理",
                "xn--fiq228c.xn--0zwm56d:8000/%E7%94%A8%E6%88%B7/%E7%AE%A1%E7%90%86",
            ),
            ("[2001:db8::1]:8080", "[2001:db8::1]:8080"),
            ("[2001:db8::1]/path", "[2001:db8::1]/path"),
            (
                "[2001:db8::1]/路径/资源",
                "[2001:db8::1]/%E8%B7%AF%E5%BE%84/%E8%B5%84%E6%BA%90",
            ),
        ];
        let schemes = ["tcp", "udp", "ws", "wss", "wg", "quic", "http", "https"];

        for (host_part, expected_host_part) in cases {
            for scheme in schemes {
                for round_trip in [false, true] {
                    let input = Url::parse(&format!("{scheme}://{host_part}")).unwrap();
                    let input = if round_trip {
                        input.to_string().parse().unwrap()
                    } else {
                        input
                    };
                    let actual = convert_idn_to_ascii(input.clone()).unwrap().to_string();
                    let mut expected = format!("{scheme}://{expected_host_part}");
                    if input.is_special()
                        && actual.ends_with('/')
                        && !expected_host_part.ends_with('/')
                    {
                        expected.push('/');
                    }
                    assert_eq!(actual, expected, "scheme={scheme}, input={host_part}");
                }
            }
        }
    }

    struct StaticDnsResolver {
        ips: Vec<IpAddr>,
        queries: Mutex<Vec<DnsQuery>>,
    }

    struct ChainedEndpointResolver;

    struct CyclingEndpointResolver;

    #[async_trait]
    impl ManualEndpointResolver for ChainedEndpointResolver {
        async fn resolve_endpoint(&self, url: &Url) -> anyhow::Result<Url> {
            match url.scheme() {
                "http" => Ok("txt://discovery.example".parse().unwrap()),
                "txt" => Ok("tcp://peer.example:12000".parse().unwrap()),
                scheme => anyhow::bail!("unexpected endpoint scheme: {scheme}"),
            }
        }
    }

    #[async_trait]
    impl ManualEndpointResolver for CyclingEndpointResolver {
        async fn resolve_endpoint(&self, url: &Url) -> anyhow::Result<Url> {
            Ok(url.clone())
        }
    }

    #[async_trait]
    impl DnsResolver for StaticDnsResolver {
        async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
            self.queries.lock().unwrap().push(query);
            Ok(self.ips.clone())
        }
    }

    #[test]
    fn manual_transport_maps_ip_protocols_to_their_socket_boundary() {
        let cases = [
            (
                "tcp://127.0.0.1:1",
                ManualTransport::Tcp(TcpSocketPurpose::ManualConnect),
            ),
            (
                "ws://127.0.0.1:1",
                ManualTransport::Tcp(TcpSocketPurpose::ManualConnect),
            ),
            (
                "wss://127.0.0.1:1",
                ManualTransport::Tcp(TcpSocketPurpose::ManualConnect),
            ),
            (
                "faketcp://127.0.0.1:1",
                ManualTransport::Tcp(TcpSocketPurpose::FakeTcp),
            ),
            (
                "udp://127.0.0.1:1",
                ManualTransport::Udp(UdpSessionMode::EasyTierMux),
            ),
            (
                "wg://127.0.0.1:1",
                ManualTransport::Udp(UdpSessionMode::Classified(UdpSessionProtocol::WireGuard)),
            ),
            (
                "quic://127.0.0.1:1",
                ManualTransport::Udp(UdpSessionMode::Classified(UdpSessionProtocol::Quic)),
            ),
            ("ring://local", ManualTransport::ByteStream),
            ("unix:///tmp/easytier.sock", ManualTransport::ByteStream),
        ];

        for (url, expected) in cases {
            assert_eq!(
                ManualTransport::from_url(&url.parse().unwrap()).unwrap(),
                expected
            );
        }
        assert!(ManualTransport::from_url(&"http://127.0.0.1:1".parse().unwrap()).is_err());
        assert!(validate_manual_url(&"http://127.0.0.1:1".parse().unwrap()).is_ok());
    }

    #[tokio::test]
    async fn manual_endpoint_resolution_preserves_the_discovery_chain() {
        let endpoint = resolve_manual_endpoint(
            &ChainedEndpointResolver,
            "http://discovery.example".parse().unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(endpoint.url.as_str(), "tcp://peer.example:12000");
        assert_eq!(endpoint.tunnel_prefixes, ["http", "txt"]);
    }

    #[tokio::test]
    async fn manual_endpoint_resolution_rejects_cycles() {
        let error = resolve_manual_endpoint(
            &CyclingEndpointResolver,
            "http://discovery.example".parse().unwrap(),
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("cycle detected"));
    }

    #[tokio::test]
    async fn txt_discovery_does_not_require_address_records() {
        let resolver = StaticDnsResolver {
            ips: Vec::new(),
            queries: Mutex::new(Vec::new()),
        };
        let versions = resolve_reconnect_ip_versions(
            &"txt://discovery.example".parse().unwrap(),
            Duration::from_secs(1),
            SocketContext::default(),
            &resolver,
        )
        .await
        .unwrap();

        assert_eq!(versions, [IpVersion::Both]);
        assert!(resolver.queries.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn external_byte_stream_does_not_require_address_records() {
        let resolver = StaticDnsResolver {
            ips: Vec::new(),
            queries: Mutex::new(Vec::new()),
        };
        let versions = resolve_reconnect_ip_versions(
            &"ring://local".parse().unwrap(),
            Duration::from_secs(1),
            SocketContext::default(),
            &resolver,
        )
        .await
        .unwrap();

        assert_eq!(versions, [IpVersion::Both]);
        assert!(resolver.queries.lock().unwrap().is_empty());
    }

    #[test]
    fn manual_protocols_keep_their_default_ports() {
        let cases = [
            ("tcp://127.0.0.1", 11010),
            ("udp://127.0.0.1", 11010),
            ("ws://127.0.0.1", 80),
            ("wss://127.0.0.1", 443),
            ("wg://127.0.0.1", 11011),
            ("quic://127.0.0.1", 11012),
            ("faketcp://127.0.0.1", 11013),
        ];

        for (url, expected) in cases {
            assert_eq!(manual_default_port(&url.parse().unwrap()), expected);
        }
    }

    #[test]
    fn external_protocol_and_discovery_timeouts_are_explicit() {
        struct Protocol;

        #[async_trait]
        impl ClientProtocolUpgrader<()> for Protocol {
            fn supports_scheme(&self, scheme: &str) -> bool {
                scheme == "external"
            }

            fn connect_timeout(&self, scheme: &str) -> Option<Duration> {
                (scheme == "external").then_some(Duration::from_secs(20))
            }

            async fn upgrade_client(
                &self,
                _connected: ConnectedTransport<()>,
                _requested_url: Url,
            ) -> anyhow::Result<Box<dyn Tunnel>> {
                unreachable!()
            }
        }

        let options = ManualConnectorOptions::default();
        assert_eq!(
            options.connect_timeout(&"external://127.0.0.1".parse().unwrap(), &Protocol),
            Duration::from_secs(20)
        );
        assert_eq!(
            options.connect_timeout(&"txt://example.com".parse().unwrap(), &Protocol),
            Duration::from_secs(20)
        );
        assert_eq!(
            options.connect_timeout(&"tcp://127.0.0.1".parse().unwrap(), &Protocol),
            Duration::from_secs(2)
        );
    }

    #[tokio::test]
    async fn resolver_receives_instance_socket_context_and_filters_family() {
        let resolver = StaticDnsResolver {
            ips: vec![IpAddr::from([127, 0, 0, 1]), Ipv6Addr::LOCALHOST.into()],
            queries: Mutex::new(Vec::new()),
        };
        let url: Url = "udp://example.com:12000".parse().unwrap();

        let addrs = resolve_url_addrs(
            &url,
            crate::connectivity::protocol::protocol_default_port("tcp").unwrap(),
            SocketContext::default()
                .with_ip_version(IpVersion::V6)
                .with_socket_mark(Some(7)),
            &resolver,
        )
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
                crate::runtime_time::sleep(Duration::from_millis(20)).await;
                Ok::<(), anyhow::Error>(())
            })
            .await
            .unwrap_err();

        assert!(error.to_string().contains("connect timeout after"));
    }

    #[test]
    fn interrupted_reconnects_return_to_the_pending_set_unless_removed() {
        let connectors = DashSet::new();
        let reconnecting = DashSet::new();
        let removed = DashSet::new();
        let retained: Url = "tcp://127.0.0.1:11010".parse().unwrap();
        let deleted: Url = "udp://127.0.0.1:11010".parse().unwrap();
        reconnecting.insert(retained.clone());
        reconnecting.insert(deleted.clone());
        removed.insert(deleted.clone());

        restore_interrupted_connectors(&connectors, &reconnecting, &removed);
        restore_interrupted_connectors(&connectors, &reconnecting, &removed);

        assert!(connectors.contains(&retained));
        assert!(!connectors.contains(&deleted));
        assert!(reconnecting.is_empty());
        assert!(removed.is_empty());
    }
}

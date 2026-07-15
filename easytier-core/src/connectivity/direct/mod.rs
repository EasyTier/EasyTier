use std::{
    collections::HashSet,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant as StdInstant},
};

use anyhow::Context;
use async_trait::async_trait;
use dashmap::DashMap;
use quanta::Instant;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use url::{Host, Url};

use crate::{
    config::PeerId,
    connectivity::{
        protocol::ClientProtocolUpgrader,
        transport::{self, ConnectedTransport, UdpSessionMode},
    },
    hole_punch::udp::{should_background_p2p_with_peer, should_try_p2p_with_peer},
    listener::RunningListenerProvider,
    peers::{
        foreign_network_manager::ForeignNetworkRpcRegistrar, peer_conn::PeerConnId,
        peer_manager::PeerManagerCore, peer_rpc::PeerRpcManager,
    },
    proto::{
        common::Void,
        peer_rpc::{
            DirectConnectorRpc, DirectConnectorRpcClientFactory,
            DirectConnectorRpcServer as GeneratedDirectConnectorRpcServer, GetIpListRequest,
            GetIpListResponse, SendUdpHolePunchPacketRequest,
        },
        rpc_types::{self, controller::BaseController},
    },
    socket::{
        IpVersion, SocketContext,
        dns::DnsResolver,
        tcp::{TcpBindOptions, TcpSocketPurpose},
        udp::{
            PreferredIpv6Source, UdpBindOptions, UdpSessionProtocol, VirtualUdpSocket,
            VirtualUdpSocketFactory, send_v4_hole_punch_control_packet,
            send_v6_hole_punch_control_packet,
        },
    },
    stun::{StunInfoProvider, StunSocketMapper},
    task::{PeerTaskLauncher, PeerTaskManager},
    tunnel::Tunnel,
};

use super::manual::{
    ManualConnectorHost, collect_bind_addrs, convert_idn_to_ascii, resolve_remote_addr,
    resolve_url_addrs,
};

mod udp;

const DIRECT_CONNECTOR_BLACKLIST_TIMEOUT: Duration = Duration::from_secs(300);
const INVALID_SERVICE_BLACKLIST_TIMEOUT: Duration = Duration::from_secs(3600);
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
const DIRECT_TASK_LOOP_INTERVAL_MS: u64 = 5000;
const MAX_IPV6_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 16;
const MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS: usize = 16;

#[async_trait]
pub trait DirectConnectorHost: ManualConnectorHost {
    async fn collect_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse;

    async fn collect_foreign_ip_addrs(&self, context: &SocketContext) -> GetIpListResponse {
        self.collect_ip_addrs(context).await
    }

    fn mapped_listeners(&self) -> Vec<Url>;

    fn running_listeners(&self) -> Vec<Url>;

    fn is_local_ip(&self, ip: &IpAddr) -> bool;

    fn is_protected_tcp_port(&self, port: u16) -> bool;

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool;

    async fn preferred_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source>;

    async fn preferred_foreign_ipv6_source(
        &self,
        ip: Ipv6Addr,
        context: SocketContext,
    ) -> Option<PreferredIpv6Source> {
        self.preferred_ipv6_source(ip, context).await
    }
}

struct HostRunningListenerProvider<H>
where
    H: DirectConnectorHost,
{
    host: Arc<H>,
}

impl<H> std::fmt::Debug for HostRunningListenerProvider<H>
where
    H: DirectConnectorHost,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostRunningListenerProvider")
            .finish_non_exhaustive()
    }
}

impl<H> RunningListenerProvider for HostRunningListenerProvider<H>
where
    H: DirectConnectorHost,
{
    fn running_listeners(&self) -> Vec<Url> {
        self.host.running_listeners()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectTransport {
    Tcp(TcpSocketPurpose),
    Udp(UdpSessionMode),
}

impl DirectTransport {
    fn from_url(url: &Url) -> anyhow::Result<Self> {
        match url.scheme() {
            "tcp" | "ws" | "wss" => Ok(Self::Tcp(TcpSocketPurpose::DirectConnect)),
            "faketcp" => Ok(Self::Tcp(TcpSocketPurpose::FakeTcp)),
            "udp" => Ok(Self::Udp(UdpSessionMode::EasyTierMux)),
            "wg" => Ok(Self::Udp(UdpSessionMode::Classified(
                UdpSessionProtocol::WireGuard,
            ))),
            "quic" => Ok(Self::Udp(UdpSessionMode::Classified(
                UdpSessionProtocol::Quic,
            ))),
            scheme => anyhow::bail!("unsupported direct transport scheme: {scheme}"),
        }
    }

    fn is_udp(self) -> bool {
        matches!(self, Self::Udp(_))
    }

    fn supports_interface_bind(self) -> bool {
        !matches!(self, Self::Tcp(TcpSocketPurpose::FakeTcp))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectConnectorOptions {
    pub network_name: String,
    pub default_protocol: String,
    pub enable_ipv6: bool,
    pub allow_public_server: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
    pub bind_device: bool,
    pub allow_interface_bind: bool,
    pub tcp_bind: TcpBindOptions,
    pub udp_bind: UdpBindOptions,
    #[serde(skip)]
    pub testing: bool,
}

impl Default for DirectConnectorOptions {
    fn default() -> Self {
        Self {
            network_name: "default".to_owned(),
            default_protocol: "tcp".to_owned(),
            enable_ipv6: true,
            allow_public_server: false,
            lazy_p2p: false,
            disable_p2p: false,
            need_p2p: false,
            bind_device: false,
            allow_interface_bind: true,
            tcp_bind: TcpBindOptions::default(),
            udp_bind: UdpBindOptions::direct_connect(),
            testing: false,
        }
    }
}

impl DirectConnectorOptions {
    fn socket_context(&self, transport: DirectTransport, ip_version: IpVersion) -> SocketContext {
        let context = match transport {
            DirectTransport::Tcp(_) => self.tcp_bind.context.clone(),
            DirectTransport::Udp(_) => self.udp_bind.context.clone(),
        };
        context.with_ip_version(ip_version)
    }
}

#[derive(Debug)]
struct ExpiringSet<K>
where
    K: Eq + Hash,
{
    entries: DashMap<K, StdInstant>,
}

impl<K> Default for ExpiringSet<K>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<K> ExpiringSet<K>
where
    K: Eq + Hash + Clone,
{
    fn insert(&self, key: K, ttl: Duration) {
        self.entries.insert(key, StdInstant::now() + ttl);
    }

    fn contains(&self, key: &K) -> bool {
        let active = self
            .entries
            .get(key)
            .is_some_and(|expires_at| *expires_at > StdInstant::now());
        if !active {
            self.entries.remove(key);
        }
        active
    }

    fn cleanup(&self) {
        let now = StdInstant::now();
        self.entries.retain(|_, expires_at| *expires_at > now);
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
struct ListenerBlacklistKey(PeerId, String);

struct DirectConnectorData<H>
where
    H: DirectConnectorHost,
{
    peer_manager: Arc<PeerManagerCore>,
    host: Arc<H>,
    stun: Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>,
    running_listeners: Arc<dyn RunningListenerProvider>,
    dns: Arc<dyn DnsResolver>,
    protocol:
        Arc<dyn ClientProtocolUpgrader<<H as crate::socket::tcp::VirtualTcpSocketFactory>::Socket>>,
    options: DirectConnectorOptions,
    listener_blacklist: ExpiringSet<ListenerBlacklistKey>,
    peer_blacklist: ExpiringSet<PeerId>,
}

impl<H> std::fmt::Debug for DirectConnectorData<H>
where
    H: DirectConnectorHost,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectConnectorData")
            .field("peer_id", &self.peer_manager.my_peer_id())
            .field("network_name", &self.options.network_name)
            .finish()
    }
}

pub struct DirectConnectorManager<H>
where
    H: DirectConnectorHost,
{
    data: Arc<DirectConnectorData<H>>,
    client: PeerTaskManager<DirectConnectorLauncher<H>>,
}

impl<H> DirectConnectorManager<H>
where
    H: DirectConnectorHost,
{
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        stun: Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>,
        dns: Arc<dyn DnsResolver>,
        protocol: Arc<
            dyn ClientProtocolUpgrader<<H as crate::socket::tcp::VirtualTcpSocketFactory>::Socket>,
        >,
        options: DirectConnectorOptions,
    ) -> Self {
        let running_listeners = Arc::new(HostRunningListenerProvider { host: host.clone() });
        Self::new_with_running_listeners(
            peer_manager,
            host,
            stun,
            running_listeners,
            dns,
            protocol,
            options,
        )
    }

    pub fn new_with_running_listeners(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        stun: Arc<dyn StunSocketMapper<<H as VirtualUdpSocketFactory>::Socket>>,
        running_listeners: Arc<dyn RunningListenerProvider>,
        dns: Arc<dyn DnsResolver>,
        protocol: Arc<
            dyn ClientProtocolUpgrader<<H as crate::socket::tcp::VirtualTcpSocketFactory>::Socket>,
        >,
        options: DirectConnectorOptions,
    ) -> Self {
        let data = Arc::new(DirectConnectorData {
            peer_manager: peer_manager.clone(),
            host,
            stun,
            running_listeners,
            dns,
            protocol,
            options,
            listener_blacklist: ExpiringSet::default(),
            peer_blacklist: ExpiringSet::default(),
        });
        let client = PeerTaskManager::new_with_external_signal(
            DirectConnectorLauncher(data.clone()),
            peer_manager.clone(),
            Some(peer_manager.p2p_demand_notify()),
        );
        Self { data, client }
    }

    pub fn run(&self) {
        self.run_as_server();
        self.run_as_client();
    }

    pub fn run_as_server(&self) {
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                GeneratedDirectConnectorRpcServer::new(
                    DirectConnectorRpcHandler::new_with_running_listeners_and_stun(
                        self.data.host.clone(),
                        self.data.running_listeners.clone(),
                        self.data.options.udp_bind.context.clone(),
                        Some(self.data.stun.clone()),
                    ),
                ),
                &self.data.options.network_name,
            );
    }

    pub fn run_as_client(&self) {
        self.client.start();
    }

    pub async fn stop(&self) {
        self.client.stop().await;
        self.data
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                GeneratedDirectConnectorRpcServer::new(
                    DirectConnectorRpcHandler::new_with_running_listeners_and_stun(
                        self.data.host.clone(),
                        self.data.running_listeners.clone(),
                        self.data.options.udp_bind.context.clone(),
                        Some(self.data.stun.clone()),
                    ),
                ),
                &self.data.options.network_name,
            );
    }

    pub async fn try_direct_connect_with_ip_list(
        &self,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> anyhow::Result<()> {
        self.data
            .try_direct_connect_with_ip_list(dst_peer_id, ip_list)
            .await
    }

    pub fn running_listeners(&self) -> Vec<Url> {
        self.data.running_listeners.running_listeners()
    }

    pub async fn local_address_observations(&self) -> GetIpListResponse {
        collect_address_observations(
            self.data.host.as_ref(),
            &self.data.options.udp_bind.context,
            false,
            Some(self.data.stun.as_ref()),
        )
        .await
    }
}

struct DirectConnectorLauncher<H>(Arc<DirectConnectorData<H>>)
where
    H: DirectConnectorHost;

impl<H> Clone for DirectConnectorLauncher<H>
where
    H: DirectConnectorHost,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl<H> PeerTaskLauncher for DirectConnectorLauncher<H>
where
    H: DirectConnectorHost,
{
    type PeerManager = PeerManagerCore;
    type Data = Arc<DirectConnectorData<H>>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_manager: Arc<PeerManagerCore>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<PeerId> {
        data.peer_blacklist.cleanup();
        let my_peer_id = data.peer_manager.my_peer_id();
        let now = Instant::now();
        data.peer_manager
            .get_route()
            .list_routes()
            .await
            .into_iter()
            .filter(|route| {
                let static_allowed = should_background_p2p_with_peer(
                    route.feature_flag.as_ref(),
                    data.options.allow_public_server,
                    data.options.lazy_p2p,
                    data.options.disable_p2p,
                    data.options.need_p2p,
                );
                let dynamic_allowed = should_try_p2p_with_peer(
                    route.feature_flag.as_ref(),
                    data.options.allow_public_server,
                    data.options.disable_p2p,
                    data.options.need_p2p,
                ) && data.peer_manager.has_recent_traffic(route.peer_id, now);
                route.peer_id != my_peer_id
                    && (static_allowed || dynamic_allowed)
                    && !data.peer_manager.has_directly_connected_conn(route.peer_id)
                    && !data.peer_blacklist.contains(&route.peer_id)
            })
            .map(|route| route.peer_id)
            .collect()
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        peer_id: PeerId,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let data = data.clone();
        tokio::spawn(async move { data.try_direct_connect(peer_id).await })
    }

    fn loop_interval_ms(&self) -> u64 {
        DIRECT_TASK_LOOP_INTERVAL_MS
    }
}

impl<H> DirectConnectorData<H>
where
    H: DirectConnectorHost,
{
    async fn try_direct_connect(self: Arc<Self>, dst_peer_id: PeerId) -> anyhow::Result<()> {
        let backoffs_ms = [1000, 2000, 2000, 5000, 5000, 10000, 30000, 60000];
        let mut backoff_index = 0usize;
        let mut attempt = 0usize;

        loop {
            if self.peer_blacklist.contains(&dst_peer_id) {
                anyhow::bail!("peer {dst_peer_id} is blacklisted");
            }
            if attempt > 0 {
                crate::runtime_time::sleep(Duration::from_millis(backoffs_ms[backoff_index])).await;
                backoff_index = (backoff_index + 1).min(backoffs_ms.len() - 1);
            }
            attempt += 1;

            let rpc_stub = self
                .peer_manager
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
                self.peer_manager.my_peer_id(),
                dst_peer_id,
                self.options.network_name.clone(),
            );
            let ip_list = match rpc_stub
                .get_ip_list(BaseController::default(), GetIpListRequest {})
                .await
            {
                Ok(ip_list) => ip_list,
                Err(error @ rpc_types::error::Error::InvalidServiceKey(_, _)) => {
                    self.peer_blacklist
                        .insert(dst_peer_id, INVALID_SERVICE_BLACKLIST_TIMEOUT);
                    return Err(error.into());
                }
                Err(error) => return Err(error.into()),
            };

            tracing::info!(?ip_list, dst_peer_id, "got direct-connect IP list");
            let result = self
                .try_direct_connect_with_ip_list(dst_peer_id, ip_list)
                .await;
            tracing::info!(?result, dst_peer_id, "direct-connect attempt returned");
            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }
        }
    }

    async fn try_direct_connect_with_ip_list(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        ip_list: GetIpListResponse,
    ) -> anyhow::Result<()> {
        let mut available_listeners = ip_list
            .listeners
            .clone()
            .into_iter()
            .map(Into::<Url>::into)
            .filter(|listener| listener.scheme() != "ring")
            .filter(|listener| {
                mapped_listener_port(listener).is_some() && listener.host().is_some()
            })
            .filter(|listener| {
                self.options.enable_ipv6 || !matches!(listener.host(), Some(Host::Ipv6(_)))
            })
            .collect::<Vec<_>>();

        if available_listeners.is_empty() {
            anyhow::bail!("peer {dst_peer_id} has no valid listener");
        }

        available_listeners.sort_by_key(|listener| {
            if listener.scheme() == self.options.default_protocol {
                3
            } else if listener.scheme() == "udp" {
                2
            } else {
                1
            }
        });

        while !available_listeners.is_empty() {
            let mut tasks = JoinSet::new();
            let current_scheme = available_listeners
                .last()
                .expect("non-empty listener list")
                .scheme()
                .to_owned();
            while available_listeners
                .last()
                .is_some_and(|listener| listener.scheme() == current_scheme)
            {
                let listener = available_listeners.pop().expect("listener should exist");
                self.spawn_direct_connect_tasks(dst_peer_id, &ip_list, &listener, &mut tasks)
                    .await;
            }
            let _ = tasks.join_all().await;
            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }
        }
        Ok(())
    }

    async fn spawn_direct_connect_tasks(
        self: &Arc<Self>,
        dst_peer_id: PeerId,
        ip_list: &GetIpListResponse,
        listener: &Url,
        tasks: &mut JoinSet<anyhow::Result<()>>,
    ) {
        let Ok(mut addrs) = resolve_mapped_listener_addrs(
            listener,
            self.options.tcp_bind.context.clone(),
            self.dns.as_ref(),
        )
        .await
        else {
            tracing::error!(?listener, "failed to resolve direct listener");
            return;
        };
        let listener_host = addrs.pop();
        let is_udp = is_udp_protocol(listener.scheme());
        let local_listeners = self.running_listeners.running_listeners();
        let port_has_local_listener = |port: u16| {
            local_listeners.iter().any(|local| {
                local.port() == Some(port) && is_udp_protocol(local.scheme()) == is_udp
            })
        };
        let should_deny_target = |target: &SocketAddr| {
            let port_is_protected = port_has_local_listener(target.port())
                || (!is_udp && self.host.is_protected_tcp_port(target.port()));
            port_is_protected && self.host.is_local_ip(&target.ip())
        };

        match listener_host {
            Some(SocketAddr::V4(socket_addr)) if socket_addr.ip().is_unspecified() => {
                for ip in ip_list
                    .interface_ipv4s
                    .iter()
                    .chain(ip_list.public_ipv4.iter())
                {
                    let target = SocketAddr::new(IpAddr::V4(ip.addr.into()), socket_addr.port());
                    if should_deny_target(&target) {
                        continue;
                    }
                    let mut url = listener.clone();
                    if url.set_ip_host(target.ip()).is_ok() {
                        tasks.spawn(Self::try_connect_to_url(
                            self.clone(),
                            dst_peer_id,
                            url.to_string(),
                        ));
                    }
                }
            }
            Some(SocketAddr::V4(socket_addr))
                if !socket_addr.ip().is_loopback() || self.options.testing =>
            {
                if !should_deny_target(&SocketAddr::V4(socket_addr)) {
                    tasks.spawn(Self::try_connect_to_url(
                        self.clone(),
                        dst_peer_id,
                        listener.to_string(),
                    ));
                }
            }
            Some(SocketAddr::V6(socket_addr)) if socket_addr.ip().is_unspecified() => {
                let candidates = ip_list
                    .interface_ipv6s
                    .iter()
                    .chain(ip_list.public_ipv6.iter())
                    .map(|ip| Ipv6Addr::from(*ip))
                    .filter(|ip| self.is_usable_public_ipv6(ip))
                    .collect::<HashSet<_>>();
                for ip in candidates {
                    let target = SocketAddr::new(IpAddr::V6(ip), socket_addr.port());
                    if should_deny_target(&target) {
                        continue;
                    }
                    let mut url = listener.clone();
                    if url.set_ip_host(target.ip()).is_ok() {
                        tasks.spawn(Self::try_connect_to_url(
                            self.clone(),
                            dst_peer_id,
                            url.to_string(),
                        ));
                    }
                }
            }
            Some(SocketAddr::V6(socket_addr))
                if self
                    .peer_manager
                    .is_easytier_managed_ipv6(socket_addr.ip())
                    .await =>
            {
                tracing::debug!(?listener, "skip managed IPv6 direct target");
            }
            Some(SocketAddr::V6(socket_addr))
                if !socket_addr.ip().is_loopback() || self.options.testing =>
            {
                if !should_deny_target(&SocketAddr::V6(socket_addr)) {
                    tasks.spawn(Self::try_connect_to_url(
                        self.clone(),
                        dst_peer_id,
                        listener.to_string(),
                    ));
                }
            }
            _ => {}
        }
    }

    async fn try_connect_to_url(
        self: Arc<Self>,
        dst_peer_id: PeerId,
        url: String,
    ) -> anyhow::Result<()> {
        self.listener_blacklist.cleanup();
        let key = ListenerBlacklistKey(dst_peer_id, url.clone());
        if self.listener_blacklist.contains(&key) {
            anyhow::bail!("direct listener URL is blacklisted");
        }

        let backoffs_ms = [1000i64, 2000, 4000];
        for attempt in 0..=backoffs_ms.len() {
            if self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }
            let result = self.connect_to_url_once(dst_peer_id, &url).await;
            if result.is_ok() || self.peer_manager.has_directly_connected_conn(dst_peer_id) {
                return Ok(());
            }
            if attempt == backoffs_ms.len() {
                self.listener_blacklist
                    .insert(key, DIRECT_CONNECTOR_BLACKLIST_TIMEOUT);
                return result;
            }

            let base = backoffs_ms[attempt];
            let delta = base >> 1;
            let delay_ms = {
                let mut rng = rand::thread_rng();
                base + rng.gen_range(-delta..delta)
            };
            crate::runtime_time::sleep(Duration::from_millis(delay_ms as u64)).await;
        }
        unreachable!("direct URL retry loop must return")
    }

    async fn connect_to_url_once(&self, dst_peer_id: PeerId, raw_url: &str) -> anyhow::Result<()> {
        let url = Url::parse(raw_url)?;
        let (peer_id, conn_id) = if url.scheme() == "udp" {
            match url.host() {
                Some(Host::Ipv6(_)) => self.connect_public_ipv6(dst_peer_id, &url).await?,
                Some(Host::Ipv4(ip)) if is_public_ipv4(ip) => {
                    match self.connect_public_ipv4(dst_peer_id, &url).await {
                        Ok(result) => result,
                        Err(error) => {
                            tracing::debug!(?error, %url, "public IPv4 UDP punch failed; fallback");
                            self.connect_ordinary(dst_peer_id, url.clone()).await?
                        }
                    }
                }
                _ => self.connect_ordinary(dst_peer_id, url.clone()).await?,
            }
        } else {
            self.connect_ordinary(dst_peer_id, url.clone()).await?
        };

        if peer_id != dst_peer_id && !self.options.testing {
            self.peer_manager.close_peer_conn(peer_id, &conn_id).await?;
            anyhow::bail!("direct peer mismatch for {url}: expected {dst_peer_id}, got {peer_id}");
        }
        Ok(())
    }

    async fn connect_ordinary(
        &self,
        dst_peer_id: PeerId,
        url: Url,
    ) -> anyhow::Result<(PeerId, PeerConnId)> {
        let transport = DirectTransport::from_url(&url)?;
        let normalized = convert_idn_to_ascii(url.clone())?;
        let default_port = mapped_listener_port(&normalized)
            .ok_or_else(|| anyhow::anyhow!("listener has no port: {url}"))?;
        let remote_addr = resolve_remote_addr(
            self.peer_manager.as_ref(),
            self.host.as_ref(),
            self.dns.as_ref(),
            &normalized,
            default_port,
            self.options.socket_context(transport, IpVersion::Both),
        )
        .await?;
        let bind_addrs = if self.options.bind_device
            && self.options.allow_interface_bind
            && transport.supports_interface_bind()
        {
            collect_bind_addrs(
                self.peer_manager.as_ref(),
                self.host.as_ref(),
                transport.is_udp(),
                remote_addr,
            )
            .await?
        } else {
            Vec::new()
        };
        crate::runtime_time::timeout(DIRECT_CONNECT_TIMEOUT, async {
            let connected = match transport {
                DirectTransport::Tcp(purpose) => ConnectedTransport::Tcp(
                    transport::connect_tcp(
                        self.host.clone(),
                        remote_addr,
                        bind_addrs,
                        self.options.tcp_bind.clone(),
                        purpose,
                    )
                    .await?,
                ),
                DirectTransport::Udp(mode) => ConnectedTransport::Udp(
                    transport::connect_udp(
                        self.host.clone(),
                        remote_addr,
                        bind_addrs,
                        self.options.udp_bind.clone(),
                        mode,
                    )
                    .await?,
                ),
            };
            let tunnel = self.protocol.upgrade_client(connected, url).await?;
            self.admit(tunnel, dst_peer_id).await
        })
        .await?
    }

    async fn connect_public_ipv4(
        &self,
        dst_peer_id: PeerId,
        url: &Url,
    ) -> anyhow::Result<(PeerId, PeerConnId)> {
        let socket = self
            .host
            .bind_udp(
                UdpBindOptions::direct_connect()
                    .with_context(
                        self.options
                            .udp_bind
                            .context
                            .clone()
                            .with_ip_version(IpVersion::V4),
                    )
                    .with_local_addr(Some("0.0.0.0:0".parse().unwrap())),
            )
            .await?;
        let connector_addr = self
            .stun
            .get_udp_port_mapping_with_socket(socket.clone())
            .await?;
        let _ = self
            .remote_send_udp_hole_punch_packet(dst_peer_id, vec![connector_addr], None, url)
            .await;
        let remote_addr = resolve_literal_url(url, IpVersion::V4)?;
        let connected = udp::connect_with_socket(self.host.clone(), socket, remote_addr).await?;
        let tunnel = self
            .protocol
            .upgrade_client(ConnectedTransport::Udp(connected), url.clone())
            .await?;
        self.admit(tunnel, dst_peer_id).await
    }

    async fn connect_public_ipv6(
        &self,
        dst_peer_id: PeerId,
        url: &Url,
    ) -> anyhow::Result<(PeerId, PeerConnId)> {
        let socket = self
            .host
            .bind_udp(
                UdpBindOptions::direct_connect()
                    .with_context(
                        self.options
                            .udp_bind
                            .context
                            .clone()
                            .with_ip_version(IpVersion::V6),
                    )
                    .with_local_addr(Some("[::]:0".parse().unwrap())),
            )
            .await?;
        let connector_ips = self.collect_ipv6_hole_punch_candidates().await?;
        if !connector_ips.is_empty() {
            let port = socket.local_addr()?.port();
            let connector_addrs = connector_ips
                .into_iter()
                .map(|ip| SocketAddr::new(IpAddr::V6(ip), port))
                .collect();
            let preferred_src = match url.host() {
                Some(Host::Ipv6(ip)) => Some(ip),
                _ => None,
            };
            let _ = self
                .remote_send_udp_hole_punch_packet(dst_peer_id, connector_addrs, preferred_src, url)
                .await;
        }
        let remote_addr = resolve_literal_url(url, IpVersion::V6)?;
        let connected = udp::connect_with_socket(self.host.clone(), socket, remote_addr).await?;
        let tunnel = self
            .protocol
            .upgrade_client(ConnectedTransport::Udp(connected), url.clone())
            .await?;
        self.admit(tunnel, dst_peer_id).await
    }

    async fn collect_ipv6_hole_punch_candidates(&self) -> anyhow::Result<Vec<Ipv6Addr>> {
        let mut candidates = Vec::new();
        for ip in self
            .stun
            .get_stun_info()
            .public_ip
            .into_iter()
            .filter_map(|ip| ip.parse().ok())
        {
            if let IpAddr::V6(ip) = ip {
                self.push_ipv6_candidate(&mut candidates, ip);
            }
        }
        let interface_addrs = self.host.interface_addrs().await?;
        for ip in interface_addrs
            .interface_ipv6s
            .into_iter()
            .chain(interface_addrs.public_ipv6)
        {
            self.push_ipv6_candidate(&mut candidates, ip);
        }
        Ok(candidates)
    }

    fn push_ipv6_candidate(&self, candidates: &mut Vec<Ipv6Addr>, ip: Ipv6Addr) {
        if candidates.len() < MAX_IPV6_HOLE_PUNCH_CONNECTOR_ADDRS
            && self.is_usable_public_ipv6(&ip)
            && !candidates.contains(&ip)
        {
            candidates.push(ip);
        }
    }

    fn is_usable_public_ipv6(&self, ip: &Ipv6Addr) -> bool {
        !self.host.is_easytier_managed_ipv6(ip)
            && (self.options.testing
                || (!ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_unique_local()
                    && !ip.is_unicast_link_local()
                    && !ip.is_multicast()))
    }

    async fn remote_send_udp_hole_punch_packet(
        &self,
        dst_peer_id: PeerId,
        connector_addrs: Vec<SocketAddr>,
        preferred_src_ipv6: Option<Ipv6Addr>,
        remote_url: &Url,
    ) -> anyhow::Result<()> {
        if remote_url.scheme() != "udp" {
            anyhow::bail!("UDP punch request requires a UDP listener: {remote_url}");
        }
        let listener_port = mapped_listener_port(remote_url)
            .ok_or_else(|| anyhow::anyhow!("listener has no port: {remote_url}"))?;
        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<DirectConnectorRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            self.options.network_name.clone(),
        );
        rpc_stub
            .send_udp_hole_punch_packet(
                BaseController::default(),
                SendUdpHolePunchPacketRequest {
                    connector_addr: connector_addrs.first().copied().map(Into::into),
                    listener_port: listener_port as u32,
                    preferred_src_ipv6: preferred_src_ipv6.map(Into::into),
                    connector_addrs: connector_addrs.into_iter().map(Into::into).collect(),
                },
            )
            .await
            .with_context(|| format!("send UDP punch request to peer {dst_peer_id}"))?;
        Ok(())
    }

    async fn admit(
        &self,
        tunnel: Box<dyn Tunnel>,
        dst_peer_id: PeerId,
    ) -> anyhow::Result<(PeerId, PeerConnId)> {
        self.peer_manager
            .add_client_tunnel_with_peer_id_hint(tunnel, true, Some(dst_peer_id))
            .await
            .map_err(Into::into)
    }
}

pub struct DirectConnectorRpcHandler<H>
where
    H: DirectConnectorHost,
{
    host: Arc<H>,
    running_listeners: Arc<dyn RunningListenerProvider>,
    socket_context: SocketContext,
    foreign_network: bool,
    stun: Option<Arc<dyn StunInfoProvider>>,
}

impl<H> Clone for DirectConnectorRpcHandler<H>
where
    H: DirectConnectorHost,
{
    fn clone(&self) -> Self {
        Self {
            host: self.host.clone(),
            running_listeners: self.running_listeners.clone(),
            socket_context: self.socket_context.clone(),
            foreign_network: self.foreign_network,
            stun: self.stun.clone(),
        }
    }
}

impl<H> DirectConnectorRpcHandler<H>
where
    H: DirectConnectorHost,
{
    pub fn new(host: Arc<H>, socket_context: SocketContext) -> Self {
        Self::new_with_stun(host, socket_context, None)
    }

    pub fn new_with_stun(
        host: Arc<H>,
        socket_context: SocketContext,
        stun: Option<Arc<dyn StunInfoProvider>>,
    ) -> Self {
        let running_listeners = Arc::new(HostRunningListenerProvider { host: host.clone() });
        Self {
            host,
            running_listeners,
            socket_context,
            foreign_network: false,
            stun,
        }
    }

    pub fn new_for_foreign_network(host: Arc<H>, socket_context: SocketContext) -> Self {
        Self::new_for_foreign_network_with_stun(host, socket_context, None)
    }

    pub fn new_for_foreign_network_with_stun(
        host: Arc<H>,
        socket_context: SocketContext,
        stun: Option<Arc<dyn StunInfoProvider>>,
    ) -> Self {
        let running_listeners = Arc::new(HostRunningListenerProvider { host: host.clone() });
        Self {
            host,
            running_listeners,
            socket_context,
            foreign_network: true,
            stun,
        }
    }

    pub fn new_with_running_listeners(
        host: Arc<H>,
        running_listeners: Arc<dyn RunningListenerProvider>,
        socket_context: SocketContext,
    ) -> Self {
        Self::new_with_running_listeners_and_stun(host, running_listeners, socket_context, None)
    }

    fn new_with_running_listeners_and_stun(
        host: Arc<H>,
        running_listeners: Arc<dyn RunningListenerProvider>,
        socket_context: SocketContext,
        stun: Option<Arc<dyn StunInfoProvider>>,
    ) -> Self {
        Self {
            host,
            running_listeners,
            socket_context,
            foreign_network: false,
            stun,
        }
    }
}

async fn collect_address_observations<H>(
    host: &H,
    socket_context: &SocketContext,
    foreign_network: bool,
    stun: Option<&dyn StunInfoProvider>,
) -> GetIpListResponse
where
    H: DirectConnectorHost,
{
    let mut response = if foreign_network {
        host.collect_foreign_ip_addrs(socket_context).await
    } else {
        host.collect_ip_addrs(socket_context).await
    };
    if let Some(stun) = stun {
        for public_ip in stun.get_stun_info().public_ip {
            match public_ip.parse::<IpAddr>() {
                Ok(IpAddr::V4(ip)) => response.public_ipv4 = Some(ip.into()),
                Ok(IpAddr::V6(ip)) => response.public_ipv6 = Some(ip.into()),
                Err(_) => {}
            }
        }
    }
    if !foreign_network {
        response
            .interface_ipv6s
            .retain(|ip| !host.is_easytier_managed_ipv6(&Ipv6Addr::from(*ip)));
        if response
            .public_ipv6
            .as_ref()
            .map(|ip| Ipv6Addr::from(*ip))
            .is_some_and(|ip| host.is_easytier_managed_ipv6(&ip))
        {
            response.public_ipv6 = None;
        }
    }
    response
}

pub struct ForeignDirectConnectorRpcRegistrar<H>
where
    H: DirectConnectorHost,
{
    host: Arc<H>,
    stun: Arc<dyn StunInfoProvider>,
}

impl<H> ForeignDirectConnectorRpcRegistrar<H>
where
    H: DirectConnectorHost,
{
    pub fn new(host: Arc<H>, stun: Arc<dyn StunInfoProvider>) -> Self {
        Self { host, stun }
    }
}

impl<H> ForeignNetworkRpcRegistrar for ForeignDirectConnectorRpcRegistrar<H>
where
    H: DirectConnectorHost,
{
    fn register_peer_rpc_services(
        &self,
        peer_rpc: &Arc<PeerRpcManager>,
        network_name: &str,
        socket_context: SocketContext,
    ) {
        peer_rpc.rpc_server().registry().register(
            GeneratedDirectConnectorRpcServer::new(
                DirectConnectorRpcHandler::new_for_foreign_network_with_stun(
                    self.host.clone(),
                    socket_context,
                    Some(self.stun.clone()),
                ),
            ),
            network_name,
        );
    }
}

#[async_trait]
impl<H> DirectConnectorRpc for DirectConnectorRpcHandler<H>
where
    H: DirectConnectorHost,
{
    type Controller = BaseController;

    async fn get_ip_list(
        &self,
        _: BaseController,
        _: GetIpListRequest,
    ) -> rpc_types::error::Result<GetIpListResponse> {
        let mut response = collect_address_observations(
            self.host.as_ref(),
            &self.socket_context,
            self.foreign_network,
            self.stun.as_deref(),
        )
        .await;
        response.listeners = self
            .host
            .mapped_listeners()
            .into_iter()
            .chain(self.running_listeners.running_listeners())
            .map(Into::into)
            .collect();
        Ok(response)
    }

    async fn send_udp_hole_punch_packet(
        &self,
        _: BaseController,
        request: SendUdpHolePunchPacketRequest,
    ) -> rpc_types::error::Result<Void> {
        let (listener_port, connector_addrs, preferred_src_ipv6) =
            connector_addrs_from_request(request)?;
        let preferred_source = match preferred_src_ipv6.map(Ipv6Addr::from) {
            Some(ip) => {
                if self.foreign_network {
                    self.host
                        .preferred_foreign_ipv6_source(ip, self.socket_context.clone())
                        .await
                } else {
                    self.host
                        .preferred_ipv6_source(ip, self.socket_context.clone())
                        .await
                }
            }
            None => None,
        };

        for _ in 0..3 {
            for connector_addr in &connector_addrs {
                let result = match connector_addr {
                    SocketAddr::V4(addr) => {
                        send_v4_hole_punch_control_packet(
                            self.host.as_ref(),
                            self.socket_context.clone(),
                            listener_port,
                            *addr,
                        )
                        .await
                    }
                    SocketAddr::V6(addr) => {
                        send_v6_hole_punch_control_packet(
                            self.host.as_ref(),
                            self.socket_context.clone(),
                            listener_port,
                            *addr,
                            preferred_source,
                        )
                        .await
                    }
                };
                if let Err(error) = result {
                    tracing::debug!(?error, ?connector_addr, "send UDP punch packet failed");
                }
            }
            crate::runtime_time::sleep(Duration::from_millis(30)).await;
        }
        Ok(Void::default())
    }
}

fn connector_addrs_from_request(
    request: SendUdpHolePunchPacketRequest,
) -> rpc_types::error::Result<(u16, Vec<SocketAddr>, Option<crate::proto::common::Ipv6Addr>)> {
    let listener_port = u16::try_from(request.listener_port)
        .map_err(|_| anyhow::anyhow!("listener_port out of range: {}", request.listener_port))?;
    let mut connector_addrs = request
        .connector_addrs
        .into_iter()
        .map(SocketAddr::from)
        .collect::<Vec<_>>();
    if connector_addrs.is_empty() {
        connector_addrs.push(
            request
                .connector_addr
                .ok_or_else(|| anyhow::anyhow!("connector_addr is required"))?
                .into(),
        );
    }
    let mut deduped = Vec::with_capacity(connector_addrs.len());
    for addr in connector_addrs {
        if !deduped.contains(&addr) {
            deduped.push(addr);
        }
        if deduped.len() >= MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS {
            break;
        }
    }
    Ok((listener_port, deduped, request.preferred_src_ipv6))
}

fn mapped_listener_port(url: &Url) -> Option<u16> {
    url.port().or_else(|| default_port(url.scheme()))
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "tcp" | "udp" => Some(11010),
        "wg" => Some(11011),
        "quic" => Some(11012),
        "ws" => Some(80),
        "wss" => Some(443),
        "faketcp" => Some(11013),
        _ => None,
    }
}

fn is_udp_protocol(scheme: &str) -> bool {
    matches!(scheme, "udp" | "wg" | "quic")
}

async fn resolve_mapped_listener_addrs(
    listener: &Url,
    context: SocketContext,
    dns: &dyn DnsResolver,
) -> anyhow::Result<Vec<SocketAddr>> {
    let port = mapped_listener_port(listener)
        .ok_or_else(|| anyhow::anyhow!("listener has no default port: {listener}"))?;
    resolve_url_addrs(
        listener,
        port,
        context.with_ip_version(IpVersion::Both),
        dns,
    )
    .await
}

fn resolve_literal_url(url: &Url, ip_version: IpVersion) -> anyhow::Result<SocketAddr> {
    let port =
        mapped_listener_port(url).ok_or_else(|| anyhow::anyhow!("listener has no port: {url}"))?;
    match (url.host(), ip_version) {
        (Some(Host::Ipv4(ip)), IpVersion::V4 | IpVersion::Both) => {
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        (Some(Host::Ipv6(ip)), IpVersion::V6 | IpVersion::Both) => {
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        _ => anyhow::bail!("URL host does not match {ip_version:?}: {url}"),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    !ip.is_private()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_broadcast()
        && !ip.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapped_listener_defaults_match_native_schemes() {
        assert_eq!(
            mapped_listener_port(&"ws://example.com".parse().unwrap()),
            Some(80)
        );
        assert_eq!(
            mapped_listener_port(&"wss://example.com".parse().unwrap()),
            Some(443)
        );
        assert_eq!(
            mapped_listener_port(&"tcp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
        assert_eq!(
            mapped_listener_port(&"udp://127.0.0.1".parse().unwrap()),
            Some(11010)
        );
        assert_eq!(
            mapped_listener_port(&"wg://127.0.0.1".parse().unwrap()),
            Some(11011)
        );
    }

    #[test]
    fn faketcp_uses_specialized_tcp_socket_without_interface_binding() {
        let transport =
            DirectTransport::from_url(&"faketcp://127.0.0.1:11013".parse().unwrap()).unwrap();

        assert_eq!(transport, DirectTransport::Tcp(TcpSocketPurpose::FakeTcp));
        assert!(!transport.supports_interface_bind());
        assert!(!transport.is_udp());
    }

    #[test]
    fn connector_address_request_deduplicates_and_caps() {
        let mut request = SendUdpHolePunchPacketRequest {
            listener_port: 11010,
            ..Default::default()
        };
        for port in 1..=20 {
            request
                .connector_addrs
                .push(SocketAddr::from(([127, 0, 0, 1], port)).into());
        }
        request
            .connector_addrs
            .push(SocketAddr::from(([127, 0, 0, 1], 1)).into());

        let (_, addrs, _) = connector_addrs_from_request(request).unwrap();
        assert_eq!(addrs.len(), MAX_UDP_HOLE_PUNCH_CONNECTOR_ADDRS);
        assert_eq!(addrs[0], SocketAddr::from(([127, 0, 0, 1], 1)));
    }

    #[test]
    fn expiring_set_removes_expired_entries() {
        let set = ExpiringSet::default();
        set.insert(7u32, Duration::ZERO);
        assert!(!set.contains(&7));
    }
}

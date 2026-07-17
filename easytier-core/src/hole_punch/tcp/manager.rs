use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use anyhow::Context as _;
use async_trait::async_trait;
use dashmap::DashMap;
use quanta::Instant;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    config::PeerId,
    connectivity::protocol::{ClientProtocolUpgrader, ServerProtocolUpgrader},
    foundation::task::{PeerTaskLauncher, PeerTaskManager},
    hole_punch::udp::{BackOff, should_background_p2p_with_peer, should_try_p2p_with_peer},
    peers::peer_manager::PeerManagerCore,
    proto::{
        common::NatType,
        peer_rpc::{
            TcpHolePunchRequest, TcpHolePunchResponse, TcpHolePunchRpc,
            TcpHolePunchRpcClientFactory, TcpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    socket::{
        IpVersion, SocketContext,
        tcp::{TcpBindOptions, TcpListenOptions, VirtualTcpListener},
    },
    stun::StunInfoProvider,
};

use super::{
    AcceptedTcpSocket, ConnectedTcpSocket, ProtocolTcpHolePunchTransportSink,
    TcpHolePunchAdmission, TcpHolePunchHost, TcpHolePunchTransportSinkFor, accept_connections,
    select_local_port, try_connect_to_remote,
};

const BLACKLIST_TIMEOUT: Duration = Duration::from_secs(3600);

fn fallback_listener_options(
    socket_context: SocketContext,
    bind_addr: std::net::SocketAddr,
) -> TcpListenOptions {
    let bind = TcpBindOptions::default()
        .with_context(socket_context.with_ip_version(IpVersion::V4))
        .with_local_addr(Some(bind_addr))
        .with_only_v6(true);
    TcpListenOptions::hole_punch(bind_addr).with_bind(bind)
}

struct TcpHolePunchBlacklist {
    entries: DashMap<PeerId, Instant>,
}

impl TcpHolePunchBlacklist {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    fn insert(&self, peer_id: PeerId) {
        self.entries.insert(peer_id, Instant::now());
    }

    fn contains(&self, peer_id: PeerId) -> bool {
        let active = self
            .entries
            .get(&peer_id)
            .is_some_and(|inserted_at| inserted_at.elapsed() < BLACKLIST_TIMEOUT);
        if !active {
            self.entries.remove(&peer_id);
        }
        active
    }

    fn cleanup(&self) {
        self.entries
            .retain(|_, inserted_at| inserted_at.elapsed() < BLACKLIST_TIMEOUT);
    }
}

fn handle_rpc_result<T>(
    result: Result<T, rpc_types::error::Error>,
    dst_peer_id: PeerId,
    blacklist: &TcpHolePunchBlacklist,
) -> Result<T, rpc_types::error::Error> {
    match result {
        Ok(result) => Ok(result),
        Err(error) => {
            if matches!(error, rpc_types::error::Error::InvalidServiceKey(_, _)) {
                blacklist.insert(dst_peer_id);
            }
            Err(error)
        }
    }
}

fn is_symmetric_tcp_nat(nat_type: NatType) -> bool {
    matches!(
        nat_type,
        NatType::Symmetric | NatType::SymmetricEasyInc | NatType::SymmetricEasyDec
    )
}

fn join_joinset_background(tasks: Arc<Mutex<JoinSet<()>>>) -> AbortOnDropHandle<()> {
    let tasks = Arc::downgrade(&tasks);
    AbortOnDropHandle::new(tokio::spawn(async move {
        while tasks.strong_count() > 0 {
            crate::foundation::time::sleep(Duration::from_secs(1)).await;
            let Some(tasks) = tasks.upgrade() else {
                break;
            };
            let mut tasks = tasks.lock().unwrap();
            while tasks.try_join_next().is_some() {}
        }
    }))
}

struct TcpHolePunchServer<H>
where
    H: TcpHolePunchHost,
{
    host: Arc<H>,
    stun: Arc<dyn StunInfoProvider>,
    socket_context: SocketContext,
    transport_sink: Arc<TcpHolePunchTransportSinkFor<H>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
    reaper: Mutex<Option<AbortOnDropHandle<()>>>,
    stopping: AtomicBool,
}

impl<H> TcpHolePunchServer<H>
where
    H: TcpHolePunchHost,
{
    fn new(
        host: Arc<H>,
        stun: Arc<dyn StunInfoProvider>,
        socket_context: SocketContext,
        transport_sink: Arc<TcpHolePunchTransportSinkFor<H>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            host,
            stun,
            socket_context,
            transport_sink,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            reaper: Mutex::new(None),
            stopping: AtomicBool::new(true),
        })
    }

    fn start(&self) {
        let mut reaper = self.reaper.lock().unwrap();
        if reaper.as_ref().is_some_and(|task| !task.is_finished()) {
            return;
        }
        {
            let _tasks = self.tasks.lock().unwrap();
            self.stopping.store(false, Ordering::Release);
        }
        reaper.replace(join_joinset_background(self.tasks.clone()));
    }

    fn begin_stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    async fn stop(&self) {
        let reaper = self.reaper.lock().unwrap().take();
        if let Some(reaper) = reaper {
            reaper.abort();
            let _ = reaper.await;
        }
        let mut tasks = {
            let mut task_slot = self.tasks.lock().unwrap();
            std::mem::replace(&mut *task_slot, JoinSet::new())
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[async_trait]
impl<H> TcpHolePunchRpc for TcpHolePunchServer<H>
where
    H: TcpHolePunchHost,
{
    type Controller = BaseController;

    #[tracing::instrument(skip(self), fields(a_mapped_addr = ?input.connector_mapped_addr), err)]
    async fn exchange_mapped_addr(
        &self,
        _controller: Self::Controller,
        input: TcpHolePunchRequest,
    ) -> rpc_types::error::Result<TcpHolePunchResponse> {
        let local_nat_type =
            NatType::try_from(self.stun.get_stun_info().tcp_nat_type).unwrap_or(NatType::Unknown);
        tracing::debug!(?local_nat_type, "tcp hole punch rpc received");
        if local_nat_type == NatType::Unknown {
            tracing::warn!(?local_nat_type, "tcp hole punch rpc rejected (unknown)");
            return Err(anyhow::anyhow!("tcp nat type unknown not supported").into());
        }

        let remote_mapped_addr = input
            .connector_mapped_addr
            .ok_or_else(|| anyhow::anyhow!("connector_mapped_addr is required"))?;
        let remote_mapped_addr: std::net::SocketAddr = remote_mapped_addr.into();
        let remote_ip = remote_mapped_addr.ip();
        if remote_ip.is_unspecified() || remote_ip.is_multicast() {
            tracing::warn!(
                ?remote_mapped_addr,
                "tcp hole punch rpc invalid connector addr"
            );
            return Err(anyhow::anyhow!("connector_mapped_addr is malformed").into());
        }

        let local_port = select_local_port(
            self.host.as_ref(),
            self.socket_context.clone(),
            remote_mapped_addr.is_ipv6(),
        )
        .await?;
        let local_mapped_addr = self
            .stun
            .get_tcp_port_mapping(local_port)
            .await
            .context("failed to get tcp port mapping")?;

        tracing::info!(
            ?remote_mapped_addr,
            local_port,
            ?local_mapped_addr,
            "tcp hole punch rpc responding with listener mapped addr and start connecting"
        );

        let host = self.host.clone();
        let socket_context = self.socket_context.clone();
        let transport_sink = self.transport_sink.clone();
        let mut tasks = self.tasks.lock().unwrap();
        if self.stopping.load(Ordering::Acquire) {
            return Err(rpc_types::error::Error::Shutdown);
        }
        tasks.spawn(async move {
            let _ = try_connect_to_remote(
                host,
                transport_sink,
                remote_mapped_addr,
                local_port,
                socket_context,
                TcpHolePunchAdmission::Client,
                5,
            )
            .await;
        });

        Ok(TcpHolePunchResponse {
            listener_mapped_addr: Some(local_mapped_addr.into()),
        })
    }
}

struct TcpHolePunchConnectorData<H>
where
    H: TcpHolePunchHost,
{
    host: Arc<H>,
    stun: Arc<dyn StunInfoProvider>,
    socket_context: SocketContext,
    peer_manager: Arc<PeerManagerCore>,
    transport_sink: Arc<TcpHolePunchTransportSinkFor<H>>,
    blacklist: TcpHolePunchBlacklist,
}

impl<H> TcpHolePunchConnectorData<H>
where
    H: TcpHolePunchHost,
{
    async fn punch_as_initiator(self: Arc<Self>, dst_peer_id: PeerId) -> anyhow::Result<()> {
        let mut backoff = BackOff::new(vec![1000, 1000, 4000, 8000]);

        loop {
            backoff.sleep_for_next_backoff().await;
            if self.do_punch_as_initiator(dst_peer_id).await.is_ok() {
                break;
            }

            if self.blacklist.contains(dst_peer_id) {
                tracing::warn!(
                    dst_peer_id,
                    "tcp hole punch initiator skipped (blacklisted)"
                );
                break;
            }
        }

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(dst_peer_id), err)]
    async fn do_punch_as_initiator(&self, dst_peer_id: PeerId) -> anyhow::Result<()> {
        let local_nat_type =
            NatType::try_from(self.stun.get_stun_info().tcp_nat_type).unwrap_or(NatType::Unknown);
        tracing::debug!(?local_nat_type, "tcp hole punch initiator start");
        if is_symmetric_tcp_nat(local_nat_type) || local_nat_type == NatType::Unknown {
            tracing::debug!("tcp hole punch initiator skipped (symmetric)");
            return Ok(());
        }

        let local_port =
            select_local_port(self.host.as_ref(), self.socket_context.clone(), false).await?;
        let local_mapped_addr = self
            .stun
            .get_tcp_port_mapping(local_port)
            .await
            .context("failed to get tcp port mapping")?;

        tracing::info!(
            dst_peer_id,
            local_port,
            ?local_mapped_addr,
            "tcp hole punch initiator got mapped addr, start rpc exchange"
        );

        let rpc_stub = self
            .peer_manager
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
            self.peer_manager.my_peer_id(),
            dst_peer_id,
            self.peer_manager.network_name().to_owned(),
        );
        let response = rpc_stub
            .exchange_mapped_addr(
                BaseController {
                    timeout_ms: 6000,
                    ..Default::default()
                },
                TcpHolePunchRequest {
                    connector_mapped_addr: Some(local_mapped_addr.into()),
                },
            )
            .await;
        let response = handle_rpc_result(response, dst_peer_id, &self.blacklist)?;
        let remote_mapped_addr = response
            .listener_mapped_addr
            .ok_or_else(|| anyhow::anyhow!("listener_mapped_addr is required"))?;
        let remote_mapped_addr = remote_mapped_addr.into();
        tracing::info!(
            dst_peer_id,
            ?remote_mapped_addr,
            "tcp hole punch initiator rpc returned"
        );

        if try_connect_to_remote(
            self.host.clone(),
            self.transport_sink.clone(),
            remote_mapped_addr,
            local_port,
            self.socket_context.clone(),
            TcpHolePunchAdmission::Server,
            1,
        )
        .await
        .is_ok()
        {
            tracing::info!(
                dst_peer_id,
                local_port,
                ?remote_mapped_addr,
                "tcp hole punch initiator connected to remote mapped addr with simultaneous connection"
            );
            return Ok(());
        }

        tracing::debug!(
            dst_peer_id,
            local_port,
            ?remote_mapped_addr,
            "tcp hole punch initiator sent syn to remote mapped addr"
        );

        let bind_addr =
            std::net::SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), local_port);
        let listener = self
            .host
            .bind_tcp(fallback_listener_options(
                self.socket_context.clone(),
                bind_addr,
            ))
            .await?;
        tracing::info!(
            dst_peer_id,
            local_port,
            local_addr = ?listener.local_addr()?,
            "tcp hole punch initiator listening"
        );

        crate::foundation::time::timeout(
            Duration::from_secs(10),
            accept_connections(listener, self.transport_sink.clone(), dst_peer_id),
        )
        .await??;

        tracing::info!(
            dst_peer_id,
            "tcp hole punch initiator accepted and added server tunnel"
        );
        Ok(())
    }

    async fn collect_peers_need_task(&self) -> Vec<PeerId> {
        let local_nat_type =
            NatType::try_from(self.stun.get_stun_info().tcp_nat_type).unwrap_or(NatType::Unknown);
        if is_symmetric_tcp_nat(local_nat_type) || local_nat_type == NatType::Unknown {
            tracing::trace!(
                ?local_nat_type,
                "tcp hole punch task collect skipped (symmetric)"
            );
            return Vec::new();
        }

        self.blacklist.cleanup();
        let policy = self.peer_manager.p2p_policy_flags();
        let local_peer_id = self.peer_manager.my_peer_id();
        let now = Instant::now();
        let mut peers_to_connect = Vec::new();
        for route in self.peer_manager.get_route().list_routes().await {
            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                policy.lazy_p2p,
                policy.disable_p2p,
                policy.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                policy.disable_p2p,
                policy.need_p2p,
            ) && self.peer_manager.has_recent_traffic(route.peer_id, now);
            if !static_allowed && !dynamic_allowed {
                continue;
            }

            let peer_id = route.peer_id;
            if peer_id == local_peer_id {
                tracing::trace!(peer_id, "tcp hole punch task collect skip self");
                continue;
            }
            if self.blacklist.contains(peer_id) {
                tracing::debug!(peer_id, "tcp hole punch task collect skip blacklisted");
                continue;
            }
            if self.peer_manager.get_peer_map().has_peer(peer_id) {
                tracing::trace!(peer_id, "tcp hole punch task collect skip already has peer");
                continue;
            }

            let peer_nat_type = route
                .stun_info
                .as_ref()
                .map(|stun_info| stun_info.tcp_nat_type)
                .and_then(|nat_type| NatType::try_from(nat_type).ok())
                .unwrap_or(NatType::Unknown);
            if peer_nat_type == NatType::Unknown {
                tracing::debug!(
                    peer_id,
                    ?peer_nat_type,
                    "tcp hole punch task collect skip peer unknown"
                );
                continue;
            }

            tracing::info!(
                peer_id,
                local_peer_id,
                ?local_nat_type,
                ?peer_nat_type,
                "tcp hole punch task collect add peer"
            );
            peers_to_connect.push(peer_id);
        }
        peers_to_connect
    }
}

struct TcpHolePunchPeerTaskLauncher<H>(Arc<TcpHolePunchConnectorData<H>>)
where
    H: TcpHolePunchHost;

impl<H> Clone for TcpHolePunchPeerTaskLauncher<H>
where
    H: TcpHolePunchHost,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl<H> PeerTaskLauncher for TcpHolePunchPeerTaskLauncher<H>
where
    H: TcpHolePunchHost,
{
    type PeerManager = PeerManagerCore;
    type Data = Arc<TcpHolePunchConnectorData<H>>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_manager: Arc<PeerManagerCore>) -> Self::Data {
        self.0.clone()
    }

    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<PeerId> {
        data.collect_peers_need_task().await
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        dst_peer_id: PeerId,
    ) -> tokio::task::JoinHandle<anyhow::Result<()>> {
        let data = data.clone();
        tokio::spawn(async move { data.punch_as_initiator(dst_peer_id).await })
    }

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct TcpHolePunchConnector<H>
where
    H: TcpHolePunchHost,
{
    server: Arc<TcpHolePunchServer<H>>,
    client: PeerTaskManager<TcpHolePunchPeerTaskLauncher<H>>,
    peer_manager: Arc<PeerManagerCore>,
}

impl<H> TcpHolePunchConnector<H>
where
    H: TcpHolePunchHost,
{
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        host: Arc<H>,
        stun: Arc<dyn StunInfoProvider>,
        socket_context: SocketContext,
        client_protocol: Arc<dyn ClientProtocolUpgrader<ConnectedTcpSocket<H>>>,
        server_protocol: Arc<dyn ServerProtocolUpgrader<AcceptedTcpSocket<H>>>,
    ) -> Self {
        let transport_sink: Arc<TcpHolePunchTransportSinkFor<H>> =
            Arc::new(ProtocolTcpHolePunchTransportSink::new(
                client_protocol,
                server_protocol,
                peer_manager.clone(),
            ));
        let data = Arc::new(TcpHolePunchConnectorData {
            host: host.clone(),
            stun: stun.clone(),
            socket_context: socket_context.clone(),
            peer_manager: peer_manager.clone(),
            transport_sink: transport_sink.clone(),
            blacklist: TcpHolePunchBlacklist::new(),
        });
        Self {
            server: TcpHolePunchServer::new(host, stun, socket_context, transport_sink),
            client: PeerTaskManager::new_with_external_signal(
                TcpHolePunchPeerTaskLauncher(data.clone()),
                peer_manager.clone(),
                Some(peer_manager.p2p_demand_notify()),
            ),
            peer_manager,
        }
    }

    pub fn run(&self) {
        if self.peer_manager.tcp_hole_punching_disabled() {
            tracing::debug!("tcp hole punch disabled by runtime configuration");
            return;
        }
        self.server.start();
        self.peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                TcpHolePunchRpcServer::new_arc(self.server.clone()),
                self.peer_manager.network_name(),
            );
        self.client.start();
    }

    pub async fn stop(&self) {
        self.client.stop().await;
        self.server.begin_stop();
        self.peer_manager
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .unregister(
                TcpHolePunchRpcServer::new_arc(self.server.clone()),
                self.peer_manager.network_name(),
            );
        self.server.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symmetric_tcp_nat_variants_are_ineligible_initiators() {
        assert!(is_symmetric_tcp_nat(NatType::Symmetric));
        assert!(is_symmetric_tcp_nat(NatType::SymmetricEasyInc));
        assert!(is_symmetric_tcp_nat(NatType::SymmetricEasyDec));
        assert!(!is_symmetric_tcp_nat(NatType::PortRestricted));
        assert!(!is_symmetric_tcp_nat(NatType::Unknown));
    }

    #[test]
    fn blacklist_tracks_and_cleans_entries() {
        let blacklist = TcpHolePunchBlacklist::new();
        assert!(!blacklist.contains(7));
        blacklist.insert(7);
        assert!(blacklist.contains(7));
        blacklist.cleanup();
        assert!(blacklist.contains(7));
    }

    #[test]
    fn fallback_listener_normalizes_context_to_ipv4() {
        let bind_addr = "0.0.0.0:23333".parse().unwrap();
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(crate::socket::NetNamespace::new("test-netns")));

        let options = fallback_listener_options(context, bind_addr);

        assert_eq!(
            options.purpose,
            crate::socket::tcp::TcpListenPurpose::HolePunch
        );
        assert_eq!(options.bind.local_addr, Some(bind_addr));
        assert_eq!(options.bind.context.ip_version, IpVersion::V4);
        assert_eq!(options.bind.context.socket_mark, Some(0));
        assert_eq!(
            options
                .bind
                .context
                .netns
                .as_ref()
                .map(|netns| netns.token()),
            Some("test-netns")
        );
        assert!(options.bind.only_v6);
        assert_eq!(options.bind.reuse_addr, None);
        assert!(!options.bind.reuse_port);
    }
}

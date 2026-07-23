#![cfg_attr(not(feature = "tcp-hole-punch"), allow(dead_code))]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
use rand::Rng as _;
use tokio::task::JoinSet;
use tokio_util::task::AbortOnDropHandle;

use crate::{
    config::{P2pPolicyFlags, PeerId},
    connectivity::{
        hole_punch::{
            HolePunchRpcRegistry, HolePunchTunnelSink,
            policy::{BackOff, should_background_p2p_with_peer, should_try_p2p_with_peer},
        },
        protocol::{ClientProtocolUpgrader, ServerProtocolUpgrade, ServerProtocolUpgrader},
        stun::StunInfoProvider,
        transport::ConnectedTransport,
    },
    foundation::task::{
        ExternalTaskSignal, PeerTaskLauncher, PeerTaskManager, reap_joinset_background,
    },
    proto::{
        common::{NatType, PeerFeatureFlag},
        peer_rpc::{
            TcpHolePunchRequest, TcpHolePunchResponse, TcpHolePunchRpc, TcpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    socket::{
        IpVersion, SocketContext,
        tcp::{
            TcpBindOptions, TcpConnectOptions, TcpListenOptions, VirtualTcpListener,
            VirtualTcpListenerFactory, VirtualTcpSocketFactory,
        },
    },
};

pub trait TcpHolePunchHost: VirtualTcpListenerFactory + VirtualTcpSocketFactory {}

impl<T> TcpHolePunchHost for T where T: VirtualTcpListenerFactory + VirtualTcpSocketFactory {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHolePunchAdmission {
    Client,
    Server,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpPunchCandidate {
    pub peer_id: PeerId,
    pub tcp_nat_type: NatType,
    pub feature_flag: Option<PeerFeatureFlag>,
    pub has_direct_connection: bool,
    pub has_recent_traffic: bool,
}

/// Narrow peer-graph view required by the TCP hole-punch engine.
///
/// Implemented only by the sealed peer adapter in `super::peer_adapters`.
#[async_trait]
pub trait TcpHolePunchPeerSource: Send + Sync + 'static {
    fn local_peer_id(&self) -> PeerId;

    fn p2p_policy_flags(&self) -> P2pPolicyFlags;

    fn tcp_hole_punching_disabled(&self) -> bool;

    fn p2p_demand_notify(&self) -> Arc<ExternalTaskSignal>;

    async fn candidates(&self) -> Vec<TcpPunchCandidate>;

    fn rpc_stub(
        &self,
        dst_peer_id: PeerId,
    ) -> Box<dyn TcpHolePunchRpc<Controller = BaseController> + Send + Sync + 'static>;
}

#[derive(Debug, thiserror::Error)]
pub enum TcpHolePunchTransportError {
    #[error("TCP hole-punch protocol upgrade failed")]
    Upgrade(#[source] anyhow::Error),
    #[error("TCP hole-punch tunnel admission failed")]
    Admission(#[source] anyhow::Error),
}

#[async_trait]
pub trait TcpHolePunchTransportSink: Send + Sync + 'static {
    type ConnectedSocket;
    type AcceptedSocket;

    async fn add_connected_transport(
        &self,
        socket: Self::ConnectedSocket,
        requested_url: url::Url,
        admission: TcpHolePunchAdmission,
    ) -> Result<(), TcpHolePunchTransportError>;

    async fn add_accepted_transport(
        &self,
        socket: Self::AcceptedSocket,
        local_url: url::Url,
    ) -> Result<(), TcpHolePunchTransportError>;
}

pub struct ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T> {
    client_protocol: Arc<dyn ClientProtocolUpgrader<ConnectedSocket>>,
    server_protocol: Arc<dyn ServerProtocolUpgrader<AcceptedSocket>>,
    tunnel_sink: Arc<T>,
}

impl<ConnectedSocket, AcceptedSocket, T>
    ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T>
{
    pub fn new(
        client_protocol: Arc<dyn ClientProtocolUpgrader<ConnectedSocket>>,
        server_protocol: Arc<dyn ServerProtocolUpgrader<AcceptedSocket>>,
        tunnel_sink: Arc<T>,
    ) -> Self {
        Self {
            client_protocol,
            server_protocol,
            tunnel_sink,
        }
    }
}

#[async_trait]
impl<ConnectedSocket, AcceptedSocket, T> TcpHolePunchTransportSink
    for ProtocolTcpHolePunchTransportSink<ConnectedSocket, AcceptedSocket, T>
where
    ConnectedSocket: Send + 'static,
    AcceptedSocket: Send + 'static,
    T: HolePunchTunnelSink,
{
    type ConnectedSocket = ConnectedSocket;
    type AcceptedSocket = AcceptedSocket;

    async fn add_connected_transport(
        &self,
        socket: ConnectedSocket,
        requested_url: url::Url,
        admission: TcpHolePunchAdmission,
    ) -> Result<(), TcpHolePunchTransportError> {
        let tunnel = self
            .client_protocol
            .upgrade_client(ConnectedTransport::Tcp(socket), requested_url)
            .await
            .map_err(TcpHolePunchTransportError::Upgrade)?;
        match admission {
            TcpHolePunchAdmission::Client => self.tunnel_sink.add_client_tunnel(tunnel).await,
            TcpHolePunchAdmission::Server => self.tunnel_sink.add_server_tunnel(tunnel).await,
        }
        .map_err(TcpHolePunchTransportError::Admission)
    }

    async fn add_accepted_transport(
        &self,
        socket: AcceptedSocket,
        local_url: url::Url,
    ) -> Result<(), TcpHolePunchTransportError> {
        let upgrade = self
            .server_protocol
            .upgrade_tcp(socket, local_url)
            .await
            .map_err(TcpHolePunchTransportError::Upgrade)?;
        let ServerProtocolUpgrade::Tunnel(tunnel) = upgrade else {
            return Err(TcpHolePunchTransportError::Upgrade(anyhow::anyhow!(
                "TCP hole-punch protocol returned a tunnel acceptor"
            )));
        };
        self.tunnel_sink
            .add_server_tunnel(tunnel)
            .await
            .map_err(TcpHolePunchTransportError::Admission)
    }
}

type ConnectedTcpSocket<H> = <H as VirtualTcpSocketFactory>::Socket;
type AcceptedTcpSocket<H> =
    <<H as VirtualTcpListenerFactory>::Listener as VirtualTcpListener>::Socket;

pub(super) type TcpHolePunchTransportSinkFor<H> = dyn TcpHolePunchTransportSink<
        ConnectedSocket = ConnectedTcpSocket<H>,
        AcceptedSocket = AcceptedTcpSocket<H>,
    >;

fn bind_addr_for_port(port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }
}

pub async fn select_local_port<H>(
    host: &H,
    context: SocketContext,
    is_v6: bool,
) -> anyhow::Result<u16>
where
    H: VirtualTcpListenerFactory,
{
    let bind_addr = bind_addr_for_port(0, is_v6);
    tracing::trace!(?bind_addr, is_v6, "tcp hole punch select local port");
    let context = context.with_ip_version(if is_v6 { IpVersion::V6 } else { IpVersion::V4 });
    let listener = host
        .bind_tcp(
            TcpListenOptions::hole_punch(bind_addr).with_bind(
                TcpBindOptions::default()
                    .with_context(context)
                    .with_local_addr(Some(bind_addr)),
            ),
        )
        .await?;
    let port = listener.local_addr()?.port();
    tracing::debug!(?bind_addr, port, "tcp hole punch selected local port");
    Ok(port)
}

// TCP supports simultaneous connect, so both peers may dial from the mapped port.
pub async fn try_connect_to_remote<H, AcceptedSocket>(
    host: Arc<H>,
    transport_sink: Arc<
        dyn TcpHolePunchTransportSink<
                ConnectedSocket = <H as VirtualTcpSocketFactory>::Socket,
                AcceptedSocket = AcceptedSocket,
            >,
    >,
    remote_mapped_addr: SocketAddr,
    local_port: u16,
    context: SocketContext,
    admission: TcpHolePunchAdmission,
    max_attempts: u32,
) -> anyhow::Result<()>
where
    H: VirtualTcpSocketFactory,
    AcceptedSocket: 'static,
{
    tracing::info!(
        ?remote_mapped_addr,
        local_port,
        "tcp hole punch server start connect loop"
    );

    let bind_addr = bind_addr_for_port(local_port, remote_mapped_addr.is_ipv6());
    let context = context.with_ip_version(if remote_mapped_addr.is_ipv6() {
        IpVersion::V6
    } else {
        IpVersion::V4
    });
    let requested_url: url::Url = format!("tcp://{remote_mapped_addr}").parse().unwrap();

    let start = crate::foundation::time::Instant::now();
    let mut attempts = 0_u32;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let bind = TcpBindOptions::default()
            .with_context(context.clone())
            .with_local_addr(Some(bind_addr))
            .with_only_v6(true);
        let options =
            TcpConnectOptions::hole_punch(remote_mapped_addr, Some(bind_addr)).with_bind(bind);
        if let Ok(Ok(socket)) =
            crate::foundation::time::timeout(Duration::from_secs(3), host.connect_tcp(options))
                .await
        {
            let admission_result = transport_sink
                .add_connected_transport(socket, requested_url.clone(), admission)
                .await;
            match admission_result {
                Ok(()) => {}
                Err(TcpHolePunchTransportError::Upgrade(error)) => return Err(error),
                Err(TcpHolePunchTransportError::Admission(error)) => {
                    tracing::error!(
                        ?remote_mapped_addr,
                        local_port,
                        attempts,
                        ?error,
                        "tcp hole punch server connected and added client tunnel failed"
                    );
                    continue;
                }
            }

            tracing::info!(
                ?remote_mapped_addr,
                local_port,
                attempts,
                ?admission,
                "tcp hole punch server connected and added tunnel"
            );
            return Ok(());
        }
        tracing::trace!(
            ?remote_mapped_addr,
            local_port,
            attempts,
            "tcp hole punch server connect attempt failed"
        );
        let sleep_ms = rand::thread_rng().gen_range(10..100);
        crate::foundation::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    tracing::warn!(
        ?remote_mapped_addr,
        local_port,
        attempts,
        "tcp hole punch server connect loop timeout"
    );

    Err(anyhow::anyhow!(
        "tcp hole punch server connect loop timeout"
    ))
}

pub async fn accept_connections<L, ConnectedSocket>(
    listener: Arc<L>,
    transport_sink: Arc<
        dyn TcpHolePunchTransportSink<ConnectedSocket = ConnectedSocket, AcceptedSocket = L::Socket>,
    >,
    dst_peer_id: PeerId,
) -> anyhow::Result<()>
where
    L: VirtualTcpListener,
    ConnectedSocket: 'static,
{
    loop {
        match listener.accept().await {
            Ok((socket, _)) => {
                let local_url = format!("tcp://0.0.0.0:{}", listener.local_addr()?.port())
                    .parse()
                    .unwrap();
                if let Err(error) = transport_sink
                    .add_accepted_transport(socket, local_url)
                    .await
                {
                    tracing::error!(?error, "tcp hole punch transport admission error");
                    continue;
                }

                tracing::info!(
                    dst_peer_id,
                    "tcp hole punch initiator accepted and added server tunnel"
                );
            }
            Err(error) => {
                tracing::error!(?error, "tcp hole punch accept error");
            }
        }
    }
}

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
        reaper.replace(AbortOnDropHandle::new(tokio::spawn(
            reap_joinset_background(self.tasks.clone(), "tcp hole punch"),
        )));
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

struct TcpHolePunchConnectorData<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource,
{
    host: Arc<H>,
    stun: Arc<dyn StunInfoProvider>,
    socket_context: SocketContext,
    peer_source: Arc<P>,
    transport_sink: Arc<TcpHolePunchTransportSinkFor<H>>,
    blacklist: TcpHolePunchBlacklist,
}

impl<H, P> TcpHolePunchConnectorData<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource,
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

        let rpc_stub = self.peer_source.rpc_stub(dst_peer_id);
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
        let policy = self.peer_source.p2p_policy_flags();
        let local_peer_id = self.peer_source.local_peer_id();
        let mut peers_to_connect = Vec::new();
        for candidate in self.peer_source.candidates().await {
            let static_allowed = should_background_p2p_with_peer(
                candidate.feature_flag.as_ref(),
                false,
                policy.lazy_p2p,
                policy.disable_p2p,
                policy.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                candidate.feature_flag.as_ref(),
                false,
                policy.disable_p2p,
                policy.need_p2p,
            ) && candidate.has_recent_traffic;
            if !static_allowed && !dynamic_allowed {
                continue;
            }

            let peer_id = candidate.peer_id;
            if peer_id == local_peer_id {
                tracing::trace!(peer_id, "tcp hole punch task collect skip self");
                continue;
            }
            if self.blacklist.contains(peer_id) {
                tracing::debug!(peer_id, "tcp hole punch task collect skip blacklisted");
                continue;
            }
            if candidate.has_direct_connection {
                tracing::trace!(peer_id, "tcp hole punch task collect skip already has peer");
                continue;
            }

            let peer_nat_type = candidate.tcp_nat_type;
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

struct TcpHolePunchPeerTaskLauncher<H, P>(Arc<TcpHolePunchConnectorData<H, P>>)
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource;

impl<H, P> Clone for TcpHolePunchPeerTaskLauncher<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl<H, P> PeerTaskLauncher for TcpHolePunchPeerTaskLauncher<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource,
{
    type PeerManager = P;
    type Data = Arc<TcpHolePunchConnectorData<H, P>>;
    type CollectPeerItem = PeerId;
    type TaskRet = ();

    fn new_data(&self, _peer_manager: Arc<P>) -> Self::Data {
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

pub struct TcpHolePunchConnector<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource + HolePunchTunnelSink + HolePunchRpcRegistry,
{
    server: Arc<TcpHolePunchServer<H>>,
    client: PeerTaskManager<TcpHolePunchPeerTaskLauncher<H, P>>,
    peer_source: Arc<P>,
}

impl<H, P> TcpHolePunchConnector<H, P>
where
    H: TcpHolePunchHost,
    P: TcpHolePunchPeerSource + HolePunchTunnelSink + HolePunchRpcRegistry,
{
    pub fn new(
        peer_source: Arc<P>,
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
                peer_source.clone(),
            ));
        let data = Arc::new(TcpHolePunchConnectorData {
            host: host.clone(),
            stun: stun.clone(),
            socket_context: socket_context.clone(),
            peer_source: peer_source.clone(),
            transport_sink: transport_sink.clone(),
            blacklist: TcpHolePunchBlacklist::new(),
        });
        Self {
            server: TcpHolePunchServer::new(host, stun, socket_context, transport_sink),
            client: PeerTaskManager::new_with_external_signal(
                TcpHolePunchPeerTaskLauncher(data.clone()),
                peer_source.clone(),
                Some(peer_source.p2p_demand_notify()),
            ),
            peer_source,
        }
    }

    pub fn run(&self) {
        if self.peer_source.tcp_hole_punching_disabled() {
            tracing::debug!("tcp hole punch disabled by runtime configuration");
            return;
        }
        self.server.start();
        self.peer_source
            .register_rpc_service(TcpHolePunchRpcServer::new_arc(self.server.clone()));
        self.client.start();
    }

    pub async fn stop(&self) {
        self.client.stop().await;
        self.server.begin_stop();
        self.peer_source
            .unregister_rpc_service(TcpHolePunchRpcServer::new_arc(self.server.clone()));
        self.server.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use super::*;
    use crate::tunnel::Tunnel;

    #[derive(Default)]
    struct MockProtocols {
        client_upgrades: AtomicUsize,
        server_upgrades: AtomicUsize,
        fail_client_upgrade: AtomicBool,
    }

    #[async_trait]
    impl ClientProtocolUpgrader<()> for MockProtocols {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "tcp"
        }

        async fn upgrade_client(
            &self,
            connected: ConnectedTransport<()>,
            _requested_url: url::Url,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            let ConnectedTransport::Tcp(()) = connected else {
                anyhow::bail!("expected TCP transport");
            };
            if self.fail_client_upgrade.load(Ordering::Relaxed) {
                anyhow::bail!("mock client upgrade failure");
            }
            self.client_upgrades.fetch_add(1, Ordering::Relaxed);
            Ok(crate::tunnel::ring::create_ring_tunnel_pair().0)
        }
    }

    #[async_trait]
    impl ServerProtocolUpgrader<()> for MockProtocols {
        fn supports_scheme(&self, scheme: &str) -> bool {
            scheme == "tcp"
        }

        async fn upgrade_tcp(
            &self,
            _socket: (),
            _local_url: url::Url,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            self.server_upgrades.fetch_add(1, Ordering::Relaxed);
            Ok(ServerProtocolUpgrade::Tunnel(
                crate::tunnel::ring::create_ring_tunnel_pair().0,
            ))
        }

        async fn upgrade_udp(
            &self,
            _session: crate::socket::udp::UdpSession,
            _local_url: url::Url,
            _admission: Option<crate::connectivity::protocol::ServerProtocolAdmission>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("unexpected UDP transport")
        }

        async fn upgrade_byte_stream(
            &self,
            _socket: (),
            _local_url: url::Url,
            _remote_url: Option<url::Url>,
        ) -> anyhow::Result<ServerProtocolUpgrade> {
            anyhow::bail!("unexpected byte stream")
        }
    }

    #[derive(Default)]
    struct MockTunnelSink {
        clients: AtomicUsize,
        servers: AtomicUsize,
        fail_client_admission: AtomicBool,
    }

    #[async_trait]
    impl HolePunchTunnelSink for MockTunnelSink {
        async fn add_client_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            if self.fail_client_admission.load(Ordering::Relaxed) {
                anyhow::bail!("mock client admission failure");
            }
            self.clients.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        async fn add_server_tunnel(&self, _tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
            self.servers.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[tokio::test]
    async fn protocol_sink_upgrades_before_tcp_hole_punch_admission() {
        let protocols = Arc::new(MockProtocols::default());
        let tunnel_sink = Arc::new(MockTunnelSink::default());
        let sink = ProtocolTcpHolePunchTransportSink::new(
            protocols.clone(),
            protocols.clone(),
            tunnel_sink.clone(),
        );
        let url = url::Url::parse("tcp://198.51.100.1:11010").unwrap();

        sink.add_connected_transport((), url.clone(), TcpHolePunchAdmission::Client)
            .await
            .unwrap();
        sink.add_connected_transport((), url.clone(), TcpHolePunchAdmission::Server)
            .await
            .unwrap();
        sink.add_accepted_transport((), url).await.unwrap();

        assert_eq!(protocols.client_upgrades.load(Ordering::Relaxed), 2);
        assert_eq!(protocols.server_upgrades.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_sink.clients.load(Ordering::Relaxed), 1);
        assert_eq!(tunnel_sink.servers.load(Ordering::Relaxed), 2);

        protocols.fail_client_upgrade.store(true, Ordering::Relaxed);
        assert!(matches!(
            sink.add_connected_transport(
                (),
                url::Url::parse("tcp://198.51.100.1:11010").unwrap(),
                TcpHolePunchAdmission::Client,
            )
            .await,
            Err(TcpHolePunchTransportError::Upgrade(_))
        ));
        protocols
            .fail_client_upgrade
            .store(false, Ordering::Relaxed);
        tunnel_sink
            .fail_client_admission
            .store(true, Ordering::Relaxed);
        assert!(matches!(
            sink.add_connected_transport(
                (),
                url::Url::parse("tcp://198.51.100.1:11010").unwrap(),
                TcpHolePunchAdmission::Client,
            )
            .await,
            Err(TcpHolePunchTransportError::Admission(_))
        ));
    }

    #[test]
    fn bind_address_tracks_requested_family_and_port() {
        assert_eq!(
            bind_addr_for_port(1234, false),
            "0.0.0.0:1234".parse().unwrap()
        );
        assert_eq!(bind_addr_for_port(4321, true), "[::]:4321".parse().unwrap());
    }

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

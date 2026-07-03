use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Error};
use quanta::Instant;
use rand::Rng as _;
use tokio::task::JoinSet;

use crate::{
    common::{
        PeerId, global_ctx::ArcGlobalCtx, join_joinset_background, stun::StunInfoCollectorTrait,
    },
    connector::udp_hole_punch::BackOff,
    peers::{
        peer_manager::PeerManager,
        peer_task::{PeerTaskLauncher, PeerTaskManager},
    },
    proto::{
        common::NatType,
        peer_rpc::{
            TcpHolePunchRequest, TcpHolePunchResponse, TcpHolePunchRpc,
            TcpHolePunchRpcClientFactory, TcpHolePunchRpcServer,
        },
        rpc_types::{self, controller::BaseController},
    },
    tunnel::{Tunnel, TunnelConnector as _, tcp::get_tunnel_with_tcp_stream},
};

use crate::tunnel::common::bind;
use tokio::net::{TcpSocket, TcpStream};

#[cfg(feature = "websocket")]
use crate::tunnel::websocket::WsTunnelConnector;

use crate::connector::{should_background_p2p_with_peer, should_try_p2p_with_peer};

pub const BLACKLIST_TIMEOUT_SEC: u64 = 3600;

fn handle_rpc_result<T>(
    ret: Result<T, rpc_types::error::Error>,
    dst_peer_id: PeerId,
    blacklist: &timedmap::TimedMap<PeerId, ()>,
) -> Result<T, rpc_types::error::Error> {
    match ret {
        Ok(ret) => Ok(ret),
        Err(e) => {
            if matches!(e, rpc_types::error::Error::InvalidServiceKey(_, _)) {
                blacklist.insert(dst_peer_id, (), Duration::from_secs(BLACKLIST_TIMEOUT_SEC));
            }
            Err(e)
        }
    }
}

fn is_symmetric_tcp_nat(nat_type: NatType) -> bool {
    matches!(
        nat_type,
        NatType::Symmetric | NatType::SymmetricEasyInc | NatType::SymmetricEasyDec
    )
}

fn bind_addr_for_port(port: u16, is_v6: bool) -> SocketAddr {
    if is_v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }
}

async fn select_local_port(peer_mgr: &Arc<PeerManager>, is_v6: bool) -> Result<u16, Error> {
    let bind_addr = bind_addr_for_port(0, is_v6);
    tracing::trace!(?bind_addr, is_v6, "tcp hole punch select local port");
    let _g = peer_mgr.get_global_ctx().net_ns.guard();
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let port = listener.local_addr()?.port();
    tracing::debug!(?bind_addr, port, "tcp hole punch selected local port");
    Ok(port)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TcpHolePunchTunnel {
    Tcp,
    Ws,
    Wss,
}

impl TcpHolePunchTunnel {
    fn scheme(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Ws => "ws",
            Self::Wss => "wss",
        }
    }

    fn from_scheme(scheme: &str) -> Result<Self, Error> {
        match scheme {
            "" | "tcp" => Ok(Self::Tcp),
            "ws" => Ok(Self::Ws),
            "wss" => Ok(Self::Wss),
            _ => Err(anyhow::anyhow!(
                "unsupported tcp hole punch tunnel scheme: {}",
                scheme
            )),
        }
    }

    fn is_websocket(self) -> bool {
        matches!(self, Self::Ws | Self::Wss)
    }
}

fn listener_has_scheme(peer_mgr: &Arc<PeerManager>, scheme: &str) -> bool {
    peer_mgr
        .get_global_ctx()
        .config
        .get_listener_uris()
        .iter()
        .any(|listener| listener.scheme() == scheme)
}

fn select_tcp_hole_punch_transport(peer_mgr: &Arc<PeerManager>) -> TcpHolePunchTunnel {
    let global_ctx = peer_mgr.get_global_ctx();
    match global_ctx.get_flags().default_protocol.as_str() {
        "ws" => TcpHolePunchTunnel::Ws,
        "wss" => TcpHolePunchTunnel::Wss,
        _ if listener_has_scheme(peer_mgr, "tcp") => TcpHolePunchTunnel::Tcp,
        _ if listener_has_scheme(peer_mgr, "wss") => TcpHolePunchTunnel::Wss,
        _ if listener_has_scheme(peer_mgr, "ws") => TcpHolePunchTunnel::Ws,
        _ => TcpHolePunchTunnel::Tcp,
    }
}

fn tcp_hole_punch_transport_enabled(
    peer_mgr: &Arc<PeerManager>,
    tunnel: TcpHolePunchTunnel,
) -> bool {
    match tunnel {
        TcpHolePunchTunnel::Tcp => true,
        TcpHolePunchTunnel::Ws | TcpHolePunchTunnel::Wss => {
            #[cfg(feature = "websocket")]
            {
                let default_protocol = peer_mgr.get_global_ctx().get_flags().default_protocol;
                default_protocol == tunnel.scheme()
                    || listener_has_scheme(peer_mgr, tunnel.scheme())
            }

            #[cfg(not(feature = "websocket"))]
            {
                false
            }
        }
    }
}

async fn build_punched_tcp_tunnel(
    stream: TcpStream,
    tunnel: TcpHolePunchTunnel,
    is_server: bool,
    remote_addr: SocketAddr,
) -> Result<Box<dyn Tunnel>, Error> {
    match tunnel {
        TcpHolePunchTunnel::Tcp => {
            let _ = is_server;
            let remote_url =
                crate::tunnel::build_url_from_socket_addr(&remote_addr.to_string(), "tcp");
            get_tunnel_with_tcp_stream(stream, remote_url).map_err(Into::into)
        }
        TcpHolePunchTunnel::Ws | TcpHolePunchTunnel::Wss => {
            let _ = (stream, is_server, remote_addr);
            Err(anyhow::anyhow!(
                "{} hole punch should use mapped websocket listener",
                tunnel.scheme()
            ))
        }
    }
}

fn set_linger_reset(stream: &TcpStream) {
    if let Err(error) = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO)) {
        tracing::trace!(?error, "failed to set tcp pre-punch linger");
    }
}

fn mapped_listener_url(tunnel: TcpHolePunchTunnel, mapped_addr: SocketAddr) -> url::Url {
    crate::tunnel::build_url_from_socket_addr(&mapped_addr.to_string(), tunnel.scheme())
}

fn running_listener_for_tunnel(
    peer_mgr: &Arc<PeerManager>,
    tunnel: TcpHolePunchTunnel,
    is_v6: bool,
) -> Option<url::Url> {
    peer_mgr
        .get_global_ctx()
        .get_running_listeners()
        .into_iter()
        .filter(|listener| listener.scheme() == tunnel.scheme())
        .filter(|listener| listener.port().is_some())
        .find(|listener| {
            let Some(host) = listener.host() else {
                return false;
            };
            match host {
                url::Host::Ipv4(_) => !is_v6,
                url::Host::Ipv6(_) => is_v6,
                url::Host::Domain(_) => true,
            }
        })
}

fn running_listener_port_for_tunnel(
    peer_mgr: &Arc<PeerManager>,
    tunnel: TcpHolePunchTunnel,
    is_v6: bool,
) -> Result<u16, Error> {
    running_listener_for_tunnel(peer_mgr, tunnel, is_v6)
        .and_then(|listener| listener.port())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} tcp pre-punch requires an already-running ws/wss listener",
                tunnel.scheme()
            )
        })
}

fn advertise_dynamic_mapped_listener(global_ctx: ArcGlobalCtx, url: url::Url, ttl: Duration) {
    global_ctx.add_dynamic_mapped_listener(url.clone());
    tokio::spawn(async move {
        tokio::time::sleep(ttl).await;
        global_ctx.remove_dynamic_mapped_listener(&url);
    });
}

async fn pre_punch_tcp_mapping(
    peer_mgr: Arc<PeerManager>,
    remote_mapped_addr: SocketAddr,
    local_port: u16,
    tunnel: TcpHolePunchTunnel,
    max_attempts: u32,
) -> Result<(), Error> {
    let tunnel_scheme = tunnel.scheme();
    tracing::info!(
        ?remote_mapped_addr,
        local_port,
        tunnel = tunnel_scheme,
        "tcp pre-punch start connect loop"
    );

    let start = tokio::time::Instant::now();
    let mut attempts: u32 = 0;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let _g = peer_mgr.get_global_ctx().net_ns.guard();

        let bind_addr = bind_addr_for_port(local_port, remote_mapped_addr.is_ipv6());
        let socket = match bind::<TcpSocket>()
            .addr(bind_addr)
            .only_v6(remote_mapped_addr.is_ipv6())
            .maybe_socket_mark(peer_mgr.get_global_ctx().config.get_flags().socket_mark)
            .reuse_address(true)
            .reuse_port(true)
            .call()
        {
            Ok(socket) => socket,
            Err(error) => {
                tracing::trace!(
                    ?error,
                    ?bind_addr,
                    attempts,
                    tunnel = tunnel_scheme,
                    "tcp pre-punch bind failed"
                );
                continue;
            }
        };

        if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(3), socket.connect(remote_mapped_addr)).await
        {
            set_linger_reset(&stream);
            tracing::info!(
                ?remote_mapped_addr,
                local_port,
                attempts,
                tunnel = tunnel_scheme,
                "tcp pre-punch connected"
            );
            return Ok(());
        }

        tracing::trace!(
            ?remote_mapped_addr,
            local_port,
            attempts,
            tunnel = tunnel_scheme,
            "tcp pre-punch connect attempt failed"
        );
        let sleep_ms = rand::thread_rng().gen_range(10..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    Err(anyhow::anyhow!("tcp pre-punch connect loop timeout"))
}

#[cfg(feature = "websocket")]
async fn connect_websocket_mapped_listener(
    peer_mgr: Arc<PeerManager>,
    dst_peer_id: PeerId,
    local_port: u16,
    remote_mapped_addr: SocketAddr,
    tunnel: TcpHolePunchTunnel,
) -> Result<(), Error> {
    let remote_url = mapped_listener_url(tunnel, remote_mapped_addr);
    let start = tokio::time::Instant::now();
    let mut attempts: u32 = 0;

    while start.elapsed() < Duration::from_secs(10) {
        attempts = attempts.wrapping_add(1);
        let result = {
            let _g = peer_mgr.get_global_ctx().net_ns.guard();
            let mut connector = WsTunnelConnector::new(remote_url.clone());
            connector.set_resolved_addr(remote_mapped_addr);
            connector.set_bind_addrs(vec![bind_addr_for_port(
                local_port,
                remote_mapped_addr.is_ipv6(),
            )]);
            connector.set_reuse_bind_port(true);
            connector.set_socket_mark(peer_mgr.get_global_ctx().config.get_flags().socket_mark);
            tokio::time::timeout(Duration::from_secs(3), connector.connect()).await
        };

        match result {
            Ok(Ok(tunnel)) => {
                match peer_mgr
                    .add_client_tunnel(tunnel, true)
                    .await
                    .map(|_| ())
                    .with_context(|| "add dynamic websocket mapped tunnel")
                {
                    Ok(()) => {
                        tracing::info!(
                            dst_peer_id,
                            attempts,
                            local_port,
                            remote_url = %remote_url,
                            "connected dynamic websocket mapped listener"
                        );
                        return Ok(());
                    }
                    Err(error) => {
                        tracing::trace!(
                            ?error,
                            attempts,
                            local_port,
                            remote_url = %remote_url,
                            "dynamic websocket mapped listener add tunnel failed"
                        );
                    }
                }
            }
            Ok(Err(error)) => {
                tracing::trace!(
                    ?error,
                    attempts,
                    local_port,
                    remote_url = %remote_url,
                    "dynamic websocket mapped listener connect failed"
                );
            }
            Err(_) => {
                tracing::trace!(
                    attempts,
                    local_port,
                    remote_url = %remote_url,
                    "dynamic websocket mapped listener connect timeout"
                );
            }
        }

        let sleep_ms = rand::thread_rng().gen_range(10..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    Err(anyhow::anyhow!(
        "dynamic websocket mapped listener connect timeout: {}",
        remote_url
    ))
}

async fn try_connect_to_remote(
    peer_mgr: Arc<PeerManager>,
    a_mapped_addr: SocketAddr,
    local_port: u16,
    tunnel: TcpHolePunchTunnel,
    is_client: bool,
    max_attempts: u32,
) -> Result<(), Error> {
    let tunnel_scheme = tunnel.scheme();
    tracing::info!(
        ?a_mapped_addr,
        local_port,
        tunnel = tunnel_scheme,
        "tcp hole punch start connect loop"
    );

    let is_server = !is_client; // 发起方=server role，响应方=client role
    let bind_addr = bind_addr_for_port(local_port, a_mapped_addr.is_ipv6());

    let start = tokio::time::Instant::now();
    let mut attempts: u32 = 0;
    while start.elapsed() < Duration::from_secs(10) && attempts < max_attempts {
        attempts = attempts.wrapping_add(1);
        let _g = peer_mgr.get_global_ctx().net_ns.guard();

        let socket = match bind::<TcpSocket>()
            .addr(bind_addr)
            .only_v6(a_mapped_addr.is_ipv6())
            .call()
        {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(?e, ?bind_addr, "tcp hole punch bind failed");
                continue;
            }
        };

        if let Ok(Ok(stream)) =
            tokio::time::timeout(Duration::from_secs(3), socket.connect(a_mapped_addr)).await
        {
            let tunnel =
                match build_punched_tcp_tunnel(stream, tunnel, is_server, a_mapped_addr).await {
                    Ok(tunnel) => tunnel,
                    Err(e) => {
                        tracing::error!(
                            ?a_mapped_addr,
                            local_port,
                            attempts,
                            tunnel = tunnel_scheme,
                            ?e,
                            "tcp hole punch connected but tunnel upgrade failed"
                        );
                        continue;
                    }
                };

            let add_tunnel_ret = if is_client {
                peer_mgr.add_client_tunnel(tunnel, false).await.map(|_| ())
            } else {
                peer_mgr.add_tunnel_as_server(tunnel, false).await
            };
            if let Err(e) = add_tunnel_ret {
                tracing::error!(
                    ?a_mapped_addr,
                    local_port,
                    attempts,
                    tunnel = tunnel_scheme,
                    ?e,
                    "tcp hole punch connected and add tunnel failed"
                );
                continue;
            }

            tracing::info!(
                ?a_mapped_addr,
                local_port,
                attempts,
                is_client,
                tunnel = tunnel_scheme,
                "tcp hole punch connected and added tunnel"
            );
            return Ok(());
        }

        tracing::trace!(
            ?a_mapped_addr,
            local_port,
            attempts,
            tunnel = tunnel_scheme,
            "tcp hole punch connect attempt failed"
        );
        let sleep_ms = rand::thread_rng().gen_range(10..100);
        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
    }

    Err(anyhow::anyhow!("tcp hole punch connect loop timeout"))
}

struct TcpHolePunchServer {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl TcpHolePunchServer {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "tcp hole punch server".to_string());
        Arc::new(Self { peer_mgr, tasks })
    }
}

#[async_trait::async_trait]
impl TcpHolePunchRpc for TcpHolePunchServer {
    type Controller = BaseController;

    #[tracing::instrument(skip(self), fields(a_mapped_addr = ?input.connector_mapped_addr), err)]
    async fn exchange_mapped_addr(
        &self,
        _ctrl: Self::Controller,
        input: TcpHolePunchRequest,
    ) -> rpc_types::error::Result<TcpHolePunchResponse> {
        let my_tcp_nat_type = NatType::try_from(
            self.peer_mgr
                .get_global_ctx()
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        tracing::debug!(?my_tcp_nat_type, "tcp hole punch rpc received");
        if matches!(my_tcp_nat_type, NatType::Unknown) {
            tracing::warn!(?my_tcp_nat_type, "tcp hole punch rpc rejected (unknown)");
            return Err(anyhow::anyhow!("tcp nat type unknown not supported").into());
        }

        let a_mapped_addr = input
            .connector_mapped_addr
            .ok_or(anyhow::anyhow!("connector_mapped_addr is required"))?;
        let a_mapped_addr: SocketAddr = a_mapped_addr.into();
        let a_ip = a_mapped_addr.ip();
        if a_ip.is_unspecified() || a_ip.is_multicast() {
            tracing::warn!(?a_mapped_addr, "tcp hole punch rpc invalid connector addr");
            return Err(anyhow::anyhow!("connector_mapped_addr is malformed").into());
        }

        let is_legacy_request = input.tunnel_scheme.is_empty();
        let tunnel = if is_legacy_request {
            select_tcp_hole_punch_transport(&self.peer_mgr)
        } else {
            TcpHolePunchTunnel::from_scheme(&input.tunnel_scheme)?
        };
        if !tcp_hole_punch_transport_enabled(&self.peer_mgr, tunnel) {
            tracing::warn!(
                ?tunnel,
                tunnel_scheme = input.tunnel_scheme,
                "tcp hole punch rpc rejected (tunnel scheme not enabled)"
            );
            return Err(anyhow::anyhow!(
                "tcp hole punch tunnel scheme not enabled: {}",
                input.tunnel_scheme
            )
            .into());
        }

        let is_v6 = a_mapped_addr.is_ipv6();
        let local_port = match tunnel {
            TcpHolePunchTunnel::Tcp => select_local_port(&self.peer_mgr, is_v6).await?,
            TcpHolePunchTunnel::Ws | TcpHolePunchTunnel::Wss => {
                running_listener_port_for_tunnel(&self.peer_mgr, tunnel, is_v6)?
            }
        };
        let mapped_addr = self
            .peer_mgr
            .get_global_ctx()
            .get_stun_info_collector()
            .get_tcp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get tcp port mapping")?;

        tracing::info!(
            ?a_mapped_addr,
            local_port,
            ?mapped_addr,
            tunnel = tunnel.scheme(),
            is_legacy_request,
            "tcp hole punch rpc responding with listener mapped addr and start connecting"
        );

        let peer_mgr = self.peer_mgr.clone();
        self.tasks.lock().unwrap().spawn(async move {
            match tunnel {
                TcpHolePunchTunnel::Tcp => {
                    let _ =
                        try_connect_to_remote(peer_mgr, a_mapped_addr, local_port, tunnel, true, 5)
                            .await;
                }
                TcpHolePunchTunnel::Ws | TcpHolePunchTunnel::Wss => {
                    #[cfg(feature = "websocket")]
                    {
                        if let Err(error) = pre_punch_tcp_mapping(
                            peer_mgr.clone(),
                            a_mapped_addr,
                            local_port,
                            tunnel,
                            5,
                        )
                        .await
                        {
                            tracing::warn!(
                                ?error,
                                local_port,
                                tunnel = tunnel.scheme(),
                                "tcp pre-punch failed, still advertise existing websocket listener mapped address"
                            );
                        }

                        let mapped_url = mapped_listener_url(tunnel, mapped_addr);
                        advertise_dynamic_mapped_listener(
                            peer_mgr.get_global_ctx(),
                            mapped_url.clone(),
                            Duration::from_secs(60),
                        );
                        tracing::info!(
                            local_port,
                            mapped_url = %mapped_url,
                            tunnel = tunnel.scheme(),
                            "advertised existing websocket listener mapped address after tcp pre-punch"
                        );
                    }

                    #[cfg(not(feature = "websocket"))]
                    {
                        let _ = (peer_mgr, a_mapped_addr, local_port, mapped_addr);
                        tracing::warn!("websocket feature required for dynamic ws/wss listener");
                    }
                }
            }
        });

        Ok(TcpHolePunchResponse {
            listener_mapped_addr: Some(mapped_addr.into()),
            tunnel_scheme: tunnel.scheme().to_string(),
        })
    }
}

struct TcpHolePunchConnectorData {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
}

impl TcpHolePunchConnectorData {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self {
            peer_mgr,
            blacklist: Arc::new(timedmap::TimedMap::new()),
        })
    }

    async fn punch_as_initiator(self: Arc<Self>, dst_peer_id: PeerId) -> Result<(), Error> {
        let mut backoff = BackOff::new(vec![1000, 1000, 4000, 8000]);

        loop {
            backoff.sleep_for_next_backoff().await;
            if self.do_punch_as_initiator(dst_peer_id).await.is_ok() {
                break;
            }

            if self.blacklist.contains(&dst_peer_id) {
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
    async fn do_punch_as_initiator(&self, dst_peer_id: PeerId) -> Result<(), Error> {
        let global_ctx = self.peer_mgr.get_global_ctx();
        let my_tcp_nat_type = NatType::try_from(
            global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        tracing::debug!(?my_tcp_nat_type, "tcp hole punch initiator start");
        if is_symmetric_tcp_nat(my_tcp_nat_type) || my_tcp_nat_type == NatType::Unknown {
            tracing::debug!("tcp hole punch initiator skipped (symmetric)");
            return Ok(());
        }

        let tunnel = select_tcp_hole_punch_transport(&self.peer_mgr);
        let local_port = match tunnel {
            TcpHolePunchTunnel::Tcp => select_local_port(&self.peer_mgr, false).await?,
            TcpHolePunchTunnel::Ws | TcpHolePunchTunnel::Wss => {
                running_listener_port_for_tunnel(&self.peer_mgr, tunnel, false)?
            }
        };
        let mapped_addr = global_ctx
            .get_stun_info_collector()
            .get_tcp_port_mapping(local_port)
            .await
            .with_context(|| "failed to get tcp port mapping")?;

        tracing::info!(
            dst_peer_id,
            local_port,
            ?mapped_addr,
            tunnel = tunnel.scheme(),
            "tcp hole punch initiator got mapped addr, start rpc exchange"
        );

        let rpc_stub = self
            .peer_mgr
            .get_peer_rpc_mgr()
            .rpc_client()
            .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
                self.peer_mgr.my_peer_id(),
                dst_peer_id,
                global_ctx.get_network_name(),
            );

        let resp = rpc_stub
            .exchange_mapped_addr(
                BaseController {
                    timeout_ms: 6000,
                    ..Default::default()
                },
                TcpHolePunchRequest {
                    connector_mapped_addr: Some(mapped_addr.into()),
                    tunnel_scheme: tunnel.scheme().to_string(),
                },
            )
            .await;
        let resp = handle_rpc_result(resp, dst_peer_id, &self.blacklist)?;
        let remote_tunnel = if resp.tunnel_scheme.is_empty() {
            TcpHolePunchTunnel::Tcp
        } else {
            TcpHolePunchTunnel::from_scheme(&resp.tunnel_scheme)?
        };
        let remote_mapped_addr = resp
            .listener_mapped_addr
            .ok_or(anyhow::anyhow!("listener_mapped_addr is required"))?;
        let remote_mapped_addr: SocketAddr = remote_mapped_addr.into();
        tracing::info!(
            dst_peer_id,
            ?remote_mapped_addr,
            remote_tunnel = remote_tunnel.scheme(),
            "tcp hole punch initiator rpc returned"
        );

        if tunnel.is_websocket() {
            #[cfg(feature = "websocket")]
            {
                if let Err(error) = pre_punch_tcp_mapping(
                    self.peer_mgr.clone(),
                    remote_mapped_addr,
                    local_port,
                    tunnel,
                    5,
                )
                .await
                {
                    tracing::warn!(
                        ?error,
                        local_port,
                        tunnel = tunnel.scheme(),
                        "tcp pre-punch failed, still connect websocket mapped listener"
                    );
                }
                let mapped_url = mapped_listener_url(tunnel, mapped_addr);
                advertise_dynamic_mapped_listener(
                    global_ctx.clone(),
                    mapped_url.clone(),
                    Duration::from_secs(60),
                );
                tracing::info!(
                    local_port,
                    mapped_url = %mapped_url,
                    tunnel = tunnel.scheme(),
                    "advertised local websocket listener mapped address after tcp pre-punch"
                );
                if remote_tunnel != tunnel {
                    tracing::info!(
                        dst_peer_id,
                        local_port,
                        remote_tunnel = remote_tunnel.scheme(),
                        local_tunnel = tunnel.scheme(),
                        "remote tcp hole punch peer does not expose a websocket mapped listener; waiting for direct connector to use our advertised listener"
                    );
                    return Ok(());
                }

                connect_websocket_mapped_listener(
                    self.peer_mgr.clone(),
                    dst_peer_id,
                    local_port,
                    remote_mapped_addr,
                    tunnel,
                )
                .await?;
                return Ok(());
            }

            #[cfg(not(feature = "websocket"))]
            {
                return Err(anyhow::anyhow!("websocket feature required").into());
            }
        }

        if let Ok(()) = try_connect_to_remote(
            self.peer_mgr.clone(),
            remote_mapped_addr,
            local_port,
            tunnel,
            false,
            1,
        )
        .await
        {
            tracing::info!(
                dst_peer_id,
                local_port,
                ?remote_mapped_addr,
                tunnel = tunnel.scheme(),
                "tcp hole punch initiator connected to remote mapped addr with simultaneous connection"
            );
            return Ok(());
        }

        tracing::debug!(
            dst_peer_id,
            local_port,
            ?remote_mapped_addr,
            tunnel = tunnel.scheme(),
            "tcp hole punch initiator sent syn to remote mapped addr"
        );

        let mut listener = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            bind::<tokio::net::TcpListener>()
                .addr(bind_addr_for_port(local_port, false))
                .only_v6(false)
                .call()?
        };
        tracing::info!(
            dst_peer_id,
            local_port,
            tunnel = tunnel.scheme(),
            "tcp hole punch initiator listening"
        );

        tokio::time::timeout(
            Duration::from_secs(10),
            self.accept_loop(&mut listener, dst_peer_id, tunnel),
        )
        .await??;

        tracing::info!(
            dst_peer_id,
            "tcp hole punch initiator accepted and added server tunnel"
        );

        Ok(())
    }

    async fn accept_loop(
        &self,
        listener: &mut tokio::net::TcpListener,
        dst_peer_id: PeerId,
        tunnel: TcpHolePunchTunnel,
    ) -> Result<(), Error> {
        loop {
            match listener.accept().await {
                Ok((stream, remote_addr)) => {
                    let tunnel =
                        match build_punched_tcp_tunnel(stream, tunnel, true, remote_addr).await {
                            Ok(tunnel) => tunnel,
                            Err(e) => {
                                tracing::error!(
                                    dst_peer_id,
                                    ?remote_addr,
                                    tunnel = tunnel.scheme(),
                                    ?e,
                                    "tcp hole punch accept tunnel upgrade failed"
                                );
                                continue;
                            }
                        };

                    let tunnel_type = tunnel.info().map(|info| info.tunnel_type);
                    if let Err(e) = self.peer_mgr.add_tunnel_as_server(tunnel, false).await {
                        tracing::error!("tcp hole punch add tunnel error: {}", e);
                        continue;
                    }

                    tracing::info!(
                        dst_peer_id,
                        ?tunnel_type,
                        "tcp hole punch initiator accepted and added server tunnel"
                    );
                }
                Err(e) => {
                    tracing::error!("tcp hole punch accept error: {}", e);
                }
            }
        }
    }
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
struct TcpPunchTaskInfo {
    dst_peer_id: PeerId,
}

#[derive(Clone)]
struct TcpHolePunchPeerTaskLauncher {}

#[async_trait::async_trait]
impl PeerTaskLauncher for TcpHolePunchPeerTaskLauncher {
    type Data = Arc<TcpHolePunchConnectorData>;
    type CollectPeerItem = TcpPunchTaskInfo;
    type TaskRet = ();

    fn new_data(&self, peer_mgr: Arc<PeerManager>) -> Self::Data {
        TcpHolePunchConnectorData::new(peer_mgr)
    }

    #[tracing::instrument(skip(self, data))]
    async fn collect_peers_need_task(&self, data: &Self::Data) -> Vec<Self::CollectPeerItem> {
        let global_ctx = data.peer_mgr.get_global_ctx();
        let flags = global_ctx.get_flags();
        let lazy_p2p = flags.lazy_p2p;
        let my_tcp_nat_type = NatType::try_from(
            global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        if is_symmetric_tcp_nat(my_tcp_nat_type) || my_tcp_nat_type == NatType::Unknown {
            tracing::trace!(
                ?my_tcp_nat_type,
                "tcp hole punch task collect skipped (symmetric)"
            );
            return vec![];
        }

        let my_peer_id = data.peer_mgr.my_peer_id();
        let now = Instant::now();

        data.blacklist.cleanup();

        let mut peers_to_connect = Vec::new();
        for route in data.peer_mgr.list_routes().await.iter() {
            let static_allowed = should_background_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                lazy_p2p,
                flags.disable_p2p,
                flags.need_p2p,
            );
            let dynamic_allowed = should_try_p2p_with_peer(
                route.feature_flag.as_ref(),
                false,
                flags.disable_p2p,
                flags.need_p2p,
            ) && data.peer_mgr.has_recent_traffic(route.peer_id, now);
            if !static_allowed && !dynamic_allowed {
                continue;
            }

            let peer_id: PeerId = route.peer_id;
            if peer_id == my_peer_id {
                tracing::trace!(peer_id, "tcp hole punch task collect skip self");
                continue;
            }

            if data.blacklist.contains(&peer_id) {
                tracing::debug!(peer_id, "tcp hole punch task collect skip blacklisted");
                continue;
            }

            if data.peer_mgr.get_peer_map().has_peer(peer_id) {
                tracing::trace!(peer_id, "tcp hole punch task collect skip already has peer");
                continue;
            }

            let peer_tcp_nat_type = route
                .stun_info
                .as_ref()
                .map(|x| x.tcp_nat_type)
                .unwrap_or(0);
            let peer_tcp_nat_type =
                NatType::try_from(peer_tcp_nat_type).unwrap_or(NatType::Unknown);
            if matches!(peer_tcp_nat_type, NatType::Unknown) {
                tracing::debug!(
                    peer_id,
                    ?peer_tcp_nat_type,
                    "tcp hole punch task collect skip peer unknown"
                );
                continue;
            }

            tracing::info!(
                peer_id,
                my_peer_id,
                ?my_tcp_nat_type,
                ?peer_tcp_nat_type,
                "tcp hole punch task collect add peer"
            );
            peers_to_connect.push(TcpPunchTaskInfo {
                dst_peer_id: peer_id,
            });
        }

        peers_to_connect
    }

    async fn launch_task(
        &self,
        data: &Self::Data,
        item: Self::CollectPeerItem,
    ) -> tokio::task::JoinHandle<Result<Self::TaskRet, anyhow::Error>> {
        let data = data.clone();
        tokio::spawn(async move { data.punch_as_initiator(item.dst_peer_id).await.map(|_| ()) })
    }

    async fn all_task_done(&self, _data: &Self::Data) {}

    fn loop_interval_ms(&self) -> u64 {
        5000
    }
}

pub struct TcpHolePunchConnector {
    server: Arc<TcpHolePunchServer>,
    client: PeerTaskManager<TcpHolePunchPeerTaskLauncher>,
    peer_mgr: Arc<PeerManager>,
}

impl TcpHolePunchConnector {
    pub fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self {
            server: TcpHolePunchServer::new(peer_mgr.clone()),
            client: PeerTaskManager::new_with_external_signal(
                TcpHolePunchPeerTaskLauncher {},
                peer_mgr.clone(),
                Some(peer_mgr.p2p_demand_notify()),
            ),
            peer_mgr,
        }
    }

    pub async fn run_as_client(&mut self) -> Result<(), Error> {
        tracing::info!("tcp hole punch client start");
        self.client.start();
        Ok(())
    }

    pub async fn run_as_server(&mut self) -> Result<(), Error> {
        tracing::info!("tcp hole punch server register rpc");
        self.peer_mgr
            .get_peer_rpc_mgr()
            .rpc_server()
            .registry()
            .register(
                TcpHolePunchRpcServer::new_arc(self.server.clone()),
                &self.peer_mgr.get_global_ctx().get_network_name(),
            );
        Ok(())
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let flags = self.peer_mgr.get_global_ctx().get_flags();
        if flags.disable_tcp_hole_punching {
            tracing::debug!(
                "tcp hole punch disabled by disable_tcp_hole_punching(={});",
                flags.disable_tcp_hole_punching
            );
            return Ok(());
        }

        self.run_as_client().await?;
        self.run_as_server().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use crate::{
        common::{error::Error, stun::StunInfoCollectorTrait},
        connector::tcp_hole_punch::TcpHolePunchConnector,
        instance::listeners::ListenerManager,
        peers::{
            peer_manager::PeerManager,
            peer_task::PeerTaskLauncher,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::common::{NatType, StunInfo},
        tunnel::{TunnelListener as _, common::tests::wait_for_condition},
    };

    use super::{TcpHolePunchPeerTaskLauncher, TcpHolePunchTunnel, pre_punch_tcp_mapping};

    struct MockStunInfoCollector {
        udp_nat_type: NatType,
        tcp_nat_type: NatType,
    }

    #[async_trait::async_trait]
    impl StunInfoCollectorTrait for MockStunInfoCollector {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                udp_nat_type: self.udp_nat_type as i32,
                tcp_nat_type: self.tcp_nat_type as i32,
                last_update_time: 0,
                public_ip: vec!["127.0.0.1".to_string(), "::1".to_string()],
                min_port: 100,
                max_port: 200,
            }
        }

        async fn get_udp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }

        async fn get_udp_port_mapping_with_socket(
            &self,
            udp: std::sync::Arc<tokio::net::UdpSocket>,
        ) -> Result<SocketAddr, Error> {
            self.get_udp_port_mapping(udp.local_addr()?.port()).await
        }

        async fn get_tcp_port_mapping(&self, mut port: u16) -> Result<SocketAddr, Error> {
            if port == 0 {
                port = 40144;
            }
            Ok(format!("127.0.0.1:{}", port).parse().unwrap())
        }
    }

    fn replace_stun_info_collector(peer_mgr: Arc<PeerManager>, tcp_nat_type: NatType) {
        let collector = Box::new(MockStunInfoCollector {
            udp_nat_type: NatType::Unknown,
            tcp_nat_type,
        });
        peer_mgr
            .get_global_ctx()
            .replace_stun_info_collector(collector);
    }

    async fn collect_lazy_punch_peers(peer_mgr: Arc<PeerManager>) -> Vec<u32> {
        let launcher = TcpHolePunchPeerTaskLauncher {};
        let data = launcher.new_data(peer_mgr);
        launcher
            .collect_peers_need_task(&data)
            .await
            .into_iter()
            .map(|task| task.dst_peer_id)
            .collect()
    }

    #[tokio::test]
    async fn tcp_hole_punch_connects() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = TcpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = TcpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;
        hole_punching_c.client.run_immediately().await;

        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                async move {
                    let a_has = p_a
                        .get_peer_map()
                        .list_peer_conns(p_c.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    let c_has = p_c
                        .get_peer_map()
                        .list_peer_conns(p_a.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    a_has || c_has
                }
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[cfg(feature = "websocket")]
    #[tokio::test]
    async fn websocket_pre_punch_reuses_listener_port() {
        let peer_mgr = create_mock_peer_manager().await;
        let mut ws_listener =
            crate::tunnel::websocket::WsTunnelListener::new("ws://127.0.0.1:0".parse().unwrap());
        ws_listener.listen().await.unwrap();
        let local_port = ws_listener.local_url().port().unwrap();

        let remote_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote_listener.local_addr().unwrap();
        let accept_task = tokio::spawn(async move {
            let (_stream, peer_addr) = remote_listener.accept().await.unwrap();
            peer_addr.port()
        });

        pre_punch_tcp_mapping(peer_mgr, remote_addr, local_port, TcpHolePunchTunnel::Ws, 1)
            .await
            .unwrap();

        assert_eq!(accept_task.await.unwrap(), local_port);
    }

    #[cfg(feature = "websocket")]
    #[rstest::rstest]
    #[tokio::test]
    async fn websocket_hole_punch_connects(#[values("ws", "wss")] scheme: &str) {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        let mut flags_a = p_a.get_global_ctx().get_flags();
        flags_a.default_protocol = scheme.to_string();
        p_a.get_global_ctx().set_flags(flags_a);

        let mut flags_c = p_c.get_global_ctx().get_flags();
        flags_c.default_protocol = scheme.to_string();
        p_c.get_global_ctx().set_flags(flags_c);

        p_a.get_global_ctx()
            .config
            .set_listeners(vec![format!("{}://0.0.0.0:0", scheme).parse().unwrap()]);
        p_c.get_global_ctx()
            .config
            .set_listeners(vec![format!("{}://0.0.0.0:0", scheme).parse().unwrap()]);

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut listener_a = ListenerManager::new(p_a.get_global_ctx(), p_a.clone());
        let mut listener_c = ListenerManager::new(p_c.get_global_ctx(), p_c.clone());
        listener_a.prepare_listeners().await.unwrap();
        listener_c.prepare_listeners().await.unwrap();
        listener_a.run().await.unwrap();
        listener_c.run().await.unwrap();
        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                let scheme = scheme.to_string();
                async move {
                    p_a.get_global_ctx()
                        .get_running_listeners()
                        .iter()
                        .any(|listener| listener.scheme() == scheme)
                        && p_c
                            .get_global_ctx()
                            .get_running_listeners()
                            .iter()
                            .any(|listener| listener.scheme() == scheme)
                }
            },
            Duration::from_secs(5),
        )
        .await;

        let mut hole_punching_a = TcpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = TcpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;
        hole_punching_c.client.run_immediately().await;

        wait_for_condition(
            || {
                let p_a = p_a.clone();
                let p_c = p_c.clone();
                async move {
                    let a_has = p_a
                        .get_peer_map()
                        .list_peer_conns(p_c.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    let c_has = p_c
                        .get_peer_map()
                        .list_peer_conns(p_a.my_peer_id())
                        .await
                        .is_some_and(|c| !c.is_empty());
                    a_has || c_has
                }
            },
            Duration::from_secs(15),
        )
        .await;
    }

    #[tokio::test]
    async fn tcp_hole_punch_skip_symmetric_peer() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::Symmetric);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::Symmetric);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        let mut hole_punching_a = TcpHolePunchConnector::new(p_a.clone());
        let mut hole_punching_c = TcpHolePunchConnector::new(p_c.clone());
        hole_punching_a.run().await.unwrap();
        hole_punching_c.run().await.unwrap();

        hole_punching_a.client.run_immediately().await;
        hole_punching_c.client.run_immediately().await;

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(
            p_a.get_peer_map()
                .list_peer_conns(p_c.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
        assert!(
            p_c.get_peer_map()
                .list_peer_conns(p_a.my_peer_id())
                .await
                .map(|c| c.is_empty())
                .unwrap_or(true)
        );
    }

    #[tokio::test]
    async fn lazy_p2p_collects_tcp_hole_punch_tasks_only_after_recent_traffic() {
        let p_a = create_mock_peer_manager().await;
        let p_b = create_mock_peer_manager().await;
        let p_c = create_mock_peer_manager().await;

        replace_stun_info_collector(p_a.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_b.clone(), NatType::PortRestricted);
        replace_stun_info_collector(p_c.clone(), NatType::PortRestricted);

        let mut flags = p_a.get_global_ctx().get_flags();
        flags.lazy_p2p = true;
        p_a.get_global_ctx().set_flags(flags);

        connect_peer_manager(p_a.clone(), p_b.clone()).await;
        connect_peer_manager(p_b.clone(), p_c.clone()).await;
        wait_route_appear(p_a.clone(), p_c.clone()).await.unwrap();

        assert!(
            !collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );

        p_a.mark_recent_traffic(p_c.my_peer_id());

        assert!(
            collect_lazy_punch_peers(p_a.clone())
                .await
                .contains(&p_c.my_peer_id())
        );
    }
}

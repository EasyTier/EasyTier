use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Error};
use dashmap;
use tokio::task::JoinSet;

use crate::{
    common::{PeerId, join_joinset_background, stun::StunInfoCollectorTrait, upnp, global_ctx::GlobalCtxEvent},
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
    tunnel::{
        TunnelListener as _,
        tcp::TcpTunnelListener,
    },
};

use crate::connector::{should_background_p2p_with_peer, should_try_p2p_with_peer};

pub const BLACKLIST_TIMEOUT_SEC: u64 = 3600;

/// Custom error type for TCP hole punch that carries the allocated port
/// so it can be reused on retry or cleaned up on failure.
#[derive(Debug)]
struct HolePunchError {
    error: anyhow::Error,
    allocated_port: Option<u16>,
}

impl std::fmt::Display for HolePunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for HolePunchError {}

impl HolePunchError {
    fn new(error: anyhow::Error, port: Option<u16>) -> Self {
        Self { error, allocated_port: port }
    }
}

type HolePunchResult<T> = Result<T, HolePunchError>;

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
        // Try to bind to the physical interface address to avoid using virtual network interfaces
        let physical_addr = upnp::get_physical_ipv4_addr()
            .map(|ip| IpAddr::V4(ip))
            .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        SocketAddr::new(physical_addr, port)
    }
}

/// Create a TcpSocket bound to an ephemeral port.
/// The socket is NOT dropped, so the port remains locked.
/// Returns (socket, local_port).
async fn create_bound_socket(peer_mgr: &Arc<PeerManager>, is_v6: bool) -> Result<(tokio::net::TcpSocket, u16), Error> {
    let _g = peer_mgr.get_global_ctx().net_ns.guard();
    let socket = if is_v6 {
        tokio::net::TcpSocket::new_v6()?
    } else {
        tokio::net::TcpSocket::new_v4()?
    };

    // Set SO_REUSEADDR to allow rebinding to the same port
    // This is required because STUN verification may also try to bind to this port
    socket.set_reuseaddr(true)?;
    #[cfg(unix)]
    socket.set_reuseport(true)?;

    socket.bind(bind_addr_for_port(0, is_v6))?;
    let local_port = socket.local_addr()?.port();
    tracing::debug!(is_v6, local_port, "tcp hole punch created bound socket");
    Ok((socket, local_port))
}

/// Connect to remote using a pre-bound socket.
/// This avoids TOCTOU: the socket was bound earlier and port is still locked.
/// Note: TcpSocket is consumed on first successful connect attempt.
async fn try_connect_with_socket(
    peer_mgr: Arc<PeerManager>,
    socket: tokio::net::TcpSocket,
    remote_addr: SocketAddr,
    local_port: u16,
    is_client: bool,
) -> Result<(), Error> {
    tracing::info!(
        ?remote_addr,
        local_port,
        "tcp hole punch start connect with pre-bound socket"
    );

    let _g = peer_mgr.get_global_ctx().net_ns.guard();

    // TcpSocket can only be used once for connect
    match tokio::time::timeout(Duration::from_secs(10), socket.connect(remote_addr)).await {
        Ok(Ok(stream)) => {
            // Set TCP options
            let _ = stream.set_nodelay(true);
            let _ = socket2::SockRef::from(&stream).set_linger(Some(Duration::ZERO));

            // Create tunnel from stream
            let tunnel_url = format!("tcp://{}", remote_addr).parse().unwrap();
            let tunnel = crate::tunnel::tcp::get_tunnel_with_tcp_stream(stream, tunnel_url)
                .map_err(|e| anyhow::anyhow!("create tunnel failed: {:?}", e))?;

            let add_tunnel_ret = if is_client {
                peer_mgr.add_client_tunnel(tunnel, false).await.map(|_| ())
            } else {
                peer_mgr.add_tunnel_as_server(tunnel, false).await
            };
            if let Err(e) = add_tunnel_ret {
                tracing::error!(
                    ?remote_addr,
                    local_port,
                    ?e,
                    "tcp hole punch connected but add tunnel failed"
                );
                return Err(anyhow::anyhow!("add tunnel failed: {:?}", e));
            } else {
                tracing::info!(
                    ?remote_addr,
                    local_port,
                    is_client,
                    "tcp hole punch connected and added tunnel"
                );
                return Ok(());
            }
        }
        Ok(Err(e)) => {
            tracing::warn!(
                ?remote_addr,
                local_port,
                ?e,
                "tcp hole punch connect failed"
            );
            return Err(anyhow::anyhow!("connect failed: {:?}", e));
        }
        Err(_) => {
            tracing::warn!(
                ?remote_addr,
                local_port,
                "tcp hole punch connect timeout"
            );
            return Err(anyhow::anyhow!("connect timeout"));
        }
    }
}

struct TcpHolePunchServer {
    peer_mgr: Arc<PeerManager>,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
    // Track peers we're already connecting to, to avoid duplicate tasks
    // DashSet::insert returns true if value was newly inserted (atomic operation)
    connecting_peers: Arc<dashmap::DashSet<SocketAddr>>,
    // Store active UPnP port mapping leases to keep them alive
    port_mapping_leases: Arc<tokio::sync::Mutex<std::collections::HashMap<u16, upnp::TcpPortMappingLease>>>,
}

impl TcpHolePunchServer {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "tcp hole punch server".to_string());
        Arc::new(Self {
            peer_mgr,
            tasks,
            connecting_peers: Arc::new(dashmap::DashSet::new()),
            port_mapping_leases: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    /// Store a UPnP port mapping lease to keep it alive
    async fn store_port_mapping_lease(&self, port: u16, lease: upnp::TcpPortMappingLease) {
        let mut leases = self.port_mapping_leases.lock().await;
        tracing::info!(?port, "storing UPnP port mapping lease on server");
        leases.insert(port, lease);
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
        tracing::info!(?my_tcp_nat_type, "tcp hole punch rpc received");
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

        let is_v6 = a_mapped_addr.is_ipv6();

        // NAT4 (Symmetric NAT) cannot be reached from outside.
        // No point doing UPnP or STUN - just bind a port and connect directly.
        let is_symmetric = is_symmetric_tcp_nat(my_tcp_nat_type);

        // Step 1: Create socket and bind to a port
        let (socket, local_port, mapped_addr) = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            let socket = if is_v6 {
                tokio::net::TcpSocket::new_v6().map_err(|e| anyhow::anyhow!(e))?
            } else {
                tokio::net::TcpSocket::new_v4().map_err(|e| anyhow::anyhow!(e))?
            };
            socket.set_reuseaddr(true).map_err(|e| anyhow::anyhow!(e))?;
            #[cfg(unix)]
            socket.set_reuseport(true).map_err(|e| anyhow::anyhow!(e))?;

            // Check if NAT detection already created a TCP port mapping
            let nat_detection_port = if !is_v6 {
                self.peer_mgr.get_global_ctx().get_stun_info_collector().get_nat_detection_tcp_port()
            } else {
                None
            };

            // Bind to the NAT detection port if available, otherwise use port 0
            let bind_port = nat_detection_port.unwrap_or(0);
            socket.bind(bind_addr_for_port(bind_port, is_v6)).map_err(|e| anyhow::anyhow!(e))?;
            let local_port = socket.local_addr().map_err(|e| anyhow::anyhow!(e))?.port();

            if is_symmetric {
                // Symmetric NAT: skip UPnP/STUN, return dummy mapped addr
                // NAT4 will connect directly to NAT1's address
                tracing::info!(
                    ?my_tcp_nat_type,
                    local_port,
                    "symmetric NAT: skipping UPnP/STUN, will connect directly"
                );
                (socket, local_port, SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
            } else {
                // Non-symmetric NAT: do UPnP + STUN to get public address
                let listener_url = format!("tcp://0.0.0.0:{}", local_port).parse().unwrap();
                let (mapped_addr, port_mapping_lease) = upnp::resolve_tcp_public_addr(
                    self.peer_mgr.get_global_ctx().clone(),
                    &listener_url,
                    local_port,
                )
                .await
                .with_context(|| "failed to get tcp port mapping")?;

                // Store the lease to keep UPnP mapping alive
                if let Some(lease) = port_mapping_lease {
                    self.store_port_mapping_lease(local_port, lease).await;
                }

                tracing::info!(?local_port, ?nat_detection_port, "tcp hole punch server reusing NAT detection port");
                (socket, local_port, mapped_addr)
            }
        };

        tracing::info!(
            ?a_mapped_addr,
            local_port,
            ?mapped_addr,
            ?my_tcp_nat_type,
            "tcp hole punch rpc responding with mapped addr and start connecting"
        );

        // Atomic dedup: DashSet::insert returns true if value was newly inserted
        let peer_key = a_mapped_addr;
        let connecting_peers = self.connecting_peers.clone();

        if connecting_peers.insert(peer_key) {
            // Successfully inserted - we are the first to try connecting to this peer
            let peer_mgr = self.peer_mgr.clone();
            let connecting_peers_clone = connecting_peers.clone();
            self.tasks.lock().unwrap().spawn(async move {
                let _ = try_connect_with_socket(peer_mgr, socket, a_mapped_addr, local_port, true).await;
                connecting_peers_clone.remove(&peer_key);
            });
        } else {
            // Already existed - another task is already connecting to this peer
            tracing::debug!(
                ?a_mapped_addr,
                "tcp hole punch server already connecting to this peer, skipping duplicate task"
            );
        }

        Ok(TcpHolePunchResponse {
            listener_mapped_addr: Some(mapped_addr.into()),
            tcp_nat_type: my_tcp_nat_type as i32,
        })
    }
}

struct TcpHolePunchConnectorData {
    peer_mgr: Arc<PeerManager>,
    blacklist: Arc<timedmap::TimedMap<PeerId, ()>>,
    // Track peers we're already connecting to, to avoid duplicate tasks
    // DashSet::insert returns true if value was newly inserted (atomic operation)
    connecting_peers: Arc<dashmap::DashSet<PeerId>>,
    // Flag to force TCP hole punch even if peer already connected (e.g., via relay)
    force_hole_punch: Arc<std::sync::atomic::AtomicBool>,
    // Store active UPnP port mapping leases to keep them alive
    // Key: local port, Value: lease (keeps mapping alive until dropped)
    port_mapping_leases: Arc<tokio::sync::Mutex<std::collections::HashMap<u16, upnp::TcpPortMappingLease>>>,
}

impl TcpHolePunchConnectorData {
    fn new(peer_mgr: Arc<PeerManager>) -> Arc<Self> {
        Arc::new(Self {
            peer_mgr,
            blacklist: Arc::new(timedmap::TimedMap::new()),
            connecting_peers: Arc::new(dashmap::DashSet::new()),
            force_hole_punch: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            port_mapping_leases: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        })
    }

    fn set_force_hole_punch(&self, force: bool) {
        self.force_hole_punch.store(force, std::sync::atomic::Ordering::Relaxed);
    }

    fn should_force_hole_punch(&self) -> bool {
        self.force_hole_punch.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Store a UPnP port mapping lease to keep it alive
    async fn store_port_mapping_lease(&self, port: u16, lease: upnp::TcpPortMappingLease) {
        let mut leases = self.port_mapping_leases.lock().await;
        tracing::info!(?port, "storing UPnP port mapping lease");
        leases.insert(port, lease);
    }

    /// Remove a UPnP port mapping lease (will delete the mapping)
    async fn remove_port_mapping_lease(&self, port: &u16) {
        let mut leases = self.port_mapping_leases.lock().await;
        if leases.remove(port).is_some() {
            tracing::info!(?port, "removed UPnP port mapping lease");
        }
    }

    /// Check if we have a UPnP port mapping lease for the given port
    async fn has_port_mapping_lease(&self, port: &u16) -> bool {
        let leases = self.port_mapping_leases.lock().await;
        leases.contains_key(port)
    }

    async fn punch_as_initiator(self: Arc<Self>, dst_peer_id: PeerId) -> Result<(), Error> {
        // Atomic dedup: DashSet::insert returns true if value was newly inserted
        if !self.connecting_peers.insert(dst_peer_id) {
            tracing::debug!(
                dst_peer_id,
                "tcp hole punch initiator skipped (already connecting)"
            );
            return Ok(());
        }

        // Allocate port ONCE and reuse across retries to avoid UPnP lease leaks
        let mut reused_port: Option<u16> = None;

            let mut backoff = BackOff::new(vec![1000, 1000, 4000, 8000]);
        let mut success = false;

        loop {
            backoff.sleep_for_next_backoff().await;
            match self.do_punch_as_initiator(dst_peer_id, reused_port).await {
                Ok((port, _lease)) => {
                    // Save port for potential cleanup if needed
                    reused_port = Some(port);
                    success = true;
                    break;
                }
                Err(err) => {
                    // Save port even on failure for reuse in next attempt
                    if let Some(port) = err.allocated_port {
                        if reused_port.is_none() {
                            tracing::info!(?port, "saving port for reuse in next attempt");
                            reused_port = Some(port);
                        }
                    }

                    let e = err.error;
                    // If NAT type is unknown, don't retry - will be picked up on next collect cycle
                    if e.to_string().contains("NAT type unknown") {
                        tracing::info!(dst_peer_id, "tcp hole punch waiting for NAT detection");
                        break;
                    }
                    // For symmetric NAT, don't retry
                    if e.to_string().contains("symmetric NAT") {
                        tracing::info!(dst_peer_id, "tcp hole punch skipped (symmetric NAT)");
                        break;
                    }
                    // For other errors, continue retrying
                    tracing::warn!(dst_peer_id, ?e, "tcp hole punch attempt failed, retrying");
                }
            }

            if self.blacklist.contains(&dst_peer_id) {
                tracing::warn!(
                    dst_peer_id,
                    "tcp hole punch initiator skipped (blacklisted)"
                );
                break;
            }
        }

        // Clean up: remove UPnP mapping if hole punch didn't succeed
        if !success {
            if let Some(port) = reused_port {
                tracing::info!(?port, "cleaning up UPnP mapping after failed hole punch");
                self.remove_port_mapping_lease(&port).await;
            }
        }

        // Remove from connecting set
        self.connecting_peers.remove(&dst_peer_id);

        Ok(())
    }

    #[tracing::instrument(skip(self), fields(dst_peer_id))]
    async fn do_punch_as_initiator(&self, dst_peer_id: PeerId, reused_port: Option<u16>) -> HolePunchResult<(u16, Option<upnp::TcpPortMappingLease>)> {
        let global_ctx = self.peer_mgr.get_global_ctx();
        let my_tcp_nat_type = NatType::try_from(
            global_ctx
                .get_stun_info_collector()
                .get_stun_info()
                .tcp_nat_type,
        )
        .unwrap_or(NatType::Unknown);
        tracing::info!(?my_tcp_nat_type, "tcp hole punch initiator start");

        // Skip only for symmetric NAT (NAT4)
        if is_symmetric_tcp_nat(my_tcp_nat_type) {
            tracing::info!("tcp hole punch initiator skipped (symmetric)");
            return Err(HolePunchError::new(anyhow::anyhow!("symmetric NAT, skip"), None));
        }

        // If NAT type is Unknown, return error to retry later
        if my_tcp_nat_type == NatType::Unknown {
            tracing::info!("tcp hole punch initiator skipped (unknown, waiting for NAT detection)");
            return Err(HolePunchError::new(anyhow::anyhow!("NAT type unknown, retry later"), None));
        }

        // Step 1: Get or reuse port
        let local_port = match reused_port {
            Some(port) => {
                tracing::info!(?port, "reusing existing port for retry");
                port
            }
            None => {
                // Check if NAT detection already created a TCP port mapping
                let nat_detection_port = global_ctx.get_stun_info_collector().get_nat_detection_tcp_port();
                if let Some(port) = nat_detection_port {
                    tracing::info!(?port, "reusing NAT detection port for UPnP mapping");
                    port
                } else {
                    // No existing mapping, allocate a new port
                    let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
                    let temp_socket = match tokio::net::TcpSocket::new_v4() {
                        Ok(s) => s,
                        Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("create socket failed: {:?}", e), None)),
                    };
                    if let Err(e) = temp_socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
                        return Err(HolePunchError::new(anyhow::anyhow!("bind failed: {:?}", e), None));
                    }
                    let port = match temp_socket.local_addr() {
                        Ok(addr) => addr.port(),
                        Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("local_addr failed: {:?}", e), None)),
                    };
                    drop(temp_socket);
                    port
                }
            }
        };

        // Step 2: UPnP mapping + STUN verification
        // SKIP UPnP if reusing port (mapping already exists from first attempt)
        let mapped_addr = if reused_port.is_some() {
            // Reuse existing mapping - just do STUN to get mapped address
            match global_ctx.get_stun_info_collector().get_tcp_port_mapping(local_port).await {
                Ok(addr) => addr,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("STUN failed: {:?}", e), Some(local_port))),
            }
        } else {
            // First attempt - create UPnP mapping + STUN
            let listener_url = format!("tcp://0.0.0.0:{}", local_port).parse().unwrap();
            let (mapped_addr, port_mapping_lease) = match upnp::resolve_tcp_public_addr(
                global_ctx.clone(),
                &listener_url,
                local_port,
            ).await {
                Ok(result) => result,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("UPnP/STUN failed: {:?}", e), Some(local_port))),
            };

            // Store the lease to keep UPnP mapping alive
            if let Some(lease) = port_mapping_lease {
                self.store_port_mapping_lease(local_port, lease).await;
            }

            mapped_addr
        };

        // Step 3: Create persistent socket for hole punch (re-bind to same port)
        let socket = {
            let _g = self.peer_mgr.get_global_ctx().net_ns.guard();
            let socket = match tokio::net::TcpSocket::new_v4() {
                Ok(s) => s,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("create socket failed: {:?}", e), Some(local_port))),
            };
            if let Err(e) = socket.set_reuseaddr(true) {
                    return Err(HolePunchError::new(anyhow::anyhow!("set_reuseaddr failed: {:?}", e), Some(local_port)));
            }
            #[cfg(unix)]
            if let Err(e) = socket.set_reuseport(true) {
                    return Err(HolePunchError::new(anyhow::anyhow!("set_reuseport failed: {:?}", e), Some(local_port)));
            }
            if let Err(e) = socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)) {
                    return Err(HolePunchError::new(anyhow::anyhow!("bind failed: {:?}", e), Some(local_port)));
            }
            socket
        };

        tracing::info!(
            dst_peer_id,
            local_port,
            ?mapped_addr,
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
                },
            )
            .await;
        let resp = match handle_rpc_result(resp, dst_peer_id, &self.blacklist) {
            Ok(resp) => resp,
            Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("RPC error: {:?}", e), Some(local_port))),
        };
        let remote_mapped_addr = match resp.listener_mapped_addr {
            Some(addr) => SocketAddr::from(addr),
            None => return Err(HolePunchError::new(anyhow::anyhow!("listener_mapped_addr is required"), Some(local_port))),
        };
        let remote_tcp_nat_type = NatType::try_from(resp.tcp_nat_type).unwrap_or(NatType::Unknown);
        tracing::info!(
            dst_peer_id,
            ?remote_mapped_addr,
            ?remote_tcp_nat_type,
            "tcp hole punch initiator rpc returned"
        );

        // Key optimization: When remote is Symmetric NAT, skip simultaneous open
        // because Symmetric NAT allocates different ports per destination.
        // Instead, go directly to STUN traversal mode (NAT1 listens, NAT4 connects).
        let skip_simultaneous_open = is_symmetric_tcp_nat(remote_tcp_nat_type);

        if skip_simultaneous_open {
            tracing::info!(
                dst_peer_id,
                ?my_tcp_nat_type,
                ?remote_tcp_nat_type,
                "tcp hole punch initiator: remote is symmetric, skipping simultaneous open"
            );

            // When skipping simultaneous open, we need to listen on the port immediately
            // so NAT4 can connect to us. Convert socket to listener.
            if my_tcp_nat_type == NatType::FullCone {
                tracing::info!(
                    dst_peer_id,
                    local_port,
                    ?mapped_addr,
                    "tcp hole punch initiator: NAT1 listening for NAT4 connection"
                );

                // Convert TcpSocket to TcpListener - port stays bound and now listens
                let tcp_listener = match socket.listen(128) {
                    Ok(l) => l,
                    Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("listen failed: {:?}", e), Some(local_port))),
                };
                let listener_url = format!("tcp://0.0.0.0:{}", local_port).parse().unwrap();
                let mut listener = TcpTunnelListener::from_listener(tcp_listener, listener_url);

                // Wait for NAT4 to connect (with timeout)
                let accept_timeout = Duration::from_secs(15);
                match tokio::time::timeout(accept_timeout, listener.accept()).await {
                    Ok(Ok(tunnel)) => {
                        tracing::info!(local_port, "listener accepted connection from NAT4");
                        if let Err(e) = self.peer_mgr.add_tunnel_as_server(tunnel, false).await {
                            tracing::error!(?e, "listener failed to add tunnel");
                            return Err(HolePunchError::new(anyhow::anyhow!("failed to add tunnel: {:?}", e), Some(local_port)));
                        }
                        tracing::info!(local_port, "listener added tunnel successfully");
                        return Ok((local_port, None));
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(?e, local_port, "listener accept error");
                        return Err(HolePunchError::new(anyhow::anyhow!("accept error: {:?}", e), Some(local_port)));
                    }
                    Err(_) => {
                        tracing::warn!(local_port, "listener accept timeout, NAT4 did not connect");
                        return Err(HolePunchError::new(anyhow::anyhow!("accept timeout"), Some(local_port)));
                    }
                }
            }
        } else {
            // If we are symmetric NAT (NAT4) and remote is FullCone (NAT1),
            // add a small delay to let the remote side establish their mapping first
            if is_symmetric_tcp_nat(my_tcp_nat_type) && remote_tcp_nat_type == NatType::FullCone {
                tracing::info!(
                    dst_peer_id,
                    ?my_tcp_nat_type,
                    ?remote_tcp_nat_type,
                    "tcp hole punch initiator: symmetric NAT waiting for fullcone peer"
                );
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            // Try simultaneous open
            if let Ok(()) = try_connect_with_socket(
                self.peer_mgr.clone(),
                socket,
                remote_mapped_addr,
                local_port,
                false,
            )
            .await
            {
                tracing::info!(
                    dst_peer_id,
                    local_port,
                    ?remote_mapped_addr,
                    "tcp hole punch initiator connected to remote mapped addr with simultaneous connection"
                );
                return Ok((local_port, None));
            }

            tracing::info!(
                dst_peer_id,
                local_port,
                ?remote_mapped_addr,
                "tcp hole punch initiator simultaneous open failed"
            );
        }

        // If we are NAT1 (FullCone), try STUN traversal with a DIFFERENT port
        // Using a different port avoids conflicts between simultaneous open and listening
        if my_tcp_nat_type == NatType::FullCone {
            tracing::info!(
                dst_peer_id,
                ?my_tcp_nat_type,
                "tcp hole punch initiator trying STUN traversal for NAT1"
            );

            // Create a bound socket for STUN traversal
            let (stun_socket, stun_port) = match create_bound_socket(&self.peer_mgr, false).await {
                Ok(result) => result,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("create_bound_socket failed: {:?}", e), Some(local_port))),
            };
            let stun_listener_url = format!("tcp://0.0.0.0:{}", stun_port).parse().unwrap();
            let (public_addr, stun_lease) = match upnp::resolve_tcp_public_addr(
                global_ctx.clone(),
                &stun_listener_url,
                stun_port,
            ).await {
                Ok(result) => result,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("STUN failed: {:?}", e), Some(stun_port))),
            };

            // Store the lease to keep UPnP mapping alive
            if let Some(lease) = stun_lease {
                self.store_port_mapping_lease(stun_port, lease).await;
            }

            tracing::info!(
                dst_peer_id,
                stun_port,
                ?public_addr,
                "tcp hole punch initiator got public address via STUN for NAT1"
            );

            // Convert TcpSocket to TcpListener directly - port is never released
            let tcp_listener = match stun_socket.listen(128) {
                Ok(l) => l,
                Err(e) => return Err(HolePunchError::new(anyhow::anyhow!("listen failed: {:?}", e), Some(stun_port))),
            };
            let mut listener = TcpTunnelListener::from_listener(tcp_listener, stun_listener_url);

            // Report the public listening address to other nodes via RPC
            let rpc_stub = self
                .peer_mgr
                .get_peer_rpc_mgr()
                .rpc_client()
                .scoped_client::<TcpHolePunchRpcClientFactory<BaseController>>(
                    self.peer_mgr.my_peer_id(),
                    dst_peer_id,
                    global_ctx.get_network_name(),
                );

            // Send the public address to the remote peer
            let report_resp = rpc_stub
                .exchange_mapped_addr(
                    BaseController {
                        timeout_ms: 6000,
                        ..Default::default()
                    },
                    TcpHolePunchRequest {
                        connector_mapped_addr: Some(public_addr.into()),
                    },
                )
                .await;

            match report_resp {
                Ok(_) => {
                    tracing::info!(
                        dst_peer_id,
                        stun_port,
                        ?public_addr,
                        "tcp hole punch initiator reported public listening address for NAT1"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        dst_peer_id,
                        stun_port,
                        ?public_addr,
                        ?e,
                        "tcp hole punch initiator failed to report public listening address"
                    );
                }
            }

            // Wait for NAT4 to connect (with timeout)
            let accept_timeout = Duration::from_secs(15);
            match tokio::time::timeout(accept_timeout, listener.accept()).await {
                Ok(Ok(tunnel)) => {
                    tracing::info!(stun_port, "stun listener accepted connection from NAT4");
                    if let Err(e) = self.peer_mgr.add_tunnel_as_server(tunnel, false).await {
                        tracing::error!(?e, "stun listener failed to add tunnel");
                            return Err(HolePunchError::new(anyhow::anyhow!("failed to add tunnel: {:?}", e), Some(stun_port)));
                    }
                    tracing::info!(stun_port, "stun listener added tunnel successfully");
                        return Ok((stun_port, None));
                }
                Ok(Err(e)) => {
                    tracing::warn!(?e, stun_port, "stun listener accept error");
                        return Err(HolePunchError::new(anyhow::anyhow!("accept error: {:?}", e), Some(stun_port)));
                }
                Err(_) => {
                    tracing::warn!(stun_port, "stun listener accept timeout, NAT4 did not connect");
                        return Err(HolePunchError::new(anyhow::anyhow!("accept timeout"), Some(stun_port)));
                }
            }
        }

        Err(HolePunchError::new(anyhow::anyhow!("tcp hole punch simultaneous open failed"), Some(local_port)))
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

        // Skip only for symmetric NAT (NAT4), not for Unknown
        // Unknown means NAT detection hasn't completed yet, we should retry later
        if is_symmetric_tcp_nat(my_tcp_nat_type) {
            tracing::trace!(
                ?my_tcp_nat_type,
                "tcp hole punch task collect skipped (symmetric)"
            );
            return vec![];
        }

        // If NAT type is Unknown, log and return empty (will retry on next loop)
        if my_tcp_nat_type == NatType::Unknown {
            tracing::trace!(
                ?my_tcp_nat_type,
                "tcp hole punch task collect skipped (unknown, waiting for NAT detection)"
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

            // Skip peers that are already connected
            // Even with force_hole_punch, we don't want to punch again if already connected
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

            // Skip peers that are already in the connecting set (another task is working on it)
            if data.connecting_peers.contains(&peer_id) {
                tracing::debug!(
                    peer_id,
                    "tcp hole punch task collect skip already connecting"
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

        // Subscribe to TCP NAT type detection events
        let mut event_rx = self.peer_mgr.get_global_ctx().subscribe();
        let p2p_demand_notify = self.peer_mgr.p2p_demand_notify();
        let data = self.client.data();
        tokio::spawn(async move {
            loop {
                match event_rx.recv().await {
                    Ok(GlobalCtxEvent::TcpNatTypeDetected) => {
                        tracing::info!("TCP NAT type detected, forcing TCP hole punch for all peers");
                        // Set force flag to bypass has_peer check
                        data.set_force_hole_punch(true);
                        p2p_demand_notify.notify();
                        // Reset force flag after a delay
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        data.set_force_hole_punch(false);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!(?e, "event receiver error, stopping listener");
                        break;
                    }
                }
            }
        });

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
        peers::{
            peer_manager::PeerManager,
            peer_task::PeerTaskLauncher,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        proto::common::{NatType, StunInfo},
        tunnel::common::tests::wait_for_condition,
    };

    use super::TcpHolePunchPeerTaskLauncher;

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

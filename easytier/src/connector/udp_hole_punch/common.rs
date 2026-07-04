use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex as StdMutex},
};

use async_trait::async_trait;
use easytier_core::hole_punch::udp as core_udp_hole_punch;
use quanta::Instant;
use tokio::net::UdpSocket;

use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx, upnp},
    peers::peer_manager::PeerManager,
    proto::common::NatType,
    tunnel::{
        Tunnel, TunnelConnCounter, TunnelListener as _,
        udp::{RuntimeUdpSocket, UdpTunnelConnector, UdpTunnelListener},
    },
};

#[allow(dead_code)]
struct RuntimeUdpPunchAcceptor {
    listener: UdpTunnelListener,
}

#[async_trait]
impl core_udp_hole_punch::UdpPunchAcceptor for RuntimeUdpPunchAcceptor {
    async fn accept(&mut self) -> anyhow::Result<Box<dyn Tunnel>> {
        self.listener.accept().await.map_err(anyhow::Error::from)
    }
}

#[allow(dead_code)]
struct RuntimeUdpPunchConnCounter {
    inner: Arc<Box<dyn TunnelConnCounter>>,
}

impl core_udp_hole_punch::UdpPunchConnCounter for RuntimeUdpPunchConnCounter {
    fn get(&self) -> Option<u32> {
        self.inner.get()
    }
}

#[allow(dead_code)]
struct RuntimeUdpPortMappingLease {
    _inner: StdMutex<Option<upnp::UdpPortMappingLease>>,
}

impl Debug for RuntimeUdpPortMappingLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuntimeUdpPortMappingLease")
            .finish_non_exhaustive()
    }
}

impl core_udp_hole_punch::UdpPortMappingLease for RuntimeUdpPortMappingLease {}

#[allow(dead_code)]
pub(crate) struct RuntimeUdpHolePunchRuntime {
    global_ctx: ArcGlobalCtx,
}

impl RuntimeUdpHolePunchRuntime {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }

    async fn create_listener_ext(
        &self,
        with_mapped_addr: bool,
        port: Option<u16>,
    ) -> anyhow::Result<core_udp_hole_punch::UdpPunchListener<RuntimeUdpSocket>> {
        let bind_options = match port {
            Some(port) => core_udp_hole_punch::UdpBindOptions::port_bound_listener(SocketAddr::V4(
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            )),
            None => core_udp_hole_punch::UdpBindOptions::hole_punch_control(),
        };
        let socket = core_udp_hole_punch::UdpHolePunchRuntime::bind_udp(self, bind_options).await?;
        let local_port = socket.socket().local_addr()?.port();
        let listen_url: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();

        let (mapped_addr, port_mapping_lease) = if with_mapped_addr {
            upnp::resolve_udp_public_addr(self.global_ctx.clone(), &listen_url, socket.socket())
                .await?
        } else {
            (
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port)),
                None,
            )
        };

        let mut listener = UdpTunnelListener::new_with_socket(listen_url, socket.socket());

        {
            let _g = self.global_ctx.net_ns.guard();
            listener.listen().await?;
        }

        let socket = listener
            .get_runtime_socket()
            .ok_or_else(|| anyhow::anyhow!("udp tunnel listener did not expose socket"))?;
        let conn_counter = Arc::new(RuntimeUdpPunchConnCounter {
            inner: listener.get_conn_counter(),
        });
        let acceptor = Box::new(RuntimeUdpPunchAcceptor { listener });
        let port_mapping_lease = port_mapping_lease.map(|lease| {
            Box::new(RuntimeUdpPortMappingLease {
                _inner: StdMutex::new(Some(lease)),
            }) as Box<dyn core_udp_hole_punch::UdpPortMappingLease>
        });

        Ok(core_udp_hole_punch::UdpPunchListener {
            socket,
            mapped_addr,
            conn_counter,
            acceptor,
            port_mapping_lease,
        })
    }
}

#[async_trait]
impl core_udp_hole_punch::UdpHolePunchRuntime for RuntimeUdpHolePunchRuntime {
    type Socket = RuntimeUdpSocket;

    fn stun_info(&self) -> crate::proto::common::StunInfo {
        self.global_ctx.get_stun_info_collector().get_stun_info()
    }

    async fn bind_udp(
        &self,
        options: core_udp_hole_punch::UdpBindOptions,
    ) -> anyhow::Result<Arc<Self::Socket>> {
        let bind_addr = options
            .local_addr
            .unwrap_or_else(|| SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
        let socket = {
            let _g = self.global_ctx.net_ns.guard();
            Arc::new(UdpSocket::bind(bind_addr).await?)
        };

        Ok(Arc::new(RuntimeUdpSocket::new(socket)))
    }

    async fn bind_direct_connect_udp(&self) -> anyhow::Result<Arc<Self::Socket>> {
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        Ok(Arc::new(RuntimeUdpSocket::new(socket)))
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<core_udp_hole_punch::UdpResolvedPublicAddr> {
        let local_port = socket.socket().local_addr()?.port();
        let listen_url: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();
        let (mapped_addr, port_mapping_lease) =
            upnp::resolve_udp_public_addr(self.global_ctx.clone(), &listen_url, socket.socket())
                .await?;
        let port_mapping_lease = port_mapping_lease.map(|lease| {
            Box::new(RuntimeUdpPortMappingLease {
                _inner: StdMutex::new(Some(lease)),
            }) as Box<dyn core_udp_hole_punch::UdpPortMappingLease>
        });

        Ok(core_udp_hole_punch::UdpResolvedPublicAddr {
            mapped_addr,
            port_mapping_lease,
        })
    }

    async fn get_udp_port_mapping(&self, port: u16) -> anyhow::Result<SocketAddr> {
        self.global_ctx
            .get_stun_info_collector()
            .get_udp_port_mapping(port)
            .await
            .map_err(anyhow::Error::from)
    }

    async fn create_listener(
        &self,
        _prefer_port_mapping: bool,
    ) -> anyhow::Result<core_udp_hole_punch::UdpPunchListener<Self::Socket>> {
        self.create_listener_ext(true, None).await
    }

    async fn create_port_bound_listener(
        &self,
        port: u16,
    ) -> anyhow::Result<core_udp_hole_punch::UdpPunchListener<Self::Socket>> {
        self.create_listener_ext(false, Some(port)).await
    }

    async fn connect_with_socket(
        &self,
        socket: Arc<Self::Socket>,
        remote: SocketAddr,
    ) -> anyhow::Result<Box<dyn Tunnel>> {
        try_connect_with_runtime_socket(self.global_ctx.clone(), socket, remote)
            .await
            .map_err(anyhow::Error::from)
    }
}

#[allow(dead_code)]
pub(crate) struct RuntimeUdpHolePunchTunnelSink {
    peer_mgr: Arc<PeerManager>,
}

impl RuntimeUdpHolePunchTunnelSink {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        Self { peer_mgr }
    }
}

#[async_trait]
impl core_udp_hole_punch::UdpHolePunchTunnelSink for RuntimeUdpHolePunchTunnelSink {
    async fn add_client_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        self.peer_mgr
            .add_client_tunnel(tunnel, false)
            .await
            .map(|_| ())
            .map_err(anyhow::Error::from)
    }

    async fn add_server_tunnel(&self, tunnel: Box<dyn Tunnel>) -> anyhow::Result<()> {
        self.peer_mgr
            .add_tunnel_as_server(tunnel, false)
            .await
            .map_err(anyhow::Error::from)
    }
}

pub(crate) struct RuntimeUdpHolePunchPeerSource {
    peer_mgr: Arc<PeerManager>,
    network_name: String,
}

impl RuntimeUdpHolePunchPeerSource {
    pub(crate) fn new(peer_mgr: Arc<PeerManager>) -> Self {
        let network_name = peer_mgr.get_global_ctx().get_network_name();
        Self {
            peer_mgr,
            network_name,
        }
    }
}

#[async_trait]
impl core_udp_hole_punch::UdpHolePunchPeerSource for RuntimeUdpHolePunchPeerSource {
    fn local_peer_id(&self) -> PeerId {
        self.peer_mgr.my_peer_id()
    }

    fn network_name(&self) -> &str {
        &self.network_name
    }

    fn p2p_policy_flags(&self) -> core_udp_hole_punch::P2pPolicyFlags {
        let flags = self.peer_mgr.get_global_ctx().get_flags();
        core_udp_hole_punch::P2pPolicyFlags {
            disable_udp_hole_punching: flags.disable_udp_hole_punching,
            disable_sym_hole_punching: flags.disable_sym_hole_punching,
            lazy_p2p: flags.lazy_p2p,
            disable_p2p: flags.disable_p2p,
            need_p2p: flags.need_p2p,
        }
    }

    async fn candidates(&self) -> Vec<core_udp_hole_punch::UdpPunchCandidate> {
        let now = Instant::now();
        let routes = self.peer_mgr.list_routes().await;
        routes
            .iter()
            .filter_map(|route| {
                let udp_nat_type = route
                    .stun_info
                    .as_ref()
                    .map(|info| info.udp_nat_type)
                    .unwrap_or(0);
                let Ok(udp_nat_type) = NatType::try_from(udp_nat_type) else {
                    return None;
                };

                Some(core_udp_hole_punch::UdpPunchCandidate {
                    peer_id: route.peer_id,
                    udp_nat_type,
                    feature_flag: route.feature_flag.clone(),
                    has_direct_connection: self.peer_mgr.get_peer_map().has_peer(route.peer_id),
                    has_recent_traffic: self.peer_mgr.has_recent_traffic(route.peer_id, now),
                })
            })
            .collect()
    }
}

async fn check_udp_socket_local_addr(
    global_ctx: ArcGlobalCtx,
    remote_mapped_addr: SocketAddr,
) -> Result<(), Error> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(remote_mapped_addr).await?;
    if let Ok(local_addr) = socket.local_addr()
        && let Some(err) = easytier_managed_local_addr_error(&global_ctx, local_addr)
    {
        return Err(anyhow::anyhow!(err).into());
    }

    Ok(())
}

fn easytier_managed_local_addr_error(
    global_ctx: &ArcGlobalCtx,
    local_addr: SocketAddr,
) -> Option<&'static str> {
    // local_addr should not be equal to an EasyTier-managed virtual/public address.
    match local_addr.ip() {
        IpAddr::V4(ip) if global_ctx.get_ipv4().map(|ip| ip.address()) == Some(ip) => {
            Some("local address is virtual ipv4")
        }
        IpAddr::V6(ip) if global_ctx.is_ip_easytier_managed_ipv6(&ip) => {
            Some("local address is easytier-managed ipv6")
        }
        _ => None,
    }
}

pub(crate) async fn try_connect_with_socket(
    global_ctx: ArcGlobalCtx,
    socket: Arc<UdpSocket>,
    remote_mapped_addr: SocketAddr,
) -> Result<Box<dyn Tunnel>, Error> {
    try_connect_with_runtime_socket(
        global_ctx,
        Arc::new(RuntimeUdpSocket::new(socket)),
        remote_mapped_addr,
    )
    .await
}

pub(crate) async fn try_connect_with_runtime_socket(
    global_ctx: ArcGlobalCtx,
    socket: Arc<RuntimeUdpSocket>,
    remote_mapped_addr: SocketAddr,
) -> Result<Box<dyn Tunnel>, Error> {
    let connector = UdpTunnelConnector::new(
        format!(
            "udp://{}:{}",
            remote_mapped_addr.ip(),
            remote_mapped_addr.port()
        )
        .parse()
        .unwrap(),
    );

    check_udp_socket_local_addr(global_ctx, remote_mapped_addr).await?;

    connector
        .try_connect_with_runtime_socket(socket, remote_mapped_addr)
        .await
        .map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr};

    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::{core_udp_hole_punch, easytier_managed_local_addr_error};

    #[tokio::test]
    async fn local_addr_check_rejects_easytier_public_ipv6_route() {
        let global_ctx = get_mock_global_ctx();
        let public_route: cidr::Ipv6Inet = "2001:db8::4/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([public_route]));

        let local_addr: SocketAddr = "[2001:db8::4]:1234".parse().unwrap();

        assert_eq!(
            easytier_managed_local_addr_error(&global_ctx, local_addr),
            Some("local address is easytier-managed ipv6")
        );
    }

    #[tokio::test]
    async fn runtime_adapter_can_bind_udp_socket() {
        let runtime = super::RuntimeUdpHolePunchRuntime::new(get_mock_global_ctx());

        let socket = core_udp_hole_punch::UdpHolePunchRuntime::bind_udp(
            &runtime,
            core_udp_hole_punch::UdpBindOptions::hole_punch_control(),
        )
        .await
        .unwrap();

        assert_ne!(socket.socket().local_addr().unwrap().port(), 0);
    }

    #[tokio::test]
    async fn runtime_adapter_port_bound_listener_skips_mapped_addr() {
        let runtime = super::RuntimeUdpHolePunchRuntime::new(get_mock_global_ctx());

        let listener =
            core_udp_hole_punch::UdpHolePunchRuntime::create_port_bound_listener(&runtime, 0)
                .await
                .unwrap();

        let local_port = listener.socket.socket().local_addr().unwrap().port();
        assert_ne!(local_port, 0);
        assert!(listener.mapped_addr.ip().is_unspecified());
        assert_eq!(listener.mapped_addr.port(), local_port);
        assert!(listener.port_mapping_lease.is_none());
    }

    #[test]
    fn listener_selection_prefers_reuse_before_cap() {
        assert!(!core_udp_hole_punch::should_create_public_listener(
            1, true, true, false, false
        ));
        assert!(!core_udp_hole_punch::should_create_public_listener(
            core_udp_hole_punch::MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            false,
            false
        ));
    }

    #[test]
    fn listener_selection_creates_when_empty_or_no_reusable_listener() {
        assert!(core_udp_hole_punch::should_create_public_listener(
            0, false, false, false, false
        ));
        assert!(core_udp_hole_punch::should_create_public_listener(
            1, false, false, false, false
        ));
    }

    #[test]
    fn listener_selection_force_new_respects_cap() {
        assert!(core_udp_hole_punch::should_create_public_listener(
            1, true, true, true, false
        ));
        assert!(!core_udp_hole_punch::should_create_public_listener(
            core_udp_hole_punch::MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
            true,
            true,
            true,
            false
        ));
    }

    #[test]
    fn listener_selection_prefers_port_mapping_until_available() {
        assert!(core_udp_hole_punch::should_create_public_listener(
            1, true, false, false, true
        ));
        assert!(!core_udp_hole_punch::should_create_public_listener(
            1, true, true, false, true
        ));
    }

    #[test]
    fn listener_selection_retry_respects_cap() {
        assert!(core_udp_hole_punch::should_retry_public_listener_selection(
            false, 1, false, false
        ));
        assert!(
            !core_udp_hole_punch::should_retry_public_listener_selection(
                false,
                core_udp_hole_punch::MAX_PUBLIC_UDP_HOLE_PUNCH_LISTENERS,
                false,
                false
            )
        );
        assert!(
            !core_udp_hole_punch::should_retry_public_listener_selection(true, 1, false, false)
        );
        assert!(!core_udp_hole_punch::should_retry_public_listener_selection(false, 1, true, true));
    }
}

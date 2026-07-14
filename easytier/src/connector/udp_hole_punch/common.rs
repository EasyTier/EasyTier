use std::{
    fmt::Debug,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::{Arc, Mutex as StdMutex, Weak},
};

use async_trait::async_trait;
use easytier_core::{
    hole_punch::udp as core_udp_hole_punch,
    socket::udp::{UdpSessionSocket, VirtualUdpSocket},
};
use quanta::Instant;
use tokio::net::UdpSocket;

use crate::{
    common::{PeerId, error::Error, global_ctx::ArcGlobalCtx, netns::NetNS, upnp},
    connector::core_instance::runtime_socket_context,
    peers::peer_manager::PeerManager,
    proto::common::NatType,
    socket::udp::{RuntimeUdpSessionLayer, RuntimeUdpSocket},
    tunnel::common::{BindDev, bind},
};

#[allow(dead_code)]
struct RuntimeUdpPunchAcceptor {
    layer: Arc<RuntimeUdpSessionLayer>,
}

#[async_trait]
impl core_udp_hole_punch::UdpPunchAcceptor for RuntimeUdpPunchAcceptor {
    async fn accept(&mut self) -> anyhow::Result<core_udp_hole_punch::UdpPunchSocket> {
        let session = self.layer.accept().await?;
        let remote_addr = session.peer_addr()?;
        Ok(core_udp_hole_punch::UdpPunchSocket::new(
            session,
            remote_addr,
            self.layer.clone(),
        ))
    }
}

#[allow(dead_code)]
struct RuntimeUdpPunchConnCounter {
    layer: Weak<RuntimeUdpSessionLayer>,
}

impl core_udp_hole_punch::UdpPunchConnCounter for RuntimeUdpPunchConnCounter {
    fn get(&self) -> Option<u32> {
        Some(
            self.layer
                .upgrade()
                .map(|layer| layer.active_session_count() as u32)
                .unwrap_or(0),
        )
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
        }
        .with_context(
            runtime_socket_context(&self.global_ctx)
                .with_ip_version(easytier_core::socket::IpVersion::V4),
        );
        let socket = core_udp_hole_punch::UdpHolePunchRuntime::bind_udp(self, bind_options).await?;
        let local_port = socket.socket().local_addr()?.port();
        let listen_url: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();

        let (mapped_addr, port_mapping_lease) = if with_mapped_addr {
            upnp::resolve_udp_public_addr(self.global_ctx.clone(), &listen_url, socket.clone())
                .await?
        } else {
            (
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, local_port)),
                None,
            )
        };

        let layer = socket.udp_session_layer();
        let conn_counter = Arc::new(RuntimeUdpPunchConnCounter {
            layer: Arc::downgrade(&layer),
        });
        let acceptor = Box::new(RuntimeUdpPunchAcceptor { layer });
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

    fn socket_context(&self) -> easytier_core::socket::SocketContext {
        runtime_socket_context(&self.global_ctx)
    }

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
        let bind_device = options
            .bind_device
            .map(BindDev::from)
            .unwrap_or(BindDev::Disabled);
        let socket = {
            Arc::new(
                bind::<UdpSocket>()
                    .addr(bind_addr)
                    .dev(bind_device)
                    .maybe_net_ns(Some(NetNS::from_socket_context(&options.context)))
                    .only_v6(options.only_v6)
                    .reuse_addr(options.reuse_addr)
                    .reuse_port(options.reuse_port)
                    .maybe_socket_mark(options.context.socket_mark)
                    .call()?,
            )
        };

        Ok(Arc::new(RuntimeUdpSocket::new_with_context(
            socket,
            options.context,
        )))
    }

    async fn resolve_udp_public_addr(
        &self,
        socket: Arc<Self::Socket>,
    ) -> anyhow::Result<core_udp_hole_punch::UdpResolvedPublicAddr> {
        let local_port = socket.socket().local_addr()?.port();
        let listen_url: url::Url = format!("udp://0.0.0.0:{local_port}").parse().unwrap();
        let (mapped_addr, port_mapping_lease) =
            upnp::resolve_udp_public_addr(self.global_ctx.clone(), &listen_url, socket.clone())
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
    ) -> anyhow::Result<core_udp_hole_punch::UdpPunchSocket> {
        check_udp_socket_local_addr(self.global_ctx.clone(), socket.socket_context(), remote)
            .await?;

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(socket.socket().as_ref())?;

        let layer = socket.udp_session_layer();
        let session = layer.connect(remote).await?;
        if session.peer_addr()? != remote {
            tracing::debug!(
                recv_addr = ?session.peer_addr()?,
                ?remote,
                "udp connect addr not match"
            );
        }

        Ok(core_udp_hole_punch::UdpPunchSocket::new(
            session, remote, layer,
        ))
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
                    has_direct_connection: self
                        .peer_mgr
                        .core()
                        .get_peer_map()
                        .has_peer(route.peer_id),
                    has_recent_traffic: self.peer_mgr.core().has_recent_traffic(route.peer_id, now),
                })
            })
            .collect()
    }
}

async fn check_udp_socket_local_addr(
    global_ctx: ArcGlobalCtx,
    context: easytier_core::socket::SocketContext,
    remote_mapped_addr: SocketAddr,
) -> Result<(), Error> {
    let socket = bind::<UdpSocket>()
        .addr("0.0.0.0:0".parse().unwrap())
        .maybe_net_ns(Some(NetNS::from_socket_context(&context)))
        .maybe_socket_mark(context.socket_mark)
        .call()?;
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, net::SocketAddr};

    use easytier_core::socket::{IpVersion, SocketContext, udp::VirtualUdpSocket};

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
        let context = SocketContext::default()
            .with_ip_version(IpVersion::V4)
            .with_socket_mark(Some(0));

        let socket = core_udp_hole_punch::UdpHolePunchRuntime::bind_udp(
            &runtime,
            core_udp_hole_punch::UdpBindOptions::hole_punch_control().with_context(context.clone()),
        )
        .await
        .unwrap();

        assert_ne!(socket.socket().local_addr().unwrap().port(), 0);
        assert_eq!(socket.socket_context(), context);
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

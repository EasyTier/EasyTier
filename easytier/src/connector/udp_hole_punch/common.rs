use std::sync::Arc;

use async_trait::async_trait;
use easytier_core::{
    hole_punch::udp as core_udp_hole_punch,
    instance::udp_hole_punch::{CoreUdpHolePunchRuntime, UdpHolePunchPlatform},
};
use quanta::Instant;

use crate::{
    common::{PeerId, global_ctx::ArcGlobalCtx, upnp},
    connector::{
        core_instance::runtime_socket_context,
        runtime::{RuntimeConnectorHost, runtime_connector_host},
    },
    peers::peer_manager::PeerManager,
    proto::common::NatType,
};

pub(crate) type RuntimeUdpHolePunchRuntime = CoreUdpHolePunchRuntime<RuntimeConnectorHost>;

#[async_trait]
impl UdpHolePunchPlatform for RuntimeUdpHolePunchPlatform {
    async fn start_udp_port_mapping(
        &self,
        local_listener: &url::Url,
    ) -> anyhow::Result<Option<Box<dyn core_udp_hole_punch::UdpPortMappingLease>>> {
        Ok(
            upnp::start_udp_port_mapping(&self.global_ctx, local_listener)
                .await?
                .map(|lease| Box::new(lease) as Box<dyn core_udp_hole_punch::UdpPortMappingLease>),
        )
    }
}

struct RuntimeUdpHolePunchPlatform {
    global_ctx: ArcGlobalCtx,
}

pub(crate) fn runtime_udp_hole_punch_runtime(
    peer_mgr: &Arc<PeerManager>,
) -> Arc<RuntimeUdpHolePunchRuntime> {
    let global_ctx = peer_mgr.get_global_ctx();
    Arc::new(CoreUdpHolePunchRuntime::new(
        runtime_connector_host(global_ctx.clone()),
        peer_mgr.core(),
        global_ctx.get_stun_info_collector(),
        Arc::new(RuntimeUdpHolePunchPlatform {
            global_ctx: global_ctx.clone(),
        }),
        runtime_socket_context(&global_ctx),
    ))
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
            disable_upnp: flags.disable_upnp,
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

#[cfg(test)]
mod tests {
    use easytier_core::socket::{IpVersion, SocketContext, udp::VirtualUdpSocket};

    use crate::peers::tests::create_mock_peer_manager;

    use super::{core_udp_hole_punch, runtime_udp_hole_punch_runtime};

    #[tokio::test]
    async fn runtime_adapter_can_bind_udp_socket() {
        let peer_manager = create_mock_peer_manager().await;
        let runtime = runtime_udp_hole_punch_runtime(&peer_manager);
        let context = SocketContext::default()
            .with_ip_version(IpVersion::V4)
            .with_socket_mark(Some(0));

        let socket = core_udp_hole_punch::UdpHolePunchRuntime::bind_udp(
            runtime.as_ref(),
            core_udp_hole_punch::UdpBindOptions::hole_punch_control().with_context(context.clone()),
        )
        .await
        .unwrap();

        assert_ne!(socket.socket().local_addr().unwrap().port(), 0);
        assert_eq!(socket.socket_context(), context);
    }

    #[tokio::test]
    async fn runtime_adapter_port_bound_listener_skips_mapped_addr() {
        let peer_manager = create_mock_peer_manager().await;
        let runtime = runtime_udp_hole_punch_runtime(&peer_manager);

        let listener = core_udp_hole_punch::UdpHolePunchRuntime::create_port_bound_listener(
            runtime.as_ref(),
            0,
        )
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

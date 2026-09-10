use crate::{
    events::{CoreEvent, CoreEventSink},
    wasi::imports::emit_event,
};

#[derive(Debug)]
pub struct WasiHostEventSink {
    handle: u64,
}

impl WasiHostEventSink {
    pub fn new(handle: u64) -> Self {
        Self { handle }
    }
}

impl CoreEventSink for WasiHostEventSink {
    fn emit(&self, event: CoreEvent) {
        let kind = event_kind(&event);
        let message = format!("{event:?}");
        let _ = unsafe {
            emit_event(
                self.handle,
                kind.as_ptr() as u32,
                kind.len() as u32,
                message.as_ptr() as u32,
                message.len() as u32,
            )
        };
    }
}

fn event_kind(event: &CoreEvent) -> &'static str {
    match event {
        CoreEvent::PeerAdded(_) => "peer_added",
        CoreEvent::PeerRemoved(_) => "peer_removed",
        CoreEvent::PeerConnAdded(_) => "peer_connection_added",
        CoreEvent::PeerConnRemoved(_) => "peer_connection_removed",
        CoreEvent::CredentialChanged => "credential_changed",
        CoreEvent::ManualConnecting { .. } => "connecting",
        CoreEvent::ManualConnectError { .. } => "connect_error",
        CoreEvent::ListenerPlanFailed { .. } => "listener_plan_failed",
        CoreEvent::ListenerAdded { .. } => "listener_added",
        CoreEvent::ListenerRemoved { .. } => "listener_removed",
        CoreEvent::ListenerAddFailed { .. } => "listener_add_failed",
        CoreEvent::ListenerAcceptFailed { .. } => "listener_accept_failed",
        CoreEvent::ListenerSocketAccepted { .. } => "listener_socket_accepted",
        CoreEvent::ListenerAcceptedSocketHandleFailed { .. } => "listener_socket_handle_failed",
        CoreEvent::TunnelAccepted { .. } => "tunnel_accepted",
        CoreEvent::TunnelAdmissionFailed { .. } => "tunnel_admission_failed",
        CoreEvent::UdpPortMappingEstablished { .. } => "udp_port_mapping_established",
        CoreEvent::ProxyCidrsUpdated { .. } => "proxy_cidrs_updated",
        CoreEvent::PublicIpv6LeaseChanged { .. } => "public_ipv6_lease_changed",
        CoreEvent::PublicIpv6RoutesChanged { .. } => "public_ipv6_routes_changed",
        CoreEvent::VpnPortalStarted(_) => "vpn_portal_started",
        CoreEvent::VpnPortalClientConnected { .. } => "vpn_portal_client_connected",
        CoreEvent::VpnPortalClientDisconnected { .. } => "vpn_portal_client_disconnected",
        CoreEvent::GatewayPortForwardAdded(_) => "gateway_port_forward_added",
    }
}

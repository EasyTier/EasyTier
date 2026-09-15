use std::sync::Arc;

use cidr::{Ipv4Cidr, Ipv6Inet};
use url::Url;

use crate::{
    config::{PeerId, gateway::PortForwardConfig},
    socket::{IpVersion, ListenerConnectionCounter},
};

/// Notifications emitted by the portable core runtime to its host.
#[derive(Debug, Clone)]
pub enum CoreEvent {
    PeerAdded(PeerId),
    PeerRemoved(PeerId),
    PeerConnAdded(easytier_proto::core_peer::peer::PeerConnInfo),
    PeerConnRemoved(easytier_proto::core_peer::peer::PeerConnInfo),
    CredentialChanged,

    ManualConnecting {
        url: Url,
    },
    ManualConnectError {
        url: Url,
        ip_version: IpVersion,
        error: String,
    },

    ListenerPlanFailed {
        url: Url,
        error: String,
    },
    ListenerAdded {
        url: Url,
        connection_counter: Arc<dyn ListenerConnectionCounter>,
    },
    ListenerRemoved {
        url: Url,
    },
    ListenerAddFailed {
        url: Url,
        error: String,
        retry_count: usize,
        will_retry: bool,
    },
    ListenerAcceptFailed {
        url: Url,
        error: String,
    },
    ListenerSocketAccepted {
        url: Url,
    },
    ListenerAcceptedSocketHandleFailed {
        url: Url,
        error: String,
    },

    TunnelAccepted {
        local_url: String,
        remote_url: String,
    },
    TunnelAdmissionFailed {
        local_url: String,
        remote_url: String,
        error: String,
    },
    UdpPortMappingEstablished {
        local_listener: Url,
        mapped_listener: Url,
        backend: String,
    },

    ProxyCidrsUpdated {
        added: Vec<Ipv4Cidr>,
        removed: Vec<Ipv4Cidr>,
    },
    PublicIpv6LeaseChanged {
        old: Option<Ipv6Inet>,
        new: Option<Ipv6Inet>,
    },
    PublicIpv6RoutesChanged {
        added: Vec<Ipv6Inet>,
        removed: Vec<Ipv6Inet>,
    },

    VpnPortalStarted(String),
    VpnPortalClientConnected {
        portal: String,
        client: String,
    },
    VpnPortalClientDisconnected {
        portal: String,
        client: String,
    },
    GatewayPortForwardAdded(PortForwardConfig),
}

pub trait CoreEventSink: Send + Sync + 'static {
    fn emit(&self, event: CoreEvent);
}

impl CoreEventSink for () {
    fn emit(&self, _event: CoreEvent) {}
}

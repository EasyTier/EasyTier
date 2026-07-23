//! Packet-plane features: the gateway dataplane, proxy services, and the
//! instance-level network services. See `CONTEXT.md` "Gateway dataplane"
//! and "Module layers".

#[cfg(feature = "proxy-smoltcp-stack")]
mod dataplane;
pub mod dhcp;
pub mod magic_dns;
pub mod proxy;
#[cfg(feature = "proxy-smoltcp-stack")]
mod smoltcp;
#[cfg(feature = "proxy-smoltcp-stack")]
mod socks5;
#[cfg(feature = "proxy-packet")]
pub mod udp_broadcast;
pub mod vpn_portal;

#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use dataplane::GatewayModule;
#[cfg(feature = "proxy-smoltcp-stack")]
pub use dataplane::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

use crate::config::gateway::PortForwardConfig;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayEvent {
    PortForwardAdded(PortForwardConfig),
}

pub trait GatewayEventSink: Send + Sync + 'static {
    fn emit(&self, event: GatewayEvent);
}

impl GatewayEventSink for () {
    fn emit(&self, _event: GatewayEvent) {}
}

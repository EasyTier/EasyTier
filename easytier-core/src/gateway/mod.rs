//! Packet-plane features: the gateway dataplane, proxy services, and the
//! instance-level network services. See `CONTEXT.md` "Gateway dataplane"
//! and "Module layers".

mod config;
pub mod dhcp;
pub mod magic_dns;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) mod module;
pub mod proxy;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) mod socks5;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) mod stack;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) mod tokio_smoltcp;
#[cfg(feature = "proxy-packet")]
pub mod udp_broadcast;
pub mod vpn_portal;

pub use config::{GatewayRuntimeConfig, PortForwardConfig};
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use module::GatewayModule;
#[cfg(feature = "proxy-smoltcp-stack")]
pub use module::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

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

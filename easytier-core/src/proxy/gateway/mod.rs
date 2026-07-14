mod config;

#[cfg(feature = "proxy-smoltcp-stack")]
mod runtime;

pub use config::{GatewayRuntimeConfig, PortForwardConfig};
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use runtime::GatewayModule;
#[cfg(feature = "proxy-smoltcp-stack")]
pub use runtime::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

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

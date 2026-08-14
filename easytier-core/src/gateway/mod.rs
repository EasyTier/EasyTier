//! Packet-plane features: the gateway dataplane, proxy services, and the
//! instance-level network services. See `CONTEXT.md` "Gateway dataplane"
//! and "Module layers".

#[cfg(feature = "proxy-smoltcp-stack")]
mod dataplane;
pub mod dhcp;
pub mod magic_dns;
#[cfg(feature = "proxy-smoltcp-stack")]
mod port_forward;
pub mod proxy;
#[cfg(feature = "proxy-smoltcp-stack")]
mod smoltcp;
#[cfg(feature = "proxy-smoltcp-stack")]
mod socks5;
#[cfg(feature = "proxy-packet")]
pub mod udp_broadcast;
pub mod vpn_portal;

#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use dataplane::DataPlaneRuntime;
#[cfg(feature = "proxy-smoltcp-stack")]
pub use dataplane::{
    DataPlaneCompletionDescriptor, DataPlaneCompletionStatus, DataPlaneError, DataPlaneErrorKind,
    DataPlaneOperationId, DataPlaneOperationKind, DataPlaneOperationOutcome,
    DataPlaneOperationResult, DataPlaneResourceId, DataPlaneSession, DataPlaneSessionLimits,
    DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket,
};
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use port_forward::PortForwardAdapter;
#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use socks5::Socks5GatewayAdapter;

//! Packet-plane features: the gateway dataplane, proxy services, and the
//! instance-level network services. See `CONTEXT.md` "Gateway dataplane"
//! and "Module layers".

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

#[cfg(feature = "proxy-smoltcp-stack")]
pub(crate) use module::GatewayModule;
#[cfg(feature = "proxy-smoltcp-stack")]
pub use module::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

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

#[derive(Clone)]
pub struct UdpBroadcastRelayStats {
    packets_captured: crate::foundation::stats::CounterHandle,
    packets_ignored: crate::foundation::stats::CounterHandle,
    packets_forwarded: crate::foundation::stats::CounterHandle,
    packets_forward_failed: crate::foundation::stats::CounterHandle,
}

impl UdpBroadcastRelayStats {
    pub(crate) fn new(
        packets_captured: crate::foundation::stats::CounterHandle,
        packets_ignored: crate::foundation::stats::CounterHandle,
        packets_forwarded: crate::foundation::stats::CounterHandle,
        packets_forward_failed: crate::foundation::stats::CounterHandle,
    ) -> Self {
        Self {
            packets_captured,
            packets_ignored,
            packets_forwarded,
            packets_forward_failed,
        }
    }

    pub fn record_captured(&self) {
        self.packets_captured.inc();
    }

    pub fn record_ignored(&self) {
        self.packets_ignored.inc();
    }

    pub fn record_forwarded(&self) {
        self.packets_forwarded.inc();
    }

    pub fn record_forward_failed(&self) {
        self.packets_forward_failed.inc();
    }
}

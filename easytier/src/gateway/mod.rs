use std::net::IpAddr;

use easytier_core::proxy::runtime::WrappedTcpDestinationRuntime;

use crate::common::global_ctx::ArcGlobalCtx;

pub mod icmp_proxy;
pub mod tcp_proxy;

#[cfg(feature = "socks5")]
pub mod fast_socks5;
#[cfg(feature = "socks5")]
pub mod socks5;

#[cfg(feature = "kcp")]
pub mod kcp_proxy;

#[cfg(feature = "quic")]
pub mod quic_proxy;

pub(crate) struct RuntimeWrappedTcpDestinationAdapter {
    global_ctx: ArcGlobalCtx,
}

impl RuntimeWrappedTcpDestinationAdapter {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self { global_ctx }
    }
}

impl WrappedTcpDestinationRuntime for RuntimeWrappedTcpDestinationAdapter {
    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
    }

    fn no_tun(&self) -> bool {
        self.global_ctx.no_tun()
    }

    fn should_deny_tcp_proxy(&self, dst: std::net::SocketAddr) -> bool {
        self.global_ctx.should_deny_proxy(&dst, false)
    }
}

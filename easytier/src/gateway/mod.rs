#[cfg(any(feature = "kcp", feature = "quic"))]
mod hedge;

pub mod icmp_proxy;
pub mod tcp_proxy;

#[cfg(feature = "kcp")]
pub mod kcp_proxy;

#[cfg(feature = "quic")]
pub mod quic_proxy;

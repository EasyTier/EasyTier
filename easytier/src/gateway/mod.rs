#[cfg(any(feature = "kcp", feature = "quic"))]
mod hedge;

#[cfg(all(not(test), feature = "icmp-proxy"))]
pub mod icmp_proxy;

#[cfg(feature = "kcp")]
pub mod kcp_proxy;

#[cfg(feature = "quic")]
pub mod quic_proxy;

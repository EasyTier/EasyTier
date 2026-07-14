pub mod icmp_proxy;
pub mod tcp_proxy;

#[cfg(all(test, feature = "socks5"))]
mod tests;

#[cfg(feature = "socks5")]
#[cfg(feature = "kcp")]
pub mod kcp_proxy;

#[cfg(feature = "quic")]
pub mod quic_proxy;

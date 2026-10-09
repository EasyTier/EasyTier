pub mod buf;
#[cfg(feature = "management")]
pub mod panic;
pub mod string;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Weak};

#[cfg(feature = "management")]
pub type PeerRoutePair = crate::proto::api::instance::PeerRoutePair;

/// Select the process-wide TLS backend before starting application services.
pub fn init_crypto_provider() {
    #[cfg(any(
        feature = "endpoint-discovery",
        feature = "quic",
        feature = "websocket"
    ))]
    {
        // Cargo features are additive: another dependency can enable aws-lc
        // alongside ring, making rustls's automatic selection panic (#2607).
        // Keep an existing provider chosen by an embedding application.
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub fn check_tcp_available(port: u16) -> bool {
    let s = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    TcpListener::bind(s).is_ok()
}

pub fn find_free_tcp_port(mut range: std::ops::Range<u16>) -> Option<u16> {
    range.find(|&port| check_tcp_available(port))
}

pub fn weak_upgrade<T>(weak: &Weak<T>) -> anyhow::Result<Arc<T>> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("{} not available", std::any::type_name::<T>()))
}

pub trait BoxExt: Sized {
    fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl<T> BoxExt for T {}

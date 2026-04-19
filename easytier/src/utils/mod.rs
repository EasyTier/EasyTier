pub mod dirty;
pub mod dns;
pub mod panic;
pub mod string;
pub mod task;

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{Arc, Weak};

pub type PeerRoutePair = crate::proto::api::instance::PeerRoutePair;

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

pub fn hostname() -> String {
    hostname::get()
        .unwrap_or_else(|_| "localhost".into())
        .to_string_lossy()
        .into_owned()
}

pub trait BoxExt: Sized {
    fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl<T> BoxExt for T {}

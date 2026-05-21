pub mod error;
pub mod panic;
pub mod string;
pub mod task;

use shlex::split;
use std::ffi::OsStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::process::Output;
use std::sync::{Arc, Weak};
use tokio::process::Command;

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

pub trait BoxExt: Sized {
    fn boxed(self) -> Box<Self> {
        Box::new(self)
    }
}

impl<T> BoxExt for T {}

pub async fn execute<E, K, V>(command: impl AsRef<str>, environment: E) -> io::Result<Output>
where
    E: IntoIterator<Item = (K, V)>,
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
{
    let args = split(command.as_ref())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "failed to parse command"))?;
    let (program, args) = args
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty command"))?;
    Command::new(program)
        .args(args)
        .envs(environment)
        .kill_on_drop(true)
        .output()
        .await
}

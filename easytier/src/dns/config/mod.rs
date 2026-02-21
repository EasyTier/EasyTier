use crate::dns::utils::NameServerAddr;
use hickory_proto::rr::LowerName;
use hickory_proto::xfer::Protocol;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;
use url::Url;

mod dns;
pub use dns::*;
mod policy;
mod zone;

pub const DNS_DEFAULT_ADDRESS: NameServerAddr = NameServerAddr {
    protocol: Protocol::Udp,
    addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53)),
};
pub static DNS_DEFAULT_TLD: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());
pub static DNS_SERVER_RPC_ADDR: LazyLock<Url> =
    LazyLock::new(|| Url::parse("tcp://127.0.0.1:49813").unwrap());
pub(super) static DNS_SUPPORTED_PROTOCOLS: [Protocol; 2] = [
    Protocol::Udp,
    Protocol::Tcp,
    // Protocol::Tls,
    // Protocol::Https,
    // Protocol::Quic,
    // Protocol::H3,
];

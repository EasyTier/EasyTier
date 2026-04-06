use crate::dns::utils::addr::NameServerAddr;
use hickory_proto::rr::LowerName;
use hickory_proto::xfer::Protocol;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;
use std::time::Duration;
use url::Url;

mod dns;
pub use dns::*;
mod policy;
pub mod zone;

pub static DNS_DEFAULT_DOMAIN: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());
pub const DNS_DEFAULT_ADDRESS: NameServerAddr = NameServerAddr {
    protocol: Protocol::Udp,
    addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53)),
};

pub static DNS_SUPPORTED_PROTOCOLS: [Protocol; 2] = [
    Protocol::Udp,
    Protocol::Tcp,
    // Protocol::Tls,
    // Protocol::Https,
    // Protocol::Quic,
    // Protocol::H3,
];

pub static DNS_SERVER_RPC_ADDR: LazyLock<Url> =
    LazyLock::new(|| Url::parse("tcp://127.0.0.1:49813").unwrap());

pub const DNS_NODE_TTI: Duration = Duration::from_secs(5);

pub const DNS_NODE_RR_INTERVAL: Duration = Duration::from_secs(1);
pub const DNS_SERVER_ELECTION_INTERVAL: Duration = Duration::from_secs(5);
pub const DNS_PEER_TTI: Duration = Duration::from_secs(3);

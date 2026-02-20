use crate::dns::utils::NameServerAddr;
use hickory_proto::rr::LowerName;
use hickory_proto::xfer::Protocol;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::LazyLock;
use url::Url;

pub const DNS_DEFAULT_ADDRESS: NameServerAddr = NameServerAddr {
    protocol: Protocol::Udp,
    addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(100, 100, 100, 101), 53)),
};
pub static DNS_DEFAULT_TLD: LazyLock<LowerName> =
    LazyLock::new(|| LowerName::from_str("et.net.").unwrap());
pub static DNS_SERVER_RPC_ADDR: LazyLock<Url> =
    LazyLock::new(|| Url::parse("tcp://127.0.0.1:49813").unwrap());

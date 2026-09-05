//
// Port supporting code for wireguard-nt from wireguard-windows v0.5.3 to Rust
// This file replicates parts of wireguard-windows/tunnel/winipcfg/types.go
//

use cidr::{Ipv4Inet, Ipv6Inet};
use std::net::{Ipv4Addr, Ipv6Addr};
use winapi::shared::ws2def::*;
use winapi::shared::ws2ipdef::*;

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct RouteDataIpv4 {
    pub destination: Ipv4Inet,
    pub next_hop: Ipv4Addr,
    pub metric: u32,
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub struct RouteDataIpv6 {
    pub destination: Ipv6Inet,
    pub next_hop: Ipv6Addr,
    pub metric: u32,
}

/// This function converts std::net::Ipv4Addr to winapi::shared::inaddr::in_addr
#[inline]
pub fn convert_ipv4addr_to_inaddr(ip: &Ipv4Addr) -> winapi::shared::inaddr::in_addr {
    let mut winaddr = winapi::shared::inaddr::in_addr::default();

    let s_un_b = unsafe { winaddr.S_un.S_un_b_mut() };
    s_un_b.s_b1 = ip.octets()[0];
    s_un_b.s_b2 = ip.octets()[1];
    s_un_b.s_b3 = ip.octets()[2];
    s_un_b.s_b4 = ip.octets()[3];

    winaddr
}

/// This function converts std::net::Ipv6Addr to winapi::shared::in6addr::in6_addr
#[inline]
pub fn convert_ipv6addr_to_inaddr(ip: &Ipv6Addr) -> winapi::shared::in6addr::in6_addr {
    let mut winaddr = winapi::shared::in6addr::in6_addr::default();
    let octets = ip.octets();
    for (i, &octet) in octets.iter().enumerate() {
        unsafe { winaddr.u.Byte_mut()[i] = octet };
    }
    winaddr
}

/// This function converts std::net::Ipv4Addr to winapi::shared::ws2def::SOCKADDR_IN
pub fn convert_ipv4addr_to_sockaddr(ip: &Ipv4Addr) -> SOCKADDR_IN {
    SOCKADDR_IN {
        sin_family: AF_INET as ADDRESS_FAMILY,
        sin_addr: convert_ipv4addr_to_inaddr(ip),
        ..Default::default()
    }
}

/// This function converts ipnet::Ipv6Addr to winapi::shared::ws2ipdef::SOCKADDR_IN6
pub fn convert_ipv6addr_to_sockaddr(ip: &Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6 as ADDRESS_FAMILY,
        sin6_addr: convert_ipv6addr_to_inaddr(ip),
        ..Default::default()
    }
}

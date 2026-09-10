use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

pub(crate) const SOCKET_ADDRESS_LEN: usize = 27;
pub(crate) const UDP_METADATA_LEN: usize = 48;

const V4_FAMILY: u8 = 4;
const V6_FAMILY: u8 = 6;
const ADDRESS_FAMILY: usize = 0;
const ADDRESS_BYTES: std::ops::Range<usize> = 1..17;
const PORT_BYTES: std::ops::Range<usize> = 17..19;
const FLOWINFO_BYTES: std::ops::Range<usize> = 19..23;
const SCOPE_ID_BYTES: std::ops::Range<usize> = 23..27;
const OPTIONAL_IP_FAMILY: usize = 27;
const OPTIONAL_IP_BYTES: std::ops::Range<usize> = 28..44;
const OPTIONAL_IFINDEX_BYTES: std::ops::Range<usize> = 44..48;

pub(crate) fn encode_udp_metadata(
    peer_addr: SocketAddr,
    optional_ip: Option<IpAddr>,
    optional_ifindex: Option<u32>,
) -> [u8; UDP_METADATA_LEN] {
    let mut wire = [0_u8; UDP_METADATA_LEN];
    wire[..SOCKET_ADDRESS_LEN].copy_from_slice(&encode_socket_address(peer_addr));

    match optional_ip {
        None => {}
        Some(IpAddr::V4(ip)) => {
            wire[OPTIONAL_IP_FAMILY] = V4_FAMILY;
            wire[OPTIONAL_IP_BYTES.start..OPTIONAL_IP_BYTES.start + 4]
                .copy_from_slice(&ip.octets());
        }
        Some(IpAddr::V6(ip)) => {
            wire[OPTIONAL_IP_FAMILY] = V6_FAMILY;
            wire[OPTIONAL_IP_BYTES].copy_from_slice(&ip.octets());
        }
    }
    if let Some(ifindex) = optional_ifindex {
        wire[OPTIONAL_IFINDEX_BYTES].copy_from_slice(&ifindex.to_be_bytes());
    }
    wire
}

pub(crate) fn encode_socket_address(addr: SocketAddr) -> [u8; SOCKET_ADDRESS_LEN] {
    let mut wire = [0_u8; SOCKET_ADDRESS_LEN];
    match addr {
        SocketAddr::V4(addr) => {
            wire[ADDRESS_FAMILY] = V4_FAMILY;
            wire[ADDRESS_BYTES.start..ADDRESS_BYTES.start + 4].copy_from_slice(&addr.ip().octets());
            wire[PORT_BYTES].copy_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            wire[ADDRESS_FAMILY] = V6_FAMILY;
            wire[ADDRESS_BYTES].copy_from_slice(&addr.ip().octets());
            wire[PORT_BYTES].copy_from_slice(&addr.port().to_be_bytes());
            wire[FLOWINFO_BYTES].copy_from_slice(&addr.flowinfo().to_be_bytes());
            wire[SCOPE_ID_BYTES].copy_from_slice(&addr.scope_id().to_be_bytes());
        }
    }
    wire
}

pub(crate) fn decode_udp_metadata(
    wire: &[u8; UDP_METADATA_LEN],
) -> io::Result<(SocketAddr, Option<IpAddr>, Option<u32>)> {
    let address = <[u8; SOCKET_ADDRESS_LEN]>::try_from(&wire[..SOCKET_ADDRESS_LEN]).unwrap();
    let peer_addr = decode_socket_address(&address)?;

    let optional_ip = match wire[OPTIONAL_IP_FAMILY] {
        0 => {
            require_zero(&wire[OPTIONAL_IP_BYTES], "absent optional IP")?;
            require_zero(
                &wire[OPTIONAL_IFINDEX_BYTES],
                "absent optional IP interface index",
            )?;
            None
        }
        V4_FAMILY => {
            require_zero(
                &wire[OPTIONAL_IP_BYTES.start + 4..OPTIONAL_IP_BYTES.end],
                "optional IPv4 padding",
            )?;
            require_zero(
                &wire[OPTIONAL_IFINDEX_BYTES],
                "optional IPv4 interface index",
            )?;
            Some(IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(&wire[OPTIONAL_IP_BYTES.start..OPTIONAL_IP_BYTES.start + 4])
                    .unwrap(),
            )))
        }
        V6_FAMILY => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&wire[OPTIONAL_IP_BYTES]).unwrap(),
        ))),
        family => return Err(invalid_family("optional IP", family)),
    };
    let optional_ifindex =
        match u32::from_be_bytes(wire[OPTIONAL_IFINDEX_BYTES].try_into().unwrap()) {
            0 => None,
            ifindex => Some(ifindex),
        };
    Ok((peer_addr, optional_ip, optional_ifindex))
}

pub(crate) fn decode_socket_address(wire: &[u8; SOCKET_ADDRESS_LEN]) -> io::Result<SocketAddr> {
    let port = u16::from_be_bytes(wire[PORT_BYTES].try_into().unwrap());
    match wire[ADDRESS_FAMILY] {
        V4_FAMILY => {
            require_zero(
                &wire[ADDRESS_BYTES.start + 4..ADDRESS_BYTES.end],
                "IPv4 padding",
            )?;
            require_zero(&wire[FLOWINFO_BYTES], "IPv4 flowinfo")?;
            require_zero(&wire[SCOPE_ID_BYTES], "IPv4 scope ID")?;
            Ok(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::from(
                    <[u8; 4]>::try_from(&wire[ADDRESS_BYTES.start..ADDRESS_BYTES.start + 4])
                        .unwrap(),
                ),
                port,
            )))
        }
        V6_FAMILY => Ok(SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(<[u8; 16]>::try_from(&wire[ADDRESS_BYTES]).unwrap()),
            port,
            u32::from_be_bytes(wire[FLOWINFO_BYTES].try_into().unwrap()),
            u32::from_be_bytes(wire[SCOPE_ID_BYTES].try_into().unwrap()),
        ))),
        family => Err(invalid_family("peer address", family)),
    }
}

fn require_zero(bytes: &[u8], field: &str) -> io::Result<()> {
    if bytes.iter().all(|byte| *byte == 0) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("host UDP metadata has nonzero {field}"),
        ))
    }
}

fn invalid_family(field: &str, family: u8) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("host UDP metadata has invalid {field} family {family}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_ipv4_address_and_optional_source() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 11013));
        let source = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)));
        let expected = [
            0x04, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x2b, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
            0xc6, 0x33, 0x64, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(encode_udp_metadata(peer, source, None), expected);
        assert_eq!(
            decode_udp_metadata(&expected).unwrap(),
            (peer, source, None)
        );
    }

    #[test]
    fn round_trips_ipv6_flow_scope_and_optional_destination() {
        let peer = SocketAddr::V6(SocketAddrV6::new(
            "2001:db8::1".parse().unwrap(),
            22026,
            7,
            11,
        ));
        let destination = Some(IpAddr::V6("2001:db8::2".parse().unwrap()));
        assert_eq!(
            decode_udp_metadata(&encode_udp_metadata(peer, destination, Some(17))).unwrap(),
            (peer, destination, Some(17))
        );
    }

    #[test]
    fn rejects_noncanonical_or_unknown_families() {
        let mut wire = encode_udp_metadata("192.0.2.1:11013".parse().unwrap(), None, None);
        wire[ADDRESS_BYTES.start + 4] = 1;
        assert!(decode_udp_metadata(&wire).is_err());

        wire = encode_udp_metadata("192.0.2.1:11013".parse().unwrap(), None, None);
        wire[OPTIONAL_IP_FAMILY] = 9;
        assert!(decode_udp_metadata(&wire).is_err());

        wire = encode_udp_metadata(
            "192.0.2.1:11013".parse().unwrap(),
            Some("192.0.2.2".parse().unwrap()),
            None,
        );
        wire[OPTIONAL_IFINDEX_BYTES.end - 1] = 1;
        assert!(decode_udp_metadata(&wire).is_err());
    }
}

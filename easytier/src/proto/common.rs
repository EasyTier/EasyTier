use std::str::FromStr;

include!(concat!(env!("OUT_DIR"), "/common.rs"));

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        let (high, low) = uuid.as_u64_pair();
        Uuid { low, high }
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> Self {
        uuid::Uuid::from_u64_pair(uuid.high, uuid.low)
    }
}

impl ToString for Uuid {
    fn to_string(&self) -> String {
        uuid::Uuid::from(self.clone()).to_string()
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(value: std::net::Ipv4Addr) -> Self {
        Self {
            addr: value.to_bits(),
        }
    }
}

impl From<Ipv4Addr> for std::net::Ipv4Addr {
    fn from(value: Ipv4Addr) -> Self {
        std::net::Ipv4Addr::from(value.addr)
    }
}

impl ToString for Ipv4Addr {
    fn to_string(&self) -> String {
        std::net::Ipv4Addr::from(self.addr).to_string()
    }
}

impl From<std::net::Ipv6Addr> for Ipv6Addr {
    fn from(value: std::net::Ipv6Addr) -> Self {
        let b = value.octets();
        Self {
            low: u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
            high: u64::from_be_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        }
    }
}

impl From<Ipv6Addr> for std::net::Ipv6Addr {
    fn from(value: Ipv6Addr) -> Self {
        let low = value.low.to_be_bytes();
        let high = value.high.to_be_bytes();
        std::net::Ipv6Addr::from([
            low[0], low[1], low[2], low[3], low[4], low[5], low[6], low[7], high[0], high[1],
            high[2], high[3], high[4], high[5], high[6], high[7],
        ])
    }
}

impl ToString for Ipv6Addr {
    fn to_string(&self) -> String {
        std::net::Ipv6Addr::from(self.clone()).to_string()
    }
}

impl From<url::Url> for Url {
    fn from(value: url::Url) -> Self {
        Url {
            url: value.to_string(),
        }
    }
}

impl From<Url> for url::Url {
    fn from(value: Url) -> Self {
        url::Url::parse(&value.url).unwrap()
    }
}

impl FromStr for Url {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Url {
            url: s.parse::<url::Url>()?.to_string(),
        })
    }
}

impl ToString for Url {
    fn to_string(&self) -> String {
        self.url.clone()
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        match value {
            std::net::SocketAddr::V4(v4) => SocketAddr {
                ip: Some(socket_addr::Ip::Ipv4(v4.ip().clone().into())),
                port: v4.port() as u32,
            },
            std::net::SocketAddr::V6(v6) => SocketAddr {
                ip: Some(socket_addr::Ip::Ipv6(v6.ip().clone().into())),
                port: v6.port() as u32,
            },
        }
    }
}

impl From<SocketAddr> for std::net::SocketAddr {
    fn from(value: SocketAddr) -> Self {
        match value.ip.unwrap() {
            socket_addr::Ip::Ipv4(ip) => std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::from(ip),
                value.port as u16,
            )),
            socket_addr::Ip::Ipv6(ip) => std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::from(ip),
                value.port as u16,
                0,
                0,
            )),
        }
    }
}

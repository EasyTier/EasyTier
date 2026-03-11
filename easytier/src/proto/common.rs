use std::{
    fmt::{self, Display},
    str::FromStr,
};

use anyhow::Context;
use base64::{prelude::BASE64_STANDARD, Engine as _};

use crate::tunnel::packet_def::CompressorAlgo;

include!(concat!(env!("OUT_DIR"), "/common.rs"));

impl From<uuid::Uuid> for Uuid {
    fn from(uuid: uuid::Uuid) -> Self {
        let (high, low) = uuid.as_u64_pair();
        Uuid {
            part1: (high >> 32) as u32,
            part2: (high & 0xFFFFFFFF) as u32,
            part3: (low >> 32) as u32,
            part4: (low & 0xFFFFFFFF) as u32,
        }
    }
}

impl From<Uuid> for uuid::Uuid {
    fn from(uuid: Uuid) -> Self {
        uuid::Uuid::from_u64_pair(
            (u64::from(uuid.part1) << 32) | u64::from(uuid.part2),
            (u64::from(uuid.part3) << 32) | u64::from(uuid.part4),
        )
    }
}

impl From<String> for Uuid {
    fn from(value: String) -> Self {
        uuid::Uuid::parse_str(&value).unwrap().into()
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", uuid::Uuid::from(*self))
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", uuid::Uuid::from(*self))
    }
}

impl From<std::net::Ipv4Addr> for Ipv4Addr {
    fn from(value: std::net::Ipv4Addr) -> Self {
        Self {
            addr: u32::from_be_bytes(value.octets()),
        }
    }
}

impl From<Ipv4Addr> for std::net::Ipv4Addr {
    fn from(value: Ipv4Addr) -> Self {
        std::net::Ipv4Addr::from(value.addr)
    }
}

impl Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv4Addr::from(self.addr))
    }
}

impl From<std::net::Ipv6Addr> for Ipv6Addr {
    fn from(value: std::net::Ipv6Addr) -> Self {
        let b = value.octets();
        Self {
            part1: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
            part2: u32::from_be_bytes([b[4], b[5], b[6], b[7]]),
            part3: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            part4: u32::from_be_bytes([b[12], b[13], b[14], b[15]]),
        }
    }
}

impl From<Ipv6Addr> for std::net::Ipv6Addr {
    fn from(value: Ipv6Addr) -> Self {
        let part1 = value.part1.to_be_bytes();
        let part2 = value.part2.to_be_bytes();
        let part3 = value.part3.to_be_bytes();
        let part4 = value.part4.to_be_bytes();
        std::net::Ipv6Addr::from([
            part1[0], part1[1], part1[2], part1[3], part2[0], part2[1], part2[2], part2[3],
            part3[0], part3[1], part3[2], part3[3], part4[0], part4[1], part4[2], part4[3],
        ])
    }
}

impl Display for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::Ipv6Addr::from(*self))
    }
}

impl From<cidr::Ipv4Inet> for Ipv4Inet {
    fn from(value: cidr::Ipv4Inet) -> Self {
        Ipv4Inet {
            address: Some(value.address().into()),
            network_length: value.network_length() as u32,
        }
    }
}

impl From<std::net::IpAddr> for IpAddr {
    fn from(value: std::net::IpAddr) -> Self {
        match value {
            std::net::IpAddr::V4(v4) => IpAddr {
                ip: Some(ip_addr::Ip::Ipv4(Ipv4Addr::from(v4))),
            },
            std::net::IpAddr::V6(v6) => IpAddr {
                ip: Some(ip_addr::Ip::Ipv6(Ipv6Addr::from(v6))),
            },
        }
    }
}

impl From<IpAddr> for std::net::IpAddr {
    fn from(value: IpAddr) -> Self {
        match value.ip {
            Some(ip_addr::Ip::Ipv4(v4)) => std::net::IpAddr::V4(v4.into()),
            Some(ip_addr::Ip::Ipv6(v6)) => std::net::IpAddr::V6(v6.into()),
            None => panic!("IpAddr is None"),
        }
    }
}

impl Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::IpAddr::from(*self))
    }
}

impl FromStr for IpAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpAddr::from(std::net::IpAddr::from_str(s)?))
    }
}

impl From<Ipv4Inet> for cidr::Ipv4Inet {
    fn from(value: Ipv4Inet) -> Self {
        cidr::Ipv4Inet::new(
            value.address.unwrap_or_default().into(),
            value.network_length as u8,
        )
        .unwrap()
    }
}

impl From<Ipv4Inet> for cidr::Ipv4Cidr {
    fn from(value: Ipv4Inet) -> Self {
        cidr::Ipv4Cidr::new(
            value.address.unwrap_or_default().into(),
            value.network_length as u8,
        )
        .unwrap()
    }
}

impl fmt::Display for Ipv4Inet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", cidr::Ipv4Inet::from(*self))
    }
}

impl FromStr for Ipv4Inet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Ipv4Inet::from(
            cidr::Ipv4Inet::from_str(s).with_context(|| "Failed to parse Ipv4Inet")?,
        ))
    }
}

impl From<cidr::Ipv6Inet> for Ipv6Inet {
    fn from(value: cidr::Ipv6Inet) -> Self {
        Ipv6Inet {
            address: Some(value.address().into()),
            network_length: value.network_length() as u32,
        }
    }
}

impl From<Ipv6Inet> for cidr::Ipv6Inet {
    fn from(value: Ipv6Inet) -> Self {
        cidr::Ipv6Inet::new(
            value.address.unwrap_or_default().into(),
            value.network_length as u8,
        )
        .unwrap()
    }
}

impl fmt::Display for Ipv6Inet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", cidr::Ipv6Inet::from(*self))
    }
}

impl FromStr for Ipv6Inet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Ipv6Inet::from(
            cidr::Ipv6Inet::from_str(s).with_context(|| "Failed to parse Ipv6Inet")?,
        ))
    }
}

impl From<cidr::IpInet> for IpInet {
    fn from(value: cidr::IpInet) -> Self {
        match value {
            cidr::IpInet::V4(v4) => IpInet {
                ip: Some(ip_inet::Ip::Ipv4(Ipv4Inet::from(v4))),
            },
            cidr::IpInet::V6(v6) => IpInet {
                ip: Some(ip_inet::Ip::Ipv6(Ipv6Inet::from(v6))),
            },
        }
    }
}

impl From<IpInet> for cidr::IpInet {
    fn from(value: IpInet) -> Self {
        match value.ip {
            Some(ip_inet::Ip::Ipv4(v4)) => cidr::IpInet::V4(v4.into()),
            Some(ip_inet::Ip::Ipv6(v6)) => cidr::IpInet::V6(v6.into()),
            None => panic!("IpInet is None"),
        }
    }
}

impl Display for IpInet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", cidr::IpInet::from(*self))
    }
}

impl FromStr for IpInet {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(IpInet::from(cidr::IpInet::from_str(s)?))
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedTunnelUrl {
    scheme: String,
    host: String,
    port: Option<u16>,
    is_ipv6: bool,
    has_brackets: bool,
}

fn canonical_tunnel_scheme(raw_scheme: &str) -> Option<&'static str> {
    const SCHEMES: &[&str] = &["faketcp", "quic", "wss", "tcp", "udp", "ws", "wg"];

    if SCHEMES.contains(&raw_scheme) {
        return SCHEMES.iter().copied().find(|scheme| *scheme == raw_scheme);
    }

    SCHEMES.iter().copied().find(|scheme| {
        raw_scheme
            .strip_suffix(scheme)
            .map(|prefix| prefix.is_empty() || prefix.ends_with('-'))
            .unwrap_or(false)
    })
}

fn normalize_tunnel_port(raw_port: &str, is_ipv6: bool) -> Option<u16> {
    if let Ok(port) = raw_port.parse::<u16>() {
        return Some(port);
    }

    if is_ipv6 && raw_port.ends_with('6') {
        return raw_port[..raw_port.len() - 1].parse::<u16>().ok();
    }

    None
}

fn normalize_tunnel_host(raw_host: &str) -> (&str, bool) {
    let trimmed = raw_host.trim();
    if let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
    {
        (inner, true)
    } else {
        (trimmed, false)
    }
}

fn parse_tunnel_url(raw: &str) -> Option<ParsedTunnelUrl> {
    if let Ok(url) = url::Url::parse(raw) {
        let scheme = canonical_tunnel_scheme(url.scheme())?;
        let (host, had_brackets) = normalize_tunnel_host(url.host_str()?);
        let is_ipv6 = matches!(url.host(), Some(url::Host::Ipv6(_)));
        return Some(ParsedTunnelUrl {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port: url.port_or_known_default(),
            is_ipv6,
            has_brackets: is_ipv6 || had_brackets,
        });
    }

    let (raw_scheme, rest) = raw.split_once("://")?;
    let scheme = canonical_tunnel_scheme(raw_scheme)?;

    if let Some(rest) = rest.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let (host, _) = normalize_tunnel_host(host);
        let port = remainder
            .strip_prefix(':')
            .and_then(|raw_port| normalize_tunnel_port(raw_port, true))?;
        return Some(ParsedTunnelUrl {
            scheme: scheme.to_string(),
            host: host.to_string(),
            port: Some(port),
            is_ipv6: true,
            has_brackets: true,
        });
    }

    let (host, raw_port) = rest.rsplit_once(':')?;
    let port = normalize_tunnel_port(raw_port, false)?;
    Some(ParsedTunnelUrl {
        scheme: scheme.to_string(),
        host: host.to_string(),
        port: Some(port),
        is_ipv6: false,
        has_brackets: false,
    })
}

fn normalized_tunnel_url(raw: &str) -> Option<String> {
    let parsed = parse_tunnel_url(raw)?;
    let scheme = if parsed.is_ipv6
        && matches!(
            parsed.scheme.as_str(),
            "tcp" | "udp" | "quic" | "wg" | "ws" | "wss"
        ) {
        format!("{}6", parsed.scheme)
    } else {
        parsed.scheme.to_string()
    };
    let host = if parsed.has_brackets {
        format!("[{}]", parsed.host)
    } else {
        parsed.host.to_string()
    };

    Some(match parsed.port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    })
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

impl Url {
    pub fn normalized_tunnel_display(&self) -> String {
        normalized_tunnel_url(&self.url).unwrap_or_else(|| self.url.clone())
    }

    pub fn is_ipv6_tunnel_endpoint(&self) -> bool {
        parse_tunnel_url(&self.url)
            .map(|parsed| parsed.is_ipv6)
            .unwrap_or(false)
    }
}

impl From<std::net::SocketAddr> for SocketAddr {
    fn from(value: std::net::SocketAddr) -> Self {
        match value {
            std::net::SocketAddr::V4(v4) => SocketAddr {
                ip: Some(socket_addr::Ip::Ipv4((*v4.ip()).into())),
                port: v4.port() as u32,
            },
            std::net::SocketAddr::V6(v6) => SocketAddr {
                ip: Some(socket_addr::Ip::Ipv6((*v6.ip()).into())),
                port: v6.port() as u32,
            },
        }
    }
}

impl From<SocketAddr> for std::net::SocketAddr {
    fn from(value: SocketAddr) -> Self {
        if value.ip.is_none() {
            return "0.0.0.0:0".parse().unwrap();
        }
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

impl Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::net::SocketAddr::from(*self))
    }
}

impl TunnelInfo {
    pub fn display_tunnel_type(&self) -> String {
        let is_ipv6 = self
            .local_addr
            .as_ref()
            .or(self.remote_addr.as_ref())
            .map(|url| url.is_ipv6_tunnel_endpoint())
            .unwrap_or(false);
        if is_ipv6 {
            format!("{}6", self.tunnel_type)
        } else {
            self.tunnel_type.clone()
        }
    }

    pub fn display_remote_addr(&self) -> Option<String> {
        self.remote_addr
            .as_ref()
            .map(|url| url.normalized_tunnel_display())
    }
}

impl TryFrom<CompressionAlgoPb> for CompressorAlgo {
    type Error = anyhow::Error;

    fn try_from(value: CompressionAlgoPb) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "zstd")]
            CompressionAlgoPb::Zstd => Ok(CompressorAlgo::ZstdDefault),
            CompressionAlgoPb::None => Ok(CompressorAlgo::None),
            _ => Err(anyhow::anyhow!("Invalid CompressionAlgoPb")),
        }
    }
}

impl TryFrom<CompressorAlgo> for CompressionAlgoPb {
    type Error = anyhow::Error;

    fn try_from(value: CompressorAlgo) -> Result<Self, Self::Error> {
        match value {
            #[cfg(feature = "zstd")]
            CompressorAlgo::ZstdDefault => Ok(CompressionAlgoPb::Zstd),
            CompressorAlgo::None => Ok(CompressionAlgoPb::None),
        }
    }
}

impl fmt::Debug for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let std_ipv4_addr = std::net::Ipv4Addr::from(*self);
        write!(f, "{}", std_ipv4_addr)
    }
}

impl fmt::Debug for Ipv6Addr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let std_ipv6_addr = std::net::Ipv6Addr::from(*self);
        write!(f, "{}", std_ipv6_addr)
    }
}

impl SecureModeConfig {
    pub fn private_key(&self) -> anyhow::Result<x25519_dalek::StaticSecret> {
        let local_private_key = self
            .local_private_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("local private key is not set"))?;
        let k = BASE64_STANDARD
            .decode(local_private_key)
            .with_context(|| format!("failed to decode private key: {}", local_private_key))?;
        // convert vec to 32b array
        let len = k.len();
        let k: [u8; 32] = k
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid private key length: {}", len))?;
        Ok(x25519_dalek::StaticSecret::from(k))
    }

    pub fn public_key(&self) -> anyhow::Result<x25519_dalek::PublicKey> {
        let local_public_key = self
            .local_public_key
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("local public key is not set"))?;
        let k = BASE64_STANDARD
            .decode(local_public_key)
            .with_context(|| format!("failed to decode public key: {}", local_public_key))?;
        // convert vec to 32b array
        let len = k.len();
        let k: [u8; 32] = k
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public key length: {}", len))?;
        Ok(x25519_dalek::PublicKey::from(k))
    }
}

#[cfg(test)]
mod tests {
    use super::{normalized_tunnel_url, TunnelInfo, Url};

    #[test]
    fn normalize_ipv6_tcp_tunnel_url() {
        let url = Url {
            url: "tcp://[2001:db8::1]:11010".to_string(),
        };
        assert_eq!(
            url.normalized_tunnel_display(),
            "tcp6://[2001:db8::1]:11010"
        );
        assert!(url.is_ipv6_tunnel_endpoint());
    }

    #[test]
    fn recover_malformed_ipv6_tcp_tunnel_url() {
        assert_eq!(
            normalized_tunnel_url("txt-tcp://[2001:db8::1]:110106").as_deref(),
            Some("tcp6://[2001:db8::1]:11010")
        );
    }

    #[test]
    fn tunnel_info_display_tunnel_type_uses_remote_addr_fallback() {
        let tunnel = TunnelInfo {
            tunnel_type: "tcp".to_string(),
            local_addr: None,
            remote_addr: Some(Url {
                url: "tcp://[2001:db8::2]:11010".to_string(),
            }),
        };

        assert_eq!(tunnel.display_tunnel_type(), "tcp6");
        assert_eq!(
            tunnel.display_remote_addr().as_deref(),
            Some("tcp6://[2001:db8::2]:11010")
        );
    }
}

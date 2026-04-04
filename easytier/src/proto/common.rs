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

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

const IPV6_TUNNEL_SCHEMES: &[&str] = &["faketcp", "quic", "wss", "tcp", "udp", "ws", "wg"];

fn split_tunnel_scheme(raw_scheme: &str) -> Option<(&str, &'static str, bool)> {
    for scheme in IPV6_TUNNEL_SCHEMES {
        let ipv6_suffix = format!("{scheme}6");
        if let Some(prefix) = raw_scheme.strip_suffix(&ipv6_suffix) {
            if prefix.is_empty() || prefix.ends_with('-') {
                return Some((prefix, *scheme, true));
            }
        }

        if let Some(prefix) = raw_scheme.strip_suffix(scheme) {
            if prefix.is_empty() || prefix.ends_with('-') {
                return Some((prefix, *scheme, false));
            }
        }
    }

    None
}

fn normalize_tunnel_scheme(raw_scheme: &str, is_ipv6: bool) -> Option<String> {
    let (prefix, scheme, had_ipv6_suffix) = split_tunnel_scheme(raw_scheme)?;
    let suffix = if is_ipv6 || had_ipv6_suffix { "6" } else { "" };
    Some(format!("{prefix}{scheme}{suffix}"))
}

fn infer_tunnel_ipv6(raw: &str) -> Option<bool> {
    let (_, rest) = raw.split_once("://")?;
    if rest.starts_with('[') {
        return Some(true);
    }

    match url::Url::parse(raw).ok()?.host() {
        Some(url::Host::Ipv4(_)) => Some(false),
        Some(url::Host::Ipv6(_)) => Some(true),
        Some(url::Host::Domain(_)) | None => None,
    }
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

fn normalize_tunnel_url(raw: &str, fallback_ipv6: Option<bool>) -> Option<String> {
    let (raw_scheme, rest) = raw.split_once("://")?;

    if let Some(rest) = rest.strip_prefix('[') {
        let (host, remainder) = rest.split_once(']')?;
        let raw_port = remainder.strip_prefix(':')?;
        let port = normalize_tunnel_port(raw_port, true)?;
        let scheme = normalize_tunnel_scheme(raw_scheme, true)?;
        return Some(format!("{scheme}://[{host}]:{port}"));
    }

    let is_ipv6 = infer_tunnel_ipv6(raw).or(fallback_ipv6).unwrap_or(false);
    let scheme = normalize_tunnel_scheme(raw_scheme, is_ipv6)?;

    if let Ok(url) = url::Url::parse(raw) {
        let host = url.host_str()?;
        let host = if is_ipv6 {
            format!("[{host}]")
        } else {
            host.to_string()
        };

        return Some(match url.port_or_known_default() {
            Some(port) => format!("{scheme}://{host}:{port}"),
            None => format!("{scheme}://{host}"),
        });
    }

    let (host, raw_port) = rest.rsplit_once(':')?;
    let port = normalize_tunnel_port(raw_port, is_ipv6)?;
    Some(format!("{scheme}://{host}:{port}"))
}

impl Url {
    pub fn is_ipv6_tunnel_endpoint(&self) -> bool {
        infer_tunnel_ipv6(&self.url).unwrap_or(false)
    }

    pub fn normalized_tunnel_display(&self) -> String {
        normalize_tunnel_url(&self.url, None).unwrap_or_else(|| self.url.clone())
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
    pub fn effective_remote_addr(&self) -> Option<&Url> {
        self.resolved_remote_addr
            .as_ref()
            .or(self.remote_addr.as_ref())
    }

    pub fn display_tunnel_type(&self) -> String {
        let is_ipv6 = infer_tunnel_ipv6(&self.tunnel_type).or_else(|| {
            self.resolved_remote_addr
                .as_ref()
                .or(self.local_addr.as_ref())
                .or(self.remote_addr.as_ref())
                .map(Url::is_ipv6_tunnel_endpoint)
        });

        if self.tunnel_type.contains("://") {
            normalize_tunnel_url(&self.tunnel_type, is_ipv6)
                .unwrap_or_else(|| self.tunnel_type.clone())
        } else {
            is_ipv6
                .and_then(|is_ipv6| normalize_tunnel_scheme(&self.tunnel_type, is_ipv6))
                .unwrap_or_else(|| self.tunnel_type.clone())
        }
    }

    pub fn display_remote_addr(&self) -> Option<String> {
        self.effective_remote_addr()
            .map(Url::normalized_tunnel_display)
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
    use super::{normalize_tunnel_url, TunnelInfo, Url};

    #[test]
    fn normalize_plain_ipv6_tunnel_url() {
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
    fn normalize_composite_ipv6_tunnel_url() {
        assert_eq!(
            normalize_tunnel_url("txt-tcp://[2001:db8::1]:11010", None).as_deref(),
            Some("txt-tcp6://[2001:db8::1]:11010")
        );
    }

    #[test]
    fn recover_malformed_composite_ipv6_tunnel_url() {
        assert_eq!(
            normalize_tunnel_url("txt-tcp://[2001:db8::1]:110106", None).as_deref(),
            Some("txt-tcp6://[2001:db8::1]:11010")
        );
    }

    #[test]
    fn keep_normalized_ipv6_tunnel_url_stable() {
        assert_eq!(
            normalize_tunnel_url("tcp6://[2001:db8::1]:11010", None).as_deref(),
            Some("tcp6://[2001:db8::1]:11010")
        );
    }

    #[test]
    fn tunnel_info_display_tunnel_type_preserves_composite_prefix() {
        let tunnel = TunnelInfo {
            tunnel_type: "txt-tcp://[2001:db8::2]:110106".to_string(),
            local_addr: None,
            remote_addr: Some(Url {
                url: "txt://et.example.com".to_string(),
            }),
            resolved_remote_addr: None,
        };

        assert_eq!(
            tunnel.display_tunnel_type(),
            "txt-tcp6://[2001:db8::2]:11010"
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
            resolved_remote_addr: None,
        };

        assert_eq!(tunnel.display_tunnel_type(), "tcp6");
        assert_eq!(
            tunnel.display_remote_addr().as_deref(),
            Some("tcp6://[2001:db8::2]:11010")
        );
    }

    #[test]
    fn tunnel_info_prefers_resolved_remote_addr() {
        let tunnel = TunnelInfo {
            tunnel_type: "txt-tcp".to_string(),
            local_addr: None,
            remote_addr: Some(Url {
                url: "txt://et.example.com".to_string(),
            }),
            resolved_remote_addr: Some(Url {
                url: "tcp://[2001:db8::3]:11010".to_string(),
            }),
        };

        assert_eq!(tunnel.display_tunnel_type(), "txt-tcp6");
        assert_eq!(
            tunnel.display_remote_addr().as_deref(),
            Some("tcp6://[2001:db8::3]:11010")
        );
        assert_eq!(
            tunnel.effective_remote_addr().map(|url| url.url.as_str()),
            Some("tcp://[2001:db8::3]:11010")
        );
    }
}

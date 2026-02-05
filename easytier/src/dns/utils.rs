use anyhow::{anyhow, Error};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::NameServerConfig;
use idna::AsciiDenyList;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use url::Url;

pub fn sanitize(name: &str) -> String {
    let dot = name.ends_with('.');
    let mut name = idna::domain_to_ascii_cow(name.as_ref(), AsciiDenyList::EMPTY)
        .unwrap_or_default()
        .into_owned()
        .to_lowercase()
        .split('.')
        .map(|label| {
            label
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .take(63)
                .collect::<String>()
                .trim_matches('-')
                .to_string()
        })
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>()
        .join(".");
    name.truncate(253);
    if dot {
        name.push('.');
    }
    name
}

static DNS_SUPPORTED_PROTOCOLS: [Protocol; 2] = [
    Protocol::Udp,
    Protocol::Tcp,
    // Protocol::Tls,
    // Protocol::Https,
    // Protocol::Quic,
    // Protocol::H3,
];

#[derive(Debug, Clone, SerializeDisplay, DeserializeFromStr, PartialEq, Eq, Hash)]
pub struct NameServerAddr {
    protocol: Protocol,
    addr: SocketAddr,
}

impl From<NameServerAddr> for NameServerConfig {
    fn from(value: NameServerAddr) -> Self {
        Self::new(value.addr, value.protocol)
    }
}

impl TryFrom<Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: Url) -> Result<Self, Self::Error> {
        let scheme = value.scheme();
        let protocol = *DNS_SUPPORTED_PROTOCOLS
            .iter()
            .find(|p| p.to_string() == scheme)
            .ok_or(anyhow!("unsupported scheme: {}", scheme))?;
        let addr = value.host_str().ok_or(anyhow!("host not found"))?;
        let addr = addr
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .map_err(|e| anyhow!("invalid ip address '{}': {}", addr, e))?;
        let port = if let Some(port) = value.port() {
            port
        } else {
            match protocol {
                Protocol::Udp | Protocol::Tcp => 53,
                _ => return Err(anyhow!("port not found")),
            }
        };

        Ok(Self {
            protocol,
            addr: SocketAddr::new(addr, port),
        })
    }
}

impl FromStr for NameServerAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = if s.parse::<IpAddr>().is_ok() || s.parse::<SocketAddr>().is_ok() {
            Url::parse(&format!("udp://{}", s))?
        } else {
            Url::parse(s)?
        };

        url.try_into()
    }
}

impl Display for NameServerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}", self.protocol, self.addr)
    }
}

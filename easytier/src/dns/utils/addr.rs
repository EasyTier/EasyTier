use crate::dns::config::DNS_SUPPORTED_PROTOCOLS;
use crate::proto;
use crate::proto::utils::RepeatedMessageModel;
use anyhow::{Error, anyhow};
use hickory_proto::xfer::Protocol;
use hickory_resolver::config::{NameServerConfig, NameServerConfigGroup};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use url::Url;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, SerializeDisplay, DeserializeFromStr)]
pub struct NameServerAddr {
    pub protocol: Protocol,
    pub addr: SocketAddr,
}

impl From<NameServerAddr> for NameServerConfig {
    fn from(value: NameServerAddr) -> Self {
        Self::new(value.addr, value.protocol)
    }
}

impl From<&NameServerConfig> for NameServerAddr {
    fn from(value: &NameServerConfig) -> Self {
        Self {
            protocol: value.protocol,
            addr: value.socket_addr,
        }
    }
}

impl From<NameServerConfig> for NameServerAddr {
    fn from(value: NameServerConfig) -> Self {
        (&value).into()
    }
}

impl From<SocketAddr> for NameServerAddr {
    fn from(value: SocketAddr) -> Self {
        Self {
            protocol: Protocol::Udp,
            addr: value,
        }
    }
}

impl From<IpAddr> for NameServerAddr {
    fn from(value: IpAddr) -> Self {
        SocketAddr::new(value, 53).into()
    }
}

impl From<NameServerAddr> for Url {
    fn from(value: NameServerAddr) -> Self {
        Url::parse(&format!("{}://{}", value.protocol, value.addr)).unwrap()
    }
}

impl TryFrom<&Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: &Url) -> Result<Self, Self::Error> {
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

impl From<NameServerAddr> for proto::common::Url {
    fn from(value: NameServerAddr) -> Self {
        Url::from(value).into()
    }
}

impl TryFrom<&proto::common::Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: &proto::common::Url) -> Result<Self, Self::Error> {
        Self::try_from(&Url::try_from(value)?)
    }
}

impl FromStr for NameServerAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        macro_rules! try_parse {
            ($($t:ty),+) => {
                $( if let Ok(v) = s.parse::<$t>() { return Ok(v.into()); } )+
            };
        }

        try_parse!(IpAddr, SocketAddr);

        (&Url::parse(s)?).try_into()
    }
}

impl Display for NameServerAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(Url::from(*self).as_str())
    }
}

pub type NameServerAddrGroup = RepeatedMessageModel<NameServerAddr>;

impl From<NameServerAddrGroup> for NameServerConfigGroup {
    fn from(value: NameServerAddrGroup) -> Self {
        value.into_iter().map(Into::into).collect::<Vec<_>>().into()
    }
}

impl From<NameServerConfigGroup> for NameServerAddrGroup {
    fn from(value: NameServerConfigGroup) -> Self {
        value
            .into_inner()
            .into_iter()
            .map(Into::into)
            .collect::<Vec<_>>()
            .into()
    }
}

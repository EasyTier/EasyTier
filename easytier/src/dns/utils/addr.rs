use crate::proto;
use crate::proto::utils::RepeatedMessageModel;
use anyhow::{Error, anyhow};
use hickory_net::xfer::Protocol;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};
use serde::de::IntoDeserializer;
use serde::{Deserialize, de};
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
        let mut config = match value.protocol {
            Protocol::Udp => ConnectionConfig::udp(),
            Protocol::Tcp => ConnectionConfig::tcp(),
            _ => unimplemented!(),
        };
        config.port = value.addr.port();
        Self::new(value.addr.ip(), true, vec![config])
    }
}

impl From<(IpAddr, &ConnectionConfig)> for NameServerAddr {
    fn from(value: (IpAddr, &ConnectionConfig)) -> Self {
        let (ip, config) = value;
        Self {
            protocol: config.protocol.to_protocol(),
            addr: SocketAddr::new(ip, config.port),
        }
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
        let protocol = match Protocol::deserialize(value.scheme().into_deserializer()).map_err(
            |e: de::value::Error| anyhow!("invalid protocol '{}': {}", value.scheme(), e),
        )? {
            Protocol::Udp => ProtocolConfig::Udp,
            Protocol::Tcp => ProtocolConfig::Tcp,
            p => return Err(anyhow!("unsupported protocol: {}", p)),
        };
        let host = value.host_str().ok_or(anyhow!("host not found"))?;
        let port = value.port().unwrap_or(protocol.default_port());
        let addr = if let Ok(addr) = IpAddr::from_str(host) {
            SocketAddr::new(addr, port)
        } else {
            return Err(anyhow!("invalid address: {}", host));
        };
        Ok(Self {
            protocol: protocol.to_protocol(),
            addr,
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

impl From<&NameServerConfig> for NameServerAddrGroup {
    fn from(value: &NameServerConfig) -> Self {
        value
            .connections
            .iter()
            .map(|c| (value.ip, c).into())
            .collect()
    }
}

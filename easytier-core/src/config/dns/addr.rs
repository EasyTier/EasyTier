use anyhow::{Error, anyhow};
use derivative::Derivative;
use derive_more::{AsMut, AsRef, Deref, DerefMut, From, IntoIterator};
use hickory_net::xfer::Protocol;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig};
use serde::de::IntoDeserializer;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::str::FromStr;
use url::Url;

#[derive(
    Derivative, Debug, Clone, PartialEq, Eq, Hash, From, Deref, DerefMut, AsRef, AsMut, IntoIterator,
)]
#[as_ref(forward)]
#[as_mut(forward)]
#[into_iterator(owned, ref, ref_mut)]
pub struct RepeatedMessageModel<Model> {
    pub models: Vec<Model>,
}

impl<Model> Default for RepeatedMessageModel<Model> {
    fn default() -> Self {
        Self { models: Vec::new() }
    }
}

impl<Model> FromIterator<Model> for RepeatedMessageModel<Model> {
    fn from_iter<I: IntoIterator<Item = Model>>(iter: I) -> Self {
        Self {
            models: iter.into_iter().collect(),
        }
    }
}

impl<Model> Extend<Model> for RepeatedMessageModel<Model> {
    fn extend<T: IntoIterator<Item = Model>>(&mut self, iter: T) {
        self.models.extend(iter);
    }
}

pub trait MessageModel<Message: prost::Message>:
    Into<Message> + for<'m> TryFrom<&'m Message>
{
}

impl<Message, Model> MessageModel<Message> for Model
where
    Message: prost::Message,
    Model: Into<Message> + for<'m> TryFrom<&'m Message>,
{
}

impl<'m, Message, Model> TryFrom<&'m [Message]> for RepeatedMessageModel<Model>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    type Error = <Model as TryFrom<&'m Message>>::Error;

    fn try_from(value: &'m [Message]) -> Result<Self, Self::Error> {
        value.iter().map(TryInto::try_into).collect()
    }
}

impl<Message, Model> From<RepeatedMessageModel<Model>> for Vec<Message>
where
    Message: prost::Message,
    Model: MessageModel<Message>,
{
    fn from(value: RepeatedMessageModel<Model>) -> Self {
        value.into_iter().map(Into::into).collect()
    }
}

pub trait RepeatedSerialize: Serialize + Sized {
    fn serialize<S>(models: &RepeatedMessageModel<Self>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        Serialize::serialize(&**models, serializer)
    }
}

pub trait RepeatedDeserialize<'de>: Deserialize<'de> {
    fn deserialize<D>(deserializer: D) -> Result<RepeatedMessageModel<Self>, D::Error>
    where
        D: Deserializer<'de>;
}

impl<Model: RepeatedSerialize> Serialize for RepeatedMessageModel<Model> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        RepeatedSerialize::serialize(self, serializer)
    }
}

impl<'de, Model: RepeatedDeserialize<'de>> Deserialize<'de> for RepeatedMessageModel<Model> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        RepeatedDeserialize::deserialize(deserializer)
    }
}

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

impl TryFrom<&Url> for NameServerAddr {
    type Error = Error;

    fn try_from(url: &Url) -> Result<Self, Self::Error> {
        let protocol = match Protocol::deserialize(url.scheme().into_deserializer())
            .map_err(|e: de::value::Error| anyhow!("invalid protocol '{}': {}", url.scheme(), e))?
        {
            Protocol::Udp => ProtocolConfig::Udp,
            Protocol::Tcp => ProtocolConfig::Tcp,
            p => return Err(anyhow!("unsupported protocol: {}", p)),
        };
        let host = url.host_str().ok_or_else(|| anyhow!("host not found"))?;
        let port = url.port().unwrap_or(protocol.default_port());
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

impl TryFrom<&crate::proto::common::Url> for NameServerAddr {
    type Error = Error;

    fn try_from(value: &crate::proto::common::Url) -> Result<Self, Self::Error> {
        (&Url::try_from(value)?).try_into()
    }
}

impl From<&NameServerAddr> for Url {
    fn from(value: &NameServerAddr) -> Self {
        Url::parse(&format!("{}://{}", value.protocol, value.addr)).unwrap()
    }
}

impl From<&NameServerAddr> for crate::proto::common::Url {
    fn from(value: &NameServerAddr) -> Self {
        Url::from(value).into()
    }
}

impl From<NameServerAddr> for Url {
    fn from(value: NameServerAddr) -> Self {
        (&value).into()
    }
}

impl From<NameServerAddr> for crate::proto::common::Url {
    fn from(value: NameServerAddr) -> Self {
        (&value).into()
    }
}

impl FromStr for NameServerAddr {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
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

impl From<SocketAddr> for NameServerAddrGroup {
    fn from(value: SocketAddr) -> Self {
        vec![
            NameServerAddr {
                protocol: Protocol::Udp,
                addr: value,
            },
            NameServerAddr {
                protocol: Protocol::Tcp,
                addr: value,
            },
        ]
        .into()
    }
}

impl From<IpAddr> for NameServerAddrGroup {
    fn from(value: IpAddr) -> Self {
        SocketAddr::new(value, 53).into()
    }
}

impl From<u16> for NameServerAddrGroup {
    fn from(value: u16) -> Self {
        SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), value).into()
    }
}

impl RepeatedSerialize for NameServerAddr {}

impl<'de> RepeatedDeserialize<'de> for NameServerAddr {
    fn deserialize<D>(deserializer: D) -> Result<NameServerAddrGroup, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Candidate {
            NameServerAddr(NameServerAddr),
            U16(u16),
            IpAddr(IpAddr),
            SocketAddr(SocketAddr),
        }

        let items = Vec::<Candidate>::deserialize(deserializer)?;
        let items = items
            .into_iter()
            .flat_map(|item| -> NameServerAddrGroup {
                match item {
                    Candidate::NameServerAddr(addr) => vec![addr].into(),
                    Candidate::U16(port) => port.into(),
                    Candidate::IpAddr(ip) => ip.into(),
                    Candidate::SocketAddr(addr) => addr.into(),
                }
            })
            .collect();

        Ok(items)
    }
}

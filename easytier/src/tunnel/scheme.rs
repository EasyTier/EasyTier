use crate::common::error::Error;
use delegate::delegate;
use derive_more::{Deref, From, TryInto};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use socket2::Protocol;
use std::fmt::Display;
use std::str::FromStr;
use strum::{Display, EnumString, IntoStaticStr, ParseError, VariantArray, VariantNames};

#[derive(Debug, Clone, Copy)]
struct IpProtoAttributes {
    protocol: Protocol,
    port_offset: u16,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Display, EnumString, IntoStaticStr, VariantArray, VariantNames,
)]
#[strum(serialize_all = "lowercase")]
pub enum IpProto {
    Tcp,
    Udp,
    #[cfg(feature = "wireguard")]
    Wg,
    #[cfg(feature = "quic")]
    Quic,
    #[cfg(feature = "websocket")]
    Ws,
    #[cfg(feature = "websocket")]
    Wss,
    #[cfg(feature = "faketcp")]
    FakeTcp,
}

impl IpProto {
    pub const VARIANTS: &'static [Self] = <Self as VariantArray>::VARIANTS;
    pub const VARIANT_NAMES: &'static [&'static str] = <Self as VariantNames>::VARIANTS;

    const fn attributes(self) -> IpProtoAttributes {
        let (protocol, port_offset) = match self {
            Self::Tcp => (Protocol::TCP, 0),
            Self::Udp => (Protocol::UDP, 0),
            #[cfg(feature = "wireguard")]
            Self::Wg => (Protocol::UDP, 1),
            #[cfg(feature = "quic")]
            Self::Quic => (Protocol::UDP, 2),
            #[cfg(feature = "websocket")]
            Self::Ws => (Protocol::TCP, 1),
            #[cfg(feature = "websocket")]
            Self::Wss => (Protocol::TCP, 2),
            #[cfg(feature = "faketcp")]
            Self::FakeTcp => (Protocol::TCP, 3),
        };
        IpProtoAttributes {
            protocol,
            port_offset,
        }
    }

    delegate! {
        to self.attributes() {
            #[field]
            pub const fn protocol(&self) -> Protocol;
            #[field]
            pub const fn port_offset(&self) -> u16;
        }
    }

    pub const fn default_port(self) -> u16 {
        match self {
            #[cfg(feature = "websocket")]
            Self::Ws => 80,
            #[cfg(feature = "websocket")]
            Self::Wss => 443,
            _ => 11010 + self.port_offset(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Deref, DeserializeFromStr, SerializeDisplay)]
pub struct IpScheme {
    #[deref]
    pub proto: IpProto,
    pub v6: bool,
}

impl From<IpProto> for IpScheme {
    fn from(proto: IpProto) -> Self {
        Self { proto, v6: false }
    }
}

impl FromStr for IpScheme {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, v6) = match s.strip_suffix('6') {
            Some(s) => (s, true),
            None => (s, false),
        };

        Ok(Self {
            proto: scheme.parse()?,
            v6,
        })
    }
}

impl Display for IpScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.proto, if self.v6 { "6" } else { "" })
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Display, EnumString, IntoStaticStr, VariantArray, VariantNames,
)]
#[strum(serialize_all = "lowercase")]
pub enum DiscoveryProto {
    Http,
    Https,
    Txt,
    Srv,
}

impl DiscoveryProto {
    pub const VARIANTS: &'static [Self] = <Self as VariantArray>::VARIANTS;
    pub const VARIANT_NAMES: &'static [&'static str] = <Self as VariantNames>::VARIANTS;
}

#[derive(Debug, Clone, Copy, PartialEq, Deref, DeserializeFromStr, SerializeDisplay)]
pub struct DiscoveryScheme {
    #[deref]
    pub proto: DiscoveryProto,
    pub scheme: Option<IpScheme>,
}

impl From<DiscoveryProto> for DiscoveryScheme {
    fn from(proto: DiscoveryProto) -> Self {
        Self {
            proto,
            scheme: None,
        }
    }
}

impl FromStr for DiscoveryScheme {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.split_once('-') {
            Some((method, transport)) => Self {
                proto: method.parse()?,
                scheme: Some(transport.parse()?),
            },
            None => s.parse::<DiscoveryProto>()?.into(),
        })
    }
}

impl Display for DiscoveryScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.proto)?;
        if let Some(scheme) = &self.scheme {
            write!(f, "-{}", scheme)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, From, TryInto, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TunnelScheme {
    Ring,
    #[cfg(unix)]
    Unix,
    #[serde(untagged)]
    Ip(IpScheme),
    #[serde(untagged)]
    Discovery(DiscoveryScheme),
}

impl FromStr for TunnelScheme {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(&serde_json::to_string(s)?)
    }
}

impl Display for TunnelScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(self)
                .map_err(|_| std::fmt::Error)?
                .trim_matches('"')
        )
    }
}

impl From<IpProto> for TunnelScheme {
    fn from(value: IpProto) -> Self {
        Self::Ip(value.into())
    }
}

impl From<DiscoveryProto> for TunnelScheme {
    fn from(value: DiscoveryProto) -> Self {
        Self::Discovery(value.into())
    }
}

impl TryFrom<&url::Url> for TunnelScheme {
    type Error = Error;

    fn try_from(value: &url::Url) -> Result<Self, Self::Error> {
        value
            .scheme()
            .parse()
            .map(|mut scheme| {
                if matches!(value.host(), Some(url::Host::Ipv6(_))) {
                    match &mut scheme {
                        TunnelScheme::Ip(scheme) => scheme.v6 = true,
                        TunnelScheme::Discovery(DiscoveryScheme {
                            scheme: Some(scheme),
                            ..
                        }) => scheme.v6 = true,
                        _ => {}
                    };
                }
                scheme
            })
            .map_err(|_| Error::InvalidUrl(value.to_string()))
    }
}

macro_rules! __matches_protocol__ {
    ($url:expr, $( $pattern:pat_param )|+ ) => {{
        if let Ok($crate::tunnel::scheme::TunnelScheme::Ip(scheme)) = ($url).try_into() {
            matches!(scheme.protocol(), $( $pattern )|+)
        } else {
            false
        }
    }};
}

pub(crate) use __matches_protocol__ as matches_protocol;

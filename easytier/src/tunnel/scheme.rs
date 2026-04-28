use crate::common::error::Error;
use crate::utils::BoxExt;
use anyhow::Context;
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (scheme, v6) = match s.strip_suffix('6') {
            Some(s) => (s, true),
            None => (s, false),
        };

        Ok(Self {
            proto: scheme
                .parse()
                .with_context(|| format!("invalid scheme: {}", s))?,
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

#[derive(Debug, Clone, PartialEq, Deref, DeserializeFromStr, SerializeDisplay)]
pub struct DiscoveryScheme {
    #[deref]
    pub proto: DiscoveryProto,
    pub scheme: Option<Box<TunnelScheme>>,
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
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.split_once('-') {
            Some((proto, scheme)) => Self {
                proto: proto
                    .parse()
                    .with_context(|| format!("invalid scheme: {}", s))?,
                scheme: Some(scheme.parse::<TunnelScheme>()?.boxed()),
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

macro_rules! impl_ip_extractor {
    ($self:expr, $method:ident) => {
        match $self {
            Self::Ip(scheme) => Some(scheme),
            Self::Discovery(DiscoveryScheme {
                scheme: Some(inner),
                ..
            }) => inner.$method(),
            _ => None,
        }
    };
}

#[derive(Debug, Clone, PartialEq, From, TryInto, Deserialize, Serialize)]
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

impl TunnelScheme {
    pub fn into_ip(self) -> Option<IpScheme> {
        impl_ip_extractor!(self, into_ip)
    }
    pub fn as_ip(&self) -> Option<&IpScheme> {
        impl_ip_extractor!(self, as_ip)
    }
    pub fn as_ip_mut(&mut self) -> Option<&mut IpScheme> {
        impl_ip_extractor!(self, as_ip_mut)
    }

    pub fn set_v6(&mut self, v6: bool) {
        if let Some(scheme) = self.as_ip_mut() {
            scheme.v6 = v6;
        }
    }
}

impl FromStr for TunnelScheme {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(&serde_json::to_string(s)?)
            .map_err(|_| ParseError::VariantNotFound)
            .with_context(|| format!("invalid scheme: {}", s))
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

macro_rules! impl_from_proto {
    ($variant:ident, $ty:ty) => {
        impl From<$ty> for TunnelScheme {
            fn from(value: $ty) -> Self {
                Self::$variant(value.into())
            }
        }
    };
}

impl_from_proto!(Ip, IpProto);
impl_from_proto!(Discovery, DiscoveryProto);

impl TryFrom<&url::Url> for TunnelScheme {
    type Error = Error;

    fn try_from(value: &url::Url) -> Result<Self, Self::Error> {
        value
            .scheme()
            .parse::<Self>()
            .map(|mut scheme| {
                if matches!(value.host(), Some(url::Host::Ipv6(_))) {
                    scheme.set_v6(true);
                }
                scheme
            })
            .map_err(|_| Error::InvalidUrl(value.to_string()))
    }
}

impl TryFrom<&url::Url> for IpScheme {
    type Error = Error;

    fn try_from(value: &url::Url) -> Result<Self, Self::Error> {
        TunnelScheme::try_from(value)?
            .into_ip()
            .ok_or_else(|| Error::InvalidUrl(value.to_string()))
    }
}

macro_rules! __matches_proto__ {
    ($url:expr, $( $pattern:pat_param )|+ ) => {{
        matches!(
            {
                let url: &url::Url = &$url;
                $crate::tunnel::scheme::IpScheme::try_from(url).ok().map(|s| s.proto)
            },
            Some($( $pattern )|+)
        )
    }};
}

pub(crate) use __matches_proto__ as matches_proto;

macro_rules! __matches_protocol__ {
    ($url:expr, $( $pattern:pat_param )|+ ) => {{
        matches!(
            {
                let url: &url::Url = &$url;
                $crate::tunnel::scheme::IpScheme::try_from(url).ok().map(|s| s.protocol())
            },
            Some($( $pattern )|+)
        )
    }};
}

pub(crate) use __matches_protocol__ as matches_protocol;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_scheme_accepts_owned_url() {
        let url: url::Url = "udp://[2001:db8::1]:11010".parse().unwrap();

        assert!(matches_proto!(url, IpProto::Udp));
    }

    #[test]
    fn matches_scheme_accepts_borrowed_url() {
        let url: url::Url = "udp://[2001:db8::1]:11010".parse().unwrap();

        assert!(matches_proto!(&url, IpProto::Udp));
    }

    #[test]
    fn normalize_all_enabled_ipv6_tunnel_urls() {
        for scheme in IpProto::VARIANT_NAMES {
            let url = url::Url::parse(&format!("{scheme}://[::]:0")).unwrap();
            let parsed = TunnelScheme::try_from(&url).unwrap();

            assert_eq!(parsed.to_string(), format!("{scheme}6"));
        }
    }

    #[test]
    fn normalize_composite_ipv6_tunnel_url() {
        let url = url::Url::parse("txt-tcp://[::]:0").unwrap();
        let parsed = TunnelScheme::try_from(&url).unwrap();

        assert_eq!(parsed.to_string(), "txt-tcp6");
    }

    #[test]
    fn reject_unknown_composite_prefix_in_tunnel_url_normalization() {
        let url = url::Url::parse("foo-tcp://[::]:0").unwrap();

        assert!(TunnelScheme::try_from(&url).is_err());
    }

    #[test]
    fn keep_normalized_ipv6_tunnel_url_stable() {
        let url = url::Url::parse("tcp6://[::]:0").unwrap();
        let parsed = TunnelScheme::try_from(&url).unwrap();

        assert_eq!(parsed.to_string(), "tcp6");
    }
}

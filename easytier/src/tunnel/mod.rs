use std::{collections::hash_map::DefaultHasher, hash::Hasher, net::SocketAddr};

use crate::common::{dns::socket_addrs, error::Error};
use derive_more::{From, TryInto};
use easytier_core::tunnel::{IpVersion, TunnelError};
use strum::{Display, EnumString, IntoStaticStr, VariantArray};

pub mod common;
pub(crate) mod protocol;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod websocket;

pub fn build_url_from_socket_addr(addr: &String, scheme: &str) -> url::Url {
    if let Ok(sock_addr) = addr.parse::<SocketAddr>() {
        let url_str = format!("{}://0.0.0.0", scheme);
        let mut ret_url = url::Url::parse(url_str.as_str())
            .unwrap_or_else(|_| panic!("invalid url: {}", url_str));
        ret_url.set_ip_host(sock_addr.ip()).unwrap();
        ret_url.set_port(Some(sock_addr.port())).unwrap();
        ret_url
    } else {
        url::Url::parse(format!("{}://{}", scheme, addr).as_str()).unwrap()
    }
}

#[async_trait::async_trait]
pub(crate) trait FromUrl {
    async fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError>
    where
        Self: Sized;
}

#[async_trait::async_trait]
impl FromUrl for SocketAddr {
    async fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError> {
        let addrs = socket_addrs(&url, || {
            (&url)
                .try_into()
                .ok()
                .and_then(|s: TunnelScheme| s.try_into().ok())
                .map(IpScheme::default_port)
        })
        .await
        .map_err(|e| {
            TunnelError::InvalidAddr(format!(
                "failed to resolve socket addr, url: {}, error: {}",
                url, e
            ))
        })?;
        tracing::debug!(?addrs, ?ip_version, ?url, "convert url to socket addrs");
        let addrs = addrs
            .into_iter()
            .filter(|addr| match ip_version {
                IpVersion::V4 => addr.is_ipv4(),
                IpVersion::V6 => addr.is_ipv6(),
                IpVersion::Both => true,
            })
            .collect::<Vec<_>>();

        use rand::seq::SliceRandom;
        // randomly select one address
        addrs
            .choose(&mut rand::thread_rng())
            .copied()
            .ok_or(TunnelError::NoDnsRecordFound(ip_version))
    }
}

pub struct TunnelUrl {
    inner: url::Url,
}

impl From<url::Url> for TunnelUrl {
    fn from(url: url::Url) -> Self {
        TunnelUrl { inner: url }
    }
}

impl From<TunnelUrl> for url::Url {
    fn from(url: TunnelUrl) -> Self {
        url.into_inner()
    }
}

impl TunnelUrl {
    pub fn into_inner(self) -> url::Url {
        self.inner
    }

    pub fn bind_dev(&self) -> Option<String> {
        self.inner.path().strip_prefix("/").and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(String::from_utf8(percent_encoding::percent_decode_str(s).collect()).unwrap())
            }
        })
    }
}

pub fn generate_digest_from_str(str1: &str, str2: &str, digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    hasher.write(str1.as_bytes());
    hasher.write(str2.as_bytes());

    assert_eq!(digest.len() % 8, 0, "digest length must be multiple of 8");

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Display, EnumString, IntoStaticStr, VariantArray)]
#[strum(serialize_all = "lowercase")]
pub enum IpScheme {
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

impl IpScheme {
    pub const fn port_offset(self) -> u16 {
        match self {
            Self::Tcp | Self::Udp => 0,
            #[cfg(feature = "wireguard")]
            Self::Wg => 1,
            #[cfg(feature = "quic")]
            Self::Quic => 2,
            #[cfg(feature = "websocket")]
            Self::Ws => 1,
            #[cfg(feature = "websocket")]
            Self::Wss => 2,
            #[cfg(feature = "faketcp")]
            Self::FakeTcp => 3,
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

#[derive(Debug, Clone, Copy, PartialEq, EnumString, From, TryInto)]
#[strum(serialize_all = "lowercase")]
pub enum TunnelScheme {
    #[strum(disabled)]
    Ip(IpScheme),
    #[cfg(unix)]
    Unix,
    // Only for connector
    Http,
    Https,
    Ring,
    Txt,
    Srv,
}

impl TryFrom<&url::Url> for TunnelScheme {
    type Error = Error;

    fn try_from(value: &url::Url) -> Result<Self, Self::Error> {
        let scheme = value.scheme();
        scheme.parse().or_else(|_| {
            Ok(TunnelScheme::Ip(
                scheme
                    .parse()
                    .map_err(|_| Error::InvalidUrl(value.to_string()))?,
            ))
        })
    }
}

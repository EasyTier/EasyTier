use std::{
    collections::hash_map::DefaultHasher, hash::Hasher, net::SocketAddr, pin::Pin, sync::Arc,
};

use crate::{
    common::{dns::socket_addrs, error::Error},
    proto::common::TunnelInfo,
};
use async_trait::async_trait;
use derive_more::{From, TryInto};
use futures::{Sink, Stream};
use socket2::Protocol;
use std::fmt::Debug;
use strum::{Display, EnumString, IntoStaticStr, VariantArray};
use tokio::time::error::Elapsed;

use self::packet_def::ZCPacket;

pub mod buf;
pub mod common;
pub mod filter;
pub mod mpsc;
pub mod packet_def;
pub mod ring;
pub mod stats;
pub mod tcp;
pub mod udp;

#[cfg(feature = "faketcp")]
pub mod fake_tcp;

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod websocket;

#[cfg(any(feature = "quic", feature = "websocket"))]
pub mod insecure_tls;

#[cfg(unix)]
pub mod unix;

#[derive(thiserror::Error, Debug)]
pub enum TunnelError {
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("invalid packet. msg: {0}")]
    InvalidPacket(String),
    #[error("exceed max packet size. max: {0}, input: {1}")]
    ExceedMaxPacketSize(usize, usize),

    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),
    #[error("invalid addr: {0}")]
    InvalidAddr(String),

    #[error("internal error {0}")]
    InternalError(String),

    #[error("conn id not match, expect: {0}, actual: {1}")]
    ConnIdNotMatch(u32, u32),
    #[error("buffer full")]
    BufferFull,

    #[error("timeout")]
    Timeout(#[from] Elapsed),

    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("shutdown")]
    Shutdown,

    #[error("no dns record found")]
    NoDnsRecordFound(IpVersion),

    #[cfg(feature = "websocket")]
    #[error("websocket error: {0}")]
    WebSocketError(#[from] tokio_websockets::Error),

    #[error("tunnel error: {0}")]
    TunError(String),
}

pub type StreamT = packet_def::ZCPacket;
pub type StreamItem = Result<StreamT, TunnelError>;
pub type SinkItem = packet_def::ZCPacket;
pub type SinkError = TunnelError;

pub trait ZCPacketStream: Stream<Item = StreamItem> + Send {}
impl<T> ZCPacketStream for T where T: Stream<Item = StreamItem> + Send {}
pub trait ZCPacketSink: Sink<SinkItem, Error = SinkError> + Send {}
impl<T> ZCPacketSink for T where T: Sink<SinkItem, Error = SinkError> + Send {}

pub type SplitTunnel = (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>);

#[auto_impl::auto_impl(Box, Arc)]
pub trait Tunnel: Send {
    fn split(&self) -> SplitTunnel;
    fn info(&self) -> Option<TunnelInfo>;
}

#[auto_impl::auto_impl(Arc)]
pub trait TunnelConnCounter: 'static + Send + Sync + Debug {
    fn get(&self) -> Option<u32>;
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Both,
}

#[async_trait]
#[auto_impl::auto_impl(Box)]
pub trait TunnelListener: Send {
    async fn listen(&mut self) -> Result<(), TunnelError>;
    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError>;
    fn local_url(&self) -> url::Url;
    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        #[derive(Debug)]
        struct FakeTunnelConnCounter {}
        impl TunnelConnCounter for FakeTunnelConnCounter {
            fn get(&self) -> Option<u32> {
                None
            }
        }
        Arc::new(Box::new(FakeTunnelConnCounter {}))
    }
}

#[async_trait]
#[auto_impl::auto_impl(Box, &mut)]
pub trait TunnelConnector: Send {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError>;
    fn remote_url(&self) -> url::Url;
    fn set_bind_addrs(&mut self, _addrs: Vec<SocketAddr>) {}
    fn set_ip_version(&mut self, _ip_version: IpVersion) {}
}

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

impl std::fmt::Debug for dyn Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("info", &self.info())
            .finish()
    }
}

impl std::fmt::Debug for dyn TunnelConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelConnector")
            .field("remote_url", &self.remote_url())
            .finish()
    }
}

impl std::fmt::Debug for dyn TunnelListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelListener")
            .field("local_url", &self.local_url())
            .finish()
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

#[async_trait::async_trait]
impl FromUrl for uuid::Uuid {
    async fn from_url(url: url::Url, _ip_version: IpVersion) -> Result<Self, TunnelError> {
        let o = url.host_str().unwrap();
        let o = uuid::Uuid::parse_str(o).map_err(|e| TunnelError::InvalidAddr(e.to_string()))?;
        Ok(o)
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

#[derive(Debug, Clone, Copy)]
struct IpSchemeAttributes {
    protocol: Protocol,
    port_offset: u16,
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
    const fn attributes(self) -> IpSchemeAttributes {
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
        IpSchemeAttributes {
            protocol,
            port_offset,
        }
    }
    pub const fn protocol(self) -> Protocol {
        self.attributes().protocol
    }

    pub const fn port_offset(self) -> u16 {
        self.attributes().port_offset
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

macro_rules! __matches_scheme__ {
    ($url:expr, $( $pattern:pat_param )|+ ) => {
        matches!($crate::tunnel::TunnelScheme::try_from(($url).as_ref()), Ok($( $pattern )|+))
    };
}

pub(crate) use __matches_scheme__ as matches_scheme;

pub fn get_protocol_by_url(l: &url::Url) -> Result<Protocol, Error> {
    let TunnelScheme::Ip(scheme) = l.try_into()? else {
        return Err(Error::InvalidUrl(l.to_string()));
    };
    Ok(scheme.protocol())
}

macro_rules! __matches_protocol__ {
    ($url:expr, $( $pattern:pat_param )|+ ) => {
        matches!($crate::tunnel::get_protocol_by_url($url), Ok($( $pattern )|+))
    };
}

pub(crate) use __matches_protocol__ as matches_protocol;

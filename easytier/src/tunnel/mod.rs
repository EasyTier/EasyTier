use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::{net::SocketAddr, pin::Pin, sync::Arc};

use async_trait::async_trait;
use futures::{Sink, Stream};
use std::fmt::Debug;

use tokio::time::error::Elapsed;

use crate::proto::common::TunnelInfo;

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

pub const PROTO_PORT_OFFSET: &[(&str, u16)] =
    &[("tcp", 0), ("udp", 0), ("wg", 1), ("ws", 1), ("wss", 2)];

#[cfg(feature = "wireguard")]
pub mod wireguard;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "websocket")]
pub mod websocket;

#[cfg(any(feature = "quic", feature = "websocket"))]
pub mod insecure_tls;

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

#[auto_impl::auto_impl(Box, Arc)]
pub trait Tunnel: Send {
    fn split(&self) -> (Pin<Box<dyn ZCPacketStream>>, Pin<Box<dyn ZCPacketSink>>);
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
        let mut ret_url = url::Url::parse(format!("{}://0.0.0.0", scheme).as_str()).unwrap();
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

pub(crate) trait FromUrl {
    fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError>
    where
        Self: Sized;
}

pub(crate) fn check_scheme_and_get_socket_addr_ext<T>(
    url: &url::Url,
    scheme: &str,
    ip_version: IpVersion,
) -> Result<T, TunnelError>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(TunnelError::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone(), ip_version)?)
}

pub(crate) fn check_scheme_and_get_socket_addr<T>(
    url: &url::Url,
    scheme: &str,
    ip_version: IpVersion,
) -> Result<T, TunnelError>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(TunnelError::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone(), ip_version)?)
}

fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "tcp" => Some(11010),
        "udp" => Some(11010),
        "ws" => Some(11011),
        "wss" => Some(11012),
        "quic" => Some(11012),
        "wg" => Some(11011),
        _ => None,
    }
}

impl FromUrl for SocketAddr {
    fn from_url(url: url::Url, ip_version: IpVersion) -> Result<Self, TunnelError> {
        let addrs = url.socket_addrs(|| default_port(url.scheme()))?;
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

impl FromUrl for uuid::Uuid {
    fn from_url(url: url::Url, _ip_version: IpVersion) -> Result<Self, TunnelError> {
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
                Some(String::from_utf8(percent_encoding::percent_decode_str(&s).collect()).unwrap())
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

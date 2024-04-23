pub mod codec;
pub mod common;
// pub mod ring_tunnel;
// pub mod stats;
// pub mod tcp_tunnel;
// pub mod tunnel_filter;
// pub mod udp_tunnel;
// pub mod wireguard;

use std::{fmt::Debug, net::SocketAddr, pin::Pin, sync::Arc};

use crate::rpc::TunnelInfo;
use async_trait::async_trait;
use futures::{Sink, SinkExt, Stream};

use thiserror::Error;
use tokio_util::bytes::{Bytes, BytesMut};

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("Error: {0}")]
    CommonError(String),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("wait resp error {0}")]
    WaitRespError(String),
    #[error("Connect Error: {0}")]
    ConnectError(String),
    #[error("Invalid Protocol: {0}")]
    InvalidProtocol(String),
    #[error("Invalid Addr: {0}")]
    InvalidAddr(String),
    #[error("Tun Error: {0}")]
    TunError(String),
    #[error("timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

pub type StreamT = BytesMut;
pub type StreamItem = Result<StreamT, TunnelError>;
pub type SinkItem = Bytes;
pub type SinkError = TunnelError;

pub trait DatagramStream: Stream<Item = StreamItem> + Send + Sync {}
impl<T> DatagramStream for T where T: Stream<Item = StreamItem> + Send + Sync {}
pub trait DatagramSink: Sink<SinkItem, Error = SinkError> + Send + Sync {}
impl<T> DatagramSink for T where T: Sink<SinkItem, Error = SinkError> + Send + Sync {}

#[auto_impl::auto_impl(Box, Arc)]
pub trait Tunnel: Send + Sync {
    fn stream(&self) -> Box<dyn DatagramStream>;
    fn sink(&self) -> Box<dyn DatagramSink>;

    fn pin_stream(&self) -> Pin<Box<dyn DatagramStream>> {
        Box::into_pin(self.stream())
    }

    fn pin_sink(&self) -> Pin<Box<dyn DatagramSink>> {
        Box::into_pin(self.sink())
    }

    fn info(&self) -> Option<TunnelInfo>;
}

pub async fn close_tunnel(t: &Box<dyn Tunnel>) -> Result<(), TunnelError> {
    t.pin_sink().close().await
}

#[auto_impl::auto_impl(Arc)]
pub trait TunnelConnCounter: 'static + Send + Sync + Debug {
    fn get(&self) -> u32;
}

#[async_trait]
#[auto_impl::auto_impl(Box)]
pub trait TunnelListener: Send + Sync {
    async fn listen(&mut self) -> Result<(), TunnelError>;
    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, TunnelError>;
    fn local_url(&self) -> url::Url;
    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        #[derive(Debug)]
        struct FakeTunnelConnCounter {}
        impl TunnelConnCounter for FakeTunnelConnCounter {
            fn get(&self) -> u32 {
                0
            }
        }
        Arc::new(Box::new(FakeTunnelConnCounter {}))
    }
}

#[async_trait]
#[auto_impl::auto_impl(Box)]
pub trait TunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, TunnelError>;
    fn remote_url(&self) -> url::Url;
    fn set_bind_addrs(&mut self, _addrs: Vec<SocketAddr>) {}
}

pub fn build_url_from_socket_addr(addr: &String, scheme: &str) -> url::Url {
    url::Url::parse(format!("{}://{}", scheme, addr).as_str()).unwrap()
}

impl std::fmt::Debug for dyn Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("info", &self.info())
            .finish()
    }
}

impl std::fmt::Debug for dyn TunnelConnector + Sync + Send {
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
    fn from_url(url: url::Url) -> Result<Self, TunnelError>
    where
        Self: Sized;
}

pub(crate) fn check_scheme_and_get_socket_addr<T>(
    url: &url::Url,
    scheme: &str,
) -> Result<T, TunnelError>
where
    T: FromUrl,
{
    if url.scheme() != scheme {
        return Err(TunnelError::InvalidProtocol(url.scheme().to_string()));
    }

    Ok(T::from_url(url.clone())?)
}

impl FromUrl for SocketAddr {
    fn from_url(url: url::Url) -> Result<Self, TunnelError> {
        Ok(url.socket_addrs(|| None)?.pop().unwrap())
    }
}

impl FromUrl for uuid::Uuid {
    fn from_url(url: url::Url) -> Result<Self, TunnelError> {
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

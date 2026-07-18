//! Shared tunnel contract and per-transport tunnel implementations.
//!
//! This root file declares the shared tunnel contract: [`TunnelError`], the
//! [`Tunnel`] trait, and the [`ZCPacket`] stream/sink aliases that tunnels
//! carry. The sibling files in this directory hold the per-transport tunnel
//! implementations (TCP, UDP, ring, mpsc) and the filters and wrappers
//! layered on top of them.

use std::{fmt::Debug, pin::Pin};

use futures::{Sink, Stream};

use crate::{foundation::time::error::Elapsed, packet::ZCPacket, proto::common::TunnelInfo};

pub use crate::socket::IpVersion;

pub mod filter;
pub mod framed;
pub mod mpsc;
pub mod ring;
pub mod stats;
pub mod tcp;
pub mod udp;
pub mod web_security;
pub mod wrapper;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("io error: {0}")]
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
    #[error("{0}")]
    ProtocolError(String),
    #[error("tunnel error: {0}")]
    TunError(String),
}

impl From<TunnelError> for crate::proto::rpc_types::error::Error {
    fn from(value: TunnelError) -> Self {
        Self::TunnelError(value.to_string())
    }
}

pub type StreamT = ZCPacket;
pub type StreamItem = Result<StreamT, TunnelError>;
pub type SinkItem = ZCPacket;
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

impl std::fmt::Debug for dyn Tunnel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tunnel")
            .field("info", &self.info())
            .finish()
    }
}

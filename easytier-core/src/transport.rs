use std::net::SocketAddr;

use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::packet::ZCPacket;

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    #[error("invalid packet: {0}")]
    InvalidPacket(String),
    #[error("timeout")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("shutdown")]
    Shutdown,
    #[error("transport error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, TransportError>;

#[async_trait]
pub trait PacketTransport: Send + Sync {
    async fn send_packet(&self, packet: ZCPacket) -> Result<()>;
    async fn recv_packet(&self) -> Result<ZCPacket>;
}

#[async_trait]
pub trait TunnelIo: Send + Sync {
    async fn send(&self, packet: ZCPacket) -> Result<()>;
    async fn recv(&self) -> Result<ZCPacket>;
}

#[async_trait]
pub trait DatagramSocket: Send + Sync {
    async fn send_to(&self, buf: Bytes, target: SocketAddr) -> Result<usize>;
    async fn recv_from(&self, buf: &mut BytesMut) -> Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

pub trait StreamSocket: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T> StreamSocket for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

#[async_trait]
pub trait StreamListener: Send + Sync {
    type Stream: StreamSocket;

    async fn accept(&self) -> Result<(Self::Stream, SocketAddr)>;
    fn local_addr(&self) -> Result<SocketAddr>;
}

#[async_trait]
pub trait SocketFactory: Send + Sync {
    type Datagram: DatagramSocket;
    type Stream: StreamSocket;
    type Listener: StreamListener<Stream = Self::Stream>;

    async fn bind_datagram(&self, local: SocketAddr) -> Result<Self::Datagram>;
    async fn connect_stream(&self, remote: SocketAddr) -> Result<Self::Stream>;
    async fn bind_stream_listener(&self, local: SocketAddr) -> Result<Self::Listener>;
}

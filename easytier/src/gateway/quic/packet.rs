use std::net::SocketAddr;
use bytes::BytesMut;
use crate::gateway::quic::QuicBufferMargins;

#[derive(Debug)]
pub struct QuicPacket {
    pub addr: SocketAddr,
    pub payload: BytesMut,
}

pub type QuicPacketMargins = QuicBufferMargins;

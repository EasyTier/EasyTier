//! Error type definitions for errors that can occur during RPC interactions.
use std::result;

use prost;
use thiserror;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("rust tun error {0}")]
    ExecutionError(#[from] anyhow::Error),

    #[error("Decode error: {0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("Encode error: {0}")]
    EncodeError(#[from] prost::EncodeError),

    #[error("Invalid method index: {0}, service: {1}")]
    InvalidMethodIndex(u8, String),

    #[error("Invalid service name: {0}, proto name: {1}")]
    InvalidServiceKey(String, String),

    #[error("Invalid packet: {0}")]
    MalformatRpcPacket(String),

    #[error("Timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),

    #[error("Tunnel error: {0}")]
    TunnelError(#[from] crate::tunnel::TunnelError),

    #[error("Shutdown")]
    Shutdown,
}

pub type Result<T> = result::Result<T, Error>;

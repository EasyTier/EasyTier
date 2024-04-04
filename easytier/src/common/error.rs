use std::{io, result};

use thiserror::Error;

use crate::tunnels;

use super::PeerId;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    IOError(#[from] io::Error),
    #[error("rust tun error {0}")]
    TunError(#[from] tun::Error),
    #[error("tunnel error {0}")]
    TunnelError(#[from] tunnels::TunnelError),
    #[error("Peer has no conn, PeerId: {0}")]
    PeerNoConnectionError(PeerId),
    #[error("RouteError: {0:?}")]
    RouteError(Option<String>),
    #[error("Not found")]
    NotFound,
    #[error("Invalid Url: {0}")]
    InvalidUrl(String),
    #[error("Shell Command error: {0}")]
    ShellCommandError(String),
    // #[error("Rpc listen error: {0}")]
    // RpcListenError(String),
    #[error("Rpc connect error: {0}")]
    RpcConnectError(String),
    #[error("Rpc error: {0}")]
    RpcClientError(#[from] tarpc::client::RpcError),
    #[error("Timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("url in blacklist")]
    UrlInBlacklist,
    #[error("unknown data store error")]
    Unknown,
    #[error("anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
}

pub type Result<T> = result::Result<T, Error>;

// impl From for std::

use std::{io, result};
use thiserror::Error;

use easytier_core::tunnel::TunnelError;

#[derive(Error, Debug)]
pub enum Error {
    #[error("io error")]
    IOError(#[from] io::Error),

    #[cfg(feature = "tun")]
    #[error("rust tun error {0}")]
    TunError(#[from] tun::Error),

    #[error("tunnel error {0}")]
    TunnelError(#[from] TunnelError),
    #[error("Not found")]
    NotFound,
    #[error("Invalid Url: {0}")]
    InvalidUrl(String),
    #[error("Shell Command error: {0}")]
    ShellCommandError(String),
    #[error("Timeout error: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
    #[error("anyhow error: {0}")]
    AnyhowError(#[from] anyhow::Error),
}

pub type Result<T> = result::Result<T, Error>;

use crate::{config::PeerId, tunnel::TunnelError};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("wait response error: {0}")]
    WaitRespError(String),
    #[error("secret key error: {0}")]
    SecretKeyError(String),
    #[error("peer has no connection: {0}")]
    PeerNoConnectionError(PeerId),
    #[error("route error: {0:?}")]
    RouteError(Option<String>),
    #[error("not found")]
    NotFound,
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<snow::Error> for Error {
    fn from(value: snow::Error) -> Self {
        Self::WaitRespError(value.to_string())
    }
}

impl From<crate::foundation::time::error::Elapsed> for Error {
    fn from(value: crate::foundation::time::error::Elapsed) -> Self {
        Self::WaitRespError(value.to_string())
    }
}

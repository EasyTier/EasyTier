use std::{io, string::FromUtf8Error};

use easytier_core::tunnel::TunnelError;

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpTransportError {
    #[error("socket error: {0}")]
    Socket(#[from] TunnelError),
    #[error("HTTP request error: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("HTTP connection error: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("HTTP response is not UTF-8: {0}")]
    Utf8(#[from] FromUtf8Error),
    #[error("HTTP request timed out")]
    TimedOut,
    #[error("invalid HTTP response: {0}")]
    InvalidResponse(String),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RequestError {
    #[error(transparent)]
    Http(#[from] HttpTransportError),
    #[error("invalid response from gateway: {0}")]
    InvalidResponse(String),
    #[error("gateway response error {0}: {1}")]
    ErrorCode(u16, String),
    #[error("gateway does not support action: {0}")]
    UnsupportedAction(String),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SearchError {
    #[error("invalid response")]
    InvalidResponse,
    #[error("no response within timeout")]
    NoResponseWithinTimeout,
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::str::Utf8Error),
    #[error("XML error: {0}")]
    Xml(#[from] xmltree::ParseError),
    #[error(transparent)]
    Http(#[from] HttpTransportError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AddAnyPortError {
    #[error("the client is not authorized to map this port")]
    ActionNotAuthorized,
    #[error("cannot add a mapping for local port 0")]
    InternalPortZeroInvalid,
    #[error("the gateway does not have any free ports")]
    NoPortsAvailable,
    #[error("the required same-numbered external port is in use")]
    ExternalPortInUse,
    #[error("the gateway only supports permanent leases")]
    OnlyPermanentLeasesSupported,
    #[error("the description was too long for the gateway")]
    DescriptionTooLong,
    #[error("request error: {0}")]
    RequestError(#[from] RequestError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AddPortError {
    #[error("the client is not authorized to map this port")]
    ActionNotAuthorized,
    #[error("cannot add a mapping for local port 0")]
    InternalPortZeroInvalid,
    #[error("external port 0 is invalid")]
    ExternalPortZeroInvalid,
    #[error("the requested port is in use")]
    PortInUse,
    #[error("the gateway requires matching internal and external ports")]
    SamePortValuesRequired,
    #[error("the gateway only supports permanent leases")]
    OnlyPermanentLeasesSupported,
    #[error("the description was too long for the gateway")]
    DescriptionTooLong,
    #[error("request error: {0}")]
    RequestError(#[source] RequestError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RemovePortError {
    #[error("the client is not authorized to remove the port")]
    ActionNotAuthorized,
    #[error("the port was not mapped")]
    NoSuchPortMapping,
    #[error("request error: {0}")]
    RequestError(#[source] RequestError),
}

#[derive(Debug, thiserror::Error)]
#[cfg(test)]
pub(crate) enum GetExternalIpError {
    #[error("the client is not authorized to get the external IP address")]
    ActionNotAuthorized,
    #[error("request error: {0}")]
    RequestError(#[source] RequestError),
}

#[derive(Debug, thiserror::Error)]
#[cfg(test)]
pub(crate) enum GetGenericPortMappingEntryError {
    #[error("the client is not authorized to look up port mappings")]
    ActionNotAuthorized,
    #[error("the provided mapping index is invalid")]
    SpecifiedArrayIndexInvalid,
    #[error("request error: {0}")]
    RequestError(#[source] RequestError),
}

#[cfg(test)]
impl From<RequestError> for GetGenericPortMappingEntryError {
    fn from(error: RequestError) -> Self {
        match error {
            RequestError::ErrorCode(606, _) => Self::ActionNotAuthorized,
            RequestError::ErrorCode(713, _) => Self::SpecifiedArrayIndexInvalid,
            other => Self::RequestError(other),
        }
    }
}

//! Stable errors returned by the public data-plane interface.

use std::{fmt, io};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
#[repr(u16)]
pub enum DataPlaneErrorKind {
    Cancelled = 1,
    DeadlineExceeded = 2,
    InstanceStopped = 3,
    HandleClosed = 4,
    NoOverlayRoute = 5,
    PathNotReady = 6,
    AddressFamilyUnsupported = 7,
    AddressInUse = 8,
    ConnectionRefused = 9,
    NetworkChanged = 10,
    ResourceLimit = 11,
    Io = 12,
    BufferTooSmall = 13,
}

#[derive(Clone, Debug)]
pub struct DataPlaneError {
    kind: DataPlaneErrorKind,
    message: String,
}

impl DataPlaneError {
    pub(crate) fn new(kind: DataPlaneErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    pub(crate) fn deadline_exceeded() -> Self {
        Self::new(
            DataPlaneErrorKind::DeadlineExceeded,
            "data-plane deadline exceeded",
        )
    }

    pub fn kind(&self) -> DataPlaneErrorKind {
        self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn into_io_error(self) -> io::Error {
        let kind = match self.kind {
            DataPlaneErrorKind::Cancelled => io::ErrorKind::Interrupted,
            DataPlaneErrorKind::DeadlineExceeded => io::ErrorKind::TimedOut,
            DataPlaneErrorKind::AddressFamilyUnsupported => io::ErrorKind::Unsupported,
            DataPlaneErrorKind::AddressInUse => io::ErrorKind::AddrInUse,
            DataPlaneErrorKind::ConnectionRefused => io::ErrorKind::ConnectionRefused,
            DataPlaneErrorKind::ResourceLimit => io::ErrorKind::OutOfMemory,
            DataPlaneErrorKind::BufferTooSmall => io::ErrorKind::InvalidInput,
            DataPlaneErrorKind::InstanceStopped
            | DataPlaneErrorKind::HandleClosed
            | DataPlaneErrorKind::NetworkChanged => io::ErrorKind::BrokenPipe,
            DataPlaneErrorKind::NoOverlayRoute | DataPlaneErrorKind::PathNotReady => {
                io::ErrorKind::NotConnected
            }
            DataPlaneErrorKind::Io => io::ErrorKind::Other,
        };
        io::Error::new(kind, self)
    }
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DataPlaneError {}

impl From<io::Error> for DataPlaneError {
    fn from(error: io::Error) -> Self {
        if let Some(error) = error
            .get_ref()
            .and_then(|error| error.downcast_ref::<Self>())
        {
            return Self::new(error.kind, error.message.clone());
        }
        let kind = match error.kind() {
            io::ErrorKind::TimedOut => DataPlaneErrorKind::DeadlineExceeded,
            io::ErrorKind::AddrInUse => DataPlaneErrorKind::AddressInUse,
            io::ErrorKind::ConnectionRefused => DataPlaneErrorKind::ConnectionRefused,
            io::ErrorKind::Interrupted => DataPlaneErrorKind::Cancelled,
            io::ErrorKind::Unsupported => DataPlaneErrorKind::AddressFamilyUnsupported,
            io::ErrorKind::NotConnected => DataPlaneErrorKind::PathNotReady,
            io::ErrorKind::BrokenPipe => DataPlaneErrorKind::HandleClosed,
            io::ErrorKind::OutOfMemory => DataPlaneErrorKind::ResourceLimit,
            _ => DataPlaneErrorKind::Io,
        };
        Self::new(kind, error.to_string())
    }
}

impl From<anyhow::Error> for DataPlaneError {
    fn from(error: anyhow::Error) -> Self {
        if let Some(error) = error.downcast_ref::<Self>() {
            return Self::new(error.kind, error.message.clone());
        }
        if let Some(error) = error.downcast_ref::<io::Error>() {
            return Self::from(io::Error::new(error.kind(), error.to_string()));
        }
        Self::new(DataPlaneErrorKind::Io, format!("{error:#}"))
    }
}

pub type DataPlaneResult<T> = Result<T, DataPlaneError>;

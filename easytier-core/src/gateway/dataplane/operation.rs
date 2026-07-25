//! Stable operation, completion, and result types for one data-plane session.

use std::net::SocketAddr;

use crate::foundation::operation_broker::OperationId;

use super::DataPlaneErrorKind;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct DataPlaneOperationId(OperationId);

impl DataPlaneOperationId {
    pub fn from_raw(value: u64) -> Option<Self> {
        OperationId::from_raw(value).map(Self)
    }

    pub fn get(self) -> u64 {
        self.0.get()
    }

    pub(super) fn from_broker(operation_id: OperationId) -> Self {
        Self(operation_id)
    }

    pub(super) fn broker_id(self) -> OperationId {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct DataPlaneResourceId(u64);

impl DataPlaneResourceId {
    pub fn from_raw(value: u64) -> Option<Self> {
        (value != 0).then_some(Self(value))
    }

    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum DataPlaneOperationKind {
    TcpConnect = 1,
    TcpBind = 2,
    TcpAccept = 3,
    TcpRead = 4,
    TcpWrite = 5,
    UdpBind = 6,
    UdpReceive = 7,
    UdpSend = 8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataPlaneCompletionStatus {
    Success,
    Error(DataPlaneErrorKind),
}

impl DataPlaneCompletionStatus {
    pub fn code(self) -> u16 {
        match self {
            Self::Success => 0,
            Self::Error(kind) => kind as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataPlaneCompletionDescriptor {
    pub operation_id: DataPlaneOperationId,
    pub kind: DataPlaneOperationKind,
    pub status: DataPlaneCompletionStatus,
}

#[derive(Debug)]
pub enum DataPlaneOperationResult {
    TcpConnected {
        stream: DataPlaneResourceId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    TcpBound {
        listener: DataPlaneResourceId,
        local_addr: SocketAddr,
    },
    TcpAccepted {
        stream: DataPlaneResourceId,
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
    },
    TcpRead {
        data: Vec<u8>,
        eof: bool,
    },
    TcpWritten {
        len: usize,
    },
    UdpBound {
        socket: DataPlaneResourceId,
        local_addr: SocketAddr,
    },
    UdpReceived {
        data: Vec<u8>,
        peer_addr: SocketAddr,
        truncated: bool,
    },
    UdpSent {
        len: usize,
    },
}

impl DataPlaneOperationResult {
    pub(super) fn retained_bytes(&self) -> usize {
        match self {
            Self::TcpRead { data, .. } | Self::UdpReceived { data, .. } => data.capacity(),
            _ => 0,
        }
    }

    pub(super) fn payload_bytes(&self) -> usize {
        match self {
            Self::TcpRead { data, .. } | Self::UdpReceived { data, .. } => data.len(),
            _ => 0,
        }
    }

    pub(super) fn created_resource(&self) -> Option<DataPlaneResourceId> {
        match self {
            Self::TcpConnected { stream, .. } | Self::TcpAccepted { stream, .. } => Some(*stream),
            Self::TcpBound { listener, .. } => Some(*listener),
            Self::UdpBound { socket, .. } => Some(*socket),
            Self::TcpRead { .. }
            | Self::TcpWritten { .. }
            | Self::UdpReceived { .. }
            | Self::UdpSent { .. } => None,
        }
    }
}

pub type DataPlaneOperationOutcome = Result<DataPlaneOperationResult, DataPlaneErrorKind>;

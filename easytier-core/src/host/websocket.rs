//! Host-backed WebSocket message tunnels.
//!
//! The host owns the WebSocket handshake and endpoint. Core owns EasyTier
//! packet semantics: each binary WebSocket message is one tunnel payload and
//! each outgoing tunnel packet becomes one binary WebSocket message.

use std::{io, task::Poll};

use super::socket::{HostOperationId, HostSocketHandle, HostSocketIo};

/// Maximum binary WebSocket message accepted from a host adapter.
pub const MAX_HOST_WEBSOCKET_MESSAGE_LEN: usize = 1024 * 1024;

/// One message returned by a host WebSocket endpoint.
pub enum HostWebSocketMessage {
    Binary(Vec<u8>),
    Text,
}

/// Mechanical host WebSocket I/O below EasyTier's message-tunnel seam.
///
/// Submit methods copy their complete input before returning. A receive keeps
/// the WebSocket message boundary intact. A clean remote close is reported as
/// [`io::ErrorKind::UnexpectedEof`] by `take_receive`.
pub trait HostWebSocketIo: HostSocketIo {
    fn submit_receive(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_receive(&self, operation: HostOperationId) -> Poll<io::Result<HostWebSocketMessage>>;

    fn submit_send(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()>;

    fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>>;
}

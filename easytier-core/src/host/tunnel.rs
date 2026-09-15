//! Host-backed message tunnels.
//!
//! The host owns the concrete transport and exposes complete EasyTier tunnel
//! payloads. Core owns packet semantics and the peer lifecycle above them.

use std::{io, task::Poll};

use super::socket::{HostOperationId, HostSocketHandle, HostSocketIo};

/// Maximum message payload accepted from a host tunnel adapter.
pub const MAX_HOST_TUNNEL_PAYLOAD_LEN: usize = 1024 * 1024;

/// Mechanical host I/O below EasyTier's message-tunnel seam.
///
/// Submit methods copy their complete input before returning. A receive keeps
/// the host transport's message boundary intact. A clean remote close is
/// reported as [`io::ErrorKind::UnexpectedEof`] by `take_receive`.
pub trait HostTunnelIo: HostSocketIo {
    fn submit_receive(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()>;

    fn take_receive(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>>;

    fn submit_send(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()>;

    fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>>;
}

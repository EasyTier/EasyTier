//! WASI imports for connector environment operations.

use std::{io, net::SocketAddr, task::Poll};

use crate::socket::SocketContext;
use crate::{
    host::{environment::HostConnectorEnvironmentIo, socket::HostOperationId},
    wasi::{
        imports::{
            HOST_PENDING, cancel_operation, start_local_addr_for_remote, take_local_addr_for_remote,
        },
        wire::{
            common::{host_error, status},
            options::encode_socket_context,
            socket::{SOCKET_ADDRESS_LEN, decode_socket_address, encode_socket_address},
        },
    },
};

#[derive(Default)]
pub struct WasiHostConnectorEnvironmentIo;

impl HostConnectorEnvironmentIo for WasiHostConnectorEnvironmentIo {
    fn submit_local_addr_for_remote(
        &self,
        operation: HostOperationId,
        remote_addr: SocketAddr,
        context: &SocketContext,
    ) -> io::Result<()> {
        let encoded = encode_socket_address(remote_addr);
        let encoded_context = encode_socket_context(context)?;
        status("start_local_addr_for_remote", unsafe {
            start_local_addr_for_remote(
                operation.0,
                encoded.as_ptr() as u32,
                SOCKET_ADDRESS_LEN as u32,
                encoded_context.as_ptr() as u32,
                encoded_context.len() as u32,
            )
        })
    }

    fn take_local_addr_for_remote(
        &self,
        operation: HostOperationId,
    ) -> Poll<io::Result<SocketAddr>> {
        take_address(
            "take_local_addr_for_remote",
            operation,
            take_local_addr_for_remote,
        )
    }

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }
}

fn take_address(
    name: &'static str,
    operation: HostOperationId,
    take: unsafe extern "C" fn(u64, u32, u32) -> i32,
) -> Poll<io::Result<SocketAddr>> {
    let mut encoded = [0_u8; SOCKET_ADDRESS_LEN];
    match unsafe {
        take(
            operation.0,
            encoded.as_mut_ptr() as u32,
            SOCKET_ADDRESS_LEN as u32,
        )
    } {
        HOST_PENDING => Poll::Pending,
        0 => Poll::Ready(decode_socket_address(&encoded)),
        value => Poll::Ready(Err(host_error(name, value))),
    }
}

//! WASI imports for connector environment operations.

use std::{io, net::SocketAddr, task::Poll};

use crate::socket::host::{
    HostOperationId, HostSocketHandle,
    wasi_common::{host_error, status},
    wasi_wire::{SOCKET_ADDRESS_LEN, decode_socket_address, encode_socket_address},
};

use super::HostConnectorEnvironmentIo;

const HOST_PENDING: i32 = -1;

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
    fn start_local_addr_for_remote(operation: u64, remote_addr: u32, remote_addr_len: u32) -> i32;
    fn take_local_addr_for_remote(operation: u64, result: u32, result_len: u32) -> i32;
    fn start_udp_port_mapping(operation: u64, socket: u64) -> i32;
    fn take_udp_port_mapping(operation: u64, result: u32, result_len: u32) -> i32;
    fn start_tcp_port_mapping(operation: u64, local_port: u32) -> i32;
    fn take_tcp_port_mapping(operation: u64, result: u32, result_len: u32) -> i32;
    fn cancel_operation(operation: u64) -> i32;
}

#[derive(Default)]
pub struct WasiHostConnectorEnvironmentIo;

impl HostConnectorEnvironmentIo for WasiHostConnectorEnvironmentIo {
    fn submit_local_addr_for_remote(
        &self,
        operation: HostOperationId,
        remote_addr: SocketAddr,
    ) -> io::Result<()> {
        let encoded = encode_socket_address(remote_addr);
        status("start_local_addr_for_remote", unsafe {
            start_local_addr_for_remote(
                operation.0,
                encoded.as_ptr() as u32,
                SOCKET_ADDRESS_LEN as u32,
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

    fn submit_udp_port_mapping(
        &self,
        operation: HostOperationId,
        socket: HostSocketHandle,
    ) -> io::Result<()> {
        status("start_udp_port_mapping", unsafe {
            start_udp_port_mapping(operation.0, socket.0)
        })
    }

    fn take_udp_port_mapping(&self, operation: HostOperationId) -> Poll<io::Result<SocketAddr>> {
        take_address("take_udp_port_mapping", operation, take_udp_port_mapping)
    }

    fn submit_tcp_port_mapping(
        &self,
        operation: HostOperationId,
        local_port: u16,
    ) -> io::Result<()> {
        status("start_tcp_port_mapping", unsafe {
            start_tcp_port_mapping(operation.0, u32::from(local_port))
        })
    }

    fn take_tcp_port_mapping(&self, operation: HostOperationId) -> Poll<io::Result<SocketAddr>> {
        take_address("take_tcp_port_mapping", operation, take_tcp_port_mapping)
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

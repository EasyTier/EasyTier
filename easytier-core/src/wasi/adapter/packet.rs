use std::{io, task::Poll};

use crate::{
    host::{
        packet::{HostPacketIo, HostPacketSinkHandle},
        socket::HostOperationId,
    },
    wasi::{
        imports::{
            HOST_PENDING, HOST_WOULD_BLOCK, cancel_operation, start_packet_write_ready,
            take_packet_write_ready, try_packet_write,
        },
        wire::common::{host_error, status},
    },
};

const MAX_HOST_PACKET_LEN: usize = 1024 * 1024;

#[derive(Default)]
pub struct WasiHostPacketIo;

impl HostPacketIo for WasiHostPacketIo {
    fn try_write_packet(&self, handle: HostPacketSinkHandle, packet: &[u8]) -> io::Result<()> {
        if packet.len() > MAX_HOST_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("host packet exceeds {MAX_HOST_PACKET_LEN} bytes"),
            ));
        }
        let length = u32::try_from(packet.len()).expect("host packet limit fits u32");
        match unsafe { try_packet_write(handle.0, packet.as_ptr() as u32, length) } {
            0 => Ok(()),
            HOST_WOULD_BLOCK => Err(io::ErrorKind::WouldBlock.into()),
            value => Err(host_error("try_packet_write", value)),
        }
    }

    fn submit_write_ready(
        &self,
        handle: HostPacketSinkHandle,
        operation: HostOperationId,
    ) -> io::Result<()> {
        status("start_packet_write_ready", unsafe {
            start_packet_write_ready(handle.0, operation.0)
        })
    }

    fn take_write_ready(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        match unsafe { take_packet_write_ready(operation.0) } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(Ok(())),
            value => Poll::Ready(Err(host_error("take_packet_write_ready", value))),
        }
    }

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }
}

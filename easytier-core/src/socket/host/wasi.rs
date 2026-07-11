use std::{io, task::Poll};

use super::{HostOperationId, HostSocketHandle, HostTcpIo};

const HOST_PENDING: i32 = -1;

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
    fn start_read(handle: u64, operation: u64, capacity: u32) -> i32;
    fn take_read(operation: u64, destination: u32, capacity: u32) -> i32;
    fn start_write(handle: u64, operation: u64, source: u32, length: u32) -> i32;
    fn take_write(operation: u64) -> i32;
    fn cancel_operation(operation: u64) -> i32;
    fn close(handle: u64) -> i32;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WasiHostTcpIo;

impl HostTcpIo for WasiHostTcpIo {
    fn submit_read(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        let capacity = u32::try_from(capacity)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read buffer is too large"))?;
        status("start_read", unsafe {
            start_read(handle.0, operation.0, capacity)
        })
    }

    fn take_read(
        &self,
        operation: HostOperationId,
        destination: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let Ok(capacity) = u32::try_from(destination.len()) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read buffer is too large",
            )));
        };
        let result = unsafe { take_read(operation.0, destination.as_mut_ptr() as u32, capacity) };
        completion("take_read", result)
    }

    fn submit_write(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        source: &[u8],
    ) -> io::Result<()> {
        let length = u32::try_from(source.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "write buffer is too large")
        })?;
        status("start_write", unsafe {
            start_write(handle.0, operation.0, source.as_ptr() as u32, length)
        })
    }

    fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<usize>> {
        completion("take_write", unsafe { take_write(operation.0) })
    }

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }

    fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
        status("close", unsafe { close(handle.0) })
    }
}

fn status(operation: &str, result: i32) -> io::Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(host_error(operation, result))
    }
}

fn completion(operation: &str, result: i32) -> Poll<io::Result<usize>> {
    match result {
        HOST_PENDING => Poll::Pending,
        value if value >= 0 => Poll::Ready(Ok(value as usize)),
        value => Poll::Ready(Err(host_error(operation, value))),
    }
}

fn host_error(operation: &str, code: i32) -> io::Error {
    io::Error::other(format!("host {operation} failed with code {code}"))
}

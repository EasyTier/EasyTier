//! WASI TCP adapter behind the portable host socket seams.
//!
//! [`WasiHostTcpIo`] implements the TCP half of the host socket I/O traits on
//! top of the `easytier_host` import module, and
//! [`backend::WasiHostSocketBackend`] composes the TCP, UDP, factory, and
//! listener imports into one host socket backend. Shared status mapping and
//! wire codecs live in [`crate::wasi::wire`].

pub mod backend;
pub mod udp;

use std::{collections::HashMap, io, sync::Mutex, task::Poll};

use crate::{
    host::socket::{HostOperationId, HostSocketHandle, HostSocketIo, HostTcpIo},
    wasi::{
        imports::{
            HOST_PENDING, cancel_operation, close, start_read, start_write, take_read, take_write,
        },
        wire::common::{host_error, status},
    },
};

#[derive(Debug, Default)]
pub struct WasiHostTcpIo {
    read_buffers: Mutex<HashMap<HostOperationId, Vec<u8>>>,
}

impl WasiHostTcpIo {
    pub(super) fn forget_operation(&self, operation: HostOperationId) {
        self.read_buffers
            .lock()
            .expect("WASI read buffer registry poisoned")
            .remove(&operation);
    }
}

impl HostSocketIo for WasiHostTcpIo {
    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        self.forget_operation(operation);
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }

    fn close(&self, handle: HostSocketHandle) -> io::Result<()> {
        status("close", unsafe { close(handle.0) })
    }
}

impl HostTcpIo for WasiHostTcpIo {
    fn submit_read(
        &self,
        handle: HostSocketHandle,
        operation: HostOperationId,
        capacity: usize,
    ) -> io::Result<()> {
        let capacity_u32 = u32::try_from(capacity)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "read buffer is too large"))?;
        status("start_read", unsafe {
            start_read(handle.0, operation.0, capacity_u32)
        })?;
        self.read_buffers
            .lock()
            .expect("WASI read buffer registry poisoned")
            .insert(operation, vec![0; capacity]);
        Ok(())
    }

    fn take_read(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
        let mut buffers = self
            .read_buffers
            .lock()
            .expect("WASI read buffer registry poisoned");
        let Some(buffer) = buffers.get_mut(&operation) else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WASI read operation buffer is missing",
            )));
        };
        let result =
            unsafe { take_read(operation.0, buffer.as_mut_ptr() as u32, buffer.len() as u32) };
        match result {
            HOST_PENDING => Poll::Pending,
            value if value >= 0 => {
                let length = value as usize;
                if length > buffer.len() {
                    buffers.remove(&operation);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "host read completion exceeds the submitted capacity",
                    )));
                }
                let mut buffer = buffers.remove(&operation).unwrap();
                buffer.truncate(length);
                Poll::Ready(Ok(buffer))
            }
            value => {
                buffers.remove(&operation);
                Poll::Ready(Err(host_error("take_read", value)))
            }
        }
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

    fn take_write(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
        match unsafe { take_write(operation.0) } {
            HOST_PENDING => Poll::Pending,
            0 => Poll::Ready(Ok(())),
            value => Poll::Ready(Err(host_error("take_write", value))),
        }
    }
}

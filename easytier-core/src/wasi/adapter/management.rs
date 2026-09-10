use std::{io, task::Poll};

use crate::{
    host::{management::HostManagementIo, socket::HostOperationId},
    wasi::{
        imports::{HOST_PENDING, cancel_operation, start_management_call, take_management_call},
        wire::common::{host_error, status},
    },
};

const MAX_MANAGEMENT_RESULT_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Default)]
pub struct WasiHostManagementIo;

impl HostManagementIo for WasiHostManagementIo {
    fn submit_call(&self, operation: HostOperationId, request: &[u8]) -> io::Result<()> {
        let length = u32::try_from(request.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "management request is too long",
            )
        })?;
        status("start_management_call", unsafe {
            start_management_call(operation.0, request.as_ptr() as u32, length)
        })
    }

    fn take_call(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>> {
        let required = unsafe { take_management_call(operation.0, 0, 0) };
        if required == HOST_PENDING {
            return Poll::Pending;
        }
        if required <= 0 {
            return Poll::Ready(Err(host_error("take_management_call", required)));
        }
        let required = usize::try_from(required).expect("positive i32 fits usize");
        if required > MAX_MANAGEMENT_RESULT_LEN {
            let _ = unsafe { cancel_operation(operation.0) };
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host management response is too long",
            )));
        }
        let mut response = vec![0; required];
        let copied = unsafe {
            take_management_call(
                operation.0,
                response.as_mut_ptr() as u32,
                u32::try_from(required).expect("management result limit fits u32"),
            )
        };
        if copied != i32::try_from(required).expect("management result length fits i32") {
            let _ = unsafe { cancel_operation(operation.0) };
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "host management response length changed",
            )));
        }
        Poll::Ready(Ok(response))
    }

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
        status("cancel_operation", unsafe { cancel_operation(operation.0) })
    }
}

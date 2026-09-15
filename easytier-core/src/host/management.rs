use std::{io, sync::Arc, task::Poll};

use super::socket::{HostOperationId, HostSocketRuntime};

/// Mechanical process-management I/O delegated to the embedding host.
pub trait HostManagementIo: Send + Sync + 'static {
    fn submit_call(&self, operation: HostOperationId, request: &[u8]) -> io::Result<()>;

    fn take_call(&self, operation: HostOperationId) -> Poll<io::Result<Vec<u8>>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;
}

#[derive(Clone)]
pub struct HostManagementClient<I>
where
    I: HostManagementIo,
{
    runtime: HostSocketRuntime,
    io: Arc<I>,
}

impl<I> HostManagementClient<I>
where
    I: HostManagementIo,
{
    pub fn new(runtime: HostSocketRuntime, io: Arc<I>) -> Self {
        Self { runtime, io }
    }

    pub async fn call(&self, request: &[u8]) -> io::Result<Vec<u8>> {
        self.runtime
            .run_operation(
                self.io.clone(),
                |io, operation| io.submit_call(operation, request),
                HostManagementIo::take_call,
                |io, operation| io.cancel_operation(operation),
            )
            .await
    }
}

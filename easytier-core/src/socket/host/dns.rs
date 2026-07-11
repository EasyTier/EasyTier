use std::{io, net::IpAddr, sync::Arc, task::Poll};

use async_trait::async_trait;
use futures::future::poll_fn;

use crate::socket::dns::{DnsQuery, DnsRecordResolver, DnsResolver, DnsSrvRecord};

use super::{HostOperationId, HostSocketRuntime};

/// Mechanical asynchronous DNS below core's resolver seam.
///
/// Submit methods must return without waiting for DNS. Completion methods own
/// their returned data and must not retain guest-memory borrows. Cancellation
/// removes pending or completed-but-unobserved operation state.
pub trait HostDnsIo: Send + Sync + 'static {
    fn submit_resolve(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()>;

    fn take_resolve(&self, operation: HostOperationId) -> Poll<io::Result<Vec<IpAddr>>>;

    fn submit_txt(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()>;

    fn take_txt(&self, operation: HostOperationId) -> Poll<io::Result<String>>;

    fn submit_srv(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()>;

    fn take_srv(&self, operation: HostOperationId) -> Poll<io::Result<Vec<DnsSrvRecord>>>;

    fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()>;
}

struct PendingHostDns<D>
where
    D: HostDnsIo,
{
    runtime: HostSocketRuntime,
    io: Arc<D>,
    operation: HostOperationId,
    completed: bool,
}

impl<D> PendingHostDns<D>
where
    D: HostDnsIo,
{
    fn new(runtime: HostSocketRuntime, io: Arc<D>, operation: HostOperationId) -> Self {
        Self {
            runtime,
            io,
            operation,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.runtime.inner.wakers.remove(self.operation);
        self.completed = true;
    }
}

impl<D> Drop for PendingHostDns<D>
where
    D: HostDnsIo,
{
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        self.runtime.inner.wakers.remove(self.operation);
        let _ = self.io.cancel_operation(self.operation);
    }
}

pub struct HostDnsResolver<D>
where
    D: HostDnsIo,
{
    runtime: HostSocketRuntime,
    io: Arc<D>,
}

impl<D> Clone for HostDnsResolver<D>
where
    D: HostDnsIo,
{
    fn clone(&self) -> Self {
        Self {
            runtime: self.runtime.clone(),
            io: self.io.clone(),
        }
    }
}

impl<D> HostDnsResolver<D>
where
    D: HostDnsIo,
{
    pub fn new(runtime: HostSocketRuntime, io: Arc<D>) -> Self {
        Self { runtime, io }
    }

    async fn run_operation<T>(
        &self,
        submit: impl FnOnce(&D, HostOperationId) -> io::Result<()>,
        take: impl Fn(&D, HostOperationId) -> Poll<io::Result<T>>,
    ) -> io::Result<T> {
        let operation = self.runtime.next_operation();
        submit(&self.io, operation)?;
        let mut pending = PendingHostDns::new(self.runtime.clone(), self.io.clone(), operation);
        poll_fn(|context| {
            let epoch = self
                .runtime
                .inner
                .completion_epoch
                .load(std::sync::atomic::Ordering::SeqCst);
            match take(&self.io, operation) {
                Poll::Pending => {
                    self.runtime.register_pending(operation, epoch, context);
                    Poll::Pending
                }
                Poll::Ready(result) => {
                    pending.complete();
                    Poll::Ready(result)
                }
            }
        })
        .await
    }
}

#[async_trait]
impl<D> DnsResolver for HostDnsResolver<D>
where
    D: HostDnsIo,
{
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>> {
        Ok(self
            .run_operation(
                |io, operation| io.submit_resolve(operation, &query),
                HostDnsIo::take_resolve,
            )
            .await?)
    }
}

#[async_trait]
impl<D> DnsRecordResolver for HostDnsResolver<D>
where
    D: HostDnsIo,
{
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String> {
        Ok(self
            .run_operation(
                |io, operation| io.submit_txt(operation, &query),
                HostDnsIo::take_txt,
            )
            .await?)
    }

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>> {
        Ok(self
            .run_operation(
                |io, operation| io.submit_srv(operation, &query),
                HostDnsIo::take_srv,
            )
            .await?)
    }
}

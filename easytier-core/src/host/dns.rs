use std::{io, net::IpAddr, sync::Arc, task::Poll};

use async_trait::async_trait;

use crate::socket::SocketContext;

use super::socket::{HostOperationId, HostSocketRuntime};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub host: String,
    pub context: SocketContext,
}

impl DnsQuery {
    pub fn new(host: impl Into<String>, context: SocketContext) -> Self {
        Self {
            host: host.into(),
            context,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync + 'static {
    async fn resolve(&self, query: DnsQuery) -> anyhow::Result<Vec<IpAddr>>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsSrvRecord {
    pub priority: u16,
    pub weight: u16,
    pub port: u16,
    pub target: String,
}

/// Resolves non-address DNS records used by EasyTier endpoint discovery.
#[async_trait]
pub trait DnsRecordResolver: Send + Sync + 'static {
    async fn resolve_txt(&self, query: DnsQuery) -> anyhow::Result<String>;

    async fn resolve_srv(&self, query: DnsQuery) -> anyhow::Result<Vec<DnsSrvRecord>>;
}

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
        self.runtime
            .run_operation(self.io.clone(), submit, take, |io, operation| {
                io.cancel_operation(operation)
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

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, sync::Mutex};

    use crate::socket::{IpVersion, SocketContext};

    use super::*;

    enum TestDnsOperation {
        Resolve {
            query: DnsQuery,
            result: Option<io::Result<Vec<IpAddr>>>,
        },
        Txt {
            query: DnsQuery,
            result: Option<io::Result<String>>,
        },
        Srv {
            query: DnsQuery,
            result: Option<io::Result<Vec<DnsSrvRecord>>>,
        },
    }

    #[derive(Default)]
    struct TestDnsIo {
        operations: Mutex<HashMap<HostOperationId, TestDnsOperation>>,
        cancelled: Mutex<Vec<HostOperationId>>,
    }

    impl TestDnsIo {
        fn operation(
            &self,
            predicate: impl Fn(&TestDnsOperation) -> bool,
        ) -> (HostOperationId, DnsQuery) {
            self.operations
                .lock()
                .unwrap()
                .iter()
                .find_map(|(operation, value)| {
                    if !predicate(value) {
                        return None;
                    }
                    let query = match value {
                        TestDnsOperation::Resolve { query, .. }
                        | TestDnsOperation::Txt { query, .. }
                        | TestDnsOperation::Srv { query, .. } => query,
                    };
                    Some((*operation, query.clone()))
                })
                .unwrap()
        }

        fn complete_resolve(&self, operation: HostOperationId, addresses: Vec<IpAddr>) {
            let mut operations = self.operations.lock().unwrap();
            let TestDnsOperation::Resolve { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not an address query");
            };
            *result = Some(Ok(addresses));
        }

        fn complete_txt(&self, operation: HostOperationId, text: String) {
            let mut operations = self.operations.lock().unwrap();
            let TestDnsOperation::Txt { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not a TXT query");
            };
            *result = Some(Ok(text));
        }

        fn complete_srv(&self, operation: HostOperationId, records: Vec<DnsSrvRecord>) {
            let mut operations = self.operations.lock().unwrap();
            let TestDnsOperation::Srv { result, .. } = operations.get_mut(&operation).unwrap()
            else {
                panic!("operation is not an SRV query");
            };
            *result = Some(Ok(records));
        }
    }

    impl HostDnsIo for TestDnsIo {
        fn submit_resolve(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestDnsOperation::Resolve {
                    query: query.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_resolve(&self, operation: HostOperationId) -> Poll<io::Result<Vec<IpAddr>>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestDnsOperation::Resolve { result, .. }) = operations.get_mut(&operation)
            else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }

        fn submit_txt(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestDnsOperation::Txt {
                    query: query.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_txt(&self, operation: HostOperationId) -> Poll<io::Result<String>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestDnsOperation::Txt { result, .. }) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }

        fn submit_srv(&self, operation: HostOperationId, query: &DnsQuery) -> io::Result<()> {
            self.operations.lock().unwrap().insert(
                operation,
                TestDnsOperation::Srv {
                    query: query.clone(),
                    result: None,
                },
            );
            Ok(())
        }

        fn take_srv(&self, operation: HostOperationId) -> Poll<io::Result<Vec<DnsSrvRecord>>> {
            let mut operations = self.operations.lock().unwrap();
            let Some(TestDnsOperation::Srv { result, .. }) = operations.get_mut(&operation) else {
                return Poll::Ready(Err(io::ErrorKind::NotFound.into()));
            };
            let Some(result) = result.take() else {
                return Poll::Pending;
            };
            operations.remove(&operation);
            Poll::Ready(result)
        }

        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            self.operations.lock().unwrap().remove(&operation);
            self.cancelled.lock().unwrap().push(operation);
            Ok(())
        }
    }

    fn query(host: &str, ip_version: IpVersion) -> DnsQuery {
        DnsQuery::new(
            host,
            SocketContext {
                ip_version,
                socket_mark: Some(7),
                netns: None,
            },
        )
    }

    #[test]
    fn query_keeps_host_and_socket_context() {
        let context = SocketContext::default();
        assert_eq!(
            DnsQuery::new("example.com", context.clone()),
            DnsQuery {
                host: "example.com".to_owned(),
                context,
            }
        );
    }

    #[test]
    fn srv_record_keeps_dns_selection_fields() {
        let record = DnsSrvRecord {
            priority: 10,
            weight: 20,
            port: 11010,
            target: "peer.example.com.".to_owned(),
        };

        assert_eq!(record.priority, 10);
        assert_eq!(record.weight, 20);
        assert_eq!(record.port, 11010);
        assert_eq!(record.target, "peer.example.com.");
    }

    #[tokio::test]
    async fn forwards_all_query_types_and_wakes_completed_futures() {
        let io = Arc::new(TestDnsIo::default());
        let runtime = HostSocketRuntime::new();
        let resolver = HostDnsResolver::new(runtime.clone(), io.clone());

        let address_query = query("peer.example", IpVersion::V4);
        let address_task = tokio::spawn({
            let resolver = resolver.clone();
            let query = address_query.clone();
            async move { resolver.resolve(query).await }
        });
        tokio::task::yield_now().await;
        let (address_operation, submitted) =
            io.operation(|value| matches!(value, TestDnsOperation::Resolve { .. }));
        assert_eq!(submitted, address_query);
        let addresses = vec!["192.0.2.1".parse().unwrap()];
        io.complete_resolve(address_operation, addresses.clone());
        runtime.notify_completions();
        assert_eq!(address_task.await.unwrap().unwrap(), addresses);

        let txt_query = query("_easytier.example", IpVersion::Both);
        let mut txt = Box::pin(resolver.resolve_txt(txt_query.clone()));
        assert!(futures::poll!(&mut txt).is_pending());
        let (txt_operation, submitted) =
            io.operation(|value| matches!(value, TestDnsOperation::Txt { .. }));
        assert_eq!(submitted, txt_query);
        io.complete_txt(txt_operation, "tcp://peer.example:11010".to_owned());
        runtime.notify_completions();
        assert_eq!(txt.await.unwrap(), "tcp://peer.example:11010");

        let srv_query = query("_easytier._udp.example", IpVersion::V6);
        let mut srv = Box::pin(resolver.resolve_srv(srv_query.clone()));
        assert!(futures::poll!(&mut srv).is_pending());
        let (srv_operation, submitted) =
            io.operation(|value| matches!(value, TestDnsOperation::Srv { .. }));
        assert_eq!(submitted, srv_query);
        let records = vec![DnsSrvRecord {
            priority: 10,
            weight: 20,
            port: 11010,
            target: "peer.example.".to_owned(),
        }];
        io.complete_srv(srv_operation, records.clone());
        runtime.notify_completions();
        assert_eq!(srv.await.unwrap(), records);
    }

    #[tokio::test]
    async fn dropping_pending_or_unobserved_completion_cancels_host_state() {
        let io = Arc::new(TestDnsIo::default());
        let runtime = HostSocketRuntime::new();
        let resolver = HostDnsResolver::new(runtime.clone(), io.clone());

        let pending_operation = {
            let mut resolve =
                Box::pin(resolver.resolve_txt(query("pending.example", IpVersion::Both)));
            assert!(futures::poll!(&mut resolve).is_pending());
            assert_eq!(runtime.inner.wakers.len(), 1);
            let (operation, _) =
                io.operation(|value| matches!(value, TestDnsOperation::Txt { .. }));
            drop(resolve);
            assert_eq!(runtime.inner.wakers.len(), 0);
            operation
        };
        let completed_operation = {
            let mut resolve = Box::pin(resolver.resolve(query("cancel.example", IpVersion::Both)));
            assert!(futures::poll!(&mut resolve).is_pending());
            assert_eq!(runtime.inner.wakers.len(), 1);
            let (operation, _) =
                io.operation(|value| matches!(value, TestDnsOperation::Resolve { .. }));
            io.complete_resolve(operation, vec!["192.0.2.2".parse().unwrap()]);
            drop(resolve);
            assert_eq!(runtime.inner.wakers.len(), 0);
            operation
        };

        assert_eq!(
            *io.cancelled.lock().unwrap(),
            vec![pending_operation, completed_operation]
        );
        assert!(io.operations.lock().unwrap().is_empty());
    }
}

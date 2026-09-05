use crate::common::global_ctx::ArcGlobalCtx;
use crate::dns::config::DnsConfigLoaderExt;
use crate::dns::host::DnsHost;
use crate::dns::node_mgr::DnsNodeMgr;
use crate::dns::system::SystemConfig;
use crate::dns::utils::addr::NameServerAddr;
use crate::proto::dns::DnsNodeMgrRpcServer;
use crate::proto::rpc::standalone::{RuntimeRpcListener, StandAloneServer};
use crate::utils::task::CancellableTask;
use hickory_net::runtime::Time;
use hickory_net::xfer::Protocol;
use hickory_server::{
    Server,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::Catalog,
};
use std::collections::HashSet;
use std::{sync::Arc, time::Duration};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{Instrument, instrument};
use uuid::Uuid;

#[derive(Clone)]
struct DynamicCatalog {
    inner: Arc<tokio::sync::RwLock<Catalog>>,
}

impl DynamicCatalog {
    fn new() -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(Catalog::new())),
        }
    }

    async fn replace(&self, new: Catalog) {
        *self.inner.write().await = new;
    }
}

#[async_trait::async_trait]
impl RequestHandler for DynamicCatalog {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        response_handle: R,
    ) -> ResponseInfo {
        self.inner
            .read()
            .await
            .handle_request::<_, T>(request, response_handle)
            .await
    }
}

#[derive(Default)]
struct ListenerRuntime {
    task: Option<CancellableTask<()>>,
    bindings: HashSet<NameServerAddr>,
    generation: Option<u64>,
}

/// One elected, machine-local server. No peer manager or interface is owned here.
pub struct DnsServer {
    mgr: Arc<DnsNodeMgr>,
    host: Arc<dyn DnsHost>,
    owner: Uuid,
    global_ctx: ArcGlobalCtx,
    catalog: DynamicCatalog,
    runtime: Mutex<ListenerRuntime>,
}

const DNS_SERVER_TCP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_SERVER_TCP_BUFFER_SIZE: usize = 32;

impl DnsServer {
    pub fn new(global_ctx: ArcGlobalCtx, host: Arc<dyn DnsHost>) -> Self {
        Self {
            mgr: Arc::new(DnsNodeMgr::new()),
            host,
            owner: Uuid::new_v4(),
            global_ctx,
            catalog: DynamicCatalog::new(),
            runtime: Mutex::new(ListenerRuntime::default()),
        }
    }

    pub fn register(&self, rpc: &StandAloneServer<RuntimeRpcListener>) {
        rpc.registry()
            .register(DnsNodeMgrRpcServer::new_arc(self.mgr.clone()), "");
    }

    /// A single reconciler owns address and listener changes. Failed applications
    /// remain pending and are retried even when the desired snapshot is unchanged.
    async fn reconcile(&self, generation: u64) -> anyhow::Result<()> {
        let addresses: HashSet<_> = self.mgr.iter_addresses().collect();
        let desired_ips = addresses.iter().map(|a| a.addr.ip()).collect();
        let available = self
            .host
            .addresses(self.owner, generation, &desired_ips)
            .await?;
        let desired: HashSet<_> = addresses
            .into_iter()
            .filter(|a| available.contains(&a.addr.ip()))
            .chain(self.mgr.iter_listeners())
            .collect();

        let mut runtime = self.runtime.lock().await;
        if runtime.bindings != desired
            || runtime.generation != Some(generation)
            || runtime
                .task
                .as_ref()
                .is_some_and(CancellableTask::is_finished)
        {
            if let Some(task) = runtime.task.take() {
                task.stop(Some(Duration::from_secs(5))).await?;
            }
            runtime.bindings.clear();
            runtime.generation = Some(generation);
            let mut server = Server::new(self.catalog.clone());
            for binding in &desired {
                let result: anyhow::Result<()> = match binding.protocol {
                    Protocol::Tcp => tokio::net::TcpListener::bind(binding.addr)
                        .await
                        .map(|socket| {
                            server.register_listener(
                                socket,
                                DNS_SERVER_TCP_TIMEOUT,
                                DNS_SERVER_TCP_BUFFER_SIZE,
                            )
                        })
                        .map_err(Into::into),
                    Protocol::Udp => tokio::net::UdpSocket::bind(binding.addr)
                        .await
                        .map(|socket| server.register_socket(socket))
                        .map_err(Into::into),
                    _ => Err(anyhow::anyhow!("unsupported DNS listener protocol")),
                };
                match result {
                    Ok(()) => {
                        runtime.bindings.insert(*binding);
                    }
                    Err(error) => {
                        tracing::warn!(?binding, ?error, "failed to bind DNS listener; will retry")
                    }
                }
            }
            if !runtime.bindings.is_empty() {
                let token = server.shutdown_token().clone();
                let task = tokio::spawn(
                    async move {
                        if let Err(error) = server.block_until_done().await {
                            tracing::error!(?error, "DNS listener runtime exited");
                        }
                    }
                    .instrument(tracing::info_span!("DNS server backend runtime")),
                );
                runtime.task = Some(CancellableTask::with_handle(token, task));
            }
        }

        let config = self.global_ctx.config.try_get_dns()?;
        let domain = config.domain.to_string();
        let system = SystemConfig {
            nameservers: runtime
                .bindings
                .iter()
                .filter(|&a| {
                    a.protocol == Protocol::Udp
                        && a.addr.port() == 53
                        && !a.addr.ip().is_unspecified()
                })
                .map(|a| a.addr.ip().to_string())
                .collect(),
            search_domains: vec![domain.clone()],
            match_domains: std::iter::once(domain)
                .chain(config.zones.iter().map(|zone| zone.origin.to_string()))
                .collect(),
        };
        self.host
            .system_dns(self.owner, generation, &system)
            .await?;
        Ok(())
    }

    async fn stop(&self) {
        // Keep the election RPC listener alive until this method has completed.
        if let Err(error) = self.host.clear_system_dns(self.owner).await {
            tracing::warn!(?error, "failed to clear system DNS settings");
        }
        let mut runtime = self.runtime.lock().await;
        if let Some(task) = runtime.task.take()
            && let Err(error) = task.stop(Some(Duration::from_secs(5))).await
        {
            tracing::warn!(?error, "failed to stop DNS listener runtime");
        }
        runtime.bindings.clear();
        if let Err(error) = self.host.release(self.owner).await {
            tracing::warn!(?error, "failed to release DNS interface resources");
        }
    }

    #[instrument(skip_all, name = "DnsServer main loop")]
    pub async fn run(&self, token: CancellationToken) {
        let mut interface = self.host.subscribe();
        let mut interface_open = true;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                biased;
                _ = token.cancelled() => break,
                _ = interval.tick() => {},
                _ = self.mgr.dirty.catalog.wait() => {},
                _ = self.mgr.dirty.addresses.wait() => {},
                _ = self.mgr.dirty.listeners.wait() => {},
                changed = interface.changed(), if interface_open => {
                    interface_open = changed.is_ok();
                }
            }
            self.mgr.maintain().await;
            if self.mgr.dirty.catalog.reset() {
                self.catalog.replace(self.mgr.catalog()).await;
            }
            self.mgr.dirty.addresses.reset();
            self.mgr.dirty.listeners.reset();
            let generation = interface.borrow_and_update().generation;
            if let Err(error) = self.reconcile(generation).await {
                tracing::warn!(?error, "DNS resources not yet applied; will retry");
            }
        }
        self.stop().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_net::client::{Client, ClientHandle};
    use hickory_net::runtime::TokioRuntimeProvider;
    use hickory_net::udp::UdpClientStream;
    use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, rdata};
    use hickory_server::store::in_memory::InMemoryZoneHandler;
    use hickory_server::zone_handler::ZoneType;
    use hickory_server::zone_handler::{AxfrPolicy, Catalog};
    use std::net::Ipv4Addr;
    use std::str::FromStr;
    use std::time::Duration;

    use crate::dns::host::{DnsInterfaceState, NoDnsInterface};
    use crate::proto::dns::{DnsNodeMgrRpc, DnsSnapshot, HeartbeatRequest};
    use crate::proto::rpc_types::controller::BaseController;
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::sync::watch;

    #[derive(Debug)]
    struct RecordingHost {
        state: watch::Sender<DnsInterfaceState>,
        fail_next: AtomicBool,
        calls: Mutex<Vec<(u64, HashSet<IpAddr>)>>,
        cleanup: Mutex<Vec<&'static str>>,
    }

    impl RecordingHost {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: watch::channel(DnsInterfaceState {
                    generation: 0,
                    available: true,
                })
                .0,
                fail_next: AtomicBool::new(false),
                calls: Mutex::new(Vec::new()),
                cleanup: Mutex::new(Vec::new()),
            })
        }
    }

    #[async_trait::async_trait]
    impl DnsHost for RecordingHost {
        fn subscribe(&self) -> watch::Receiver<DnsInterfaceState> {
            self.state.subscribe()
        }

        async fn addresses(
            &self,
            _: Uuid,
            generation: u64,
            desired: &HashSet<IpAddr>,
        ) -> anyhow::Result<HashSet<IpAddr>> {
            anyhow::ensure!(
                generation == self.state.borrow().generation,
                "stale interface"
            );
            self.calls.lock().await.push((generation, desired.clone()));
            anyhow::ensure!(
                !self.fail_next.swap(false, Ordering::SeqCst),
                "temporarily unavailable"
            );
            Ok(desired.clone())
        }

        async fn system_dns(
            &self,
            _: Uuid,
            generation: u64,
            _: &SystemConfig,
        ) -> anyhow::Result<()> {
            anyhow::ensure!(
                generation == self.state.borrow().generation,
                "stale interface"
            );
            Ok(())
        }

        async fn clear_system_dns(&self, _: Uuid) -> anyhow::Result<()> {
            self.cleanup.lock().await.push("system");
            Ok(())
        }

        async fn release(&self, _: Uuid) -> anyhow::Result<()> {
            self.cleanup.lock().await.push("addresses");
            Ok(())
        }
    }

    fn test_server(host: Arc<dyn DnsHost>) -> DnsServer {
        DnsServer::new(
            crate::common::global_ctx::tests::get_mock_global_ctx(),
            host,
        )
    }

    fn unused_address() -> SocketAddr {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    async fn set_snapshot(server: &DnsServer, addresses: Vec<String>, listeners: Vec<String>) {
        let mut heartbeat = HeartbeatRequest {
            id: Some(Uuid::nil().into()),
            ..Default::default()
        };
        heartbeat.update(DnsSnapshot {
            addresses: addresses.into_iter().map(|a| a.parse().unwrap()).collect(),
            listeners: listeners.into_iter().map(|a| a.parse().unwrap()).collect(),
            zones: Vec::new(),
        });
        server
            .mgr
            .heartbeat(BaseController::default(), heartbeat)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn unchanged_snapshot_reapplies_generation_and_retries_failed_host() {
        let host = RecordingHost::new();
        let server = test_server(host.clone());
        let addr = unused_address();
        set_snapshot(&server, vec![format!("udp://{addr}")], vec![]).await;
        server.reconcile(0).await.unwrap();

        host.state.send_replace(DnsInterfaceState {
            generation: 1,
            available: true,
        });
        host.fail_next.store(true, Ordering::SeqCst);
        assert!(server.reconcile(1).await.is_err());
        server.reconcile(1).await.unwrap();
        assert!(server.reconcile(0).await.is_err());
        let calls = host.calls.lock().await;
        assert_eq!(
            calls.iter().map(|call| call.0).collect::<Vec<_>>(),
            vec![0, 1, 1]
        );
        assert!(
            calls
                .iter()
                .all(|call| call.1 == HashSet::from([addr.ip()]))
        );
        drop(calls);

        server.stop().await;
        assert_eq!(*host.cleanup.lock().await, vec!["system", "addresses"]);
        assert!(
            std::net::UdpSocket::bind(addr).is_ok(),
            "stop must await socket release"
        );
    }

    #[tokio::test]
    async fn removing_one_protocol_keeps_shared_interface_ip() {
        let host = RecordingHost::new();
        let server = test_server(host.clone());
        let addr = unused_address();
        set_snapshot(
            &server,
            vec![format!("udp://{addr}"), format!("tcp://{addr}")],
            vec![],
        )
        .await;
        server.reconcile(0).await.unwrap();
        set_snapshot(&server, vec![format!("tcp://{addr}")], vec![]).await;
        server.reconcile(0).await.unwrap();

        let calls = host.calls.lock().await;
        assert_eq!(calls.len(), 2);
        assert!(
            calls
                .iter()
                .all(|call| call.1 == HashSet::from([addr.ip()]))
        );
        drop(calls);
        assert!(std::net::UdpSocket::bind(addr).is_ok());
        server.stop().await;
        assert!(std::net::TcpListener::bind(addr).is_ok());
    }

    #[tokio::test]
    async fn listener_only_without_interface_answers_and_releases_port() {
        let server = test_server(Arc::new(NoDnsInterface));
        let addr = unused_address();
        server.catalog.replace(build_test_catalog()).await;
        set_snapshot(&server, vec![], vec![format!("udp://{addr}")]).await;
        server.reconcile(0).await.unwrap();
        let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
        let (mut client, background) = Client::<TokioRuntimeProvider>::from_sender(stream);
        let background = tokio::spawn(background);
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            client.query(
                "test.example.com.".parse().unwrap(),
                DNSClass::IN,
                RecordType::A,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            result
                .answers
                .iter()
                .any(|r| matches!(&r.data, RData::A(ip) if ip.0 == Ipv4Addr::new(1,2,3,4)))
        );
        background.abort();
        let _ = background.await;
        server.stop().await;
        assert!(std::net::UdpSocket::bind(addr).is_ok());
    }

    /// Build a `Catalog` containing a single A record: `test.example.com -> 1.2.3.4`.
    fn build_test_catalog() -> Catalog {
        let origin = Name::from_str("example.com.").unwrap();
        let mut zone_handler = InMemoryZoneHandler::<TokioRuntimeProvider>::empty(
            origin.clone(),
            ZoneType::Primary,
            AxfrPolicy::default(),
        );

        let record = Record::from_rdata(
            Name::from_str("test.example.com.").unwrap(),
            60,
            RData::A(rdata::a::A(Ipv4Addr::new(1, 2, 3, 4))),
        );
        let rr_key =
            hickory_proto::rr::RrKey::new(record.name.clone().into(), record.record_type());
        let mut rr_set =
            hickory_proto::rr::RecordSet::new(record.name.clone(), record.record_type(), 0);
        rr_set.insert(record, 0);
        zone_handler
            .records_get_mut()
            .insert(rr_key, Arc::new(rr_set));

        let mut catalog = Catalog::new();
        catalog.upsert(
            origin.into(),
            vec![Arc::new(zone_handler) as Arc<dyn hickory_server::zone_handler::ZoneHandler>],
        );
        catalog
    }

    // ─── Tests ───────────────────────────────────────────────────────────

    /// Full end-to-end test: start a real DNS UDP listener via `ServerFuture`,
    /// send a query with a `hickory_client`, and verify the response.
    #[tokio::test]
    async fn should_resolve_record_via_real_udp_listener() {
        use hickory_server::Server;
        use tokio::net::UdpSocket;
        use tokio::time::timeout;

        // Build a catalog with test.example.com -> 1.2.3.4.
        let catalog = build_test_catalog();

        // Bind to a random port.
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let mut server = Server::new(catalog);
        server.register_socket(socket);

        let shutdown_token = server.shutdown_token().clone();
        tokio::spawn(async move {
            server.block_until_done().await.ok();
        });

        // Send a real DNS query using hickory_client.
        let stream = UdpClientStream::builder(addr, TokioRuntimeProvider::default()).build();
        let (mut client, bg) = Client::<TokioRuntimeProvider>::from_sender(stream);

        tokio::spawn(bg);

        let response = timeout(
            Duration::from_secs(2),
            client.query(
                Name::from_str("test.example.com.").unwrap(),
                DNSClass::IN,
                RecordType::A,
            ),
        )
        .await
        .expect("query timeout")
        .expect("query failed");

        assert!(!response.answers.is_empty(), "should get answers");
        let a_record = &response.answers[0];
        if let RData::A(a) = a_record.data {
            assert_eq!(a.0, Ipv4Addr::new(1, 2, 3, 4));
        } else {
            panic!("expected A record, got {:?}", a_record.data);
        }

        // Shutdown the server.
        shutdown_token.cancel();
    }
}

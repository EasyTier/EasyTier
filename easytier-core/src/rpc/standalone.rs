use std::{
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::Context as _;
use tokio::task::JoinSet;

use crate::{
    connectivity::protocol::raw::TunnelDialer,
    proto::{
        common::TunnelInfo,
        rpc_types::{__rt::RpcClientFactory, error::Error},
    },
    rpc::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
    socket::SocketListener,
    tunnel::Tunnel,
};

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc, Box)]
pub trait RpcServerHook: Send + Sync {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        Ok(tunnel_info)
    }

    async fn on_client_disconnected(&self, _tunnel_info: Option<TunnelInfo>) {}
}

struct DefaultHook;

impl RpcServerHook for DefaultHook {}

struct BoundListener<L, G> {
    listener: L,
    // Release protection only after the listener has been dropped.
    _guard: G,
}

pub struct StandAloneServer<L> {
    registry: Arc<ServiceRegistry>,
    listener: Option<L>,
    inflight_server: Arc<AtomicU32>,
    tasks: JoinSet<()>,
    hook: Option<Arc<dyn RpcServerHook>>,
    rx_timeout: Option<Duration>,
}

impl<L> StandAloneServer<L>
where
    L: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn new(listener: L) -> Self {
        Self {
            registry: Arc::new(ServiceRegistry::new()),
            listener: Some(listener),
            inflight_server: Arc::new(AtomicU32::new(0)),
            tasks: JoinSet::new(),
            hook: None,
            rx_timeout: Some(Duration::from_secs(60)),
        }
    }

    pub fn set_rx_timeout(&mut self, timeout: Option<Duration>) {
        self.rx_timeout = timeout;
    }

    pub fn set_hook(&mut self, hook: Arc<dyn RpcServerHook>) {
        self.hook = Some(hook);
    }

    pub fn registry(&self) -> &ServiceRegistry {
        &self.registry
    }

    async fn serve_loop(
        listener: &mut L,
        inflight: Arc<AtomicU32>,
        registry: Arc<ServiceRegistry>,
        hook: Arc<dyn RpcServerHook>,
        rx_timeout: Option<Duration>,
    ) -> Result<(), Error> {
        let mut client_tasks = JoinSet::new();

        loop {
            let accepted = {
                let accept = listener.accept();
                tokio::pin!(accept);
                loop {
                    tokio::select! {
                        accepted = &mut accept => break accepted,
                        _ = client_tasks.join_next(), if !client_tasks.is_empty() => {}
                    }
                }
            };
            let tunnel = accepted?;
            let tunnel_info = tunnel.info();
            let registry = registry.clone();
            let inflight_server = inflight.clone();
            let hook = hook.clone();

            let tunnel_info = match hook.on_new_client(tunnel_info).await {
                Ok(info) => info,
                Err(error) => {
                    tracing::warn!(?error, "standalone hook.on_new_client failed");
                    continue;
                }
            };

            inflight_server.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            client_tasks.spawn(async move {
                let server = BidirectRpcManager::new().set_rx_timeout(rx_timeout);
                server.rpc_server().registry().replace_registry(&registry);
                server.run_with_tunnel(tunnel);
                server.wait().await;
                hook.on_client_disconnected(tunnel_info).await;
                inflight_server.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    async fn run_bound_listener<G>(
        mut bound_listener: BoundListener<L, G>,
        inflight_server: Arc<AtomicU32>,
        registry: Arc<ServiceRegistry>,
        hook: Arc<dyn RpcServerHook>,
        rx_timeout: Option<Duration>,
    ) where
        G: Send + 'static,
    {
        loop {
            let ret = Self::serve_loop(
                &mut bound_listener.listener,
                inflight_server.clone(),
                registry.clone(),
                hook.clone(),
                rx_timeout,
            )
            .await;
            if let Err(error) = ret {
                tracing::error!(
                    ?error,
                    url = ?bound_listener.listener.local_url(),
                    "serve_loop exit unexpectedly"
                );
                println!("standalone serve_loop exit unexpectedly: {error:?}");
            }

            crate::foundation::time::sleep(Duration::from_secs(1)).await;
        }
    }

    pub async fn serve(&mut self) -> Result<(), Error> {
        self.serve_with_bound_listener((), |_| Ok(())).await
    }

    #[cfg(feature = "management-rpc")]
    pub(crate) fn listener_url(&self) -> url::Url {
        self.listener
            .as_ref()
            .expect("standalone listener must be available before serve")
            .local_url()
    }

    pub(crate) async fn serve_with_bound_listener<F, B, G>(
        &mut self,
        binding_guard: B,
        on_bound: F,
    ) -> Result<(), Error>
    where
        F: FnOnce(&url::Url) -> Result<G, Error>,
        G: Send + 'static,
    {
        let mut listener = self.listener.take().unwrap();
        let hook = self.hook.take().unwrap_or_else(|| Arc::new(DefaultHook));
        let rx_timeout = self.rx_timeout;

        if let Err(error) = listener.listen().await.with_context(|| "failed to listen") {
            drop(listener);
            drop(binding_guard);
            return Err(error.into());
        }
        let guard = match on_bound(&listener.local_url()) {
            Ok(guard) => guard,
            Err(error) => {
                drop(listener);
                drop(binding_guard);
                return Err(error);
            }
        };
        drop(binding_guard);
        let bound_listener = BoundListener {
            listener,
            _guard: guard,
        };

        let registry = self.registry.clone();
        let inflight_server = self.inflight_server.clone();

        self.tasks.spawn(Self::run_bound_listener(
            bound_listener,
            inflight_server,
            registry,
            hook,
            rx_timeout,
        ));

        Ok(())
    }

    pub fn inflight_server(&self) -> u32 {
        self.inflight_server
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct StandAloneClient<C: TunnelDialer> {
    connector: C,
    client: Option<BidirectRpcManager>,
}

impl<C: TunnelDialer> StandAloneClient<C> {
    pub fn new(connector: C) -> Self {
        Self {
            connector,
            client: None,
        }
    }

    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        Ok(self.connector.connect().await.with_context(|| {
            format!(
                "failed to connect to server: {:?}",
                self.connector.remote_url()
            )
        })?)
    }

    pub async fn scoped_client<F: RpcClientFactory>(
        &mut self,
        domain_name: String,
    ) -> Result<F::ClientImpl, Error> {
        let mut client = self.client.take();
        let error = client.as_ref().and_then(BidirectRpcManager::take_error);
        if client.is_none() || error.is_some() {
            tracing::info!(?error, "reconnect standalone RPC client");
            let tunnel = self.connect().await?;
            let manager = BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(60)));
            manager.run_with_tunnel(tunnel);
            client = Some(manager);
        }

        self.client = client;

        Ok(self
            .client
            .as_ref()
            .unwrap()
            .rpc_client()
            .scoped_client::<F>(1, 1, domain_name))
    }

    pub async fn wait(&mut self) {
        if let Some(client) = self.client.take() {
            client.wait().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicU32, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::mpsc;
    use url::Url;

    use super::{RpcServerHook, StandAloneClient, StandAloneServer};
    use crate::{
        connectivity::protocol::raw::TunnelDialer,
        foundation::time::{sleep, timeout},
        proto::{
            common::TunnelInfo,
            peer_rpc::{
                GetGlobalPeerMapRequest, GetGlobalPeerMapResponse, PeerCenterRpc,
                PeerCenterRpcClientFactory, PeerCenterRpcServer, ReportPeersRequest,
                ReportPeersResponse,
            },
            rpc_types::{controller::BaseController, error},
        },
        socket::SocketListener,
        tunnel::{Tunnel, ring::create_ring_tunnel_pair},
    };

    struct TestListener {
        accepted: mpsc::Receiver<Box<dyn Tunnel>>,
        accept_tracker: Option<Arc<AcceptTracker>>,
    }

    struct BoundUrlListener {
        listening: bool,
        drop_order: Option<Arc<Mutex<Vec<&'static str>>>>,
        binding_guard_alive: Option<Arc<AtomicBool>>,
    }

    struct TestProtectionLease(Arc<Mutex<Vec<&'static str>>>);

    struct TestBindingGuard(Arc<AtomicBool>);

    #[derive(Default)]
    struct AcceptTracker {
        started: AtomicU32,
        cancelled: AtomicU32,
    }

    struct AcceptAttempt {
        tracker: Arc<AcceptTracker>,
        completed: bool,
    }

    impl Drop for AcceptAttempt {
        fn drop(&mut self) {
            if !self.completed {
                self.tracker.cancelled.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    impl fmt::Debug for TestListener {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("TestListener").finish()
        }
    }

    impl fmt::Debug for BoundUrlListener {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("BoundUrlListener").finish()
        }
    }

    impl Drop for BoundUrlListener {
        fn drop(&mut self) {
            if let Some(drop_order) = &self.drop_order {
                drop_order.lock().unwrap().push("listener");
            }
        }
    }

    impl Drop for TestProtectionLease {
        fn drop(&mut self) {
            self.0.lock().unwrap().push("protection");
        }
    }

    impl Drop for TestBindingGuard {
        fn drop(&mut self) {
            self.0.store(false, Ordering::Release);
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for TestListener {
        type Accepted = Box<dyn Tunnel>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            let mut attempt = self.accept_tracker.as_ref().map(|tracker| {
                tracker.started.fetch_add(1, Ordering::Relaxed);
                AcceptAttempt {
                    tracker: tracker.clone(),
                    completed: false,
                }
            });
            let result = self
                .accepted
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("test listener closed"));
            if let Some(attempt) = attempt.as_mut() {
                attempt.completed = true;
            }
            result
        }

        fn local_url(&self) -> Url {
            "ring://standalone-rpc".parse().unwrap()
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for BoundUrlListener {
        type Accepted = Box<dyn Tunnel>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            if let Some(alive) = &self.binding_guard_alive {
                assert!(alive.load(Ordering::Acquire));
            }
            self.listening = true;
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            std::future::pending().await
        }

        fn local_url(&self) -> Url {
            if self.listening {
                "tcp://127.0.0.1:15888".parse().unwrap()
            } else {
                "tcp://127.0.0.1:0".parse().unwrap()
            }
        }
    }

    struct TestDialer {
        accepted: Arc<Mutex<mpsc::Sender<Box<dyn Tunnel>>>>,
        connections: Arc<AtomicU32>,
    }

    #[async_trait::async_trait]
    impl TunnelDialer for TestDialer {
        async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
            let (client, accepted) = create_ring_tunnel_pair();
            let sender = self.accepted.lock().unwrap().clone();
            sender
                .send(accepted)
                .await
                .map_err(|_| anyhow::anyhow!("test listener closed"))?;
            self.connections.fetch_add(1, Ordering::Relaxed);
            Ok(client)
        }

        fn remote_url(&self) -> Url {
            "ring://standalone-rpc".parse().unwrap()
        }
    }

    #[derive(Clone, Debug)]
    struct TestRpcService;

    #[async_trait::async_trait]
    impl PeerCenterRpc for TestRpcService {
        type Controller = BaseController;

        async fn report_peers(
            &self,
            _controller: BaseController,
            _request: ReportPeersRequest,
        ) -> error::Result<ReportPeersResponse> {
            Ok(ReportPeersResponse::default())
        }

        async fn get_global_peer_map(
            &self,
            _controller: BaseController,
            _request: GetGlobalPeerMapRequest,
        ) -> error::Result<GetGlobalPeerMapResponse> {
            Ok(GetGlobalPeerMapResponse {
                digest: Some(42),
                ..Default::default()
            })
        }
    }

    #[derive(Default)]
    struct CountingHook {
        connected: AtomicU32,
        disconnected: AtomicU32,
    }

    #[async_trait::async_trait]
    impl RpcServerHook for CountingHook {
        async fn on_new_client(
            &self,
            tunnel_info: Option<TunnelInfo>,
        ) -> Result<Option<TunnelInfo>, anyhow::Error> {
            self.connected.fetch_add(1, Ordering::Relaxed);
            Ok(tunnel_info)
        }

        async fn on_client_disconnected(&self, _tunnel_info: Option<TunnelInfo>) {
            self.disconnected.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[tokio::test]
    async fn serve_reports_the_actual_bound_listener_url() {
        let mut server = StandAloneServer::new(BoundUrlListener {
            listening: false,
            drop_order: None,
            binding_guard_alive: None,
        });
        let mut bound_url = None;

        server
            .serve_with_bound_listener((), |url| {
                bound_url = Some(url.clone());
                Ok(())
            })
            .await
            .unwrap();

        assert_eq!(
            bound_url.unwrap(),
            "tcp://127.0.0.1:15888".parse::<Url>().unwrap()
        );
    }

    #[tokio::test]
    async fn binding_guard_covers_listen_and_bound_guard_creation() {
        let binding_guard_alive = Arc::new(AtomicBool::new(true));
        let mut server = StandAloneServer::new(BoundUrlListener {
            listening: false,
            drop_order: None,
            binding_guard_alive: Some(binding_guard_alive.clone()),
        });

        server
            .serve_with_bound_listener(TestBindingGuard(binding_guard_alive.clone()), |_| {
                assert!(binding_guard_alive.load(Ordering::Acquire));
                Ok(())
            })
            .await
            .unwrap();

        assert!(!binding_guard_alive.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn listener_drops_before_its_bound_resource_guard() {
        let drop_order = Arc::new(Mutex::new(Vec::new()));
        let mut server = StandAloneServer::new(BoundUrlListener {
            listening: false,
            drop_order: Some(drop_order.clone()),
            binding_guard_alive: None,
        });
        server
            .serve_with_bound_listener((), |_| Ok(TestProtectionLease(drop_order.clone())))
            .await
            .unwrap();

        drop(server);
        timeout(Duration::from_secs(1), async {
            loop {
                if drop_order.lock().unwrap().len() == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        assert_eq!(*drop_order.lock().unwrap(), ["listener", "protection"]);
    }

    #[tokio::test]
    async fn server_owns_accepted_client_lifecycle() {
        let (sender, receiver) = mpsc::channel(1);
        let hook = Arc::new(CountingHook::default());
        let mut server = StandAloneServer::new(TestListener {
            accepted: receiver,
            accept_tracker: None,
        });
        server.set_hook(hook.clone());
        server.serve().await.unwrap();

        let (client, accepted) = create_ring_tunnel_pair();
        sender.send(accepted).await.unwrap();

        timeout(Duration::from_secs(1), async {
            while server.inflight_server() != 1 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(hook.connected.load(Ordering::Relaxed), 1);

        drop(client);
        timeout(Duration::from_secs(1), async {
            while server.inflight_server() != 0 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(hook.disconnected.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn reaping_clients_does_not_cancel_an_in_progress_accept() {
        let (sender, receiver) = mpsc::channel(1);
        let tracker = Arc::new(AcceptTracker::default());
        let mut server = StandAloneServer::new(TestListener {
            accepted: receiver,
            accept_tracker: Some(tracker.clone()),
        });
        server.serve().await.unwrap();

        let (client, accepted) = create_ring_tunnel_pair();
        sender.send(accepted).await.unwrap();
        timeout(Duration::from_secs(1), async {
            while tracker.started.load(Ordering::Relaxed) < 2 {
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        drop(client);
        timeout(Duration::from_secs(1), async {
            while server.inflight_server() != 0 {
                sleep(Duration::from_millis(10)).await;
            }
            sleep(Duration::from_millis(20)).await;
        })
        .await
        .unwrap();

        assert_eq!(tracker.started.load(Ordering::Relaxed), 2);
        assert_eq!(tracker.cancelled.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn client_reuses_connection_and_reconnects_after_disconnect() {
        let (sender, receiver) = mpsc::channel(2);
        let accepted = Arc::new(Mutex::new(sender));
        let connections = Arc::new(AtomicU32::new(0));
        let dialer = TestDialer {
            accepted: accepted.clone(),
            connections: connections.clone(),
        };
        let mut server = StandAloneServer::new(TestListener {
            accepted: receiver,
            accept_tracker: None,
        });
        server
            .registry()
            .register(PeerCenterRpcServer::new(TestRpcService), "test");
        server.serve().await.unwrap();

        let mut client = StandAloneClient::new(dialer);
        let rpc = client
            .scoped_client::<PeerCenterRpcClientFactory<BaseController>>("test".to_string())
            .await
            .unwrap();
        let response = rpc
            .get_global_peer_map(
                BaseController::default(),
                GetGlobalPeerMapRequest::default(),
            )
            .await
            .unwrap();
        assert_eq!(response.digest, Some(42));

        client
            .scoped_client::<PeerCenterRpcClientFactory<BaseController>>("test".to_string())
            .await
            .unwrap();
        assert_eq!(connections.load(Ordering::Relaxed), 1);

        drop(server);
        let (sender, receiver) = mpsc::channel(2);
        *accepted.lock().unwrap() = sender;
        let mut restarted_server = StandAloneServer::new(TestListener {
            accepted: receiver,
            accept_tracker: None,
        });
        restarted_server
            .registry()
            .register(PeerCenterRpcServer::new(TestRpcService), "test");
        restarted_server.serve().await.unwrap();

        let rpc = timeout(Duration::from_secs(1), async {
            loop {
                let rpc = client
                    .scoped_client::<PeerCenterRpcClientFactory<BaseController>>("test".to_string())
                    .await
                    .unwrap();
                if connections.load(Ordering::Relaxed) == 2 {
                    break rpc;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        rpc.get_global_peer_map(
            BaseController::default(),
            GetGlobalPeerMapRequest::default(),
        )
        .await
        .unwrap();
    }
}

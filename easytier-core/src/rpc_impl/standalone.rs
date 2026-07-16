use std::{
    sync::{Arc, atomic::AtomicU32},
    time::Duration,
};

use anyhow::Context as _;
use tokio::task::JoinSet;

use crate::{
    connectivity::protocol::raw::TunnelDialer,
    listener::SocketListener,
    proto::{
        common::TunnelInfo,
        rpc_types::{__rt::RpcClientFactory, error::Error},
    },
    rpc_impl::{bidirect::BidirectRpcManager, service_registry::ServiceRegistry},
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
            tokio::select! {
                accepted = listener.accept() => {
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
                _ = client_tasks.join_next(), if !client_tasks.is_empty() => {}
            }
        }
    }

    pub async fn serve(&mut self) -> Result<(), Error> {
        let mut listener = self.listener.take().unwrap();
        let hook = self.hook.take().unwrap_or_else(|| Arc::new(DefaultHook));
        let rx_timeout = self.rx_timeout;

        listener
            .listen()
            .await
            .with_context(|| "failed to listen")?;

        let registry = self.registry.clone();
        let inflight_server = self.inflight_server.clone();

        self.tasks.spawn(async move {
            loop {
                let ret = Self::serve_loop(
                    &mut listener,
                    inflight_server.clone(),
                    registry.clone(),
                    hook.clone(),
                    rx_timeout,
                )
                .await;
                if let Err(error) = ret {
                    tracing::error!(
                        ?error,
                        url = ?listener.local_url(),
                        "serve_loop exit unexpectedly"
                    );
                    println!("standalone serve_loop exit unexpectedly: {error:?}");
                }

                crate::runtime_time::sleep(Duration::from_secs(1)).await;
            }
        });

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
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        time::Duration,
    };

    use tokio::sync::mpsc;
    use url::Url;

    use super::{RpcServerHook, StandAloneServer};
    use crate::{
        listener::SocketListener,
        proto::common::TunnelInfo,
        runtime_time::{sleep, timeout},
        tunnel::{Tunnel, ring::create_ring_tunnel_pair},
    };

    struct TestListener {
        accepted: mpsc::Receiver<Box<dyn Tunnel>>,
    }

    impl fmt::Debug for TestListener {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("TestListener").finish()
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for TestListener {
        type Accepted = Box<dyn Tunnel>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            self.accepted
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("test listener closed"))
        }

        fn local_url(&self) -> Url {
            "ring://standalone-rpc".parse().unwrap()
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
    async fn server_owns_accepted_client_lifecycle() {
        let (sender, receiver) = mpsc::channel(1);
        let hook = Arc::new(CountingHook::default());
        let mut server = StandAloneServer::new(TestListener { accepted: receiver });
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
}

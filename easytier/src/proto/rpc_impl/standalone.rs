use std::{
    sync::{atomic::AtomicU32, Arc, Mutex},
    time::Duration,
};

use anyhow::Context as _;
use tokio::task::JoinSet;

use crate::{
    common::join_joinset_background,
    proto::{
        common::TunnelInfo,
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{__rt::RpcClientFactory, error::Error},
    },
    tunnel::{Tunnel, TunnelConnector, TunnelListener},
};

use super::service_registry::ServiceRegistry;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc, Box)]
pub trait RpcServerHook: Send + Sync {
    async fn on_new_client(&self, _tunnel_info: Option<TunnelInfo>) {}
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
}

impl<L: TunnelListener + 'static> StandAloneServer<L> {
    pub fn new(listener: L) -> Self {
        StandAloneServer {
            registry: Arc::new(ServiceRegistry::new()),
            listener: Some(listener),
            inflight_server: Arc::new(AtomicU32::new(0)),
            tasks: JoinSet::new(),

            hook: None,
        }
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
    ) -> Result<(), Error> {
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "standalone serve_loop".to_string());

        loop {
            let tunnel = listener.accept().await?;
            let tunnel_info = tunnel.info();
            let registry = registry.clone();
            let inflight_server = inflight.clone();
            let hook = hook.clone();

            hook.on_new_client(tunnel_info.clone()).await;

            inflight_server.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tasks.lock().unwrap().spawn(async move {
                let server =
                    BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(60)));
                server.rpc_server().registry().replace_registry(&registry);
                server.run_with_tunnel(tunnel);
                server.wait().await;
                hook.on_client_disconnected(tunnel_info.clone()).await;
                inflight_server.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    pub async fn serve(&mut self) -> Result<(), Error> {
        let mut listener = self.listener.take().unwrap();
        let hook = self.hook.take().unwrap_or_else(|| Arc::new(DefaultHook));

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
                )
                .await;
                if let Err(e) = ret {
                    tracing::error!(?e, url = ?listener.local_url(), "serve_loop exit unexpectedly");
                    println!("standalone serve_loop exit unexpectedly: {:?}", e);
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    pub fn inflight_server(&self) -> u32 {
        self.inflight_server
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

pub struct StandAloneClient<C: TunnelConnector> {
    connector: C,
    client: Option<BidirectRpcManager>,
}

impl<C: TunnelConnector> StandAloneClient<C> {
    pub fn new(connector: C) -> Self {
        StandAloneClient {
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
        let mut c = self.client.take();
        let error = c.as_ref().and_then(|c| c.take_error());
        if c.is_none() || error.is_some() {
            tracing::info!("reconnect due to error: {:?}", error);
            let tunnel = self.connect().await?;
            let mgr = BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(60)));
            mgr.run_with_tunnel(tunnel);
            c = Some(mgr);
        }

        self.client = c;

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
    use crate::{
        proto::rpc_impl::standalone::StandAloneServer,
        tunnel::{
            tcp::{TcpTunnelConnector, TcpTunnelListener},
            TunnelConnector as _,
        },
    };

    #[tokio::test]
    async fn standalone_exit_on_drop() {
        let addr: url::Url = "tcp://0.0.0.0:53884".parse().unwrap();
        let tunnel = TcpTunnelListener::new(addr.clone());
        let mut server = StandAloneServer::new(tunnel);
        server.serve().await.unwrap();
        drop(server);

        // tcp should closed
        let mut connector = TcpTunnelConnector::new(addr);
        connector.connect().await.unwrap_err();
    }
}

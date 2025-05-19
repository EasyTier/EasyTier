use std::{
    sync::{atomic::AtomicU32, Arc, Mutex},
    time::Duration,
};

use anyhow::Context as _;
use tokio::task::JoinSet;

use crate::{
    common::join_joinset_background,
    proto::{
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{__rt::RpcClientFactory, error::Error},
    },
    tunnel::{Tunnel, TunnelConnector, TunnelListener},
};

use super::service_registry::ServiceRegistry;

pub struct StandAloneServer<L> {
    registry: Arc<ServiceRegistry>,
    listener: Option<L>,
    inflight_server: Arc<AtomicU32>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl<L: TunnelListener + 'static> StandAloneServer<L> {
    pub fn new(listener: L) -> Self {
        StandAloneServer {
            registry: Arc::new(ServiceRegistry::new()),
            listener: Some(listener),
            inflight_server: Arc::new(AtomicU32::new(0)),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        }
    }

    pub fn registry(&self) -> &ServiceRegistry {
        &self.registry
    }

    async fn serve_loop(
        listener: &mut L,
        inflight: Arc<AtomicU32>,
        registry: Arc<ServiceRegistry>,
        tasks: Arc<Mutex<JoinSet<()>>>,
    ) -> Result<(), Error> {
        listener
            .listen()
            .await
            .with_context(|| "failed to listen")?;

        loop {
            let tunnel = listener.accept().await?;
            let registry = registry.clone();
            let inflight_server = inflight.clone();
            inflight_server.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tasks.lock().unwrap().spawn(async move {
                let server =
                    BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(60)));
                server.rpc_server().registry().replace_registry(&registry);
                server.run_with_tunnel(tunnel);
                server.wait().await;
                inflight_server.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }

    pub async fn serve(&mut self) -> Result<(), Error> {
        let tasks = self.tasks.clone();
        let mut listener = self.listener.take().unwrap();
        let registry = self.registry.clone();

        join_joinset_background(tasks.clone(), "standalone server tasks".to_string());

        let inflight_server = self.inflight_server.clone();

        self.tasks.lock().unwrap().spawn(async move {
            loop {
                let ret = Self::serve_loop(
                    &mut listener,
                    inflight_server.clone(),
                    registry.clone(),
                    tasks.clone(),
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
}

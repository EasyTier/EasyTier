use std::{
    sync::{atomic::AtomicU32, Arc, Mutex},
    time::Duration,
};

use anyhow::Context as _;
use futures::{SinkExt as _, StreamExt};
use tokio::task::JoinSet;

use crate::{
    common::join_joinset_background,
    proto::rpc_types::{__rt::RpcClientFactory, error::Error},
    tunnel::{Tunnel, TunnelConnector, TunnelListener},
};

use super::{client::Client, server::Server, service_registry::ServiceRegistry};

struct StandAloneServerOneTunnel {
    tunnel: Box<dyn Tunnel>,
    rpc_server: Server,
}

impl StandAloneServerOneTunnel {
    pub fn new(tunnel: Box<dyn Tunnel>, registry: Arc<ServiceRegistry>) -> Self {
        let rpc_server = Server::new_with_registry(registry);
        StandAloneServerOneTunnel { tunnel, rpc_server }
    }

    pub async fn run(self) {
        use tokio_stream::StreamExt as _;

        let (tunnel_rx, tunnel_tx) = self.tunnel.split();
        let (rpc_rx, rpc_tx) = (
            self.rpc_server.get_transport_stream(),
            self.rpc_server.get_transport_sink(),
        );

        let mut tasks = JoinSet::new();

        tasks.spawn(async move {
            let ret = tunnel_rx.timeout(Duration::from_secs(60));
            tokio::pin!(ret);
            while let Ok(Some(Ok(p))) = ret.try_next().await {
                if let Err(e) = rpc_tx.send(p).await {
                    tracing::error!("tunnel_rx send to rpc_tx error: {:?}", e);
                    break;
                }
            }
            tracing::info!("forward tunnel_rx to rpc_tx done");
        });

        tasks.spawn(async move {
            let ret = rpc_rx.forward(tunnel_tx).await;
            tracing::info!("rpc_rx forward tunnel_tx done: {:?}", ret);
        });

        self.rpc_server.run();

        while let Some(ret) = tasks.join_next().await {
            self.rpc_server.close();
            tracing::info!("task done: {:?}", ret);
        }

        tracing::info!("all tasks done");
    }
}

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

    pub async fn serve(&mut self) -> Result<(), Error> {
        let tasks = self.tasks.clone();
        let mut listener = self.listener.take().unwrap();
        let registry = self.registry.clone();

        join_joinset_background(tasks.clone(), "standalone server tasks".to_string());

        listener
            .listen()
            .await
            .with_context(|| "failed to listen")?;

        let inflight_server = self.inflight_server.clone();

        self.tasks.lock().unwrap().spawn(async move {
            while let Ok(tunnel) = listener.accept().await {
                let server = StandAloneServerOneTunnel::new(tunnel, registry.clone());
                let inflight_server = inflight_server.clone();
                inflight_server.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tasks.lock().unwrap().spawn(async move {
                    server.run().await;
                    inflight_server.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
            panic!("standalone server listener exit");
        });

        Ok(())
    }

    pub fn inflight_server(&self) -> u32 {
        self.inflight_server
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

struct StandAloneClientOneTunnel {
    rpc_client: Client,
    tasks: Arc<Mutex<JoinSet<()>>>,
    error: Arc<Mutex<Option<Error>>>,
}

impl StandAloneClientOneTunnel {
    pub fn new(tunnel: Box<dyn Tunnel>) -> Self {
        let rpc_client = Client::new();
        let (mut rpc_rx, rpc_tx) = (
            rpc_client.get_transport_stream(),
            rpc_client.get_transport_sink(),
        );
        let tasks = Arc::new(Mutex::new(JoinSet::new()));

        let (mut tunnel_rx, mut tunnel_tx) = tunnel.split();

        let error_store = Arc::new(Mutex::new(None));

        let error = error_store.clone();
        tasks.lock().unwrap().spawn(async move {
            while let Some(p) = rpc_rx.next().await {
                match p {
                    Ok(p) => {
                        if let Err(e) = tunnel_tx
                            .send(p)
                            .await
                            .with_context(|| "failed to send packet")
                        {
                            *error.lock().unwrap() = Some(e.into());
                        }
                    }
                    Err(e) => {
                        *error.lock().unwrap() = Some(anyhow::Error::from(e).into());
                    }
                }
            }

            *error.lock().unwrap() = Some(anyhow::anyhow!("rpc_rx next exit").into());
        });

        let error = error_store.clone();
        tasks.lock().unwrap().spawn(async move {
            while let Some(p) = tunnel_rx.next().await {
                match p {
                    Ok(p) => {
                        if let Err(e) = rpc_tx
                            .send(p)
                            .await
                            .with_context(|| "failed to send packet")
                        {
                            *error.lock().unwrap() = Some(e.into());
                        }
                    }
                    Err(e) => {
                        *error.lock().unwrap() = Some(anyhow::Error::from(e).into());
                    }
                }
            }

            *error.lock().unwrap() = Some(anyhow::anyhow!("tunnel_rx next exit").into());
        });

        rpc_client.run();

        StandAloneClientOneTunnel {
            rpc_client,
            tasks,
            error: error_store,
        }
    }

    pub fn take_error(&self) -> Option<Error> {
        self.error.lock().unwrap().take()
    }
}

pub struct StandAloneClient<C: TunnelConnector> {
    connector: C,
    client: Option<StandAloneClientOneTunnel>,
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
            c = Some(StandAloneClientOneTunnel::new(tunnel));
        }

        self.client = c;

        Ok(self
            .client
            .as_ref()
            .unwrap()
            .rpc_client
            .scoped_client::<F>(1, 1, domain_name))
    }
}

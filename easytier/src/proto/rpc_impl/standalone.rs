use std::{
    sync::{Arc, Mutex, atomic::AtomicU32},
    time::Duration,
};

use anyhow::Context as _;
use easytier_core::{
    connectivity::protocol::raw::{
        TcpTunnelDialer, TcpTunnelListener, TunnelDialer, UdpTunnelDialer, UdpTunnelListener,
    },
    listener::SocketListener,
    socket::udp::{UdpBindOptions, UdpSessionListenRequest},
    tunnel::Tunnel,
};
use tokio::task::JoinSet;

use crate::{
    common::{dns::RuntimeDnsResolver, join_joinset_background, netns::NetNS},
    proto::{
        common::TunnelInfo,
        rpc_impl::bidirect::BidirectRpcManager,
        rpc_types::{__rt::RpcClientFactory, error::Error},
    },
    socket::{
        tcp::{RuntimeTcpListenerFactory, RuntimeTcpSocketFactory},
        udp::RuntimeUdpSocketFactory,
    },
    tunnel::TunnelUrl,
};

use super::service_registry::ServiceRegistry;

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

pub type RuntimeRpcDialer = TcpTunnelDialer<RuntimeTcpSocketFactory>;
pub type RuntimeRpcListener = TcpTunnelListener<RuntimeTcpListenerFactory>;
pub type RuntimeRpcClient = StandAloneClient<RuntimeRpcDialer>;

pub fn runtime_rpc_dialer(remote_url: url::Url) -> RuntimeRpcDialer {
    TcpTunnelDialer::new(
        remote_url,
        Arc::new(RuntimeTcpSocketFactory::new(NetNS::new(None))),
        Arc::new(RuntimeDnsResolver::new()),
    )
}

pub fn runtime_rpc_client(remote_url: url::Url) -> RuntimeRpcClient {
    StandAloneClient::new(runtime_rpc_dialer(remote_url))
}

pub fn runtime_rpc_listener(local_addr: std::net::SocketAddr) -> RuntimeRpcListener {
    TcpTunnelListener::new(
        local_addr,
        Arc::new(RuntimeTcpListenerFactory::new(NetNS::new(None))),
    )
}

pub fn runtime_udp_tunnel_dialer(remote_url: url::Url) -> impl TunnelDialer {
    UdpTunnelDialer::new(
        remote_url,
        Arc::new(RuntimeUdpSocketFactory::new(NetNS::new(None))),
        Arc::new(RuntimeDnsResolver::new()),
    )
}

pub fn runtime_udp_tunnel_listener(
    local_url: url::Url,
    local_addr: std::net::SocketAddr,
) -> impl SocketListener<Accepted = Box<dyn Tunnel>> {
    let bind = UdpBindOptions::port_bound_listener(local_addr)
        .with_bind_device(TunnelUrl::from(local_url.clone()).bind_dev())
        .with_only_v6(true);
    UdpTunnelListener::new_with_request(
        local_url,
        UdpSessionListenRequest::new(bind),
        Arc::new(RuntimeUdpSocketFactory::new(NetNS::new(None))),
    )
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
        StandAloneServer {
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
        let tasks = Arc::new(Mutex::new(JoinSet::new()));
        join_joinset_background(tasks.clone(), "standalone serve_loop".to_string());

        loop {
            let tunnel = listener.accept().await?;
            let tunnel_info = tunnel.info();
            let registry = registry.clone();
            let inflight_server = inflight.clone();
            let hook = hook.clone();

            let tunnel_info = match hook.on_new_client(tunnel_info).await {
                Ok(info) => info,
                Err(e) => {
                    tracing::warn!(?e, "standalone hook.on_new_client failed");
                    continue;
                }
            };

            inflight_server.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tasks.lock().unwrap().spawn(async move {
                let server = BidirectRpcManager::new().set_rx_timeout(rx_timeout);
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

pub struct StandAloneClient<C: TunnelDialer> {
    connector: C,
    client: Option<BidirectRpcManager>,
}

impl<C: TunnelDialer> StandAloneClient<C> {
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
    use easytier_core::{
        connectivity::protocol::raw::TunnelDialer as _, listener::SocketListener as _,
    };

    use crate::proto::rpc_impl::standalone::{
        StandAloneServer, runtime_rpc_dialer, runtime_rpc_listener, runtime_udp_tunnel_dialer,
        runtime_udp_tunnel_listener,
    };

    #[tokio::test]
    async fn standalone_exit_on_drop() {
        let addr = "0.0.0.0:53884".parse().unwrap();
        let tunnel = runtime_rpc_listener(addr);
        let mut server = StandAloneServer::new(tunnel);
        server.serve().await.unwrap();
        drop(server);

        // tcp should closed
        let connector = runtime_rpc_dialer("tcp://0.0.0.0:53884".parse().unwrap());
        connector.connect().await.unwrap_err();
    }

    #[tokio::test]
    async fn standalone_ipv4_and_ipv6_listeners_share_port() {
        let mut ipv6 = runtime_rpc_listener("[::]:0".parse().unwrap());
        ipv6.listen().await.unwrap();
        let port = ipv6.local_url().port().unwrap();

        let mut ipv4 = runtime_rpc_listener(format!("0.0.0.0:{port}").parse().unwrap());
        ipv4.listen().await.unwrap();
    }

    #[tokio::test]
    async fn runtime_udp_tunnel_endpoints_connect() {
        let local_url = "udp://127.0.0.1:0".parse().unwrap();
        let mut listener = runtime_udp_tunnel_listener(local_url, "127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_url = listener.local_url();
        let dialer = runtime_udp_tunnel_dialer(listener_url.clone());

        let (accepted, connected) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::try_join!(listener.accept(), dialer.connect())
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            accepted.info().unwrap().local_addr.unwrap().url,
            listener_url.as_str()
        );
        assert_eq!(
            connected.info().unwrap().remote_addr.unwrap().url,
            listener_url.as_str()
        );
    }
}

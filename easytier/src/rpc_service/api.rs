use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;
#[cfg(feature = "management")]
use easytier_core::management::ManagementServer;
use easytier_core::{management::ReadOnlyManagementServer, socket::SocketListener, tunnel::Tunnel};

#[cfg(feature = "management")]
use crate::{
    instance::config_storage::NativeConfigFileStorage, rpc_service::logger::NativeLoggerControl,
    web_client::DefaultHooks,
};
use crate::{
    instance::factory::NativeInstanceSet,
    proto::{
        rpc::standalone::{RuntimeRpcListener, runtime_rpc_listener},
        rpc_types::error::Error,
    },
};

#[cfg(feature = "management")]
pub struct ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    rpc_server: ManagementServer<T>,
}

#[cfg(feature = "management")]
impl ApiRpcServer<RuntimeRpcListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NativeInstanceSet>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(runtime_rpc_listener(rpc_addr), instance_manager);
        server.rpc_server.set_whitelist(rpc_portal_whitelist);

        Ok(server)
    }
}

#[cfg(feature = "management")]
impl<T> ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NativeInstanceSet>) -> Self {
        let rpc_server = ManagementServer::new(
            tunnel,
            instance_manager,
            Arc::new(DefaultHooks),
            Arc::new(NativeConfigFileStorage),
            Arc::new(NativeLoggerControl),
        );
        Self { rpc_server }
    }
}

#[cfg(feature = "management")]
impl<T> ApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

pub struct ReadOnlyApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    rpc_server: ReadOnlyManagementServer<T>,
}

impl ReadOnlyApiRpcServer<RuntimeRpcListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NativeInstanceSet>,
    ) -> anyhow::Result<Self> {
        let rpc_addr = parse_rpc_portal(rpc_portal)?;
        let mut server = Self::from_tunnel(runtime_rpc_listener(rpc_addr), instance_manager);
        server.rpc_server.set_whitelist(rpc_portal_whitelist);
        Ok(server)
    }
}

impl<T> ReadOnlyApiRpcServer<T>
where
    T: SocketListener<Accepted = Box<dyn Tunnel>> + 'static,
{
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NativeInstanceSet>) -> Self {
        Self {
            rpc_server: ReadOnlyManagementServer::new(tunnel, instance_manager),
        }
    }

    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    let mut rpc_addr = if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        Some(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?
    };
    select_proper_rpc_port(&mut rpc_addr)?;
    rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))
}

fn select_proper_rpc_port(addr: &mut Option<SocketAddr>) -> anyhow::Result<()> {
    match addr {
        None => {
            *addr = Some(SocketAddr::from(([0, 0, 0, 0], 0)));
            select_proper_rpc_port(addr)?;
            Ok(())
        }
        Some(addr) => {
            if addr.port() == 0 {
                let Some(port) = crate::utils::find_free_tcp_port(15888..15900) else {
                    tracing::warn!(
                        "No free port found for RPC portal, skipping setting RPC portal"
                    );
                    return Err(anyhow::anyhow!("No free port found for RPC portal"));
                };
                addr.set_port(port);
            }
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "management"))]
mod tests {
    use std::{fmt, sync::Arc, time::Duration};

    use easytier_core::{
        rpc::bidirect::BidirectRpcManager,
        socket::SocketListener,
        tunnel::{Tunnel, ring::create_ring_tunnel_pair},
    };
    use tokio::sync::mpsc;

    use crate::{
        instance::factory::native_instance_set,
        proto::{
            api::logger::{GetLoggerConfigRequest, LoggerRpc, LoggerRpcClientFactory},
            rpc_types::controller::BaseController,
        },
    };

    use super::{ApiRpcServer, parse_rpc_portal};

    #[test]
    fn zero_rpc_portal_is_resolved_before_listener_binding() {
        assert_ne!(parse_rpc_portal(Some("0".to_owned())).unwrap().port(), 0);
    }

    struct RingListener {
        accepted: mpsc::Receiver<Box<dyn Tunnel>>,
    }

    impl fmt::Debug for RingListener {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.debug_struct("RingListener").finish()
        }
    }

    #[async_trait::async_trait]
    impl SocketListener for RingListener {
        type Accepted = Box<dyn Tunnel>;

        async fn listen(&mut self) -> anyhow::Result<()> {
            Ok(())
        }

        async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
            self.accepted
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("ring test listener closed"))
        }

        fn local_url(&self) -> url::Url {
            "ring://management-test".parse().unwrap()
        }
    }

    #[tokio::test]
    async fn trusted_ring_management_transport_does_not_require_an_ip_host() {
        let (client_tunnel, server_tunnel) = create_ring_tunnel_pair();
        let (accepted, receiver) = mpsc::channel(1);
        accepted.send(server_tunnel).await.unwrap();
        let server = ApiRpcServer::from_tunnel(
            RingListener { accepted: receiver },
            Arc::new(native_instance_set()),
        )
        .with_rx_timeout(Some(Duration::from_secs(1)))
        .serve()
        .await
        .unwrap();
        let client = BidirectRpcManager::new().set_rx_timeout(Some(Duration::from_secs(1)));
        client.run_with_tunnel(client_tunnel);
        let logger = client
            .rpc_client()
            .scoped_client::<LoggerRpcClientFactory<BaseController>>(1, 1, String::new());

        tokio::time::timeout(
            Duration::from_secs(1),
            logger.get_logger_config(BaseController::default(), GetLoggerConfigRequest::default()),
        )
        .await
        .unwrap()
        .unwrap();

        drop(server);
    }
}

use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use cidr::IpCidr;

use crate::{
    instance::instance::InstanceRpcServerHook,
    instance_manager::NetworkInstanceManager,
    proto::{
        api::{
            config::ConfigRpcServer,
            instance::{
                AclManageRpcServer, ConnectorManageRpcServer, MappedListenerManageRpcServer,
                PeerManageRpcServer, PortForwardManageRpcServer, StatsRpcServer, TcpProxyRpcServer,
                VpnPortalRpcServer,
            },
            logger::LoggerRpcServer,
            manage::WebClientServiceServer,
        },
        rpc_impl::{service_registry::ServiceRegistry, standalone::StandAloneServer},
        rpc_types::error::Error,
    },
    rpc_service::{
        acl_manage::AclManageRpcService, config::ConfigRpcService,
        connector_manage::ConnectorManageRpcService, instance_manage::InstanceManageRpcService,
        logger::LoggerRpcService, mapped_listener_manage::MappedListenerManageRpcService,
        peer_manage::PeerManageRpcService, port_forward_manage::PortForwardManageRpcService,
        proxy::TcpProxyRpcService, stats::StatsRpcService, vpn_portal::VpnPortalRpcService,
    },
    tunnel::{tcp::TcpTunnelListener, TunnelListener},
    web_client::DefaultHooks,
};

pub struct ApiRpcServer<T: TunnelListener + 'static> {
    rpc_server: StandAloneServer<T>,
}

impl ApiRpcServer<TcpTunnelListener> {
    pub fn new(
        rpc_portal: Option<String>,
        rpc_portal_whitelist: Option<Vec<IpCidr>>,
        instance_manager: Arc<NetworkInstanceManager>,
    ) -> anyhow::Result<Self> {
        let mut server = Self::from_tunnel(
            TcpTunnelListener::new(
                format!("tcp://{}", parse_rpc_portal(rpc_portal)?)
                    .parse()
                    .context("failed to parse rpc portal address")?,
            ),
            instance_manager,
        );

        server
            .rpc_server
            .set_hook(Arc::new(InstanceRpcServerHook::new(rpc_portal_whitelist)));

        Ok(server)
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub fn from_tunnel(tunnel: T, instance_manager: Arc<NetworkInstanceManager>) -> Self {
        let rpc_server = StandAloneServer::new(tunnel);
        register_api_rpc_service(&instance_manager, rpc_server.registry());
        Self { rpc_server }
    }
}

impl<T: TunnelListener + 'static> ApiRpcServer<T> {
    pub async fn serve(mut self) -> Result<Self, Error> {
        self.rpc_server.serve().await?;
        Ok(self)
    }

    pub fn with_rx_timeout(mut self, timeout: Option<std::time::Duration>) -> Self {
        self.rpc_server.set_rx_timeout(timeout);
        self
    }
}

impl<T: TunnelListener + 'static> Drop for ApiRpcServer<T> {
    fn drop(&mut self) {
        self.rpc_server.registry().unregister_all();
    }
}

fn register_api_rpc_service(
    instance_manager: &Arc<NetworkInstanceManager>,
    registry: &ServiceRegistry,
) {
    registry.register(
        PeerManageRpcServer::new(PeerManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        ConnectorManageRpcServer::new(ConnectorManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        MappedListenerManageRpcServer::new(MappedListenerManageRpcService::new(
            instance_manager.clone(),
        )),
        "",
    );

    registry.register(
        VpnPortalRpcServer::new(VpnPortalRpcService::new(instance_manager.clone())),
        "",
    );

    for client_type in ["tcp", "kcp_src", "kcp_dst", "quic_src", "quic_dst"] {
        registry.register(
            TcpProxyRpcServer::new(TcpProxyRpcService::new(
                instance_manager.clone(),
                client_type,
            )),
            client_type,
        );
    }

    registry.register(
        AclManageRpcServer::new(AclManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        PortForwardManageRpcServer::new(PortForwardManageRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        StatsRpcServer::new(StatsRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(LoggerRpcServer::new(LoggerRpcService), "");

    registry.register(
        ConfigRpcServer::new(ConfigRpcService::new(instance_manager.clone())),
        "",
    );

    registry.register(
        WebClientServiceServer::new(InstanceManageRpcService::new(
            instance_manager.clone(),
            Arc::new(DefaultHooks),
        )),
        "",
    );
}

fn parse_rpc_portal(rpc_portal: Option<String>) -> anyhow::Result<SocketAddr> {
    if let Some(Ok(port)) = rpc_portal.as_ref().map(|s| s.parse::<u16>()) {
        Ok(SocketAddr::from(([0, 0, 0, 0], port)))
    } else {
        let mut rpc_addr = rpc_portal
            .map(|addr| {
                addr.parse::<SocketAddr>()
                    .context("failed to parse rpc portal address")
            })
            .transpose()?;
        select_proper_rpc_port(&mut rpc_addr)?;
        rpc_addr.ok_or_else(|| anyhow::anyhow!("failed to parse rpc portal address"))
    }
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

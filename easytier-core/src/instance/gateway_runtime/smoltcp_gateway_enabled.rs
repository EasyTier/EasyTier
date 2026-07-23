use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::{
    config::{gateway::PortForwardConfig, runtime::CoreRuntimeConfigStore},
    gateway::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket, GatewayModule},
    instance::CoreInstanceHost,
};

use super::SmoltcpGatewayRuntimeInputs;

pub(in crate::instance) struct SmoltcpGatewayRuntime<H>
where
    H: CoreInstanceHost,
{
    gateway: Arc<GatewayModule<H>>,
}

impl<H> SmoltcpGatewayRuntime<H>
where
    H: CoreInstanceHost,
{
    pub(in crate::instance) fn new(inputs: SmoltcpGatewayRuntimeInputs<H>) -> Self {
        let SmoltcpGatewayRuntimeInputs {
            runtime_config,
            peer_manager,
            wrapped_transport,
            host,
            dns,
            socket_context,
            events,
        } = inputs;
        Self {
            gateway: GatewayModule::new(
                runtime_config,
                peer_manager,
                wrapped_transport.as_ref(),
                host,
                dns,
                socket_context,
                events,
            ),
        }
    }

    pub(in crate::instance) async fn start(
        &self,
        _runtime_config: &CoreRuntimeConfigStore,
    ) -> anyhow::Result<()> {
        self.gateway.start().await
    }

    pub(in crate::instance) async fn stop(&self) {
        self.gateway.stop().await;
    }

    pub(in crate::instance) async fn reload_port_forwards(
        &self,
        port_forwards: &[PortForwardConfig],
    ) -> anyhow::Result<()> {
        self.gateway.reload_port_forwards(port_forwards).await
    }

    pub(in crate::instance) async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpStream> {
        self.gateway.data_plane_tcp_connect(dst_addr, timeout).await
    }

    pub(in crate::instance) async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpListener> {
        self.gateway.data_plane_tcp_bind(local_port, timeout).await
    }

    pub(in crate::instance) async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneUdpSocket> {
        self.gateway.data_plane_udp_bind(local_port, timeout).await
    }
}

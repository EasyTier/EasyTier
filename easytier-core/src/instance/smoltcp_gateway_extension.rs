use std::{net::SocketAddr, time::Duration};

use crate::gateway::{DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket};

use super::{CoreInstance, CoreInstanceHost};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpStream> {
        self.smoltcp_gateway
            .data_plane_tcp_connect(dst_addr, timeout)
            .await
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneTcpListener> {
        self.smoltcp_gateway
            .data_plane_tcp_bind(local_port, timeout)
            .await
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> anyhow::Result<DataPlaneUdpSocket> {
        self.smoltcp_gateway
            .data_plane_udp_bind(local_port, timeout)
            .await
    }
}

use std::{net::SocketAddr, sync::Arc, time::Duration};

use crate::gateway::{
    DataPlaneError, DataPlaneSession, DataPlaneTcpListener, DataPlaneTcpStream, DataPlaneUdpSocket,
};

use super::{CoreInstance, CoreInstanceHost};

impl<H> CoreInstance<H>
where
    H: CoreInstanceHost,
{
    pub fn data_plane_session(&self) -> Arc<DataPlaneSession<H>> {
        self.data_plane_session.clone()
    }

    pub async fn data_plane_tcp_connect(
        &self,
        dst_addr: SocketAddr,
        timeout: Duration,
    ) -> Result<DataPlaneTcpStream, DataPlaneError> {
        self.data_plane_runtime
            .data_plane_tcp_connect(dst_addr, timeout)
            .await
    }

    pub async fn data_plane_tcp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> Result<DataPlaneTcpListener, DataPlaneError> {
        self.data_plane_runtime
            .data_plane_tcp_bind(local_port, timeout)
            .await
    }

    pub async fn data_plane_udp_bind(
        &self,
        local_port: u16,
        timeout: Duration,
    ) -> Result<DataPlaneUdpSocket, DataPlaneError> {
        self.data_plane_runtime
            .data_plane_udp_bind(local_port, timeout)
            .await
    }
}

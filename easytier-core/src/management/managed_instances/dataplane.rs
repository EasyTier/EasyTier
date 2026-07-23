use super::ManagedInstanceSet;
use crate::instance::{CoreInstance, CoreInstanceHost, manager::InstanceFactory};

impl<F, H> ManagedInstanceSet<F>
where
    F: InstanceFactory<Instance = CoreInstance<H>, CreateContext = ()>,
    F::Error: std::fmt::Debug + std::fmt::Display + Send + Sync + 'static,
    H: CoreInstanceHost,
{
    pub async fn data_plane_tcp_connect(
        &self,
        instance_id: &uuid::Uuid,
        dst_addr: std::net::SocketAddr,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpStream> {
        self.instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_tcp_connect(dst_addr, timeout)
            .await
    }

    pub async fn data_plane_tcp_bind(
        &self,
        instance_id: &uuid::Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneTcpListener> {
        self.instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_tcp_bind(local_port, timeout)
            .await
    }

    pub async fn data_plane_udp_bind(
        &self,
        instance_id: &uuid::Uuid,
        local_port: u16,
        timeout: std::time::Duration,
    ) -> anyhow::Result<crate::gateway::DataPlaneUdpSocket> {
        self.instance(*instance_id)
            .ok_or_else(|| anyhow::anyhow!("instance {instance_id} not found"))?
            .data_plane_udp_bind(local_port, timeout)
            .await
    }
}

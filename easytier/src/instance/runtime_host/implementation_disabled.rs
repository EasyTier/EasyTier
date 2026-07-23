use std::sync::Arc;

use easytier_core::{
    gateway::dhcp::DhcpIpv4Host,
    instance::{CorePacketPlane, InstanceRuntimeHost},
};

use super::super::NativeInstanceRuntimeHost;

#[async_trait::async_trait]
impl InstanceRuntimeHost for NativeInstanceRuntimeHost {
    async fn prepare(
        &self,
        packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
        self.prepare_runtime(packet_plane).await
    }

    async fn shutdown(&self) {
        self.shutdown_runtime().await;
    }

    fn request_shutdown(&self) {
        self.request_runtime_shutdown();
    }

    fn management_events(&self) -> Vec<String> {
        self.management_events_snapshot()
    }

    fn attach_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.attach_runtime_tun_fd(fd)
    }
}

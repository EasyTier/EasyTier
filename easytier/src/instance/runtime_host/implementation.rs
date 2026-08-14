use std::sync::Arc;

use easytier_core::{
    gateway::dhcp::DhcpIpv4Host,
    host::packet::HostPacketReceiver,
    instance::{CorePacketPlane, InstanceRuntimeHost, PacketEgressHost},
};

use super::NativeInstanceRuntimeHost;

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

    #[cfg(feature = "web-client")]
    fn synchronize_config(
        &self,
        patch: &crate::proto::api::config::InstanceConfigPatch,
        config: &easytier_core::config::runtime::CoreInstanceRuntimeConfig,
    ) {
        self.synchronize_global_ctx_config(patch, config);
    }

    #[cfg(feature = "web-client")]
    fn publish_config_patch(&self, patch: crate::proto::api::config::InstanceConfigPatch) {
        #[cfg(feature = "management")]
        self.event_journal.publish_config_patch(patch);
        #[cfg(not(feature = "management"))]
        let _ = patch;
    }

    fn attach_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.attach_runtime_tun_fd(fd)
    }
}

#[async_trait::async_trait]
impl PacketEgressHost for NativeInstanceRuntimeHost {
    async fn start(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.install_packet_receiver(receiver)
    }

    async fn stop(&self) {}

    fn request_stop(&self) {
        self.request_runtime_shutdown();
    }
}

use std::sync::Arc;

use easytier_core::{
    gateway::dhcp::{DhcpAddresses, DhcpHost},
    host::packet::HostPacketReceiver,
    instance::CorePacketPlane,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
}

impl NativeTunRuntime {
    pub(super) fn new(global_ctx: ArcGlobalCtx, cancel: CancellationToken) -> Self {
        Self { global_ctx, cancel }
    }

    pub(super) fn install_packet_receiver(
        &self,
        receiver: HostPacketReceiver,
    ) -> anyhow::Result<()> {
        drop(receiver);
        Ok(())
    }

    pub(super) async fn prepare(&self, _packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        Ok(())
    }

    pub(super) async fn shutdown(&self) {}

    pub(super) fn attach_fd(&self, _fd: i32) -> anyhow::Result<()> {
        anyhow::bail!("external TUN attachment is only supported on mobile Hosts")
    }

    pub(super) fn dhcp_host(
        &self,
        operation: Arc<Mutex<()>>,
        _packet_plane: Arc<CorePacketPlane>,
    ) -> Arc<dyn DhcpHost> {
        Arc::new(NativeDhcpHost {
            global_ctx: self.global_ctx.clone(),
            operation,
            cancel: self.cancel.clone(),
        })
    }
}

pub(super) struct NativeDhcpHost {
    pub(super) global_ctx: ArcGlobalCtx,
    pub(super) operation: Arc<Mutex<()>>,
    pub(super) cancel: CancellationToken,
}

impl NativeDhcpHost {
    pub(super) fn take_closed(&self) -> bool {
        false
    }

    pub(super) async fn apply(&self, next: DhcpAddresses) -> anyhow::Result<()> {
        self.ensure_open()?;
        self.set_addresses(next);
        Ok(())
    }
}

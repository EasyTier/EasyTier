use std::sync::Arc;

use cidr::Ipv4Inet;
use easytier_core::{
    gateway::dhcp::{DhcpIpv4ApplyOutcome, DhcpIpv4ApplyPermit, DhcpIpv4Host},
    instance::CorePacketPlane,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use super::HostPacketReceiver;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
}

impl NativeTunRuntime {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        cancel: CancellationToken,
        peer_packet_receiver: HostPacketReceiver,
    ) -> Self {
        drop(peer_packet_receiver);
        Self { global_ctx, cancel }
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
    ) -> Arc<dyn DhcpIpv4Host> {
        Arc::new(NativeDhcpIpv4Host {
            global_ctx: self.global_ctx.clone(),
            operation,
            cancel: self.cancel.clone(),
        })
    }
}

struct NativeDhcpIpv4Host {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
}

impl NativeDhcpIpv4Host {
    fn ensure_open(&self) -> anyhow::Result<()> {
        if self.cancel.is_cancelled() {
            anyhow::bail!("instance is closing; DHCP update cancelled");
        }
        Ok(())
    }

    async fn apply(&self, next: Option<Ipv4Inet>) -> anyhow::Result<Option<Ipv4Inet>> {
        self.ensure_open()?;
        let Some(ip) = next else {
            self.global_ctx.set_ipv4(None);
            return Ok(None);
        };
        self.global_ctx.set_ipv4(Some(ip));
        Ok(Some(ip))
    }
}

#[async_trait::async_trait]
impl DhcpIpv4Host for NativeDhcpIpv4Host {
    fn take_interface_closed(&self) -> bool {
        false
    }

    async fn apply_dhcp_ipv4(
        &self,
        _previous: Option<Ipv4Inet>,
        next: Option<Ipv4Inet>,
    ) -> DhcpIpv4ApplyOutcome {
        let permit = self.operation.clone().lock_owned().await;
        let outcome = match self.apply(next).await {
            Ok(actual) => DhcpIpv4ApplyOutcome::applied(actual),
            Err(error) => DhcpIpv4ApplyOutcome::failed(self.global_ctx.get_ipv4(), error),
        };
        outcome.with_permit(DhcpIpv4ApplyPermit::new(permit))
    }

    fn publish_dhcp_ipv4(
        &self,
        previous: Option<Ipv4Inet>,
        requested: Option<Ipv4Inet>,
        actual: Option<Ipv4Inet>,
    ) {
        let event = if requested.is_none() {
            GlobalCtxEvent::DhcpIpv4Conflicted(previous)
        } else {
            GlobalCtxEvent::DhcpIpv4Changed(previous, actual)
        };
        self.global_ctx.issue_event(event);
    }
}

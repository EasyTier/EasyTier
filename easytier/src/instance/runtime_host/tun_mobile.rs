use std::sync::Arc;

use anyhow::Context as _;
use cidr::Ipv4Inet;
use easytier_core::{
    gateway::dhcp::{DhcpIpv4ApplyOutcome, DhcpIpv4ApplyPermit, DhcpIpv4Host},
    instance::CorePacketPlane,
};
use futures::FutureExt as _;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio_util::sync::CancellationToken;

use super::{HostPacketReceiver, MagicDnsRuntime, tun_common::TunNicState};
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    instance::virtual_nic::NicCtx,
};

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
    nic: TunNicState,
    tun_fd: mpsc::Sender<i32>,
    tun_fd_receiver: Mutex<Option<mpsc::Receiver<i32>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl NativeTunRuntime {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        cancel: CancellationToken,
        peer_packet_receiver: HostPacketReceiver,
    ) -> Self {
        let (tun_fd, tun_fd_receiver) = mpsc::channel(16);
        Self {
            global_ctx,
            cancel,
            nic: TunNicState::new(peer_packet_receiver),
            tun_fd,
            tun_fd_receiver: Mutex::new(Some(tun_fd_receiver)),
            task: Mutex::new(None),
        }
    }

    async fn install_mobile_tun(
        nic_state: TunNicState,
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        fd: i32,
    ) -> anyhow::Result<()> {
        nic_state.drain().await;
        if fd <= 0 {
            return Ok(());
        }
        let closed = Arc::new(Notify::new());
        let mut nic = NicCtx::new(
            global_ctx.clone(),
            packet_plane.clone(),
            nic_state.receiver(),
            closed,
        );
        nic.run_for_mobile(fd).await.context("add ip failed")?;
        let magic_dns = global_ctx
            .get_ipv4()
            .map(|ip| MagicDnsRuntime::start(global_ctx, packet_plane, None, ip))
            .unwrap_or_default();
        nic_state.install(nic, magic_dns).await;
        Ok(())
    }

    pub(super) async fn prepare(&self, packet_plane: Arc<CorePacketPlane>) -> anyhow::Result<()> {
        self.nic.drain().await;
        let Some(mut tun_fds) = self.tun_fd_receiver.lock().await.take() else {
            return Ok(());
        };
        let nic_state = self.nic.clone();
        let global_ctx = self.global_ctx.clone();
        let cancel = self.cancel.clone();
        self.task.lock().await.replace(tokio::spawn(async move {
            loop {
                let fd = tokio::select! {
                    _ = cancel.cancelled() => return,
                    fd = tun_fds.recv() => match fd { Some(fd) => fd, None => return },
                };
                if let Err(error) = Self::install_mobile_tun(
                    nic_state.clone(),
                    global_ctx.clone(),
                    packet_plane.clone(),
                    fd,
                )
                .await
                {
                    tracing::error!(?error, "failed to attach mobile TUN fd");
                }
            }
        }));
        Ok(())
    }

    pub(super) async fn shutdown(&self) {
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
        self.nic.stop().await;
    }

    pub(super) fn attach_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.tun_fd
            .try_send(fd)
            .map_err(|error| anyhow::anyhow!("failed to send TUN fd: {error}"))
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
            nic: self.nic.clone(),
            closed: Arc::new(Notify::new()),
        })
    }
}

struct NativeDhcpIpv4Host {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    nic: TunNicState,
    closed: Arc<Notify>,
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
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; DHCP update cancelled"),
            _ = self.nic.drain() => {}
        }
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
        self.closed.notified().now_or_never().is_some()
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

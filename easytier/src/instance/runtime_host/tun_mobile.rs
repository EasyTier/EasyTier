use std::sync::Arc;

use anyhow::Context as _;
use cidr::Ipv4Inet;
use easytier_core::{
    gateway::dhcp::{DhcpIpv4ApplyOutcome, DhcpIpv4ApplyPermit, DhcpIpv4Host},
    host::packet::HostPacketReceiver,
    instance::CorePacketPlane,
};
use futures::FutureExt as _;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::{
    MagicDnsRuntime,
    tun_common::{TunNicState, create_nic_ctx},
};
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    instance::{shared_virtual_nic::ArcSharedVirtualNicRegistry, virtual_nic::MobileTunSources},
};

struct MobileTunAttachment {
    fd: i32,
    sources: MobileTunSources,
    completion: Option<oneshot::Sender<anyhow::Result<()>>>,
}

pub(super) struct NativeTunRuntime {
    global_ctx: ArcGlobalCtx,
    cancel: CancellationToken,
    nic: TunNicState,
    tun_fd: mpsc::Sender<MobileTunAttachment>,
    tun_fd_receiver: Mutex<Option<mpsc::Receiver<MobileTunAttachment>>>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
}

impl NativeTunRuntime {
    pub(super) fn new(
        global_ctx: ArcGlobalCtx,
        cancel: CancellationToken,
        shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
    ) -> Self {
        let (tun_fd, tun_fd_receiver) = mpsc::channel(16);
        Self {
            global_ctx,
            cancel,
            nic: TunNicState::empty(),
            tun_fd,
            tun_fd_receiver: Mutex::new(Some(tun_fd_receiver)),
            task: Mutex::new(None),
            shared_virtual_nic_registry,
        }
    }

    pub(super) fn install_packet_receiver(
        &self,
        receiver: HostPacketReceiver,
    ) -> anyhow::Result<()> {
        self.nic.install_receiver(receiver)
    }

    async fn install_mobile_tun(
        nic_state: TunNicState,
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        fd: i32,
        sources: MobileTunSources,
        shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
    ) -> anyhow::Result<()> {
        nic_state.drain().await;
        if fd <= 0 {
            return Ok(());
        }
        let closed = Arc::new(Notify::new());
        let mut nic = create_nic_ctx(
            global_ctx.clone(),
            packet_plane.clone(),
            nic_state.receiver(),
            closed,
            shared_virtual_nic_registry,
        )
        .await?;
        nic.run_for_mobile(fd, sources)
            .await
            .context("add ip failed")?;
        let magic_dns = if let Some(ip) = global_ctx.get_ipv4() {
            let shared_route_backend = nic.shared_route_backend_for_dns();
            MagicDnsRuntime::start(global_ctx, packet_plane, None, ip, shared_route_backend)
        } else {
            MagicDnsRuntime::default()
        };
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
        let shared_virtual_nic_registry = self.shared_virtual_nic_registry.clone();
        self.task.lock().await.replace(tokio::spawn(async move {
            loop {
                let attachment = tokio::select! {
                    _ = cancel.cancelled() => return,
                    attachment = tun_fds.recv() => match attachment {
                        Some(attachment) => attachment,
                        None => return,
                    },
                };
                let result = if attachment.fd <= 0 {
                    nic_state.drain().await;
                    Ok(())
                } else {
                    Self::install_mobile_tun(
                        nic_state.clone(),
                        global_ctx.clone(),
                        packet_plane.clone(),
                        attachment.fd,
                        attachment.sources,
                        shared_virtual_nic_registry.clone(),
                    )
                    .await
                };
                if let Err(error) = &result {
                    tracing::error!(?error, "failed to attach mobile TUN fd");
                }
                if let Some(completion) = attachment.completion {
                    let _ = completion.send(result);
                }
            }
        }));
        Ok(())
    }

    pub(super) async fn shutdown(&self) {
        self.cancel.cancel();
        if let Some(task) = self.task.lock().await.take() {
            let _ = task.await;
        }
        self.nic.stop().await;
    }

    pub(super) fn attach_fd(&self, fd: i32) -> anyhow::Result<()> {
        if !self.global_ctx.get_flags().dev_name.is_empty() {
            anyhow::bail!(
                "shared mobile TUN attachment requires per-instance address and route sources"
            );
        }
        self.tun_fd
            .try_send(MobileTunAttachment {
                fd,
                sources: MobileTunSources::default(),
                completion: None,
            })
            .map_err(|error| anyhow::anyhow!("failed to send TUN fd: {error}"))
    }

    pub(super) async fn attach_mobile_fd(
        &self,
        fd: i32,
        sources: MobileTunSources,
    ) -> anyhow::Result<()> {
        if self.task.lock().await.is_none() {
            anyhow::bail!("mobile TUN runtime is not running");
        }

        let (completion, result) = oneshot::channel();
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; TUN attachment cancelled"),
            send_result = self.tun_fd.send(MobileTunAttachment {
                fd,
                sources,
                completion: Some(completion),
            }) => send_result.map_err(|error| anyhow::anyhow!("failed to send TUN fd: {error}"))?,
        }

        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; TUN attachment cancelled"),
            result = result => result
                .map_err(|_| anyhow::anyhow!("mobile TUN runtime stopped before attachment completed"))?,
        }
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

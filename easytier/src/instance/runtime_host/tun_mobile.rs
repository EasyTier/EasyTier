use std::sync::Arc;

use anyhow::Context as _;
use easytier_core::{
    gateway::dhcp::DhcpHost, host::packet::HostPacketReceiver, instance::CorePacketPlane,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use super::tun_common::{NativeDhcpHost, TunNicState};
use crate::{
    common::global_ctx::ArcGlobalCtx,
    instance::{shared_virtual_nic::ArcSharedVirtualNicRegistry, virtual_nic::NicCtx},
};

struct MobileTunAttachment {
    fd: i32,
    replace_tun_fd: bool,
    completion: Option<oneshot::Sender<anyhow::Result<()>>>,
    claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
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
        replace_tun_fd: bool,
        shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
    ) -> anyhow::Result<()> {
        nic_state.drain().await;
        if fd <= 0 {
            return Ok(());
        }
        let closed = Arc::new(Notify::new());
        let nic = NicCtx::new(
            global_ctx.clone(),
            packet_plane.clone(),
            nic_state.receiver(),
            closed,
            shared_virtual_nic_registry,
        )
        .await?;
        let claims = match claims {
            Some(claims) => claims,
            None => NicCtx::mobile_tun_claims(&global_ctx, &packet_plane).await,
        };
        nic_state
            .configure_for_mobile(nic, global_ctx, packet_plane, fd, replace_tun_fd, claims)
            .await
            .context("attach mobile TUN failed")?;
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
                let result = Self::install_mobile_tun(
                    nic_state.clone(),
                    global_ctx.clone(),
                    packet_plane.clone(),
                    attachment.fd,
                    attachment.replace_tun_fd,
                    shared_virtual_nic_registry.clone(),
                    attachment.claims,
                )
                .await;
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
        self.tun_fd
            .try_send(MobileTunAttachment {
                fd,
                replace_tun_fd: true,
                completion: None,
                claims: None,
            })
            .map_err(|error| anyhow::anyhow!("failed to send TUN fd: {error}"))
    }

    pub(super) async fn attach_mobile_fd(
        &self,
        fd: i32,
        replace_tun_fd: bool,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
    ) -> anyhow::Result<()> {
        if self.task.lock().await.is_none() {
            anyhow::bail!("mobile TUN runtime is not running");
        }

        let (completion, result) = oneshot::channel();
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; TUN attachment cancelled"),
            send_result = self.tun_fd.send(MobileTunAttachment {
                fd,
                replace_tun_fd,
                completion: Some(completion),
                claims,
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
    ) -> Arc<dyn DhcpHost> {
        Arc::new(NativeDhcpHost {
            global_ctx: self.global_ctx.clone(),
            operation,
            cancel: self.cancel.clone(),
            nic: self.nic.clone(),
        })
    }

    pub(super) async fn current_mobile_tun_claims(
        &self,
    ) -> Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims> {
        self.nic.mobile_tun_claims().await
    }
}

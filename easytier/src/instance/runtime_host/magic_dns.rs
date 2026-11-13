use cidr::Ipv4Inet;
use easytier_core::instance::CorePacketPlane;
#[cfg(feature = "magic-dns")]
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

#[cfg(feature = "magic-dns")]
use crate::instance::dns_server::{MAGIC_DNS_FAKE_IP, runner::DnsRunner};
use crate::{common::global_ctx::ArcGlobalCtx, instance::virtual_nic::NicBackend};

#[derive(Default)]
pub(super) struct MagicDnsRuntime {
    #[cfg(feature = "magic-dns")]
    active: Option<MagicDnsTask>,
}

#[cfg(feature = "magic-dns")]
struct MagicDnsTask {
    task: AbortOnDropHandle<()>,
    cancel: CancellationToken,
}

impl MagicDnsRuntime {
    #[cfg(feature = "magic-dns")]
    pub(super) fn start(
        global_ctx: ArcGlobalCtx,
        packet_plane: std::sync::Arc<CorePacketPlane>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
        shared_route_backend: Option<NicBackend>,
    ) -> Self {
        let active = global_ctx.get_flags().accept_dns.then(|| {
            let mut runner = DnsRunner::new(
                packet_plane,
                global_ctx,
                tun_dev,
                tun_ip,
                MAGIC_DNS_FAKE_IP.parse().unwrap(),
            )
            .with_shared_route_backend(shared_route_backend);
            let cancel = CancellationToken::new();
            let task_cancel = cancel.clone();
            let task = tokio::spawn(async move {
                let _ = runner.run(task_cancel).await;
            });
            MagicDnsTask {
                task: AbortOnDropHandle::new(task),
                cancel,
            }
        });
        Self { active }
    }

    #[cfg(not(feature = "magic-dns"))]
    pub(super) fn start(
        _global_ctx: ArcGlobalCtx,
        _packet_plane: std::sync::Arc<CorePacketPlane>,
        _tun_dev: Option<String>,
        _tun_ip: Ipv4Inet,
        _shared_route_backend: Option<NicBackend>,
    ) -> Self {
        Self::default()
    }

    #[cfg(feature = "magic-dns")]
    pub(super) async fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            active.cancel.cancel();
            let _ = active.task.await;
        }
    }

    #[cfg(not(feature = "magic-dns"))]
    pub(super) async fn stop(&mut self) {}
}

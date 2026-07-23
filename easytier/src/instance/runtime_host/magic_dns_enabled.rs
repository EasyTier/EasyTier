use cidr::Ipv4Inet;
use easytier_core::instance::CorePacketPlane;
use tokio_util::{sync::CancellationToken, task::AbortOnDropHandle};

use crate::{
    common::{config::ConfigLoader as _, global_ctx::ArcGlobalCtx},
    instance::dns_server::{MAGIC_DNS_FAKE_IP, runner::DnsRunner},
};

#[derive(Default)]
pub(super) struct MagicDnsRuntime {
    active: Option<MagicDnsTask>,
}

struct MagicDnsTask {
    task: AbortOnDropHandle<()>,
    cancel: CancellationToken,
}

impl MagicDnsRuntime {
    pub(super) fn start(
        global_ctx: ArcGlobalCtx,
        packet_plane: std::sync::Arc<CorePacketPlane>,
        tun_dev: Option<String>,
        tun_ip: Ipv4Inet,
    ) -> Self {
        let active = global_ctx.config.get_flags().accept_dns.then(|| {
            let mut runner = DnsRunner::new(
                packet_plane,
                global_ctx,
                tun_dev,
                tun_ip,
                MAGIC_DNS_FAKE_IP.parse().unwrap(),
            );
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

    pub(super) async fn stop(&mut self) {
        if let Some(active) = self.active.take() {
            active.cancel.cancel();
            let _ = active.task.await;
        }
    }
}

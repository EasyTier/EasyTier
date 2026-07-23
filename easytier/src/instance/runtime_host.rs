use std::sync::Arc;

use easytier_core::{gateway::dhcp::DhcpIpv4Host, instance::CorePacketPlane};
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

#[cfg(feature = "management")]
#[path = "runtime_host/event_journal_enabled.rs"]
mod event_journal;
#[cfg(not(feature = "management"))]
#[path = "runtime_host/event_journal_disabled.rs"]
mod event_journal;
#[path = "runtime_host/implementation.rs"]
mod implementation;
#[cfg(all(feature = "tun", feature = "magic-dns"))]
#[path = "runtime_host/magic_dns_enabled.rs"]
mod magic_dns;
#[cfg(all(feature = "tun", not(feature = "magic-dns")))]
#[path = "runtime_host/magic_dns_disabled.rs"]
mod magic_dns;
#[cfg(feature = "tun")]
#[path = "runtime_host/tun_common.rs"]
mod tun_common;
#[cfg(not(feature = "tun"))]
#[path = "runtime_host/tun_disabled.rs"]
mod tun_runtime;
#[cfg(all(feature = "tun", not(mobile)))]
#[path = "runtime_host/tun_desktop.rs"]
mod tun_runtime;
#[cfg(all(feature = "tun", mobile))]
#[path = "runtime_host/tun_mobile.rs"]
mod tun_runtime;

use event_journal::EventJournal;
#[cfg(feature = "tun")]
use magic_dns::MagicDnsRuntime;
use tun_runtime::NativeTunRuntime;

pub(super) type HostPacketReceiver = mpsc::Receiver<Vec<u8>>;

pub(crate) struct NativeInstanceRuntimeHost {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    event_journal: EventJournal,
    tun: NativeTunRuntime,
}

impl NativeInstanceRuntimeHost {
    pub(crate) fn new(
        global_ctx: ArcGlobalCtx,
        peer_packet_receiver: HostPacketReceiver,
    ) -> Arc<Self> {
        let cancel = CancellationToken::new();
        let tun = NativeTunRuntime::new(global_ctx.clone(), cancel.clone(), peer_packet_receiver);
        let event_journal = EventJournal::new(&global_ctx);
        Arc::new(Self {
            global_ctx,
            event_journal,
            operation: Arc::new(Mutex::new(())),
            cancel,
            tun,
        })
    }

    async fn prepare_runtime(
        &self,
        packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
        self.event_journal.start(self.cancel.clone()).await;
        self.tun.prepare(packet_plane.clone()).await?;
        Ok(Some(
            self.tun.dhcp_host(self.operation.clone(), packet_plane),
        ))
    }

    async fn shutdown_runtime(&self) {
        self.cancel.cancel();
        let _operation = self.operation.lock().await;
        self.event_journal.stop().await;
        self.tun.shutdown().await;
    }

    fn request_runtime_shutdown(&self) {
        self.cancel.cancel();
    }

    fn management_events_snapshot(&self) -> Vec<String> {
        self.event_journal.events()
    }

    pub(crate) fn subscribe_event(&self) -> crate::common::global_ctx::EventBusSubscriber {
        self.global_ctx.subscribe()
    }

    fn attach_runtime_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.tun.attach_fd(fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::TomlConfig,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
    };

    #[test]
    fn runtime_host_owns_event_subscription_context() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let (_packet_sender, packet_receiver) = mpsc::channel(1);
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone(), packet_receiver);
        let mut events = runtime_host.subscribe_event();

        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);

        assert_eq!(
            events.try_recv().unwrap(),
            GlobalCtxEvent::CredentialChanged
        );
    }
}

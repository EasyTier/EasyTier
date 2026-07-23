use std::{any::Any, sync::Arc};

use tokio::{sync::Mutex, task::JoinSet};

use super::{HostPacketReceiver, MagicDnsRuntime};
use crate::instance::virtual_nic::NicCtx;

struct NicCtxContainer {
    _nic_ctx: Option<Box<dyn Any + Send>>,
    magic_dns: MagicDnsRuntime,
}

impl NicCtxContainer {
    fn new(nic_ctx: NicCtx, magic_dns: MagicDnsRuntime) -> Self {
        Self {
            _nic_ctx: Some(Box::new(nic_ctx)),
            magic_dns,
        }
    }

    fn packet_drain(tasks: JoinSet<()>) -> Self {
        Self {
            _nic_ctx: Some(Box::new(tasks)),
            magic_dns: MagicDnsRuntime::default(),
        }
    }
}

#[derive(Clone)]
pub(super) struct TunNicState {
    nic_ctx: Arc<Mutex<Option<NicCtxContainer>>>,
    receiver: Arc<Mutex<HostPacketReceiver>>,
}

impl TunNicState {
    pub(super) fn new(receiver: HostPacketReceiver) -> Self {
        Self {
            nic_ctx: Arc::new(Mutex::new(None)),
            receiver: Arc::new(Mutex::new(receiver)),
        }
    }

    pub(super) fn receiver(&self) -> Arc<Mutex<HostPacketReceiver>> {
        self.receiver.clone()
    }

    pub(super) async fn stop(&self) {
        let mut old = self.nic_ctx.lock().await.take();
        if let Some(nic) = old.as_mut() {
            nic.magic_dns.stop().await;
        }
        drop(old);
    }

    pub(super) async fn drain(&self) {
        self.stop().await;
        let receiver = self.receiver.clone();
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            let mut receiver = receiver.lock().await;
            while let Some(packet) = receiver.recv().await {
                tracing::trace!(?packet, "discarded packet without a native interface");
            }
        });
        self.nic_ctx
            .lock()
            .await
            .replace(NicCtxContainer::packet_drain(tasks));
    }

    pub(super) async fn install(&self, nic: NicCtx, magic_dns: MagicDnsRuntime) {
        self.stop().await;
        self.nic_ctx
            .lock()
            .await
            .replace(NicCtxContainer::new(nic, magic_dns));
    }
}

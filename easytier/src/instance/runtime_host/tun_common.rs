use std::{
    any::Any,
    sync::{Arc, OnceLock},
};

use cidr::Ipv4Inet;
#[cfg(not(mobile))]
use easytier_core::instance::CorePacketPlane;
use easytier_core::{
    gateway::dhcp::{DhcpIpv4ApplyOutcome, DhcpIpv4ApplyPermit, DhcpIpv4Host},
    host::packet::HostPacketReceiver,
};
use futures::FutureExt as _;
use tokio::{
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::sync::CancellationToken;

use super::MagicDnsRuntime;
#[cfg(not(mobile))]
use crate::instance::shared_virtual_nic::ArcSharedVirtualNicRegistry;
use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    instance::virtual_nic::NicCtx,
};

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
    receiver: Arc<OnceLock<Arc<Mutex<HostPacketReceiver>>>>,
}

impl TunNicState {
    pub(super) fn empty() -> Self {
        Self {
            nic_ctx: Arc::new(Mutex::new(None)),
            receiver: Arc::new(OnceLock::new()),
        }
    }

    pub(super) fn install_receiver(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.receiver
            .set(Arc::new(Mutex::new(receiver)))
            .map_err(|_| anyhow::anyhow!("native packet receiver is already installed"))
    }

    pub(super) fn receiver(&self) -> Arc<Mutex<HostPacketReceiver>> {
        self.receiver
            .get()
            .expect("packet receiver must be installed before preparing TUN")
            .clone()
    }

    pub(super) async fn stop(&self) {
        let mut old = self.nic_ctx.lock().await.take();
        if let Some(nic) = old.as_mut() {
            nic.magic_dns.stop().await;
        }
        drop(old);
    }

    #[cfg(mobile)]
    pub(super) async fn mobile_tun_claims(
        &self,
    ) -> Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims> {
        let nic = self.nic_ctx.lock().await;
        let nic = nic.as_ref()?._nic_ctx.as_ref()?.downcast_ref::<NicCtx>()?;
        nic.current_mobile_tun_claims().await
    }

    pub(super) async fn drain(&self) {
        self.stop().await;
        let receiver = self.receiver();
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

pub(super) struct NativeDhcpIpv4Host {
    pub(super) global_ctx: ArcGlobalCtx,
    pub(super) operation: Arc<Mutex<()>>,
    pub(super) cancel: CancellationToken,
    pub(super) nic: TunNicState,
    pub(super) closed: Arc<Notify>,
    #[cfg(not(mobile))]
    pub(super) packet_plane: Arc<CorePacketPlane>,
    #[cfg(not(mobile))]
    pub(super) shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
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

        #[cfg(not(mobile))]
        if let Some(ip) = next
            && !self.global_ctx.no_tun()
        {
            let mut nic = NicCtx::new(
                self.global_ctx.clone(),
                self.packet_plane.clone(),
                self.nic.receiver(),
                self.closed.clone(),
                self.shared_virtual_nic_registry.clone(),
            )
            .await;
            tokio::select! {
                _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; DHCP update cancelled"),
                result = nic.run(Some(ip), self.global_ctx.get_ipv6()) => result?,
            }
            let shared_route_backend = nic.shared_route_backend_for_dns();
            let magic_dns = MagicDnsRuntime::start(
                self.global_ctx.clone(),
                self.packet_plane.clone(),
                nic.ifname().await,
                ip,
                shared_route_backend,
            );
            self.nic.install(nic, magic_dns).await;
        }
        self.global_ctx.set_ipv4(next);
        Ok(next)
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

#[cfg(test)]
mod tests {
    use easytier_core::{config::toml::TomlConfig, process_runtime::CoreProcessRuntime};

    use super::*;
    use crate::instance::test_instance::TestInstance;

    #[tokio::test]
    async fn dhcp_preserves_publication_permit_and_cancelled_address() {
        let instance = TestInstance::new_with_process_runtime(
            TomlConfig::default(),
            CoreProcessRuntime::new(),
        );
        let global_ctx = instance.get_global_ctx();
        let mut flags = global_ctx.get_flags();
        flags.no_tun = true;
        global_ctx.set_flags(flags);
        let operation = Arc::new(Mutex::new(()));
        let cancel = CancellationToken::new();
        let runtime = super::super::NativeTunRuntime::new(
            global_ctx.clone(),
            cancel.clone(),
            TestInstance::new_shared_virtual_nic_registry(),
        );
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        runtime
            .install_packet_receiver(HostPacketReceiver::new(receiver))
            .unwrap();
        let host = runtime.dhcp_host(
            operation.clone(),
            instance.get_core_instance().packet_plane(),
        );
        let mut events = global_ctx.subscribe();
        let address = "10.20.0.7/24".parse().unwrap();
        let mut previous = None;
        for next in [Some(address), None] {
            let outcome = host.apply_dhcp_ipv4(previous, next).await;
            assert!(outcome.result.is_ok());
            assert_eq!(outcome.actual, next);
            assert_eq!(global_ctx.get_ipv4(), next);
            assert!(operation.try_lock().is_err());
            host.publish_dhcp_ipv4(previous, next, outcome.actual);
            assert_eq!(
                events.try_recv().unwrap(),
                if next.is_none() {
                    GlobalCtxEvent::DhcpIpv4Conflicted(previous)
                } else {
                    GlobalCtxEvent::DhcpIpv4Changed(previous, next)
                }
            );
            drop(outcome);
            assert!(operation.try_lock().is_ok());
            previous = next;
        }

        global_ctx.set_ipv4(Some(address));
        cancel.cancel();
        let outcome = host.apply_dhcp_ipv4(Some(address), None).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.actual, Some(address));
        assert_eq!(global_ctx.get_ipv4(), Some(address));
        runtime.shutdown().await;
    }
}

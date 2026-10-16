use std::sync::{Arc, OnceLock};

#[cfg(not(mobile))]
use easytier_core::instance::CorePacketPlane;
use easytier_core::{gateway::dhcp::DhcpAddresses, host::packet::HostPacketReceiver};
#[cfg(not(mobile))]
use futures::FutureExt as _;
#[cfg(not(mobile))]
use tokio::sync::Notify;
use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::sync::CancellationToken;

use super::MagicDnsRuntime;
#[cfg(not(mobile))]
use crate::instance::shared_virtual_nic::ArcSharedVirtualNicRegistry;
use crate::{common::global_ctx::ArcGlobalCtx, instance::virtual_nic::NicCtx};

enum NicCtxContainer {
    Active {
        nic_ctx: Box<NicCtx>,
        magic_dns: MagicDnsRuntime,
    },
    PacketDrain(JoinSet<()>),
}

impl NicCtxContainer {
    fn new(nic_ctx: NicCtx, magic_dns: MagicDnsRuntime) -> Self {
        Self::Active {
            nic_ctx: Box::new(nic_ctx),
            magic_dns,
        }
    }

    fn packet_drain(tasks: JoinSet<()>) -> Self {
        Self::PacketDrain(tasks)
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
        let old = self.nic_ctx.lock().await.take();
        match old {
            Some(NicCtxContainer::Active {
                mut nic_ctx,
                mut magic_dns,
            }) => {
                magic_dns.stop().await;
                nic_ctx.shutdown().await;
            }
            Some(NicCtxContainer::PacketDrain(mut tasks)) => tasks.shutdown().await,
            None => {}
        }
    }

    #[cfg(mobile)]
    pub(super) async fn mobile_tun_claims(
        &self,
    ) -> Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims> {
        let nic = self.nic_ctx.lock().await;
        match nic.as_ref()? {
            NicCtxContainer::Active { nic_ctx, .. } => nic_ctx.current_mobile_tun_claims().await,
            NicCtxContainer::PacketDrain(_) => None,
        }
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

pub(super) struct NativeDhcpHost {
    pub(super) global_ctx: ArcGlobalCtx,
    pub(super) operation: Arc<Mutex<()>>,
    pub(super) cancel: CancellationToken,
    pub(super) nic: TunNicState,
    #[cfg(not(mobile))]
    pub(super) closed: Arc<Notify>,
    #[cfg(not(mobile))]
    pub(super) packet_plane: Arc<CorePacketPlane>,
    #[cfg(not(mobile))]
    pub(super) shared_virtual_nic_registry: ArcSharedVirtualNicRegistry,
}

impl NativeDhcpHost {
    pub(super) fn take_closed(&self) -> bool {
        #[cfg(not(mobile))]
        {
            self.closed.notified().now_or_never().is_some()
        }
        #[cfg(mobile)]
        {
            // The mobile VPN owner recreates and attaches its interface in response
            // to address events; desktop interface notifications do not apply here.
            false
        }
    }

    pub(super) async fn apply(&self, next: DhcpAddresses) -> anyhow::Result<()> {
        self.ensure_open()?;
        // The static family may already have an attached VPN interface before
        // DHCP's first round. No address event will rebuild it if nothing changed.
        #[cfg(mobile)]
        if next == self.current() {
            return Ok(());
        }
        tokio::select! {
            _ = self.cancel.cancelled() => anyhow::bail!("instance is closing; DHCP update cancelled"),
            _ = self.nic.drain() => {}
        }
        #[cfg(not(mobile))]
        self.set_addresses(DhcpAddresses::default());
        self.ensure_open()?;

        #[cfg(not(mobile))]
        {
            let addresses = self.with_static_addresses(next);
            if !self.global_ctx.no_tun() && (addresses.ipv4.is_some() || addresses.ipv6.is_some()) {
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
                    result = nic.run(addresses.ipv4, addresses.ipv6) => result?,
                }
                let magic_dns = if let Some(ip) = addresses.ipv4 {
                    let shared_route_backend = nic.shared_route_backend_for_dns();
                    MagicDnsRuntime::start(
                        self.global_ctx.clone(),
                        self.packet_plane.clone(),
                        nic.ifname().await,
                        ip,
                        shared_route_backend,
                    )
                } else {
                    MagicDnsRuntime::default()
                };
                self.nic.install(nic, magic_dns).await;
            }
        }
        self.set_addresses(next);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::{config::toml::TomlConfig, process_runtime::CoreProcessRuntime};

    use super::*;
    use crate::{common::global_ctx::GlobalCtxEvent, instance::test_instance::TestInstance};

    #[tokio::test]
    async fn stop_releases_packet_receiver_before_returning() {
        let state = TunNicState::empty();
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        state
            .install_receiver(HostPacketReceiver::new(receiver))
            .unwrap();
        let receiver = state.receiver();
        state.drain().await;
        // Let the drain acquire the receiver and block waiting for a packet.
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while receiver.try_lock().is_ok() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();

        state.stop().await;
        assert!(receiver.try_lock().is_ok());
    }

    #[tokio::test]
    async fn dhcp_preserves_publication_permit_and_cancelled_address() {
        let instance = TestInstance::new_with_process_runtime(
            TomlConfig::new_from_str("dhcp = true\ndhcpv6 = true").unwrap(),
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
            TestInstance::current_shared_virtual_nic_registry(),
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
        let addresses = DhcpAddresses {
            ipv4: Some("10.20.0.7/24".parse().unwrap()),
            ipv6: Some("fd12::7/64".parse().unwrap()),
        };
        let mut previous = DhcpAddresses::default();
        for next in [addresses, DhcpAddresses::default()] {
            let outcome = host.apply_dhcp(next).await;
            assert!(outcome.result.is_ok());
            assert_eq!(outcome.actual, next);
            assert_eq!(global_ctx.get_ipv4(), next.ipv4);
            assert_eq!(global_ctx.get_ipv6(), next.ipv6);
            assert!(operation.try_lock().is_err());
            host.publish_dhcp(previous, outcome.actual);
            assert_eq!(
                events.try_recv().unwrap(),
                if next.ipv4.is_none() {
                    GlobalCtxEvent::DhcpIpv4Conflicted(previous.ipv4)
                } else {
                    GlobalCtxEvent::DhcpIpv4Changed(previous.ipv4, next.ipv4)
                }
            );
            assert_eq!(
                events.try_recv().unwrap(),
                if next.ipv6.is_none() {
                    GlobalCtxEvent::DhcpIpv6Conflicted(previous.ipv6)
                } else {
                    GlobalCtxEvent::DhcpIpv6Changed(previous.ipv6, next.ipv6)
                }
            );
            drop(outcome);
            assert!(operation.try_lock().is_ok());
            previous = next;
        }

        global_ctx.set_ipv4(addresses.ipv4);
        global_ctx.set_ipv6(addresses.ipv6);
        cancel.cancel();
        let outcome = host.apply_dhcp(DhcpAddresses::default()).await;
        assert!(outcome.result.is_err());
        assert_eq!(outcome.actual, addresses);
        assert_eq!(global_ctx.get_ipv4(), addresses.ipv4);
        assert_eq!(global_ctx.get_ipv6(), addresses.ipv6);
        runtime.shutdown().await;
    }
}

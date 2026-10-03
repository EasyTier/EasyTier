use std::sync::Arc;

use easytier_core::{
    config::runtime::CoreInstanceRuntimeConfig, gateway::dhcp::DhcpIpv4Host,
    host::packet::HostPacketReceiver, instance::CorePacketPlane,
};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

mod event_journal;
mod implementation;
#[cfg(feature = "tun")]
mod magic_dns;
#[cfg(feature = "tun")]
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

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use std::time::Duration;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use anyhow::Context as _;
#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use tokio::task::JoinHandle;

#[cfg(all(target_os = "linux", feature = "linux-netlink"))]
use crate::instance::route::{HostRouteManager, PlatformRouteBackend, RouteLease, stop_manager};

pub(crate) struct NativeInstanceRuntimeHost {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    event_journal: EventJournal,
    tun: NativeTunRuntime,
    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    route_task: Mutex<Option<JoinHandle<Result<(), crate::instance::route::CleanupIncomplete>>>>,
    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    route_cancel: CancellationToken,
}

impl NativeInstanceRuntimeHost {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        let cancel = CancellationToken::new();
        let tun = NativeTunRuntime::new(global_ctx.clone(), cancel.clone());
        let event_journal = EventJournal::new(&global_ctx);
        Arc::new(Self {
            global_ctx,
            event_journal,
            operation: Arc::new(Mutex::new(())),
            cancel,
            tun,
            #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
            route_task: Mutex::new(None),
            #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
            route_cancel: CancellationToken::new(),
        })
    }

    async fn prepare_runtime(
        &self,
        packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
        self.event_journal.start(self.cancel.clone()).await;
        self.tun.prepare(packet_plane.clone()).await?;

        #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
        if !self.global_ctx.get_flags().no_tun {
            let cancel_token = self.route_cancel.clone();
            let backend = PlatformRouteBackend::new()
                .context("failed to initialize platform netlink route backend")?;
            let default_metric = 65535;
            let manager = HostRouteManager::new(
                self.global_ctx.clone(),
                backend,
                cancel_token.clone(),
                default_metric,
            );

            let handle = manager.handle();
            self.global_ctx.set_route_handle(Some(handle.clone()));

            let proxy_lease = handle.register();
            let p_global_ctx = self.global_ctx.clone();
            let p_packet_plane = packet_plane.clone();
            let p_cancel = cancel_token.clone();
            tokio::spawn(async move {
                Self::run_proxy_routes_publisher(
                    p_global_ctx,
                    p_packet_plane,
                    proxy_lease,
                    p_cancel,
                )
                .await;
            });

            let join_handle = tokio::spawn(manager.run());
            *self.route_task.lock().await = Some(join_handle);
        }

        Ok(Some(
            self.tun.dhcp_host(self.operation.clone(), packet_plane),
        ))
    }

    async fn shutdown_runtime(&self) {
        self.cancel.cancel();
        let _operation = self.operation.lock().await;

        #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
        {
            self.route_cancel.cancel();
            self.global_ctx.set_route_handle(None);
            let mut join_guard = self.route_task.lock().await;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            let res = stop_manager(&self.route_cancel, &mut join_guard, deadline).await;
            if let Err(err) = res {
                tracing::warn!(?err, "failed or incomplete route manager shutdown cleanup");
            }
        }

        self.event_journal.stop().await;
        self.tun.shutdown().await;
    }

    fn request_runtime_shutdown(&self) {
        self.cancel.cancel();
    }

    fn management_events_snapshot(&self) -> Vec<String> {
        self.event_journal.events()
    }

    #[cfg(feature = "web-client")]
    fn synchronize_global_ctx_config(
        &self,
        patch: &crate::proto::api::config::InstanceConfigPatch,
        config: &CoreInstanceRuntimeConfig,
    ) {
        if patch.hostname.is_some() {
            self.global_ctx.set_hostname(
                config
                    .peer
                    .runtime
                    .core
                    .node
                    .hostname
                    .clone()
                    .unwrap_or_default(),
            );
        }
        if patch.ipv4.is_some() && !config.services.dhcp_ipv4 {
            self.global_ctx
                .set_ipv4(crate::common::global_ctx::GlobalCtx::runtime_ipv4(
                    &config.peer,
                ));
        }
        if patch.ipv6.is_some() {
            self.global_ctx
                .set_ipv6(crate::common::global_ctx::GlobalCtx::runtime_ipv6(
                    &config.peer,
                ));
        }
        if patch.disable_relay_data.is_some() || patch.prefer_peer_relay.is_some() {
            self.global_ctx.set_flags(config.peer.flags.clone());
        }
    }

    pub(crate) fn subscribe_event(&self) -> crate::common::global_ctx::EventBusSubscriber {
        self.global_ctx.subscribe()
    }

    fn attach_runtime_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.tun.attach_fd(fd)
    }

    fn install_packet_receiver(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.tun.install_packet_receiver(receiver)
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    async fn run_proxy_routes_publisher(
        global_ctx: ArcGlobalCtx,
        packet_plane: Arc<CorePacketPlane>,
        lease: RouteLease,
        cancel: CancellationToken,
    ) {
        use crate::common::global_ctx::GlobalCtxEvent;

        let mut cur_proxy_cidrs = std::collections::BTreeSet::<cidr::Ipv4Cidr>::new();
        let mut event_receiver = global_ctx.subscribe();

        if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
            cur_proxy_cidrs = diff.current;
            let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                .iter()
                .copied()
                .map(cidr::IpCidr::V4)
                .collect();
            lease.set(set);
        }

        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                res = event_receiver.recv() => {
                    match res {
                        Ok(GlobalCtxEvent::ProxyCidrsUpdated(_, _)) => {
                            if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
                                cur_proxy_cidrs = diff.current;
                                let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                                    .iter()
                                    .copied()
                                    .map(cidr::IpCidr::V4)
                                    .collect();
                                lease.set(set);
                            }
                        }
                        Ok(_) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                            event_receiver = event_receiver.resubscribe();
                            if let Some(diff) = packet_plane.proxy_cidr_diff(&cur_proxy_cidrs).await {
                                cur_proxy_cidrs = diff.current;
                                let set: std::collections::BTreeSet<cidr::IpCidr> = cur_proxy_cidrs
                                    .iter()
                                    .copied()
                                    .map(cidr::IpCidr::V4)
                                    .collect();
                                lease.set(set);
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::TomlConfig,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
    };

    #[cfg(feature = "web-client")]
    fn runtime_config(config: &TomlConfig) -> CoreInstanceRuntimeConfig {
        let normalized = easytier_core::instance::CoreInstanceConfig::from_toml(config).unwrap();
        CoreInstanceRuntimeConfig {
            services: normalized.connectivity.runtime,
            peer: Arc::new(normalized.peer.snapshot),
        }
    }

    #[test]
    fn runtime_host_owns_event_subscription_context() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());
        let mut events = runtime_host.subscribe_event();

        global_ctx.issue_event(GlobalCtxEvent::CredentialChanged);

        assert_eq!(
            events.try_recv().unwrap(),
            GlobalCtxEvent::CredentialChanged
        );
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn runtime_host_synchronizes_normalized_config_without_management() {
        use easytier_core::{config::toml::ConfigLoader as _, instance::InstanceRuntimeHost as _};

        let config = TomlConfig::default();
        config.set_hostname(Some("before".to_owned()));
        config.set_ipv4(Some("10.20.0.1/24".parse().unwrap()));
        config.set_ipv6(Some("fd00::1/64".parse().unwrap()));
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());

        assert_eq!(global_ctx.get_hostname(), "before");
        assert_eq!(global_ctx.get_ipv4(), Some("10.20.0.1/24".parse().unwrap()));
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::1/64".parse().unwrap()));
        assert!(!global_ctx.get_flags().disable_relay_data);
        assert!(!global_ctx.get_flags().prefer_peer_relay);

        config.set_hostname(Some("after".to_owned()));
        config.set_ipv4(Some("10.20.0.2/24".parse().unwrap()));
        config.set_ipv6(Some("fd00::2/64".parse().unwrap()));
        let mut flags = config.get_flags();
        flags.disable_relay_data = true;
        flags.prefer_peer_relay = true;
        config.set_flags(flags);
        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                hostname: Some("ignored-raw-hostname".to_owned()),
                ipv4: Some("10.99.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ipv6: Some("fd99::1/64".parse::<cidr::Ipv6Inet>().unwrap().into()),
                disable_relay_data: Some(false),
                prefer_peer_relay: Some(false),
                ..Default::default()
            },
            &runtime_config(&config),
        );

        assert_eq!(global_ctx.get_hostname(), "after");
        assert_eq!(global_ctx.get_ipv4(), Some("10.20.0.2/24".parse().unwrap()));
        assert_eq!(global_ctx.get_ipv6(), Some("fd00::2/64".parse().unwrap()));
        assert!(global_ctx.get_flags().disable_relay_data);
        assert!(global_ctx.get_flags().prefer_peer_relay);
    }

    #[cfg(feature = "web-client")]
    #[test]
    fn runtime_host_preserves_dhcp_ipv4_during_config_synchronization() {
        use easytier_core::{config::toml::ConfigLoader as _, instance::InstanceRuntimeHost as _};

        let config = TomlConfig::default();
        config.set_dhcp(true);
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());
        let lease = "10.20.0.7/24".parse().unwrap();
        global_ctx.set_ipv4(Some(lease));

        config.set_ipv4(None);
        runtime_host.synchronize_config(
            &crate::proto::api::config::InstanceConfigPatch {
                ipv4: Some("10.99.0.1/24".parse::<cidr::Ipv4Inet>().unwrap().into()),
                ..Default::default()
            },
            &runtime_config(&config),
        );

        assert_eq!(global_ctx.get_ipv4(), Some(lease));
    }
}

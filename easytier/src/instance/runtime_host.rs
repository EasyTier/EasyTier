use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[cfg(feature = "web-client")]
use easytier_core::config::runtime::CoreInstanceRuntimeConfig;
use easytier_core::{
    gateway::dhcp::DhcpHost, host::packet::HostPacketReceiver, instance::CorePacketPlane,
};
use tokio::sync::{Mutex, watch};
use tokio_util::sync::CancellationToken;

use crate::common::global_ctx::ArcGlobalCtx;

mod dhcp;
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

use super::runtime_executor::NativeInstanceExecutor;
use event_journal::EventJournal;
#[cfg(feature = "tun")]
use magic_dns::MagicDnsRuntime;
use tun_runtime::NativeTunRuntime;

pub(crate) struct NativeInstanceRuntimeHost {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    event_journal: Arc<EventJournal>,
    tun: Arc<NativeTunRuntime>,
    cleanup_started: AtomicBool,
    cleanup_result: watch::Sender<Option<Result<(), Arc<str>>>>,
    #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
    routes: Option<Arc<super::route::runtime::NativeRouteRuntime>>,
    executor: Option<NativeInstanceExecutor>,
}

impl NativeInstanceRuntimeHost {
    #[cfg(test)]
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        Self::new_with_executor(global_ctx, None).unwrap()
    }

    pub(super) fn new_with_executor(
        global_ctx: ArcGlobalCtx,
        executor: Option<NativeInstanceExecutor>,
    ) -> anyhow::Result<Arc<Self>> {
        #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
        let routes = (!global_ctx.no_tun())
            .then(|| super::route::runtime::NativeRouteRuntime::new(&global_ctx).map(Arc::new))
            .transpose()?;
        let cancel = CancellationToken::new();
        let tun = Arc::new(NativeTunRuntime::new(
            global_ctx.clone(),
            cancel.clone(),
            #[cfg(feature = "tun")]
            global_ctx.net_ns.nics.clone(),
            #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
            routes.as_ref().map(|routes| routes.context.clone()),
        ));
        let event_journal = Arc::new(EventJournal::new(&global_ctx));
        Ok(Arc::new(Self {
            global_ctx,
            event_journal,
            operation: Arc::new(Mutex::new(())),
            cancel,
            tun,
            executor,
            cleanup_started: AtomicBool::new(false),
            cleanup_result: watch::channel(None).0,
            #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
            routes,
        }))
    }

    async fn prepare_runtime(
        &self,
        packet_plane: Arc<CorePacketPlane>,
        runtime_config: easytier_core::config::runtime::CoreRuntimeConfigStore,
    ) -> anyhow::Result<Option<Arc<dyn DhcpHost>>> {
        let _operation = self.operation.lock().await;
        anyhow::ensure!(!self.cancel.is_cancelled(), "instance runtime is closing");
        #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
        if let Some(routes) = &self.routes {
            routes.bind_config(runtime_config)?;
        }
        #[cfg(not(all(target_os = "linux", feature = "tun", feature = "linux-netlink")))]
        let _ = runtime_config;
        anyhow::ensure!(!self.cancel.is_cancelled(), "instance runtime is closing");
        self.event_journal.start(self.cancel.clone()).await;
        self.tun.prepare(packet_plane.clone()).await?;
        Ok(Some(
            self.tun.dhcp_host(self.operation.clone(), packet_plane),
        ))
    }

    async fn shutdown_runtime(&self) {
        self.request_runtime_shutdown();
        let mut result = self.cleanup_result.subscribe();
        while result.borrow_and_update().is_none() {
            if result.changed().await.is_err() {
                break;
            }
        }
    }

    fn request_runtime_shutdown(&self) {
        self.cancel.cancel();
        #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
        if let Some(routes) = &self.routes {
            routes.request_close();
        }
        if self.cleanup_started.swap(true, Ordering::AcqRel) {
            return;
        }
        let operation = self.operation.clone();
        let journal = self.event_journal.clone();
        let tun = self.tun.clone();
        let result = self.cleanup_result.clone();
        #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
        let routes = self.routes.clone();
        // Created before spawn so loss of an unpolled cleanup is visible too.
        let on_interrupted = {
            let result = result.clone();
            #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
            let routes = routes.clone();
            move || {
                let reason: Arc<str> = "native runtime cleanup was interrupted".into();
                #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
                if let Some(routes) = routes {
                    routes.abandon(reason.clone());
                }
                result.send_replace(Some(Err(reason)));
            }
        };
        let interrupted = guarden::guard!([on_interrupted] { on_interrupted(); });
        match crate::host_runtime::native_host_runtime().shared_executor() {
            Ok(shared) => {
                shared.spawn(async move {
                    let _operation = operation.lock().await;
                    journal.stop().await;
                    tun.shutdown().await;
                    #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
                    let drained = match routes {
                        Some(routes) => routes
                            .drain()
                            .await
                            .map_err(|error| Arc::<str>::from(format!("{error:#}"))),
                        None => Ok(()),
                    };
                    #[cfg(not(all(
                        target_os = "linux",
                        feature = "tun",
                        feature = "linux-netlink"
                    )))]
                    let drained = Ok(());
                    if let Err(error) = &drained {
                        tracing::warn!(%error, "native runtime cleanup incomplete");
                    }
                    result.send_replace(Some(drained));
                    let _ = interrupted.defuse();
                });
            }
            Err(error) => {
                tracing::error!(?error, "native cleanup executor unavailable");
                drop(interrupted);
            }
        }
    }

    fn runtime_shutdown_error(&self) -> Option<String> {
        self.cleanup_result
            .borrow()
            .as_ref()
            .and_then(|result| result.as_ref().err())
            .map(ToString::to_string)
    }

    #[cfg(all(target_os = "linux", feature = "tun", feature = "linux-netlink"))]
    pub(super) fn route_context(&self) -> Option<Arc<super::route::runtime::NativeRouteContext>> {
        self.routes.as_ref().map(|routes| routes.context.clone())
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
        if patch.ipv6.is_some() && !config.services.dhcp_ipv6 {
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

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) fn tun_enabled(&self) -> bool {
        !self.global_ctx.get_flags().no_tun
    }

    fn attach_runtime_tun_fd(&self, fd: i32) -> anyhow::Result<()> {
        self.tun.attach_fd(fd)
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn attach_mobile_tun_fd(
        &self,
        fd: i32,
        replace_tun_fd: bool,
        claims: Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
    ) -> anyhow::Result<()> {
        self.tun.attach_mobile_fd(fd, replace_tun_fd, claims).await
    }

    #[cfg(all(feature = "tun", mobile))]
    pub(crate) async fn mobile_tun_claims(
        &self,
        packet_plane: &CorePacketPlane,
    ) -> (
        crate::instance::shared_virtual_nic::SharedIfConfigClaims,
        Option<crate::instance::shared_virtual_nic::SharedIfConfigClaims>,
        bool,
    ) {
        (
            crate::instance::virtual_nic::NicCtx::mobile_tun_claims(&self.global_ctx, packet_plane)
                .await,
            self.tun.current_mobile_tun_claims().await,
            cfg!(feature = "magic-dns")
                && self.global_ctx.get_flags().accept_dns
                && self.global_ctx.get_ipv4().is_some(),
        )
    }

    fn install_packet_receiver(&self, receiver: HostPacketReceiver) -> anyhow::Result<()> {
        self.tun.install_packet_receiver(receiver)
    }
}

impl Drop for NativeInstanceRuntimeHost {
    fn drop(&mut self) {
        self.request_runtime_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::{
        config::TomlConfig,
        global_ctx::{GlobalCtx, GlobalCtxEvent},
    };

    fn runtime_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceRuntimeHost> {
        NativeInstanceRuntimeHost::new(global_ctx)
    }

    #[tokio::test]
    async fn cleanup_survives_cancellation_of_its_first_waiter() {
        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let host = runtime_host(global_ctx);
        let permit = host.operation.lock().await;
        let waiter_host = host.clone();
        let waiter = tokio::spawn(async move { waiter_host.shutdown_runtime().await });
        tokio::task::yield_now().await;
        waiter.abort();
        let _ = waiter.await;
        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(3), host.shutdown_runtime())
            .await
            .unwrap();
        assert_eq!(host.cleanup_result.borrow().as_ref(), Some(&Ok(())));
    }

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
        let runtime_host = runtime_host(global_ctx.clone());
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
        let runtime_host = runtime_host(global_ctx.clone());

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
        let runtime_host = runtime_host(global_ctx.clone());
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

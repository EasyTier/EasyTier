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
mod route_runtime;
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
use route_runtime::NativeRouteRuntime;
use tun_runtime::NativeTunRuntime;

pub(crate) struct NativeInstanceRuntimeHost {
    global_ctx: ArcGlobalCtx,
    operation: Arc<Mutex<()>>,
    cancel: CancellationToken,
    event_journal: EventJournal,
    tun: NativeTunRuntime,
    route: NativeRouteRuntime,
}

impl NativeInstanceRuntimeHost {
    pub(crate) fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        let cancel = CancellationToken::new();
        let tun = NativeTunRuntime::new(global_ctx.clone(), cancel.clone());
        let event_journal = EventJournal::new(&global_ctx);
        let route = NativeRouteRuntime::new(global_ctx.clone(), cancel.clone());
        Arc::new(Self {
            global_ctx,
            event_journal,
            operation: Arc::new(Mutex::new(())),
            cancel,
            tun,
            route,
        })
    }

    pub(crate) fn route_handle(&self) -> Option<easytier_core::host::route::RouteHandle> {
        self.route.route_handle()
    }

    async fn prepare_runtime(
        &self,
        packet_plane: Arc<CorePacketPlane>,
    ) -> anyhow::Result<Option<Arc<dyn DhcpIpv4Host>>> {
        self.event_journal.start(self.cancel.clone()).await;
        self.tun.prepare(packet_plane.clone()).await?;
        self.route.prepare().await?;

        Ok(Some(
            self.tun.dhcp_host(self.operation.clone(), packet_plane),
        ))
    }

    async fn shutdown_runtime(&self) {
        self.cancel.cancel();
        self.route.request_shutdown();
        let _operation = self.operation.lock().await;

        self.route.shutdown().await;
        self.event_journal.stop().await;
        self.tun.shutdown().await;
    }

    fn request_runtime_shutdown(&self) {
        self.cancel.cancel();
        self.route.request_shutdown();
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

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    #[test]
    fn route_handle_lifecycle_without_prepare_closes_registry() {
        use easytier_core::host::route::RouteDemand;
        use std::collections::BTreeSet;

        let global_ctx = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());

        let handle = runtime_host.route_handle().expect("handle must exist");
        let reg = handle
            .register(RouteDemand::Additional(BTreeSet::new()))
            .expect("must register");
        assert!(global_ctx.get_route_handle().is_some());

        // Calling request_runtime_shutdown without ever calling prepare_runtime
        runtime_host.request_runtime_shutdown();

        // Registry is closed synchronously
        assert!(
            handle
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg.replace(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(global_ctx.get_route_handle().is_none());
    }

    #[cfg(all(target_os = "linux", feature = "linux-netlink"))]
    #[test]
    fn two_instances_have_independent_route_registries() {
        use easytier_core::host::route::RouteDemand;
        use std::collections::BTreeSet;

        let global_ctx_a = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let runtime_host_a = NativeInstanceRuntimeHost::new(global_ctx_a.clone());

        let global_ctx_b = Arc::new(GlobalCtx::new(TomlConfig::default()));
        let runtime_host_b = NativeInstanceRuntimeHost::new(global_ctx_b.clone());

        let handle_a = runtime_host_a.route_handle().unwrap();
        let handle_b = runtime_host_b.route_handle().unwrap();

        let reg_a = handle_a
            .register(RouteDemand::Additional(BTreeSet::new()))
            .unwrap();
        let reg_b = handle_b
            .register(RouteDemand::Additional(BTreeSet::new()))
            .unwrap();

        // Shut down A
        runtime_host_a.request_runtime_shutdown();
        assert!(
            handle_a
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(
            reg_a
                .replace(RouteDemand::Additional(BTreeSet::new()))
                .is_none()
        );
        assert!(global_ctx_a.get_route_handle().is_none());

        // B remains fully functional
        assert!(
            handle_b
                .register(RouteDemand::Additional(BTreeSet::new()))
                .is_some()
        );
        assert!(
            reg_b
                .replace(RouteDemand::Additional(BTreeSet::new()))
                .is_some()
        );
        assert!(global_ctx_b.get_route_handle().is_some());
    }

    #[test]
    fn no_tun_provides_no_route_handle() {
        use easytier_core::config::toml::ConfigLoader as _;

        let config = TomlConfig::default();
        let mut flags = config.get_flags();
        flags.no_tun = true;
        config.set_flags(flags);

        let global_ctx = Arc::new(GlobalCtx::new(config));
        let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());

        assert!(runtime_host.route_handle().is_none());
        assert!(global_ctx.get_route_handle().is_none());
    }
}

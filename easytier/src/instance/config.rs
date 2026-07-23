#[cfg(test)]
use std::sync::Arc;

#[cfg(feature = "management")]
use easytier_core::peers::context::{PeerCredentialEventSink, PeerEvent, PeerEventSink};
use easytier_core::{
    config::peers::HostRoutingPolicy, instance::CoreInstanceHostConfig,
    peers::peer_manager::PeerManagerHostAdapters,
};
use strum::VariantArray as _;

#[cfg(feature = "management")]
use crate::common::credential_manager::runtime_credential_storage;
#[cfg(feature = "management")]
use crate::common::global_ctx::{GlobalCtx, GlobalCtxEvent};
use crate::{
    common::{constants::EASYTIER_VERSION, global_ctx::ArcGlobalCtx},
    tunnel::IpScheme,
};

/// Projects only native Host policy and build capabilities. All TOML-derived
/// Instance configuration is normalized by `easytier-core`.
pub(crate) fn runtime_core_host_config() -> CoreInstanceHostConfig {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    CoreInstanceHostConfig {
        hostname_fallback: (!hostname.is_empty()).then_some(hostname),
        host_routing: HostRoutingPolicy {
            local_exit_node_fallback: cfg!(target_env = "ohos"),
        },
        force_exit_node: cfg!(target_env = "ohos"),
        allow_interface_bind: !cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        smoltcp_available: cfg!(feature = "smoltcp"),
        requires_smoltcp: cfg!(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        )),
        icmp_failure_is_fatal: cfg!(not(any(
            target_os = "android",
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne"),
            target_env = "ohos"
        ))),
        public_ipv6_provider_supported: cfg!(target_os = "linux"),
        gateway_enabled: cfg!(feature = "socks5"),
        easytier_version: EASYTIER_VERSION.to_owned(),
        endpoint_protocols: IpScheme::VARIANTS.iter().map(ToString::to_string).collect(),
    }
}

#[cfg(feature = "management")]
impl PeerEventSink for GlobalCtx {
    fn issue_event(&self, event: PeerEvent) {
        let event = match event {
            PeerEvent::PeerAdded(peer_id) => GlobalCtxEvent::PeerAdded(peer_id),
            PeerEvent::PeerRemoved(peer_id) => GlobalCtxEvent::PeerRemoved(peer_id),
            #[cfg(feature = "management")]
            PeerEvent::PeerConnAdded(info) => GlobalCtxEvent::PeerConnAdded(info.into()),
            #[cfg(feature = "management")]
            PeerEvent::PeerConnRemoved(info) => GlobalCtxEvent::PeerConnRemoved(info.into()),
            #[cfg(not(feature = "management"))]
            PeerEvent::PeerConnAdded(_) | PeerEvent::PeerConnRemoved(_) => return,
        };
        self.issue_event(event);
    }
}

#[cfg(feature = "management")]
impl PeerCredentialEventSink for GlobalCtx {
    fn credential_changed(&self) {
        self.issue_event(GlobalCtxEvent::CredentialChanged);
    }
}

pub(crate) fn runtime_peer_manager_host_adapters(
    global_ctx: &ArcGlobalCtx,
) -> PeerManagerHostAdapters {
    #[cfg(not(feature = "management"))]
    {
        let _ = global_ctx;
        PeerManagerHostAdapters::default()
    }
    #[cfg(feature = "management")]
    PeerManagerHostAdapters {
        event_sink: global_ctx.clone(),
        credential_storage: runtime_credential_storage(global_ctx.config.get_credential_file()),
        credential_event_sink: global_ctx.clone(),
    }
}

#[cfg(test)]
pub(crate) fn test_core_instance_config(
    global_ctx: &ArcGlobalCtx,
) -> easytier_core::instance::CoreInstanceConfig {
    use easytier_core::config::toml::{ConfigLoader as _, TomlConfig};

    let config = TomlConfig::new_from_str(&global_ctx.config.dump())
        .expect("test configuration should round-trip through TOML");
    easytier_core::instance::CoreInstanceConfig::from_toml_with_host(
        &config,
        &runtime_core_host_config(),
    )
    .expect("test configuration should normalize")
}

#[cfg(test)]
pub(crate) fn test_runtime_instance_config(
    global_ctx: &ArcGlobalCtx,
) -> easytier_core::config::runtime::CoreInstanceRuntimeConfig {
    let config = test_core_instance_config(global_ctx);
    easytier_core::config::runtime::CoreInstanceRuntimeConfig {
        services: config.connectivity.runtime,
        peer: Arc::new(config.peer.snapshot),
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::{
        config::toml::TomlConfig,
        peers::context::{PeerCredentialEventSink, PeerEventSink},
    };

    use crate::common::global_ctx::tests::get_mock_global_ctx;

    use super::*;

    #[test]
    fn native_host_config_contains_only_platform_policy() {
        let config = runtime_core_host_config();
        let hostname = gethostname::gethostname().to_string_lossy().to_string();

        assert_eq!(
            config.hostname_fallback,
            (!hostname.is_empty()).then_some(hostname)
        );
        assert_eq!(config.gateway_enabled, cfg!(feature = "socks5"));
        assert_eq!(config.smoltcp_available, cfg!(feature = "smoltcp"));
        assert_eq!(
            config.public_ipv6_provider_supported,
            cfg!(target_os = "linux")
        );
        assert_eq!(config.easytier_version, EASYTIER_VERSION);
    }

    #[test]
    fn clearing_configured_hostname_does_not_reuse_the_old_value() {
        let host = runtime_core_host_config();
        let initial = TomlConfig::new_from_str("hostname = \"configured-host\"").unwrap();
        let cleared = TomlConfig::new_from_str("hostname = \"\"").unwrap();

        let initial =
            easytier_core::instance::CoreInstanceConfig::from_toml_with_host(&initial, &host)
                .unwrap();
        let cleared =
            easytier_core::instance::CoreInstanceConfig::from_toml_with_host(&cleared, &host)
                .unwrap();

        assert_eq!(
            initial.peer.snapshot.runtime.core.node.hostname.as_deref(),
            Some("configured-host")
        );
        assert_ne!(
            cleared.peer.snapshot.runtime.core.node.hostname.as_deref(),
            Some("configured-host")
        );
        assert_eq!(
            cleared.peer.snapshot.runtime.core.node.hostname.as_deref(),
            host.hostname_fallback.as_deref()
        );
    }

    #[tokio::test]
    async fn peer_event_sink_projects_core_events_to_global_context() {
        let global_ctx = get_mock_global_ctx();
        let mut events = global_ctx.subscribe();
        PeerEventSink::issue_event(global_ctx.as_ref(), PeerEvent::PeerAdded(7));

        assert!(matches!(
            events.recv().await.unwrap(),
            GlobalCtxEvent::PeerAdded(7)
        ));
    }

    #[tokio::test]
    async fn credential_event_sink_projects_core_changes_to_global_context() {
        let global_ctx = get_mock_global_ctx();
        let mut events = global_ctx.subscribe();
        PeerCredentialEventSink::credential_changed(global_ctx.as_ref());

        assert!(matches!(
            events.recv().await.unwrap(),
            GlobalCtxEvent::CredentialChanged
        ));
    }
}

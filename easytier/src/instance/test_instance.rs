//! Test-only convenience around the production CoreInstance composition.

use std::sync::Arc;

use easytier_core::{
    config::toml::TomlConfig, connectivity::stun::StunSocketMapper,
    process_runtime::CoreProcessRuntime,
};

use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtx},
    instance::{
        composition::{NativeCoreInstance, runtime_core_host_adapters_with_packet_egress},
        runtime_host::NativeInstanceRuntimeHost,
    },
    socket::udp::RuntimeUdpSocket,
};

pub(crate) struct TestInstance {
    core: Arc<NativeCoreInstance>,
    global_ctx: ArcGlobalCtx,
}

impl TestInstance {
    pub fn new_with_process_runtime(
        config: TomlConfig,
        process_runtime: Arc<CoreProcessRuntime>,
    ) -> Self {
        Self::compose(config, process_runtime, |_| {})
    }

    pub fn new_with_process_runtime_and_stun_provider(
        config: TomlConfig,
        process_runtime: Arc<CoreProcessRuntime>,
        provider: Box<dyn StunSocketMapper<RuntimeUdpSocket>>,
    ) -> Self {
        let provider: Arc<dyn StunSocketMapper<RuntimeUdpSocket>> = Arc::from(provider);
        Self::compose(config, process_runtime, move |adapters| {
            adapters.replace_stun_provider(provider);
        })
    }

    fn compose(
        config: TomlConfig,
        process_runtime: Arc<CoreProcessRuntime>,
        customize: impl FnOnce(
            &mut easytier_core::instance::CoreHostAdapters<
                crate::instance::host::NativeInstanceHost,
            >,
        ),
    ) -> Self {
        let host_config = crate::instance::config::runtime_core_host_config();
        let mut captured_global_ctx = None;
        let mut customize = Some(customize);
        let core =
            NativeCoreInstance::compose_with_toml(&config, host_config.clone(), |normalized| {
                let global_ctx = Arc::new(GlobalCtx::new(normalized.clone(), &host_config));
                captured_global_ctx = Some(global_ctx.clone());
                let runtime_host = NativeInstanceRuntimeHost::new(global_ctx.clone());
                let mut adapters = runtime_core_host_adapters_with_packet_egress(
                    global_ctx,
                    process_runtime,
                    runtime_host.clone(),
                );
                if let Some(c) = customize.take() {
                    c(&mut adapters);
                }
                adapters.instance_runtime = runtime_host;
                Ok(adapters)
            })
            .expect("test CoreInstance composition should be valid");

        Self {
            core,
            global_ctx: captured_global_ctx.expect("global_ctx should be created in callback"),
        }
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        self.core.start().await
    }

    pub async fn clear_resources(&mut self) {
        self.core.stop().await;
    }

    pub fn get_core_instance(&self) -> Arc<NativeCoreInstance> {
        self.core.clone()
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }

    pub fn get_config_patcher(&self) -> TestConfigPatcher {
        TestConfigPatcher {
            core: self.core.clone(),
        }
    }
}

pub(crate) struct TestConfigPatcher {
    core: Arc<NativeCoreInstance>,
}

impl TestConfigPatcher {
    pub async fn apply_patch(
        &self,
        patch: crate::proto::api::config::InstanceConfigPatch,
    ) -> anyhow::Result<()> {
        easytier_core::management::apply_config_patch(&self.core, patch, None).await
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::config::toml::{ConfigLoader as _, TomlConfig};

    use super::*;

    #[tokio::test]
    async fn composition_preserves_secure_admin_identity() {
        let config = TomlConfig::default();
        config
            .set_secure_mode(Some(crate::proto::common::SecureModeConfig {
                enabled: true,
                ..Default::default()
            }))
            .unwrap();

        let instance = TestInstance::new_with_process_runtime(config, CoreProcessRuntime::new());

        assert_eq!(
            instance
                .get_global_ctx()
                .runtime_config_store()
                .snapshot()
                .network_identity
                .network_secret
                .as_deref(),
            Some("")
        );
    }

    #[tokio::test]
    async fn test_instance_isolates_external_config_mutation() {
        let config = TomlConfig::new_from_str(
            r#"
hostname = "original-host"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let instance =
            TestInstance::new_with_process_runtime(config.clone(), CoreProcessRuntime::new());

        config.set_hostname(Some("mutated-external-host".to_string()));
        assert_eq!(instance.get_global_ctx().get_hostname(), "original-host");
    }

    #[tokio::test]
    async fn test_instance_updates_global_ctx_and_toml_config_on_patch() {
        let config = TomlConfig::new_from_str(
            r#"
hostname = "before-patch"
[network_identity]
network_name = "test"
network_secret = "secret"
"#,
        )
        .unwrap();
        let mut instance =
            TestInstance::new_with_process_runtime(config, CoreProcessRuntime::new());

        assert_eq!(instance.get_global_ctx().get_hostname(), "before-patch");

        // Start instance and apply patch through management patcher
        instance.run().await.unwrap();

        let patcher = instance.get_config_patcher();
        let patch = crate::proto::api::config::InstanceConfigPatch {
            hostname: Some("after-patch".to_string()),
            ..Default::default()
        };
        patcher.apply_patch(patch).await.unwrap();

        assert_eq!(instance.get_global_ctx().get_hostname(), "after-patch");
        assert_eq!(
            instance
                .get_core_instance()
                .toml_config()
                .unwrap()
                .get_hostname(),
            "after-patch"
        );

        instance.clear_resources().await;
    }
}

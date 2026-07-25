//! Test-only convenience around the production CoreInstance composition.

use std::sync::Arc;

use easytier_core::{
    config::toml::TomlConfig, connectivity::stun::StunSocketMapper, instance::CoreInstance,
    process_runtime::CoreProcessRuntime,
};

use crate::{
    common::global_ctx::{ArcGlobalCtx, GlobalCtx},
    instance::{
        composition::{NativeCoreInstance, runtime_core_host_adapters},
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
        let global_ctx = Arc::new(GlobalCtx::new(config.clone()));
        let (packet_sender, packet_receiver) = tokio::sync::mpsc::channel(128);
        let mut adapters = runtime_core_host_adapters(
            global_ctx.clone(),
            process_runtime,
            Arc::new(packet_sender),
        );
        customize(&mut adapters);
        adapters.instance_runtime =
            NativeInstanceRuntimeHost::new(global_ctx.clone(), packet_receiver);
        let core = CoreInstance::from_toml(config, adapters)
            .expect("test CoreInstance composition should be valid");
        Self { core, global_ctx }
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
        easytier_core::management::apply_config_patch(&self.core, patch).await
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::config::{
        normalize_secure_mode_config,
        toml::{ConfigLoader as _, TomlConfig},
    };

    use super::*;

    #[tokio::test]
    async fn composition_preserves_secure_admin_identity() {
        let config = TomlConfig::default();
        config.set_secure_mode(Some(
            normalize_secure_mode_config(crate::proto::common::SecureModeConfig {
                enabled: true,
                ..Default::default()
            })
            .unwrap(),
        ));

        let instance = TestInstance::new_with_process_runtime(config, CoreProcessRuntime::new());

        assert_eq!(
            instance
                .get_global_ctx()
                .config
                .get_network_identity()
                .network_secret
                .as_deref(),
            Some("")
        );
    }
}

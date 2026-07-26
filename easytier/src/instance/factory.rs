use std::sync::Arc;

#[cfg(any(feature = "management-rpc", test))]
use easytier_core::instance::manager::InstanceManager;
#[cfg(feature = "management-rpc")]
use easytier_core::management::ProcessRuntimeProvider;
use easytier_core::{
    config::toml::TomlConfig,
    instance::{CoreInstance, manager::InstanceFactory},
    process_runtime::CoreProcessRuntime,
};

use crate::common::global_ctx::EventBusSubscriber;

use super::{
    composition::compose_native_core_instance, host::NativeInstanceHost,
    runtime_host::NativeInstanceRuntimeHost,
};

pub type NativeCoreInstance = CoreInstance<NativeInstanceHost>;
#[cfg(feature = "management-rpc")]
pub type NativeInstanceManager = InstanceManager<NativeInstanceFactory>;
#[cfg(feature = "management")]
pub type NativeProcessManagement =
    easytier_core::management::ProcessManagement<NativeInstanceFactory>;

#[cfg(feature = "management-rpc")]
pub fn native_instance_manager() -> NativeInstanceManager {
    native_instance_manager_with_optional_runtime(None)
}

#[cfg(feature = "management")]
pub fn native_cli_instance_manager() -> NativeInstanceManager {
    let process_runtime = CoreProcessRuntime::new();
    InstanceManager::new(
        NativeInstanceFactory::new(process_runtime).with_cli_event_logging(),
        None,
    )
}

pub fn create_native_instance(config: TomlConfig) -> anyhow::Result<Arc<NativeCoreInstance>> {
    NativeInstanceFactory::new(CoreProcessRuntime::new()).create(config, ())
}

/// Subscribes to native presentation events owned by this instance's runtime.
pub fn subscribe_native_instance_event(
    instance: &NativeCoreInstance,
) -> Option<EventBusSubscriber> {
    instance
        .runtime_host::<NativeInstanceRuntimeHost>()
        .map(NativeInstanceRuntimeHost::subscribe_event)
}

#[cfg(feature = "management-rpc")]
pub fn native_instance_manager_with_runtime(
    runtime_handle: tokio::runtime::Handle,
) -> NativeInstanceManager {
    native_instance_manager_with_optional_runtime(Some(runtime_handle))
}

#[cfg(feature = "management")]
pub fn native_process_management(
    instances: Arc<NativeInstanceManager>,
    hooks: Arc<dyn easytier_core::management::InstanceMutationHooks>,
) -> NativeProcessManagement {
    NativeProcessManagement::new(
        instances,
        hooks,
        Arc::new(easytier_core::management::UnsupportedConfigFileStorage),
    )
}

#[cfg(feature = "management-rpc")]
fn native_instance_manager_with_optional_runtime(
    runtime_handle: Option<tokio::runtime::Handle>,
) -> NativeInstanceManager {
    let process_runtime = CoreProcessRuntime::new();
    InstanceManager::new(
        NativeInstanceFactory::new(process_runtime).with_runtime_handle(runtime_handle.clone()),
        runtime_handle,
    )
}

/// Native construction Adapter for the canonical core InstanceManager.
pub struct NativeInstanceFactory {
    process_runtime: Arc<CoreProcessRuntime>,
    runtime_handle: Option<tokio::runtime::Handle>,
    #[cfg(feature = "management")]
    log_cli_events: bool,
}

impl NativeInstanceFactory {
    pub fn new(process_runtime: Arc<CoreProcessRuntime>) -> Self {
        Self {
            process_runtime,
            runtime_handle: None,
            #[cfg(feature = "management")]
            log_cli_events: false,
        }
    }

    #[cfg(feature = "management")]
    fn with_cli_event_logging(mut self) -> Self {
        self.log_cli_events = true;
        self
    }

    #[cfg(feature = "management-rpc")]
    fn with_runtime_handle(mut self, runtime_handle: Option<tokio::runtime::Handle>) -> Self {
        self.runtime_handle = runtime_handle;
        self
    }
}

impl InstanceFactory for NativeInstanceFactory {
    type Instance = NativeCoreInstance;
    type CreateContext = ();
    type Error = anyhow::Error;

    fn create(
        &self,
        config: TomlConfig,
        (): Self::CreateContext,
    ) -> Result<Arc<Self::Instance>, Self::Error> {
        let _runtime = self
            .runtime_handle
            .as_ref()
            .map(tokio::runtime::Handle::enter);
        let instance = compose_native_core_instance(config, self.process_runtime.clone())?;
        #[cfg(feature = "management")]
        if self.log_cli_events {
            let events = subscribe_native_instance_event(&instance)
                .ok_or_else(|| anyhow::anyhow!("native instance runtime host is unavailable"))?;
            super::cli_event_logger::spawn(instance.instance_id(), events);
        }
        Ok(instance)
    }
}

#[cfg(feature = "management-rpc")]
impl ProcessRuntimeProvider for NativeInstanceFactory {
    fn process_runtime(&self) -> Arc<CoreProcessRuntime> {
        self.process_runtime.clone()
    }
}

#[cfg(test)]
mod tests {
    use easytier_core::{config::toml::ConfigLoader as _, instance::CoreInstanceState};

    use super::*;

    #[tokio::test]
    async fn core_manager_stores_and_runs_native_core_instance_directly() {
        let factory = NativeInstanceFactory::new(CoreProcessRuntime::new());
        let manager = InstanceManager::new(factory, None);
        let config = TomlConfig::default();
        let mut flags = config.get_flags();
        flags.no_tun = true;
        config.set_flags(flags);
        config.set_listeners(Vec::new());

        let instance = manager.create(config, ()).unwrap();
        instance.start().await.unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Running);

        manager
            .delete_network_instances([instance.instance_id()])
            .await
            .unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

    #[test]
    fn configured_runtime_supports_synchronous_instance_construction() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let factory = NativeInstanceFactory::new(CoreProcessRuntime::new())
            .with_runtime_handle(Some(runtime.handle().clone()));
        let manager = InstanceManager::new(factory, Some(runtime.handle().clone()));
        let config = TomlConfig::default();
        config.set_listeners(Vec::new());

        let instance = manager.create(config, ()).unwrap();

        drop(instance);
    }

    #[test]
    fn event_subscription_is_recovered_from_the_native_runtime() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let factory = NativeInstanceFactory::new(CoreProcessRuntime::new())
            .with_runtime_handle(Some(runtime.handle().clone()));
        let manager = InstanceManager::new(factory, Some(runtime.handle().clone()));
        let config = TomlConfig::default();
        config.set_listeners(Vec::new());

        let instance = manager.create(config, ()).unwrap();
        assert!(subscribe_native_instance_event(&instance).is_some());
    }
}

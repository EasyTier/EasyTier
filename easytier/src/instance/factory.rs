use std::sync::Arc;

#[cfg(any(feature = "management-rpc", test))]
use easytier_core::instance::manager::InstanceManager;
#[cfg(feature = "management-rpc")]
use easytier_core::management::ProcessRuntimeProvider;
use easytier_core::{
    config::toml::{ConfigLoader as _, TomlConfig},
    instance::{CoreInstance, manager::InstanceFactory},
    process_runtime::CoreProcessRuntime,
};

use crate::common::global_ctx::EventBusSubscriber;

use super::{
    composition::compose_native_core_instance, host::NativeInstanceHost,
    runtime_executor::NativeInstanceExecutor, runtime_host::NativeInstanceRuntimeHost,
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

#[cfg(feature = "management-rpc")]
pub fn native_compact_instance_manager_with_runtime(
    runtime_handle: tokio::runtime::Handle,
) -> NativeInstanceManager {
    let process_runtime = CoreProcessRuntime::new();
    let factory = NativeInstanceFactory::new(process_runtime)
        .with_runtime_handle(Some(runtime_handle.clone()))
        .with_compact_runtime();
    #[cfg(feature = "logging")]
    let factory = factory.with_cli_event_logging();
    InstanceManager::new(factory, Some(runtime_handle))
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
    compact_runtime: bool,
    #[cfg(feature = "logging")]
    log_cli_events: bool,
}

impl NativeInstanceFactory {
    pub fn new(process_runtime: Arc<CoreProcessRuntime>) -> Self {
        Self {
            process_runtime,
            runtime_handle: None,
            compact_runtime: false,
            #[cfg(feature = "logging")]
            log_cli_events: false,
        }
    }

    #[cfg(feature = "logging")]
    fn with_cli_event_logging(mut self) -> Self {
        self.log_cli_events = true;
        self
    }

    #[cfg(feature = "management-rpc")]
    fn with_runtime_handle(mut self, runtime_handle: Option<tokio::runtime::Handle>) -> Self {
        self.runtime_handle = runtime_handle;
        self
    }

    fn with_compact_runtime(mut self) -> Self {
        self.compact_runtime = true;
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
        let executor = if self.compact_runtime {
            None
        } else {
            let flags = config.get_flags();
            Some(NativeInstanceExecutor::new(
                flags.multi_thread,
                flags.multi_thread_count,
            )?)
        };
        let runtime_handle = executor
            .as_ref()
            .map(NativeInstanceExecutor::handle)
            .or_else(|| self.runtime_handle.clone());
        let _runtime = runtime_handle.as_ref().map(tokio::runtime::Handle::enter);
        let instance = compose_native_core_instance(
            config,
            self.process_runtime.clone(),
            self.compact_runtime,
            executor,
        )?;
        #[cfg(feature = "logging")]
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
    use std::{future::pending, time::Duration};

    use easytier_core::instance::{CoreInstanceState, manager::ConfigFileControl};
    use tokio::runtime::RuntimeFlavor;

    use super::*;

    fn isolated_config(multi_thread: bool, count: u32) -> TomlConfig {
        let config = TomlConfig::default();
        let mut flags = config.get_flags();
        flags.no_tun = true;
        flags.enable_ipv6 = false;
        flags.disable_upnp = true;
        flags.disable_p2p = true;
        flags.disable_tcp_hole_punching = true;
        flags.disable_udp_hole_punching = true;
        flags.multi_thread = multi_thread;
        flags.multi_thread_count = count;
        config.set_flags(flags);
        config.set_listeners(Vec::new());
        config.set_stun_servers(Some(Vec::new()));
        config.set_stun_servers_v6(Some(Vec::new()));
        config.set_tcp_stun_servers(Some(Vec::new()));
        config
    }

    #[tokio::test]
    async fn manager_honors_per_instance_runtime_configuration_and_teardown() {
        let caller = tokio::runtime::Handle::current();
        let manager = native_instance_manager_with_runtime(caller.clone());
        let mut runtimes = Vec::new();
        let mut ids = Vec::new();
        for (multi_thread, count, workers) in [(false, 8, 1), (true, 4, 4)] {
            let config = isolated_config(multi_thread, count);
            let id = manager
                .run_network_instance(config, ConfigFileControl::STATIC_CONFIG)
                .unwrap();
            let runtime = manager.data_plane_runtime_handle(&id).unwrap();
            assert_ne!(runtime.id(), caller.id());
            assert_eq!(runtime.metrics().num_workers(), workers);
            assert_eq!(
                runtime.runtime_flavor(),
                if multi_thread {
                    RuntimeFlavor::MultiThread
                } else {
                    RuntimeFlavor::CurrentThread
                }
            );
            ids.push(id);
            runtimes.push(runtime);
        }
        assert_ne!(runtimes[0].id(), runtimes[1].id());
        tokio::time::timeout(Duration::from_secs(5), async {
            while manager
                .instances()
                .iter()
                .any(|instance| !instance.is_ready())
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("instances must start on their own executors");

        // Shared process resources must continue to work across distinct executors.
        let single = manager.instance(ids[0]).unwrap();
        let multi = manager.instance(ids[1]).unwrap();
        multi
            .add_connector(format!("ring://{}", ids[0]).parse().unwrap())
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if single.connected_peers().await.contains(&multi.peer_id())
                    && multi.connected_peers().await.contains(&single.peer_id())
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("single- and multi-thread instances must connect through the shared ring registry");
        drop(single);
        drop(multi);

        let instances = manager.instances();
        let tasks: Vec<_> = runtimes
            .iter()
            .map(|runtime| runtime.spawn(pending::<()>()))
            .collect();
        manager.delete_network_instances(ids.clone()).await.unwrap();
        assert!(
            instances
                .iter()
                .all(|instance| instance.state() == CoreInstanceState::Stopped)
        );
        assert!(
            ids.iter()
                .all(|id| manager.data_plane_runtime_handle(id).is_none())
        );
        drop(instances);
        for task in tasks {
            assert!(
                tokio::time::timeout(Duration::from_secs(5), task)
                    .await
                    .expect("deleting the last instance owner must shut down its executor")
                    .unwrap_err()
                    .is_cancelled()
            );
        }
    }

    #[test]
    fn direct_instance_outlives_its_callers_runtime() {
        for multi_thread in [false, true] {
            let caller = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            // Standard native construction no longer needs an entered caller runtime.
            let instance = create_native_instance(isolated_config(multi_thread, 3)).unwrap();
            caller.block_on(instance.start()).unwrap();
            drop(caller);
            let executor = instance.runtime_handle().unwrap();
            let caller = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            caller.block_on(async {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    executor.spawn(async {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }),
                )
                .await
                .unwrap()
                .unwrap();
                instance.stop().await;
            });
            assert_eq!(instance.state(), CoreInstanceState::Stopped);
            drop(instance);
        }
    }

    #[tokio::test]
    async fn compact_manager_retains_the_supplied_runtime() {
        let caller = tokio::runtime::Handle::current();
        let manager = native_compact_instance_manager_with_runtime(caller.clone());
        let instance = manager.create(isolated_config(true, 8), ()).unwrap();
        assert!(instance.runtime_handle().is_none());
        assert_eq!(
            manager
                .data_plane_runtime_handle(&instance.instance_id())
                .unwrap()
                .id(),
            caller.id()
        );
        instance.start().await.unwrap();
        manager
            .delete_network_instances([instance.instance_id()])
            .await
            .unwrap();
        assert_eq!(instance.state(), CoreInstanceState::Stopped);
    }

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

use std::sync::Arc;

use easytier::instance::factory::{
    NativeInstanceSet, NativeProcessManagement, native_instance_set_with_runtime,
    native_process_management,
};
use tokio::runtime::{Builder, Runtime};

struct FfiOwnedInstanceHooks;

#[async_trait::async_trait]
impl easytier_core::management::InstanceMutationHooks for FfiOwnedInstanceHooks {
    async fn post_remove_network_instances(
        &self,
        instance_ids: &[uuid::Uuid],
    ) -> Result<(), String> {
        crate::config_server::remove_config_server_tracked_instance_ids(instance_ids);
        crate::data_plane::remove_data_plane_handles_by_instance_ids(instance_ids);
        Ok(())
    }
}

pub(crate) struct FfiContext {
    pub(crate) runtime: Runtime,
    pub(crate) manager: Arc<NativeInstanceSet>,
    pub(crate) process_management: NativeProcessManagement,
}

impl FfiContext {
    fn new() -> Self {
        let runtime = Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for easytier-ffi");
        let manager = Arc::new(native_instance_set_with_runtime(runtime.handle().clone()));
        let process_management =
            native_process_management(manager.clone(), Arc::new(FfiOwnedInstanceHooks));
        Self {
            runtime,
            manager,
            process_management,
        }
    }
}

static FFI_CONTEXT: once_cell::sync::Lazy<FfiContext> = once_cell::sync::Lazy::new(FfiContext::new);

pub(crate) fn ffi_context() -> &'static FfiContext {
    &FFI_CONTEXT
}

pub(crate) fn resolve_instance_id_by_name(inst_name: &str) -> Result<Option<uuid::Uuid>, String> {
    easytier_core::management::resolve_optional_instance_by_name(
        ffi_context().manager.manager().as_ref(),
        inst_name,
    )
    .map(|instance| instance.map(|instance| instance.instance_id()))
    .map_err(|error| error.to_string())
}

#[cfg(test)]
pub(crate) fn find_instance_id_by_name(inst_name: &str) -> Option<uuid::Uuid> {
    resolve_instance_id_by_name(inst_name).ok().flatten()
}

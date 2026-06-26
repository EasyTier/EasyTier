use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use easytier::instance_manager::NetworkInstanceManager;
use tokio::runtime::{Builder, Runtime};
use uuid::Uuid;

pub(crate) static INSTANCE_NAME_ID_MAP: once_cell::sync::Lazy<DashMap<String, Uuid>> =
    once_cell::sync::Lazy::new(DashMap::new);
pub(crate) static INSTANCE_MANAGER: once_cell::sync::Lazy<Arc<NetworkInstanceManager>> =
    once_cell::sync::Lazy::new(|| Arc::new(NetworkInstanceManager::new()));
pub(crate) static ASYNC_RUNTIME: once_cell::sync::Lazy<Runtime> =
    once_cell::sync::Lazy::new(|| {
        Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("tokio runtime for easytier-ffi")
    });
pub(crate) static INSTANCE_MUTATION_LOCK: once_cell::sync::Lazy<Mutex<()>> =
    once_cell::sync::Lazy::new(|| Mutex::new(()));

pub(crate) fn remove_instance_name_ids(ids: &[Uuid]) {
    if ids.is_empty() {
        return;
    }

    INSTANCE_NAME_ID_MAP.retain(|_, instance_id| !ids.contains(instance_id));
}

pub(crate) fn lock_remote_instance_mutation() -> tokio::sync::OwnedMutexGuard<()> {
    INSTANCE_MANAGER
        .remote_mutation_lock()
        .blocking_lock_owned()
}

pub(crate) fn instance_name_exists(inst_name: &str) -> bool {
    find_instance_id_by_name(inst_name).is_some()
}

pub(crate) fn find_instance_id_by_name(inst_name: &str) -> Option<Uuid> {
    INSTANCE_NAME_ID_MAP
        .get(inst_name)
        .map(|id| *id)
        .or_else(|| {
            INSTANCE_MANAGER
                .list_network_instance_ids()
                .into_iter()
                .find(|id| {
                    INSTANCE_MANAGER
                        .get_instance_name(id)
                        .is_some_and(|name| name == inst_name)
                })
        })
}

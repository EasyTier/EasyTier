pub mod local_dns;
pub mod routing;
pub mod socket_protector;
pub mod state;
pub mod tun_watcher;

use easytier::instance::factory::{NativeInstanceManager, native_instance_manager_with_runtime};
use once_cell::sync::Lazy;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::{Builder, Runtime};

/// Compact Tokio runtime for HarmonyOS control-plane tasks (event watchers,
/// local authoritative DNS, web-client, and N-API bridge calls).
/// Instance data planes run on their own upstream `NativeInstanceExecutor`s, so
/// a single worker thread with a 512 KiB stack is sufficient here.
pub static ASYNC_RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .worker_threads(1)
        .max_blocking_threads(4)
        .thread_keep_alive(Duration::from_secs(10))
        .thread_stack_size(512 * 1024)
        .thread_name("et-core-rt")
        .enable_all()
        .build()
        .expect("tokio runtime for easytier-ohrs")
});

/// Process-wide EasyTier instance manager backed by the upstream native factory.
pub static INSTANCE_MANAGER: Lazy<Arc<NativeInstanceManager>> = Lazy::new(|| {
    Arc::new(native_instance_manager_with_runtime(
        ASYNC_RUNTIME.handle().clone(),
    ))
});

/// Flushes jemalloc thread caches on the calling thread, the control-plane
/// Tokio worker, and any active instance data-plane executors on OHOS.
pub fn flush_runtime_allocators() {
    #[cfg(target_env = "ohos")]
    {
        unsafe extern "C" {
            fn mallopt(param: i32, value: i32) -> i32;
        }
        let flush_here = || unsafe {
            let _ = mallopt(-1003, 0);
            let _ = mallopt(-1004, 103);
            let _ = mallopt(-1002, 0);
        };
        flush_here();
        if let Some(rt) = Lazy::get(&ASYNC_RUNTIME) {
            rt.spawn(async move {
                flush_here();
            });
        }
        if let Some(manager) = Lazy::get(&INSTANCE_MANAGER) {
            for id in manager.instance_ids() {
                if let Some(handle) = manager.data_plane_runtime_handle(&id) {
                    let probes = handle.metrics().num_workers().clamp(1, 4);
                    for _ in 0..probes {
                        handle.spawn(async move {
                            flush_here();
                        });
                    }
                }
            }
        }
    }
}

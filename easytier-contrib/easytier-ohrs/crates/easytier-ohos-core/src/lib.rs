pub mod protocol;
pub mod routing;
pub mod runtime;
pub mod socket_protection;

use easytier::instance::factory::{NativeInstanceManager, native_instance_manager_with_runtime};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::runtime::{Builder, Runtime};

/// The single Tokio runtime that owns HarmonyOS kernel and web-client work.
pub static ASYNC_RUNTIME: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime for easytier-ohos-core")
});

/// Process-wide EasyTier instance manager. Keeping it in the kernel crate prevents feature/storage
/// code from acquiring lifecycle ownership.
pub static INSTANCE_MANAGER: Lazy<Arc<NativeInstanceManager>> = Lazy::new(|| {
    Arc::new(native_instance_manager_with_runtime(
        ASYNC_RUNTIME.handle().clone(),
    ))
});

#[cfg(test)]
mod architecture_tests {
    fn assert_no_napi_annotations(path: &std::path::Path) {
        for entry in std::fs::read_dir(path).expect("read source directory") {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                assert_no_napi_annotations(&path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).expect("read Rust source");
                let marker = ["#[", "napi"].concat();
                assert!(!source.contains(&marker), "N-API annotation in {path:?}");
            }
        }
    }

    #[test]
    fn inner_crate_has_no_napi_registration_dependency() {
        let manifest = include_str!("../Cargo.toml");
        let runtime_dependency = ["napi", "ohos"].join("-");
        let derive_dependency = ["napi", "derive", "ohos"].join("-");
        assert!(!manifest.contains(&runtime_dependency));
        assert!(!manifest.contains(&derive_dependency));
        assert!(!manifest.contains("easytier-ohos-features"));
        assert_no_napi_annotations(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .as_path(),
        );
    }
}

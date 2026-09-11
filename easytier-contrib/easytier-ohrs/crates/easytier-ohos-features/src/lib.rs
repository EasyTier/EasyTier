use std::sync::OnceLock;

#[derive(Clone, Copy)]
pub struct FeatureLogSink {
    pub enabled: fn(i32) -> bool,
    pub emit: fn(i32, &str, &str),
}

static FEATURE_LOG_SINK: OnceLock<FeatureLogSink> = OnceLock::new();

/// Installs the outer HAR facade's log sink without coupling this feature crate to N-API setup.
pub fn install_log_sink(sink: FeatureLogSink) {
    let _ = FEATURE_LOG_SINK.set(sink);
}

#[doc(hidden)]
pub fn log_enabled(level: i32) -> bool {
    FEATURE_LOG_SINK
        .get()
        .map(|sink| (sink.enabled)(level))
        .unwrap_or(true)
}

#[doc(hidden)]
pub fn emit_log(level: i32, message: String) {
    if let Some(sink) = FEATURE_LOG_SINK.get() {
        (sink.emit)(level, "RustOhrs", &message);
        return;
    }
    match level {
        5 => tracing::error!(target: "easytier_ohrs", "{message}"),
        4 => tracing::info!(target: "easytier_ohrs", "{message}"),
        _ => tracing::debug!(target: "easytier_ohrs", "{message}"),
    }
}

macro_rules! ohrs_log_error {
    ($($arg:tt)*) => {{
        $crate::emit_log(5, std::format!($($arg)*));
    }};
}

macro_rules! ohrs_log_debug {
    ($($arg:tt)*) => {{
        if $crate::log_enabled(3) {
            $crate::emit_log(3, std::format!($($arg)*));
        }
    }};
}

pub mod config;

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
        assert_no_napi_annotations(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src")
                .as_path(),
        );
    }
}

//! Minimal logging for the embedded (WASI) core.
//!
//! The CLI package installs its subscriber in `log::init`, but the WASI artifact is built from this
//! package, which cannot depend on that code. As a result an embedded instance had no subscriber
//! installed at all and every `tracing` call inside the guest was a no-op - the host could not see
//! anything, debug or otherwise.
//!
//! This module keeps the embedded path self-contained: a subscriber written directly against
//! `tracing` (already a dependency here) so that no new imports are introduced into the wasm
//! artifact, plus a level handle that can be changed at runtime.

use std::sync::atomic::{AtomicUsize, Ordering};

use tracing::Level;

static LEVEL: AtomicUsize = AtomicUsize::new(level_to_usize(Level::INFO));
static INSTALLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();

const fn level_to_usize(level: Level) -> usize {
    match level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

fn level_from_str(level: &str) -> Level {
    match level.to_ascii_lowercase().as_str() {
        "off" | "disabled" => Level::ERROR,
        "error" => Level::ERROR,
        "warn" | "warning" => Level::WARN,
        "debug" => Level::DEBUG,
        "trace" => Level::TRACE,
        _ => Level::INFO,
    }
}

/// Change the maximum level; takes effect immediately for every later event.
pub fn set_level(level: Level) {
    LEVEL.store(level_to_usize(level), Ordering::Relaxed);
}

/// Parse and apply a level name; unknown names fall back to `info`.
pub fn set_level_name(name: &str) {
    set_level(level_from_str(name));
}

/// Test-only view of the current level (kept out of release builds to avoid dead code).
#[cfg(test)]
pub(crate) fn level() -> Level {
    match LEVEL.load(Ordering::Relaxed) {
        1 => Level::ERROR,
        2 => Level::WARN,
        4 => Level::DEBUG,
        5 => Level::TRACE,
        _ => Level::INFO,
    }
}

struct StdoutSubscriber;

impl tracing::Subscriber for StdoutSubscriber {
    fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
        level_to_usize(*metadata.level()) <= LEVEL.load(Ordering::Relaxed)
    }

    fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

    fn event(&self, event: &tracing::Event<'_>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                use std::fmt::Write as _;
                let _ = write!(self.0, " {}={:?}", field.name(), value);
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        println!(
            "[{}] {}{}",
            event.metadata().level(),
            event.metadata().target(),
            fields.0
        );
    }

    fn enter(&self, _: &tracing::span::Id) {}

    fn exit(&self, _: &tracing::span::Id) {}
}

/// Install the subscriber once; later calls are ignored. Safe to call from every entry point.
pub fn install(level_name: Option<&str>) {
    let _ = INSTALLED.get_or_init(|| {
        if let Some(name) = level_name {
            set_level_name(name);
        }
        tracing::subscriber::set_global_default(StdoutSubscriber).is_ok()
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_names_map_to_levels() {
        set_level_name("trace");
        assert_eq!(level(), Level::TRACE);
        set_level_name("DEBUG");
        assert_eq!(level(), Level::DEBUG);
        set_level_name("warn");
        assert_eq!(level(), Level::WARN);
        set_level_name("error");
        assert_eq!(level(), Level::ERROR);
        set_level_name("info");
        assert_eq!(level(), Level::INFO);
    }

    #[test]
    fn unknown_level_names_fall_back_to_info() {
        set_level_name("trace");
        set_level_name("nonsense");
        assert_eq!(level(), Level::INFO);
    }

    #[test]
    fn install_is_idempotent() {
        // Every ABI instance creation calls this; repeated calls must be a no-op rather than a panic
        // or a second global default. The level is process state, so this deliberately does not
        // assert its value - other tests in the same binary may have set it already.
        install(Some("debug"));
        install(Some("trace"));
        install(None);
    }

    #[test]
    fn emitting_an_event_does_not_panic() {
        install(None);
        tracing::info!(answer = 42, "logger smoke test");
        tracing::trace!("below the default level");
    }
}
